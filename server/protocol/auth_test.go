package protocol

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
)

func authRouter() *Router {
	return NewRouter(map[string]Handler{
		"challenge":    Challenge(),
		"authenticate": Authenticate(),
	}, nil)
}

func requestChallenge(t *testing.T, conn *Conn) []byte {
	t.Helper()
	resp := decodeResponse(t, conn.Handle([]byte(`{"type":"challenge","id":"c1","payload":{}}`)))
	if resp.Type != "challenge" || resp.ID != "c1" {
		t.Fatalf("challenge response = %+v", resp)
	}
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(resp.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(payload.Nonce)
	if err != nil || len(nonce) != auth.ChallengeSize {
		t.Fatalf("nonce %q: %v", payload.Nonce, err)
	}
	return nonce
}

func expectCode(t *testing.T, data []byte, code Code) {
	t.Helper()
	if got := errorCode(t, decodeResponse(t, data)); got != code {
		t.Fatalf("code = %q, want %q", got, code)
	}
}

func TestAuthenticateBindsSession(t *testing.T) {
	registry := auth.NewRegistry(time.Now, nil, testDevices)
	session := registry.Open()
	conn := authRouter().Conn(session, discard)
	s := newSigner(t)

	nonce := requestChallenge(t, conn)
	resp := decodeResponse(t, authenticate(conn, s.identity, s.device.ID, s.proof(nonce)))

	if resp.Type != "authenticated" || resp.ID != "a1" || string(resp.Payload) != `{"identity":"`+s.identity+`","device":"`+s.device.ID+`"}` {
		t.Fatalf("response = %+v %s", resp, resp.Payload)
	}
	if id, ok := session.Identity(); !ok || id.String() != s.identity {
		t.Fatal("session not bound to identity")
	}
}

func TestAuthenticateRejectsCrossConnectionProof(t *testing.T) {
	registry := auth.NewRegistry(time.Now, nil, testDevices)
	router := authRouter()
	firstSession, secondSession := registry.Open(), registry.Open()
	first, second := router.Conn(firstSession, discard), router.Conn(secondSession, discard)
	s := newSigner(t)

	nonce := requestChallenge(t, first)
	requestChallenge(t, second)
	expectCode(t, authenticate(second, s.identity, s.device.ID, s.proof(nonce)), CodeAuthFailed)

	if _, ok := secondSession.Identity(); ok {
		t.Fatal("second connection authenticated with first connection's proof")
	}
	if _, ok := firstSession.Identity(); ok {
		t.Fatal("first connection authenticated without completing its own proof")
	}
}

func TestAuthenticateFailures(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)

	tests := map[string]struct {
		run  func(t *testing.T, conn *Conn) []byte
		code Code
	}{
		"no challenge": {func(t *testing.T, conn *Conn) []byte {
			return authenticate(conn, s.identity, s.device.ID, s.proof(make([]byte, auth.ChallengeSize)))
		}, CodeAuthFailed},
		"replayed proof": {func(t *testing.T, conn *Conn) []byte {
			sig := s.proof(requestChallenge(t, conn))
			expectCode(t, authenticate(conn, s.identity, s.device.ID, other.sign([]byte("x"))), CodeAuthFailed)
			return authenticate(conn, s.identity, s.device.ID, sig)
		}, CodeAuthFailed},
		"other identity": {func(t *testing.T, conn *Conn) []byte {
			return authenticate(conn, other.identity, other.device.ID, s.proof(requestChallenge(t, conn)))
		}, CodeAuthFailed},
		"previous proof context": {func(t *testing.T, conn *Conn) []byte {
			nonce := requestChallenge(t, conn)
			return authenticate(conn, s.identity, s.device.ID, s.sign(append([]byte("ghostx/identity/proof/v1\x00"), nonce...)))
		}, CodeAuthFailed},
		"duplicate authentication": {func(t *testing.T, conn *Conn) []byte {
			sig := s.proof(requestChallenge(t, conn))
			if resp := decodeResponse(t, authenticate(conn, s.identity, s.device.ID, sig)); resp.Type != "authenticated" {
				t.Fatalf("first authentication = %+v", resp)
			}
			return authenticate(conn, s.identity, s.device.ID, sig)
		}, CodeAuthFailed},
		"challenge after authentication": {func(t *testing.T, conn *Conn) []byte {
			if resp := decodeResponse(t, authenticate(conn, s.identity, s.device.ID, s.proof(requestChallenge(t, conn)))); resp.Type != "authenticated" {
				t.Fatalf("authentication = %+v", resp)
			}
			return conn.Handle([]byte(`{"type":"challenge","id":"c2","payload":{}}`))
		}, CodeAuthFailed},
		"malformed identity": {func(t *testing.T, conn *Conn) []byte {
			return authenticate(conn, s.identity+"=", s.device.ID, s.proof(requestChallenge(t, conn)))
		}, CodeInvalidPayload},
		"malformed payload": {func(t *testing.T, conn *Conn) []byte {
			requestChallenge(t, conn)
			return conn.Handle([]byte(`{"type":"authenticate","id":"a1","payload":{"identity":1}}`))
		}, CodeInvalidPayload},
		"challenge payload": {func(t *testing.T, conn *Conn) []byte {
			return conn.Handle([]byte(`{"type":"challenge","id":"c1","payload":{"x":1}}`))
		}, CodeInvalidPayload},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conn := authRouter().Conn(testSession(), discard)
			expectCode(t, tt.run(t, conn), tt.code)
		})
	}
}

func TestMalformedAuthenticateConsumesChallenge(t *testing.T) {
	conn := authRouter().Conn(testSession(), discard)
	s := newSigner(t)

	nonce := requestChallenge(t, conn)
	expectCode(t, conn.Handle([]byte(`{"type":"authenticate","id":"a1","payload":{}}`)), CodeInvalidPayload)
	expectCode(t, authenticate(conn, s.identity, s.device.ID, s.proof(nonce)), CodeAuthFailed)
}

func TestAuthenticationLocksAfterFailures(t *testing.T) {
	session := testSession()
	conn := authRouter().Conn(session, discard)
	s := newSigner(t)
	other := newSigner(t)

	for range auth.MaxFailures {
		nonce := requestChallenge(t, conn)
		expectCode(t, authenticate(conn, s.identity, s.device.ID, other.proof(nonce)), CodeAuthFailed)
	}
	expectCode(t, conn.Handle([]byte(`{"type":"challenge","id":"c1","payload":{}}`)), CodeAuthFailed)
	if session.State() != auth.Failed {
		t.Fatalf("State() = %v, want %v", session.State(), auth.Failed)
	}
}

func TestClosedSessionRejectsAuthentication(t *testing.T) {
	session := testSession()
	conn := authRouter().Conn(session, discard)
	s := newSigner(t)

	nonce := requestChallenge(t, conn)
	session.Close()

	expectCode(t, authenticate(conn, s.identity, s.device.ID, s.proof(nonce)), CodeAuthFailed)
	expectCode(t, conn.Handle([]byte(`{"type":"challenge","id":"c1","payload":{}}`)), CodeAuthFailed)
	if _, ok := session.Identity(); ok {
		t.Fatal("closed session authenticated")
	}
}

func TestAuthErrorsDoNotLeakDetails(t *testing.T) {
	conn := authRouter().Conn(testSession(), discard)
	s := newSigner(t)

	for _, out := range [][]byte{
		authenticate(conn, s.identity, s.device.ID, "x"),
		authenticate(conn, "x", "x", "x"),
		authenticate(conn, s.identity, unregistered().device.ID, s.proof(make([]byte, 32))),
		authenticate(conn, s.identity, s.device.ID, strings.Repeat("A", 86)),
	} {
		for _, leak := range []string{"auth:", "identity:", "edwards25519", "session", "nonce"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}

func FuzzAuthenticateMessage(f *testing.F) {
	s := newSigner(f)
	f.Add(`{"identity":"` + s.identity + `","device":"` + s.device.ID + `","signature":"` + strings.Repeat("A", 86) + `"}`)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`{"identity":1,"signature":[]}`)
	f.Add(`{"identity":"` + strings.Repeat("A", 43) + `","device":"` + strings.Repeat("A", 22) + `","signature":"` + strings.Repeat("_", 86) + `","x":1}`)
	f.Add(`{"identity":"` + s.identity + `","signature":"` + strings.Repeat("A", 86) + `"}`)

	router := authRouter()
	registry := auth.NewRegistry(time.Now, nil, testDevices)
	f.Fuzz(func(t *testing.T, payload string) {
		session := registry.Open()
		defer session.Close()
		conn := router.Conn(session, discard)
		conn.Handle([]byte(`{"type":"challenge","id":"c1","payload":{}}`))
		out := conn.Handle([]byte(`{"type":"authenticate","id":"a1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		if resp.Type != "error" {
			t.Fatalf("forged authentication accepted: %s", out)
		}
		if _, ok := session.Identity(); ok {
			t.Fatal("session authenticated by fuzz input")
		}
	})
}

func TestAuthenticateRequiresAnAuthorizedDeviceKey(t *testing.T) {
	pair := newSiblings(t, 2)
	outsider := unregistered()
	tests := map[string]func(conn *Conn) []byte{
		"unregistered identity": func(conn *Conn) []byte {
			return authenticate(conn, outsider.identity, outsider.device.ID, outsider.proof(requestChallenge(t, conn)))
		},
		"sibling proof for this device": func(conn *Conn) []byte {
			return authenticate(conn, pair[0].identity, pair[0].device.ID, pair[1].proof(requestChallenge(t, conn)))
		},
		"identity root key": func(conn *Conn) []byte {
			nonce := requestChallenge(t, conn)
			sig := base64.RawURLEncoding.EncodeToString(ed25519Sign(pair[0], auth.Message(nonce, decoded(pair[0].identity), pair[0].device.IDRaw)))
			return authenticate(conn, pair[0].identity, pair[0].device.ID, sig)
		},
		"device of another identity": func(conn *Conn) []byte {
			other := newSigner(t)
			return authenticate(conn, pair[0].identity, other.device.ID, other.proof(requestChallenge(t, conn)))
		},
		"missing device": func(conn *Conn) []byte {
			requestChallenge(t, conn)
			return conn.Handle([]byte(`{"type":"authenticate","id":"a1","payload":{"identity":"` + pair[0].identity + `","signature":"x"}}`))
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			session := testSession()
			out := run(authRouter().Conn(session, discard))
			if resp := decodeResponse(t, out); resp.Type != "error" {
				t.Fatalf("accepted: %s", out)
			}
			if _, ok := session.Identity(); ok {
				t.Fatal("session authenticated")
			}
		})
	}
	revoked := newSiblings(t, 2)
	conn := authRouter().Conn(testSession(), discard)
	nonce := requestChallenge(t, conn)
	if err := testDevices.Publish(revoked[0].owner.Remove(revoked[1].device)); err != nil {
		t.Fatal(err)
	}
	expectCode(t, authenticate(conn, revoked[1].identity, revoked[1].device.ID, revoked[1].proof(nonce)), CodeAuthFailed)
}
