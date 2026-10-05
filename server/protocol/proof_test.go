package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	now atomic.Int64
}

func newClock() *clock {
	c := &clock{}
	c.now.Store(time.Now().UnixNano())
	return c
}

func (c *clock) Now() time.Time {
	return time.Unix(0, c.now.Load())
}

func (c *clock) Advance(d time.Duration) {
	c.now.Add(int64(d))
}

type signer struct {
	private  ed25519.PrivateKey
	identity string
}

func newSigner(t testing.TB) signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{private: private, identity: base64.RawURLEncoding.EncodeToString(public)}
}

func (s signer) sign(message []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, message))
}

func proofRouter(c *clock) *Router {
	return NewRouter(map[string]Handler{
		"challenge": Challenge(c.Now),
		"prove":     Prove(c.Now),
	})
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
	if err != nil || len(nonce) != challengeSize {
		t.Fatalf("nonce %q: %v", payload.Nonce, err)
	}
	return nonce
}

func prove(conn *Conn, identity, signature string) []byte {
	return conn.Handle(fmt.Appendf(nil, `{"type":"prove","id":"p1","payload":{"identity":%q,"signature":%q}}`, identity, signature))
}

func expectCode(t *testing.T, data []byte, code Code) {
	t.Helper()
	resp := decodeResponse(t, data)
	if got := errorCode(t, resp); got != code {
		t.Fatalf("code = %q, want %q", got, code)
	}
}

func TestProofSucceeds(t *testing.T) {
	conn := proofRouter(newClock()).Conn()
	s := newSigner(t)

	nonce := requestChallenge(t, conn)
	resp := decodeResponse(t, prove(conn, s.identity, s.sign(ProofMessage(nonce))))

	if resp.Type != "proven" || resp.ID != "p1" {
		t.Fatalf("response = %+v", resp)
	}
	if want := `{"identity":"` + s.identity + `"}`; string(resp.Payload) != want {
		t.Errorf("payload = %s, want %s", resp.Payload, want)
	}
}

func TestProofMessageIsDomainSeparated(t *testing.T) {
	nonce := make([]byte, challengeSize)
	got := ProofMessage(nonce)
	want := append([]byte("ghostx/identity/proof/v1\x00"), nonce...)
	if string(got) != string(want) {
		t.Fatalf("ProofMessage() = %q, want %q", got, want)
	}
	if string(ProofMessage(nonce)) != string(got) {
		t.Fatal("ProofMessage() is not deterministic")
	}
}

func TestChallengesAreUnique(t *testing.T) {
	conn := proofRouter(newClock()).Conn()
	seen := make(map[string]struct{})
	for range 100 {
		nonce := string(requestChallenge(t, conn))
		if _, dup := seen[nonce]; dup {
			t.Fatal("duplicate challenge")
		}
		seen[nonce] = struct{}{}
	}
}

func TestProofRejected(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)

	tests := map[string]func(t *testing.T, c *clock, conn *Conn) []byte{
		"no challenge": func(t *testing.T, c *clock, conn *Conn) []byte {
			return prove(conn, s.identity, s.sign(ProofMessage(make([]byte, challengeSize))))
		},
		"replayed proof": func(t *testing.T, c *clock, conn *Conn) []byte {
			sig := s.sign(ProofMessage(requestChallenge(t, conn)))
			if resp := decodeResponse(t, prove(conn, s.identity, sig)); resp.Type != "proven" {
				t.Fatalf("first proof = %+v", resp)
			}
			return prove(conn, s.identity, sig)
		},
		"superseded challenge": func(t *testing.T, c *clock, conn *Conn) []byte {
			first := requestChallenge(t, conn)
			requestChallenge(t, conn)
			return prove(conn, s.identity, s.sign(ProofMessage(first)))
		},
		"expired challenge": func(t *testing.T, c *clock, conn *Conn) []byte {
			nonce := requestChallenge(t, conn)
			c.Advance(challengeTTL)
			return prove(conn, s.identity, s.sign(ProofMessage(nonce)))
		},
		"signed by other key": func(t *testing.T, c *clock, conn *Conn) []byte {
			return prove(conn, s.identity, other.sign(ProofMessage(requestChallenge(t, conn))))
		},
		"claims other identity": func(t *testing.T, c *clock, conn *Conn) []byte {
			return prove(conn, other.identity, s.sign(ProofMessage(requestChallenge(t, conn))))
		},
		"nonce without context": func(t *testing.T, c *clock, conn *Conn) []byte {
			return prove(conn, s.identity, s.sign(requestChallenge(t, conn)))
		},
		"other context": func(t *testing.T, c *clock, conn *Conn) []byte {
			nonce := requestChallenge(t, conn)
			return prove(conn, s.identity, s.sign(append([]byte("ghostx/identity/proof/v2\x00"), nonce...)))
		},
		"malformed signature": func(t *testing.T, c *clock, conn *Conn) []byte {
			requestChallenge(t, conn)
			return prove(conn, s.identity, "not-a-signature")
		},
		"retry after failure": func(t *testing.T, c *clock, conn *Conn) []byte {
			nonce := requestChallenge(t, conn)
			expectCode(t, prove(conn, s.identity, other.sign(ProofMessage(nonce))), CodeInvalidProof)
			return prove(conn, s.identity, s.sign(ProofMessage(nonce)))
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			expectCode(t, run(t, c, proofRouter(c).Conn()), CodeInvalidProof)
		})
	}
}

func TestProofExpiresExactlyAtTTL(t *testing.T) {
	s := newSigner(t)
	c := newClock()
	conn := proofRouter(c).Conn()

	nonce := requestChallenge(t, conn)
	c.Advance(challengeTTL - time.Nanosecond)
	if resp := decodeResponse(t, prove(conn, s.identity, s.sign(ProofMessage(nonce)))); resp.Type != "proven" {
		t.Fatalf("response before expiry = %+v", resp)
	}
}

func TestProofIsBoundToConnection(t *testing.T) {
	s := newSigner(t)
	router := proofRouter(newClock())
	first, second := router.Conn(), router.Conn()

	nonce := requestChallenge(t, first)
	expectCode(t, prove(second, s.identity, s.sign(ProofMessage(nonce))), CodeInvalidProof)

	if resp := decodeResponse(t, prove(first, s.identity, s.sign(ProofMessage(nonce)))); resp.Type != "proven" {
		t.Fatalf("original connection response = %+v", resp)
	}
}

func TestProofInvalidPayload(t *testing.T) {
	s := newSigner(t)
	smallOrder := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	sig := strings.Repeat("A", 86)

	tests := map[string]string{
		"missing payload":   `{"type":"prove","id":"p1"}`,
		"null payload":      `{"type":"prove","id":"p1","payload":null}`,
		"empty payload":     `{"type":"prove","id":"p1","payload":{}}`,
		"missing signature": `{"type":"prove","id":"p1","payload":{"identity":"` + s.identity + `"}}`,
		"extra field":       `{"type":"prove","id":"p1","payload":{"identity":"` + s.identity + `","signature":"` + sig + `","nonce":"x"}}`,
		"numeric identity":  `{"type":"prove","id":"p1","payload":{"identity":1,"signature":"` + sig + `"}}`,
		"null signature":    `{"type":"prove","id":"p1","payload":{"identity":"` + s.identity + `","signature":null}}`,
		"padded identity":   `{"type":"prove","id":"p1","payload":{"identity":"` + s.identity + `=","signature":"` + sig + `"}}`,
		"small order key":   `{"type":"prove","id":"p1","payload":{"identity":"` + smallOrder + `","signature":"` + sig + `"}}`,
		"oversized key":     `{"type":"prove","id":"p1","payload":{"identity":"` + strings.Repeat("A", 20000) + `","signature":"` + sig + `"}}`,
		"challenge payload": `{"type":"challenge","id":"c1","payload":{"x":1}}`,
		"challenge missing": `{"type":"challenge","id":"c1"}`,
		"challenge null":    `{"type":"challenge","id":"c1","payload":null}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			conn := proofRouter(newClock()).Conn()
			requestChallenge(t, conn)
			expectCode(t, conn.Handle([]byte(input)), CodeInvalidPayload)
		})
	}
}

func TestMalformedProofConsumesChallenge(t *testing.T) {
	s := newSigner(t)
	conn := proofRouter(newClock()).Conn()

	nonce := requestChallenge(t, conn)
	expectCode(t, conn.Handle([]byte(`{"type":"prove","id":"p1","payload":{}}`)), CodeInvalidPayload)
	expectCode(t, prove(conn, s.identity, s.sign(ProofMessage(nonce))), CodeInvalidProof)
}

func FuzzProve(f *testing.F) {
	s := newSigner(f)
	f.Add(s.identity, s.sign([]byte("x")))
	f.Add("", "")
	f.Add(strings.Repeat("A", 43), strings.Repeat("A", 86))
	f.Add(s.identity, strings.Repeat("_", 86))

	router := proofRouter(newClock())
	f.Fuzz(func(t *testing.T, identity, signature string) {
		conn := router.Conn()
		conn.Handle([]byte(`{"type":"challenge","id":"c1","payload":{}}`))
		payload, err := json.Marshal(map[string]string{"identity": identity, "signature": signature})
		if err != nil {
			t.Skip()
		}
		out := conn.Handle([]byte(`{"type":"prove","id":"p1","payload":` + string(payload) + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		if resp.Type != "error" {
			t.Fatalf("unexpected acceptance %s", out)
		}
		if strings.Contains(string(out), "identity:") || strings.Contains(string(out), "edwards25519") {
			t.Fatalf("response leaks internal error: %s", out)
		}
	})
}
