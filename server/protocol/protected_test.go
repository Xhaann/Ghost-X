package protocol

import (
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
)

func protectedRouter() *Router {
	return NewRouter(map[string]Handler{
		"challenge":    Challenge(),
		"authenticate": Authenticate(),
	}, map[string]ProtectedHandler{
		"whoami": WhoAmI(),
	})
}

func whoami(conn *Conn) []byte {
	return conn.Handle([]byte(`{"type":"whoami","id":"w1","payload":{}}`))
}

func TestProtectedRequiresAuthentication(t *testing.T) {
	conn := protectedRouter().Conn(testSession(), discard)

	for _, input := range []string{
		`{"type":"whoami","id":"w1","payload":{}}`,
		`{"type":"whoami","id":"w1"}`,
		`{"type":"whoami","id":"w1","payload":{"x":1}}`,
	} {
		resp := decodeResponse(t, conn.Handle([]byte(input)))
		if code := errorCode(t, resp); code != CodeAuthRequired || resp.ID != "w1" {
			t.Fatalf("response to %s = %+v code %q", input, resp, code)
		}
	}
}

func TestProtectedRequiresCompletedAuthentication(t *testing.T) {
	conn := protectedRouter().Conn(testSession(), discard)
	s := newSigner(t)
	other := newSigner(t)

	requestChallenge(t, conn)
	expectCode(t, whoami(conn), CodeAuthRequired)

	expectCode(t, authenticate(conn, s.identity, s.device.ID, other.proof(requestChallenge(t, conn))), CodeAuthFailed)
	expectCode(t, whoami(conn), CodeAuthRequired)
}

func TestProtectedReturnsSessionIdentity(t *testing.T) {
	router := protectedRouter()
	s := newSigner(t)
	other := newSigner(t)
	first, second := router.Conn(testSession(), discard), router.Conn(testSession(), discard)

	authenticated(t, first, s)
	authenticated(t, second, other)

	for conn, want := range map[*Conn]signer{first: s, second: other} {
		resp := decodeResponse(t, whoami(conn))
		if resp.Type != "whoami" || resp.ID != "w1" || string(resp.Payload) != `{"identity":"`+want.identity+`","device":"`+want.device.ID+`"}` {
			t.Fatalf("whoami = %+v %s, want %s", resp, resp.Payload, want.identity)
		}
	}
	expectCode(t, conn(router).Handle([]byte(`{"type":"whoami","id":"w1","payload":{}}`)), CodeAuthRequired)
}

func conn(r *Router) *Conn {
	return r.Conn(testSession(), discard)
}

func TestProtectedValidatesPayloadAfterAuthentication(t *testing.T) {
	c := protectedRouter().Conn(testSession(), discard)
	authenticated(t, c, newSigner(t))

	expectCode(t, c.Handle([]byte(`{"type":"whoami","id":"w1","payload":{"x":1}}`)), CodeInvalidPayload)
	expectCode(t, c.Handle([]byte(`{"type":"whoami","id":"w1"}`)), CodeInvalidPayload)
}

func TestProtectedRejectedAfterSessionClose(t *testing.T) {
	session := testSession()
	c := protectedRouter().Conn(session, discard)
	authenticated(t, c, newSigner(t))

	session.Close()

	expectCode(t, whoami(c), CodeAuthRequired)
}

func TestProtectedRejectedAfterLockout(t *testing.T) {
	c := protectedRouter().Conn(testSession(), discard)
	s := newSigner(t)
	other := newSigner(t)
	for range auth.MaxFailures {
		authenticate(c, s.identity, s.device.ID, other.proof(requestChallenge(t, c)))
	}

	expectCode(t, whoami(c), CodeAuthRequired)
}

func TestRouterRejectsAmbiguousRoutes(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewRouter() accepted a route that is both public and protected")
		}
	}()
	NewRouter(map[string]Handler{"whoami": Challenge()}, map[string]ProtectedHandler{"whoami": WhoAmI()})
}

func TestUnknownTypeIsUnsupportedRegardlessOfAuthentication(t *testing.T) {
	c := protectedRouter().Conn(testSession(), discard)
	expectCode(t, c.Handle([]byte(`{"type":"unknown","id":"u1","payload":{}}`)), CodeUnsupportedType)
	authenticated(t, c, newSigner(t))
	expectCode(t, c.Handle([]byte(`{"type":"unknown","id":"u1","payload":{}}`)), CodeUnsupportedType)
}

func TestSessionsAreIndependentAcrossRegistries(t *testing.T) {
	registry := auth.NewRegistry(time.Now, nil, testDevices)
	router := protectedRouter()
	s := newSigner(t)
	session := registry.Open()
	authenticated(t, router.Conn(session, discard), s)

	expectCode(t, router.Conn(registry.Open(), discard).Handle([]byte(`{"type":"whoami","id":"w1","payload":{}}`)), CodeAuthRequired)
	if registry.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", registry.Authenticated())
	}
}
