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

func authenticated(t *testing.T, conn *Conn, s signer) {
	t.Helper()
	resp := decodeResponse(t, authenticate(conn, s.identity, s.sign(auth.Message(requestChallenge(t, conn)))))
	if resp.Type != "authenticated" {
		t.Fatalf("authentication = %+v", resp)
	}
}

func whoami(conn *Conn) []byte {
	return conn.Handle([]byte(`{"type":"whoami","id":"w1","payload":{}}`))
}

func TestProtectedRequiresAuthentication(t *testing.T) {
	conn := protectedRouter().Conn(testSession())

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
	conn := protectedRouter().Conn(testSession())
	s := newSigner(t)
	other := newSigner(t)

	requestChallenge(t, conn)
	expectCode(t, whoami(conn), CodeAuthRequired)

	expectCode(t, authenticate(conn, s.identity, other.sign(auth.Message(requestChallenge(t, conn)))), CodeAuthFailed)
	expectCode(t, whoami(conn), CodeAuthRequired)
}

func TestProtectedReturnsSessionIdentity(t *testing.T) {
	router := protectedRouter()
	s := newSigner(t)
	other := newSigner(t)
	first, second := router.Conn(testSession()), router.Conn(testSession())

	authenticated(t, first, s)
	authenticated(t, second, other)

	for conn, want := range map[*Conn]string{first: s.identity, second: other.identity} {
		resp := decodeResponse(t, whoami(conn))
		if resp.Type != "whoami" || resp.ID != "w1" || string(resp.Payload) != `{"identity":"`+want+`"}` {
			t.Fatalf("whoami = %+v %s, want %s", resp, resp.Payload, want)
		}
	}
	expectCode(t, conn(router).Handle([]byte(`{"type":"whoami","id":"w1","payload":{}}`)), CodeAuthRequired)
}

func conn(r *Router) *Conn {
	return r.Conn(testSession())
}

func TestProtectedValidatesPayloadAfterAuthentication(t *testing.T) {
	c := protectedRouter().Conn(testSession())
	authenticated(t, c, newSigner(t))

	expectCode(t, c.Handle([]byte(`{"type":"whoami","id":"w1","payload":{"x":1}}`)), CodeInvalidPayload)
	expectCode(t, c.Handle([]byte(`{"type":"whoami","id":"w1"}`)), CodeInvalidPayload)
}

func TestProtectedRejectedAfterSessionClose(t *testing.T) {
	session := testSession()
	c := protectedRouter().Conn(session)
	authenticated(t, c, newSigner(t))

	session.Close()

	expectCode(t, whoami(c), CodeAuthRequired)
}

func TestProtectedRejectedAfterLockout(t *testing.T) {
	c := protectedRouter().Conn(testSession())
	s := newSigner(t)
	other := newSigner(t)
	for range auth.MaxFailures {
		authenticate(c, s.identity, other.sign(auth.Message(requestChallenge(t, c))))
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
	c := protectedRouter().Conn(testSession())
	expectCode(t, c.Handle([]byte(`{"type":"unknown","id":"u1","payload":{}}`)), CodeUnsupportedType)
	authenticated(t, c, newSigner(t))
	expectCode(t, c.Handle([]byte(`{"type":"unknown","id":"u1","payload":{}}`)), CodeUnsupportedType)
}

func TestSessionsAreIndependentAcrossRegistries(t *testing.T) {
	registry := auth.NewRegistry(time.Now)
	router := protectedRouter()
	s := newSigner(t)
	session := registry.Open()
	authenticated(t, router.Conn(session), s)

	expectCode(t, router.Conn(registry.Open()).Handle([]byte(`{"type":"whoami","id":"w1","payload":{}}`)), CodeAuthRequired)
	if registry.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", registry.Authenticated())
	}
}
