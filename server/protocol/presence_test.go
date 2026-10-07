package protocol

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/presence"
)

type outbox struct {
	mu       sync.Mutex
	messages []string
}

func (o *outbox) push(data []byte) {
	o.mu.Lock()
	o.messages = append(o.messages, string(data))
	o.mu.Unlock()
}

func (o *outbox) all() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.messages...)
}

type presenceFixture struct {
	router   *Router
	sessions *auth.Registry
	presence *presence.Registry
}

func newPresenceFixture() presenceFixture {
	p := presence.NewRegistry()
	return presenceFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"presence": Presence(p),
		}),
		sessions: auth.NewRegistry(time.Now, p, testDevices),
		presence: p,
	}
}

func (f presenceFixture) conn() (*Conn, *auth.Session, *outbox) {
	out := &outbox{}
	session := f.sessions.Open()
	return f.router.Conn(session, out.push), session, out
}

func event(typ, identity string) string {
	return `{"type":"` + typ + `","payload":{"identity":"` + identity + `"}}`
}

const subscribe = `{"type":"presence","id":"s1","payload":{}}`

func TestPresenceRequiresAuthentication(t *testing.T) {
	f := newPresenceFixture()
	conn, _, out := f.conn()

	expectCode(t, conn.Handle([]byte(subscribe)), CodeAuthRequired)
	requestChallenge(t, conn)
	expectCode(t, conn.Handle([]byte(subscribe)), CodeAuthRequired)

	if len(out.all()) != 0 {
		t.Fatalf("pushed %v to unauthenticated connection", out.all())
	}
	if len(f.presence.Present()) != 0 {
		t.Fatalf("Present() = %v", f.presence.Present())
	}
}

func TestPresenceSubscriptionDeliversSnapshotThenAck(t *testing.T) {
	f := newPresenceFixture()
	conn, _, out := f.conn()
	s := newSigner(t)
	authenticated(t, conn, s)

	resp := decodeResponse(t, conn.Handle([]byte(subscribe)))

	if resp.Type != "presence" || resp.ID != "s1" || string(resp.Payload) != `{}` {
		t.Fatalf("ack = %+v %s", resp, resp.Payload)
	}
	if got := out.all(); len(got) != 1 || got[0] != event("present", s.identity) {
		t.Fatalf("pushed %v", got)
	}
}

func TestPresenceEventsFollowSessions(t *testing.T) {
	f := newPresenceFixture()
	watcher, _, out := f.conn()
	ws := newSigner(t)
	authenticated(t, watcher, ws)
	watcher.Handle([]byte(subscribe))

	k := newSigner(t)
	first, firstSession, _ := f.conn()
	second, secondSession, _ := f.conn()
	authenticated(t, first, k)
	authenticated(t, second, k)
	firstSession.Close()
	secondSession.Close()

	want := []string{event("present", ws.identity), event("present", k.identity), event("absent", k.identity)}
	if got := out.all(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("pushed %v, want %v", got, want)
	}
}

func TestPresenceRejectsForgedPayloads(t *testing.T) {
	f := newPresenceFixture()
	conn, _, out := f.conn()
	s := newSigner(t)
	other := newSigner(t)
	authenticated(t, conn, s)

	for _, input := range []string{
		`{"type":"presence","id":"s1","payload":{"identity":"` + other.identity + `"}}`,
		`{"type":"presence","id":"s1","payload":{"present":true}}`,
		`{"type":"presence","id":"s1","payload":null}`,
		`{"type":"presence","id":"s1"}`,
		`{"type":"presence","id":"s1","payload":[]}`,
	} {
		expectCode(t, conn.Handle([]byte(input)), CodeInvalidPayload)
	}
	if len(out.all()) != 0 {
		t.Fatalf("rejected request subscribed: %v", out.all())
	}
	for _, input := range []string{
		`{"type":"present","id":"p1","payload":{"identity":"` + other.identity + `"}}`,
		`{"type":"absent","id":"p1","payload":{"identity":"` + s.identity + `"}}`,
	} {
		expectCode(t, conn.Handle([]byte(input)), CodeUnsupportedType)
	}
	if got := f.presence.Present(); len(got) != 1 || got[0] != s.identity {
		t.Fatalf("Present() = %v", got)
	}
}

func TestPresenceUsesSessionIdentity(t *testing.T) {
	f := newPresenceFixture()
	conn, _, out := f.conn()
	s := newSigner(t)
	authenticated(t, conn, s)

	conn.Handle([]byte(subscribe))

	for _, msg := range out.all() {
		var decoded struct {
			Payload struct {
				Identity string `json:"identity"`
			} `json:"payload"`
		}
		if err := json.Unmarshal([]byte(msg), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Payload.Identity != s.identity {
			t.Fatalf("event for %q, want only %q", decoded.Payload.Identity, s.identity)
		}
	}
}

func TestPresenceRejectedAfterSessionClose(t *testing.T) {
	f := newPresenceFixture()
	conn, session, out := f.conn()
	authenticated(t, conn, newSigner(t))

	session.Close()

	expectCode(t, conn.Handle([]byte(subscribe)), CodeAuthRequired)
	if len(out.all()) != 0 {
		t.Fatalf("pushed %v after close", out.all())
	}
}

func TestPresenceIsNotDerivedFromConnection(t *testing.T) {
	f := newPresenceFixture()
	for range 5 {
		conn, _, _ := f.conn()
		requestChallenge(t, conn)
	}
	if len(f.presence.Present()) != 0 || f.sessions.Len() != 5 {
		t.Fatalf("Present() = %v, Len() = %d", f.presence.Present(), f.sessions.Len())
	}
}

func FuzzPresenceRequest(f *testing.F) {
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`{"identity":"` + strings.Repeat("A", 43) + `"}`)
	f.Add(`{"present":true,"identity":1}`)
	f.Add(`[` + strings.Repeat(`{}`, 100) + `]`)

	fx := newPresenceFixture()
	s := newSigner(f)
	f.Fuzz(func(t *testing.T, payload string) {
		conn, session, out := fx.conn()
		defer session.Close()
		nonce := requestChallenge(t, conn)
		if resp := decodeResponse(t, authenticate(conn, s.identity, s.device.ID, s.proof(nonce))); resp.Type != "authenticated" {
			t.Fatalf("authentication = %+v", resp)
		}
		reply := conn.Handle([]byte(`{"type":"presence","id":"s1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(reply, &resp); err != nil {
			t.Fatalf("invalid response %q", reply)
		}
		if resp.Type == "presence" {
			if payload != "{}" && strings.TrimSpace(payload) != "{}" {
				var obj map[string]json.RawMessage
				if json.Unmarshal([]byte(payload), &obj) != nil || len(obj) != 0 {
					t.Fatalf("accepted payload %q", payload)
				}
			}
			for _, msg := range out.all() {
				if !strings.Contains(msg, `"identity":"`+s.identity+`"`) {
					t.Fatalf("unexpected event %s", msg)
				}
			}
		} else if len(out.all()) != 0 {
			t.Fatalf("rejected request pushed %v", out.all())
		}
	})
}
