package app

import (
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type feed struct {
	messages chan message
}

func subscribe(t *testing.T, conn *websocket.Conn) *feed {
	t.Helper()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"presence","id":"s1","payload":{}}`)); err != nil {
		t.Fatal(err)
	}
	f := &feed{messages: make(chan message, 256)}
	go func() {
		defer close(f.messages)
		conn.SetReadDeadline(time.Time{})
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg message
			if json.Unmarshal(data, &msg) != nil {
				return
			}
			f.messages <- msg
		}
	}()
	return f
}

func (f *feed) next(t *testing.T) message {
	t.Helper()
	select {
	case msg, ok := <-f.messages:
		if !ok {
			t.Fatal("presence feed closed")
		}
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for presence event")
	}
	return message{}
}

func (f *feed) expect(t *testing.T, typ, identity string) {
	t.Helper()
	msg := f.next(t)
	if msg.Type != typ || msg.ID != "" || string(msg.Payload) != `{"identity":"`+identity+`"}` {
		t.Fatalf("event = %+v %s, want %s %s", msg, msg.Payload, typ, identity)
	}
}

func (f *feed) expectAck(t *testing.T) {
	t.Helper()
	if msg := f.next(t); msg.Type != "presence" || msg.ID != "s1" || string(msg.Payload) != `{}` {
		t.Fatalf("ack = %+v %s", msg, msg.Payload)
	}
}

func watch(t *testing.T, url string) (*feed, key) {
	t.Helper()
	k := newKey(t)
	conn := dialApp(t, url)
	authenticateConn(t, conn, k)
	f := subscribe(t, conn)
	f.expect(t, "present", k.identity)
	f.expectAck(t)
	return f, k
}

func TestPresenceLifecycleOverWebSocket(t *testing.T) {
	srv, url := startServer(t)
	f, watcher := watch(t, url)
	k := newKey(t)

	unauthenticated := dialApp(t, url)
	challenge(t, unauthenticated)

	first := dialApp(t, url)
	authenticateConn(t, first, k)
	f.expect(t, "present", k.identity)

	second := dialApp(t, url)
	authenticateConn(t, second, k)
	first.Close()
	waitUntil(t, "first session removal", func() bool { return srv.sessions.Len() == 3 })
	if !slices.Contains(srv.presence.Present(), k.identity) {
		t.Fatal("identity absent while a session remains")
	}
	second.Close()
	f.expect(t, "absent", k.identity)

	if got := srv.presence.Present(); !slices.Equal(got, []string{watcher.identity}) {
		t.Fatalf("Present() = %v", got)
	}
}

func TestPresenceReturnsAfterReconnect(t *testing.T) {
	srv, url := startServer(t)
	f, _ := watch(t, url)
	k := newKey(t)

	conn := dialApp(t, url)
	authenticateConn(t, conn, k)
	f.expect(t, "present", k.identity)
	conn.Close()
	f.expect(t, "absent", k.identity)

	reconnected := dialApp(t, url)
	challenge(t, reconnected)
	waitUntil(t, "new session", func() bool { return srv.sessions.Len() == 2 })
	if slices.Contains(srv.presence.Present(), k.identity) {
		t.Fatal("presence restored before authentication")
	}
	authenticateConn(t, reconnected, k)
	f.expect(t, "present", k.identity)
}

func TestPresenceRejectsClientClaims(t *testing.T) {
	srv, url := startServer(t)
	k := newKey(t)
	other := newKey(t)

	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, `{"type":"presence","id":"s1","payload":{}}`), "authentication_required")
	expectError(t, roundTrip(t, conn, `{"type":"present","id":"p1","payload":{"identity":"`+other.identity+`"}}`), "unsupported_type")

	authenticateConn(t, conn, k)
	expectError(t, roundTrip(t, conn, `{"type":"presence","id":"s1","payload":{"identity":"`+other.identity+`"}}`), "invalid_payload")
	expectError(t, roundTrip(t, conn, `{"type":"absent","id":"p1","payload":{"identity":"`+k.identity+`"}}`), "unsupported_type")

	if got := srv.presence.Present(); !slices.Equal(got, []string{k.identity}) {
		t.Fatalf("Present() = %v", got)
	}
}

func TestPresenceConcurrentSessionsOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	f, _ := watch(t, url)
	k := newKey(t)

	conns := make([]*websocket.Conn, 20)
	var wg sync.WaitGroup
	for i := range conns {
		wg.Go(func() {
			conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			nonce := challengeOrFail(conn)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(authenticateRequest(k, nonce))); err != nil {
				t.Error(err)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, _, err := conn.ReadMessage(); err != nil {
				t.Error(err)
			}
			conns[i] = conn
		})
	}
	wg.Wait()
	f.expect(t, "present", k.identity)

	for _, conn := range conns {
		wg.Go(func() { conn.Close() })
	}
	wg.Wait()
	f.expect(t, "absent", k.identity)
}

func TestShutdownClearsPresence(t *testing.T) {
	srv, url, cancel, done := serveDirect(t)
	k := newKey(t)
	for range 2 {
		conn := dialApp(t, url)
		authenticateConn(t, conn, k)
		drain(conn)
	}
	watcher := dialApp(t, url)
	authenticateConn(t, watcher, newKey(t))
	subscribe(t, watcher)
	waitUntil(t, "presence", func() bool { return len(srv.presence.Present()) == 2 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if got := srv.presence.Present(); len(got) != 0 {
		t.Fatalf("Present() after shutdown = %v", got)
	}
}
