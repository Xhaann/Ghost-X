package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Xhaann/ghost-x/server/auth"
)

type key struct {
	private  ed25519.PrivateKey
	identity string
}

func newKey(t *testing.T) key {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key{private: private, identity: base64.RawURLEncoding.EncodeToString(public)}
}

func challenge(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	msg := roundTrip(t, conn, `{"type":"challenge","id":"c1","payload":{}}`)
	if msg.Type != "challenge" {
		t.Fatalf("challenge response = %+v", msg)
	}
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(payload.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func authenticateRequest(k key, nonce []byte) string {
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, auth.Message(nonce)))
	return fmt.Sprintf(`{"type":"authenticate","id":"a1","payload":{"identity":%q,"signature":%q}}`, k.identity, signature)
}

func authenticateConn(t *testing.T, conn *websocket.Conn, k key) {
	t.Helper()
	msg := roundTrip(t, conn, authenticateRequest(k, challenge(t, conn)))
	if msg.Type != "authenticated" || string(msg.Payload) != `{"identity":"`+k.identity+`"}` {
		t.Fatalf("authenticate response = %+v %s", msg, msg.Payload)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func expectError(t *testing.T, msg message, code string) {
	t.Helper()
	if msg.Type != "error" || string(msg.Payload) != `{"code":"`+code+`"}` {
		t.Fatalf("response = %+v %s, want error %s", msg, msg.Payload, code)
	}
}

func TestConnectionAuthenticates(t *testing.T) {
	srv, url := startServer(t)
	conn := dialApp(t, url)
	waitUntil(t, "session", func() bool { return srv.sessions.Len() == 1 })

	if srv.sessions.Authenticated() != 0 {
		t.Fatal("new connection is authenticated")
	}
	authenticateConn(t, conn, newKey(t))
	if srv.sessions.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", srv.sessions.Authenticated())
	}
	if msg := roundTrip(t, conn, pingRequest("p1", 1)); msg.Type != "pong" {
		t.Fatalf("ping after authentication = %+v", msg)
	}
}

func TestProofCannotMoveBetweenConnections(t *testing.T) {
	srv, url := startServer(t)
	first, second := dialApp(t, url), dialApp(t, url)
	k := newKey(t)

	nonce := challenge(t, first)
	challenge(t, second)
	expectError(t, roundTrip(t, second, authenticateRequest(k, nonce)), "authentication_failed")
	if srv.sessions.Authenticated() != 0 {
		t.Fatal("proof from another connection authenticated a session")
	}

	if msg := roundTrip(t, first, authenticateRequest(k, nonce)); msg.Type != "authenticated" {
		t.Fatalf("owning connection response = %+v", msg)
	}
	if srv.sessions.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", srv.sessions.Authenticated())
	}

	authenticateConn(t, second, k)
	if srv.sessions.Authenticated() != 2 {
		t.Fatalf("Authenticated() = %d, want 2", srv.sessions.Authenticated())
	}
}

func TestSessionDestroyedOnDisconnect(t *testing.T) {
	srv, url := startServer(t)
	conn := dialApp(t, url)
	authenticateConn(t, conn, newKey(t))

	conn.Close()

	waitUntil(t, "session removal", func() bool { return srv.sessions.Len() == 0 })
	if srv.sessions.Authenticated() != 0 {
		t.Fatal("authenticated session survived disconnect")
	}
}

func TestReconnectRequiresFreshAuthentication(t *testing.T) {
	srv, url := startServer(t)
	k := newKey(t)
	first := dialApp(t, url)
	nonce := challenge(t, first)
	request := authenticateRequest(k, nonce)
	if msg := roundTrip(t, first, request); msg.Type != "authenticated" {
		t.Fatalf("first authentication = %+v", msg)
	}
	first.Close()
	waitUntil(t, "session removal", func() bool { return srv.sessions.Len() == 0 })

	second := dialApp(t, url)
	waitUntil(t, "new session", func() bool { return srv.sessions.Len() == 1 })
	if srv.sessions.Authenticated() != 0 {
		t.Fatal("reconnected connection inherited authentication")
	}
	expectError(t, roundTrip(t, second, request), "authentication_failed")

	authenticateConn(t, second, k)
	if srv.sessions.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", srv.sessions.Authenticated())
	}
}

func TestSameIdentityOnMultipleConnections(t *testing.T) {
	srv, url := startServer(t)
	k := newKey(t)
	first, second := dialApp(t, url), dialApp(t, url)

	authenticateConn(t, first, k)
	authenticateConn(t, second, k)
	if srv.sessions.Authenticated() != 2 {
		t.Fatalf("Authenticated() = %d, want 2", srv.sessions.Authenticated())
	}

	first.Close()
	waitUntil(t, "first session removal", func() bool { return srv.sessions.Len() == 1 })
	if srv.sessions.Authenticated() != 1 {
		t.Fatal("closing one connection destroyed another session")
	}
	if msg := roundTrip(t, second, pingRequest("p1", 1)); msg.Type != "pong" {
		t.Fatalf("remaining connection = %+v", msg)
	}
}

func serveDirect(t *testing.T) (*Server, string, context.CancelFunc, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := New(testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	return srv, "ws://" + ln.Addr().String() + "/ws", cancel, done
}

func drain(conn *websocket.Conn) {
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

func openSessions(t *testing.T, srv *Server, url string) []*websocket.Conn {
	t.Helper()
	k := newKey(t)
	var conns []*websocket.Conn
	for range 3 {
		conn := dialApp(t, url)
		authenticateConn(t, conn, k)
		conns = append(conns, conn)
	}
	pending := dialApp(t, url)
	challenge(t, pending)
	conns = append(conns, pending)
	waitUntil(t, "sessions", func() bool { return srv.sessions.Len() == 4 })
	if srv.sessions.Authenticated() != 3 {
		t.Fatalf("Authenticated() = %d, want 3", srv.sessions.Authenticated())
	}
	return conns
}

func TestShutdownDestroysSessions(t *testing.T) {
	srv, url, cancel, done := serveDirect(t)
	for _, conn := range openSessions(t, srv, url) {
		conn.SetReadDeadline(time.Time{})
		drain(conn)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if srv.sessions.Len() != 0 || srv.sessions.Authenticated() != 0 {
		t.Fatalf("Len() = %d, Authenticated() = %d after shutdown", srv.sessions.Len(), srv.sessions.Authenticated())
	}
}

func TestForcedShutdownDestroysSessions(t *testing.T) {
	srv, url, cancel, done := serveDirect(t)
	openSessions(t, srv, url)

	cancel()
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if srv.sessions.Len() != 0 || srv.sessions.Authenticated() != 0 {
		t.Fatalf("Len() = %d, Authenticated() = %d after forced shutdown", srv.sessions.Len(), srv.sessions.Authenticated())
	}
}

func TestConcurrentAuthenticationAndDisconnect(t *testing.T) {
	srv, url := startServer(t)
	k := newKey(t)

	var wg sync.WaitGroup
	for i := range 30 {
		wg.Go(func() {
			conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			defer conn.Close()
			nonce := challengeOrFail(conn)
			if nonce == nil {
				t.Error("challenge failed")
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(authenticateRequest(k, nonce))); err != nil {
				t.Error(err)
				return
			}
			if i%2 == 0 {
				return
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, data, err := conn.ReadMessage(); err != nil || !json.Valid(data) {
				t.Errorf("authenticate reply %q: %v", data, err)
			}
		})
	}
	wg.Wait()

	waitUntil(t, "all sessions removed", func() bool { return srv.sessions.Len() == 0 })
	if srv.sessions.Authenticated() != 0 {
		t.Fatal("authenticated sessions survived disconnect")
	}
}

func challengeOrFail(conn *websocket.Conn) []byte {
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"challenge","id":"c1","payload":{}}`)); err != nil {
		return nil
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		return nil
	}
	var msg struct {
		Payload struct {
			Nonce string `json:"nonce"`
		} `json:"payload"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return nil
	}
	nonce, err := base64.RawURLEncoding.DecodeString(msg.Payload.Nonce)
	if err != nil {
		return nil
	}
	return nonce
}

func TestProtectedOperationBoundToConnection(t *testing.T) {
	_, url := startServer(t)
	k := newKey(t)
	other := newKey(t)
	first, second, third := dialApp(t, url), dialApp(t, url), dialApp(t, url)

	expectError(t, roundTrip(t, first, `{"type":"whoami","id":"w1","payload":{}}`), "authentication_required")

	authenticateConn(t, first, k)
	authenticateConn(t, second, other)

	for conn, want := range map[*websocket.Conn]string{first: k.identity, second: other.identity} {
		msg := roundTrip(t, conn, `{"type":"whoami","id":"w1","payload":{}}`)
		if msg.Type != "whoami" || string(msg.Payload) != `{"identity":"`+want+`"}` {
			t.Fatalf("whoami = %+v %s, want %s", msg, msg.Payload, want)
		}
	}
	expectError(t, roundTrip(t, third, `{"type":"whoami","id":"w1","payload":{}}`), "authentication_required")
}

func TestProtectedOperationRequiresReauthenticationAfterReconnect(t *testing.T) {
	srv, url := startServer(t)
	k := newKey(t)
	first := dialApp(t, url)
	authenticateConn(t, first, k)
	first.Close()
	waitUntil(t, "session removal", func() bool { return srv.sessions.Len() == 0 })

	second := dialApp(t, url)
	expectError(t, roundTrip(t, second, `{"type":"whoami","id":"w1","payload":{}}`), "authentication_required")
	authenticateConn(t, second, k)
	if msg := roundTrip(t, second, `{"type":"whoami","id":"w2","payload":{}}`); msg.Type != "whoami" {
		t.Fatalf("whoami after re-authentication = %+v", msg)
	}
}
