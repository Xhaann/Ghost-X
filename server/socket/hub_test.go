package socket

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testOptions() Options {
	opts := DefaultOptions()
	opts.WriteTimeout = time.Second
	return opts
}

func startServer(t *testing.T, opts Options, origins ...string) (*Hub, string) {
	t.Helper()
	hub := NewHub(opts)
	srv := httptest.NewServer(NewHandler(hub, origins))
	t.Cleanup(srv.Close)
	return hub, "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp.Body.Close()
	t.Cleanup(func() { conn.Close() })
	return conn
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func onlyClient(t *testing.T, hub *Hub) *Client {
	t.Helper()
	waitFor(t, "registration", func() bool { return hub.Len() == 1 })
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for c := range hub.clients {
		return c
	}
	return nil
}

func expectClose(t *testing.T, conn *websocket.Conn, code int) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		if !websocket.IsCloseError(err, code) {
			t.Fatalf("read error = %v, want close code %d", err, code)
		}
		return
	}
}

func TestRegisterAndUnregister(t *testing.T) {
	hub, url := startServer(t, testOptions())
	conn := dial(t, url)

	c := onlyClient(t, hub)
	if c.ID() == "" {
		t.Error("client ID is empty")
	}

	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	if err := conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unregistration", func() bool { return hub.Len() == 0 })
	<-c.Done()
}

func TestClientIDsAreUnique(t *testing.T) {
	hub, url := startServer(t, testOptions())
	dial(t, url)
	dial(t, url)
	waitFor(t, "registration", func() bool { return hub.Len() == 2 })

	hub.mu.Lock()
	defer hub.mu.Unlock()
	ids := make(map[string]struct{})
	for c := range hub.clients {
		ids[c.ID()] = struct{}{}
	}
	if len(ids) != 2 {
		t.Errorf("unique IDs = %d, want 2", len(ids))
	}
}

func TestConcurrentConnections(t *testing.T) {
	const n = 50
	var received atomic.Int64
	opts := testOptions()
	opts.Accept = func(*Client) func([]byte) { return func([]byte) { received.Add(1) } }
	hub, url := startServer(t, opts)

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
			defer conn.Close()
			if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				errs <- err
				return
			}
			msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
			if err := conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second)); err != nil {
				errs <- err
				return
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	waitFor(t, "all clients to unregister", func() bool { return hub.Len() == 0 })
	if got := received.Load(); got != n {
		t.Errorf("received = %d, want %d", got, n)
	}
}

func TestConcurrentRegisterUnregister(t *testing.T) {
	hub := NewHub(testOptions())
	clients := make([]*Client, 100)
	for i := range clients {
		clients[i] = &Client{}
	}

	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Go(func() {
			if err := hub.register(c); err != nil {
				t.Error(err)
				return
			}
			hub.Len()
			hub.unregister(c)
		})
	}
	wg.Wait()

	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestRegisterRejected(t *testing.T) {
	opts := testOptions()
	opts.MaxConnections = 1
	hub := NewHub(opts)

	if err := hub.register(&Client{}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := hub.register(&Client{}); !errors.Is(err, ErrHubFull) {
		t.Errorf("register when full = %v, want %v", err, ErrHubFull)
	}

	hub.closed = true
	if err := hub.register(&Client{}); !errors.Is(err, ErrHubClosed) {
		t.Errorf("register when closed = %v, want %v", err, ErrHubClosed)
	}
}

func TestUnregisterUnknownClient(t *testing.T) {
	hub := NewHub(testOptions())
	hub.unregister(&Client{})
	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestConnectionLimit(t *testing.T) {
	opts := testOptions()
	opts.MaxConnections = 1
	hub, url := startServer(t, opts)
	dial(t, url)
	onlyClient(t, hub)

	_, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil {
		t.Fatal("dial succeeded beyond connection limit")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("response = %v, want status %d", resp, http.StatusServiceUnavailable)
	}
	resp.Body.Close()
}
