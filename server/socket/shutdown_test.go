package socket

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func shutdown(t *testing.T, hub *Hub, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return hub.Shutdown(ctx)
}

func TestShutdownClosesClients(t *testing.T) {
	hub, url := startServer(t, testOptions())
	conns := []*websocket.Conn{dial(t, url), dial(t, url), dial(t, url)}
	waitFor(t, "registration", func() bool { return hub.Len() == len(conns) })

	results := make(chan error, len(conns))
	for _, conn := range conns {
		go func() {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					results <- err
					return
				}
			}
		}()
	}

	if err := shutdown(t, hub, 5*time.Second); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	for range conns {
		if err := <-results; !websocket.IsCloseError(err, websocket.CloseGoingAway) {
			t.Errorf("read error = %v, want close code %d", err, websocket.CloseGoingAway)
		}
	}
	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestShutdownRejectsNewConnections(t *testing.T) {
	hub, url := startServer(t, testOptions())
	if err := shutdown(t, hub, time.Second); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	_, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil {
		t.Fatal("dial succeeded after shutdown")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("response = %v, want status %d", resp, http.StatusServiceUnavailable)
	}
	resp.Body.Close()
}

func TestShutdownEmptyHubIsRepeatable(t *testing.T) {
	hub := NewHub(testOptions())
	for range 2 {
		if err := shutdown(t, hub, time.Second); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	}
}

func TestShutdownWaitsForUnresponsivePeer(t *testing.T) {
	opts := testOptions()
	opts.WriteTimeout = 200 * time.Millisecond
	hub, url := startServer(t, opts)
	dial(t, url)
	c := onlyClient(t, hub)

	start := time.Now()
	if err := shutdown(t, hub, 5*time.Second); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown() took %v", elapsed)
	}
	if err := c.Send([]byte("late")); !errors.Is(err, ErrClientClosed) {
		t.Errorf("Send() after shutdown = %v, want %v", err, ErrClientClosed)
	}
}

func TestShutdownForcesCloseOnDeadline(t *testing.T) {
	opts := testOptions()
	opts.WriteTimeout = time.Minute
	hub, url := startServer(t, opts)
	dial(t, url)
	onlyClient(t, hub)

	start := time.Now()
	err := shutdown(t, hub, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown() took %v", elapsed)
	}
	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestShutdownDuringConnects(t *testing.T) {
	hub, url := startServer(t, testOptions())

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
			resp.Body.Close()
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		})
	}

	time.Sleep(10 * time.Millisecond)
	if err := shutdown(t, hub, 5*time.Second); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	wg.Wait()

	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}
