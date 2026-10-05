package socket

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestReadLifecycle(t *testing.T) {
	received := make(chan []byte, 1)
	opts := testOptions()
	opts.Accept = func(*Client) func([]byte) { return func(data []byte) { received <- data } }
	_, url := startServer(t, opts)
	conn := dial(t, url)

	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if string(got) != "hello" {
			t.Errorf("received %q, want %q", got, "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message not received")
	}
}

func TestWriteLifecycle(t *testing.T) {
	hub, url := startServer(t, testOptions())
	conn := dial(t, url)
	c := onlyClient(t, hub)

	if err := c.Send([]byte("hello")); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if kind != websocket.TextMessage || string(data) != "hello" {
		t.Errorf("read (%d, %q), want (%d, %q)", kind, data, websocket.TextMessage, "hello")
	}
}

func TestServerInitiatedClose(t *testing.T) {
	hub, url := startServer(t, testOptions())
	conn := dial(t, url)
	c := onlyClient(t, hub)

	c.Close(websocket.CloseNormalClosure, "bye")
	expectClose(t, conn, websocket.CloseNormalClosure)
	waitFor(t, "unregistration", func() bool { return hub.Len() == 0 })

	if err := c.Send([]byte("late")); !errors.Is(err, ErrClientClosed) {
		t.Errorf("Send() after close = %v, want %v", err, ErrClientClosed)
	}
}

func TestOversizedMessage(t *testing.T) {
	opts := testOptions()
	opts.MaxMessageSize = 16
	opts.Accept = func(*Client) func([]byte) { return func([]byte) { t.Error("oversized message delivered") } }
	hub, url := startServer(t, opts)
	conn := dial(t, url)
	onlyClient(t, hub)

	if err := conn.WriteMessage(websocket.TextMessage, bytes.Repeat([]byte("a"), 17)); err != nil {
		t.Fatal(err)
	}
	expectClose(t, conn, websocket.CloseMessageTooBig)
	waitFor(t, "unregistration", func() bool { return hub.Len() == 0 })
}

func TestMessageAtSizeLimit(t *testing.T) {
	received := make(chan []byte, 1)
	opts := testOptions()
	opts.MaxMessageSize = 16
	opts.Accept = func(*Client) func([]byte) { return func(data []byte) { received <- data } }
	_, url := startServer(t, opts)
	conn := dial(t, url)

	if err := conn.WriteMessage(websocket.TextMessage, bytes.Repeat([]byte("a"), 16)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if len(got) != 16 {
			t.Errorf("received %d bytes, want 16", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message not received")
	}
}

func TestRejectedPayloads(t *testing.T) {
	tests := []struct {
		name string
		kind int
		data []byte
		code int
	}{
		{"binary", websocket.BinaryMessage, []byte{0x01, 0x02}, websocket.CloseUnsupportedData},
		{"invalid utf-8", websocket.TextMessage, []byte{0xff, 0xfe}, websocket.CloseInvalidFramePayloadData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions()
			opts.Accept = func(*Client) func([]byte) { return func([]byte) { t.Error("rejected payload delivered") } }
			hub, url := startServer(t, opts)
			conn := dial(t, url)
			onlyClient(t, hub)

			if err := conn.WriteMessage(tt.kind, tt.data); err != nil {
				t.Fatal(err)
			}
			expectClose(t, conn, tt.code)
			waitFor(t, "unregistration", func() bool { return hub.Len() == 0 })
		})
	}
}

func TestMalformedFrame(t *testing.T) {
	hub, url := startServer(t, testOptions())
	conn := dial(t, url)
	onlyClient(t, hub)

	unmasked := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if _, err := conn.NetConn().Write(unmasked); err != nil {
		t.Fatal(err)
	}
	expectClose(t, conn, websocket.CloseProtocolError)
	waitFor(t, "unregistration", func() bool { return hub.Len() == 0 })
}

func TestAbruptDisconnect(t *testing.T) {
	hub, url := startServer(t, testOptions())
	conn := dial(t, url)
	c := onlyClient(t, hub)

	conn.NetConn().Close()
	waitFor(t, "unregistration", func() bool { return hub.Len() == 0 })
	<-c.Done()
}

func TestSlowClient(t *testing.T) {
	opts := testOptions()
	opts.SendQueueSize = 1
	opts.WriteTimeout = 200 * time.Millisecond
	hub, url := startServer(t, opts)
	dial(t, url)
	c := onlyClient(t, hub)

	payload := bytes.Repeat([]byte("a"), 64<<10)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := c.Send(payload)
		if errors.Is(err, ErrSendQueueFull) || errors.Is(err, ErrClientClosed) {
			break
		}
		if err != nil {
			t.Fatalf("Send() error = %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("slow client was never cut off")
		}
	}

	waitFor(t, "slow client removal", func() bool { return hub.Len() == 0 })
	<-c.Done()
}

func TestAcceptRunsOncePerConnection(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[*Client]*int)
	opts := testOptions()
	opts.Accept = func(c *Client) func([]byte) {
		n := new(int)
		mu.Lock()
		counts[c] = n
		mu.Unlock()
		return func([]byte) {
			mu.Lock()
			*n++
			mu.Unlock()
		}
	}
	hub, url := startServer(t, opts)
	first := dial(t, url)
	second := dial(t, url)
	waitFor(t, "registration", func() bool { return hub.Len() == 2 })

	for range 3 {
		if err := first.WriteMessage(websocket.TextMessage, []byte("a")); err != nil {
			t.Fatal(err)
		}
	}
	if err := second.WriteMessage(websocket.TextMessage, []byte("b")); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		total := 0
		for _, n := range counts {
			total += *n
		}
		return total == 4
	})
	mu.Lock()
	defer mu.Unlock()
	if len(counts) != 2 {
		t.Fatalf("Accept calls = %d, want 2", len(counts))
	}
	got := []int{}
	for _, n := range counts {
		got = append(got, *n)
	}
	if !(got[0] == 3 && got[1] == 1) && !(got[0] == 1 && got[1] == 3) {
		t.Errorf("per-connection counts = %v, want 3 and 1", got)
	}
}
