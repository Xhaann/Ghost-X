package socket

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func heartbeatOptions() Options {
	opts := testOptions()
	opts.PingInterval = 20 * time.Millisecond
	opts.PongTimeout = 100 * time.Millisecond
	return opts
}

func readUntilError(conn *websocket.Conn) <-chan error {
	errc := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				errc <- err
				return
			}
		}
	}()
	return errc
}

func TestHeartbeatKeepsHealthyClient(t *testing.T) {
	hub, url := startServer(t, heartbeatOptions())
	conn := dial(t, url)

	var pings atomic.Int64
	conn.SetPingHandler(func(data string) error {
		pings.Add(1)
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	readUntilError(conn)
	onlyClient(t, hub)

	time.Sleep(500 * time.Millisecond)

	if got := hub.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
	if got := pings.Load(); got < 5 {
		t.Errorf("pings = %d, want at least 5", got)
	}
}

func TestHeartbeatRemovesStaleClient(t *testing.T) {
	hub, url := startServer(t, heartbeatOptions())
	conn := dial(t, url)

	var pings atomic.Int64
	conn.SetPingHandler(func(string) error {
		pings.Add(1)
		return nil
	})
	errc := readUntilError(conn)
	c := onlyClient(t, hub)

	waitFor(t, "stale client removal", func() bool { return hub.Len() == 0 })
	<-c.Done()

	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("stale connection was not closed")
	}
	if pings.Load() == 0 {
		t.Error("no pings received before removal")
	}
}

func TestHeartbeatRemovesUnresponsivePeer(t *testing.T) {
	hub, url := startServer(t, heartbeatOptions())
	dial(t, url)
	c := onlyClient(t, hub)

	waitFor(t, "unresponsive peer removal", func() bool { return hub.Len() == 0 })
	<-c.Done()
}
