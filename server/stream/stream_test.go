package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type recorder struct {
	mu     sync.Mutex
	frames [][]byte
	closed int
	conn   *Conn
	echo   bool
}

func (r *recorder) Receive(data []byte) {
	r.mu.Lock()
	r.frames = append(r.frames, append([]byte(nil), data...))
	echo, conn := r.echo, r.conn
	r.mu.Unlock()
	if echo {
		conn.Send(data)
	}
}

func (r *recorder) Close() {
	r.mu.Lock()
	r.closed++
	r.mu.Unlock()
}

func (r *recorder) snapshot() ([][]byte, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.frames...), r.closed
}

func listen(t testing.TB) net.Listener {
	t.Helper()
	dir, err := os.MkdirTemp("", "gx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func serve(t testing.TB, opts Options) (*Server, string, chan *recorder) {
	t.Helper()
	accepted := make(chan *recorder, 64)
	opts.Accept = func(c *Conn) Receiver {
		r := &recorder{conn: c, echo: true}
		accepted <- r
		return r
	}
	s := NewServer(opts)
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return s, ln.Addr().String(), accepted
}

func dial(t testing.TB, path string) net.Conn {
	t.Helper()
	nc, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

func read(t testing.TB, nc net.Conn) []byte {
	t.Helper()
	nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(nc, header); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, binary.BigEndian.Uint32(header))
	if _, err := io.ReadFull(nc, frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

func closedByServer(t testing.TB, nc net.Conn) {
	t.Helper()
	nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := nc.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection still open: %v", err)
	}
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestFramesArriveIntactAndInOrder(t *testing.T) {
	_, path, accepted := serve(t, DefaultOptions())
	nc := dial(t, path)
	frames := []string{`{"type":"ping"}`, "é", string(make([]byte, 32<<10))}
	for _, f := range frames {
		if _, err := nc.Write(Encode([]byte(f))); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range frames {
		if got := read(t, nc); string(got) != want {
			t.Fatalf("echo = %d bytes, want %d", len(got), len(want))
		}
	}
	r := <-accepted
	got, _ := r.snapshot()
	if len(got) != len(frames) {
		t.Fatalf("received %d frames", len(got))
	}
}

func TestMalformedFramesCloseTheConnection(t *testing.T) {
	opts := DefaultOptions()
	opts.FrameTimeout = 100 * time.Millisecond
	_, path, accepted := serve(t, opts)
	oversized := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(oversized, uint32(opts.MaxFrameSize+1))
	huge := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(huge, ^uint32(0))
	for name, data := range map[string][]byte{
		"empty frame":   make([]byte, HeaderSize),
		"oversized":     oversized,
		"huge":          huge,
		"invalid utf-8": Encode([]byte{0xff, 0xfe}),
		"stalled frame": Encode([]byte("abcdef"))[:HeaderSize+2],
	} {
		nc := dial(t, path)
		if _, err := nc.Write(data); err != nil {
			t.Fatal(err)
		}
		closedByServer(t, nc)
		r := <-accepted
		waitFor(t, name+" receiver closed", func() bool {
			_, closed := r.snapshot()
			return closed == 1
		})
		if got, _ := r.snapshot(); len(got) != 0 {
			t.Fatalf("%s delivered %d frames", name, len(got))
		}
	}
}

func TestSendValidatesFramesAndFailsAfterClose(t *testing.T) {
	_, path, accepted := serve(t, DefaultOptions())
	nc := dial(t, path)
	nc.Write(Encode([]byte("x")))
	r := <-accepted
	read(t, nc)
	if err := r.conn.Send(nil); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("empty send = %v", err)
	}
	if err := r.conn.Send(make([]byte, 32<<10+1)); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("oversized send = %v", err)
	}
	r.conn.Close("done")
	r.conn.Close("again")
	if err := r.conn.Send([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatalf("send after close = %v", err)
	}
	closedByServer(t, nc)
}

func TestAFullSendQueueClosesTheConnection(t *testing.T) {
	opts := DefaultOptions()
	opts.SendQueueSize = 2
	opts.WriteTimeout = 30 * time.Second
	_, path, accepted := serve(t, opts)
	nc := dial(t, path)
	nc.Write(Encode([]byte("x")))
	r := <-accepted
	frame := make([]byte, 32<<10)
	var err error
	for range 1000 {
		if err = r.conn.Send(frame); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("unbounded send queue: %v", err)
	}
	closed := time.Now()
	waitFor(t, "receiver closed", func() bool {
		_, n := r.snapshot()
		return n == 1
	})
	if time.Since(closed) > time.Second {
		t.Fatal("a full send queue did not close the connection promptly")
	}
}

func TestConnectionLimit(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxConnections = 2
	s, path, accepted := serve(t, opts)
	for range 2 {
		nc := dial(t, path)
		nc.Write(Encode([]byte("x")))
		read(t, nc)
		<-accepted
	}
	extra := dial(t, path)
	closedByServer(t, extra)
	if s.Len() != 2 {
		t.Fatalf("Len() = %d", s.Len())
	}
}

func TestShutdownReleasesEveryConnection(t *testing.T) {
	before := runtime.NumGoroutine()
	accepted := make(chan *recorder, 16)
	opts := DefaultOptions()
	opts.Accept = func(c *Conn) Receiver {
		r := &recorder{conn: c}
		accepted <- r
		return r
	}
	s := NewServer(opts)
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	var conns []net.Conn
	for range 5 {
		nc := dial(t, ln.Addr().String())
		nc.Write(Encode([]byte("x")))
		conns = append(conns, nc)
	}
	recorders := make([]*recorder, 0, 5)
	for range 5 {
		recorders = append(recorders, <-accepted)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve after shutdown = %v", err)
	}
	for _, nc := range conns {
		closedByServer(t, nc)
	}
	for _, r := range recorders {
		if _, closed := r.snapshot(); closed != 1 {
			t.Fatalf("receiver closed %d times", closed)
		}
	}
	if s.Len() != 0 {
		t.Fatalf("Len() = %d after shutdown", s.Len())
	}
	if err := s.Serve(listen(t)); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("Serve after shutdown = %v", err)
	}
	for _, nc := range conns {
		nc.Close()
	}
	waitFor(t, "goroutines released", func() bool { return runtime.NumGoroutine() <= before+1 })
}

func TestConcurrentSendAndCloseAreSafe(t *testing.T) {
	_, path, accepted := serve(t, DefaultOptions())
	for range 20 {
		nc := dial(t, path)
		nc.Write(Encode([]byte("x")))
		r := <-accepted
		go io.Copy(io.Discard, nc)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 50 {
					r.conn.Send([]byte("payload"))
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.conn.Close("racing")
		}()
		wg.Wait()
		waitFor(t, "receiver closed", func() bool {
			_, closed := r.snapshot()
			return closed == 1
		})
	}
}

func FuzzReadFrames(f *testing.F) {
	f.Add(Encode([]byte(`{"type":"ping","id":"p1","payload":{"sentAt":1}}`)))
	f.Add(append(Encode([]byte("a")), Encode([]byte("bc"))...))
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1})
	f.Add(Encode([]byte{0xc3, 0x28}))
	f.Fuzz(func(t *testing.T, data []byte) {
		client, server := net.Pipe()
		r := &recorder{}
		opts := DefaultOptions()
		opts.FrameTimeout = 50 * time.Millisecond
		s := NewServer(opts)
		c := &Conn{server: s, nc: server, send: make(chan []byte, 1), done: make(chan struct{})}
		finished := make(chan struct{})
		go func() {
			c.readLoop(r)
			close(finished)
		}()
		go func() {
			client.Write(data)
			client.Close()
		}()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("reader did not stop")
		}
		server.Close()
		frames, _ := r.snapshot()
		consumed := 0
		for _, frame := range frames {
			if len(frame) == 0 || len(frame) > opts.MaxFrameSize || !utf8.Valid(frame) {
				t.Fatalf("delivered an invalid frame of %d bytes", len(frame))
			}
			consumed += HeaderSize + len(frame)
		}
		if consumed > len(data) {
			t.Fatal("delivered more than was written")
		}
	})
}
