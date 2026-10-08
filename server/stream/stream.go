package stream

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"
)

const HeaderSize = 4

var (
	ErrClosed       = errors.New("stream: connection closed")
	ErrQueueFull    = errors.New("stream: send queue full")
	ErrFrameSize    = errors.New("stream: invalid frame size")
	ErrShuttingDown = errors.New("stream: shutting down")
)

type Receiver interface {
	Receive(data []byte)
	Close()
}

type Options struct {
	MaxConnections int
	MaxFrameSize   int
	SendQueueSize  int
	WriteTimeout   time.Duration
	FrameTimeout   time.Duration
	Accept         func(c *Conn) Receiver
}

func DefaultOptions() Options {
	return Options{
		MaxConnections: 1000,
		MaxFrameSize:   32 << 10,
		SendQueueSize:  64,
		WriteTimeout:   10 * time.Second,
		FrameTimeout:   10 * time.Second,
	}
}

type Server struct {
	opts      Options
	mu        sync.Mutex
	conns     map[*Conn]struct{}
	listeners map[net.Listener]struct{}
	closing   bool
	wg        sync.WaitGroup
}

func NewServer(opts Options) *Server {
	return &Server{opts: opts, conns: make(map[*Conn]struct{}), listeners: make(map[net.Listener]struct{})}
}

func (s *Server) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		ln.Close()
		return ErrShuttingDown
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			delete(s.listeners, ln)
			s.mu.Unlock()
			if closing {
				return nil
			}
			return err
		}
		s.admit(nc)
	}
}

func (s *Server) admit(nc net.Conn) {
	s.mu.Lock()
	if s.closing || len(s.conns) >= s.opts.MaxConnections {
		s.mu.Unlock()
		nc.Close()
		return
	}
	c := &Conn{
		id:     rand.Text(),
		server: s,
		nc:     nc,
		send:   make(chan []byte, s.opts.SendQueueSize),
		done:   make(chan struct{}),
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	go c.run()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	listeners := make([]net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		listeners = append(listeners, ln)
	}
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, ln := range listeners {
		ln.Close()
	}
	for _, c := range conns {
		c.Close("server shutting down")
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Conn struct {
	id        string
	server    *Server
	nc        net.Conn
	send      chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func (c *Conn) ID() string {
	return c.id
}

func (c *Conn) Done() <-chan struct{} {
	return c.done
}

func (c *Conn) Send(data []byte) error {
	if len(data) == 0 || len(data) > c.server.opts.MaxFrameSize {
		return ErrFrameSize
	}
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	select {
	case c.send <- data:
		return nil
	default:
		c.Close("send queue full")
		return ErrQueueFull
	}
}

func (c *Conn) Close(string) {
	c.closeOnce.Do(func() {
		close(c.done)
		c.nc.Close()
	})
}

func (c *Conn) run() {
	defer c.server.wg.Done()
	var receiver Receiver
	if accept := c.server.opts.Accept; accept != nil {
		receiver = accept(c)
	}
	writer := make(chan struct{})
	go func() {
		defer close(writer)
		c.writeLoop()
	}()
	c.readLoop(receiver)
	c.Close("")
	<-writer
	if receiver != nil {
		receiver.Close()
	}
	c.server.mu.Lock()
	delete(c.server.conns, c)
	c.server.mu.Unlock()
}

func (c *Conn) readLoop(receiver Receiver) {
	header := make([]byte, HeaderSize)
	for {
		c.nc.SetReadDeadline(time.Time{})
		if _, err := io.ReadFull(c.nc, header); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header)
		if size == 0 || uint64(size) > uint64(c.server.opts.MaxFrameSize) {
			return
		}
		c.nc.SetReadDeadline(time.Now().Add(c.server.opts.FrameTimeout))
		frame := make([]byte, size)
		if _, err := io.ReadFull(c.nc, frame); err != nil {
			return
		}
		if !utf8.Valid(frame) {
			return
		}
		select {
		case <-c.done:
			return
		default:
		}
		if receiver != nil {
			receiver.Receive(frame)
		}
	}
}

func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.done:
			return
		case data := <-c.send:
			c.nc.SetWriteDeadline(time.Now().Add(c.server.opts.WriteTimeout))
			if _, err := c.nc.Write(Encode(data)); err != nil {
				c.Close("")
				return
			}
		}
	}
}

func Encode(frame []byte) []byte {
	out := make([]byte, HeaderSize+len(frame))
	binary.BigEndian.PutUint32(out, uint32(len(frame)))
	copy(out[HeaderSize:], frame)
	return out
}
