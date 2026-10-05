package socket

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

var (
	ErrClientClosed  = errors.New("socket: client closed")
	ErrSendQueueFull = errors.New("socket: send queue full")
)

type Client struct {
	id        string
	hub       *Hub
	conn      *websocket.Conn
	send      chan []byte
	done      chan struct{}
	readDone  chan struct{}
	closeOnce sync.Once
	closeCode int
	closeText string
}

func newClient(h *Hub, conn *websocket.Conn) *Client {
	return &Client{
		id:       rand.Text(),
		hub:      h,
		conn:     conn,
		send:     make(chan []byte, h.opts.SendQueueSize),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}
}

func (c *Client) ID() string {
	return c.id
}

func (c *Client) Done() <-chan struct{} {
	return c.done
}

func (c *Client) Send(data []byte) error {
	select {
	case <-c.done:
		return ErrClientClosed
	default:
	}
	select {
	case c.send <- data:
		return nil
	default:
		c.Close(websocket.ClosePolicyViolation, "send queue full")
		return ErrSendQueueFull
	}
}

func (c *Client) Close(code int, text string) {
	c.closeOnce.Do(func() {
		c.closeCode = code
		c.closeText = text
		close(c.done)
	})
}

func (c *Client) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *Client) readLoop() {
	defer c.hub.wg.Done()
	defer c.hub.unregister(c)
	defer close(c.readDone)

	c.conn.SetReadLimit(c.hub.opts.MaxMessageSize)
	for {
		kind, data, err := c.conn.ReadMessage()
		if err != nil {
			c.Close(websocket.CloseNormalClosure, "")
			return
		}
		if c.closed() {
			continue
		}
		if kind != websocket.TextMessage {
			c.Close(websocket.CloseUnsupportedData, "text messages only")
			continue
		}
		if !utf8.Valid(data) {
			c.Close(websocket.CloseInvalidFramePayloadData, "invalid utf-8")
			continue
		}
		if c.hub.opts.OnMessage != nil {
			c.hub.opts.OnMessage(c, data)
		}
	}
}

func (c *Client) writeLoop() {
	defer c.hub.wg.Done()
	defer c.conn.Close()

	for {
		select {
		case data := <-c.send:
			if err := c.write(websocket.TextMessage, data); err != nil {
				c.Close(websocket.CloseGoingAway, "")
				return
			}
		case <-c.done:
			c.finish()
			return
		}
	}
}

func (c *Client) write(kind int, data []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.hub.opts.WriteTimeout)); err != nil {
		return err
	}
	return c.conn.WriteMessage(kind, data)
}

func (c *Client) finish() {
	timeout := c.hub.opts.WriteTimeout
	msg := websocket.FormatCloseMessage(c.closeCode, c.closeText)
	_ = c.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(timeout))

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.readDone:
	case <-timer.C:
	}
}
