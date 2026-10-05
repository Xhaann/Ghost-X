package socket

import (
	"errors"
	"sync"

	"github.com/gorilla/websocket"
)

var (
	ErrHubClosed = errors.New("socket: hub closed")
	ErrHubFull   = errors.New("socket: connection limit reached")
)

type Hub struct {
	opts    Options
	mu      sync.Mutex
	clients map[*Client]struct{}
	closed  bool
	wg      sync.WaitGroup
}

func NewHub(opts Options) *Hub {
	return &Hub{
		opts:    opts,
		clients: make(map[*Client]struct{}),
	}
}

func (h *Hub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *Hub) accepting() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.admit()
}

func (h *Hub) admit() error {
	if h.closed {
		return ErrHubClosed
	}
	if len(h.clients) >= h.opts.MaxConnections {
		return ErrHubFull
	}
	return nil
}

func (h *Hub) attach(conn *websocket.Conn) error {
	c := newClient(h, conn)
	if err := h.register(c); err != nil {
		return err
	}
	go c.readLoop()
	go c.writeLoop()
	return nil
}

func (h *Hub) register(c *Client) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.admit(); err != nil {
		return err
	}
	h.clients[c] = struct{}{}
	h.wg.Add(2)
	return nil
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}
