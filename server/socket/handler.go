package socket

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Handler struct {
	hub      *Hub
	upgrader websocket.Upgrader
}

func NewHandler(hub *Hub, allowedOrigins []string) *Handler {
	return &Handler{
		hub: hub,
		upgrader: websocket.Upgrader{
			HandshakeTimeout: 10 * time.Second,
			CheckOrigin:      originChecker(allowedOrigins),
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.hub.accepting(); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	if err := h.hub.attach(conn); err != nil {
		msg := websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "")
		_ = conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(h.hub.opts.WriteTimeout))
		_ = conn.Close()
	}
}

func originChecker(allowed []string) func(*http.Request) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, origin := range allowed {
		set[strings.ToLower(origin)] = struct{}{}
	}

	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return false
		}
		if strings.EqualFold(u.Host, r.Host) {
			return true
		}
		_, ok := set[strings.ToLower(origin)]
		return ok
	}
}
