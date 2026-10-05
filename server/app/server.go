package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/config"
	"github.com/Xhaann/ghost-x/server/presence"
	"github.com/Xhaann/ghost-x/server/protocol"
	"github.com/Xhaann/ghost-x/server/socket"
)

type Server struct {
	cfg      config.Config
	hub      *socket.Hub
	sessions *auth.Registry
	presence *presence.Registry
	http     *http.Server
}

type endpoint struct {
	client  *socket.Client
	conn    *protocol.Conn
	session *auth.Session
}

func (e *endpoint) Receive(data []byte) {
	_ = e.client.Send(e.conn.Handle(data))
}

func (e *endpoint) Close() {
	e.session.Close()
}

func New(cfg config.Config) *Server {
	present := presence.NewRegistry()
	sessions := auth.NewRegistry(time.Now, present)
	router := protocol.NewRouter(map[string]protocol.Handler{
		"ping":         protocol.Ping(time.Now),
		"challenge":    protocol.Challenge(),
		"authenticate": protocol.Authenticate(),
	}, map[string]protocol.ProtectedHandler{
		"whoami":   protocol.WhoAmI(),
		"presence": protocol.Presence(present),
	})

	opts := socket.DefaultOptions()
	opts.Accept = func(c *socket.Client) socket.Receiver {
		session := sessions.Open()
		push := func(data []byte) { _ = c.Send(data) }
		return &endpoint{client: c, conn: router.Conn(session, push), session: session}
	}
	hub := socket.NewHub(opts)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.Handle("GET /ws", socket.NewHandler(hub, cfg.AllowedOrigins))

	return &Server{
		cfg:      cfg,
		hub:      hub,
		sessions: sessions,
		presence: present,
		http: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.http.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()

	httpErr := s.http.Shutdown(shutdownCtx)
	hubErr := s.hub.Shutdown(shutdownCtx)

	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return errors.Join(httpErr, hubErr)
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
