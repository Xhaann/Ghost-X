package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/Xhaann/ghost-x/server/config"
	"github.com/Xhaann/ghost-x/server/protocol"
	"github.com/Xhaann/ghost-x/server/socket"
)

type Server struct {
	cfg  config.Config
	hub  *socket.Hub
	http *http.Server
}

func New(cfg config.Config) *Server {
	router := protocol.NewRouter(map[string]protocol.Handler{
		"ping": protocol.Ping(time.Now),
	})

	opts := socket.DefaultOptions()
	opts.OnMessage = func(c *socket.Client, data []byte) {
		_ = c.Send(router.Handle(data))
	}
	hub := socket.NewHub(opts)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.Handle("GET /ws", socket.NewHandler(hub, cfg.AllowedOrigins))

	return &Server{
		cfg: cfg,
		hub: hub,
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
