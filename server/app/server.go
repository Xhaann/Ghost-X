package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/config"
	"github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/identity"
	"github.com/Xhaann/ghost-x/server/prekey"
	"github.com/Xhaann/ghost-x/server/presence"
	"github.com/Xhaann/ghost-x/server/protocol"
	"github.com/Xhaann/ghost-x/server/queue"
	"github.com/Xhaann/ghost-x/server/socket"
	"github.com/Xhaann/ghost-x/server/stream"
)

const (
	RosterRate          = 5.0
	RosterBurst         = 50.0
	IdentityRosterRate  = 0.1
	IdentityRosterBurst = 6.0
)

type Server struct {
	cfg      config.Config
	hub      *socket.Hub
	stream   *stream.Server
	sessions *auth.Registry
	presence *presence.Registry
	devices  *device.Registry
	queue    *queue.Registry
	http     *http.Server
}

type observers []auth.Observer

func (o observers) Authenticated(s *auth.Session, id identity.Identity, device string) {
	for _, observer := range o {
		observer.Authenticated(s, id, device)
	}
}

func (o observers) Closed(s *auth.Session, id identity.Identity) {
	for _, observer := range o {
		observer.Closed(s, id)
	}
}

type carrier interface {
	Send(data []byte) error
	Close(reason string)
}

type socketCarrier struct {
	client *socket.Client
}

func (c socketCarrier) Send(data []byte) error {
	return c.client.Send(data)
}

func (c socketCarrier) Close(reason string) {
	c.client.Close(websocket.ClosePolicyViolation, reason)
}

type endpoint struct {
	client   carrier
	conn     *protocol.Conn
	session  *auth.Session
	deadline *time.Timer
	devices  *device.Registry
	prekeys  *prekey.Registry
	queue    *queue.Registry
}

func (e *endpoint) Receive(data []byte) {
	_ = e.client.Send(e.conn.Handle(data))
	if e.session.State() == auth.Failed {
		e.client.Close("authentication failed")
	}
}

func (e *endpoint) Close() {
	e.deadline.Stop()
	e.session.Close()
	e.devices.Detach(e.session)
	e.prekeys.Detach(e.session)
	e.queue.Detach(e.session)
}

func New(cfg config.Config) (*Server, error) {
	devices, err := device.Open(cfg.DeviceStore)
	if err != nil {
		return nil, err
	}
	devices.SetLimits(device.Limits{
		Rate:          RosterRate,
		Burst:         RosterBurst,
		IdentityRate:  IdentityRosterRate,
		IdentityBurst: IdentityRosterBurst,
		Now:           time.Now,
	})
	present := presence.NewRegistry()
	prekeys := prekey.NewRegistry(devices.Authorized)
	queued := queue.NewRegistry(time.Now, devices.Authorized)
	devices.OnRevoke(func(owner, id string) {
		prekeys.RemoveDevice(owner, id)
		queued.RemoveDevice(owner, id)
	})
	sessions := auth.NewRegistry(time.Now, observers{present, prekeys, queued}, devices)
	router := protocol.NewRouter(map[string]protocol.Handler{
		"ping":         protocol.Ping(time.Now),
		"challenge":    protocol.Challenge(),
		"authenticate": protocol.Authenticate(),
		"register":     protocol.Register(devices),
		"devices":      protocol.Devices(devices),
	}, map[string]protocol.ProtectedHandler{
		"whoami":   protocol.WhoAmI(),
		"presence": protocol.Presence(present),
		"send":     protocol.Send(queued),
		"fetch":    protocol.Fetch(queued),
		"ack":      protocol.Ack(queued),
		"clear":    protocol.Clear(queued),
		"prekeys":  protocol.Prekeys(devices, prekeys),
		"bundle":   protocol.FetchBundle(prekeys),
		"initiate": protocol.Initiate(devices, prekeys),
		"accept":   protocol.Accept(prekeys),
	})

	timeout := cfg.AuthTimeout
	if timeout <= 0 {
		timeout = config.DefaultAuthTimeout
	}
	accept := func(c carrier) *endpoint {
		session := sessions.Open()
		deadline := time.AfterFunc(timeout, func() {
			if session.Expire() {
				c.Close("authentication timeout")
			}
		})
		push := func(data []byte) { _ = c.Send(data) }
		devices.Attach(session, func() {
			session.Close()
			c.Close("device revoked")
		})
		queued.Attach(session, func(p queue.Push) bool {
			return c.Send(protocol.EncodePush(p)) == nil
		})
		prekeys.Attach(session, func(e prekey.Event) bool {
			return c.Send(protocol.EncodeEvent(e)) == nil
		})
		return &endpoint{client: c, conn: router.Conn(session, push), session: session, deadline: deadline, devices: devices, prekeys: prekeys, queue: queued}
	}
	opts := socket.DefaultOptions()
	opts.Accept = func(c *socket.Client) socket.Receiver {
		return accept(socketCarrier{client: c})
	}
	hub := socket.NewHub(opts)
	local := stream.DefaultOptions()
	local.Accept = func(c *stream.Conn) stream.Receiver {
		return accept(c)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.Handle("GET /ws", socket.NewHandler(hub, cfg.AllowedOrigins))

	return &Server{
		cfg:      cfg,
		hub:      hub,
		stream:   stream.NewServer(local),
		sessions: sessions,
		presence: present,
		devices:  devices,
		queue:    queued,
		http: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	if s.cfg.LocalSocket != "" {
		local, err := listenLocal(s.cfg.LocalSocket)
		if err != nil {
			ln.Close()
			return err
		}
		defer os.Remove(s.cfg.LocalSocket)
		go s.stream.Serve(local)
	}
	return s.Serve(ctx, ln)
}

func listenLocal(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("local socket %q exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
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
	streamErr := s.stream.Shutdown(shutdownCtx)

	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return errors.Join(httpErr, hubErr, streamErr)
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
