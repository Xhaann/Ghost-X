package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	ChallengeSize = 32
	ChallengeTTL  = 30 * time.Second
	MaxFailures   = 3
	DeviceIDSize  = 16
)

const context = "ghostx/session/authenticate/v2\x00"

var (
	ErrFailed          = errors.New("auth: authentication failed")
	ErrInvalidIdentity = errors.New("auth: invalid identity")
	ErrClosed          = errors.New("auth: session closed")
)

type State int

const (
	Unauthenticated State = iota
	Challenged
	Authenticated
	Failed
	Closed
)

func Message(nonce, owner, device []byte) []byte {
	out := make([]byte, 0, len(context)+len(nonce)+len(owner)+len(device))
	out = append(out, context...)
	out = append(out, nonce...)
	out = append(out, owner...)
	return append(out, device...)
}

type Devices interface {
	Admit(session any, owner identity.Identity, device string, verify func(identity.Identity) bool) error
	Release(session any)
}

type Observer interface {
	Authenticated(s *Session, id identity.Identity, device string)
	Closed(s *Session, id identity.Identity)
}

type Registry struct {
	now      func() time.Time
	observer Observer
	devices  Devices
	mu       sync.Mutex
	sessions map[*Session]struct{}
}

func NewRegistry(now func() time.Time, observer Observer, devices Devices) *Registry {
	return &Registry{now: now, observer: observer, devices: devices, sessions: make(map[*Session]struct{})}
}

func (r *Registry) Open() *Session {
	s := &Session{registry: r}
	r.mu.Lock()
	r.sessions[s] = struct{}{}
	r.mu.Unlock()
	return s
}

func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

func (r *Registry) Authenticated() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for s := range r.sessions {
		if s.State() == Authenticated {
			n++
		}
	}
	return n
}

func (r *Registry) remove(s *Session) {
	r.mu.Lock()
	delete(r.sessions, s)
	r.mu.Unlock()
}

type Session struct {
	registry *Registry
	mu       sync.Mutex
	state    State
	nonce    []byte
	expires  time.Time
	identity identity.Identity
	device   string
	failures int
}

func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Session) Identity() (identity.Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identity, s.state == Authenticated
}

func (s *Session) Device() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.device, s.state == Authenticated
}

func (s *Session) Challenge() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return nil, err
	}
	nonce := make([]byte, ChallengeSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	s.nonce = nonce
	s.expires = s.registry.now().Add(ChallengeTTL)
	s.state = Challenged
	return append([]byte(nil), nonce...), nil
}

func (s *Session) Authenticate(encoded, device, signature string) (identity.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return identity.Identity{}, err
	}

	nonce, expires := s.nonce, s.expires
	s.nonce = nil

	id, err := identity.Parse(encoded)
	deviceRaw, deviceErr := base64.RawURLEncoding.Strict().DecodeString(device)
	if err != nil || deviceErr != nil || len(deviceRaw) != DeviceIDSize || len(device) != base64.RawURLEncoding.EncodedLen(DeviceIDSize) {
		s.fail()
		return identity.Identity{}, ErrInvalidIdentity
	}
	if nonce == nil || !s.registry.now().Before(expires) || s.registry.devices == nil {
		s.fail()
		return identity.Identity{}, ErrFailed
	}
	owner, _ := base64.RawURLEncoding.DecodeString(encoded)
	message := Message(nonce, owner, deviceRaw)
	admitted := s.registry.devices.Admit(s, id, device, func(key identity.Identity) bool {
		return key.Verify(message, signature) == nil
	})
	if admitted != nil {
		s.fail()
		return identity.Identity{}, ErrFailed
	}

	s.state = Authenticated
	s.identity = id
	s.device = device
	if s.registry.observer != nil {
		s.registry.observer.Authenticated(s, id, device)
	}
	return id, nil
}

func (s *Session) Close() {
	s.mu.Lock()
	if s.state == Closed {
		s.mu.Unlock()
		return
	}
	wasAuthenticated, id := s.state == Authenticated, s.identity
	s.state = Closed
	s.nonce = nil
	s.identity = identity.Identity{}
	s.device = ""
	if wasAuthenticated && s.registry.devices != nil {
		s.registry.devices.Release(s)
	}
	if wasAuthenticated && s.registry.observer != nil {
		s.registry.observer.Closed(s, id)
	}
	s.mu.Unlock()
	s.registry.remove(s)
}

func (s *Session) open() error {
	switch s.state {
	case Closed:
		return ErrClosed
	case Authenticated, Failed:
		return ErrFailed
	}
	return nil
}

func (s *Session) fail() {
	s.failures++
	if s.failures >= MaxFailures {
		s.state = Failed
	} else {
		s.state = Unauthenticated
	}
}
