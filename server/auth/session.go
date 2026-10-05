package auth

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	ChallengeSize = 32
	ChallengeTTL  = 30 * time.Second
	MaxFailures   = 3
)

const context = "ghostx/session/authenticate/v1\x00"

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

func Message(nonce []byte) []byte {
	return append([]byte(context), nonce...)
}

type Registry struct {
	now      func() time.Time
	mu       sync.Mutex
	sessions map[*Session]struct{}
}

func NewRegistry(now func() time.Time) *Registry {
	return &Registry{now: now, sessions: make(map[*Session]struct{})}
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

func (s *Session) Authenticate(encoded, signature string) (identity.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return identity.Identity{}, err
	}

	nonce, expires := s.nonce, s.expires
	s.nonce = nil

	id, err := identity.Parse(encoded)
	if err != nil {
		s.fail()
		return identity.Identity{}, ErrInvalidIdentity
	}
	if nonce == nil || !s.registry.now().Before(expires) || id.Verify(Message(nonce), signature) != nil {
		s.fail()
		return identity.Identity{}, ErrFailed
	}

	s.state = Authenticated
	s.identity = id
	return id, nil
}

func (s *Session) Close() {
	s.mu.Lock()
	if s.state == Closed {
		s.mu.Unlock()
		return
	}
	s.state = Closed
	s.nonce = nil
	s.identity = identity.Identity{}
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
