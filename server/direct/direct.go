package direct

import (
	"errors"
	"sync"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

var (
	ErrUnauthenticated = errors.New("direct: sender not authenticated")
	ErrKeyConflict     = errors.New("direct: identity already bound to another key")
)

type Bundle struct {
	Key       string
	Signature string
}

type binding struct {
	bundle   Bundle
	sessions map[*auth.Session]struct{}
}

type Registry struct {
	mu         sync.Mutex
	identities map[*auth.Session]string
	keys       map[string]*binding
}

func NewRegistry() *Registry {
	return &Registry{
		identities: make(map[*auth.Session]string),
		keys:       make(map[string]*binding),
	}
}

func (r *Registry) Detach(s *auth.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forget(s)
}

func (r *Registry) Authenticated(s *auth.Session, id identity.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.identities[s]; !ok {
		r.identities[s] = id.String()
	}
}

func (r *Registry) Closed(s *auth.Session, _ identity.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forget(s)
}

func (r *Registry) Publish(s *auth.Session, bundle Bundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	current := r.keys[owner]
	switch {
	case current == nil:
		r.keys[owner] = &binding{bundle: bundle, sessions: map[*auth.Session]struct{}{s: {}}}
	case current.bundle.Key == bundle.Key:
		current.sessions[s] = struct{}{}
	case len(current.sessions) == 1 && hasSession(current.sessions, s):
		current.bundle = bundle
	default:
		return ErrKeyConflict
	}
	return nil
}

func (r *Registry) Static(s *auth.Session) (Bundle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.identities[s]
	if !ok {
		return Bundle{}, false
	}
	current := r.keys[owner]
	if current == nil || !hasSession(current.sessions, s) {
		return Bundle{}, false
	}
	return current.bundle, true
}

func (r *Registry) Bundle(id identity.Identity) (Bundle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.keys[id.String()]
	if current == nil {
		return Bundle{}, false
	}
	return current.bundle, true
}

func (r *Registry) forget(s *auth.Session) {
	key, ok := r.identities[s]
	if !ok {
		return
	}
	delete(r.identities, s)
	if current := r.keys[key]; current != nil {
		delete(current.sessions, s)
		if len(current.sessions) == 0 {
			delete(r.keys, key)
		}
	}
}

func hasSession(sessions map[*auth.Session]struct{}, s *auth.Session) bool {
	_, ok := sessions[s]
	return ok
}
