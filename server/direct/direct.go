package direct

import (
	"errors"
	"sync"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

var (
	ErrUnauthenticated = errors.New("direct: sender not authenticated")
	ErrUnavailable     = errors.New("direct: recipient unavailable")
)

type Message struct {
	From string
	Body string
}

type Deliver func(Message) bool

type Registry struct {
	mu         sync.Mutex
	endpoints  map[*auth.Session]Deliver
	identities map[*auth.Session]string
	recipients map[string]map[*auth.Session]struct{}
}

func NewRegistry() *Registry {
	return &Registry{
		endpoints:  make(map[*auth.Session]Deliver),
		identities: make(map[*auth.Session]string),
		recipients: make(map[string]map[*auth.Session]struct{}),
	}
}

func (r *Registry) Attach(s *auth.Session, deliver Deliver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endpoints[s] = deliver
}

func (r *Registry) Detach(s *auth.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.endpoints, s)
	r.forget(s)
}

func (r *Registry) Authenticated(s *auth.Session, id identity.Identity) {
	key := id.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.identities[s]; ok {
		return
	}
	r.identities[s] = key
	if r.recipients[key] == nil {
		r.recipients[key] = make(map[*auth.Session]struct{})
	}
	r.recipients[key][s] = struct{}{}
}

func (r *Registry) Closed(s *auth.Session, _ identity.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forget(s)
}

func (r *Registry) Send(from *auth.Session, to identity.Identity, body string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sender, ok := r.identities[from]
	if !ok {
		return ErrUnauthenticated
	}
	delivered := 0
	msg := Message{From: sender, Body: body}
	for s := range r.recipients[to.String()] {
		if deliver, ok := r.endpoints[s]; ok && deliver(msg) {
			delivered++
		}
	}
	if delivered == 0 {
		return ErrUnavailable
	}
	return nil
}

func (r *Registry) forget(s *auth.Session) {
	key, ok := r.identities[s]
	if !ok {
		return
	}
	delete(r.identities, s)
	delete(r.recipients[key], s)
	if len(r.recipients[key]) == 0 {
		delete(r.recipients, key)
	}
}
