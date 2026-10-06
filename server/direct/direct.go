package direct

import (
	"errors"
	"sync"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

const recentLimit = 256

var (
	ErrUnauthenticated = errors.New("direct: sender not authenticated")
	ErrUnavailable     = errors.New("direct: recipient unavailable")
	ErrNoKey           = errors.New("direct: sender has no published key")
	ErrKeyConflict     = errors.New("direct: identity already bound to another key")
	ErrDuplicate       = errors.New("direct: duplicate message id")
)

type Bundle struct {
	Key       string
	Signature string
}

type Envelope struct {
	Salt       string
	IV         string
	Ciphertext string
}

type Message struct {
	ID       string
	From     string
	Sender   Bundle
	Envelope Envelope
}

type Deliver func(Message) bool

type binding struct {
	bundle   Bundle
	sessions map[*auth.Session]struct{}
}

type recent struct {
	order []string
	seen  map[string]struct{}
}

func (r *recent) add(id string) bool {
	if _, ok := r.seen[id]; ok {
		return false
	}
	if len(r.order) == recentLimit {
		delete(r.seen, r.order[0])
		r.order = r.order[1:]
	}
	r.order = append(r.order, id)
	r.seen[id] = struct{}{}
	return true
}

type Registry struct {
	mu         sync.Mutex
	endpoints  map[*auth.Session]Deliver
	identities map[*auth.Session]string
	recipients map[string]map[*auth.Session]struct{}
	keys       map[string]*binding
	recent     map[*auth.Session]*recent
}

func NewRegistry() *Registry {
	return &Registry{
		endpoints:  make(map[*auth.Session]Deliver),
		identities: make(map[*auth.Session]string),
		recipients: make(map[string]map[*auth.Session]struct{}),
		keys:       make(map[string]*binding),
		recent:     make(map[*auth.Session]*recent),
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
	r.recent[s] = &recent{seen: make(map[string]struct{})}
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

func (r *Registry) Bundle(id identity.Identity) (Bundle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.keys[id.String()]
	if current == nil {
		return Bundle{}, false
	}
	return current.bundle, true
}

func (r *Registry) Send(from *auth.Session, to identity.Identity, id string, envelope Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sender, ok := r.identities[from]
	if !ok {
		return ErrUnauthenticated
	}
	current := r.keys[sender]
	if current == nil || !hasSession(current.sessions, from) {
		return ErrNoKey
	}
	if !r.recent[from].add(id) {
		return ErrDuplicate
	}
	delivered := 0
	msg := Message{ID: id, From: sender, Sender: current.bundle, Envelope: envelope}
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
	delete(r.recent, s)
	delete(r.recipients[key], s)
	if len(r.recipients[key]) == 0 {
		delete(r.recipients, key)
	}
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
