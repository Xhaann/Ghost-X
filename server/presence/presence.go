package presence

import (
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

var ErrNotPresent = errors.New("presence: session not present")

type Event struct {
	Identity string
	Present  bool
}

type Registry struct {
	mu          sync.Mutex
	sessions    map[*auth.Session]string
	identities  map[string]int
	subscribers map[*auth.Session]func(Event)
}

func NewRegistry() *Registry {
	return &Registry{
		sessions:    make(map[*auth.Session]string),
		identities:  make(map[string]int),
		subscribers: make(map[*auth.Session]func(Event)),
	}
}

func (r *Registry) Authenticated(s *auth.Session, id identity.Identity) {
	key := id.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[s]; ok {
		return
	}
	r.sessions[s] = key
	r.identities[key]++
	if r.identities[key] == 1 {
		r.broadcast(Event{Identity: key, Present: true})
	}
}

func (r *Registry) Closed(s *auth.Session, _ identity.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.sessions[s]
	if !ok {
		return
	}
	delete(r.sessions, s)
	delete(r.subscribers, s)
	r.identities[key]--
	if r.identities[key] == 0 {
		delete(r.identities, key)
		r.broadcast(Event{Identity: key, Present: false})
	}
}

func (r *Registry) Subscribe(s *auth.Session, deliver func(Event)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[s]; !ok {
		return ErrNotPresent
	}
	if _, ok := r.subscribers[s]; ok {
		return nil
	}
	r.subscribers[s] = deliver
	for _, key := range slices.Sorted(maps.Keys(r.identities)) {
		deliver(Event{Identity: key, Present: true})
	}
	return nil
}

func (r *Registry) Present() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Sorted(maps.Keys(r.identities))
}

func (r *Registry) broadcast(e Event) {
	for _, deliver := range r.subscribers {
		deliver(e)
	}
}
