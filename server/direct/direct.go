package direct

import (
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	recentLimit = 256
	MaxSessions = 4
	MaxEpoch    = 1<<31 - 1
)

var (
	ErrUnauthenticated = errors.New("direct: sender not authenticated")
	ErrUnavailable     = errors.New("direct: recipient unavailable")
	ErrNoKey           = errors.New("direct: sender has no published key")
	ErrKeyConflict     = errors.New("direct: identity already bound to another key")
	ErrDuplicate       = errors.New("direct: duplicate message id")
	ErrStale           = errors.New("direct: stale or invalid session state")
	ErrSessionLimit    = errors.New("direct: too many sessions for identity")
)

type Bundle struct {
	Key       string
	Signature string
}

type SessionBundle struct {
	ID        string
	Epoch     uint32
	Key       string
	Signature string
}

type Envelope struct {
	Session    string
	Epoch      uint32
	Salt       string
	IV         string
	Ciphertext string
}

type Message struct {
	ID       string
	From     string
	Sender   Bundle
	Session  SessionBundle
	Envelope Envelope
}

type Deliver func(Message) bool

type binding struct {
	bundle   Bundle
	sessions map[*auth.Session]struct{}
}

type epochs struct {
	current  SessionBundle
	previous *SessionBundle
}

func (e *epochs) at(epoch uint32) (SessionBundle, bool) {
	if e.current.Epoch == epoch {
		return e.current, true
	}
	if e.previous != nil && e.previous.Epoch == epoch {
		return *e.previous, true
	}
	return SessionBundle{}, false
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
	sessions   map[*auth.Session]*epochs
	recent     map[*auth.Session]*recent
}

func NewRegistry() *Registry {
	return &Registry{
		endpoints:  make(map[*auth.Session]Deliver),
		identities: make(map[*auth.Session]string),
		recipients: make(map[string]map[*auth.Session]struct{}),
		keys:       make(map[string]*binding),
		sessions:   make(map[*auth.Session]*epochs),
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
		delete(r.sessions, s)
	default:
		return ErrKeyConflict
	}
	return nil
}

func (r *Registry) Establish(s *auth.Session, staticKey string, bundle SessionBundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	current := r.keys[owner]
	if current == nil || !hasSession(current.sessions, s) || current.bundle.Key != staticKey {
		return ErrNoKey
	}
	if bundle.Epoch > MaxEpoch {
		return ErrStale
	}
	state := r.sessions[s]
	if state == nil || (bundle.Epoch == 0 && bundle.ID != state.current.ID) {
		if bundle.Epoch != 0 {
			return ErrStale
		}
		count := 0
		for other := range r.recipients[owner] {
			if st := r.sessions[other]; st != nil && other != s {
				count++
				if st.current.ID == bundle.ID {
					return ErrStale
				}
			}
		}
		if count >= MaxSessions {
			return ErrSessionLimit
		}
		r.sessions[s] = &epochs{current: bundle}
		return nil
	}
	if bundle.ID != state.current.ID || bundle.Epoch != state.current.Epoch+1 {
		return ErrStale
	}
	previous := state.current
	state.previous = &previous
	state.current = bundle
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

func (r *Registry) Lookup(id identity.Identity) (Bundle, []SessionBundle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := id.String()
	current := r.keys[key]
	if current == nil {
		return Bundle{}, nil, false
	}
	sessions := []SessionBundle{}
	for s := range r.recipients[key] {
		if st := r.sessions[s]; st != nil && hasSession(current.sessions, s) {
			sessions = append(sessions, st.current)
		}
	}
	slices.SortFunc(sessions, func(a, b SessionBundle) int { return strings.Compare(a.ID, b.ID) })
	return current.bundle, sessions, true
}

func (r *Registry) Send(from *auth.Session, to identity.Identity, id string, epoch uint32, envelopes []Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sender, ok := r.identities[from]
	if !ok {
		return ErrUnauthenticated
	}
	current := r.keys[sender]
	state := r.sessions[from]
	if current == nil || !hasSession(current.sessions, from) || state == nil {
		return ErrNoKey
	}
	senderSession, ok := state.at(epoch)
	if !ok {
		return ErrStale
	}
	if !r.recent[from].add(id) {
		return ErrDuplicate
	}
	delivered := 0
	for _, envelope := range envelopes {
		for s := range r.recipients[to.String()] {
			st := r.sessions[s]
			if st == nil || st.current.ID != envelope.Session {
				continue
			}
			if _, ok := st.at(envelope.Epoch); !ok {
				break
			}
			msg := Message{ID: id, From: sender, Sender: current.bundle, Session: senderSession, Envelope: envelope}
			if deliver, ok := r.endpoints[s]; ok && deliver(msg) {
				delivered++
			}
			break
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
	delete(r.sessions, s)
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
