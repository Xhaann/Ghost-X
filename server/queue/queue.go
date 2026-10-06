package queue

import (
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	MaxPerRecipient      = 256
	MaxBytesPerRecipient = 1 << 20
	MaxPerPair           = 128
	MaxPerSender         = 512
	MaxTotal             = 16384
	MaxBytesTotal        = 32 << 20
	MaxReceiptsPerSender = 512
	MaxReceiptsTotal     = 65536
	MaxAttempts          = 32
	Window               = 16
	TTL                  = 72 * time.Hour
	SweepInterval        = time.Minute
	SeenLimit            = 16384
	Overhead             = 256
)

var (
	ErrUnauthenticated = errors.New("queue: not authenticated")
	ErrInvalid         = errors.New("queue: invalid request")
	ErrDuplicate       = errors.New("queue: duplicate message")
	ErrFull            = errors.New("queue: limit reached")
)

type Status string

const (
	Delivered Status = "delivered"
	Expired   Status = "expired"
)

type Message struct {
	ID         string
	From       string
	Key        string
	Signature  string
	Ciphertext string
}

type Receipt struct {
	To     string
	ID     string
	Status Status
}

type Push struct {
	Message *Message
	Receipt *Receipt
}

type Deliver func(Push) bool

type entry struct {
	message  Message
	to       string
	size     int
	queued   time.Time
	holder   *auth.Session
	attempts int
}

type note struct {
	receipt Receipt
	created time.Time
	holder  *auth.Session
}

type inbox struct {
	entries []*entry
	bytes   int
}

type endpoint struct {
	deliver    Deliver
	subscribed bool
	inflight   int
}

type pair struct {
	from, to string
}

type Registry struct {
	mu         sync.Mutex
	now        func() time.Time
	endpoints  map[*auth.Session]*endpoint
	identities map[*auth.Session]string
	listeners  map[string]map[*auth.Session]struct{}
	inboxes    map[string]*inbox
	outboxes   map[string][]*note
	senders    map[string]int
	pairs      map[pair]int
	seen       map[string]struct{}
	order      []string
	total      int
	bytes      int
	notes      int
	swept      time.Time
}

func NewRegistry(now func() time.Time) *Registry {
	return &Registry{
		now:        now,
		endpoints:  make(map[*auth.Session]*endpoint),
		identities: make(map[*auth.Session]string),
		listeners:  make(map[string]map[*auth.Session]struct{}),
		inboxes:    make(map[string]*inbox),
		outboxes:   make(map[string][]*note),
		senders:    make(map[string]int),
		pairs:      make(map[pair]int),
		seen:       make(map[string]struct{}),
		swept:      now(),
	}
}

func (r *Registry) Attach(s *auth.Session, deliver Deliver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endpoints[s] = &endpoint{deliver: deliver}
}

func (r *Registry) Detach(s *auth.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.release(s)
	r.unlisten(s)
	delete(r.endpoints, s)
	delete(r.identities, s)
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
	r.release(s)
	r.unlisten(s)
	delete(r.identities, s)
}

func (r *Registry) Subscribe(s *auth.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.identities[s]
	e := r.endpoints[s]
	if !ok || e == nil {
		return ErrUnauthenticated
	}
	r.release(s)
	e.subscribed = true
	if r.listeners[owner] == nil {
		r.listeners[owner] = make(map[*auth.Session]struct{})
	}
	r.listeners[owner][s] = struct{}{}
	r.sweep(false)
	r.pump(owner)
	return nil
}

func (r *Registry) Enqueue(s *auth.Session, to identity.Identity, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	from, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	recipient := to.String()
	if recipient == from || m.ID == "" || m.Ciphertext == "" {
		return ErrInvalid
	}
	m.From = from
	k := seenKey(from, recipient, m.ID)
	if _, dup := r.seen[k]; dup {
		return ErrDuplicate
	}
	size := len(m.Ciphertext) + Overhead
	r.sweep(false)
	if !r.fits(from, recipient, size) {
		r.sweep(true)
		if !r.fits(from, recipient, size) {
			return ErrFull
		}
	}
	box := r.inboxes[recipient]
	if box == nil {
		box = &inbox{}
		r.inboxes[recipient] = box
	}
	box.entries = append(box.entries, &entry{message: m, to: recipient, size: size, queued: r.now()})
	box.bytes += size
	r.senders[from]++
	r.pairs[pair{from, recipient}]++
	r.total++
	r.bytes += size
	r.remember(k)
	r.pump(recipient)
	return nil
}

func (r *Registry) Ack(s *auth.Session, from identity.Identity, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	recipient, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	box := r.inboxes[recipient]
	if box == nil {
		return nil
	}
	sender := from.String()
	i := slices.IndexFunc(box.entries, func(e *entry) bool {
		return e.message.From == sender && e.message.ID == id
	})
	if i < 0 {
		return nil
	}
	e := box.entries[i]
	if e.attempts == 0 {
		return ErrInvalid
	}
	r.remove(box, i)
	r.notify(sender, Receipt{To: recipient, ID: id, Status: Delivered})
	r.pump(sender)
	r.pump(recipient)
	return nil
}

func (r *Registry) Clear(s *auth.Session, to identity.Identity, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sender, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	recipient := to.String()
	notes := r.outboxes[sender]
	i := slices.IndexFunc(notes, func(n *note) bool {
		return n.receipt.To == recipient && n.receipt.ID == id
	})
	if i < 0 {
		return nil
	}
	r.drop(sender, i)
	r.pump(sender)
	return nil
}

func (r *Registry) Queued(id identity.Identity) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if box := r.inboxes[id.String()]; box != nil {
		return len(box.entries)
	}
	return 0
}

func (r *Registry) Receipts(id identity.Identity) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.outboxes[id.String()])
}

func (r *Registry) Usage() (messages, bytes, receipts int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total, r.bytes, r.notes
}

func (r *Registry) fits(from, recipient string, size int) bool {
	box := r.inboxes[recipient]
	count, used := 0, 0
	if box != nil {
		count, used = len(box.entries), box.bytes
	}
	return count < MaxPerRecipient &&
		used+size <= MaxBytesPerRecipient &&
		r.pairs[pair{from, recipient}] < MaxPerPair &&
		r.senders[from] < MaxPerSender &&
		r.total < MaxTotal &&
		r.bytes+size <= MaxBytesTotal
}

func (r *Registry) remove(box *inbox, i int) {
	e := box.entries[i]
	r.unhold(e.holder)
	box.entries = slices.Delete(box.entries, i, i+1)
	box.bytes -= e.size
	r.total--
	r.bytes -= e.size
	r.senders[e.message.From]--
	if r.senders[e.message.From] == 0 {
		delete(r.senders, e.message.From)
	}
	p := pair{e.message.From, e.to}
	r.pairs[p]--
	if r.pairs[p] == 0 {
		delete(r.pairs, p)
	}
	if len(box.entries) == 0 {
		delete(r.inboxes, e.to)
	}
}

func (r *Registry) notify(sender string, receipt Receipt) {
	if notes := r.outboxes[sender]; len(notes) >= MaxReceiptsPerSender {
		r.drop(sender, 0)
	}
	if r.notes >= MaxReceiptsTotal {
		return
	}
	r.outboxes[sender] = append(r.outboxes[sender], &note{receipt: receipt, created: r.now()})
	r.notes++
}

func (r *Registry) drop(sender string, i int) {
	notes := r.outboxes[sender]
	r.unhold(notes[i].holder)
	notes = slices.Delete(notes, i, i+1)
	r.notes--
	if len(notes) == 0 {
		delete(r.outboxes, sender)
	} else {
		r.outboxes[sender] = notes
	}
}

func (r *Registry) unhold(s *auth.Session) {
	if s == nil {
		return
	}
	if e := r.endpoints[s]; e != nil && e.inflight > 0 {
		e.inflight--
	}
}

func (r *Registry) release(s *auth.Session) {
	owner, ok := r.identities[s]
	if !ok {
		return
	}
	if box := r.inboxes[owner]; box != nil {
		for _, e := range box.entries {
			if e.holder == s {
				e.holder = nil
			}
		}
	}
	for _, n := range r.outboxes[owner] {
		if n.holder == s {
			n.holder = nil
		}
	}
	if e := r.endpoints[s]; e != nil {
		e.inflight = 0
	}
}

func (r *Registry) unlisten(s *auth.Session) {
	if e := r.endpoints[s]; e != nil {
		e.subscribed = false
	}
	owner, ok := r.identities[s]
	if !ok {
		return
	}
	delete(r.listeners[owner], s)
	if len(r.listeners[owner]) == 0 {
		delete(r.listeners, owner)
	}
}

func (r *Registry) pump(owner string) {
	for s := range r.listeners[owner] {
		e := r.endpoints[s]
		if e == nil || !e.subscribed {
			continue
		}
		for _, n := range r.outboxes[owner] {
			if e.inflight >= Window {
				break
			}
			if n.holder != nil {
				continue
			}
			receipt := n.receipt
			if !e.deliver(Push{Receipt: &receipt}) {
				return
			}
			n.holder = s
			e.inflight++
		}
		box := r.inboxes[owner]
		if box == nil {
			continue
		}
		for _, q := range box.entries {
			if e.inflight >= Window {
				break
			}
			if q.holder != nil {
				continue
			}
			message := q.message
			if !e.deliver(Push{Message: &message}) {
				return
			}
			q.holder = s
			q.attempts++
			e.inflight++
		}
	}
}

func (r *Registry) sweep(force bool) {
	now := r.now()
	if !force && now.Sub(r.swept) < SweepInterval {
		return
	}
	r.swept = now
	affected := map[string]struct{}{}
	for recipient, box := range r.inboxes {
		for i := len(box.entries) - 1; i >= 0; i-- {
			e := box.entries[i]
			if e.holder != nil || (now.Sub(e.queued) < TTL && e.attempts < MaxAttempts) {
				continue
			}
			sender := e.message.From
			r.remove(box, i)
			r.notify(sender, Receipt{To: recipient, ID: e.message.ID, Status: Expired})
			affected[sender] = struct{}{}
		}
	}
	for sender, notes := range r.outboxes {
		for i := len(notes) - 1; i >= 0; i-- {
			if notes[i].holder == nil && now.Sub(notes[i].created) >= TTL {
				r.drop(sender, i)
				notes = r.outboxes[sender]
			}
		}
	}
	for sender := range affected {
		r.pump(sender)
	}
}

func (r *Registry) remember(k string) {
	if len(r.order) >= SeenLimit {
		delete(r.seen, r.order[0])
		r.order = r.order[1:]
	}
	r.order = append(r.order, k)
	r.seen[k] = struct{}{}
}

func seenKey(from, to, id string) string {
	return from + "/" + to + "/" + id
}
