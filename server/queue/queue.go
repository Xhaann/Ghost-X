package queue

import (
	"errors"
	"slices"
	"strings"
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
	ErrRevoked         = errors.New("queue: device not authorized")
)

type Status string

const (
	Delivered Status = "delivered"
	Expired   Status = "expired"
)

type Message struct {
	ID         string
	From       string
	FromDevice string
	Ciphertext string
}

type Receipt struct {
	To     string
	Device string
	ID     string
	Status Status
}

type Authorizer func(owner, device string) bool

func Address(owner, device string) string {
	return owner + "/" + device
}

func split(address string) (string, string) {
	owner, device, _ := strings.Cut(address, "/")
	return owner, device
}

type Push struct {
	Message *Message
	Receipt *Receipt
}

type Deliver func(Push) bool

type entry struct {
	message  Message
	from     string
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
	authorized Authorizer
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

func NewRegistry(now func() time.Time, authorized Authorizer) *Registry {
	return &Registry{
		now:        now,
		authorized: authorized,
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

func (r *Registry) Authenticated(s *auth.Session, id identity.Identity, device string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.identities[s]; !ok {
		r.identities[s] = Address(id.String(), device)
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
	if !r.authorized(split(owner)) {
		return ErrRevoked
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

type Envelope struct {
	Device     string
	Ciphertext string
}

func (r *Registry) Enqueue(s *auth.Session, to identity.Identity, id string, envelopes []Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	from, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	sender, senderDevice := split(from)
	if !r.authorized(sender, senderDevice) {
		return ErrRevoked
	}
	if to.String() == sender || id == "" || len(envelopes) == 0 {
		return ErrInvalid
	}
	recipients := make([]string, 0, len(envelopes))
	size := 0
	for _, e := range envelopes {
		recipient := Address(to.String(), e.Device)
		if e.Ciphertext == "" || slices.Contains(recipients, recipient) {
			return ErrInvalid
		}
		if !r.authorized(to.String(), e.Device) {
			return ErrRevoked
		}
		if _, dup := r.seen[seenKey(from, recipient, id)]; dup {
			return ErrDuplicate
		}
		recipients = append(recipients, recipient)
		size += len(e.Ciphertext) + Overhead
	}
	r.sweep(false)
	if !r.fitsAll(from, recipients, envelopes) {
		r.sweep(true)
		if !r.fitsAll(from, recipients, envelopes) {
			return ErrFull
		}
	}
	for i, e := range envelopes {
		recipient := recipients[i]
		entrySize := len(e.Ciphertext) + Overhead
		box := r.inboxes[recipient]
		if box == nil {
			box = &inbox{}
			r.inboxes[recipient] = box
		}
		m := Message{ID: id, From: sender, FromDevice: senderDevice, Ciphertext: e.Ciphertext}
		box.entries = append(box.entries, &entry{message: m, from: from, to: recipient, size: entrySize, queued: r.now()})
		box.bytes += entrySize
		r.senders[from]++
		r.pairs[pair{from, recipient}]++
		r.total++
		r.bytes += entrySize
		r.remember(seenKey(from, recipient, id))
	}
	for _, recipient := range recipients {
		r.pump(recipient)
	}
	return nil
}

func (r *Registry) fitsAll(from string, recipients []string, envelopes []Envelope) bool {
	total := 0
	for i, e := range envelopes {
		size := len(e.Ciphertext) + Overhead
		total += size
		if !r.fits(from, recipients[i], size) {
			return false
		}
	}
	return r.senders[from]+len(envelopes) <= MaxPerSender &&
		r.total+len(envelopes) <= MaxTotal &&
		r.bytes+total <= MaxBytesTotal
}

func (r *Registry) RemoveDevice(owner, device string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	gone := Address(owner, device)
	if box := r.inboxes[gone]; box != nil {
		for i := len(box.entries) - 1; i >= 0; i-- {
			r.remove(box, i)
		}
	}
	for _, box := range r.inboxes {
		for i := len(box.entries) - 1; i >= 0; i-- {
			if box.entries[i].from == gone {
				r.remove(box, i)
			}
		}
	}
	for len(r.outboxes[gone]) > 0 {
		r.drop(gone, 0)
	}
}

func (r *Registry) Ack(s *auth.Session, from identity.Identity, fromDevice, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	recipient, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	if !r.authorized(split(recipient)) {
		return ErrRevoked
	}
	box := r.inboxes[recipient]
	if box == nil {
		return nil
	}
	sender := Address(from.String(), fromDevice)
	i := slices.IndexFunc(box.entries, func(e *entry) bool {
		return e.from == sender && e.message.ID == id
	})
	if i < 0 {
		return nil
	}
	e := box.entries[i]
	if e.attempts == 0 {
		return ErrInvalid
	}
	r.remove(box, i)
	owner, device := split(recipient)
	r.notify(sender, Receipt{To: owner, Device: device, ID: id, Status: Delivered})
	r.pump(sender)
	r.pump(recipient)
	return nil
}

func (r *Registry) Clear(s *auth.Session, to identity.Identity, device, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sender, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	if !r.authorized(split(sender)) {
		return ErrRevoked
	}
	recipient := to.String()
	notes := r.outboxes[sender]
	i := slices.IndexFunc(notes, func(n *note) bool {
		return n.receipt.To == recipient && n.receipt.Device == device && n.receipt.ID == id
	})
	if i < 0 {
		return nil
	}
	r.drop(sender, i)
	r.pump(sender)
	return nil
}

func (r *Registry) Queued(address string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if box := r.inboxes[address]; box != nil {
		return len(box.entries)
	}
	return 0
}

func (r *Registry) Receipts(address string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.outboxes[address])
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
	r.senders[e.from]--
	if r.senders[e.from] == 0 {
		delete(r.senders, e.from)
	}
	p := pair{e.from, e.to}
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
			sender := e.from
			r.remove(box, i)
			owner, device := split(recipient)
			r.notify(sender, Receipt{To: owner, Device: device, ID: e.message.ID, Status: Expired})
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
