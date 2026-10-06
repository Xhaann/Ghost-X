package prekey

import (
	"errors"
	"slices"
	"sync"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	MaxDevices      = 4
	MaxOnetime      = 100
	MaxIdentities   = 4096
	MaxPending      = 32
	MaxPendingTotal = 4096
	MaxID           = 1<<31 - 1
	seenLimit       = 1024
	deliveredLimit  = 256
)

var (
	ErrUnauthenticated = errors.New("prekey: not authenticated")
	ErrNoKey           = errors.New("prekey: static key not published by this session")
	ErrInvalid         = errors.New("prekey: invalid prekey state")
	ErrUnavailable     = errors.New("prekey: no bundle")
	ErrLimit           = errors.New("prekey: pending limit reached")
	ErrDuplicate       = errors.New("prekey: duplicate initiation")
)

type Static struct {
	Key       string
	Signature string
}

type Prekey struct {
	ID        uint32
	Key       string
	Signature string
}

type Bundle struct {
	Device  string
	Signed  Prekey
	Onetime *Prekey
}

type Initiation struct {
	From      string
	Sender    Static
	Device    string
	Signed    uint32
	Onetime   *uint32
	Ephemeral string
	Ratchet   string
	Proof     string
	Confirm   string
}

type Acceptance struct {
	From      string
	Ephemeral string
	Confirm   string
}

type Event struct {
	Initiation *Initiation
	Acceptance *Acceptance
}

type Push func(Event) bool

type ring struct {
	order []string
	seen  map[string]string
	limit int
}

func newRing(limit int) *ring {
	return &ring{seen: make(map[string]string), limit: limit}
}

func (r *ring) has(k string) bool {
	_, ok := r.seen[k]
	return ok
}

func (r *ring) get(k string) (string, bool) {
	v, ok := r.seen[k]
	return v, ok
}

func (r *ring) add(k, v string) {
	if r.has(k) {
		return
	}
	if len(r.order) == r.limit {
		delete(r.seen, r.order[0])
		r.order = r.order[1:]
	}
	r.order = append(r.order, k)
	r.seen[k] = v
}

func (r *ring) remove(k string) {
	if !r.has(k) {
		return
	}
	delete(r.seen, k)
	r.order = slices.DeleteFunc(r.order, func(x string) bool { return x == k })
}

type device struct {
	static     Static
	signed     Prekey
	previous   *Prekey
	onetime    []Prekey
	reserved   map[uint32]struct{}
	published  *ring
	ephemerals *ring
	delivered  *ring
	pending    []Initiation
	stamp      uint64
}

type Registry struct {
	mu         sync.Mutex
	endpoints  map[*auth.Session]Push
	identities map[*auth.Session]string
	devices    map[*auth.Session]string
	owners     map[string]map[string]*device
	accepts    map[string][]Acceptance
	pending    int
	clock      uint64
}

func NewRegistry() *Registry {
	return &Registry{
		endpoints:  make(map[*auth.Session]Push),
		identities: make(map[*auth.Session]string),
		devices:    make(map[*auth.Session]string),
		owners:     make(map[string]map[string]*device),
		accepts:    make(map[string][]Acceptance),
	}
}

func idKey(id uint32) string {
	return string([]byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
}

func (r *Registry) Attach(s *auth.Session, push Push) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endpoints[s] = push
}

func (r *Registry) Detach(s *auth.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.endpoints, s)
	delete(r.identities, s)
	delete(r.devices, s)
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
	delete(r.identities, s)
	delete(r.devices, s)
}

func (r *Registry) Publish(s *auth.Session, static Static, deviceID string, signed Prekey, onetime []Prekey) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.identities[s]
	if !ok {
		return 0, ErrUnauthenticated
	}
	if current, ok := r.devices[s]; ok && current != deviceID {
		return 0, ErrInvalid
	}
	for _, other := range r.owners[owner] {
		if other.static != static {
			delete(r.owners, owner)
			break
		}
	}
	devs := r.owners[owner]
	if devs == nil {
		r.evict()
		devs = make(map[string]*device)
		r.owners[owner] = devs
	}
	d := devs[deviceID]
	if d == nil {
		if len(devs) >= MaxDevices {
			return 0, ErrLimit
		}
		d = &device{static: static, reserved: make(map[uint32]struct{}), published: newRing(seenLimit), ephemerals: newRing(seenLimit), delivered: newRing(deliveredLimit)}
		devs[deviceID] = d
	}
	switch {
	case d.signed.Key == "":
		d.signed = signed
	case signed.ID == d.signed.ID:
		if signed.Key != d.signed.Key {
			return 0, ErrInvalid
		}
	case signed.ID > d.signed.ID:
		previous := d.signed
		d.previous = &previous
		d.signed = signed
	default:
		return 0, ErrInvalid
	}
	for _, p := range onetime {
		k := idKey(p.ID)
		if d.published.has(k) {
			if v, _ := d.published.get(k); v != p.Key {
				return 0, ErrInvalid
			}
			continue
		}
		if len(d.onetime) >= MaxOnetime {
			break
		}
		d.published.add(k, p.Key)
		d.onetime = append(d.onetime, p)
	}
	r.clock++
	d.stamp = r.clock
	r.devices[s] = deviceID

	pending := d.pending
	d.pending = nil
	r.pending -= len(pending)
	push := r.endpoints[s]
	for _, init := range pending {
		if push == nil || !push(Event{Initiation: &init}) {
			d.pending = append(d.pending, init)
			r.pending++
		}
	}
	accepts := r.accepts[owner]
	delete(r.accepts, owner)
	r.pending -= len(accepts)
	for _, a := range accepts {
		if push == nil || !push(Event{Acceptance: &a}) {
			r.accepts[owner] = append(r.accepts[owner], a)
			r.pending++
		}
	}
	return len(d.onetime), nil
}

func (r *Registry) evict() {
	for len(r.owners) >= MaxIdentities {
		var oldest string
		var stamp uint64
		for owner, devs := range r.owners {
			latest := uint64(0)
			for _, d := range devs {
				latest = max(latest, d.stamp)
			}
			if oldest == "" || latest < stamp {
				oldest, stamp = owner, latest
			}
		}
		for _, d := range r.owners[oldest] {
			r.pending -= len(d.pending)
		}
		delete(r.owners, oldest)
	}
}

func (r *Registry) Fetch(id identity.Identity) (Static, []Bundle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	devs := r.owners[id.String()]
	if len(devs) == 0 {
		return Static{}, nil, false
	}
	keys := make([]string, 0, len(devs))
	for k := range devs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	bundles := make([]Bundle, 0, len(keys))
	var static Static
	for _, k := range keys {
		d := devs[k]
		static = d.static
		b := Bundle{Device: k, Signed: d.signed}
		if len(d.onetime) > 0 {
			p := d.onetime[0]
			d.onetime = d.onetime[1:]
			d.reserved[p.ID] = struct{}{}
			b.Onetime = &p
		}
		bundles = append(bundles, b)
	}
	return static, bundles, true
}

func (r *Registry) Device(to identity.Identity, deviceID string) (Static, Prekey, *Prekey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.owners[to.String()][deviceID]
	if d == nil {
		return Static{}, Prekey{}, nil, false
	}
	var previous *Prekey
	if d.previous != nil {
		p := *d.previous
		previous = &p
	}
	return d.static, d.signed, previous, true
}

func (r *Registry) Onetime(to identity.Identity, deviceID string, id uint32) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.owners[to.String()][deviceID]
	if d == nil {
		return "", false
	}
	if _, ok := d.reserved[id]; !ok {
		return "", false
	}
	return d.published.get(idKey(id))
}

func (r *Registry) Initiate(s *auth.Session, to identity.Identity, init Initiation, static Static) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	from, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	d := r.owners[to.String()][init.Device]
	if d == nil {
		return ErrUnavailable
	}
	if d.static != static {
		return ErrInvalid
	}
	if init.Signed != d.signed.ID && (d.previous == nil || init.Signed != d.previous.ID) {
		return ErrInvalid
	}
	if init.Onetime != nil {
		if _, ok := d.reserved[*init.Onetime]; !ok {
			return ErrInvalid
		}
	}
	if d.ephemerals.has(init.Ephemeral) {
		return ErrDuplicate
	}
	if init.Onetime != nil {
		delete(d.reserved, *init.Onetime)
	}
	d.ephemerals.add(init.Ephemeral, from)
	d.delivered.add(init.Ephemeral, from)
	init.From = from

	delivered := false
	for session, dev := range r.devices {
		if dev != init.Device || r.identities[session] != to.String() {
			continue
		}
		if push := r.endpoints[session]; push != nil && push(Event{Initiation: &init}) {
			delivered = true
		}
	}
	if delivered {
		return nil
	}
	if len(d.pending) >= MaxPending || r.pending >= MaxPendingTotal {
		return ErrLimit
	}
	d.pending = append(d.pending, init)
	r.pending++
	return nil
}

func (r *Registry) Accept(s *auth.Session, initiator identity.Identity, ephemeral, confirm string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner, ok := r.identities[s]
	if !ok {
		return ErrUnauthenticated
	}
	deviceID, ok := r.devices[s]
	if !ok {
		return ErrNoKey
	}
	d := r.owners[owner][deviceID]
	if d == nil {
		return ErrInvalid
	}
	if from, ok := d.delivered.get(ephemeral); !ok || from != initiator.String() {
		return ErrInvalid
	}
	d.delivered.remove(ephemeral)
	a := Acceptance{From: owner, Ephemeral: ephemeral, Confirm: confirm}
	delivered := false
	for session, id := range r.identities {
		if id != initiator.String() {
			continue
		}
		if push := r.endpoints[session]; push != nil && push(Event{Acceptance: &a}) {
			delivered = true
		}
	}
	if delivered {
		return nil
	}
	if len(r.accepts[initiator.String()]) >= MaxPending || r.pending >= MaxPendingTotal {
		return ErrLimit
	}
	r.accepts[initiator.String()] = append(r.accepts[initiator.String()], a)
	r.pending++
	return nil
}
