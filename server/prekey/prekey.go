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
	ErrInvalid         = errors.New("prekey: invalid prekey state")
	ErrUnavailable     = errors.New("prekey: no bundle")
	ErrLimit           = errors.New("prekey: pending limit reached")
	ErrDuplicate       = errors.New("prekey: duplicate initiation")
	ErrRevoked         = errors.New("prekey: device not authorized")
)

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
	From       string
	FromDevice string
	Device     string
	Signed     uint32
	Onetime    *uint32
	Ephemeral  string
	Ratchet    string
	Proof      string
	Confirm    string
}

type Acceptance struct {
	From       string
	FromDevice string
	Ephemeral  string
	Confirm    string
}

type Event struct {
	Initiation *Initiation
	Acceptance *Acceptance
}

type Push func(Event) bool

type Authorizer func(owner, device string) bool

type address struct {
	owner, device string
}

type ring[V comparable] struct {
	order []string
	seen  map[string]V
	limit int
}

func newRing[V comparable](limit int) *ring[V] {
	return &ring[V]{seen: make(map[string]V), limit: limit}
}

func (r *ring[V]) has(k string) bool {
	_, ok := r.seen[k]
	return ok
}

func (r *ring[V]) get(k string) (V, bool) {
	v, ok := r.seen[k]
	return v, ok
}

func (r *ring[V]) add(k string, v V) {
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

func (r *ring[V]) remove(k string) {
	if !r.has(k) {
		return
	}
	delete(r.seen, k)
	r.order = slices.DeleteFunc(r.order, func(x string) bool { return x == k })
}

func idKey(id uint32) string {
	return string([]byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
}

type device struct {
	signed     Prekey
	previous   *Prekey
	onetime    []Prekey
	reserved   map[uint32]struct{}
	published  *ring[string]
	ephemerals *ring[address]
	delivered  *ring[address]
	pending    []Initiation
	stamp      uint64
}

type Registry struct {
	mu         sync.Mutex
	authorized Authorizer
	endpoints  map[*auth.Session]Push
	addresses  map[*auth.Session]address
	owners     map[string]map[string]*device
	accepts    map[address][]Acceptance
	pending    int
	clock      uint64
}

func NewRegistry(authorized Authorizer) *Registry {
	return &Registry{
		authorized: authorized,
		endpoints:  make(map[*auth.Session]Push),
		addresses:  make(map[*auth.Session]address),
		owners:     make(map[string]map[string]*device),
		accepts:    make(map[address][]Acceptance),
	}
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
	delete(r.addresses, s)
}

func (r *Registry) Authenticated(s *auth.Session, id identity.Identity, deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.addresses[s]; !ok {
		r.addresses[s] = address{id.String(), deviceID}
	}
}

func (r *Registry) Closed(s *auth.Session, _ identity.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.addresses, s)
}

func (r *Registry) RemoveDevice(owner, deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d := r.owners[owner][deviceID]; d != nil {
		r.pending -= len(d.pending)
		delete(r.owners[owner], deviceID)
		if len(r.owners[owner]) == 0 {
			delete(r.owners, owner)
		}
	}
	gone := address{owner, deviceID}
	r.pending -= len(r.accepts[gone])
	delete(r.accepts, gone)
	for _, devs := range r.owners {
		for _, d := range devs {
			kept := d.pending[:0]
			for _, init := range d.pending {
				if init.From == owner && init.FromDevice == deviceID {
					r.pending--
					continue
				}
				kept = append(kept, init)
			}
			d.pending = kept
		}
	}
	for to, list := range r.accepts {
		kept := list[:0]
		for _, a := range list {
			if a.From == owner && a.FromDevice == deviceID {
				r.pending--
				continue
			}
			kept = append(kept, a)
		}
		if len(kept) == 0 {
			delete(r.accepts, to)
		} else {
			r.accepts[to] = kept
		}
	}
}

func (r *Registry) Publish(s *auth.Session, deviceID string, signed Prekey, onetime []Prekey) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.addresses[s]
	if !ok {
		return 0, ErrUnauthenticated
	}
	if at.device != deviceID {
		return 0, ErrInvalid
	}
	if !r.authorized(at.owner, at.device) {
		return 0, ErrRevoked
	}
	devs := r.owners[at.owner]
	if devs == nil {
		r.evict()
		devs = make(map[string]*device)
		r.owners[at.owner] = devs
	}
	d := devs[deviceID]
	if d == nil {
		if len(devs) >= MaxDevices {
			return 0, ErrLimit
		}
		d = &device{reserved: make(map[uint32]struct{}), published: newRing[string](seenLimit), ephemerals: newRing[address](seenLimit), delivered: newRing[address](deliveredLimit)}
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
		if key, seen := d.published.get(idKey(p.ID)); seen {
			if key != p.Key {
				return 0, ErrInvalid
			}
			continue
		}
		if len(d.onetime) >= MaxOnetime {
			break
		}
		d.published.add(idKey(p.ID), p.Key)
		d.onetime = append(d.onetime, p)
	}
	r.clock++
	d.stamp = r.clock

	push := r.endpoints[s]
	pending := d.pending
	d.pending = nil
	r.pending -= len(pending)
	for _, init := range pending {
		if push == nil || !push(Event{Initiation: &init}) {
			d.pending = append(d.pending, init)
			r.pending++
		}
	}
	accepts := r.accepts[at]
	delete(r.accepts, at)
	r.pending -= len(accepts)
	for _, a := range accepts {
		if push == nil || !push(Event{Acceptance: &a}) {
			r.accepts[at] = append(r.accepts[at], a)
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

func (r *Registry) Fetch(id identity.Identity) ([]Bundle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner := id.String()
	devs := r.owners[owner]
	keys := make([]string, 0, len(devs))
	for k := range devs {
		if r.authorized(owner, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, false
	}
	slices.Sort(keys)
	bundles := make([]Bundle, 0, len(keys))
	for _, k := range keys {
		d := devs[k]
		b := Bundle{Device: k, Signed: d.signed}
		if len(d.onetime) > 0 {
			p := d.onetime[0]
			d.onetime = d.onetime[1:]
			d.reserved[p.ID] = struct{}{}
			b.Onetime = &p
		}
		bundles = append(bundles, b)
	}
	return bundles, true
}

func (r *Registry) Device(to identity.Identity, deviceID string) (Prekey, *Prekey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.owners[to.String()][deviceID]
	if d == nil || !r.authorized(to.String(), deviceID) {
		return Prekey{}, nil, false
	}
	var previous *Prekey
	if d.previous != nil {
		p := *d.previous
		previous = &p
	}
	return d.signed, previous, true
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

func (r *Registry) Initiate(s *auth.Session, to identity.Identity, init Initiation, signedKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	from, ok := r.addresses[s]
	if !ok {
		return ErrUnauthenticated
	}
	if !r.authorized(from.owner, from.device) {
		return ErrRevoked
	}
	owner := to.String()
	d := r.owners[owner][init.Device]
	if d == nil || !r.authorized(owner, init.Device) {
		return ErrUnavailable
	}
	switch {
	case init.Signed == d.signed.ID && signedKey == d.signed.Key:
	case d.previous != nil && init.Signed == d.previous.ID && signedKey == d.previous.Key:
	default:
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
	init.From = from.owner
	init.FromDevice = from.device

	delivered := false
	for session, at := range r.addresses {
		if at.owner != owner || at.device != init.Device {
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

func (r *Registry) Accept(s *auth.Session, initiator identity.Identity, initiatorDevice, ephemeral, confirm string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.addresses[s]
	if !ok {
		return ErrUnauthenticated
	}
	if !r.authorized(at.owner, at.device) {
		return ErrRevoked
	}
	d := r.owners[at.owner][at.device]
	if d == nil {
		return ErrInvalid
	}
	target := address{initiator.String(), initiatorDevice}
	if from, ok := d.delivered.get(ephemeral); !ok || from != target {
		return ErrInvalid
	}
	d.delivered.remove(ephemeral)
	if !r.authorized(target.owner, target.device) {
		return ErrInvalid
	}
	a := Acceptance{From: at.owner, FromDevice: at.device, Ephemeral: ephemeral, Confirm: confirm}
	delivered := false
	for session, other := range r.addresses {
		if other != target {
			continue
		}
		if push := r.endpoints[session]; push != nil && push(Event{Acceptance: &a}) {
			delivered = true
		}
	}
	if delivered {
		return nil
	}
	if len(r.accepts[target]) >= MaxPending || r.pending >= MaxPendingTotal {
		return ErrLimit
	}
	r.accepts[target] = append(r.accepts[target], a)
	r.pending++
	return nil
}
