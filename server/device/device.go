package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	IDSize        = 16
	KeySize       = 32
	MaxDevices    = 4
	MaxIdentities = 65536
	MaxVersion    = 1<<31 - 1
	MaxRevoked    = 64
)

const (
	idContext     = "ghostx/device/v1\x00"
	rosterContext = "ghostx/roster/v1\x00"
)

var (
	ErrInvalid    = errors.New("device: invalid roster")
	ErrStale      = errors.New("device: stale roster")
	ErrReused     = errors.New("device: revoked device cannot be authorized again")
	ErrLimit      = errors.New("device: registry full")
	ErrRevoked    = errors.New("device: not an authorized device")
	ErrSignature  = errors.New("device: invalid device signature")
	ErrPersist    = errors.New("device: roster could not be stored")
	ErrCorrupted  = errors.New("device: stored rosters are invalid")
	ErrRate       = errors.New("device: too many roster changes")
	strictEncoder = base64.RawURLEncoding.Strict()
)

type Device struct {
	ID       string `json:"id"`
	Signing  string `json:"signing"`
	Exchange string `json:"exchange"`
}

type Roster struct {
	Identity  string   `json:"identity"`
	Version   uint32   `json:"version"`
	Devices   []Device `json:"devices"`
	Signature string   `json:"signature"`
}

func DeriveID(owner, signing []byte) []byte {
	sum := sha256.Sum256(append(append([]byte(idContext), owner...), signing...))
	return sum[:IDSize]
}

func Message(owner []byte, version uint32, devices [][3][]byte) []byte {
	out := make([]byte, 0, len(rosterContext)+32+4+1+len(devices)*(IDSize+2*KeySize))
	out = append(out, rosterContext...)
	out = append(out, owner...)
	out = binary.BigEndian.AppendUint32(out, version)
	out = append(out, byte(len(devices)))
	for _, d := range devices {
		out = append(out, d[0]...)
		out = append(out, d[1]...)
		out = append(out, d[2]...)
	}
	return out
}

func canonicalExchange(raw []byte) bool {
	if len(raw) != KeySize || raw[31]&0x80 != 0 {
		return false
	}
	if raw[31] != 0x7f {
		return true
	}
	for i := 30; i >= 1; i-- {
		if raw[i] != 0xff {
			return true
		}
	}
	return raw[0] < 0xed
}

func decodeFixed(text string, size int) ([]byte, bool) {
	if len(text) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, false
	}
	raw, err := strictEncoder.DecodeString(text)
	return raw, err == nil && len(raw) == size
}

func Verify(r Roster) (identity.Identity, error) {
	owner, err := identity.Parse(r.Identity)
	if err != nil || r.Version == 0 || r.Version > MaxVersion || len(r.Devices) == 0 || len(r.Devices) > MaxDevices {
		return identity.Identity{}, ErrInvalid
	}
	ownerRaw, _ := strictEncoder.DecodeString(r.Identity)
	parts := make([][3][]byte, 0, len(r.Devices))
	for i, d := range r.Devices {
		id, okID := decodeFixed(d.ID, IDSize)
		exchange, okExchange := decodeFixed(d.Exchange, KeySize)
		key, err := identity.Parse(d.Signing)
		if !okID || !okExchange || err != nil || !canonicalExchange(exchange) {
			return identity.Identity{}, ErrInvalid
		}
		signing, _ := strictEncoder.DecodeString(d.Signing)
		if string(DeriveID(ownerRaw, signing)) != string(id) || key.Equal(owner) {
			return identity.Identity{}, ErrInvalid
		}
		if i > 0 && r.Devices[i-1].ID >= d.ID {
			return identity.Identity{}, ErrInvalid
		}
		for _, other := range r.Devices[:i] {
			if other.Signing == d.Signing || other.Exchange == d.Exchange {
				return identity.Identity{}, ErrInvalid
			}
		}
		parts = append(parts, [3][]byte{id, signing, exchange})
	}
	if owner.Verify(Message(ownerRaw, r.Version, parts), r.Signature) != nil {
		return identity.Identity{}, ErrInvalid
	}
	return owner, nil
}

type Admission struct {
	Identity identity.Identity
	Device   string
}

type entry struct {
	roster  Roster
	revoked []string
	keys    map[string]identity.Identity
}

type stored struct {
	Roster  Roster   `json:"roster"`
	Revoked []string `json:"revoked"`
}

type Limits struct {
	Rate          float64
	Burst         float64
	IdentityRate  float64
	IdentityBurst float64
	Now           func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(rate, burst float64, now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type Registry struct {
	mu       sync.Mutex
	path     string
	rosters  map[string]*entry
	sessions map[any]Admission
	kicks    map[any]func()
	revoked  []func(owner, device string)

	write   sync.Mutex
	lines   int
	size    int64
	limits  Limits
	global  bucket
	buckets map[string]*bucket
}

func Open(path string) (*Registry, error) {
	r := &Registry{
		path:     path,
		rosters:  make(map[string]*entry),
		sessions: make(map[any]Admission),
		kicks:    make(map[any]func()),
		buckets:  make(map[string]*bucket),
	}
	if path == "" {
		return r, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		var records []stored
		if err := json.Unmarshal(data, &records); err != nil || len(records) > MaxIdentities {
			return nil, ErrCorrupted
		}
		for _, record := range records {
			if _, dup := r.rosters[record.Roster.Identity]; dup {
				return nil, ErrCorrupted
			}
			if err := r.load(record); err != nil {
				return nil, err
			}
		}
		if err := r.compact(); err != nil {
			return nil, err
		}
		return r, nil
	}
	complete := bytes.LastIndexByte(data, '\n') + 1
	if complete < len(data) {
		if err := os.Truncate(path, int64(complete)); err != nil {
			return nil, err
		}
	}
	r.size = int64(complete)
	for line := range bytes.SplitSeq(data[:complete], []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var record stored
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, ErrCorrupted
		}
		if current := r.rosters[record.Roster.Identity]; current != nil && record.Roster.Version <= current.roster.Version {
			return nil, ErrCorrupted
		}
		if err := r.load(record); err != nil {
			return nil, err
		}
		r.lines++
	}
	if len(r.rosters) > MaxIdentities {
		return nil, ErrCorrupted
	}
	return r, nil
}

func (r *Registry) load(record stored) error {
	roster := record.Roster
	if _, err := Verify(roster); err != nil || len(record.Revoked) > MaxRevoked {
		return ErrCorrupted
	}
	for _, id := range record.Revoked {
		if _, ok := decodeFixed(id, IDSize); !ok || slices.ContainsFunc(roster.Devices, func(d Device) bool { return d.ID == id }) {
			return ErrCorrupted
		}
	}
	r.rosters[roster.Identity] = newEntry(roster, record.Revoked)
	return nil
}

func (r *Registry) SetLimits(l Limits) {
	r.write.Lock()
	defer r.write.Unlock()
	r.limits = l
}

func (r *Registry) allow(owner string) bool {
	l := r.limits
	if l.Now == nil {
		return true
	}
	now := l.Now()
	b := r.buckets[owner]
	if b == nil {
		b = &bucket{}
	}
	probe := *b
	if !probe.take(l.IdentityRate, l.IdentityBurst, now) {
		return false
	}
	if !r.global.take(l.Rate, l.Burst, now) {
		return false
	}
	*b = probe
	r.buckets[owner] = b
	return true
}

func newEntry(roster Roster, revoked []string) *entry {
	e := &entry{roster: roster, revoked: slices.Clone(revoked), keys: make(map[string]identity.Identity, len(roster.Devices))}
	for _, d := range roster.Devices {
		key, _ := identity.Parse(d.Signing)
		e.keys[d.ID] = key
	}
	return e
}

func (r *Registry) OnRevoke(fn func(owner, device string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, fn)
}

func (r *Registry) Attach(session any, kick func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kicks[session] = kick
}

func (r *Registry) Detach(session any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.kicks, session)
	delete(r.sessions, session)
}

func (r *Registry) Admit(session any, owner identity.Identity, device string, verify func(identity.Identity) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.rosters[owner.String()]
	if e == nil {
		return ErrRevoked
	}
	key, ok := e.keys[device]
	if !ok {
		return ErrRevoked
	}
	if !verify(key) {
		return ErrSignature
	}
	r.sessions[session] = Admission{Identity: owner, Device: device}
	return nil
}

func (r *Registry) Release(session any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, session)
}

func (r *Registry) Authorized(owner, device string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.rosters[owner]
	if e == nil {
		return false
	}
	_, ok := e.keys[device]
	return ok
}

func (r *Registry) Key(owner, device string) (identity.Identity, Device, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.rosters[owner]
	if e == nil {
		return identity.Identity{}, Device{}, false
	}
	key, ok := e.keys[device]
	if !ok {
		return identity.Identity{}, Device{}, false
	}
	i := slices.IndexFunc(e.roster.Devices, func(d Device) bool { return d.ID == device })
	return key, e.roster.Devices[i], true
}

func (r *Registry) Roster(owner string) (Roster, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.rosters[owner]
	if e == nil {
		return Roster{}, false
	}
	return cloneRoster(e.roster), true
}

func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rosters)
}

func (r *Registry) Publish(roster Roster) error {
	if _, err := Verify(roster); err != nil {
		return err
	}
	roster = cloneRoster(roster)
	r.write.Lock()
	removed, kicks, hooks, err := r.publish(roster)
	r.write.Unlock()
	if err != nil {
		return err
	}
	for _, d := range removed {
		for _, hook := range hooks {
			hook(roster.Identity, d)
		}
	}
	for _, kick := range kicks {
		kick()
	}
	return nil
}

func (r *Registry) publish(roster Roster) ([]string, []func(), []func(owner, device string), error) {
	r.mu.Lock()
	current := r.rosters[roster.Identity]
	count := len(r.rosters)
	r.mu.Unlock()
	switch {
	case current == nil && count >= MaxIdentities:
		return nil, nil, nil, ErrLimit
	case current != nil && roster.Version < current.roster.Version:
		return nil, nil, nil, ErrStale
	case current != nil && roster.Version == current.roster.Version:
		if sameRoster(current.roster, roster) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, ErrStale
	}
	var removed, revoked []string
	if current != nil {
		for _, d := range roster.Devices {
			if slices.Contains(current.revoked, d.ID) {
				return nil, nil, nil, ErrReused
			}
		}
		revoked = slices.Clone(current.revoked)
		for _, d := range current.roster.Devices {
			if !slices.ContainsFunc(roster.Devices, func(n Device) bool { return n.ID == d.ID }) {
				removed = append(removed, d.ID)
			}
		}
		revoked = append(revoked, removed...)
		if len(revoked) > MaxRevoked {
			revoked = revoked[len(revoked)-MaxRevoked:]
		}
	}
	if !r.allow(roster.Identity) {
		return nil, nil, nil, ErrRate
	}
	if err := r.append(stored{Roster: roster, Revoked: nonNil(revoked)}); err != nil {
		return nil, nil, nil, ErrPersist
	}
	next := newEntry(roster, revoked)
	r.mu.Lock()
	r.rosters[roster.Identity] = next
	var kicks []func()
	for session, admission := range r.sessions {
		if admission.Identity.String() == roster.Identity && slices.Contains(removed, admission.Device) {
			delete(r.sessions, session)
			if kick := r.kicks[session]; kick != nil {
				kicks = append(kicks, kick)
			}
		}
	}
	hooks := slices.Clone(r.revoked)
	r.mu.Unlock()
	r.lines++
	if r.lines > 2*count+1024 {
		r.compact()
	}
	return removed, kicks, hooks, nil
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func (r *Registry) append(record stored) error {
	if r.path == "" {
		return nil
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, statErr := os.Stat(r.path)
	created := errors.Is(statErr, os.ErrNotExist)
	if created {
		if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < r.size {
		return ErrCorrupted
	}
	if info.Size() > r.size {
		if err := f.Truncate(r.size); err != nil {
			return err
		}
	}
	if _, err = f.Write(line); err == nil {
		err = f.Sync()
	}
	if err == nil && created {
		err = syncDir(filepath.Dir(r.path))
	}
	if err != nil {
		f.Truncate(r.size)
		return err
	}
	r.size += int64(len(line))
	return nil
}

func (r *Registry) compact() error {
	if r.path == "" {
		return nil
	}
	r.mu.Lock()
	all := make([]stored, 0, len(r.rosters))
	for _, e := range r.rosters {
		all = append(all, stored{Roster: e.roster, Revoked: nonNil(e.revoked)})
	}
	r.mu.Unlock()
	slices.SortFunc(all, func(a, b stored) int {
		if a.Roster.Identity < b.Roster.Identity {
			return -1
		}
		return 1
	})
	var data []byte
	for _, record := range all {
		line, err := json.Marshal(record)
		if err != nil {
			return err
		}
		data = append(append(data, line...), '\n')
	}
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".devices-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, r.path); err != nil {
		os.Remove(name)
		return err
	}
	r.lines = len(all)
	r.size = int64(len(data))
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func cloneRoster(r Roster) Roster {
	r.Devices = slices.Clone(r.Devices)
	return r
}

func sameRoster(a, b Roster) bool {
	return a.Identity == b.Identity && a.Version == b.Version && a.Signature == b.Signature && slices.Equal(a.Devices, b.Devices)
}
