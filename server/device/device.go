package device

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"

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

type Registry struct {
	mu       sync.Mutex
	path     string
	rosters  map[string]*entry
	sessions map[any]Admission
	kicks    map[any]func()
	revoked  []func(owner, device string)
}

func Open(path string) (*Registry, error) {
	r := &Registry{
		path:     path,
		rosters:  make(map[string]*entry),
		sessions: make(map[any]Admission),
		kicks:    make(map[any]func()),
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
	var records []stored
	if err := json.Unmarshal(data, &records); err != nil || len(records) > MaxIdentities {
		return nil, ErrCorrupted
	}
	for _, record := range records {
		roster := record.Roster
		if _, err := Verify(roster); err != nil || len(record.Revoked) > MaxRevoked {
			return nil, ErrCorrupted
		}
		if _, dup := r.rosters[roster.Identity]; dup {
			return nil, ErrCorrupted
		}
		for _, id := range record.Revoked {
			if _, ok := decodeFixed(id, IDSize); !ok || slices.ContainsFunc(roster.Devices, func(d Device) bool { return d.ID == id }) {
				return nil, ErrCorrupted
			}
		}
		r.rosters[roster.Identity] = newEntry(roster, record.Revoked)
	}
	return r, nil
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
	r.mu.Lock()
	current := r.rosters[roster.Identity]
	switch {
	case current == nil && len(r.rosters) >= MaxIdentities:
		r.mu.Unlock()
		return ErrLimit
	case current != nil && roster.Version < current.roster.Version:
		r.mu.Unlock()
		return ErrStale
	case current != nil && roster.Version == current.roster.Version:
		same := sameRoster(current.roster, roster)
		r.mu.Unlock()
		if same {
			return nil
		}
		return ErrStale
	}
	if current != nil {
		for _, d := range roster.Devices {
			if slices.Contains(current.revoked, d.ID) {
				r.mu.Unlock()
				return ErrReused
			}
		}
	}
	previous := current
	var revoked []string
	if previous != nil {
		revoked = slices.Clone(previous.revoked)
		for _, d := range previous.roster.Devices {
			if !slices.ContainsFunc(roster.Devices, func(n Device) bool { return n.ID == d.ID }) {
				revoked = append(revoked, d.ID)
			}
		}
		if len(revoked) > MaxRevoked {
			revoked = revoked[len(revoked)-MaxRevoked:]
		}
	}
	r.rosters[roster.Identity] = newEntry(roster, revoked)
	if err := r.persist(); err != nil {
		if previous == nil {
			delete(r.rosters, roster.Identity)
		} else {
			r.rosters[roster.Identity] = previous
		}
		r.mu.Unlock()
		return ErrPersist
	}
	var removed []string
	if previous != nil {
		for _, d := range previous.roster.Devices {
			if !slices.ContainsFunc(roster.Devices, func(n Device) bool { return n.ID == d.ID }) {
				removed = append(removed, d.ID)
			}
		}
	}
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

func (r *Registry) persist() error {
	if r.path == "" {
		return nil
	}
	all := make([]stored, 0, len(r.rosters))
	for _, e := range r.rosters {
		revoked := e.revoked
		if revoked == nil {
			revoked = []string{}
		}
		all = append(all, stored{Roster: e.roster, Revoked: revoked})
	}
	slices.SortFunc(all, func(a, b stored) int {
		if a.Roster.Identity < b.Roster.Identity {
			return -1
		}
		return 1
	})
	data, err := json.Marshal(all)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".devices-*")
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
	return os.Rename(name, r.path)
}

func cloneRoster(r Roster) Roster {
	r.Devices = slices.Clone(r.Devices)
	return r
}

func sameRoster(a, b Roster) bool {
	return a.Identity == b.Identity && a.Version == b.Version && a.Signature == b.Signature && slices.Equal(a.Devices, b.Devices)
}
