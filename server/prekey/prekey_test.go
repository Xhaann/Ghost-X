package prekey

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	roster "github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/device/devicetest"
	"github.com/Xhaann/ghost-x/server/identity"
)

func text(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func prekeys(from, n int) []Prekey {
	out := make([]Prekey, n)
	for i := range out {
		out[i] = Prekey{ID: uint32(from + i), Key: text(32), Signature: text(64)}
	}
	return out
}

type inbox struct {
	mu     sync.Mutex
	events []Event
	accept bool
}

func (b *inbox) push(e Event) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.accept {
		return false
	}
	b.events = append(b.events, e)
	return true
}

func (b *inbox) all() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Event(nil), b.events...)
}

type fixture struct {
	devices  *roster.Registry
	prekeys  *Registry
	sessions *auth.Registry
}

func newFixture() fixture {
	d, _ := roster.Open("")
	p := NewRegistry(d.Authorized)
	d.OnRevoke(p.RemoveDevice)
	return fixture{devices: d, prekeys: p, sessions: auth.NewRegistry(time.Now, p, d)}
}

type member struct {
	owner  *devicetest.Identity
	device *devicetest.Device
	id     identity.Identity
}

func (f fixture) identity(t testing.TB, n int) []member {
	t.Helper()
	owner := devicetest.NewIdentity()
	var list []*devicetest.Device
	for range n {
		list = append(list, owner.NewDevice())
	}
	if err := f.devices.Publish(owner.Add(list...)); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Parse(owner.Identity)
	out := make([]member, n)
	for i, d := range list {
		out[i] = member{owner: owner, device: d, id: id}
	}
	return out
}

func (f fixture) connect(t testing.TB, m member) (*auth.Session, *inbox) {
	t.Helper()
	s := f.sessions.Open()
	box := &inbox{accept: true}
	f.prekeys.Attach(s, box.push)
	nonce, err := s.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(m.owner.Identity, m.device.ID, m.device.AuthSignature(m.owner, nonce)); err != nil {
		t.Fatal(err)
	}
	return s, box
}

type owner struct {
	member
	signed  Prekey
	onetime []Prekey
	session *auth.Session
	box     *inbox
}

func (f fixture) publish(t testing.TB, m member, n int) owner {
	t.Helper()
	s, box := f.connect(t, m)
	o := owner{member: m, signed: Prekey{ID: 1, Key: text(32), Signature: text(64)}, onetime: prekeys(1, n), session: s, box: box}
	if available, err := f.prekeys.Publish(s, m.device.ID, o.signed, o.onetime); err != nil || available != n {
		t.Fatalf("Publish = %d %v", available, err)
	}
	return o
}

func initiation(o owner, onetime *uint32) Initiation {
	return Initiation{Device: o.device.ID, Signed: o.signed.ID, Onetime: onetime, Ephemeral: text(32), Proof: text(64), Confirm: text(32)}
}

func TestWithdrawnAuthorizationHidesPrekeysWithoutAPurge(t *testing.T) {
	d, _ := roster.Open("")
	var withdrawn sync.Map
	p := NewRegistry(func(owner, device string) bool {
		_, gone := withdrawn.Load(device)
		return !gone && d.Authorized(owner, device)
	})
	f := fixture{devices: d, prekeys: p, sessions: auth.NewRegistry(time.Now, p, d)}
	pair := f.identity(t, 2)
	kept := f.publish(t, pair[0], 2)
	hidden := f.publish(t, pair[1], 2)
	alice := f.identity(t, 1)[0]
	sender, _ := f.connect(t, alice)
	withdrawn.Store(hidden.device.ID, true)
	if _, _, ok := p.Device(hidden.id, hidden.device.ID); ok {
		t.Fatal("prekeys of a device without authorization are still served")
	}
	if _, _, ok := p.Device(kept.id, kept.device.ID); !ok {
		t.Fatal("prekeys of the authorized sibling are hidden")
	}
	bundles, ok := p.Fetch(hidden.id)
	if !ok || len(bundles) != 1 || bundles[0].Device != kept.device.ID {
		t.Fatalf("bundle = %+v", bundles)
	}
	if err := p.Initiate(sender, hidden.id, initiation(hidden, nil), hidden.signed.Key); err == nil {
		t.Fatal("initiation reached a device without authorization")
	}
	if err := p.Initiate(sender, kept.id, initiation(kept, nil), kept.signed.Key); err != nil {
		t.Fatal(err)
	}
}

func TestPublishRequiresTheAuthenticatedDevice(t *testing.T) {
	f := newFixture()
	s := f.sessions.Open()
	if _, err := f.prekeys.Publish(s, text(16), Prekey{ID: 1}, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated publish = %v", err)
	}
	pair := f.identity(t, 2)
	o := f.publish(t, pair[0], 3)
	if _, err := f.prekeys.Publish(o.session, pair[1].device.ID, o.signed, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("publishing for a sibling device = %v", err)
	}
	if _, err := f.prekeys.Publish(o.session, text(16), o.signed, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("publishing for an unknown device = %v", err)
	}
	if _, err := f.prekeys.Publish(o.session, o.device.ID, Prekey{ID: 1, Key: text(32), Signature: text(64)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same signed id with another key = %v", err)
	}
	if _, err := f.prekeys.Publish(o.session, o.device.ID, Prekey{ID: 0, Key: text(32), Signature: text(64)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("older signed id = %v", err)
	}
	next := Prekey{ID: 2, Key: text(32), Signature: text(64)}
	if _, err := f.prekeys.Publish(o.session, o.device.ID, next, nil); err != nil {
		t.Fatal(err)
	}
	current, previous, ok := f.prekeys.Device(o.id, o.device.ID)
	if !ok || current != next || previous == nil || *previous != o.signed {
		t.Fatalf("rotation = %+v %+v", current, previous)
	}
}

func TestEachDeviceHasIsolatedPrekeys(t *testing.T) {
	f := newFixture()
	pair := f.identity(t, 2)
	a := f.publish(t, pair[0], 2)
	bs, bBox := f.connect(t, pair[1])
	b := owner{member: pair[1], signed: Prekey{ID: 1, Key: text(32), Signature: text(64)}, onetime: prekeys(500, 2), session: bs, box: bBox}
	if _, err := f.prekeys.Publish(bs, b.device.ID, b.signed, b.onetime); err != nil {
		t.Fatal(err)
	}
	bundles, ok := f.prekeys.Fetch(a.id)
	if !ok || len(bundles) != 2 {
		t.Fatalf("bundles = %+v", bundles)
	}
	byDevice := map[string]Bundle{}
	for _, bundle := range bundles {
		byDevice[bundle.Device] = bundle
	}
	if byDevice[a.device.ID].Signed != a.signed || byDevice[b.device.ID].Signed != b.signed {
		t.Fatal("signed prekeys crossed devices")
	}
	if byDevice[a.device.ID].Onetime.Key != a.onetime[0].Key || byDevice[b.device.ID].Onetime.Key != b.onetime[0].Key {
		t.Fatal("one-time prekeys crossed devices")
	}
	sender := f.identity(t, 1)[0]
	s, _ := f.connect(t, sender)
	stolen := *byDevice[a.device.ID].Onetime
	forB := initiation(b, &stolen.ID)
	if err := f.prekeys.Initiate(s, a.id, forB, b.signed.Key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("consuming a sibling's one-time prekey = %v", err)
	}
	crossed := initiation(b, nil)
	if err := f.prekeys.Initiate(s, a.id, crossed, a.signed.Key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another device's signed prekey = %v", err)
	}
	if key, ok := f.prekeys.Onetime(a.id, b.device.ID, stolen.ID); ok && key == stolen.Key {
		t.Fatal("prekey resolved under the wrong device")
	}
}

func TestOnetimePrekeysAreDeduplicatedAndBounded(t *testing.T) {
	f := newFixture()
	o := f.publish(t, f.identity(t, 1)[0], 5)
	if available, err := f.prekeys.Publish(o.session, o.device.ID, o.signed, o.onetime); err != nil || available != 5 {
		t.Fatalf("republish duplicated keys: %d", available)
	}
	if _, err := f.prekeys.Publish(o.session, o.device.ID, o.signed, prekeys(1, 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("conflicting key for an existing id = %v", err)
	}
	if available, _ := f.prekeys.Publish(o.session, o.device.ID, o.signed, prekeys(100, 200)); available != MaxOnetime {
		t.Fatalf("available = %d, want %d", available, MaxOnetime)
	}
}

func TestFetchReservesEachOnetimePrekeyOnce(t *testing.T) {
	f := newFixture()
	o := f.publish(t, f.identity(t, 1)[0], 40)
	var mu sync.Mutex
	seen := map[uint32]int{}
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			bundles, ok := f.prekeys.Fetch(o.id)
			if !ok || len(bundles) != 1 || bundles[0].Signed != o.signed {
				t.Error("bad bundle")
				return
			}
			if p := bundles[0].Onetime; p != nil {
				mu.Lock()
				seen[p.ID]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != 40 {
		t.Fatalf("reserved %d distinct keys, want 40", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("key %d handed out %d times", id, n)
		}
	}
	if _, ok := f.prekeys.Fetch(f.identity(t, 1)[0].id); ok {
		t.Fatal("bundle for an identity that never published")
	}
}

func TestInitiationConsumesReservedPrekeyOnce(t *testing.T) {
	f := newFixture()
	b := f.publish(t, f.identity(t, 1)[0], 3)
	sender, _ := f.connect(t, f.identity(t, 1)[0])
	bundles, _ := f.prekeys.Fetch(b.id)
	id := bundles[0].Onetime.ID
	unreserved := uint32(3)

	if err := f.prekeys.Initiate(sender, b.id, initiation(b, &unreserved), b.signed.Key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unreserved onetime = %v", err)
	}
	first := initiation(b, &id)
	if err := f.prekeys.Initiate(sender, b.id, first, b.signed.Key); err != nil {
		t.Fatal(err)
	}
	if err := f.prekeys.Initiate(sender, b.id, initiation(b, &id), b.signed.Key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("consumed onetime reused = %v", err)
	}
	replay := initiation(b, nil)
	replay.Ephemeral = first.Ephemeral
	if err := f.prekeys.Initiate(sender, b.id, replay, b.signed.Key); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed ephemeral = %v", err)
	}
	stale := initiation(b, nil)
	stale.Signed = 9
	if err := f.prekeys.Initiate(sender, b.id, stale, b.signed.Key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown signed prekey = %v", err)
	}
	if err := f.prekeys.Initiate(sender, b.id, initiation(b, nil), text(32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched signed key = %v", err)
	}
	other := initiation(b, nil)
	other.Device = text(16)
	if err := f.prekeys.Initiate(sender, b.id, other, b.signed.Key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown device = %v", err)
	}
	got := b.box.all()
	if len(got) != 1 || got[0].Initiation.Ephemeral != first.Ephemeral {
		t.Fatalf("delivered %+v", got)
	}
}

func TestInitiationsReachOnlyTheTargetDevice(t *testing.T) {
	f := newFixture()
	pair := f.identity(t, 2)
	a := f.publish(t, pair[0], 1)
	b := f.publish(t, pair[1], 1)
	sender := f.identity(t, 1)[0]
	s, _ := f.connect(t, sender)
	init := initiation(b, nil)
	if err := f.prekeys.Initiate(s, b.id, init, b.signed.Key); err != nil {
		t.Fatal(err)
	}
	if len(a.box.all()) != 0 {
		t.Fatal("sibling device received another device's initiation")
	}
	got := b.box.all()
	if len(got) != 1 || got[0].Initiation.From != sender.owner.Identity || got[0].Initiation.FromDevice != sender.device.ID {
		t.Fatalf("initiation = %+v", got)
	}
}

func TestPendingInitiationsAndAcceptancesAreDeviceAddressed(t *testing.T) {
	f := newFixture()
	bMember := f.identity(t, 1)[0]
	aPair := f.identity(t, 2)
	b := f.publish(t, bMember, 3)
	b.session.Close()
	f.prekeys.Detach(b.session)

	a, aBox := f.connect(t, aPair[0])
	bundles, _ := f.prekeys.Fetch(bMember.id)
	id := bundles[0].Onetime.ID
	init := initiation(b, &id)
	if err := f.prekeys.Initiate(a, bMember.id, init, b.signed.Key); err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.prekeys.Detach(a)

	s, box := f.connect(t, bMember)
	if _, err := f.prekeys.Publish(s, bMember.device.ID, b.signed, nil); err != nil {
		t.Fatal(err)
	}
	got := box.all()
	if len(got) != 1 || got[0].Initiation == nil || got[0].Initiation.FromDevice != aPair[0].device.ID {
		t.Fatalf("pending delivery = %+v", got)
	}
	if err := f.prekeys.Accept(s, aPair[0].id, aPair[1].device.ID, init.Ephemeral, text(32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accept addressed to the sibling device = %v", err)
	}
	if err := f.prekeys.Accept(s, aPair[0].id, aPair[0].device.ID, init.Ephemeral, text(32)); err != nil {
		t.Fatal(err)
	}
	if err := f.prekeys.Accept(s, aPair[0].id, aPair[0].device.ID, init.Ephemeral, text(32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second accept = %v", err)
	}
	if len(aBox.all()) != 0 {
		t.Fatal("closed initiator received acceptance")
	}
	sibling, siblingBox := f.connect(t, aPair[1])
	f.prekeys.Publish(sibling, aPair[1].device.ID, Prekey{ID: 1, Key: text(32), Signature: text(64)}, nil)
	if len(siblingBox.all()) != 0 {
		t.Fatal("sibling device received the acceptance")
	}
	a2, a2Box := f.connect(t, aPair[0])
	if _, err := f.prekeys.Publish(a2, aPair[0].device.ID, Prekey{ID: 1, Key: text(32), Signature: text(64)}, nil); err != nil {
		t.Fatal(err)
	}
	if got := a2Box.all(); len(got) != 1 || got[0].Acceptance == nil || got[0].Acceptance.FromDevice != bMember.device.ID {
		t.Fatalf("pending acceptance = %+v", got)
	}
	stranger, _ := f.connect(t, f.identity(t, 1)[0])
	if err := f.prekeys.Accept(stranger, aPair[0].id, aPair[0].device.ID, init.Ephemeral, text(32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accept from a device without prekeys = %v", err)
	}
}

func TestRevokedDevicesLosePrekeysAndCannotParticipate(t *testing.T) {
	f := newFixture()
	pair := f.identity(t, 2)
	keep := f.publish(t, pair[0], 2)
	gone := f.publish(t, pair[1], 2)
	sender := f.identity(t, 1)[0]
	s, _ := f.connect(t, sender)
	pending := initiation(gone, nil)
	gone.box.accept = false
	if err := f.prekeys.Initiate(s, gone.id, pending, gone.signed.Key); err != nil {
		t.Fatal(err)
	}
	if err := f.devices.Publish(pair[0].owner.Remove(pair[1].device)); err != nil {
		t.Fatal(err)
	}
	bundles, ok := f.prekeys.Fetch(keep.id)
	if !ok || len(bundles) != 1 || bundles[0].Device != keep.device.ID {
		t.Fatalf("bundles after revocation = %+v", bundles)
	}
	if _, _, ok := f.prekeys.Device(gone.id, gone.device.ID); ok {
		t.Fatal("revoked device still has prekeys")
	}
	if _, err := f.prekeys.Publish(gone.session, gone.device.ID, gone.signed, prekeys(50, 2)); err == nil {
		t.Fatal("revoked device republished prekeys")
	}
	if err := f.prekeys.Initiate(s, gone.id, initiation(gone, nil), gone.signed.Key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("initiation to revoked device = %v", err)
	}
	if f.prekeys.pending != 0 {
		t.Fatalf("pending initiations for revoked device retained: %d", f.prekeys.pending)
	}
	if err := f.devices.Publish(sender.owner.Remove(sender.device)); err == nil {
		t.Fatal("empty roster accepted")
	}
}

func TestPendingInitiationsAreBounded(t *testing.T) {
	f := newFixture()
	b := f.publish(t, f.identity(t, 1)[0], 0)
	b.session.Close()
	f.prekeys.Detach(b.session)
	sender, _ := f.connect(t, f.identity(t, 1)[0])
	for i := range MaxPending {
		if err := f.prekeys.Initiate(sender, b.id, initiation(b, nil), b.signed.Key); err != nil {
			t.Fatalf("pending %d = %v", i, err)
		}
	}
	if err := f.prekeys.Initiate(sender, b.id, initiation(b, nil), b.signed.Key); !errors.Is(err, ErrLimit) {
		t.Fatalf("over pending limit = %v", err)
	}
}

func TestIdentitiesAreEvictedWhenFull(t *testing.T) {
	f := newFixture()
	first := f.publish(t, f.identity(t, 1)[0], 1)
	for range MaxIdentities {
		o := f.publish(t, f.identity(t, 1)[0], 0)
		o.session.Close()
		f.prekeys.Detach(o.session)
	}
	if _, ok := f.prekeys.Fetch(first.id); ok {
		t.Fatal("oldest identity was not evicted")
	}
	if len(f.prekeys.owners) > MaxIdentities {
		t.Fatalf("owners = %d", len(f.prekeys.owners))
	}
}

func TestConcurrentInitiationsPublicationAndRevocation(t *testing.T) {
	f := newFixture()
	pair := f.identity(t, 2)
	b := f.publish(t, pair[0], MaxOnetime)
	f.publish(t, pair[1], 10)
	senders := make([]member, 10)
	for i := range senders {
		senders[i] = f.identity(t, 1)[0]
	}
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			s, _ := f.connect(t, senders[i])
			for range 3 {
				bundles, ok := f.prekeys.Fetch(b.id)
				if !ok {
					t.Error("missing bundle")
					return
				}
				for _, bundle := range bundles {
					if bundle.Device != b.device.ID {
						continue
					}
					init := initiation(b, nil)
					if p := bundle.Onetime; p != nil {
						id := p.ID
						init.Onetime = &id
					}
					if err := f.prekeys.Initiate(s, b.id, init, b.signed.Key); err != nil && !errors.Is(err, ErrLimit) {
						t.Error(err)
					}
				}
			}
		})
		wg.Go(func() {
			f.prekeys.Publish(b.session, b.device.ID, b.signed, prekeys(1000+i*10, 5))
		})
		if i == 5 {
			wg.Go(func() { f.devices.Publish(pair[0].owner.Remove(pair[1].device)) })
		}
	}
	wg.Wait()
	onetime := map[uint32]bool{}
	for _, e := range b.box.all() {
		if e.Initiation.Onetime != nil {
			if onetime[*e.Initiation.Onetime] {
				t.Fatalf("onetime %d consumed twice", *e.Initiation.Onetime)
			}
			onetime[*e.Initiation.Onetime] = true
		}
	}
	if _, _, ok := f.prekeys.Device(b.id, pair[1].device.ID); ok {
		t.Fatal("revoked device kept prekeys")
	}
}
