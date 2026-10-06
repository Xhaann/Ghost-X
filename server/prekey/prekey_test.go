package prekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

type key struct {
	private  ed25519.PrivateKey
	identity identity.Identity
}

func newKey(t testing.TB) key {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Parse(base64.RawURLEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	return key{private: private, identity: id}
}

func text(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func static() Static {
	return Static{Key: text(32), Signature: text(64)}
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
	prekeys  *Registry
	sessions *auth.Registry
}

func newFixture() fixture {
	p := NewRegistry()
	return fixture{prekeys: p, sessions: auth.NewRegistry(time.Now, p)}
}

func (f fixture) connect(t testing.TB, k key) (*auth.Session, *inbox) {
	t.Helper()
	s := f.sessions.Open()
	box := &inbox{accept: true}
	f.prekeys.Attach(s, box.push)
	nonce, err := s.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, auth.Message(nonce)))
	if _, err := s.Authenticate(k.identity.String(), signature); err != nil {
		t.Fatal(err)
	}
	return s, box
}

type owner struct {
	key     key
	static  Static
	device  string
	signed  Prekey
	onetime []Prekey
	session *auth.Session
	box     *inbox
}

func (f fixture) publish(t testing.TB, k key, n int) owner {
	t.Helper()
	s, box := f.connect(t, k)
	o := owner{key: k, static: static(), device: text(16), signed: Prekey{ID: 1, Key: text(32), Signature: text(64)}, onetime: prekeys(1, n), session: s, box: box}
	if available, err := f.prekeys.Publish(s, o.static, o.device, o.signed, o.onetime); err != nil || available != n {
		t.Fatalf("Publish = %d %v", available, err)
	}
	return o
}

func initiation(o owner, onetime *uint32) Initiation {
	return Initiation{Device: o.device, Signed: o.signed.ID, Onetime: onetime, Ephemeral: text(32), Proof: text(64), Confirm: text(32)}
}

func TestPublishRequiresAuthenticationAndKeepsDevicesStable(t *testing.T) {
	f := newFixture()
	s := f.sessions.Open()
	if _, err := f.prekeys.Publish(s, static(), text(16), Prekey{ID: 1}, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated publish = %v", err)
	}
	o := f.publish(t, newKey(t), 3)
	if _, err := f.prekeys.Publish(o.session, o.static, text(16), o.signed, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("device switch = %v", err)
	}
	if _, err := f.prekeys.Publish(o.session, o.static, o.device, Prekey{ID: 1, Key: text(32), Signature: text(64)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same signed id with another key = %v", err)
	}
	if _, err := f.prekeys.Publish(o.session, o.static, o.device, Prekey{ID: 0, Key: text(32), Signature: text(64)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("older signed id = %v", err)
	}
	next := Prekey{ID: 2, Key: text(32), Signature: text(64)}
	if _, err := f.prekeys.Publish(o.session, o.static, o.device, next, nil); err != nil {
		t.Fatal(err)
	}
	_, current, previous, ok := f.prekeys.Device(o.key.identity, o.device)
	if !ok || current != next || previous == nil || *previous != o.signed {
		t.Fatalf("rotation = %+v %+v", current, previous)
	}
}

func TestOnetimePrekeysAreDeduplicatedAndBounded(t *testing.T) {
	f := newFixture()
	o := f.publish(t, newKey(t), 5)
	if available, err := f.prekeys.Publish(o.session, o.static, o.device, o.signed, o.onetime); err != nil || available != 5 {
		t.Fatalf("republish duplicated keys: %d", available)
	}
	conflict := prekeys(1, 1)
	if _, err := f.prekeys.Publish(o.session, o.static, o.device, o.signed, conflict); !errors.Is(err, ErrInvalid) {
		t.Fatalf("conflicting key for an existing id = %v", err)
	}
	if available, _ := f.prekeys.Publish(o.session, o.static, o.device, o.signed, prekeys(100, 200)); available != MaxOnetime {
		t.Fatalf("available = %d, want %d", available, MaxOnetime)
	}
}

func TestFetchReservesEachOnetimePrekeyOnce(t *testing.T) {
	f := newFixture()
	o := f.publish(t, newKey(t), 40)
	var mu sync.Mutex
	seen := map[uint32]int{}
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			s, bundles, ok := f.prekeys.Fetch(o.key.identity)
			if !ok || s != o.static || len(bundles) != 1 || bundles[0].Signed != o.signed {
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
	if _, _, ok := f.prekeys.Fetch(newKey(t).identity); ok {
		t.Fatal("bundle for unknown identity")
	}
}

func TestInitiationConsumesReservedPrekeyOnce(t *testing.T) {
	f := newFixture()
	b := f.publish(t, newKey(t), 3)
	sender, _ := f.connect(t, newKey(t))
	_, bundles, _ := f.prekeys.Fetch(b.key.identity)
	id := bundles[0].Onetime.ID
	unreserved := uint32(3)

	if err := f.prekeys.Initiate(sender, b.key.identity, initiation(b, &unreserved), b.static); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unreserved onetime = %v", err)
	}
	first := initiation(b, &id)
	if err := f.prekeys.Initiate(sender, b.key.identity, first, b.static); err != nil {
		t.Fatal(err)
	}
	if err := f.prekeys.Initiate(sender, b.key.identity, initiation(b, &id), b.static); !errors.Is(err, ErrInvalid) {
		t.Fatalf("consumed onetime reused = %v", err)
	}
	replay := initiation(b, nil)
	replay.Ephemeral = first.Ephemeral
	if err := f.prekeys.Initiate(sender, b.key.identity, replay, b.static); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed ephemeral = %v", err)
	}
	stale := initiation(b, nil)
	stale.Signed = 9
	if err := f.prekeys.Initiate(sender, b.key.identity, stale, b.static); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown signed prekey = %v", err)
	}
	if err := f.prekeys.Initiate(sender, b.key.identity, initiation(b, nil), static()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched static key = %v", err)
	}
	other := initiation(b, nil)
	other.Device = text(16)
	if err := f.prekeys.Initiate(sender, b.key.identity, other, b.static); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown device = %v", err)
	}
	if got := b.box.all(); len(got) != 1 || got[0].Initiation.Ephemeral != first.Ephemeral {
		t.Fatalf("delivered %+v", got)
	}
}

func TestPendingInitiationsAndAcceptancesWaitForPublication(t *testing.T) {
	f := newFixture()
	bKey, aKey := newKey(t), newKey(t)
	b := f.publish(t, bKey, 3)
	b.session.Close()
	f.prekeys.Detach(b.session)

	a, aBox := f.connect(t, aKey)
	_, bundles, _ := f.prekeys.Fetch(bKey.identity)
	id := bundles[0].Onetime.ID
	init := initiation(b, &id)
	if err := f.prekeys.Initiate(a, bKey.identity, init, b.static); err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.prekeys.Detach(a)

	s, box := f.connect(t, bKey)
	if _, err := f.prekeys.Publish(s, b.static, b.device, b.signed, nil); err != nil {
		t.Fatal(err)
	}
	got := box.all()
	if len(got) != 1 || got[0].Initiation == nil || got[0].Initiation.From != aKey.identity.String() {
		t.Fatalf("pending delivery = %+v", got)
	}
	if err := f.prekeys.Accept(s, newKey(t).identity, init.Ephemeral, text(32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accept for another initiator = %v", err)
	}
	if err := f.prekeys.Accept(s, aKey.identity, init.Ephemeral, text(32)); err != nil {
		t.Fatal(err)
	}
	if err := f.prekeys.Accept(s, aKey.identity, init.Ephemeral, text(32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second accept = %v", err)
	}
	if len(aBox.all()) != 0 {
		t.Fatal("closed initiator received acceptance")
	}
	a2, a2Box := f.connect(t, aKey)
	if _, err := f.prekeys.Publish(a2, static(), text(16), Prekey{ID: 1, Key: text(32), Signature: text(64)}, nil); err != nil {
		t.Fatal(err)
	}
	if got := a2Box.all(); len(got) != 1 || got[0].Acceptance == nil || got[0].Acceptance.From != bKey.identity.String() {
		t.Fatalf("pending acceptance = %+v", got)
	}
	stranger, _ := f.connect(t, newKey(t))
	if err := f.prekeys.Accept(stranger, aKey.identity, init.Ephemeral, text(32)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("accept from an unpublished session = %v", err)
	}
}

func TestPendingInitiationsAreBounded(t *testing.T) {
	f := newFixture()
	b := f.publish(t, newKey(t), 0)
	b.session.Close()
	f.prekeys.Detach(b.session)
	sender, _ := f.connect(t, newKey(t))
	for i := range MaxPending {
		if err := f.prekeys.Initiate(sender, b.key.identity, initiation(b, nil), b.static); err != nil {
			t.Fatalf("pending %d = %v", i, err)
		}
	}
	if err := f.prekeys.Initiate(sender, b.key.identity, initiation(b, nil), b.static); !errors.Is(err, ErrLimit) {
		t.Fatalf("over pending limit = %v", err)
	}
}

func TestStaticKeyChangeDiscardsOldBundles(t *testing.T) {
	f := newFixture()
	b := f.publish(t, newKey(t), 3)
	renewed := static()
	if _, err := f.prekeys.Publish(b.session, renewed, b.device, b.signed, prekeys(10, 2)); err != nil {
		t.Fatal(err)
	}
	s, bundles, _ := f.prekeys.Fetch(b.key.identity)
	if s != renewed || bundles[0].Onetime == nil || bundles[0].Onetime.ID < 10 {
		t.Fatalf("stale bundle survived: %+v %+v", s, bundles)
	}
}

func TestIdentitiesAreEvictedWhenFull(t *testing.T) {
	f := newFixture()
	first := f.publish(t, newKey(t), 1)
	for range MaxIdentities {
		o := f.publish(t, newKey(t), 0)
		o.session.Close()
		f.prekeys.Detach(o.session)
	}
	if _, _, ok := f.prekeys.Fetch(first.key.identity); ok {
		t.Fatal("oldest identity was not evicted")
	}
	if len(f.prekeys.owners) > MaxIdentities {
		t.Fatalf("owners = %d", len(f.prekeys.owners))
	}
}

func TestConcurrentInitiationsAndPublication(t *testing.T) {
	f := newFixture()
	b := f.publish(t, newKey(t), MaxOnetime)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			s, _ := f.connect(t, newKey(t))
			for range 3 {
				_, bundles, ok := f.prekeys.Fetch(b.key.identity)
				if !ok {
					t.Error("missing bundle")
					return
				}
				init := initiation(b, nil)
				if p := bundles[0].Onetime; p != nil {
					id := p.ID
					init.Onetime = &id
				}
				if err := f.prekeys.Initiate(s, b.key.identity, init, b.static); err != nil && !errors.Is(err, ErrLimit) {
					t.Error(err)
				}
			}
			_ = i
		})
		wg.Go(func() {
			f.prekeys.Publish(b.session, b.static, b.device, b.signed, prekeys(1000+i*10, 5))
		})
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
	_ = fmt.Sprint(len(onetime))
}
