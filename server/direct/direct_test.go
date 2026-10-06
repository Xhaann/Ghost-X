package direct

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func exchangeKey(t testing.TB) string {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
}

func newBundle(t testing.TB) Bundle {
	t.Helper()
	return Bundle{Key: exchangeKey(t), Signature: randomText(64)}
}

func newSession(t testing.TB, id string, epoch uint32) SessionBundle {
	t.Helper()
	return SessionBundle{ID: id, Epoch: epoch, Key: exchangeKey(t), Signature: randomText(64)}
}

func envelopeFor(s SessionBundle) Envelope {
	return Envelope{
		Session:    s.ID,
		Epoch:      s.Epoch,
		Salt:       randomText(32),
		IV:         randomText(12),
		Ciphertext: randomText(48),
	}
}

type inbox struct {
	mu       sync.Mutex
	messages []Message
	accept   bool
}

func newInbox() *inbox {
	return &inbox{accept: true}
}

func (b *inbox) deliver(m Message) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.accept {
		return false
	}
	b.messages = append(b.messages, m)
	return true
}

func (b *inbox) all() []Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Message(nil), b.messages...)
}

type fixture struct {
	direct   *Registry
	sessions *auth.Registry
}

func newFixture() fixture {
	d := NewRegistry()
	return fixture{direct: d, sessions: auth.NewRegistry(time.Now, d)}
}

func (f fixture) open(t testing.TB) (*auth.Session, *inbox) {
	t.Helper()
	s := f.sessions.Open()
	box := newInbox()
	f.direct.Attach(s, box.deliver)
	return s, box
}

func (f fixture) authenticated(t testing.TB, k key) (*auth.Session, *inbox) {
	t.Helper()
	s, box := f.open(t)
	authenticate(t, s, k)
	return s, box
}

func (f fixture) published(t testing.TB, k key, b Bundle) (*auth.Session, *inbox) {
	t.Helper()
	s, box := f.authenticated(t, k)
	if err := f.direct.Publish(s, b); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	return s, box
}

type peer struct {
	session *auth.Session
	box     *inbox
	keys    SessionBundle
}

func (f fixture) ready(t testing.TB, k key, b Bundle) peer {
	t.Helper()
	s, box := f.published(t, k, b)
	keys := newSession(t, randomText(16), 0)
	if err := f.direct.Establish(s, b.Key, keys); err != nil {
		t.Fatalf("Establish() = %v", err)
	}
	return peer{session: s, box: box, keys: keys}
}

func (f fixture) rotate(t testing.TB, p *peer, b Bundle) {
	t.Helper()
	next := newSession(t, p.keys.ID, p.keys.Epoch+1)
	if err := f.direct.Establish(p.session, b.Key, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	p.keys = next
}

func authenticate(t testing.TB, s *auth.Session, k key) {
	t.Helper()
	nonce, err := s.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, auth.Message(nonce)))
	if _, err := s.Authenticate(k.identity.String(), signature); err != nil {
		t.Fatal(err)
	}
}

func TestRoutesEnvelopeToTargetSessionWithSenderBundles(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle, bBundle := newBundle(t), newBundle(t)
	sender := f.ready(t, a, aBundle)
	recipient := f.ready(t, b, bBundle)

	envelope := envelopeFor(recipient.keys)
	if err := f.direct.Send(sender.session, b.identity, "m1", 0, []Envelope{envelope}); err != nil {
		t.Fatalf("Send() = %v", err)
	}
	got := recipient.box.all()
	want := Message{ID: "m1", From: a.identity.String(), Sender: aBundle, Session: sender.keys, Envelope: envelope}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %+v, want %+v", got, want)
	}
	if len(sender.box.all()) != 0 {
		t.Fatal("sender received its own message")
	}
}

func TestUnauthenticatedSessionsCannotUseSessions(t *testing.T) {
	f := newFixture()
	b := newKey(t)
	recipient := f.ready(t, b, newBundle(t))
	s, _ := f.open(t)
	if err := f.direct.Publish(s, newBundle(t)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Publish = %v", err)
	}
	if err := f.direct.Establish(s, newBundle(t).Key, newSession(t, randomText(16), 0)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Establish = %v", err)
	}
	if err := f.direct.Send(s, b.identity, "m1", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Send = %v", err)
	}
	if len(recipient.box.all()) != 0 {
		t.Fatal("unauthenticated message delivered")
	}
}

func TestSenderMustPublishAndEstablish(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	recipient := f.ready(t, b, newBundle(t))
	aBundle := newBundle(t)

	bare, _ := f.authenticated(t, a)
	if err := f.direct.Establish(bare, aBundle.Key, newSession(t, randomText(16), 0)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("establish without static key = %v", err)
	}
	if err := f.direct.Send(bare, b.identity, "m1", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("send without static key = %v", err)
	}
	published, _ := f.published(t, a, aBundle)
	if err := f.direct.Send(published, b.identity, "m2", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("send without session = %v", err)
	}
	if err := f.direct.Establish(published, newBundle(t).Key, newSession(t, randomText(16), 0)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("establish under another static key = %v", err)
	}
	if len(recipient.box.all()) != 0 {
		t.Fatal("delivered without an established session")
	}
}

func TestEstablishEnforcesFreshSessionsAndSequentialEpochs(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	bundle := newBundle(t)
	s, _ := f.published(t, a, bundle)
	id := randomText(16)

	if err := f.direct.Establish(s, bundle.Key, newSession(t, id, 1)); !errors.Is(err, ErrStale) {
		t.Fatalf("first epoch 1 = %v", err)
	}
	if err := f.direct.Establish(s, bundle.Key, newSession(t, id, 0)); err != nil {
		t.Fatalf("first epoch 0 = %v", err)
	}
	for _, bad := range []SessionBundle{
		newSession(t, id, 0),
		newSession(t, id, 2),
		newSession(t, randomText(16), 1),
		newSession(t, id, MaxEpoch+1),
	} {
		if err := f.direct.Establish(s, bundle.Key, bad); !errors.Is(err, ErrStale) {
			t.Fatalf("Establish(%+v) = %v", bad, err)
		}
	}
	for epoch := uint32(1); epoch <= 5; epoch++ {
		if err := f.direct.Establish(s, bundle.Key, newSession(t, id, epoch)); err != nil {
			t.Fatalf("epoch %d = %v", epoch, err)
		}
	}
	_, sessions, ok := f.direct.Lookup(a.identity)
	if !ok || len(sessions) != 1 || sessions[0].ID != id || sessions[0].Epoch != 5 {
		t.Fatalf("Lookup = %+v %v", sessions, ok)
	}
}

func TestFreshSessionReplacesConnectionSession(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle, bBundle := newBundle(t), newBundle(t)
	sender := f.ready(t, a, aBundle)
	recipient := f.ready(t, b, bBundle)
	f.rotate(t, &recipient, bBundle)
	old := recipient.keys

	fresh := newSession(t, randomText(16), 0)
	if err := f.direct.Establish(recipient.session, bBundle.Key, fresh); err != nil {
		t.Fatalf("fresh session = %v", err)
	}
	if err := f.direct.Establish(recipient.session, bBundle.Key, newSession(t, fresh.ID, 0)); !errors.Is(err, ErrStale) {
		t.Fatalf("same fresh id again = %v", err)
	}
	for _, stale := range []SessionBundle{old, {ID: old.ID, Epoch: 0}} {
		if err := f.direct.Send(sender.session, b.identity, "x"+stale.ID[:4]+fmt.Sprint(stale.Epoch), 0, []Envelope{envelopeFor(stale)}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("envelope for replaced session = %v", err)
		}
	}
	if err := f.direct.Send(recipient.session, a.identity, "from-old", 1, []Envelope{envelopeFor(sender.keys)}); !errors.Is(err, ErrStale) {
		t.Fatalf("send with replaced epoch = %v", err)
	}
	_, sessions, _ := f.direct.Lookup(b.identity)
	if len(sessions) != 1 || sessions[0] != fresh {
		t.Fatalf("sessions = %+v", sessions)
	}
	other := f.ready(t, b, bBundle)
	if err := f.direct.Establish(recipient.session, bBundle.Key, newSession(t, other.keys.ID, 0)); !errors.Is(err, ErrStale) {
		t.Fatalf("taking another session's id = %v", err)
	}
	for range MaxSessions - 2 {
		f.ready(t, b, bBundle)
	}
	if err := f.direct.Establish(recipient.session, bBundle.Key, newSession(t, randomText(16), 0)); err != nil {
		t.Fatalf("replacement at the session limit = %v", err)
	}
}

func TestEpochCannotOverflow(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	bundle := newBundle(t)
	p := f.ready(t, a, bundle)
	f.direct.mu.Lock()
	f.direct.sessions[p.session].current.Epoch = MaxEpoch
	f.direct.mu.Unlock()
	if err := f.direct.Establish(p.session, bundle.Key, newSession(t, p.keys.ID, MaxEpoch+1)); !errors.Is(err, ErrStale) {
		t.Fatalf("overflowing epoch = %v", err)
	}
	if err := f.direct.Establish(p.session, bundle.Key, newSession(t, p.keys.ID, 0)); !errors.Is(err, ErrStale) {
		t.Fatalf("wrapped epoch = %v", err)
	}
}

func TestSessionIDsAreUniquePerIdentityAndBounded(t *testing.T) {
	f := newFixture()
	a, c := newKey(t), newKey(t)
	bundle := newBundle(t)
	first := f.ready(t, a, bundle)

	dup, _ := f.published(t, a, bundle)
	if err := f.direct.Establish(dup, bundle.Key, newSession(t, first.keys.ID, 0)); !errors.Is(err, ErrStale) {
		t.Fatalf("duplicate session id = %v", err)
	}
	other, _ := f.published(t, c, newBundle(t))
	if err := f.direct.Establish(other, mustBundle(t, f, c).Key, newSession(t, first.keys.ID, 0)); err != nil {
		t.Fatalf("same id for another identity = %v", err)
	}

	peers := []peer{first}
	for len(peers) < MaxSessions {
		peers = append(peers, f.ready(t, a, bundle))
	}
	extra, _ := f.published(t, a, bundle)
	if err := f.direct.Establish(extra, bundle.Key, newSession(t, randomText(16), 0)); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("session over limit = %v", err)
	}
	peers[0].session.Close()
	if err := f.direct.Establish(extra, bundle.Key, newSession(t, randomText(16), 0)); err != nil {
		t.Fatalf("session after a slot frees = %v", err)
	}
}

func mustBundle(t testing.TB, f fixture, k key) Bundle {
	t.Helper()
	b, ok := f.direct.Bundle(k.identity)
	if !ok {
		t.Fatal("no bundle")
	}
	return b
}

func TestOnlyCurrentAndPreviousEpochsAreAccepted(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle, bBundle := newBundle(t), newBundle(t)
	sender := f.ready(t, a, aBundle)
	recipient := f.ready(t, b, bBundle)
	epoch0 := recipient.keys

	f.rotate(t, &recipient, bBundle)
	epoch1 := recipient.keys
	if err := f.direct.Send(sender.session, b.identity, "to0", 0, []Envelope{envelopeFor(epoch0)}); err != nil {
		t.Fatalf("previous recipient epoch = %v", err)
	}
	f.rotate(t, &recipient, bBundle)
	if err := f.direct.Send(sender.session, b.identity, "to0again", 0, []Envelope{envelopeFor(epoch0)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("discarded recipient epoch = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "to1", 0, []Envelope{envelopeFor(epoch1)}); err != nil {
		t.Fatalf("previous recipient epoch after rotation = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "to2", 0, []Envelope{envelopeFor(recipient.keys)}); err != nil {
		t.Fatalf("current recipient epoch = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "future", 0, []Envelope{envelopeFor(SessionBundle{ID: recipient.keys.ID, Epoch: 3})}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("future recipient epoch = %v", err)
	}

	f.rotate(t, &sender, aBundle)
	f.rotate(t, &sender, aBundle)
	if err := f.direct.Send(sender.session, b.identity, "from0", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrStale) {
		t.Fatalf("discarded sender epoch = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "from9", 9, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrStale) {
		t.Fatalf("unknown sender epoch = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "from1", 1, []Envelope{envelopeFor(recipient.keys)}); err != nil {
		t.Fatalf("previous sender epoch = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "from2", 2, []Envelope{envelopeFor(recipient.keys)}); err != nil {
		t.Fatalf("current sender epoch = %v", err)
	}
	got := recipient.box.all()
	if len(got) != 5 || got[3].Session.Epoch != 1 || got[4].Session.Epoch != 2 {
		t.Fatalf("deliveries = %+v", got)
	}
}

func TestEachEnvelopeReachesOnlyItsSession(t *testing.T) {
	f := newFixture()
	a, b, c := newKey(t), newKey(t), newKey(t)
	bBundle := newBundle(t)
	sender := f.ready(t, a, newBundle(t))
	b1 := f.ready(t, b, bBundle)
	b2 := f.ready(t, b, bBundle)
	third := f.ready(t, c, newBundle(t))

	e1, e2 := envelopeFor(b1.keys), envelopeFor(b2.keys)
	if err := f.direct.Send(sender.session, b.identity, "both", 0, []Envelope{e1, e2}); err != nil {
		t.Fatal(err)
	}
	if got := b1.box.all(); len(got) != 1 || got[0].Envelope != e1 {
		t.Fatalf("b1 got %+v", got)
	}
	if got := b2.box.all(); len(got) != 1 || got[0].Envelope != e2 {
		t.Fatalf("b2 got %+v", got)
	}
	if err := f.direct.Send(sender.session, b.identity, "one", 0, []Envelope{envelopeFor(b1.keys)}); err != nil {
		t.Fatal(err)
	}
	if len(b2.box.all()) != 1 {
		t.Fatal("envelope for one session reached another")
	}
	if err := f.direct.Send(sender.session, b.identity, "cross", 0, []Envelope{envelopeFor(third.keys)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("envelope for another identity's session = %v", err)
	}
	if err := f.direct.Send(sender.session, b.identity, "nobody", 0, []Envelope{envelopeFor(newSession(t, randomText(16), 0))}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown session = %v", err)
	}
	if len(third.box.all()) != 0 {
		t.Fatal("cross-identity delivery")
	}
}

func TestLookupListsEstablishedSessions(t *testing.T) {
	f := newFixture()
	b := newKey(t)
	bundle := newBundle(t)
	if _, _, ok := f.direct.Lookup(b.identity); ok {
		t.Fatal("lookup of unknown identity succeeded")
	}
	f.published(t, b, bundle)
	got, sessions, ok := f.direct.Lookup(b.identity)
	if !ok || got != bundle || len(sessions) != 0 {
		t.Fatalf("published only = %+v %+v %v", got, sessions, ok)
	}
	p1 := f.ready(t, b, bundle)
	p2 := f.ready(t, b, bundle)
	f.rotate(t, &p2, bundle)
	_, sessions, _ = f.direct.Lookup(b.identity)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	byID := map[string]SessionBundle{sessions[0].ID: sessions[0], sessions[1].ID: sessions[1]}
	if byID[p1.keys.ID] != p1.keys || byID[p2.keys.ID] != p2.keys || sessions[0].ID > sessions[1].ID {
		t.Fatalf("sessions = %+v", sessions)
	}
	p1.session.Close()
	_, sessions, _ = f.direct.Lookup(b.identity)
	if len(sessions) != 1 || sessions[0] != p2.keys {
		t.Fatalf("after close = %+v", sessions)
	}
}

func TestReplacingStaticKeyRequiresNewSession(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender := f.ready(t, a, newBundle(t))
	bOld := newBundle(t)
	recipient := f.ready(t, b, bOld)
	bNew := newBundle(t)
	if err := f.direct.Publish(recipient.session, bNew); err != nil {
		t.Fatal(err)
	}
	if _, sessions, _ := f.direct.Lookup(b.identity); len(sessions) != 0 {
		t.Fatalf("session survived static key replacement: %+v", sessions)
	}
	if err := f.direct.Send(sender.session, b.identity, "m1", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("send to cleared session = %v", err)
	}
	if err := f.direct.Send(recipient.session, a.identity, "m2", 0, []Envelope{envelopeFor(sender.keys)}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("send from cleared session = %v", err)
	}
	if err := f.direct.Establish(recipient.session, bOld.Key, newSession(t, randomText(16), 0)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("establish under replaced key = %v", err)
	}
	if err := f.direct.Establish(recipient.session, bNew.Key, newSession(t, randomText(16), 0)); err != nil {
		t.Fatalf("establish under new key = %v", err)
	}
}

func TestPublishBindsOneKeyPerIdentity(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	first, second := newBundle(t), newBundle(t)
	s1, _ := f.published(t, a, first)
	s2, _ := f.authenticated(t, a)
	if err := f.direct.Publish(s2, second); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("conflicting key = %v", err)
	}
	if err := f.direct.Publish(s2, first); err != nil {
		t.Fatalf("same key = %v", err)
	}
	if err := f.direct.Publish(s1, second); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("replacing shared key = %v", err)
	}
	s2.Close()
	if err := f.direct.Publish(s1, second); err != nil {
		t.Fatalf("sole session replacement = %v", err)
	}
	if got, _ := f.direct.Bundle(a.identity); got != second {
		t.Fatalf("bundle = %+v", got)
	}
}

func TestDuplicateMessageIDsRejectedWithinBoundedWindow(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender := f.ready(t, a, newBundle(t))
	recipient := f.ready(t, b, newBundle(t))
	send := func(id string) error {
		return f.direct.Send(sender.session, b.identity, id, 0, []Envelope{envelopeFor(recipient.keys)})
	}
	if err := send("dup"); err != nil {
		t.Fatal(err)
	}
	if err := send("dup"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	for i := range recentLimit {
		if err := send(fmt.Sprintf("fill%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := send("dup"); err != nil {
		t.Fatalf("id outside window = %v", err)
	}
	other := f.ready(t, a, mustBundle(t, f, a))
	if err := f.direct.Send(other.session, b.identity, "fill1", 0, []Envelope{envelopeFor(recipient.keys)}); err != nil {
		t.Fatalf("window is per session: %v", err)
	}
}

func TestRecipientUnavailable(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender := f.ready(t, a, newBundle(t))
	recipient := f.ready(t, b, newBundle(t))
	recipient.box.mu.Lock()
	recipient.box.accept = false
	recipient.box.mu.Unlock()
	if err := f.direct.Send(sender.session, b.identity, "m1", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refusing endpoint = %v", err)
	}
	recipient.session.Close()
	if err := f.direct.Send(sender.session, b.identity, "m2", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed recipient = %v", err)
	}
}

func TestClosedSenderCannotSend(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle := newBundle(t)
	sender := f.ready(t, a, aBundle)
	recipient := f.ready(t, b, newBundle(t))
	sender.session.Close()
	if err := f.direct.Send(sender.session, b.identity, "m1", 0, []Envelope{envelopeFor(recipient.keys)}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("closed sender = %v", err)
	}
	if err := f.direct.Establish(sender.session, aBundle.Key, newSession(t, sender.keys.ID, 1)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("closed session rotated")
	}
}

func TestDetachReleasesAllState(t *testing.T) {
	f := newFixture()
	k := newKey(t)
	bundle := newBundle(t)
	var peers []peer
	for range MaxSessions {
		peers = append(peers, f.ready(t, k, bundle))
	}
	for _, p := range peers {
		p.session.Close()
		f.direct.Detach(p.session)
		f.direct.Detach(p.session)
	}
	if n := len(f.direct.endpoints) + len(f.direct.identities) + len(f.direct.recipients) + len(f.direct.keys) + len(f.direct.recent) + len(f.direct.sessions); n != 0 {
		t.Fatalf("leaked %d entries", n)
	}
}

func TestConcurrentMessagingAndRotation(t *testing.T) {
	f := newFixture()
	keys := make([]key, 6)
	bundles := make([]Bundle, 6)
	peers := make([]peer, 6)
	for i := range keys {
		keys[i], bundles[i] = newKey(t), newBundle(t)
		peers[i] = f.ready(t, keys[i], bundles[i])
	}
	ids := make([]string, len(peers))
	for i := range peers {
		ids[i] = peers[i].keys.ID
	}
	const perPair = 20
	var wg sync.WaitGroup
	for i := range keys {
		wg.Go(func() {
			for epoch := uint32(1); epoch <= 10; epoch++ {
				if err := f.direct.Establish(peers[i].session, bundles[i].Key, newSession(t, ids[i], epoch)); err != nil {
					t.Error(err)
					return
				}
			}
		})
		for j := range keys {
			if i == j {
				continue
			}
			wg.Go(func() {
				for n := range perPair {
					_, sessions, _ := f.direct.Lookup(keys[j].identity)
					envelopes := make([]Envelope, 0, len(sessions))
					for _, s := range sessions {
						envelopes = append(envelopes, envelopeFor(s))
					}
					err := f.direct.Send(peers[i].session, keys[j].identity, fmt.Sprintf("m%d_%d", j, n), 0, envelopes)
					if err != nil && !errors.Is(err, ErrStale) && !errors.Is(err, ErrUnavailable) {
						t.Error(err)
						return
					}
				}
			})
		}
	}
	wg.Wait()
	for i := range peers {
		_, sessions, _ := f.direct.Lookup(keys[i].identity)
		if len(sessions) != 1 || sessions[0].Epoch != 10 {
			t.Fatalf("peer %d sessions = %+v", i, sessions)
		}
		for _, m := range peers[i].box.all() {
			if m.Envelope.Session != ids[i] || m.From == keys[i].identity.String() {
				t.Fatalf("misrouted %+v", m)
			}
		}
	}
}

func TestSendRacingClose(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender := f.ready(t, a, newBundle(t))
	bBundle := newBundle(t)

	for i := range 100 {
		recipient := f.ready(t, b, bBundle)
		var delivered atomic.Bool
		var wg sync.WaitGroup
		wg.Go(func() {
			if f.direct.Send(sender.session, b.identity, fmt.Sprintf("r%d", i), 0, []Envelope{envelopeFor(recipient.keys)}) == nil {
				delivered.Store(true)
			}
		})
		wg.Go(func() {
			recipient.session.Close()
			f.direct.Detach(recipient.session)
		})
		wg.Wait()
		if got := len(recipient.box.all()); (got == 1) != delivered.Load() || got > 1 {
			t.Fatalf("delivered %v but inbox has %d", delivered.Load(), got)
		}
	}
	if _, ok := f.direct.keys[b.identity.String()]; ok {
		t.Fatal("recipient key binding leaked")
	}
}

func TestEstablishRacingClose(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	for range 100 {
		bundle := newBundle(t)
		s, _ := f.published(t, a, bundle)
		var wg sync.WaitGroup
		wg.Go(func() { f.direct.Establish(s, bundle.Key, newSession(t, randomText(16), 0)) })
		wg.Go(s.Close)
		wg.Wait()
	}
	if len(f.direct.keys)+len(f.direct.sessions) != 0 {
		t.Fatalf("state leaked: %d keys, %d sessions", len(f.direct.keys), len(f.direct.sessions))
	}
}
