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

func newBundle(t testing.TB) Bundle {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	rand.Read(signature)
	return Bundle{
		Key:       base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
}

func newEnvelope() Envelope {
	salt, iv, ciphertext := make([]byte, 32), make([]byte, 12), make([]byte, 48)
	rand.Read(salt)
	rand.Read(iv)
	rand.Read(ciphertext)
	return Envelope{
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
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

func (f fixture) ready(t testing.TB, k key, b Bundle) (*auth.Session, *inbox) {
	t.Helper()
	s, box := f.authenticated(t, k)
	if err := f.direct.Publish(s, b); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	return s, box
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

func TestRoutesEnvelopeUnchangedWithSenderBundle(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle := newBundle(t)
	sender, _ := f.ready(t, a, aBundle)
	_, box := f.ready(t, b, newBundle(t))
	envelope := newEnvelope()

	if err := f.direct.Send(sender, b.identity, "m1", envelope); err != nil {
		t.Fatalf("Send() = %v", err)
	}

	want := Message{ID: "m1", From: a.identity.String(), Sender: aBundle, Envelope: envelope}
	if got := box.all(); len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %+v, want %+v", got, want)
	}
}

func TestUnauthenticatedSenderRejected(t *testing.T) {
	f := newFixture()
	b := newKey(t)
	_, box := f.ready(t, b, newBundle(t))

	pending, _ := f.open(t)
	pending.Challenge()
	if err := f.direct.Publish(pending, newBundle(t)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Publish() = %v", err)
	}
	if err := f.direct.Send(pending, b.identity, "m1", newEnvelope()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Send() = %v", err)
	}
	if len(box.all()) != 0 {
		t.Fatal("unauthenticated send delivered")
	}
}

func TestSenderMustPublishKey(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)
	_, box := f.ready(t, b, newBundle(t))

	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Send() without key = %v", err)
	}

	f.ready(t, a, newBundle(t))
	if err := f.direct.Send(sender, b.identity, "m2", newEnvelope()); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Send() from session that did not publish = %v", err)
	}
	if len(box.all()) != 0 {
		t.Fatal("send without published key delivered")
	}
}

func TestPublishBindsOneKeyPerIdentity(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	first, second := newBundle(t), newBundle(t)

	s1, _ := f.ready(t, a, first)
	if got, ok := f.direct.Bundle(a.identity); !ok || got != first {
		t.Fatalf("Bundle() = %+v %v", got, ok)
	}

	s2, _ := f.authenticated(t, a)
	if err := f.direct.Publish(s2, second); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("conflicting Publish() = %v", err)
	}
	if err := f.direct.Publish(s2, first); err != nil {
		t.Fatalf("matching Publish() = %v", err)
	}
	if err := f.direct.Publish(s1, second); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("replace with other publisher present = %v", err)
	}

	s2.Close()
	if err := f.direct.Publish(s1, second); err != nil {
		t.Fatalf("sole publisher replace = %v", err)
	}
	if got, _ := f.direct.Bundle(a.identity); got != second {
		t.Fatalf("Bundle() after replace = %+v", got)
	}

	s1.Close()
	if _, ok := f.direct.Bundle(a.identity); ok {
		t.Fatal("bundle survived last session")
	}
}

func TestDuplicateMessageIDsRejectedWithinBoundedWindow(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle := newBundle(t)
	sender, _ := f.ready(t, a, aBundle)
	other, _ := f.ready(t, a, aBundle)
	_, box := f.ready(t, b, newBundle(t))

	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); err != nil {
		t.Fatal(err)
	}
	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate Send() = %v", err)
	}
	if err := f.direct.Send(other, b.identity, "m1", newEnvelope()); err != nil {
		t.Fatalf("same id from another session = %v", err)
	}
	for i := range recentLimit {
		if err := f.direct.Send(sender, b.identity, fmt.Sprintf("x%d", i), newEnvelope()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); err != nil {
		t.Fatalf("id outside window = %v", err)
	}
	if got := len(box.all()); got != recentLimit+3 {
		t.Fatalf("delivered %d, want %d", got, recentLimit+3)
	}
	if n := len(f.direct.recent[sender].order); n != recentLimit {
		t.Fatalf("recent window = %d, want %d", n, recentLimit)
	}
}

func TestDeliversOnceToEverySessionOfRecipient(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	aBundle, bBundle := newBundle(t), newBundle(t)
	sender, senderBox := f.ready(t, a, aBundle)
	_, otherSenderBox := f.ready(t, a, aBundle)
	_, first := f.ready(t, b, bBundle)
	_, second := f.ready(t, b, bBundle)

	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); err != nil {
		t.Fatal(err)
	}

	for _, box := range []*inbox{first, second} {
		if len(box.all()) != 1 {
			t.Fatalf("recipient session got %d", len(box.all()))
		}
	}
	if len(senderBox.all()) != 0 || len(otherSenderBox.all()) != 0 {
		t.Fatal("sender sessions received a copy")
	}
}

func TestNoCrossIdentityLeakage(t *testing.T) {
	f := newFixture()
	a, b, c := newKey(t), newKey(t), newKey(t)
	sender, _ := f.ready(t, a, newBundle(t))
	_, bBox := f.ready(t, b, newBundle(t))
	_, cBox := f.ready(t, c, newBundle(t))
	_, unauthenticatedBox := f.open(t)

	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); err != nil {
		t.Fatal(err)
	}
	if len(bBox.all()) != 1 || len(cBox.all()) != 0 || len(unauthenticatedBox.all()) != 0 {
		t.Fatal("message leaked across identities")
	}
}

func TestRecipientUnavailable(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.ready(t, a, newBundle(t))

	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() to absent identity = %v", err)
	}
	recipient, _ := f.ready(t, b, newBundle(t))
	recipient.Close()
	if err := f.direct.Send(sender, b.identity, "m2", newEnvelope()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() after recipient close = %v", err)
	}
	detached, _ := f.ready(t, b, newBundle(t))
	f.direct.Detach(detached)
	if err := f.direct.Send(sender, b.identity, "m3", newEnvelope()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() to detached recipient = %v", err)
	}
	_, slow := f.ready(t, b, newBundle(t))
	slow.accept = false
	if err := f.direct.Send(sender, b.identity, "m4", newEnvelope()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() with failing delivery = %v", err)
	}
}

func TestClosedSenderCannotSend(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.ready(t, a, newBundle(t))
	_, box := f.ready(t, b, newBundle(t))

	sender.Close()

	if err := f.direct.Send(sender, b.identity, "m1", newEnvelope()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Send() = %v", err)
	}
	if len(box.all()) != 0 {
		t.Fatal("closed session delivered")
	}
}

func TestDetachReleasesAllState(t *testing.T) {
	f := newFixture()
	k := newKey(t)
	bundle := newBundle(t)
	var sessions []*auth.Session
	for range 10 {
		s, _ := f.ready(t, k, bundle)
		sessions = append(sessions, s)
	}
	for _, s := range sessions {
		s.Close()
		f.direct.Detach(s)
		f.direct.Detach(s)
	}
	if n := len(f.direct.endpoints) + len(f.direct.identities) + len(f.direct.recipients) + len(f.direct.keys) + len(f.direct.recent); n != 0 {
		t.Fatalf("leaked %d entries", n)
	}
}

func TestConcurrentMessaging(t *testing.T) {
	f := newFixture()
	keys := make([]key, 8)
	senders := make([]*auth.Session, 8)
	boxes := make([]*inbox, 8)
	for i := range keys {
		keys[i] = newKey(t)
		senders[i], boxes[i] = f.ready(t, keys[i], newBundle(t))
	}

	const perPair = 20
	var wg sync.WaitGroup
	for i := range keys {
		for j := range keys {
			if i == j {
				continue
			}
			wg.Go(func() {
				for n := range perPair {
					if err := f.direct.Send(senders[i], keys[j].identity, fmt.Sprintf("m%d_%d", j, n), newEnvelope()); err != nil {
						t.Error(err)
						return
					}
				}
			})
		}
	}
	wg.Wait()

	for j, box := range boxes {
		counts := map[string]int{}
		for _, m := range box.all() {
			counts[m.From]++
		}
		for i, k := range keys {
			want := perPair
			if i == j {
				want = 0
			}
			if counts[k.identity.String()] != want {
				t.Fatalf("recipient %d got %d from %d, want %d", j, counts[k.identity.String()], i, want)
			}
		}
	}
}

func TestSendRacingClose(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.ready(t, a, newBundle(t))
	bBundle := newBundle(t)

	for i := range 100 {
		recipient, box := f.ready(t, b, bBundle)
		var delivered atomic.Bool
		var wg sync.WaitGroup
		wg.Go(func() {
			if f.direct.Send(sender, b.identity, fmt.Sprintf("r%d", i), newEnvelope()) == nil {
				delivered.Store(true)
			}
		})
		wg.Go(func() {
			recipient.Close()
			f.direct.Detach(recipient)
		})
		wg.Wait()
		if got := len(box.all()); (got == 1) != delivered.Load() || got > 1 {
			t.Fatalf("delivered %v but inbox has %d", delivered.Load(), got)
		}
	}
	if _, ok := f.direct.keys[b.identity.String()]; ok {
		t.Fatal("recipient key binding leaked")
	}
}

func TestPublishRacingClose(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	for range 100 {
		s, _ := f.authenticated(t, a)
		bundle := newBundle(t)
		var wg sync.WaitGroup
		wg.Go(func() { f.direct.Publish(s, bundle) })
		wg.Go(s.Close)
		wg.Wait()
	}
	if len(f.direct.keys) != 0 {
		t.Fatalf("key bindings leaked: %d", len(f.direct.keys))
	}
}
