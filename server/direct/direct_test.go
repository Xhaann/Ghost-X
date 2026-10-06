package direct

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
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

func expectMessages(t *testing.T, box *inbox, want ...Message) {
	t.Helper()
	got := box.all()
	if len(got) != len(want) {
		t.Fatalf("messages = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("message %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestDeliversWithSessionSender(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)
	_, box := f.authenticated(t, b)

	if err := f.direct.Send(sender, b.identity, "m1", "hello"); err != nil {
		t.Fatalf("Send() = %v", err)
	}

	expectMessages(t, box, Message{ID: "m1", From: a.identity.String(), Body: "hello"})
}

func TestUnauthenticatedSenderRejected(t *testing.T) {
	f := newFixture()
	b := newKey(t)
	_, box := f.authenticated(t, b)

	pending, _ := f.open(t)
	pending.Challenge()
	if err := f.direct.Send(pending, b.identity, "m1", "x"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Send() = %v, want %v", err, ErrUnauthenticated)
	}

	failed, _ := f.open(t)
	other := newKey(t)
	for range auth.MaxFailures {
		nonce, _ := failed.Challenge()
		failed.Authenticate(b.identity.String(), base64.RawURLEncoding.EncodeToString(ed25519.Sign(other.private, auth.Message(nonce))))
	}
	if err := f.direct.Send(failed, b.identity, "m1", "x"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Send() from failed session = %v, want %v", err, ErrUnauthenticated)
	}

	expectMessages(t, box)
}

func TestDeliversOnceToEverySessionOfRecipient(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, senderBox := f.authenticated(t, a)
	_, otherSenderBox := f.authenticated(t, a)
	_, first := f.authenticated(t, b)
	_, second := f.authenticated(t, b)
	_, third := f.authenticated(t, b)

	if err := f.direct.Send(sender, b.identity, "m1", "fan out"); err != nil {
		t.Fatal(err)
	}

	want := Message{ID: "m1", From: a.identity.String(), Body: "fan out"}
	for _, box := range []*inbox{first, second, third} {
		expectMessages(t, box, want)
	}
	expectMessages(t, senderBox)
	expectMessages(t, otherSenderBox)
}

func TestNoCrossIdentityLeakage(t *testing.T) {
	f := newFixture()
	a, b, c := newKey(t), newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)
	_, bBox := f.authenticated(t, b)
	_, cBox := f.authenticated(t, c)
	_, unauthenticatedBox := f.open(t)

	if err := f.direct.Send(sender, b.identity, "m1", "only b"); err != nil {
		t.Fatal(err)
	}

	expectMessages(t, bBox, Message{ID: "m1", From: a.identity.String(), Body: "only b"})
	expectMessages(t, cBox)
	expectMessages(t, unauthenticatedBox)
}

func TestRecipientUnavailable(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)

	if err := f.direct.Send(sender, b.identity, "m1", "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() to absent identity = %v", err)
	}

	recipient, box := f.authenticated(t, b)
	recipient.Close()
	if err := f.direct.Send(sender, b.identity, "m1", "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() after recipient close = %v", err)
	}

	detached, detachedBox := f.authenticated(t, b)
	f.direct.Detach(detached)
	if err := f.direct.Send(sender, b.identity, "m1", "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() to detached recipient = %v", err)
	}

	expectMessages(t, box)
	expectMessages(t, detachedBox)
}

func TestFailedDeliveriesAreUnavailable(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)
	_, slow := f.authenticated(t, b)
	slow.accept = false

	if err := f.direct.Send(sender, b.identity, "m1", "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() = %v, want %v", err, ErrUnavailable)
	}

	_, healthy := f.authenticated(t, b)
	if err := f.direct.Send(sender, b.identity, "m1", "y"); err != nil {
		t.Fatalf("Send() with one healthy session = %v", err)
	}
	expectMessages(t, healthy, Message{ID: "m1", From: a.identity.String(), Body: "y"})
}

func TestClosedSenderCannotSend(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)
	_, box := f.authenticated(t, b)

	sender.Close()

	if err := f.direct.Send(sender, b.identity, "m1", "x"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Send() = %v, want %v", err, ErrUnauthenticated)
	}
	expectMessages(t, box)
}

func TestRepeatedLifecycleEventsAreHarmless(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	sender, _ := f.authenticated(t, a)
	recipient, box := f.authenticated(t, b)

	f.direct.Authenticated(recipient, b.identity)
	if err := f.direct.Send(sender, b.identity, "m1", "once"); err != nil {
		t.Fatal(err)
	}
	recipient.Close()
	recipient.Close()
	f.direct.Closed(recipient, b.identity)
	f.direct.Detach(recipient)
	f.direct.Detach(recipient)

	expectMessages(t, box, Message{ID: "m1", From: a.identity.String(), Body: "once"})
	if len(f.direct.recipients) != 1 || len(f.direct.identities) != 1 {
		t.Fatalf("registry retained state: %d recipients, %d identities", len(f.direct.recipients), len(f.direct.identities))
	}
}

func TestDetachReleasesAllState(t *testing.T) {
	f := newFixture()
	k := newKey(t)
	var sessions []*auth.Session
	for range 10 {
		s, _ := f.authenticated(t, k)
		sessions = append(sessions, s)
	}
	for _, s := range sessions {
		s.Close()
		f.direct.Detach(s)
	}
	if len(f.direct.endpoints) != 0 || len(f.direct.identities) != 0 || len(f.direct.recipients) != 0 {
		t.Fatalf("leaked state: %d endpoints, %d identities, %d recipients", len(f.direct.endpoints), len(f.direct.identities), len(f.direct.recipients))
	}
}

func TestConcurrentMessaging(t *testing.T) {
	f := newFixture()
	keys := make([]key, 8)
	senders := make([]*auth.Session, 8)
	boxes := make([]*inbox, 8)
	for i := range keys {
		keys[i] = newKey(t)
		senders[i], boxes[i] = f.authenticated(t, keys[i])
	}

	const perPair = 20
	var wg sync.WaitGroup
	for i := range keys {
		for j := range keys {
			if i == j {
				continue
			}
			wg.Go(func() {
				for range perPair {
					if err := f.direct.Send(senders[i], keys[j].identity, "m1", "m"); err != nil {
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
	sender, _ := f.authenticated(t, a)

	for range 100 {
		recipient, box := f.authenticated(t, b)
		var delivered atomic.Bool
		var wg sync.WaitGroup
		wg.Go(func() {
			if f.direct.Send(sender, b.identity, "m1", "race") == nil {
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
	if _, ok := f.direct.recipients[b.identity.String()]; ok || len(f.direct.recipients) != 1 {
		t.Fatalf("recipient state leaked: %d identities tracked", len(f.direct.recipients))
	}
}

func TestSenderClosingDuringFanOut(t *testing.T) {
	f := newFixture()
	a, b := newKey(t), newKey(t)
	for range 50 {
		sender, _ := f.authenticated(t, a)
		_, box := f.authenticated(t, b)
		var wg sync.WaitGroup
		var err error
		wg.Go(func() { err = f.direct.Send(sender, b.identity, "m1", "x") })
		wg.Go(sender.Close)
		wg.Wait()
		if got := len(box.all()); (err == nil) != (got == 1) || got > 1 {
			t.Fatalf("Send() = %v but inbox has %d", err, got)
		}
	}
}
