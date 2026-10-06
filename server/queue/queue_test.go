package queue

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type sink struct {
	mu     sync.Mutex
	pushes []Push
	refuse bool
}

func (k *sink) deliver(p Push) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.refuse {
		return false
	}
	k.pushes = append(k.pushes, p)
	return true
}

func (k *sink) take() []Push {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := k.pushes
	k.pushes = nil
	return out
}

func (k *sink) messages() []Message {
	var out []Message
	for _, p := range k.take() {
		if p.Message != nil {
			out = append(out, *p.Message)
		}
	}
	return out
}

type world struct {
	t        testing.TB
	clock    *clock
	queue    *Registry
	sessions *auth.Registry
}

func newWorld(t testing.TB) *world {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	q := NewRegistry(c.Now)
	return &world{t: t, clock: c, queue: q, sessions: auth.NewRegistry(time.Now, q)}
}

type user struct {
	id      identity.Identity
	private ed25519.PrivateKey
}

func newUser(t testing.TB) user {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Parse(base64.RawURLEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	return user{id: id, private: private}
}

type conn struct {
	session *auth.Session
	sink    *sink
}

func (w *world) connect(u user) conn {
	w.t.Helper()
	s := w.sessions.Open()
	k := &sink{}
	w.queue.Attach(s, k.deliver)
	nonce, err := s.Challenge()
	if err != nil {
		w.t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(u.private, auth.Message(nonce)))
	if _, err := s.Authenticate(u.id.String(), signature); err != nil {
		w.t.Fatal(err)
	}
	return conn{session: s, sink: k}
}

func (w *world) online(u user) conn {
	w.t.Helper()
	c := w.connect(u)
	if err := w.queue.Subscribe(c.session); err != nil {
		w.t.Fatal(err)
	}
	return c
}

func (w *world) drop(c conn) {
	c.session.Close()
	w.queue.Detach(c.session)
}

func messageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sealed(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	b[0] = 1
	return base64.RawURLEncoding.EncodeToString(b)
}

func (w *world) send(from conn, to user) Message {
	w.t.Helper()
	m := Message{ID: messageID(), Key: "k", Signature: "s", Ciphertext: sealed(120)}
	if err := w.queue.Enqueue(from.session, to.id, m); err != nil {
		w.t.Fatalf("Enqueue() = %v", err)
	}
	return m
}

func (w *world) check() {
	w.t.Helper()
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	total, bytes, notes := 0, 0, 0
	senders := map[string]int{}
	pairs := map[pair]int{}
	for recipient, box := range q.inboxes {
		if len(box.entries) == 0 {
			w.t.Fatalf("empty inbox retained for %s", recipient)
		}
		used := 0
		for _, e := range box.entries {
			if e.to != recipient {
				w.t.Fatalf("entry for %s stored in inbox of %s", e.to, recipient)
			}
			used += e.size
			senders[e.message.From]++
			pairs[pair{e.message.From, e.to}]++
		}
		if used != box.bytes || len(box.entries) > MaxPerRecipient || used > MaxBytesPerRecipient {
			w.t.Fatalf("inbox accounting %d/%d entries %d", used, box.bytes, len(box.entries))
		}
		total += len(box.entries)
		bytes += used
	}
	for _, list := range q.outboxes {
		if len(list) == 0 || len(list) > MaxReceiptsPerSender {
			w.t.Fatalf("outbox size %d", len(list))
		}
		notes += len(list)
	}
	if total != q.total || bytes != q.bytes || notes != q.notes {
		w.t.Fatalf("totals %d/%d %d/%d %d/%d", total, q.total, bytes, q.bytes, notes, q.notes)
	}
	if total > MaxTotal || bytes > MaxBytesTotal || notes > MaxReceiptsTotal || len(q.seen) > SeenLimit || len(q.seen) != len(q.order) {
		w.t.Fatalf("global bounds exceeded")
	}
	if fmt.Sprint(senders) != fmt.Sprint(q.senders) || fmt.Sprint(pairs) != fmt.Sprint(q.pairs) {
		w.t.Fatalf("sender accounting %v %v", senders, q.senders)
	}
	held := map[*auth.Session]int{}
	for _, box := range q.inboxes {
		for _, e := range box.entries {
			if e.holder != nil {
				held[e.holder]++
			}
		}
	}
	for _, list := range q.outboxes {
		for _, n := range list {
			if n.holder != nil {
				held[n.holder]++
			}
		}
	}
	for s, e := range q.endpoints {
		if held[s] != e.inflight || e.inflight > Window {
			w.t.Fatalf("inflight %d held %d", e.inflight, held[s])
		}
		if e.inflight > 0 && !e.subscribed {
			w.t.Fatal("unsubscribed endpoint holds deliveries")
		}
	}
}

func TestLifecycleQueuedDeliveredAcknowledgedDeleted(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("message not queued for offline recipient")
	}
	if pushes := a.sink.take(); len(pushes) != 0 {
		t.Fatalf("sender received %v", pushes)
	}

	b := w.connect(bob)
	if len(b.sink.take()) != 0 {
		t.Fatal("delivery before subscription")
	}
	if err := w.queue.Subscribe(b.session); err != nil {
		t.Fatal(err)
	}
	got := b.sink.messages()
	want := Message{ID: m.ID, From: alice.id.String(), Key: "k", Signature: "s", Ciphertext: m.Ciphertext}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %+v, want %+v", got, want)
	}
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("transmission removed the message before acknowledgment")
	}
	w.check()

	if err := w.queue.Ack(b.session, alice.id, m.ID); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob.id) != 0 {
		t.Fatal("acknowledged message retained")
	}
	pushes := a.sink.take()
	if len(pushes) != 1 || pushes[0].Receipt == nil || *pushes[0].Receipt != (Receipt{To: bob.id.String(), ID: m.ID, Status: Delivered}) {
		t.Fatalf("receipt = %+v", pushes)
	}
	if err := w.queue.Ack(b.session, alice.id, m.ID); err != nil {
		t.Fatalf("duplicate ack = %v", err)
	}
	if w.queue.Receipts(alice.id) != 1 || len(a.sink.take()) != 0 {
		t.Fatal("duplicate ack produced a second receipt")
	}
	if err := w.queue.Clear(a.session, bob.id, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.queue.Clear(a.session, bob.id, m.ID); err != nil {
		t.Fatalf("duplicate clear = %v", err)
	}
	if w.queue.Receipts(alice.id) != 0 {
		t.Fatal("receipt not cleared")
	}
	w.check()
	w.drop(a)
	w.drop(b)
	if n := len(w.queue.endpoints) + len(w.queue.identities) + len(w.queue.listeners) + len(w.queue.inboxes) + len(w.queue.outboxes) + len(w.queue.senders) + len(w.queue.pairs); n != 0 {
		t.Fatalf("leaked %d entries", n)
	}
}

func TestOnlineDeliveryIsNotPermanentUntilAcknowledged(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	b := w.online(bob)
	m := w.send(a, bob)
	if got := b.sink.messages(); len(got) != 1 || got[0].ID != m.ID {
		t.Fatalf("online delivery = %+v", got)
	}
	w.drop(b)
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("transmitted but unacknowledged message lost on disconnect")
	}
	again := w.online(bob)
	if got := again.sink.messages(); len(got) != 1 || got[0].ID != m.ID || got[0].Ciphertext != m.Ciphertext {
		t.Fatalf("redelivery = %+v", got)
	}
	if err := w.queue.Subscribe(again.session); err != nil {
		t.Fatal(err)
	}
	if got := again.sink.messages(); len(got) != 1 {
		t.Fatalf("repeat fetch redelivers held entries once, got %d", len(got))
	}
	if err := w.queue.Ack(again.session, alice.id, m.ID); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob.id) != 0 {
		t.Fatal("not deleted on ack")
	}
	w.check()
}

func TestDeliveryWindowAndOrdering(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	var sent []Message
	for range Window + 9 {
		sent = append(sent, w.send(a, bob))
	}
	b := w.online(bob)
	got := b.sink.messages()
	if len(got) != Window {
		t.Fatalf("delivered %d, want window %d", len(got), Window)
	}
	for i, m := range got {
		if m.ID != sent[i].ID {
			t.Fatalf("delivery %d out of order", i)
		}
	}
	for i := range Window + 9 {
		if err := w.queue.Ack(b.session, alice.id, sent[i].ID); err != nil {
			t.Fatal(err)
		}
		w.check()
		if i < 9 {
			next := b.sink.messages()
			if len(next) != 1 || next[0].ID != sent[Window+i].ID {
				t.Fatalf("after ack %d delivered %+v", i, next)
			}
		}
	}
	if w.queue.Queued(bob.id) != 0 {
		t.Fatal("queue not drained")
	}
}

func TestFailedTransmissionKeepsMessageAvailable(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	b := w.connect(bob)
	b.sink.refuse = true
	if err := w.queue.Subscribe(b.session); err != nil {
		t.Fatal(err)
	}
	m := w.send(a, bob)
	w.check()
	if err := w.queue.Ack(b.session, alice.id, m.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ack of never-transmitted message = %v", err)
	}
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("message lost after failed transmission")
	}
	w.drop(b)
	if got := w.online(bob).sink.messages(); len(got) != 1 {
		t.Fatalf("redelivery = %+v", got)
	}
}

func TestAcknowledgmentAuthorization(t *testing.T) {
	w := newWorld(t)
	alice, bob, mallory := newUser(t), newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	b := w.online(bob)
	b.sink.take()
	c := w.online(mallory)

	for name, try := range map[string]func() error{
		"sender acknowledges":         func() error { return w.queue.Ack(a.session, alice.id, m.ID) },
		"sender names recipient":      func() error { return w.queue.Ack(a.session, bob.id, m.ID) },
		"third party":                 func() error { return w.queue.Ack(c.session, alice.id, m.ID) },
		"recipient wrong sender":      func() error { return w.queue.Ack(b.session, mallory.id, m.ID) },
		"recipient wrong message":     func() error { return w.queue.Ack(b.session, alice.id, messageID()) },
		"recipient names itself":      func() error { return w.queue.Ack(b.session, bob.id, m.ID) },
		"unauthenticated connection":  func() error { return w.queue.Ack(w.sessions.Open(), alice.id, m.ID) },
		"sender clears absent notice": func() error { return w.queue.Clear(a.session, bob.id, m.ID) },
	} {
		err := try()
		if w.queue.Queued(bob.id) != 1 || w.queue.Receipts(alice.id) != 0 {
			t.Fatalf("%s (%v) changed delivery state", name, err)
		}
	}
	if err := w.queue.Ack(w.sessions.Open(), alice.id, m.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated ack = %v", err)
	}
	if err := w.queue.Ack(b.session, alice.id, m.ID); err != nil || w.queue.Queued(bob.id) != 0 {
		t.Fatalf("recipient ack = %v", err)
	}
	if err := w.queue.Clear(c.session, bob.id, m.ID); err != nil || w.queue.Receipts(alice.id) != 1 {
		t.Fatalf("third party cleared another sender's receipt: %v", err)
	}
	w.check()
}

func TestRecipientsReceiveOnlyTheirOwnMessages(t *testing.T) {
	w := newWorld(t)
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	a := w.online(alice)
	toBob := w.send(a, bob)
	toCarol := w.send(a, carol)
	b := w.online(bob)
	c := w.online(carol)
	if got := b.sink.messages(); len(got) != 1 || got[0].ID != toBob.ID {
		t.Fatalf("bob received %+v", got)
	}
	if got := c.sink.messages(); len(got) != 1 || got[0].ID != toCarol.ID {
		t.Fatalf("carol received %+v", got)
	}
	if got := a.sink.messages(); len(got) != 0 {
		t.Fatalf("sender received %+v", got)
	}
}

func TestSenderIsDerivedFromSession(t *testing.T) {
	w := newWorld(t)
	alice, bob, mallory := newUser(t), newUser(t), newUser(t)
	c := w.online(mallory)
	m := Message{ID: messageID(), From: alice.id.String(), Ciphertext: sealed(100)}
	if err := w.queue.Enqueue(c.session, bob.id, m); err != nil {
		t.Fatal(err)
	}
	if got := w.online(bob).sink.messages(); len(got) != 1 || got[0].From != mallory.id.String() {
		t.Fatalf("delivered %+v", got)
	}
	if err := w.queue.Enqueue(w.sessions.Open(), bob.id, Message{ID: messageID(), Ciphertext: sealed(100)}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated enqueue = %v", err)
	}
	if err := w.queue.Enqueue(c.session, mallory.id, Message{ID: messageID(), Ciphertext: sealed(100)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self enqueue = %v", err)
	}
	for _, bad := range []Message{{Ciphertext: sealed(100)}, {ID: messageID()}} {
		if err := w.queue.Enqueue(c.session, bob.id, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("incomplete message = %v", err)
		}
	}
}

func TestDuplicateEnqueueRejected(t *testing.T) {
	w := newWorld(t)
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	if err := w.queue.Enqueue(a.session, bob.id, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	other := m
	other.Ciphertext = sealed(130)
	if err := w.queue.Enqueue(a.session, bob.id, other); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same id different ciphertext = %v", err)
	}
	b := w.online(bob)
	b.sink.take()
	if err := w.queue.Ack(b.session, alice.id, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.queue.Enqueue(a.session, bob.id, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after delivery = %v", err)
	}
	if err := w.queue.Enqueue(a.session, carol.id, m); err != nil {
		t.Fatalf("same id to another recipient = %v", err)
	}
	if w.queue.Queued(bob.id) != 0 || w.queue.Queued(carol.id) != 1 {
		t.Fatal("duplicate changed queues")
	}
	w.check()
}

func TestSeenWindowIsBounded(t *testing.T) {
	w := newWorld(t)
	alice := newUser(t)
	a := w.online(alice)
	var bobs []user
	for range 80 {
		bobs = append(bobs, newUser(t))
	}
	first := Message{ID: messageID(), Ciphertext: sealed(100)}
	if err := w.queue.Enqueue(a.session, bobs[0].id, first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < SeenLimit; i++ {
		to := bobs[1+i%79]
		m := Message{ID: messageID(), Ciphertext: sealed(40)}
		if err := w.queue.Enqueue(a.session, to.id, m); err != nil {
			if !errors.Is(err, ErrFull) {
				t.Fatal(err)
			}
			w.queue.mu.Lock()
			w.queue.remember(seenKey(alice.id.String(), to.id.String(), m.ID))
			w.queue.mu.Unlock()
		}
	}
	w.check()
	if _, ok := w.queue.seen[seenKey(alice.id.String(), bobs[0].id.String(), first.ID)]; ok {
		t.Fatal("seen window is unbounded")
	}
}

func TestPerRecipientLimits(t *testing.T) {
	w := newWorld(t)
	bob := newUser(t)
	var senders []conn
	for range 3 {
		senders = append(senders, w.online(newUser(t)))
	}
	for i := range MaxPerRecipient {
		w.send(senders[i%3], bob)
	}
	err := w.queue.Enqueue(senders[0].session, bob.id, Message{ID: messageID(), Ciphertext: sealed(40)})
	if !errors.Is(err, ErrFull) {
		t.Fatalf("over recipient count = %v", err)
	}
	w.check()

	w2 := newWorld(t)
	carol := newUser(t)
	var others []conn
	for range 8 {
		others = append(others, w2.online(newUser(t)))
	}
	big := (MaxBytesPerRecipient / 8) - Overhead
	for i := range 8 {
		if err := w2.queue.Enqueue(others[i].session, carol.id, Message{ID: messageID(), Ciphertext: strings.Repeat("A", big)}); err != nil {
			t.Fatalf("within byte limit %d: %v", i, err)
		}
	}
	if err := w2.queue.Enqueue(others[0].session, carol.id, Message{ID: messageID(), Ciphertext: "AQ"}); !errors.Is(err, ErrFull) {
		t.Fatalf("over recipient bytes = %v", err)
	}
	w2.check()
}

func TestPerPairAndPerSenderLimits(t *testing.T) {
	w := newWorld(t)
	alice := newUser(t)
	a := w.online(alice)
	bob := newUser(t)
	for range MaxPerPair {
		w.send(a, bob)
	}
	if err := w.queue.Enqueue(a.session, bob.id, Message{ID: messageID(), Ciphertext: sealed(40)}); !errors.Is(err, ErrFull) {
		t.Fatalf("over pair limit = %v", err)
	}
	other := w.online(newUser(t))
	w.send(other, bob)
	for range MaxPerSender/MaxPerPair - 1 {
		to := newUser(t)
		for range MaxPerPair {
			w.send(a, to)
		}
	}
	if err := w.queue.Enqueue(a.session, newUser(t).id, Message{ID: messageID(), Ciphertext: sealed(40)}); !errors.Is(err, ErrFull) {
		t.Fatalf("over sender limit = %v", err)
	}
	w.check()
}

func TestGlobalLimits(t *testing.T) {
	w := newWorld(t)
	var senders []conn
	for range MaxTotal/MaxPerSender + 1 {
		senders = append(senders, w.online(newUser(t)))
	}
	recipients := make([]user, MaxTotal/MaxPerPair+1)
	for i := range recipients {
		recipients[i] = newUser(t)
	}
	for i := range MaxTotal {
		s := senders[i/MaxPerSender]
		to := recipients[i/MaxPerPair]
		if err := w.queue.Enqueue(s.session, to.id, Message{ID: messageID(), Ciphertext: "AQ"}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	err := w.queue.Enqueue(senders[len(senders)-1].session, recipients[len(recipients)-1].id, Message{ID: messageID(), Ciphertext: "AQ"})
	if !errors.Is(err, ErrFull) {
		t.Fatalf("over global count = %v", err)
	}
	w.check()

	w2 := newWorld(t)
	per := MaxBytesPerRecipient/4 - Overhead
	need := MaxBytesTotal / (per + Overhead)
	var big []conn
	for range need/(MaxPerSender) + 2 {
		big = append(big, w2.online(newUser(t)))
	}
	recipient := newUser(t)
	for i := range need {
		if i%4 == 0 {
			recipient = newUser(t)
		}
		s := big[i/MaxPerSender]
		if err := w2.queue.Enqueue(s.session, recipient.id, Message{ID: messageID(), Ciphertext: strings.Repeat("A", per)}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := w2.queue.Enqueue(big[len(big)-1].session, newUser(t).id, Message{ID: messageID(), Ciphertext: strings.Repeat("A", per)}); !errors.Is(err, ErrFull) {
		t.Fatalf("over global bytes = %v", err)
	}
	_, bytes, _ := w2.queue.Usage()
	if bytes > MaxBytesTotal {
		t.Fatalf("bytes %d exceed %d", bytes, MaxBytesTotal)
	}
	w2.check()
}

func TestExpiryReportsToSenderAndFreesSpace(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	w.clock.advance(TTL - time.Second)
	w.queue.Subscribe(a.session)
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("expired early")
	}
	w.clock.advance(SweepInterval)
	if err := w.queue.Subscribe(a.session); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob.id) != 0 {
		t.Fatal("expired message retained")
	}
	var receipts []Receipt
	for _, p := range a.sink.take() {
		if p.Receipt != nil {
			receipts = append(receipts, *p.Receipt)
		}
	}
	if len(receipts) != 1 || receipts[0] != (Receipt{To: bob.id.String(), ID: m.ID, Status: Expired}) {
		t.Fatalf("expiry receipt = %+v", receipts)
	}
	if got := w.online(bob).sink.messages(); len(got) != 0 {
		t.Fatalf("expired message delivered %+v", got)
	}
	w.clock.advance(TTL)
	w.online(newUser(t))
	if w.queue.Receipts(alice.id) != 1 {
		t.Fatal("held receipt expired while in flight")
	}
	w.drop(a)
	w.clock.advance(SweepInterval)
	w.queue.Subscribe(w.online(bob).session)
	if w.queue.Receipts(alice.id) != 0 {
		t.Fatal("receipt retained beyond TTL")
	}
	w.check()
}

func TestHeldMessageDoesNotExpireUnderTheRecipient(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	b := w.online(bob)
	b.sink.take()
	w.clock.advance(TTL + SweepInterval)
	w.send(a, newUser(t))
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("message expired while held by the recipient")
	}
	if err := w.queue.Ack(b.session, alice.id, m.ID); err != nil || w.queue.Queued(bob.id) != 0 {
		t.Fatalf("late ack = %v", err)
	}
	w.check()
}

func TestRedeliveryAttemptsAreBounded(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	for range MaxAttempts {
		b := w.online(bob)
		if got := b.sink.messages(); len(got) != 1 {
			t.Fatalf("attempt delivered %d", len(got))
		}
		w.drop(b)
	}
	w.clock.advance(SweepInterval)
	b := w.online(bob)
	if got := b.sink.messages(); len(got) != 0 {
		t.Fatalf("delivered beyond attempt bound: %+v", got)
	}
	var receipts []Receipt
	for _, p := range a.sink.take() {
		if p.Receipt != nil {
			receipts = append(receipts, *p.Receipt)
		}
	}
	if len(receipts) != 1 || receipts[0].ID != m.ID || receipts[0].Status != Expired {
		t.Fatalf("receipts = %+v", receipts)
	}
	w.check()
}

func TestReceiptLimits(t *testing.T) {
	w := newWorld(t)
	alice := newUser(t)
	a := w.connect(alice)
	var first string
	for i := range MaxReceiptsPerSender + 3 {
		bob := newUser(t)
		m := w.send(a, bob)
		if i == 0 {
			first = m.ID
		}
		b := w.online(bob)
		if err := w.queue.Ack(b.session, alice.id, m.ID); err != nil {
			t.Fatal(err)
		}
		w.drop(b)
	}
	if n := w.queue.Receipts(alice.id); n != MaxReceiptsPerSender {
		t.Fatalf("receipts = %d", n)
	}
	for _, n := range w.queue.outboxes[alice.id.String()] {
		if n.receipt.ID == first {
			t.Fatal("oldest receipt not evicted")
		}
	}
	if err := w.queue.Subscribe(a.session); err != nil {
		t.Fatal(err)
	}
	if got := len(a.sink.take()); got != Window {
		t.Fatalf("receipts pushed %d, want window", got)
	}
	w.queue.mu.Lock()
	w.queue.notes = MaxReceiptsTotal
	w.queue.notify("other", Receipt{To: "x", ID: "y", Status: Delivered})
	_, ok := w.queue.outboxes["other"]
	w.queue.notes = MaxReceiptsPerSender
	w.queue.mu.Unlock()
	if ok {
		t.Fatal("receipt stored beyond global limit")
	}
	w.check()
}

func TestClosedSessionCannotUseQueue(t *testing.T) {
	w := newWorld(t)
	alice, bob := newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	b := w.online(bob)
	b.session.Close()
	if err := w.queue.Ack(b.session, alice.id, m.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("closed ack = %v", err)
	}
	if err := w.queue.Subscribe(b.session); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("closed subscribe = %v", err)
	}
	if w.queue.Queued(bob.id) != 1 {
		t.Fatal("closed session changed the queue")
	}
	w.queue.Detach(b.session)
	w.check()
}

func TestConcurrentQueueOperations(t *testing.T) {
	w := newWorld(t)
	users := make([]user, 6)
	for i := range users {
		users[i] = newUser(t)
	}
	var wg sync.WaitGroup
	for g := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			me := users[g%len(users)]
			for round := range 30 {
				c := w.online(me)
				for i := range 5 {
					to := users[(g+i+1)%len(users)]
					if to.id.Equal(me.id) {
						continue
					}
					w.queue.Enqueue(c.session, to.id, Message{ID: messageID(), Ciphertext: sealed(60)})
				}
				for _, p := range c.sink.take() {
					if p.Message != nil {
						from, _ := identity.Parse(p.Message.From)
						w.queue.Ack(c.session, from, p.Message.ID)
						w.queue.Ack(c.session, from, p.Message.ID)
					}
					if p.Receipt != nil {
						to, _ := identity.Parse(p.Receipt.To)
						w.queue.Clear(c.session, to, p.Receipt.ID)
					}
				}
				if round%7 == 0 {
					w.clock.advance(SweepInterval)
				}
				w.queue.Subscribe(c.session)
				w.drop(c)
			}
		}()
	}
	wg.Wait()
	w.check()
	for _, u := range users {
		c := w.online(u)
		for range 200 {
			pushes := c.sink.take()
			if len(pushes) == 0 {
				break
			}
			for _, p := range pushes {
				if p.Message != nil {
					from, _ := identity.Parse(p.Message.From)
					if err := w.queue.Ack(c.session, from, p.Message.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					to, _ := identity.Parse(p.Receipt.To)
					w.queue.Clear(c.session, to, p.Receipt.ID)
				}
			}
		}
		w.drop(c)
	}
	w.check()
	if messages, _, _ := w.queue.Usage(); messages != 0 {
		t.Fatalf("%d messages left after draining", messages)
	}
}

func FuzzQueueTransitions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{1, 1, 1, 1, 9, 9, 9, 2, 2, 5, 5, 7})
	f.Add([]byte{3, 0, 3, 1, 3, 2, 6, 6, 6, 4, 4, 8, 8})
	users := []user{newUser(f), newUser(f), newUser(f)}
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 400 {
			return
		}
		w := newWorld(t)
		conns := map[int]conn{}
		delivered := map[string]map[string]bool{}
		acked := map[string]bool{}
		for i, op := range ops {
			u := int(op>>4) % len(users)
			me := users[u]
			c, connected := conns[u]
			switch op % 10 {
			case 0, 1:
				if !connected {
					conns[u] = w.connect(me)
				}
			case 2:
				if connected {
					w.queue.Subscribe(c.session)
				}
			case 3, 4:
				if connected {
					to := users[(u+1+int(op>>6)%2)%len(users)]
					w.queue.Enqueue(c.session, to.id, Message{ID: fmt.Sprintf("m%d", i), Ciphertext: sealed(30 + int(op))})
				}
			case 5, 6:
				if connected {
					for _, p := range c.sink.take() {
						if p.Message == nil {
							continue
						}
						if p.Message.From == me.id.String() {
							t.Fatal("message delivered back to its sender")
						}
						if delivered[me.id.String()] == nil {
							delivered[me.id.String()] = map[string]bool{}
						}
						delivered[me.id.String()][p.Message.From+p.Message.ID] = true
						from, _ := identity.Parse(p.Message.From)
						if w.queue.Ack(c.session, from, p.Message.ID) == nil {
							acked[me.id.String()+p.Message.From+p.Message.ID] = true
						}
					}
				}
			case 7:
				if connected {
					victim := users[(u+1)%len(users)]
					before := w.queue.Queued(victim.id)
					for _, other := range users {
						w.queue.Ack(c.session, other.id, fmt.Sprintf("m%d", int(op)))
					}
					if w.queue.Queued(victim.id) != before {
						t.Fatal("acknowledgment removed another recipient's message")
					}
				}
			case 8:
				if connected {
					w.drop(c)
					delete(conns, u)
				}
			case 9:
				w.clock.advance(time.Duration(op) * time.Hour)
			}
			w.check()
			for _, s := range []int{0, 1, 2} {
				if cc, ok := conns[s]; ok {
					for _, p := range cc.sink.pushes {
						if p.Message != nil && p.Message.From == users[s].id.String() {
							t.Fatal("cross delivery")
						}
					}
				}
			}
		}
	})
}
