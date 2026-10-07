package queue

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	roster "github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/device/devicetest"
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

var devices, _ = roster.Open("")

func newWorld(t testing.TB) *world {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	q := NewRegistry(c.Now, devices.Authorized)
	return &world{t: t, clock: c, queue: q, sessions: auth.NewRegistry(time.Now, q, devices)}
}

type user struct {
	owner  *devicetest.Identity
	device *devicetest.Device
	id     identity.Identity
	addr   string
}

func newUser(t testing.TB) user {
	t.Helper()
	return newDevices(t, 1)[0]
}

func newDevices(t testing.TB, n int) []user {
	t.Helper()
	owner := devicetest.NewIdentity()
	var list []*devicetest.Device
	for range n {
		list = append(list, owner.NewDevice())
	}
	if err := devices.Publish(owner.Add(list...)); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Parse(owner.Identity)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]user, n)
	for i, d := range list {
		out[i] = user{owner: owner, device: d, id: id, addr: Address(owner.Identity, d.ID)}
	}
	return out
}

func (w *world) put(s *auth.Session, to user, m Message) error {
	return w.queue.Enqueue(s, to.id, m.ID, []Envelope{{Device: to.device.ID, Ciphertext: m.Ciphertext}})
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
	if _, err := s.Authenticate(u.owner.Identity, u.device.ID, u.device.AuthSignature(u.owner, nonce)); err != nil {
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
	m := Message{ID: messageID(), Ciphertext: sealed(120)}
	if err := w.put(from.session, to, m); err != nil {
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
			senders[e.from]++
			pairs[pair{e.from, e.to}]++
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
	if w.queue.Queued(bob.addr) != 1 {
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
	want := Message{ID: m.ID, From: alice.id.String(), FromDevice: alice.device.ID, Ciphertext: m.Ciphertext}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %+v, want %+v", got, want)
	}
	if w.queue.Queued(bob.addr) != 1 {
		t.Fatal("transmission removed the message before acknowledgment")
	}
	w.check()

	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob.addr) != 0 {
		t.Fatal("acknowledged message retained")
	}
	pushes := a.sink.take()
	if len(pushes) != 1 || pushes[0].Receipt == nil || *pushes[0].Receipt != (Receipt{To: bob.id.String(), Device: bob.device.ID, ID: m.ID, Status: Delivered}) {
		t.Fatalf("receipt = %+v", pushes)
	}
	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); err != nil {
		t.Fatalf("duplicate ack = %v", err)
	}
	if w.queue.Receipts(alice.addr) != 1 || len(a.sink.take()) != 0 {
		t.Fatal("duplicate ack produced a second receipt")
	}
	if err := w.queue.Clear(a.session, bob.id, bob.device.ID, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.queue.Clear(a.session, bob.id, bob.device.ID, m.ID); err != nil {
		t.Fatalf("duplicate clear = %v", err)
	}
	if w.queue.Receipts(alice.addr) != 0 {
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
	if w.queue.Queued(bob.addr) != 1 {
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
	if err := w.queue.Ack(again.session, alice.id, alice.device.ID, m.ID); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob.addr) != 0 {
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
		if err := w.queue.Ack(b.session, alice.id, alice.device.ID, sent[i].ID); err != nil {
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
	if w.queue.Queued(bob.addr) != 0 {
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
	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ack of never-transmitted message = %v", err)
	}
	if w.queue.Queued(bob.addr) != 1 {
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
		"sender acknowledges":         func() error { return w.queue.Ack(a.session, alice.id, alice.device.ID, m.ID) },
		"sender names recipient":      func() error { return w.queue.Ack(a.session, bob.id, bob.device.ID, m.ID) },
		"third party":                 func() error { return w.queue.Ack(c.session, alice.id, alice.device.ID, m.ID) },
		"recipient wrong sender":      func() error { return w.queue.Ack(b.session, mallory.id, mallory.device.ID, m.ID) },
		"recipient wrong message":     func() error { return w.queue.Ack(b.session, alice.id, alice.device.ID, messageID()) },
		"recipient names itself":      func() error { return w.queue.Ack(b.session, bob.id, bob.device.ID, m.ID) },
		"unauthenticated connection":  func() error { return w.queue.Ack(w.sessions.Open(), alice.id, alice.device.ID, m.ID) },
		"sender clears absent notice": func() error { return w.queue.Clear(a.session, bob.id, bob.device.ID, m.ID) },
	} {
		err := try()
		if w.queue.Queued(bob.addr) != 1 || w.queue.Receipts(alice.addr) != 0 {
			t.Fatalf("%s (%v) changed delivery state", name, err)
		}
	}
	if err := w.queue.Ack(w.sessions.Open(), alice.id, alice.device.ID, m.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated ack = %v", err)
	}
	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); err != nil || w.queue.Queued(bob.addr) != 0 {
		t.Fatalf("recipient ack = %v", err)
	}
	if err := w.queue.Clear(c.session, bob.id, bob.device.ID, m.ID); err != nil || w.queue.Receipts(alice.addr) != 1 {
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
	if err := w.put(c.session, bob, m); err != nil {
		t.Fatal(err)
	}
	if got := w.online(bob).sink.messages(); len(got) != 1 || got[0].From != mallory.id.String() {
		t.Fatalf("delivered %+v", got)
	}
	if err := w.put(w.sessions.Open(), bob, Message{ID: messageID(), Ciphertext: sealed(100)}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated enqueue = %v", err)
	}
	if err := w.put(c.session, mallory, Message{ID: messageID(), Ciphertext: sealed(100)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self enqueue = %v", err)
	}
	for _, bad := range []Message{{Ciphertext: sealed(100)}, {ID: messageID()}} {
		if err := w.put(c.session, bob, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("incomplete message = %v", err)
		}
	}
}

func TestDuplicateEnqueueRejected(t *testing.T) {
	w := newWorld(t)
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	a := w.online(alice)
	m := w.send(a, bob)
	if err := w.put(a.session, bob, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	other := m
	other.Ciphertext = sealed(130)
	if err := w.put(a.session, bob, other); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same id different ciphertext = %v", err)
	}
	b := w.online(bob)
	b.sink.take()
	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.put(a.session, bob, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after delivery = %v", err)
	}
	if err := w.put(a.session, carol, m); err != nil {
		t.Fatalf("same id to another recipient = %v", err)
	}
	if w.queue.Queued(bob.addr) != 0 || w.queue.Queued(carol.addr) != 1 {
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
	if err := w.put(a.session, bobs[0], first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < SeenLimit; i++ {
		to := bobs[1+i%79]
		m := Message{ID: messageID(), Ciphertext: sealed(40)}
		if err := w.put(a.session, to, m); err != nil {
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
	err := w.put(senders[0].session, bob, Message{ID: messageID(), Ciphertext: sealed(40)})
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
		if err := w2.put(others[i].session, carol, Message{ID: messageID(), Ciphertext: strings.Repeat("A", big)}); err != nil {
			t.Fatalf("within byte limit %d: %v", i, err)
		}
	}
	if err := w2.put(others[0].session, carol, Message{ID: messageID(), Ciphertext: "AQ"}); !errors.Is(err, ErrFull) {
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
	if err := w.put(a.session, bob, Message{ID: messageID(), Ciphertext: sealed(40)}); !errors.Is(err, ErrFull) {
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
	if err := w.put(a.session, newUser(t), Message{ID: messageID(), Ciphertext: sealed(40)}); !errors.Is(err, ErrFull) {
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
		if err := w.put(s.session, to, Message{ID: messageID(), Ciphertext: "AQ"}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	err := w.put(senders[len(senders)-1].session, recipients[len(recipients)-1], Message{ID: messageID(), Ciphertext: "AQ"})
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
		if err := w2.put(s.session, recipient, Message{ID: messageID(), Ciphertext: strings.Repeat("A", per)}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := w2.put(big[len(big)-1].session, newUser(t), Message{ID: messageID(), Ciphertext: strings.Repeat("A", per)}); !errors.Is(err, ErrFull) {
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
	if w.queue.Queued(bob.addr) != 1 {
		t.Fatal("expired early")
	}
	w.clock.advance(SweepInterval)
	if err := w.queue.Subscribe(a.session); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob.addr) != 0 {
		t.Fatal("expired message retained")
	}
	var receipts []Receipt
	for _, p := range a.sink.take() {
		if p.Receipt != nil {
			receipts = append(receipts, *p.Receipt)
		}
	}
	if len(receipts) != 1 || receipts[0] != (Receipt{To: bob.id.String(), Device: bob.device.ID, ID: m.ID, Status: Expired}) {
		t.Fatalf("expiry receipt = %+v", receipts)
	}
	if got := w.online(bob).sink.messages(); len(got) != 0 {
		t.Fatalf("expired message delivered %+v", got)
	}
	w.clock.advance(TTL)
	w.online(newUser(t))
	if w.queue.Receipts(alice.addr) != 1 {
		t.Fatal("held receipt expired while in flight")
	}
	w.drop(a)
	w.clock.advance(SweepInterval)
	w.queue.Subscribe(w.online(bob).session)
	if w.queue.Receipts(alice.addr) != 0 {
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
	if w.queue.Queued(bob.addr) != 1 {
		t.Fatal("message expired while held by the recipient")
	}
	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); err != nil || w.queue.Queued(bob.addr) != 0 {
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
		if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); err != nil {
			t.Fatal(err)
		}
		w.drop(b)
	}
	if n := w.queue.Receipts(alice.addr); n != MaxReceiptsPerSender {
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
	if err := w.queue.Ack(b.session, alice.id, alice.device.ID, m.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("closed ack = %v", err)
	}
	if err := w.queue.Subscribe(b.session); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("closed subscribe = %v", err)
	}
	if w.queue.Queued(bob.addr) != 1 {
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
					w.put(c.session, to, Message{ID: messageID(), Ciphertext: sealed(60)})
				}
				for _, p := range c.sink.take() {
					if p.Message != nil {
						from, _ := identity.Parse(p.Message.From)
						w.queue.Ack(c.session, from, p.Message.FromDevice, p.Message.ID)
						w.queue.Ack(c.session, from, p.Message.FromDevice, p.Message.ID)
					}
					if p.Receipt != nil {
						to, _ := identity.Parse(p.Receipt.To)
						w.queue.Clear(c.session, to, p.Receipt.Device, p.Receipt.ID)
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
					if err := w.queue.Ack(c.session, from, p.Message.FromDevice, p.Message.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					to, _ := identity.Parse(p.Receipt.To)
					w.queue.Clear(c.session, to, p.Receipt.Device, p.Receipt.ID)
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
					w.put(c.session, to, Message{ID: fmt.Sprintf("m%d", i), Ciphertext: sealed(30 + int(op))})
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
						if w.queue.Ack(c.session, from, p.Message.FromDevice, p.Message.ID) == nil {
							acked[me.id.String()+p.Message.From+p.Message.ID] = true
						}
					}
				}
			case 7:
				if connected {
					victim := users[(u+1)%len(users)]
					before := w.queue.Queued(victim.addr)
					for _, other := range users {
						w.queue.Ack(c.session, other.id, other.device.ID, fmt.Sprintf("m%d", int(op)))
					}
					if w.queue.Queued(victim.addr) != before {
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

func TestEachRecipientDeviceHasItsOwnQueueAndReceipts(t *testing.T) {
	w := newWorld(t)
	alice := newUser(t)
	bob := newDevices(t, 2)
	a := w.online(alice)
	id := messageID()
	envelopes := []Envelope{{Device: bob[0].device.ID, Ciphertext: sealed(90)}, {Device: bob[1].device.ID, Ciphertext: sealed(91)}}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, envelopes); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob[0].addr) != 1 || w.queue.Queued(bob[1].addr) != 1 {
		t.Fatal("envelopes not queued per device")
	}
	b0 := w.online(bob[0])
	got := b0.sink.messages()
	if len(got) != 1 || got[0].Ciphertext != envelopes[0].Ciphertext || got[0].FromDevice != alice.device.ID {
		t.Fatalf("device 0 received %+v", got)
	}
	if err := w.queue.Ack(b0.session, alice.id, alice.device.ID, id); err != nil {
		t.Fatal(err)
	}
	if w.queue.Queued(bob[0].addr) != 0 || w.queue.Queued(bob[1].addr) != 1 {
		t.Fatal("ack from one device affected the other device's queue")
	}
	receipts := a.sink.take()
	if len(receipts) != 1 || *receipts[0].Receipt != (Receipt{To: bob[0].id.String(), Device: bob[0].device.ID, ID: id, Status: Delivered}) {
		t.Fatalf("receipts = %+v", receipts)
	}
	b1 := w.online(bob[1])
	got = b1.sink.messages()
	if len(got) != 1 || got[0].Ciphertext != envelopes[1].Ciphertext {
		t.Fatalf("device 1 received %+v", got)
	}
	if err := w.queue.Ack(b1.session, alice.id, alice.device.ID, id); err != nil {
		t.Fatal(err)
	}
	if err := w.queue.Ack(b1.session, alice.id, alice.device.ID, id); err != nil {
		t.Fatal(err)
	}
	receipts = a.sink.take()
	if len(receipts) != 1 || receipts[0].Receipt.Device != bob[1].device.ID {
		t.Fatalf("second device receipt = %+v", receipts)
	}
	if w.queue.Receipts(alice.addr) != 2 {
		t.Fatal("expected one receipt per recipient device")
	}
	w.check()
}

func TestEnqueueIsAtomicAndRequiresAuthorizedDevices(t *testing.T) {
	w := newWorld(t)
	alice := newUser(t)
	bob := newDevices(t, 2)
	stranger := newUser(t)
	a := w.online(alice)
	id := messageID()
	bad := []Envelope{{Device: bob[0].device.ID, Ciphertext: sealed(80)}, {Device: stranger.device.ID, Ciphertext: sealed(80)}}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, bad); !errors.Is(err, ErrRevoked) {
		t.Fatalf("envelope for a device outside the roster = %v", err)
	}
	if w.queue.Queued(bob[0].addr) != 0 {
		t.Fatal("partial enqueue after rejection")
	}
	dup := []Envelope{{Device: bob[0].device.ID, Ciphertext: sealed(80)}, {Device: bob[0].device.ID, Ciphertext: sealed(81)}}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, dup); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate device envelopes = %v", err)
	}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no envelopes = %v", err)
	}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, []Envelope{{Device: bob[1].device.ID, Ciphertext: sealed(80)}}); err != nil {
		t.Fatalf("subset of devices = %v", err)
	}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, []Envelope{{Device: bob[1].device.ID, Ciphertext: sealed(80)}}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay to the same device = %v", err)
	}
	if err := w.queue.Enqueue(a.session, bob[0].id, id, []Envelope{{Device: bob[0].device.ID, Ciphertext: sealed(80)}}); err != nil {
		t.Fatalf("same id to another device = %v", err)
	}
	w.check()
}

func TestRevokedDevicesLoseQueuesAndCannotUseTheQueue(t *testing.T) {
	w := newWorld(t)
	alice := newDevices(t, 2)
	bob := newDevices(t, 2)
	a0 := w.online(alice[0])
	a1 := w.online(alice[1])
	toBoth := []Envelope{{Device: bob[0].device.ID, Ciphertext: sealed(80)}, {Device: bob[1].device.ID, Ciphertext: sealed(81)}}
	first := messageID()
	if err := w.queue.Enqueue(a0.session, bob[0].id, first, toBoth); err != nil {
		t.Fatal(err)
	}
	fromRevoked := messageID()
	if err := w.queue.Enqueue(a1.session, bob[0].id, fromRevoked, toBoth[:1]); err != nil {
		t.Fatal(err)
	}
	b1 := w.online(bob[1])
	b1.sink.take()
	if err := w.queue.Ack(b1.session, alice[0].id, alice[0].device.ID, first); err != nil {
		t.Fatal(err)
	}
	if err := devices.Publish(bob[0].owner.Remove(bob[1].device)); err != nil {
		t.Fatal(err)
	}
	w.queue.RemoveDevice(bob[1].owner.Identity, bob[1].device.ID)
	if err := devices.Publish(alice[0].owner.Remove(alice[1].device)); err != nil {
		t.Fatal(err)
	}
	w.queue.RemoveDevice(alice[1].owner.Identity, alice[1].device.ID)
	if w.queue.Queued(bob[1].addr) != 0 {
		t.Fatal("revoked recipient device kept its queue")
	}
	if w.queue.Queued(bob[0].addr) != 1 {
		t.Fatal("messages from the revoked sender device were not purged")
	}
	if err := w.queue.Enqueue(a1.session, bob[0].id, messageID(), toBoth[:1]); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked sender enqueued = %v", err)
	}
	if err := w.queue.Enqueue(a0.session, bob[0].id, messageID(), toBoth[1:]); !errors.Is(err, ErrRevoked) {
		t.Fatalf("enqueue to revoked device = %v", err)
	}
	if err := w.queue.Subscribe(b1.session); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked device subscribed = %v", err)
	}
	if w.queue.Receipts(alice[0].addr) != 1 {
		t.Fatal("legitimate receipt lost")
	}
	b0 := w.online(bob[0])
	if got := b0.sink.messages(); len(got) != 1 || got[0].ID != first {
		t.Fatalf("remaining device received %+v", got)
	}
	w.check()
}

func TestRevokedSessionCannotUseAnyQueueOperation(t *testing.T) {
	w := newWorld(t)
	alice := newDevices(t, 2)
	bob := newUser(t)
	sender := w.online(bob)
	revoked := w.online(alice[1])
	queued := w.send(sender, alice[1])
	if err := devices.Publish(alice[0].owner.Remove(alice[1].device)); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"enqueue":   w.put(revoked.session, bob, Message{ID: messageID(), Ciphertext: sealed(120)}),
		"subscribe": w.queue.Subscribe(revoked.session),
		"ack":       w.queue.Ack(revoked.session, bob.id, bob.device.ID, queued.ID),
		"clear":     w.queue.Clear(revoked.session, bob.id, bob.device.ID, queued.ID),
	} {
		if !errors.Is(err, ErrRevoked) {
			t.Errorf("%s by a revoked device = %v", name, err)
		}
	}
	if _, ok := revoked.session.Identity(); ok || revoked.session.State() != auth.Revoked {
		t.Fatalf("revoked session still authenticated: %v", revoked.session.State())
	}
	if _, err := revoked.session.Challenge(); !errors.Is(err, auth.ErrClosed) {
		t.Fatalf("revoked session challenge = %v", err)
	}
	if err := w.put(w.online(alice[0]).session, bob, Message{ID: messageID(), Ciphertext: sealed(120)}); err != nil {
		t.Fatalf("sibling device blocked: %v", err)
	}
}

func TestConcurrentRevocationNeverLeavesTheRevokedDeviceUsable(t *testing.T) {
	for round := range 150 {
		registry, _ := roster.Open("")
		q := NewRegistry(time.Now, registry.Authorized)
		registry.OnRevoke(q.RemoveDevice)
		sessions := auth.NewRegistry(time.Now, q, registry)
		owner := devicetest.NewIdentity()
		kept, gone := owner.NewDevice(), owner.NewDevice()
		peer := devicetest.NewIdentity()
		peerDevice := peer.NewDevice()
		if registry.Publish(owner.Add(kept, gone)) != nil || registry.Publish(peer.Add(peerDevice)) != nil {
			t.Fatal("setup")
		}
		peerID, _ := identity.Parse(peer.Identity)
		open := func() *auth.Session {
			s := sessions.Open()
			q.Attach(s, func(Push) bool { return true })
			return s
		}
		sending := open()
		nonce, _ := sending.Challenge()
		if _, err := sending.Authenticate(owner.Identity, gone.ID, gone.AuthSignature(owner, nonce)); err != nil {
			t.Fatal(err)
		}
		reconnect := open()
		again, _ := reconnect.Challenge()
		var wg sync.WaitGroup
		var sendErr, authErr error
		wg.Add(3)
		go func() {
			defer wg.Done()
			sendErr = q.Enqueue(sending, peerID, messageID(), []Envelope{{Device: peerDevice.ID, Ciphertext: sealed(120)}})
		}()
		go func() {
			defer wg.Done()
			_, authErr = reconnect.Authenticate(owner.Identity, gone.ID, gone.AuthSignature(owner, again))
		}()
		go func() {
			defer wg.Done()
			if err := registry.Publish(owner.Remove(gone)); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if n := q.Queued(Address(peer.Identity, peerDevice.ID)); n != 0 {
			t.Fatalf("round %d: message from the revoked device survived revocation (send %v)", round, sendErr)
		}
		for name, s := range map[string]*auth.Session{"sending": sending, "reconnect": reconnect} {
			if _, ok := s.Identity(); ok {
				t.Fatalf("round %d: %s session still authenticated after revocation (auth %v)", round, name, authErr)
			}
		}
		if err := q.Subscribe(reconnect); err == nil {
			t.Fatalf("round %d: revoked device subscribed", round)
		}
	}
}
