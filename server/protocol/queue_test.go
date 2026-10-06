package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/prekey"
	"github.com/Xhaann/ghost-x/server/queue"
)

type mailbox struct {
	mu    sync.Mutex
	items []string
}

func (m *mailbox) deliver(p queue.Push) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, string(EncodePush(p)))
	return true
}

func (m *mailbox) take() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.items
	m.items = nil
	return out
}

type queueFixture struct {
	router   *Router
	sessions *auth.Registry
	direct   *direct.Registry
	prekeys  *prekey.Registry
	queue    *queue.Registry
}

func newQueueFixture() queueFixture {
	d := direct.NewRegistry()
	p := prekey.NewRegistry()
	q := queue.NewRegistry(time.Now)
	return queueFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"publish": Publish(d),
			"prekeys": Prekeys(d, p),
			"send":    Send(d, p, q),
			"fetch":   Fetch(q),
			"ack":     Ack(q),
			"clear":   Clear(q),
		}),
		sessions: auth.NewRegistry(time.Now, fanout{d, p, q}),
		direct:   d,
		prekeys:  p,
		queue:    q,
	}
}

type client struct {
	party
	conn    *Conn
	session *auth.Session
	box     *mailbox
}

func (f queueFixture) open(t testing.TB) (*Conn, *auth.Session, *mailbox) {
	session := f.sessions.Open()
	box := &mailbox{}
	f.queue.Attach(session, box.deliver)
	return f.router.Conn(session, discard), session, box
}

func (f queueFixture) join(t *testing.T, p party) client {
	t.Helper()
	conn, session, box := f.open(t)
	authenticated(t, conn, p.signer)
	if resp := decodeResponse(t, conn.Handle(publishRequest(p.key, p.signature))); resp.Type != "published" {
		t.Fatalf("publish = %+v", resp)
	}
	deviceID := randomText(DeviceIDSize)
	if resp := decodeResponse(t, conn.Handle(prekeysRequest(deviceID, signPrekey(p, true, deviceID, 1), []prekeyPayload{}))); resp.Type != "prekeys" {
		t.Fatalf("prekeys = %+v %s", resp, resp.Payload)
	}
	return client{party: p, conn: conn, session: session, box: box}
}

func (f queueFixture) leave(c client) {
	c.session.Close()
	f.queue.Detach(c.session)
	f.direct.Detach(c.session)
	f.prekeys.Detach(c.session)
}

func (c client) fetch(t *testing.T) {
	t.Helper()
	if resp := decodeResponse(t, c.conn.Handle([]byte(`{"type":"fetch","id":"f1","payload":{}}`))); resp.Type != "fetched" || string(resp.Payload) != `{}` {
		t.Fatalf("fetch = %+v %s", resp, resp.Payload)
	}
}

func ratchetCiphertext(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	b[0] = RatchetVersion
	return base64.RawURLEncoding.EncodeToString(b)
}

func newMessageID() string {
	return randomText(MessageIDSize)
}

func queueSend(to, id, ciphertext string) []byte {
	payload, _ := json.Marshal(map[string]string{"to": to, "id": id, "ciphertext": ciphertext})
	return fmt.Appendf(nil, `{"type":"send","id":"s1","payload":%s}`, payload)
}

func ackRequest(from, id string) []byte {
	return fmt.Appendf(nil, `{"type":"ack","id":"a1","payload":{"from":%q,"id":%q}}`, from, id)
}

func clearRequest(to, id string) []byte {
	return fmt.Appendf(nil, `{"type":"clear","id":"c1","payload":{"to":%q,"id":%q}}`, to, id)
}

func pushedMessage(from party, id, ciphertext string) string {
	return string(EncodePush(queue.Push{Message: &queue.Message{ID: id, From: from.identity, Key: from.key, Signature: from.signature, Ciphertext: ciphertext}}))
}

func expectQueued(t *testing.T, out []byte) {
	t.Helper()
	if resp := decodeResponse(t, out); resp.Type != "queued" || resp.ID != "s1" || string(resp.Payload) != `{}` {
		t.Fatalf("send = %+v %s", resp, resp.Payload)
	}
}

func TestOfflineMessageQueuedDeliveredAndDeletedOnAck(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newParty(t))
	bob := f.join(t, newParty(t))
	f.leave(bob)
	alice.fetch(t)

	id, ciphertext := newMessageID(), ratchetCiphertext(200)
	expectQueued(t, alice.conn.Handle(queueSend(bob.identity, id, ciphertext)))
	if f.queue.Queued(mustIdentity(t, bob.identity)) != 1 {
		t.Fatal("not queued")
	}

	again := f.join(t, bob.party)
	if got := again.box.take(); len(got) != 0 {
		t.Fatalf("pushed before fetch: %v", got)
	}
	again.fetch(t)
	want := pushedMessage(alice.party, id, ciphertext)
	if got := again.box.take(); len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %v, want %s", got, want)
	}
	if f.queue.Queued(mustIdentity(t, bob.identity)) != 1 {
		t.Fatal("transmission deleted the message")
	}
	if resp := decodeResponse(t, again.conn.Handle(ackRequest(alice.identity, id))); resp.Type != "acked" || string(resp.Payload) != `{}` {
		t.Fatalf("ack = %+v", resp)
	}
	if f.queue.Queued(mustIdentity(t, bob.identity)) != 0 {
		t.Fatal("not deleted on ack")
	}
	receipt := `{"type":"receipt","payload":{"to":"` + bob.identity + `","id":"` + id + `","status":"delivered"}}`
	if got := alice.box.take(); len(got) != 1 || got[0] != receipt {
		t.Fatalf("receipt = %v", got)
	}
	if resp := decodeResponse(t, again.conn.Handle(ackRequest(alice.identity, id))); resp.Type != "acked" {
		t.Fatalf("duplicate ack = %+v", resp)
	}
	if got := alice.box.take(); len(got) != 0 {
		t.Fatalf("duplicate ack produced %v", got)
	}
	if resp := decodeResponse(t, alice.conn.Handle(clearRequest(bob.identity, id))); resp.Type != "cleared" {
		t.Fatalf("clear = %+v", resp)
	}
	if f.queue.Receipts(mustIdentity(t, alice.identity)) != 0 {
		t.Fatal("receipt retained after clear")
	}
}

func TestPushShapesCarryOnlyCiphertextAndRouting(t *testing.T) {
	p := newParty(t)
	message := pushedMessage(p, "i", "c")
	if message != `{"type":"message","payload":{"id":"i","from":"`+p.identity+`","key":"`+p.key+`","signature":"`+p.signature+`","ciphertext":"c"}}` {
		t.Fatalf("message = %s", message)
	}
	receipt := string(EncodePush(queue.Push{Receipt: &queue.Receipt{To: "t", ID: "i", Status: queue.Expired}}))
	if receipt != `{"type":"receipt","payload":{"to":"t","id":"i","status":"expired"}}` {
		t.Fatalf("receipt = %s", receipt)
	}
}

func TestSendValidation(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newParty(t))
	bob := f.join(t, newParty(t))
	id := newMessageID()
	good := ratchetCiphertext(200)
	plain := base64.RawURLEncoding.EncodeToString([]byte(`{"body":"` + strings.Repeat("hello ", 30) + `"}`))
	zeroVersion := []byte(strings.Repeat("\x00", MinCiphertext))
	cases := map[string]struct {
		input []byte
		code  Code
	}{
		"short id":            {queueSend(bob.identity, id[:21], good), CodeInvalidPayload},
		"long id":             {queueSend(bob.identity, id+"A", good), CodeInvalidPayload},
		"padded id":           {queueSend(bob.identity, id+"==", good), CodeInvalidPayload},
		"hex id":              {queueSend(bob.identity, "00112233445566778899aabb", good), CodeInvalidPayload},
		"bad recipient":       {queueSend("bad", id, good), CodeInvalidPayload},
		"self":                {queueSend(alice.identity, id, good), CodeInvalidPayload},
		"plaintext body":      {queueSend(bob.identity, id, plain), CodeInvalidPayload},
		"wrong version":       {queueSend(bob.identity, id, base64.RawURLEncoding.EncodeToString(zeroVersion)), CodeInvalidPayload},
		"too short":           {queueSend(bob.identity, id, ratchetCiphertext(MinCiphertext-1)), CodeInvalidPayload},
		"too long":            {queueSend(bob.identity, id, ratchetCiphertext(MaxCiphertext+1)), CodeTooLarge},
		"huge":                {queueSend(bob.identity, id, strings.Repeat("A", 20000)), CodeTooLarge},
		"padded ciphertext":   {queueSend(bob.identity, id, good+"="), CodeInvalidPayload},
		"non-base64":          {queueSend(bob.identity, id, "!!"+good[2:]), CodeInvalidPayload},
		"numeric ciphertext":  {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","ciphertext":1}}`), CodeInvalidPayload},
		"missing id":          {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","ciphertext":"` + good + `"}}`), CodeInvalidPayload},
		"sender claim":        {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","ciphertext":"` + good + `","from":"` + bob.identity + `"}}`), CodeInvalidPayload},
		"delivery state":      {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","ciphertext":"` + good + `","status":"delivered"}}`), CodeInvalidPayload},
		"duplicate field":     {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","id":"` + id + `","ciphertext":"` + good + `"}}`), CodeInvalidPayload},
		"null payload":        {[]byte(`{"type":"send","id":"s1","payload":null}`), CodeInvalidPayload},
		"unknown recipient":   {queueSend(newParty(t).identity, id, good), CodeUnavailable},
		"previous wire shape": {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","epoch":0,"envelopes":[]}}`), CodeInvalidPayload},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			expectCode(t, alice.conn.Handle(tc.input), tc.code)
			if n := f.queue.Queued(mustIdentity(t, bob.identity)); n != 0 {
				t.Fatalf("rejected request queued %d", n)
			}
		})
	}
	expectQueued(t, alice.conn.Handle(queueSend(bob.identity, id, ratchetCiphertext(MinCiphertext))))
	expectQueued(t, alice.conn.Handle(queueSend(bob.identity, newMessageID(), ratchetCiphertext(MaxCiphertext))))
	expectCode(t, alice.conn.Handle(queueSend(bob.identity, id, good)), CodeDuplicate)
}

func TestSendRequiresAuthenticationAndPublishedKey(t *testing.T) {
	f := newQueueFixture()
	bob := f.join(t, newParty(t))
	conn, _, _ := f.open(t)
	expectCode(t, conn.Handle(queueSend(bob.identity, newMessageID(), ratchetCiphertext(200))), CodeAuthRequired)
	expectCode(t, conn.Handle([]byte(`{"type":"fetch","id":"f1","payload":{}}`)), CodeAuthRequired)
	expectCode(t, conn.Handle(ackRequest(bob.identity, newMessageID())), CodeAuthRequired)
	expectCode(t, conn.Handle(clearRequest(bob.identity, newMessageID())), CodeAuthRequired)
	a := newParty(t)
	authenticated(t, conn, a.signer)
	expectCode(t, conn.Handle(queueSend(bob.identity, newMessageID(), ratchetCiphertext(200))), CodeKeyRequired)
	if f.queue.Queued(mustIdentity(t, bob.identity)) != 0 {
		t.Fatal("queued without a published sender key")
	}
}

func TestQueueLimitIsReported(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newParty(t))
	bob := f.join(t, newParty(t))
	for range queue.MaxPerPair {
		expectQueued(t, alice.conn.Handle(queueSend(bob.identity, newMessageID(), ratchetCiphertext(100))))
	}
	expectCode(t, alice.conn.Handle(queueSend(bob.identity, newMessageID(), ratchetCiphertext(100))), CodeQueueFull)
}

func TestForgedAcknowledgmentsCannotDelete(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newParty(t))
	bob := f.join(t, newParty(t))
	mallory := f.join(t, newParty(t))
	alice.fetch(t)
	id := newMessageID()
	expectQueued(t, alice.conn.Handle(queueSend(bob.identity, id, ratchetCiphertext(150))))

	expectCode(t, bob.conn.Handle(ackRequest(alice.identity, id)), CodeInvalidPayload)
	for name, out := range map[string][]byte{
		"sender":          alice.conn.Handle(ackRequest(alice.identity, id)),
		"sender as peer":  alice.conn.Handle(ackRequest(bob.identity, id)),
		"third party":     mallory.conn.Handle(ackRequest(alice.identity, id)),
		"third as sender": mallory.conn.Handle(ackRequest(bob.identity, id)),
	} {
		resp := decodeResponse(t, out)
		if f.queue.Queued(mustIdentity(t, bob.identity)) != 1 {
			t.Fatalf("%s ack (%s) deleted the message", name, resp.Type)
		}
	}
	if got := alice.box.take(); len(got) != 0 {
		t.Fatalf("forged acks produced receipts %v", got)
	}
	bob.fetch(t)
	bob.box.take()
	decodeResponse(t, bob.conn.Handle(ackRequest(mallory.identity, id)))
	decodeResponse(t, bob.conn.Handle(ackRequest(alice.identity, newMessageID())))
	if f.queue.Queued(mustIdentity(t, bob.identity)) != 1 {
		t.Fatal("mismatched ack deleted the message")
	}
	for _, bad := range [][]byte{
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `","id":"` + id + `","to":"x"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"bad","id":"` + id + `"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `","id":"` + id[:20] + `"}}`),
		[]byte(`{"type":"clear","id":"c1","payload":{"to":"` + bob.identity + `","id":"` + id + `","status":"delivered"}}`),
		[]byte(`{"type":"fetch","id":"f1","payload":{"since":0}}`),
	} {
		expectCode(t, bob.conn.Handle(bad), CodeInvalidPayload)
	}
	if f.queue.Queued(mustIdentity(t, bob.identity)) != 1 {
		t.Fatal("malformed ack deleted the message")
	}
	if resp := decodeResponse(t, bob.conn.Handle(ackRequest(alice.identity, id))); resp.Type != "acked" || f.queue.Queued(mustIdentity(t, bob.identity)) != 0 {
		t.Fatalf("recipient ack = %+v", resp)
	}
}

func TestQueueErrorsDoNotLeakDetails(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newParty(t))
	bob := f.join(t, newParty(t))
	id := newMessageID()
	expectQueued(t, alice.conn.Handle(queueSend(bob.identity, id, ratchetCiphertext(150))))
	for _, out := range [][]byte{
		alice.conn.Handle(queueSend(bob.identity, id, ratchetCiphertext(150))),
		alice.conn.Handle(queueSend(newParty(t).identity, newMessageID(), ratchetCiphertext(150))),
		bob.conn.Handle(ackRequest(alice.identity, id)),
		alice.conn.Handle(queueSend(bob.identity, "x", "y")),
	} {
		for _, leak := range []string{"queue:", "identity:", "registry", "base64", "limit reached"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}

func FuzzSendPayload(f *testing.F) {
	alice, bob := newParty(f), newParty(f)
	id := randomText(MessageIDSize)
	good := ratchetCiphertext(120)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","ciphertext":"` + good + `"}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","ciphertext":"` + good + `","from":"SENDER"}`)
	f.Add(`{"to":"SENDER","id":"` + id + `","ciphertext":"` + good + `"}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","ciphertext":"AAAA"}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","body":"plaintext"}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","ciphertext":"` + strings.Repeat("A", 6000) + `"}`)
	f.Add(`{"to":"RECIPIENT","epoch":0,"envelopes":[]}`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, payload string) {
		fx := newQueueFixture()
		sender := fx.join(t, alice)
		fx.join(t, bob)
		payload = strings.ReplaceAll(strings.ReplaceAll(payload, "RECIPIENT", bob.identity), "SENDER", alice.identity)
		out := sender.conn.Handle([]byte(`{"type":"send","id":"s1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		queued := fx.queue.Queued(mustIdentity(t, bob.identity))
		if resp.Type != "queued" {
			if queued != 0 {
				t.Fatalf("rejected request queued %d", queued)
			}
			return
		}
		if queued != 1 {
			t.Fatalf("accepted request queued %d", queued)
		}
		var sent struct {
			To, ID, Ciphertext string
		}
		if err := json.Unmarshal([]byte(payload), &sent); err != nil {
			t.Fatalf("accepted non-object %q", payload)
		}
		raw, err := strict.DecodeString(sent.Ciphertext)
		if err != nil || len(raw) < MinCiphertext || len(raw) > MaxCiphertext || raw[0] != RatchetVersion {
			t.Fatalf("accepted invalid ciphertext %q", payload)
		}
		recipient := fx.join(t, bob)
		recipient.fetch(t)
		got := recipient.box.take()
		if len(got) != 1 || got[0] != pushedMessage(alice, sent.ID, sent.Ciphertext) {
			t.Fatalf("delivery %v not bound to the authenticated sender", got)
		}
	})
}

func FuzzAckPayload(f *testing.F) {
	alice, bob, mallory := newParty(f), newParty(f), newParty(f)
	f.Add(`{"from":"SENDER","id":"ID"}`, true)
	f.Add(`{"from":"SENDER","id":"ID"}`, false)
	f.Add(`{"from":"RECIPIENT","id":"ID"}`, true)
	f.Add(`{"from":"SENDER","id":"ID","to":"RECIPIENT"}`, true)
	f.Add(`{"from":"SENDER","id":"IDA"}`, true)
	f.Add(`{"from":"SENDER"}`, true)
	f.Add(`[]`, false)

	f.Fuzz(func(t *testing.T, payload string, asRecipient bool) {
		fx := newQueueFixture()
		sender := fx.join(t, alice)
		recipient := fx.join(t, bob)
		attacker := fx.join(t, mallory)
		id := newMessageID()
		expectQueued(t, sender.conn.Handle(queueSend(bob.identity, id, ratchetCiphertext(120))))
		recipient.fetch(t)
		recipient.box.take()
		payload = strings.NewReplacer("SENDER", alice.identity, "RECIPIENT", bob.identity, "ID", id).Replace(payload)
		actor := attacker
		if asRecipient {
			actor = recipient
		}
		out := actor.conn.Handle([]byte(`{"type":"ack","id":"a1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		remaining := fx.queue.Queued(mustIdentity(t, bob.identity))
		exact := asRecipient && payload == `{"from":"`+alice.identity+`","id":"`+id+`"}`
		if remaining == 0 && !exact {
			t.Fatalf("payload %q from recipient=%v deleted the message", payload, asRecipient)
		}
		if exact && (remaining != 0 || resp.Type != "acked") {
			t.Fatalf("exact acknowledgment = %s, remaining %d", out, remaining)
		}
	})
}
