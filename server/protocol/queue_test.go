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
	queue    *queue.Registry
}

func newQueueFixture() queueFixture {
	q := queue.NewRegistry(time.Now, testDevices.Authorized)
	return queueFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"send":  Send(q),
			"fetch": Fetch(q),
			"ack":   Ack(q),
			"clear": Clear(q),
		}),
		sessions: auth.NewRegistry(time.Now, fanout{q}, testDevices),
		queue:    q,
	}
}

type client struct {
	signer
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

func (f queueFixture) join(t *testing.T, s signer) client {
	t.Helper()
	conn, session, box := f.open(t)
	authenticated(t, conn, s)
	return client{signer: s, conn: conn, session: session, box: box}
}

func (f queueFixture) leave(c client) {
	c.session.Close()
	f.queue.Detach(c.session)
}

func (c client) fetch(t *testing.T) {
	t.Helper()
	if resp := decodeResponse(t, c.conn.Handle([]byte(`{"type":"fetch","id":"f1","payload":{}}`))); resp.Type != "fetched" || string(resp.Payload) != `{}` {
		t.Fatalf("fetch = %+v %s", resp, resp.Payload)
	}
}

func (s signer) address() string {
	return queue.Address(s.identity, s.device.ID)
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

type wireEnvelope struct {
	Device     string `json:"device"`
	Ciphertext string `json:"ciphertext"`
}

func sendFrame(to, id string, envelopes ...wireEnvelope) []byte {
	payload, _ := json.Marshal(map[string]any{"to": to, "id": id, "envelopes": envelopes})
	return fmt.Appendf(nil, `{"type":"send","id":"s1","payload":%s}`, payload)
}

func queueSend(to signer, id, ciphertext string) []byte {
	return sendFrame(to.identity, id, wireEnvelope{Device: to.device.ID, Ciphertext: ciphertext})
}

func ackRequest(from signer, id string) []byte {
	return fmt.Appendf(nil, `{"type":"ack","id":"a1","payload":{"from":%q,"device":%q,"id":%q}}`, from.identity, from.device.ID, id)
}

func clearRequest(to signer, id string) []byte {
	return fmt.Appendf(nil, `{"type":"clear","id":"c1","payload":{"to":%q,"device":%q,"id":%q}}`, to.identity, to.device.ID, id)
}

func pushedMessage(from signer, id, ciphertext string) string {
	return string(EncodePush(queue.Push{Message: &queue.Message{ID: id, From: from.identity, FromDevice: from.device.ID, Ciphertext: ciphertext}}))
}

func expectQueued(t *testing.T, out []byte) {
	t.Helper()
	if resp := decodeResponse(t, out); resp.Type != "queued" || resp.ID != "s1" || string(resp.Payload) != `{}` {
		t.Fatalf("send = %+v %s", resp, resp.Payload)
	}
}

func TestOfflineMessageQueuedDeliveredAndDeletedOnAck(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newSigner(t))
	bobSigner := newSigner(t)
	alice.fetch(t)

	id, ciphertext := newMessageID(), ratchetCiphertext(200)
	expectQueued(t, alice.conn.Handle(queueSend(bobSigner, id, ciphertext)))
	if f.queue.Queued(bobSigner.address()) != 1 {
		t.Fatal("not queued")
	}

	bob := f.join(t, bobSigner)
	if got := bob.box.take(); len(got) != 0 {
		t.Fatalf("pushed before fetch: %v", got)
	}
	bob.fetch(t)
	want := pushedMessage(alice.signer, id, ciphertext)
	if got := bob.box.take(); len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %v, want %s", got, want)
	}
	if f.queue.Queued(bobSigner.address()) != 1 {
		t.Fatal("transmission deleted the message")
	}
	if resp := decodeResponse(t, bob.conn.Handle(ackRequest(alice.signer, id))); resp.Type != "acked" || string(resp.Payload) != `{}` {
		t.Fatalf("ack = %+v", resp)
	}
	if f.queue.Queued(bobSigner.address()) != 0 {
		t.Fatal("not deleted on ack")
	}
	receipt := `{"type":"receipt","payload":{"to":"` + bobSigner.identity + `","device":"` + bobSigner.device.ID + `","id":"` + id + `","status":"delivered"}}`
	if got := alice.box.take(); len(got) != 1 || got[0] != receipt {
		t.Fatalf("receipt = %v", got)
	}
	if resp := decodeResponse(t, bob.conn.Handle(ackRequest(alice.signer, id))); resp.Type != "acked" {
		t.Fatalf("duplicate ack = %+v", resp)
	}
	if got := alice.box.take(); len(got) != 0 {
		t.Fatalf("duplicate ack produced %v", got)
	}
	if resp := decodeResponse(t, alice.conn.Handle(clearRequest(bobSigner, id))); resp.Type != "cleared" {
		t.Fatalf("clear = %+v", resp)
	}
	if f.queue.Receipts(alice.address()) != 0 {
		t.Fatal("receipt retained after clear")
	}
}

func TestFanOutDeliversEachDeviceItsOwnEnvelope(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newSigner(t))
	bob := newSiblings(t, 2)
	id := newMessageID()
	first, second := ratchetCiphertext(120), ratchetCiphertext(121)
	expectQueued(t, alice.conn.Handle(sendFrame(bob[0].identity, id, wireEnvelope{bob[0].device.ID, first}, wireEnvelope{bob[1].device.ID, second})))
	b0 := f.join(t, bob[0])
	b1 := f.join(t, bob[1])
	b0.fetch(t)
	b1.fetch(t)
	if got := b0.box.take(); len(got) != 1 || got[0] != pushedMessage(alice.signer, id, first) {
		t.Fatalf("device 0 received %v", got)
	}
	if got := b1.box.take(); len(got) != 1 || got[0] != pushedMessage(alice.signer, id, second) {
		t.Fatalf("device 1 received %v", got)
	}
}

func TestPushShapesCarryOnlyCiphertextAndRouting(t *testing.T) {
	p := newSigner(t)
	message := pushedMessage(p, "i", "c")
	if message != `{"type":"message","payload":{"id":"i","from":"`+p.identity+`","device":"`+p.device.ID+`","ciphertext":"c"}}` {
		t.Fatalf("message = %s", message)
	}
	receipt := string(EncodePush(queue.Push{Receipt: &queue.Receipt{To: "t", Device: "d", ID: "i", Status: queue.Expired}}))
	if receipt != `{"type":"receipt","payload":{"to":"t","device":"d","id":"i","status":"expired"}}` {
		t.Fatalf("receipt = %s", receipt)
	}
}

func TestSendValidation(t *testing.T) {
	f := newQueueFixture()
	aliceSigner := newSigner(t)
	alice := f.join(t, aliceSigner)
	bob := newSigner(t)
	id := newMessageID()
	good := ratchetCiphertext(200)
	plain := base64.RawURLEncoding.EncodeToString([]byte(`{"body":"` + strings.Repeat("hello ", 30) + `"}`))
	zeroVersion := []byte(strings.Repeat("\x00", MinCiphertext))
	env := func(ciphertext string) wireEnvelope { return wireEnvelope{bob.device.ID, ciphertext} }
	cases := map[string]struct {
		input []byte
		code  Code
	}{
		"short id":                {sendFrame(bob.identity, id[:21], env(good)), CodeInvalidPayload},
		"long id":                 {sendFrame(bob.identity, id+"A", env(good)), CodeInvalidPayload},
		"padded id":               {sendFrame(bob.identity, id+"==", env(good)), CodeInvalidPayload},
		"bad recipient":           {sendFrame("bad", id, env(good)), CodeInvalidPayload},
		"self":                    {sendFrame(aliceSigner.identity, id, wireEnvelope{aliceSigner.device.ID, good}), CodeInvalidPayload},
		"plaintext body":          {sendFrame(bob.identity, id, env(plain)), CodeInvalidPayload},
		"wrong version":           {sendFrame(bob.identity, id, env(base64.RawURLEncoding.EncodeToString(zeroVersion))), CodeInvalidPayload},
		"too short":               {sendFrame(bob.identity, id, env(ratchetCiphertext(MinCiphertext-1))), CodeInvalidPayload},
		"too long":                {sendFrame(bob.identity, id, env(ratchetCiphertext(MaxCiphertext+1))), CodeTooLarge},
		"huge":                    {sendFrame(bob.identity, id, env(strings.Repeat("A", 20000))), CodeTooLarge},
		"no envelopes":            {sendFrame(bob.identity, id), CodeInvalidPayload},
		"duplicate device":        {sendFrame(bob.identity, id, env(good), env(good)), CodeInvalidPayload},
		"too many envelopes":      {sendFrame(bob.identity, id, env(good), wireEnvelope{randomText(16), good}, wireEnvelope{randomText(16), good}, wireEnvelope{randomText(16), good}, wireEnvelope{randomText(16), good}), CodeInvalidPayload},
		"malformed device":        {sendFrame(bob.identity, id, wireEnvelope{"x", good}), CodeInvalidPayload},
		"unknown device":          {sendFrame(bob.identity, id, wireEnvelope{randomText(16), good}), CodeStaleDevices},
		"other identity's device": {sendFrame(bob.identity, id, wireEnvelope{aliceSigner.device.ID, good}), CodeStaleDevices},
		"unknown recipient":       {sendFrame(newSigner(t).identity, id, env(good)), CodeStaleDevices},
		"sender claim":            {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","envelopes":[` + mustJSON(env(good)) + `],"from":"` + bob.identity + `"}}`), CodeInvalidPayload},
		"sender device claim":     {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","envelopes":[{"device":"` + bob.device.ID + `","ciphertext":"` + good + `","from":"x"}]}}`), CodeInvalidPayload},
		"previous wire shape":     {[]byte(`{"type":"send","id":"s1","payload":{"to":"` + bob.identity + `","id":"` + id + `","ciphertext":"` + good + `"}}`), CodeInvalidPayload},
		"null payload":            {[]byte(`{"type":"send","id":"s1","payload":null}`), CodeInvalidPayload},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			expectCode(t, alice.conn.Handle(tc.input), tc.code)
			if n := f.queue.Queued(bob.address()); n != 0 {
				t.Fatalf("rejected request queued %d", n)
			}
		})
	}
	expectQueued(t, alice.conn.Handle(queueSend(bob, id, ratchetCiphertext(MinCiphertext))))
	expectQueued(t, alice.conn.Handle(queueSend(bob, newMessageID(), ratchetCiphertext(MaxCiphertext))))
	expectCode(t, alice.conn.Handle(queueSend(bob, id, good)), CodeDuplicate)
}

func TestSendRequiresAuthenticationAndAnAuthorizedDevice(t *testing.T) {
	f := newQueueFixture()
	bob := newSigner(t)
	conn, _, _ := f.open(t)
	expectCode(t, conn.Handle(queueSend(bob, newMessageID(), ratchetCiphertext(200))), CodeAuthRequired)
	expectCode(t, conn.Handle([]byte(`{"type":"fetch","id":"f1","payload":{}}`)), CodeAuthRequired)
	expectCode(t, conn.Handle(ackRequest(bob, newMessageID())), CodeAuthRequired)
	expectCode(t, conn.Handle(clearRequest(bob, newMessageID())), CodeAuthRequired)

	pair := newSiblings(t, 2)
	revoked := f.join(t, pair[1])
	if err := testDevices.Publish(pair[0].owner.Remove(pair[1].device)); err != nil {
		t.Fatal(err)
	}
	expectCode(t, revoked.conn.Handle(queueSend(bob, newMessageID(), ratchetCiphertext(200))), CodeStaleDevices)
	expectCode(t, revoked.conn.Handle([]byte(`{"type":"fetch","id":"f1","payload":{}}`)), CodeStaleDevices)
	if f.queue.Queued(bob.address()) != 0 {
		t.Fatal("revoked device queued a message")
	}
}

func TestQueueLimitIsReported(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newSigner(t))
	bob := newSigner(t)
	for range queue.MaxPerPair {
		expectQueued(t, alice.conn.Handle(queueSend(bob, newMessageID(), ratchetCiphertext(100))))
	}
	expectCode(t, alice.conn.Handle(queueSend(bob, newMessageID(), ratchetCiphertext(100))), CodeQueueFull)
}

func TestForgedAcknowledgmentsCannotDelete(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newSigner(t))
	bobPair := newSiblings(t, 2)
	bob := f.join(t, bobPair[0])
	bobSibling := f.join(t, bobPair[1])
	mallory := f.join(t, newSigner(t))
	alice.fetch(t)
	id := newMessageID()
	expectQueued(t, alice.conn.Handle(queueSend(bobPair[0], id, ratchetCiphertext(150))))

	expectCode(t, bob.conn.Handle(ackRequest(alice.signer, id)), CodeInvalidPayload)
	for name, out := range map[string][]byte{
		"sender":          alice.conn.Handle(ackRequest(alice.signer, id)),
		"sender as peer":  alice.conn.Handle(ackRequest(bobPair[0], id)),
		"third party":     mallory.conn.Handle(ackRequest(alice.signer, id)),
		"sibling device":  bobSibling.conn.Handle(ackRequest(alice.signer, id)),
		"third as sender": mallory.conn.Handle(ackRequest(bobPair[0], id)),
	} {
		resp := decodeResponse(t, out)
		if f.queue.Queued(bobPair[0].address()) != 1 {
			t.Fatalf("%s ack (%s) deleted the message", name, resp.Type)
		}
	}
	if got := alice.box.take(); len(got) != 0 {
		t.Fatalf("forged acks produced receipts %v", got)
	}
	bob.fetch(t)
	bob.box.take()
	decodeResponse(t, bob.conn.Handle(ackRequest(mallory.signer, id)))
	decodeResponse(t, bob.conn.Handle(ackRequest(alice.signer, newMessageID())))
	wrongDevice := fmt.Appendf(nil, `{"type":"ack","id":"a1","payload":{"from":%q,"device":%q,"id":%q}}`, alice.identity, bobPair[1].device.ID, id)
	decodeResponse(t, bob.conn.Handle(wrongDevice))
	if f.queue.Queued(bobPair[0].address()) != 1 {
		t.Fatal("mismatched ack deleted the message")
	}
	for _, bad := range [][]byte{
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `","id":"` + id + `"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `","device":"` + alice.device.ID + `"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `","device":"` + alice.device.ID + `","id":"` + id + `","to":"x"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"bad","device":"` + alice.device.ID + `","id":"` + id + `"}}`),
		[]byte(`{"type":"ack","id":"a1","payload":{"from":"` + alice.identity + `","device":"x","id":"` + id + `"}}`),
		[]byte(`{"type":"clear","id":"c1","payload":{"to":"` + bobPair[0].identity + `","device":"` + bobPair[0].device.ID + `","id":"` + id + `","status":"delivered"}}`),
		[]byte(`{"type":"fetch","id":"f1","payload":{"since":0}}`),
	} {
		expectCode(t, bob.conn.Handle(bad), CodeInvalidPayload)
	}
	if resp := decodeResponse(t, bob.conn.Handle(ackRequest(alice.signer, id))); resp.Type != "acked" || f.queue.Queued(bobPair[0].address()) != 0 {
		t.Fatalf("recipient ack = %+v", resp)
	}
}

func TestQueueErrorsDoNotLeakDetails(t *testing.T) {
	f := newQueueFixture()
	alice := f.join(t, newSigner(t))
	bob := newSigner(t)
	id := newMessageID()
	expectQueued(t, alice.conn.Handle(queueSend(bob, id, ratchetCiphertext(150))))
	for _, out := range [][]byte{
		alice.conn.Handle(queueSend(bob, id, ratchetCiphertext(150))),
		alice.conn.Handle(queueSend(newSigner(t), newMessageID(), ratchetCiphertext(150))),
		alice.conn.Handle(sendFrame(bob.identity, "x", wireEnvelope{"y", "z"})),
	} {
		for _, leak := range []string{"queue:", "identity:", "device:", "registry", "base64", "limit reached"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}

func FuzzSendPayload(f *testing.F) {
	alice := newSigner(f)
	bob := newSiblings(f, 2)
	id := randomText(MessageIDSize)
	good := ratchetCiphertext(120)
	env0 := `{"device":"` + bob[0].device.ID + `","ciphertext":"` + good + `"}`
	env1 := `{"device":"` + bob[1].device.ID + `","ciphertext":"` + good + `"}`
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","envelopes":[` + env0 + `]}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","envelopes":[` + env0 + `,` + env1 + `]}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","envelopes":[` + env0 + `,` + env0 + `]}`)
	f.Add(`{"to":"SENDER","id":"` + id + `","envelopes":[` + env0 + `]}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","envelopes":[{"device":"` + alice.device.ID + `","ciphertext":"` + good + `"}]}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","ciphertext":"` + good + `"}`)
	f.Add(`{"to":"RECIPIENT","id":"` + id + `","envelopes":[{"device":"` + bob[0].device.ID + `","ciphertext":"` + strings.Repeat("A", 6000) + `"}]}`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, payload string) {
		fx := newQueueFixture()
		sender := fx.join(t, alice)
		payload = strings.ReplaceAll(strings.ReplaceAll(payload, "RECIPIENT", bob[0].identity), "SENDER", alice.identity)
		out := sender.conn.Handle([]byte(`{"type":"send","id":"s1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		queued := fx.queue.Queued(bob[0].address()) + fx.queue.Queued(bob[1].address())
		if resp.Type != "queued" {
			if queued != 0 {
				t.Fatalf("rejected request queued %d", queued)
			}
			return
		}
		var sent struct {
			To        string
			ID        string
			Envelopes []wireEnvelope
		}
		if err := json.Unmarshal([]byte(payload), &sent); err != nil {
			t.Fatalf("accepted non-object %q", payload)
		}
		if queued != len(sent.Envelopes) || sent.To != bob[0].identity {
			t.Fatalf("queued %d for %d envelopes", queued, len(sent.Envelopes))
		}
		for _, e := range sent.Envelopes {
			raw, err := strict.DecodeString(e.Ciphertext)
			if err != nil || len(raw) < MinCiphertext || len(raw) > MaxCiphertext || raw[0] != RatchetVersion {
				t.Fatalf("accepted invalid ciphertext %q", payload)
			}
			target := bob[0]
			if e.Device == bob[1].device.ID {
				target = bob[1]
			} else if e.Device != bob[0].device.ID {
				t.Fatalf("accepted envelope for unauthorized device %q", payload)
			}
			recipient := fx.join(t, target)
			recipient.fetch(t)
			got := recipient.box.take()
			if len(got) != 1 || got[0] != pushedMessage(alice, sent.ID, e.Ciphertext) {
				t.Fatalf("delivery %v not bound to the authenticated sender device", got)
			}
		}
	})
}

func FuzzAckPayload(f *testing.F) {
	alice, bob, mallory := newSigner(f), newSigner(f), newSigner(f)
	f.Add(`{"from":"SENDER","device":"SDEVICE","id":"ID"}`, true)
	f.Add(`{"from":"SENDER","device":"SDEVICE","id":"ID"}`, false)
	f.Add(`{"from":"RECIPIENT","device":"RDEVICE","id":"ID"}`, true)
	f.Add(`{"from":"SENDER","device":"RDEVICE","id":"ID"}`, true)
	f.Add(`{"from":"SENDER","id":"ID"}`, true)
	f.Add(`[]`, false)

	f.Fuzz(func(t *testing.T, payload string, asRecipient bool) {
		fx := newQueueFixture()
		sender := fx.join(t, alice)
		recipient := fx.join(t, bob)
		attacker := fx.join(t, mallory)
		id := newMessageID()
		expectQueued(t, sender.conn.Handle(queueSend(bob, id, ratchetCiphertext(120))))
		recipient.fetch(t)
		recipient.box.take()
		payload = strings.NewReplacer("SENDER", alice.identity, "SDEVICE", alice.device.ID, "RECIPIENT", bob.identity, "RDEVICE", bob.device.ID, "ID", id).Replace(payload)
		actor := attacker
		if asRecipient {
			actor = recipient
		}
		out := actor.conn.Handle([]byte(`{"type":"ack","id":"a1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		remaining := fx.queue.Queued(bob.address())
		exact := asRecipient && payload == `{"from":"`+alice.identity+`","device":"`+alice.device.ID+`","id":"`+id+`"}`
		if remaining == 0 && !exact {
			t.Fatalf("payload %q from recipient=%v deleted the message", payload, asRecipient)
		}
		if exact && (remaining != 0 || resp.Type != "acked") {
			t.Fatalf("exact acknowledgment = %s, remaining %d", out, remaining)
		}
	})
}
