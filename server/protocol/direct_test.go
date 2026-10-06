package protocol

import (
	"crypto/ecdh"
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
	"github.com/Xhaann/ghost-x/server/identity"
)

type mailbox struct {
	mu       sync.Mutex
	messages []string
}

func (m *mailbox) deliver(msg direct.Message) bool {
	m.mu.Lock()
	m.messages = append(m.messages, string(EncodeMessage(msg)))
	m.mu.Unlock()
	return true
}

func (m *mailbox) all() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.messages...)
}

func (m *mailbox) take() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	taken := m.messages
	m.messages = nil
	return taken
}

type directFixture struct {
	router   *Router
	sessions *auth.Registry
	direct   *direct.Registry
}

func newDirectFixture() directFixture {
	d := direct.NewRegistry()
	return directFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"send":    Send(d),
			"publish": Publish(d),
			"key":     Key(d),
		}),
		sessions: auth.NewRegistry(time.Now, d),
		direct:   d,
	}
}

func (f directFixture) conn() (*Conn, *auth.Session, *mailbox) {
	session := f.sessions.Open()
	box := &mailbox{}
	f.direct.Attach(session, box.deliver)
	return f.router.Conn(session, discard), session, box
}

type party struct {
	signer
	key       string
	signature string
}

func mustIdentity(t testing.TB, encoded string) identity.Identity {
	t.Helper()
	id, err := identity.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newParty(t testing.TB) party {
	t.Helper()
	s := newSigner(t)
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := private.PublicKey().Bytes()
	return party{
		signer:    s,
		key:       base64.RawURLEncoding.EncodeToString(raw),
		signature: s.sign(KeyMessage(s.identity, raw)),
	}
}

func publishRequest(key, signature string) []byte {
	return fmt.Appendf(nil, `{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, key, signature)
}

func (f directFixture) ready(t *testing.T, p party) (*Conn, *auth.Session, *mailbox) {
	t.Helper()
	conn, session, box := f.conn()
	authenticated(t, conn, p.signer)
	if resp := decodeResponse(t, conn.Handle(publishRequest(p.key, p.signature))); resp.Type != "published" {
		t.Fatalf("publish = %+v %s", resp, resp.Payload)
	}
	return conn, session, box
}

type sealed struct {
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newEnvelope(ciphertextBytes int) sealed {
	return sealed{Salt: randomText(SaltSize), IV: randomText(IVSize), Ciphertext: randomText(ciphertextBytes)}
}

func sendRequest(id, to string, e sealed) []byte {
	payload, _ := json.Marshal(map[string]string{"to": to, "salt": e.Salt, "iv": e.IV, "ciphertext": e.Ciphertext})
	return fmt.Appendf(nil, `{"type":"send","id":%q,"payload":%s}`, id, payload)
}

func deliveredMessage(id string, from party, e sealed) string {
	return string(EncodeMessage(direct.Message{
		ID:       id,
		From:     from.identity,
		Sender:   direct.Bundle{Key: from.key, Signature: from.signature},
		Envelope: direct.Envelope{Salt: e.Salt, IV: e.IV, Ciphertext: e.Ciphertext},
	}))
}

func TestPublishBindsVerifiedKey(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	conn, _, _ := f.conn()
	authenticated(t, conn, a.signer)

	resp := decodeResponse(t, conn.Handle(publishRequest(a.key, a.signature)))
	if resp.Type != "published" || resp.ID != "k1" || string(resp.Payload) != `{}` {
		t.Fatalf("response = %+v %s", resp, resp.Payload)
	}
	if b, ok := f.direct.Bundle(mustIdentity(t, a.identity)); !ok || b.Key != a.key || b.Signature != a.signature {
		t.Fatalf("bundle = %+v %v", b, ok)
	}
}

func TestPublishRejectsUnboundKeys(t *testing.T) {
	a, b := newParty(t), newParty(t)
	raw, _ := base64.RawURLEncoding.DecodeString(a.key)

	tests := map[string][]byte{
		"signed by other identity":  publishRequest(a.key, b.signer.sign(KeyMessage(a.identity, raw))),
		"other identity in message": publishRequest(a.key, a.signer.sign(KeyMessage(b.identity, raw))),
		"key not covered":           publishRequest(b.key, a.signature),
		"wrong context":             publishRequest(a.key, a.signer.sign(append([]byte("ghostx/encryption/key/v2\x00"+a.identity), raw...))),
		"auth proof context":        publishRequest(a.key, a.signer.sign(auth.Message(raw))),
		"malformed signature":       publishRequest(a.key, "x"),
		"short key":                 publishRequest(a.key[:42], a.signature),
		"long key":                  publishRequest(a.key+"A", a.signature),
		"padded key":                publishRequest(a.key+"=", a.signature),
		"non-canonical key":         publishRequest(a.key[:42]+"B", a.signature),
		"missing signature":         []byte(`{"type":"publish","id":"k1","payload":{"key":"` + a.key + `"}}`),
		"extra field":               []byte(`{"type":"publish","id":"k1","payload":{"key":"` + a.key + `","signature":"` + a.signature + `","private":"x"}}`),
		"numeric key":               []byte(`{"type":"publish","id":"k1","payload":{"key":1,"signature":"` + a.signature + `"}}`),
		"null payload":              []byte(`{"type":"publish","id":"k1","payload":null}`),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			f := newDirectFixture()
			conn, _, _ := f.conn()
			authenticated(t, conn, a.signer)
			expectCode(t, conn.Handle(input), CodeInvalidPayload)
			if _, ok := f.direct.Bundle(mustIdentity(t, a.identity)); ok {
				t.Fatal("unbound key was published")
			}
		})
	}
}

func TestPublishRequiresAuthentication(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	conn, _, _ := f.conn()
	expectCode(t, conn.Handle(publishRequest(a.key, a.signature)), CodeAuthRequired)
}

func TestPublishConflictRejected(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	f.ready(t, a)
	second, _, _ := f.conn()
	authenticated(t, second, a.signer)

	other := newParty(t)
	raw, _ := base64.RawURLEncoding.DecodeString(other.key)
	expectCode(t, second.Handle(publishRequest(other.key, a.signer.sign(KeyMessage(a.identity, raw)))), CodeInvalidPayload)
	if resp := decodeResponse(t, second.Handle(publishRequest(a.key, a.signature))); resp.Type != "published" {
		t.Fatalf("matching publish = %+v", resp)
	}
}

func TestKeyLookup(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	conn, _, _ := f.ready(t, a)
	f.ready(t, b)

	resp := decodeResponse(t, conn.Handle([]byte(`{"type":"key","id":"q1","payload":{"identity":"`+b.identity+`"}}`)))
	want := `{"identity":"` + b.identity + `","key":"` + b.key + `","signature":"` + b.signature + `"}`
	if resp.Type != "key" || resp.ID != "q1" || string(resp.Payload) != want {
		t.Fatalf("key = %+v %s", resp, resp.Payload)
	}

	expectCode(t, conn.Handle([]byte(`{"type":"key","id":"q2","payload":{"identity":"`+newParty(t).identity+`"}}`)), CodeUnavailable)
	expectCode(t, conn.Handle([]byte(`{"type":"key","id":"q3","payload":{"identity":"bad"}}`)), CodeInvalidPayload)
	expectCode(t, conn.Handle([]byte(`{"type":"key","id":"q4","payload":{"identity":"`+b.identity+`","x":1}}`)), CodeInvalidPayload)

	unauthenticated, _, _ := f.conn()
	expectCode(t, unauthenticated.Handle([]byte(`{"type":"key","id":"q5","payload":{"identity":"`+b.identity+`"}}`)), CodeAuthRequired)
}

func TestSendRoutesCiphertextUnchanged(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, _, senderBox := f.ready(t, a)
	_, _, box := f.ready(t, b)
	e := newEnvelope(64)

	resp := decodeResponse(t, sender.Handle(sendRequest("m1", b.identity, e)))

	if resp.Type != "sent" || resp.ID != "m1" || string(resp.Payload) != `{}` {
		t.Fatalf("response = %+v %s", resp, resp.Payload)
	}
	if got := box.all(); len(got) != 1 || got[0] != deliveredMessage("m1", a, e) {
		t.Fatalf("delivered %v", got)
	}
	if len(senderBox.all()) != 0 {
		t.Fatal("sender received its own message")
	}
}

func TestEncodedMessageHasOnlyEnvelopeFields(t *testing.T) {
	a := newParty(t)
	e := newEnvelope(32)
	var decoded struct {
		Type    string            `json:"type"`
		Payload map[string]string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(deliveredMessage("m1", a, e)), &decoded); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(decoded.Payload))
	for k := range decoded.Payload {
		keys = append(keys, k)
	}
	if decoded.Type != "message" || len(decoded.Payload) != 7 || decoded.Payload["body"] != "" {
		t.Fatalf("payload keys = %v", keys)
	}
	for _, k := range []string{"id", "from", "key", "signature", "salt", "iv", "ciphertext"} {
		if _, ok := decoded.Payload[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
}

func TestSendRejectsPlaintext(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, _, _ := f.ready(t, a)
	_, _, box := f.ready(t, b)
	e := newEnvelope(32)

	for _, input := range []string{
		`{"type":"send","id":"p1","payload":{"to":"` + b.identity + `","body":"plaintext"}}`,
		`{"type":"send","id":"p2","payload":{"to":"` + b.identity + `","body":"plaintext","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`,
		`{"type":"send","id":"p3","payload":{"to":"` + b.identity + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","plaintext":"x"}}`,
	} {
		expectCode(t, sender.Handle([]byte(input)), CodeInvalidPayload)
	}
	if len(box.all()) != 0 {
		t.Fatalf("plaintext delivered: %v", box.all())
	}
}

func TestSendValidation(t *testing.T) {
	f := newDirectFixture()
	a, b, c := newParty(t), newParty(t), newParty(t)
	sender, _, _ := f.ready(t, a)
	_, _, box := f.ready(t, b)
	to := b.identity
	e := newEnvelope(32)
	with := func(mutate func(*sealed)) []byte {
		copy := e
		mutate(&copy)
		return sendRequest("m1", to, copy)
	}

	tests := map[string]struct {
		input []byte
		code  Code
	}{
		"missing payload":          {[]byte(`{"type":"send","id":"m1"}`), CodeInvalidPayload},
		"missing ciphertext":       {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","salt":"` + e.Salt + `","iv":"` + e.IV + `"}}`), CodeInvalidPayload},
		"missing salt":             {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`), CodeInvalidPayload},
		"missing to":               {[]byte(`{"type":"send","id":"m1","payload":{"salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`), CodeInvalidPayload},
		"forged sender":            {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","from":"` + c.identity + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`), CodeInvalidPayload},
		"forged sender key":        {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","key":"` + c.key + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`), CodeInvalidPayload},
		"duplicate ciphertext":     {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `","ciphertext":"` + e.Ciphertext + `"}}`), CodeInvalidPayload},
		"short salt":               {with(func(x *sealed) { x.Salt = randomText(SaltSize - 1) }), CodeInvalidPayload},
		"long salt":                {with(func(x *sealed) { x.Salt = randomText(SaltSize + 1) }), CodeInvalidPayload},
		"short iv":                 {with(func(x *sealed) { x.IV = randomText(IVSize - 1) }), CodeInvalidPayload},
		"long iv":                  {with(func(x *sealed) { x.IV = randomText(IVSize + 1) }), CodeInvalidPayload},
		"padded iv":                {with(func(x *sealed) { x.IV += "=" }), CodeInvalidPayload},
		"standard alphabet salt":   {with(func(x *sealed) { x.Salt = "+" + x.Salt[1:] }), CodeInvalidPayload},
		"non-canonical salt":       {with(func(x *sealed) { x.Salt = x.Salt[:42] + "B" }), CodeInvalidPayload},
		"empty ciphertext":         {with(func(x *sealed) { x.Ciphertext = "" }), CodeInvalidPayload},
		"tag-only ciphertext":      {with(func(x *sealed) { x.Ciphertext = randomText(TagSize) }), CodeInvalidPayload},
		"invalid ciphertext chars": {with(func(x *sealed) { x.Ciphertext = "***" + x.Ciphertext }), CodeInvalidPayload},
		"padded ciphertext":        {with(func(x *sealed) { x.Ciphertext = randomText(31) + "=" }), CodeInvalidPayload},
		"oversized ciphertext":     {with(func(x *sealed) { x.Ciphertext = randomText(MaxCiphertext + 1) }), CodeTooLarge},
		"oversized raw ciphertext": {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + strings.Repeat(`A`, 6000) + `"}}`), CodeTooLarge},
		"numeric ciphertext":       {[]byte(`{"type":"send","id":"m1","payload":{"to":"` + to + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":1}}`), CodeInvalidPayload},
		"invalid recipient":        {sendRequest("m1", "bad", e), CodeInvalidPayload},
		"invalid message id":       {[]byte(`{"type":"send","id":"bad id","payload":{}}`), CodeInvalidMessage},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			expectCode(t, sender.Handle(tt.input), tt.code)
		})
	}
	if len(box.all()) != 0 {
		t.Fatalf("invalid requests delivered %v", box.all())
	}
}

func TestSendCiphertextBoundaries(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, _, _ := f.ready(t, a)
	_, _, box := f.ready(t, b)

	for i, n := range []int{MinCiphertext, MaxCiphertext} {
		e := newEnvelope(n)
		if resp := decodeResponse(t, sender.Handle(sendRequest(fmt.Sprintf("b%d", i), b.identity, e))); resp.Type != "sent" {
			t.Fatalf("%d-byte ciphertext rejected: %+v %s", n, resp, resp.Payload)
		}
	}
	if len(box.all()) != 2 {
		t.Fatalf("delivered %d, want 2", len(box.all()))
	}
}

func TestSendRequiresPublishedKey(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, _, _ := f.conn()
	authenticated(t, sender, a.signer)
	_, _, box := f.ready(t, b)

	expectCode(t, sender.Handle(sendRequest("m1", b.identity, newEnvelope(32))), CodeKeyRequired)
	if len(box.all()) != 0 {
		t.Fatal("unkeyed sender delivered")
	}
}

func TestSendRejectsDuplicateMessageID(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, _, _ := f.ready(t, a)
	_, _, box := f.ready(t, b)
	e := newEnvelope(32)

	if resp := decodeResponse(t, sender.Handle(sendRequest("m1", b.identity, e))); resp.Type != "sent" {
		t.Fatal(resp)
	}
	expectCode(t, sender.Handle(sendRequest("m1", b.identity, e)), CodeDuplicate)
	if len(box.all()) != 1 {
		t.Fatalf("replay delivered %d copies", len(box.all()))
	}
}

func TestSendRequiresAuthentication(t *testing.T) {
	f := newDirectFixture()
	b := newParty(t)
	_, _, box := f.ready(t, b)
	conn, _, _ := f.conn()

	expectCode(t, conn.Handle(sendRequest("m1", b.identity, newEnvelope(32))), CodeAuthRequired)
	requestChallenge(t, conn)
	expectCode(t, conn.Handle(sendRequest("m2", b.identity, newEnvelope(32))), CodeAuthRequired)
	if len(box.all()) != 0 {
		t.Fatal("unauthenticated send delivered")
	}
}

func TestSendUnavailableAndClosedSender(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, session, _ := f.ready(t, a)

	expectCode(t, sender.Handle(sendRequest("m1", b.identity, newEnvelope(32))), CodeUnavailable)

	session.Close()
	expectCode(t, sender.Handle(sendRequest("m2", b.identity, newEnvelope(32))), CodeAuthRequired)
}

func TestDeliveredMessageCarriesSenderRequestID(t *testing.T) {
	f := newDirectFixture()
	a, b, c := newParty(t), newParty(t), newParty(t)
	senderA, _, _ := f.ready(t, a)
	senderC, _, _ := f.ready(t, c)
	_, _, box := f.ready(t, b)
	e1, e2, e3 := newEnvelope(20), newEnvelope(21), newEnvelope(22)

	senderA.Handle(sendRequest("a1", b.identity, e1))
	senderC.Handle(sendRequest("c1", b.identity, e2))
	senderA.Handle([]byte(`{"type":"ping","id":"p9","payload":{"sentAt":1}}`))
	senderA.Handle(sendRequest("a2", b.identity, e3))

	want := []string{deliveredMessage("a1", a, e1), deliveredMessage("c1", c, e2), deliveredMessage("a2", a, e3)}
	if got := box.all(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("delivered %v, want %v", got, want)
	}
}

func TestSendErrorsDoNotLeakDetails(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender, _, _ := f.ready(t, a)
	for _, out := range [][]byte{
		sender.Handle(sendRequest("m1", b.identity, newEnvelope(32))),
		sender.Handle(sendRequest("m2", "bad", newEnvelope(32))),
		sender.Handle(publishRequest("x", "y")),
	} {
		for _, leak := range []string{"direct:", "identity:", "session", "registry", "base64"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}

func FuzzSendPayload(f *testing.F) {
	a := newParty(f)
	recipient := newParty(f)
	e := newEnvelope(32)
	f.Add(`{"to":"RECIPIENT","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}`)
	f.Add(`{"to":"RECIPIENT","body":"plaintext"}`)
	f.Add(`{"to":"RECIPIENT","salt":"","iv":"","ciphertext":""}`)
	f.Add(`{"to":"RECIPIENT","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `","from":"x"}`)
	f.Add(`null`)

	fx := newDirectFixture()
	receiverSession := fx.sessions.Open()
	box := &mailbox{}
	fx.direct.Attach(receiverSession, box.deliver)
	nonce, err := receiverSession.Challenge()
	if err != nil {
		f.Fatal(err)
	}
	if _, err := receiverSession.Authenticate(recipient.identity, recipient.sign(auth.Message(nonce))); err != nil {
		f.Fatal(err)
	}
	if err := fx.direct.Publish(receiverSession, direct.Bundle{Key: recipient.key, Signature: recipient.signature}); err != nil {
		f.Fatal(err)
	}
	defer receiverSession.Close()

	f.Fuzz(func(t *testing.T, payload string) {
		sender, session, _ := fx.conn()
		defer fx.direct.Detach(session)
		defer session.Close()
		authenticated(t, sender, a.signer)
		if resp := decodeResponse(t, sender.Handle(publishRequest(a.key, a.signature))); resp.Type != "published" {
			t.Fatalf("publish = %+v", resp)
		}
		box.take()
		payload = strings.ReplaceAll(payload, "RECIPIENT", recipient.identity)
		out := sender.Handle([]byte(`{"type":"send","id":"m1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		delivered := box.take()
		if resp.Type == "sent" {
			if len(delivered) != 1 || !strings.Contains(delivered[0], `"from":"`+a.identity+`"`) || strings.Contains(delivered[0], `"body"`) {
				t.Fatalf("sent without exactly one sealed delivery from session identity: %v", delivered)
			}
		} else if len(delivered) != 0 {
			t.Fatalf("rejected request delivered %v", delivered)
		}
	})
}
