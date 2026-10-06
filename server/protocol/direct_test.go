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
			"session": Establish(d),
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
	keyRaw    []byte
	signature string
}

type wireSession struct {
	Session   string `json:"session"`
	Epoch     uint32 `json:"epoch"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type wireEnvelope struct {
	Session    string `json:"session"`
	Epoch      uint32 `json:"epoch"`
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func mustIdentity(t testing.TB, encoded string) identity.Identity {
	t.Helper()
	id, err := identity.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func exchangeRaw(t testing.TB) []byte {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private.PublicKey().Bytes()
}

func newParty(t testing.TB) party {
	t.Helper()
	s := newSigner(t)
	raw := exchangeRaw(t)
	return party{
		signer:    s,
		key:       base64.RawURLEncoding.EncodeToString(raw),
		keyRaw:    raw,
		signature: s.sign(KeyMessage(s.identity, raw)),
	}
}

func decoded(text string) []byte {
	raw, _ := base64.RawURLEncoding.DecodeString(text)
	return raw
}

func (p party) session(t testing.TB, id string, epoch uint32) wireSession {
	t.Helper()
	key := exchangeRaw(t)
	return wireSession{
		Session:   id,
		Epoch:     epoch,
		Key:       base64.RawURLEncoding.EncodeToString(key),
		Signature: p.sign(SessionMessage(decoded(p.identity), p.keyRaw, decoded(id), epoch, key)),
	}
}

func publishRequest(key, signature string) []byte {
	return fmt.Appendf(nil, `{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, key, signature)
}

func sessionRequest(id string, s wireSession) []byte {
	payload, _ := json.Marshal(s)
	return fmt.Appendf(nil, `{"type":"session","id":%q,"payload":%s}`, id, payload)
}

func sendRequest(id, to string, epoch uint32, envelopes ...wireEnvelope) []byte {
	payload, _ := json.Marshal(map[string]any{"to": to, "epoch": epoch, "envelopes": envelopes})
	return fmt.Appendf(nil, `{"type":"send","id":%q,"payload":%s}`, id, payload)
}

type peer struct {
	conn    *Conn
	session *auth.Session
	box     *mailbox
	keys    wireSession
}

func (f directFixture) published(t *testing.T, p party) (*Conn, *auth.Session, *mailbox) {
	t.Helper()
	conn, session, box := f.conn()
	authenticated(t, conn, p.signer)
	if resp := decodeResponse(t, conn.Handle(publishRequest(p.key, p.signature))); resp.Type != "published" {
		t.Fatalf("publish = %+v %s", resp, resp.Payload)
	}
	return conn, session, box
}

func (f directFixture) ready(t *testing.T, p party) peer {
	t.Helper()
	conn, session, box := f.published(t, p)
	keys := p.session(t, randomText(SessionIDSize), 0)
	if resp := decodeResponse(t, conn.Handle(sessionRequest("s0", keys))); resp.Type != "established" {
		t.Fatalf("session = %+v %s", resp, resp.Payload)
	}
	return peer{conn: conn, session: session, box: box, keys: keys}
}

func (pr *peer) rotate(t *testing.T, p party) {
	t.Helper()
	next := p.session(t, pr.keys.Session, pr.keys.Epoch+1)
	if resp := decodeResponse(t, pr.conn.Handle(sessionRequest(fmt.Sprintf("r%d", next.Epoch), next))); resp.Type != "established" {
		t.Fatalf("rotate = %+v %s", resp, resp.Payload)
	}
	pr.keys = next
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func envelopeFor(s wireSession, ciphertextBytes int) wireEnvelope {
	return wireEnvelope{
		Session:    s.Session,
		Epoch:      s.Epoch,
		Salt:       randomText(SaltSize),
		IV:         randomText(IVSize),
		Ciphertext: randomText(ciphertextBytes),
	}
}

func deliveredMessage(id string, from party, sender wireSession, e wireEnvelope) string {
	return string(EncodeMessage(direct.Message{
		ID:       id,
		From:     from.identity,
		Sender:   direct.Bundle{Key: from.key, Signature: from.signature},
		Session:  direct.SessionBundle{ID: sender.Session, Epoch: sender.Epoch, Key: sender.Key, Signature: sender.Signature},
		Envelope: direct.Envelope{Session: e.Session, Epoch: e.Epoch, Salt: e.Salt, IV: e.IV, Ciphertext: e.Ciphertext},
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
	high := append([]byte(nil), a.keyRaw...)
	high[31] |= 0x80
	highKey := base64.RawURLEncoding.EncodeToString(high)

	tests := map[string][]byte{
		"signed by other identity":  publishRequest(a.key, b.signer.sign(KeyMessage(a.identity, a.keyRaw))),
		"other identity in message": publishRequest(a.key, a.signer.sign(KeyMessage(b.identity, a.keyRaw))),
		"key not covered":           publishRequest(b.key, a.signature),
		"wrong context":             publishRequest(a.key, a.signer.sign(append([]byte("ghostx/encryption/key/v2\x00"+a.identity), a.keyRaw...))),
		"auth proof context":        publishRequest(a.key, a.signer.sign(auth.Message(a.keyRaw))),
		"non-canonical point":       publishRequest(highKey, a.signer.sign(KeyMessage(a.identity, high))),
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
	expectCode(t, second.Handle(publishRequest(other.key, a.signer.sign(KeyMessage(a.identity, other.keyRaw)))), CodeInvalidPayload)
	if resp := decodeResponse(t, second.Handle(publishRequest(a.key, a.signature))); resp.Type != "published" {
		t.Fatalf("matching publish = %+v", resp)
	}
}

func TestEstablishBindsSignedSessionKey(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	conn, _, _ := f.published(t, a)
	keys := a.session(t, randomText(SessionIDSize), 0)

	resp := decodeResponse(t, conn.Handle(sessionRequest("s1", keys)))
	if resp.Type != "established" || resp.ID != "s1" || string(resp.Payload) != `{}` {
		t.Fatalf("response = %+v %s", resp, resp.Payload)
	}
	_, sessions, _ := f.direct.Lookup(mustIdentity(t, a.identity))
	if len(sessions) != 1 || sessions[0] != (direct.SessionBundle{ID: keys.Session, Epoch: 0, Key: keys.Key, Signature: keys.Signature}) {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestEstablishRejectsUnboundSessionKeys(t *testing.T) {
	a, b := newParty(t), newParty(t)
	id := randomText(SessionIDSize)
	key := exchangeRaw(t)
	keyText := base64.RawURLEncoding.EncodeToString(key)
	idRaw := decoded(id)
	owner := decoded(a.identity)
	valid := func(signature string) wireSession {
		return wireSession{Session: id, Epoch: 0, Key: keyText, Signature: signature}
	}
	high := append([]byte(nil), key...)
	high[31] |= 0x80
	raw := func(payload string) []byte {
		return []byte(`{"type":"session","id":"s1","payload":` + payload + `}`)
	}
	good := a.sign(SessionMessage(owner, a.keyRaw, idRaw, 0, key))

	tests := map[string][]byte{
		"signed by other identity":     sessionRequest("s1", valid(b.sign(SessionMessage(owner, a.keyRaw, idRaw, 0, key)))),
		"other identity in transcript": sessionRequest("s1", valid(a.sign(SessionMessage(decoded(b.identity), a.keyRaw, idRaw, 0, key)))),
		"other static key":             sessionRequest("s1", valid(a.sign(SessionMessage(owner, b.keyRaw, idRaw, 0, key)))),
		"other session id":             sessionRequest("s1", valid(a.sign(SessionMessage(owner, a.keyRaw, decoded(randomText(SessionIDSize)), 0, key)))),
		"other epoch":                  sessionRequest("s1", valid(a.sign(SessionMessage(owner, a.keyRaw, idRaw, 1, key)))),
		"other ephemeral key":          sessionRequest("s1", valid(a.sign(SessionMessage(owner, a.keyRaw, idRaw, 0, exchangeRaw(t))))),
		"static binding reused":        sessionRequest("s1", valid(a.signature)),
		"wrong context":                sessionRequest("s1", valid(a.sign(append([]byte("ghostx/session/v2\x00"), SessionMessage(owner, a.keyRaw, idRaw, 0, key)[len("ghostx/session/v1\x00"):]...)))),
		"static key as session key":    sessionRequest("s1", wireSession{Session: id, Epoch: 0, Key: a.key, Signature: good}),
		"non-canonical point":          sessionRequest("s1", wireSession{Session: id, Epoch: 0, Key: base64.RawURLEncoding.EncodeToString(high), Signature: a.sign(SessionMessage(owner, a.keyRaw, idRaw, 0, high))}),
		"malformed signature":          sessionRequest("s1", valid("x")),
		"short session id":             raw(`{"session":"` + randomText(15) + `","epoch":0,"key":"` + keyText + `","signature":"` + good + `"}`),
		"long session id":              raw(`{"session":"` + randomText(17) + `","epoch":0,"key":"` + keyText + `","signature":"` + good + `"}`),
		"padded session id":            raw(`{"session":"` + id + `==","epoch":0,"key":"` + keyText + `","signature":"` + good + `"}`),
		"negative epoch":               raw(`{"session":"` + id + `","epoch":-1,"key":"` + keyText + `","signature":"` + good + `"}`),
		"fractional epoch":             raw(`{"session":"` + id + `","epoch":0.0,"key":"` + keyText + `","signature":"` + good + `"}`),
		"exponent epoch":               raw(`{"session":"` + id + `","epoch":0e0,"key":"` + keyText + `","signature":"` + good + `"}`),
		"string epoch":                 raw(`{"session":"` + id + `","epoch":"0","key":"` + keyText + `","signature":"` + good + `"}`),
		"null epoch":                   raw(`{"session":"` + id + `","epoch":null,"key":"` + keyText + `","signature":"` + good + `"}`),
		"oversized epoch":              raw(`{"session":"` + id + `","epoch":2147483648,"key":"` + keyText + `","signature":"` + good + `"}`),
		"huge epoch":                   raw(`{"session":"` + id + `","epoch":99999999999999999999,"key":"` + keyText + `","signature":"` + good + `"}`),
		"short key":                    raw(`{"session":"` + id + `","epoch":0,"key":"` + keyText[:42] + `","signature":"` + good + `"}`),
		"missing key":                  raw(`{"session":"` + id + `","epoch":0,"signature":"` + good + `"}`),
		"extra field":                  raw(`{"session":"` + id + `","epoch":0,"key":"` + keyText + `","signature":"` + good + `","private":"x"}`),
		"duplicate field":              raw(`{"session":"` + id + `","epoch":0,"epoch":0,"key":"` + keyText + `","signature":"` + good + `"}`),
		"null payload":                 raw(`null`),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			f := newDirectFixture()
			conn, _, _ := f.published(t, a)
			expectCode(t, conn.Handle(input), CodeInvalidPayload)
			if _, sessions, _ := f.direct.Lookup(mustIdentity(t, a.identity)); len(sessions) != 0 {
				t.Fatal("unbound session key accepted")
			}
		})
	}
	f := newDirectFixture()
	conn, _, _ := f.published(t, a)
	expectCode(t, conn.Handle(raw(`{"session":"`+id+`","epoch":00,"key":"`+keyText+`","signature":"`+good+`"}`)), CodeInvalidMessage)
	if resp := decodeResponse(t, conn.Handle(sessionRequest("s1", valid(good)))); resp.Type != "established" {
		t.Fatalf("control = %+v %s", resp, resp.Payload)
	}
}

func TestEstablishRequiresAuthenticationAndStaticKey(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	keys := a.session(t, randomText(SessionIDSize), 0)
	conn, _, _ := f.conn()
	expectCode(t, conn.Handle(sessionRequest("s1", keys)), CodeAuthRequired)
	authenticated(t, conn, a.signer)
	expectCode(t, conn.Handle(sessionRequest("s2", keys)), CodeKeyRequired)
}

func TestEstablishEpochRules(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	conn, _, _ := f.published(t, a)
	id := randomText(SessionIDSize)

	expectCode(t, conn.Handle(sessionRequest("e1", a.session(t, id, 1))), CodeStaleSession)
	if resp := decodeResponse(t, conn.Handle(sessionRequest("e2", a.session(t, id, 0)))); resp.Type != "established" {
		t.Fatal(resp)
	}
	expectCode(t, conn.Handle(sessionRequest("e3", a.session(t, id, 0))), CodeStaleSession)
	expectCode(t, conn.Handle(sessionRequest("e4", a.session(t, id, 2))), CodeStaleSession)
	expectCode(t, conn.Handle(sessionRequest("e5", a.session(t, randomText(SessionIDSize), 1))), CodeStaleSession)
	if resp := decodeResponse(t, conn.Handle(sessionRequest("e6", a.session(t, id, 1)))); resp.Type != "established" {
		t.Fatal(resp)
	}

	duplicate, _, _ := f.published(t, a)
	expectCode(t, duplicate.Handle(sessionRequest("d1", a.session(t, id, 0))), CodeStaleSession)
	for range direct.MaxSessions - 1 {
		f.ready(t, a)
	}
	expectCode(t, duplicate.Handle(sessionRequest("d2", a.session(t, randomText(SessionIDSize), 0))), CodeSessionLimit)
}

func TestKeyLookupListsSessions(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	asker := f.ready(t, a)
	f.published(t, b)

	resp := decodeResponse(t, asker.conn.Handle([]byte(`{"type":"key","id":"q1","payload":{"identity":"`+b.identity+`"}}`)))
	want := `{"identity":"` + b.identity + `","key":"` + b.key + `","signature":"` + b.signature + `","sessions":[]}`
	if resp.Type != "key" || resp.ID != "q1" || string(resp.Payload) != want {
		t.Fatalf("key = %+v %s", resp, resp.Payload)
	}
	b1 := f.ready(t, b)
	b1.rotate(t, b)
	resp = decodeResponse(t, asker.conn.Handle([]byte(`{"type":"key","id":"q2","payload":{"identity":"`+b.identity+`"}}`)))
	session, _ := json.Marshal([]wireSession{b1.keys})
	want = `{"identity":"` + b.identity + `","key":"` + b.key + `","signature":"` + b.signature + `","sessions":` + string(session) + `}`
	if string(resp.Payload) != want {
		t.Fatalf("key = %s, want %s", resp.Payload, want)
	}

	expectCode(t, asker.conn.Handle([]byte(`{"type":"key","id":"q3","payload":{"identity":"`+newParty(t).identity+`"}}`)), CodeUnavailable)
	expectCode(t, asker.conn.Handle([]byte(`{"type":"key","id":"q4","payload":{"identity":"bad"}}`)), CodeInvalidPayload)
	expectCode(t, asker.conn.Handle([]byte(`{"type":"key","id":"q5","payload":{"identity":"`+b.identity+`","x":1}}`)), CodeInvalidPayload)
	unauthenticated, _, _ := f.conn()
	expectCode(t, unauthenticated.Handle([]byte(`{"type":"key","id":"q6","payload":{"identity":"`+b.identity+`"}}`)), CodeAuthRequired)
}

func TestSendRoutesEnvelopeUnchanged(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	recipient := f.ready(t, b)
	e := envelopeFor(recipient.keys, 64)

	resp := decodeResponse(t, sender.conn.Handle(sendRequest("m1", b.identity, 0, e)))
	if resp.Type != "sent" || resp.ID != "m1" || string(resp.Payload) != `{}` {
		t.Fatalf("response = %+v %s", resp, resp.Payload)
	}
	if got := recipient.box.all(); len(got) != 1 || got[0] != deliveredMessage("m1", a, sender.keys, e) {
		t.Fatalf("delivered %v", got)
	}
	if len(sender.box.all()) != 0 {
		t.Fatal("sender received its own message")
	}
}

func TestEncodedMessageShape(t *testing.T) {
	a := newParty(t)
	s := a.session(t, randomText(SessionIDSize), 3)
	e := envelopeFor(a.session(t, randomText(SessionIDSize), 7), 32)
	var payload map[string]json.RawMessage
	var outer struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal([]byte(deliveredMessage("m1", a, s, e)), &outer); err != nil || outer.Type != "message" {
		t.Fatal(err)
	}
	json.Unmarshal(outer.Payload, &payload)
	want := `{"id":"m1","from":"` + a.identity + `","key":"` + a.key + `","signature":"` + a.signature +
		`","sender":{"session":"` + s.Session + `","epoch":3,"key":"` + s.Key + `","signature":"` + s.Signature +
		`"},"envelope":{"session":"` + e.Session + `","epoch":7,"salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`
	if string(outer.Payload) != want || len(payload) != 6 {
		t.Fatalf("payload = %s", outer.Payload)
	}
}

func TestSendRejectsPlaintextAndStaticKeyFormat(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	recipient := f.ready(t, b)
	e := envelopeFor(recipient.keys, 32)
	envJSON, _ := json.Marshal(e)

	for _, input := range []string{
		`{"type":"send","id":"p1","payload":{"to":"` + b.identity + `","body":"plaintext"}}`,
		`{"type":"send","id":"p2","payload":{"to":"` + b.identity + `","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}}`,
		`{"type":"send","id":"p3","payload":{"to":"` + b.identity + `","epoch":0,"envelopes":[],"body":"plaintext"}}`,
		`{"type":"send","id":"p4","payload":{"to":"` + b.identity + `","epoch":0,"envelopes":[{"session":"` + e.Session + `","epoch":0,"body":"plaintext"}]}}`,
		`{"type":"send","id":"p5","payload":{"to":"` + b.identity + `","epoch":0,"envelopes":[` + string(envJSON) + `],"body":"plaintext"}}`,
	} {
		expectCode(t, sender.conn.Handle([]byte(input)), CodeInvalidPayload)
	}
	if len(recipient.box.all()) != 0 {
		t.Fatalf("plaintext delivered: %v", recipient.box.all())
	}
}

func TestSendValidation(t *testing.T) {
	f := newDirectFixture()
	a, b, c := newParty(t), newParty(t), newParty(t)
	sender := f.ready(t, a)
	recipient := f.ready(t, b)
	to := b.identity
	e := envelopeFor(recipient.keys, 32)
	with := func(mutate func(*wireEnvelope)) []byte {
		copy := e
		mutate(&copy)
		return sendRequest("m1", to, 0, copy)
	}
	envelopeJSON, _ := json.Marshal(e)
	raw := func(payload string) []byte {
		return []byte(`{"type":"send","id":"m1","payload":` + payload + `}`)
	}
	env := string(envelopeJSON)

	tests := map[string]struct {
		input []byte
		code  Code
	}{
		"missing payload":          {[]byte(`{"type":"send","id":"m1"}`), CodeInvalidPayload},
		"missing envelopes":        {raw(`{"to":"` + to + `","epoch":0}`), CodeInvalidPayload},
		"missing epoch":            {raw(`{"to":"` + to + `","envelopes":[` + env + `]}`), CodeInvalidPayload},
		"missing to":               {raw(`{"epoch":0,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"empty envelopes":          {raw(`{"to":"` + to + `","epoch":0,"envelopes":[]}`), CodeInvalidPayload},
		"envelope object":          {raw(`{"to":"` + to + `","epoch":0,"envelopes":` + env + `}`), CodeInvalidPayload},
		"null envelopes":           {raw(`{"to":"` + to + `","epoch":0,"envelopes":null}`), CodeInvalidPayload},
		"too many envelopes":       {sendRequest("m1", to, 0, e, envelopeFor(c.session(t, randomText(SessionIDSize), 0), 32), envelopeFor(c.session(t, randomText(SessionIDSize), 0), 32), envelopeFor(c.session(t, randomText(SessionIDSize), 0), 32), envelopeFor(c.session(t, randomText(SessionIDSize), 0), 32)), CodeInvalidPayload},
		"duplicate session":        {sendRequest("m1", to, 0, e, e), CodeInvalidPayload},
		"forged sender":            {raw(`{"to":"` + to + `","from":"` + c.identity + `","epoch":0,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"forged sender key":        {raw(`{"to":"` + to + `","key":"` + c.key + `","epoch":0,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"forged sender session":    {raw(`{"to":"` + to + `","sender":{},"epoch":0,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"duplicate field":          {raw(`{"to":"` + to + `","epoch":0,"epoch":0,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"negative epoch":           {raw(`{"to":"` + to + `","epoch":-1,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"fractional epoch":         {raw(`{"to":"` + to + `","epoch":0.5,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"string epoch":             {raw(`{"to":"` + to + `","epoch":"0","envelopes":[` + env + `]}`), CodeInvalidPayload},
		"oversized epoch":          {raw(`{"to":"` + to + `","epoch":4294967296,"envelopes":[` + env + `]}`), CodeInvalidPayload},
		"envelope extra field":     {raw(`{"to":"` + to + `","epoch":0,"envelopes":[{"session":"` + e.Session + `","epoch":0,"salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `","key":"x"}]}`), CodeInvalidPayload},
		"envelope missing iv":      {raw(`{"to":"` + to + `","epoch":0,"envelopes":[{"session":"` + e.Session + `","epoch":0,"salt":"` + e.Salt + `","ciphertext":"` + e.Ciphertext + `"}]}`), CodeInvalidPayload},
		"envelope string epoch":    {raw(`{"to":"` + to + `","epoch":0,"envelopes":[{"session":"` + e.Session + `","epoch":"0","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}]}`), CodeInvalidPayload},
		"short session id":         {with(func(x *wireEnvelope) { x.Session = randomText(SessionIDSize - 1) }), CodeInvalidPayload},
		"padded session id":        {with(func(x *wireEnvelope) { x.Session += "==" }), CodeInvalidPayload},
		"short salt":               {with(func(x *wireEnvelope) { x.Salt = randomText(SaltSize - 1) }), CodeInvalidPayload},
		"long salt":                {with(func(x *wireEnvelope) { x.Salt = randomText(SaltSize + 1) }), CodeInvalidPayload},
		"short iv":                 {with(func(x *wireEnvelope) { x.IV = randomText(IVSize - 1) }), CodeInvalidPayload},
		"long iv":                  {with(func(x *wireEnvelope) { x.IV = randomText(IVSize + 1) }), CodeInvalidPayload},
		"padded iv":                {with(func(x *wireEnvelope) { x.IV += "=" }), CodeInvalidPayload},
		"standard alphabet salt":   {with(func(x *wireEnvelope) { x.Salt = "+" + x.Salt[1:] }), CodeInvalidPayload},
		"non-canonical salt":       {with(func(x *wireEnvelope) { x.Salt = x.Salt[:42] + "B" }), CodeInvalidPayload},
		"empty ciphertext":         {with(func(x *wireEnvelope) { x.Ciphertext = "" }), CodeInvalidPayload},
		"tag-only ciphertext":      {with(func(x *wireEnvelope) { x.Ciphertext = randomText(TagSize) }), CodeInvalidPayload},
		"invalid ciphertext chars": {with(func(x *wireEnvelope) { x.Ciphertext = "***" + x.Ciphertext }), CodeInvalidPayload},
		"padded ciphertext":        {with(func(x *wireEnvelope) { x.Ciphertext = randomText(31) + "=" }), CodeInvalidPayload},
		"oversized ciphertext":     {with(func(x *wireEnvelope) { x.Ciphertext = randomText(MaxCiphertext + 1) }), CodeTooLarge},
		"oversized raw ciphertext": {raw(`{"to":"` + to + `","epoch":0,"envelopes":[{"session":"` + e.Session + `","epoch":0,"salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + strings.Repeat(`A`, 6000) + `"}]}`), CodeTooLarge},
		"numeric ciphertext":       {raw(`{"to":"` + to + `","epoch":0,"envelopes":[{"session":"` + e.Session + `","epoch":0,"salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":1}]}`), CodeInvalidPayload},
		"invalid recipient":        {sendRequest("m1", "bad", 0, e), CodeInvalidPayload},
		"invalid message id":       {[]byte(`{"type":"send","id":"bad id","payload":{}}`), CodeInvalidMessage},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			expectCode(t, sender.conn.Handle(tt.input), tt.code)
		})
	}
	if len(recipient.box.all()) != 0 {
		t.Fatalf("invalid requests delivered %v", recipient.box.all())
	}
}

func TestSendCiphertextBoundaries(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	recipient := f.ready(t, b)

	for i, n := range []int{MinCiphertext, MaxCiphertext} {
		if resp := decodeResponse(t, sender.conn.Handle(sendRequest(fmt.Sprintf("b%d", i), b.identity, 0, envelopeFor(recipient.keys, n)))); resp.Type != "sent" {
			t.Fatalf("%d-byte ciphertext rejected: %+v %s", n, resp, resp.Payload)
		}
	}
	if len(recipient.box.all()) != 2 {
		t.Fatalf("delivered %d, want 2", len(recipient.box.all()))
	}
}

func TestSendRequiresEstablishedSession(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	recipient := f.ready(t, b)

	bare, _, _ := f.conn()
	authenticated(t, bare, a.signer)
	expectCode(t, bare.Handle(sendRequest("m1", b.identity, 0, envelopeFor(recipient.keys, 32))), CodeKeyRequired)
	published, _, _ := f.published(t, a)
	expectCode(t, published.Handle(sendRequest("m2", b.identity, 0, envelopeFor(recipient.keys, 32))), CodeKeyRequired)
	if len(recipient.box.all()) != 0 {
		t.Fatal("sender without a session delivered")
	}
}

func TestSendEnforcesEpochs(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	recipient := f.ready(t, b)
	old := recipient.keys
	recipient.rotate(t, b)
	recipient.rotate(t, b)

	expectCode(t, sender.conn.Handle(sendRequest("m1", b.identity, 0, envelopeFor(old, 32))), CodeUnavailable)
	sender.rotate(t, a)
	sender.rotate(t, a)
	expectCode(t, sender.conn.Handle(sendRequest("m2", b.identity, 0, envelopeFor(recipient.keys, 32))), CodeStaleSession)
	if resp := decodeResponse(t, sender.conn.Handle(sendRequest("m3", b.identity, 1, envelopeFor(recipient.keys, 32)))); resp.Type != "sent" {
		t.Fatalf("previous sender epoch = %+v", resp)
	}
	if got := recipient.box.all(); len(got) != 1 || !strings.Contains(got[0], `"sender":{"session":"`+sender.keys.Session+`","epoch":1,`) {
		t.Fatalf("delivered %v", got)
	}
}

func TestSendRoutesPerSession(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	b1, b2 := f.ready(t, b), f.ready(t, b)
	e1, e2 := envelopeFor(b1.keys, 32), envelopeFor(b2.keys, 40)

	if resp := decodeResponse(t, sender.conn.Handle(sendRequest("m1", b.identity, 0, e1, e2))); resp.Type != "sent" {
		t.Fatal(resp)
	}
	if got := b1.box.all(); len(got) != 1 || got[0] != deliveredMessage("m1", a, sender.keys, e1) {
		t.Fatalf("b1 got %v", got)
	}
	if got := b2.box.all(); len(got) != 1 || got[0] != deliveredMessage("m1", a, sender.keys, e2) {
		t.Fatalf("b2 got %v", got)
	}
}

func TestSendRejectsDuplicateMessageID(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	recipient := f.ready(t, b)
	e := envelopeFor(recipient.keys, 32)

	if resp := decodeResponse(t, sender.conn.Handle(sendRequest("m1", b.identity, 0, e))); resp.Type != "sent" {
		t.Fatal(resp)
	}
	expectCode(t, sender.conn.Handle(sendRequest("m1", b.identity, 0, e)), CodeDuplicate)
	if len(recipient.box.all()) != 1 {
		t.Fatalf("replay delivered %d copies", len(recipient.box.all()))
	}
}

func TestSendRequiresAuthentication(t *testing.T) {
	f := newDirectFixture()
	b := newParty(t)
	recipient := f.ready(t, b)
	conn, _, _ := f.conn()

	expectCode(t, conn.Handle(sendRequest("m1", b.identity, 0, envelopeFor(recipient.keys, 32))), CodeAuthRequired)
	requestChallenge(t, conn)
	expectCode(t, conn.Handle(sendRequest("m2", b.identity, 0, envelopeFor(recipient.keys, 32))), CodeAuthRequired)
	if len(recipient.box.all()) != 0 {
		t.Fatal("unauthenticated send delivered")
	}
}

func TestSendUnavailableAndClosedSender(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	ghost := b.session(t, randomText(SessionIDSize), 0)

	expectCode(t, sender.conn.Handle(sendRequest("m1", b.identity, 0, envelopeFor(ghost, 32))), CodeUnavailable)
	sender.session.Close()
	expectCode(t, sender.conn.Handle(sendRequest("m2", b.identity, 0, envelopeFor(ghost, 32))), CodeAuthRequired)
}

func TestDeliveredMessageCarriesSenderRequestID(t *testing.T) {
	f := newDirectFixture()
	a, b, c := newParty(t), newParty(t), newParty(t)
	senderA := f.ready(t, a)
	senderC := f.ready(t, c)
	recipient := f.ready(t, b)
	e1, e2, e3 := envelopeFor(recipient.keys, 20), envelopeFor(recipient.keys, 21), envelopeFor(recipient.keys, 22)

	senderA.conn.Handle(sendRequest("a1", b.identity, 0, e1))
	senderC.conn.Handle(sendRequest("c1", b.identity, 0, e2))
	senderA.conn.Handle([]byte(`{"type":"ping","id":"p9","payload":{"sentAt":1}}`))
	senderA.conn.Handle(sendRequest("a2", b.identity, 0, e3))

	want := []string{
		deliveredMessage("a1", a, senderA.keys, e1),
		deliveredMessage("c1", c, senderC.keys, e2),
		deliveredMessage("a2", a, senderA.keys, e3),
	}
	if got := recipient.box.all(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("delivered %v, want %v", got, want)
	}
}

func TestSendErrorsDoNotLeakDetails(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	sender := f.ready(t, a)
	ghost := b.session(t, randomText(SessionIDSize), 0)
	for _, out := range [][]byte{
		sender.conn.Handle(sendRequest("m1", b.identity, 0, envelopeFor(ghost, 32))),
		sender.conn.Handle(sendRequest("m2", "bad", 0, envelopeFor(ghost, 32))),
		sender.conn.Handle(sendRequest("m3", b.identity, 9, envelopeFor(ghost, 32))),
		sender.conn.Handle(publishRequest("x", "y")),
		sender.conn.Handle(sessionRequest("s9", ghost)),
	} {
		for _, leak := range []string{"direct:", "identity:", "registry", "base64", "stale or"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}

func receiver(f *testing.F, fx directFixture, p party) (wireSession, *mailbox, func()) {
	f.Helper()
	session := fx.sessions.Open()
	box := &mailbox{}
	fx.direct.Attach(session, box.deliver)
	nonce, err := session.Challenge()
	if err != nil {
		f.Fatal(err)
	}
	if _, err := session.Authenticate(p.identity, p.sign(auth.Message(nonce))); err != nil {
		f.Fatal(err)
	}
	if err := fx.direct.Publish(session, direct.Bundle{Key: p.key, Signature: p.signature}); err != nil {
		f.Fatal(err)
	}
	keys := p.session(f, randomText(SessionIDSize), 0)
	if err := fx.direct.Establish(session, p.key, direct.SessionBundle{ID: keys.Session, Epoch: 0, Key: keys.Key, Signature: keys.Signature}); err != nil {
		f.Fatal(err)
	}
	return keys, box, session.Close
}

func FuzzSendPayload(f *testing.F) {
	a := newParty(f)
	recipient := newParty(f)
	fx := newDirectFixture()
	target, box, closeReceiver := receiver(f, fx, recipient)
	defer closeReceiver()
	e := envelopeFor(target, 32)
	env, _ := json.Marshal(e)
	f.Add(`{"to":"RECIPIENT","epoch":0,"envelopes":[` + string(env) + `]}`)
	f.Add(`{"to":"RECIPIENT","epoch":1,"envelopes":[` + string(env) + `]}`)
	f.Add(`{"to":"RECIPIENT","epoch":0,"envelopes":[` + string(env) + `,` + string(env) + `]}`)
	f.Add(`{"to":"RECIPIENT","body":"plaintext"}`)
	f.Add(`{"to":"RECIPIENT","salt":"` + e.Salt + `","iv":"` + e.IV + `","ciphertext":"` + e.Ciphertext + `"}`)
	f.Add(`{"to":"RECIPIENT","epoch":0,"envelopes":[{"session":"","epoch":0,"salt":"","iv":"","ciphertext":""}]}`)
	f.Add(`{"to":"RECIPIENT","epoch":0,"envelopes":[` + string(env) + `],"from":"x"}`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, payload string) {
		sender, session, _ := fx.conn()
		defer fx.direct.Detach(session)
		defer session.Close()
		authenticated(t, sender, a.signer)
		if resp := decodeResponse(t, sender.Handle(publishRequest(a.key, a.signature))); resp.Type != "published" {
			t.Fatalf("publish = %+v", resp)
		}
		own := a.session(t, randomText(SessionIDSize), 0)
		if resp := decodeResponse(t, sender.Handle(sessionRequest("s0", own))); resp.Type != "established" {
			t.Fatalf("session = %+v", resp)
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
			if len(delivered) != 1 ||
				!strings.Contains(delivered[0], `"from":"`+a.identity+`"`) ||
				!strings.Contains(delivered[0], `"sender":{"session":"`+own.Session+`","epoch":0,`) ||
				!strings.Contains(delivered[0], `"envelope":{"session":"`+target.Session+`","epoch":0,`) ||
				strings.Contains(delivered[0], `"body"`) {
				t.Fatalf("sent without exactly one sealed delivery bound to the sessions: %v", delivered)
			}
		} else if len(delivered) != 0 {
			t.Fatalf("rejected request delivered %v", delivered)
		}
	})
}

func FuzzEstablishPayload(f *testing.F) {
	a := newParty(f)
	fx := newDirectFixture()
	valid := a.session(f, randomText(SessionIDSize), 0)
	encoded, _ := json.Marshal(valid)
	f.Add(string(encoded))
	f.Add(`{"session":"` + valid.Session + `","epoch":1,"key":"` + valid.Key + `","signature":"` + valid.Signature + `"}`)
	f.Add(`{"session":"` + valid.Session + `","epoch":0,"key":"` + a.key + `","signature":"` + a.signature + `"}`)
	f.Add(`{"session":"","epoch":-0,"key":"","signature":""}`)
	f.Add(`{"session":"` + valid.Session + `","epoch":0e1,"key":"` + valid.Key + `","signature":"` + valid.Signature + `"}`)
	f.Add(`[]`)

	f.Fuzz(func(t *testing.T, payload string) {
		conn, session, _ := fx.conn()
		defer fx.direct.Detach(session)
		defer session.Close()
		authenticated(t, conn, a.signer)
		if resp := decodeResponse(t, conn.Handle(publishRequest(a.key, a.signature))); resp.Type != "published" {
			t.Fatalf("publish = %+v", resp)
		}
		out := conn.Handle([]byte(`{"type":"session","id":"s1","payload":` + payload + `}`))
		resp := decodeResponse(t, out)
		_, sessions, _ := fx.direct.Lookup(mustIdentity(t, a.identity))
		if resp.Type != "established" {
			for _, s := range sessions {
				if s.ID != valid.Session || s.Key != valid.Key {
					t.Fatalf("rejected payload left session state %+v", s)
				}
			}
			return
		}
		var accepted wireSession
		if err := json.Unmarshal([]byte(payload), &accepted); err != nil {
			t.Fatalf("accepted non-object %q", payload)
		}
		owner := decoded(a.identity)
		key := decoded(accepted.Key)
		if accepted.Epoch != 0 || !CanonicalExchangeKey(key) ||
			mustIdentity(t, a.identity).Verify(SessionMessage(owner, a.keyRaw, decoded(accepted.Session), 0, key), accepted.Signature) != nil {
			t.Fatalf("accepted unbound session %q", payload)
		}
	})
}
