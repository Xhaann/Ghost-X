package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/device/devicetest"
	"github.com/Xhaann/ghost-x/server/prekey"
)

type events struct {
	mu   sync.Mutex
	data []string
}

func (e *events) push(ev prekey.Event) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data = append(e.data, string(EncodeEvent(ev)))
	return true
}

func (e *events) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.data
	e.data = nil
	return out
}

type handshakeFixture struct {
	router   *Router
	sessions *auth.Registry
	prekeys  *prekey.Registry
}

func newHandshakeFixture() handshakeFixture {
	p := prekey.NewRegistry(testDevices.Authorized)
	return handshakeFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"prekeys":  Prekeys(testDevices, p),
			"bundle":   FetchBundle(p),
			"initiate": Initiate(testDevices, p),
			"accept":   Accept(p),
		}),
		sessions: auth.NewRegistry(time.Now, fanout{p}, testDevices),
		prekeys:  p,
	}
}

type endpoint struct {
	signer
	conn    *Conn
	session *auth.Session
	events  *events
	signed  prekeyPayload
	onetime []prekeyPayload
}

func (f handshakeFixture) conn(t *testing.T, s signer) (*Conn, *auth.Session, *events) {
	t.Helper()
	session := f.sessions.Open()
	ev := &events{}
	f.prekeys.Attach(session, ev.push)
	conn := f.router.Conn(session, discard)
	authenticated(t, conn, s)
	return conn, session, ev
}

func signPrekey(s signer, signedKind bool, id uint32) prekeyPayload {
	key := freshKey()
	build := OnetimePrekeyMessage
	if signedKind {
		build = SignedPrekeyMessage
	}
	return prekeyPayload{ID: id, Key: base64.RawURLEncoding.EncodeToString(key), Signature: s.sign(build(decoded(s.identity), s.device.IDRaw, s.device.ExchangeRaw, id, key))}
}

func prekeysRequest(deviceID string, signed prekeyPayload, onetime []prekeyPayload) []byte {
	if onetime == nil {
		onetime = []prekeyPayload{}
	}
	payload, _ := json.Marshal(map[string]any{"device": deviceID, "signed": signed, "onetime": onetime})
	return fmt.Appendf(nil, `{"type":"prekeys","id":"p1","payload":%s}`, payload)
}

func (f handshakeFixture) endpoint(t *testing.T, s signer, n int) *endpoint {
	t.Helper()
	conn, session, ev := f.conn(t, s)
	e := &endpoint{signer: s, conn: conn, session: session, events: ev}
	e.signed = signPrekey(s, true, 1)
	for i := range n {
		e.onetime = append(e.onetime, signPrekey(s, false, uint32(10+i)))
	}
	resp := decodeResponse(t, conn.Handle(prekeysRequest(s.device.ID, e.signed, e.onetime)))
	if resp.Type != "prekeys" || string(resp.Payload) != fmt.Sprintf(`{"available":%d}`, n) {
		t.Fatalf("prekeys = %+v %s", resp, resp.Payload)
	}
	return e
}

type initiationRequest struct {
	Version   int     `json:"version"`
	To        string  `json:"to"`
	Device    string  `json:"device"`
	Signed    uint32  `json:"signed"`
	Onetime   *uint32 `json:"onetime"`
	Ephemeral string  `json:"ephemeral"`
	Ratchet   string  `json:"ratchet"`
	Proof     string  `json:"proof"`
	Confirm   string  `json:"confirm"`
}

func (r initiationRequest) frame(id string) []byte {
	payload, _ := json.Marshal(r)
	return fmt.Appendf(nil, `{"type":"initiate","id":%q,"payload":%s}`, id, payload)
}

func transcriptFor(from signer, to *endpoint, signed prekeyPayload, onetime *prekeyPayload, ephemeral, ratchet []byte) Transcript {
	t := Transcript{
		Initiator:       decoded(from.identity),
		InitiatorDevice: from.device.IDRaw,
		Responder:       decoded(to.identity),
		ResponderDevice: to.device.IDRaw,
		InitiatorStatic: from.device.ExchangeRaw,
		ResponderStatic: to.device.ExchangeRaw,
		Signed:          signed.ID,
		SignedKey:       decoded(signed.Key),
		Ephemeral:       ephemeral,
		Ratchet:         ratchet,
	}
	if onetime != nil {
		id := onetime.ID
		t.Onetime = &id
		t.OnetimeKey = decoded(onetime.Key)
	}
	return t
}

func buildInitiation(from signer, to *endpoint, onetime *prekeyPayload, signedOverride *prekeyPayload) initiationRequest {
	return buildInitiationWith(from, to, onetime, signedOverride, freshKey())
}

func buildInitiationWith(from signer, to *endpoint, onetime *prekeyPayload, signedOverride *prekeyPayload, ratchet []byte) initiationRequest {
	ephemeral := freshKey()
	signed := to.signed
	if signedOverride != nil {
		signed = *signedOverride
	}
	t := transcriptFor(from, to, signed, onetime, ephemeral, ratchet)
	r := initiationRequest{Version: HandshakeVersion, To: to.identity, Device: to.device.ID, Signed: signed.ID, Ephemeral: base64.RawURLEncoding.EncodeToString(ephemeral), Ratchet: base64.RawURLEncoding.EncodeToString(ratchet), Confirm: randomText(ConfirmSize)}
	if onetime != nil {
		id := onetime.ID
		r.Onetime = &id
	}
	r.Proof = from.sign(ProofMessage(t))
	return r
}

func (f handshakeFixture) bundle(t *testing.T, conn *Conn, of string) prekeyBundlePayload {
	t.Helper()
	resp := decodeResponse(t, conn.Handle([]byte(`{"type":"bundle","id":"b1","payload":{"identity":"`+of+`"}}`)))
	if resp.Type != "bundle" {
		t.Fatalf("bundle = %+v %s", resp, resp.Payload)
	}
	var out prekeyBundlePayload
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func freshKey() []byte {
	return devicetest.NewExchange().PublicKey().Bytes()
}

func mustJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func TestPrekeysPublicationVerifiesEveryDeviceBinding(t *testing.T) {
	pair := newSiblings(t, 2)
	a, sibling := pair[0], pair[1]
	other := newSigner(t)
	signed := signPrekey(a, true, 1)
	onetime := []prekeyPayload{signPrekey(a, false, 5), signPrekey(a, false, 6)}
	key := freshKey()
	high := append([]byte(nil), key...)
	high[31] |= 0x80
	sign := func(build func(owner, deviceID, exchange []byte, id uint32, key []byte) []byte, owner string, deviceID, exchange []byte, id uint32, k []byte, by signer) prekeyPayload {
		return prekeyPayload{ID: id, Key: base64.RawURLEncoding.EncodeToString(k), Signature: by.sign(build(decoded(owner), deviceID, exchange, id, k))}
	}
	rootSigned := prekeyPayload{ID: 1, Key: base64.RawURLEncoding.EncodeToString(key)}
	rootSigned.Signature = base64.RawURLEncoding.EncodeToString(ed25519Sign(a, SignedPrekeyMessage(decoded(a.identity), a.device.IDRaw, a.device.ExchangeRaw, 1, key)))
	many := make([]prekeyPayload, prekey.MaxOnetime+1)
	for i := range many {
		many[i] = signPrekey(a, false, uint32(100+i))
	}
	dev, ex := a.device.IDRaw, a.device.ExchangeRaw
	tests := map[string][]byte{
		"signed by the sibling device":   prekeysRequest(a.device.ID, sign(SignedPrekeyMessage, a.identity, dev, ex, 1, key, sibling), onetime),
		"signed by another identity":     prekeysRequest(a.device.ID, sign(SignedPrekeyMessage, a.identity, dev, ex, 1, key, other), onetime),
		"signed by the identity root":    prekeysRequest(a.device.ID, rootSigned, onetime),
		"signed over another identity":   prekeysRequest(a.device.ID, sign(SignedPrekeyMessage, other.identity, dev, ex, 1, key, a), onetime),
		"signed over another device":     prekeysRequest(a.device.ID, sign(SignedPrekeyMessage, a.identity, sibling.device.IDRaw, ex, 1, key, a), onetime),
		"signed over another device key": prekeysRequest(a.device.ID, sign(SignedPrekeyMessage, a.identity, dev, sibling.device.ExchangeRaw, 1, key, a), onetime),
		"signed as one-time":             prekeysRequest(a.device.ID, sign(OnetimePrekeyMessage, a.identity, dev, ex, 1, key, a), onetime),
		"one-time as signed":             prekeysRequest(a.device.ID, signed, []prekeyPayload{sign(SignedPrekeyMessage, a.identity, dev, ex, 5, key, a)}),
		"one-time by sibling":            prekeysRequest(a.device.ID, signed, []prekeyPayload{sign(OnetimePrekeyMessage, a.identity, dev, ex, 5, key, sibling)}),
		"duplicate one-time ids":         prekeysRequest(a.device.ID, signed, []prekeyPayload{onetime[0], onetime[0]}),
		"one-time equals signed":         prekeysRequest(a.device.ID, signed, []prekeyPayload{{ID: 7, Key: signed.Key, Signature: a.sign(OnetimePrekeyMessage(decoded(a.identity), dev, ex, 7, decoded(signed.Key)))}}),
		"non-canonical key":              prekeysRequest(a.device.ID, sign(SignedPrekeyMessage, a.identity, dev, ex, 1, high, a), onetime),
		"too many one-time":              prekeysRequest(a.device.ID, signed, many),
		"short device":                   prekeysRequest(randomText(15), signed, onetime),
		"published for the sibling":      prekeysRequest(sibling.device.ID, signPrekey(sibling, true, 1), nil),
		"negative id":                    []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + a.device.ID + `","signed":{"id":-1,"key":"` + signed.Key + `","signature":"` + signed.Signature + `"},"onetime":[]}}`),
		"onetime object":                 []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + a.device.ID + `","signed":` + mustJSON(signed) + `,"onetime":{}}}`),
		"extra field":                    []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + a.device.ID + `","signed":` + mustJSON(signed) + `,"onetime":[],"private":"x"}}`),
		"private key in prekey":          []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + a.device.ID + `","signed":{"id":1,"key":"` + signed.Key + `","signature":"` + signed.Signature + `","private":"x"},"onetime":[]}}`),
		"missing signed":                 []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + a.device.ID + `","onetime":[]}}`),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			f := newHandshakeFixture()
			conn, _, _ := f.conn(t, a)
			expectCode(t, conn.Handle(input), CodeInvalidPayload)
			if _, ok := f.prekeys.Fetch(mustIdentity(t, a.identity)); ok {
				t.Fatal("invalid prekeys stored")
			}
		})
	}
	f := newHandshakeFixture()
	unauthenticated := f.router.Conn(f.sessions.Open(), discard)
	expectCode(t, unauthenticated.Handle(prekeysRequest(a.device.ID, signed, onetime)), CodeAuthRequired)
}

func TestBundleListsOnlyAuthorizedDevicesAndReserves(t *testing.T) {
	f := newHandshakeFixture()
	a := newSigner(t)
	pair := newSiblings(t, 2)
	b0 := f.endpoint(t, pair[0], 2)
	b1 := f.endpoint(t, pair[1], 1)
	conn, _, _ := f.conn(t, a)
	got := f.bundle(t, conn, pair[0].identity)
	if got.Version != HandshakeVersion || got.Identity != pair[0].identity || len(got.Bundles) != 2 {
		t.Fatalf("bundle = %+v", got)
	}
	for _, d := range got.Bundles {
		owner := b0
		if d.Device == b1.device.ID {
			owner = b1
		}
		if d.Device != owner.device.ID || d.Signed != owner.signed || d.Onetime == nil || *d.Onetime != owner.onetime[0] {
			t.Fatalf("device bundle = %+v", d)
		}
	}
	if err := testDevices.Publish(pair[0].owner.Remove(pair[1].device)); err != nil {
		t.Fatal(err)
	}
	got = f.bundle(t, conn, pair[0].identity)
	if len(got.Bundles) != 1 || got.Bundles[0].Device != b0.device.ID || *got.Bundles[0].Onetime != b0.onetime[1] {
		t.Fatalf("bundle after revocation = %+v", got)
	}
	expectCode(t, conn.Handle([]byte(`{"type":"bundle","id":"b2","payload":{"identity":"`+newSigner(t).identity+`"}}`)), CodeUnavailable)
	expectCode(t, conn.Handle([]byte(`{"type":"bundle","id":"b3","payload":{"identity":"x"}}`)), CodeInvalidPayload)
	expectCode(t, conn.Handle([]byte(`{"type":"bundle","id":"b4","payload":{"identity":"`+pair[0].identity+`","device":"x"}}`)), CodeInvalidPayload)
}

func TestInitiationRequiresADeviceProofAndFreshPrekeys(t *testing.T) {
	f := newHandshakeFixture()
	aPair := newSiblings(t, 2)
	a, aSibling := aPair[0], aPair[1]
	b := newSigner(t)
	c := newSigner(t)
	bob := f.endpoint(t, b, 3)
	alice, _, _ := f.conn(t, a)
	f.bundle(t, alice, b.identity)
	reserved := bob.onetime[0]

	r := buildInitiation(a, bob, &reserved, nil)
	bad := map[string]initiationRequest{}
	forged := r
	forged.Proof = c.sign(ProofMessage(transcriptFor(a, bob, bob.signed, &reserved, decoded(r.Ephemeral), decoded(r.Ratchet))))
	bad["proof by another identity"] = forged
	sibling := r
	sibling.Proof = aSibling.sign(ProofMessage(transcriptFor(a, bob, bob.signed, &reserved, decoded(r.Ephemeral), decoded(r.Ratchet))))
	bad["proof by the sibling device"] = sibling
	claimed := r
	claimed.Proof = a.sign(ProofMessage(transcriptFor(aSibling, bob, bob.signed, &reserved, decoded(r.Ephemeral), decoded(r.Ratchet))))
	bad["proof claiming the sibling device"] = claimed
	root := r
	root.Proof = base64.RawURLEncoding.EncodeToString(ed25519Sign(a, ProofMessage(transcriptFor(a, bob, bob.signed, &reserved, decoded(r.Ephemeral), decoded(r.Ratchet)))))
	bad["proof by the identity root"] = root
	otherEphemeral := r
	otherEphemeral.Ephemeral = base64.RawURLEncoding.EncodeToString(freshKey())
	bad["proof over another ephemeral"] = otherEphemeral
	otherRatchet := r
	otherRatchet.Ratchet = base64.RawURLEncoding.EncodeToString(freshKey())
	bad["proof over another ratchet key"] = otherRatchet
	versioned := r
	versioned.Version = 2
	bad["previous handshake version"] = versioned
	missingOnetime := r
	missingOnetime.Onetime = nil
	bad["one-time removed after signing"] = missingOnetime
	for name, input := range bad {
		expectCode(t, alice.Handle(input.frame("i1")), CodeInvalidPayload)
		_ = name
	}
	otherDevice := r
	otherDevice.Device = randomText(DeviceIDSize)
	expectCode(t, alice.Handle(otherDevice.frame("i3")), CodeUnavailable)
	high := freshKey()
	high[31] |= 0x80
	expectCode(t, alice.Handle(buildInitiationWith(a, bob, nil, nil, high).frame("i5b")), CodeInvalidPayload)
	unreserved := bob.onetime[2]
	expectCode(t, alice.Handle(buildInitiation(a, bob, &unreserved, nil).frame("i6")), CodeStaleSession)
	stale := prekeyPayload{ID: 99, Key: bob.signed.Key, Signature: bob.signed.Signature}
	expectCode(t, alice.Handle(buildInitiation(a, bob, nil, &stale).frame("i7")), CodeStaleSession)
	if got := bob.events.take(); len(got) != 0 {
		t.Fatalf("invalid initiations delivered: %v", got)
	}

	resp := decodeResponse(t, alice.Handle(r.frame("i8")))
	if resp.Type != "initiated" || string(resp.Payload) != `{}` {
		t.Fatalf("initiate = %+v %s", resp, resp.Payload)
	}
	got := bob.events.take()
	want := fmt.Sprintf(`{"type":"initiation","payload":{"version":3,"from":%q,"device":%q,"signed":1,"onetime":%d,"ephemeral":%q,"ratchet":%q,"proof":%q,"confirm":%q}}`, a.identity, a.device.ID, reserved.ID, r.Ephemeral, r.Ratchet, r.Proof, r.Confirm)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %v, want %s", got, want)
	}
	expectCode(t, alice.Handle(r.frame("i9")), CodeStaleSession)
	withoutOnetime := buildInitiation(a, bob, nil, nil)
	if resp := decodeResponse(t, alice.Handle(withoutOnetime.frame("i10"))); resp.Type != "initiated" {
		t.Fatalf("signed-only initiation = %+v", resp)
	}
	expectCode(t, alice.Handle(withoutOnetime.frame("i11")), CodeDuplicate)
}

func TestRevokedInitiatorCannotInitiate(t *testing.T) {
	f := newHandshakeFixture()
	aPair := newSiblings(t, 2)
	bob := f.endpoint(t, newSigner(t), 1)
	alice, _, _ := f.conn(t, aPair[1])
	if err := testDevices.Publish(aPair[0].owner.Remove(aPair[1].device)); err != nil {
		t.Fatal(err)
	}
	expectCode(t, alice.Handle(buildInitiation(aPair[1], bob, nil, nil).frame("i1")), CodeRevoked)
	if got := bob.events.take(); len(got) != 0 {
		t.Fatalf("revoked device initiation delivered: %v", got)
	}
}

func TestAcceptanceIsRoutedOnlyToTheInitiatingDevice(t *testing.T) {
	f := newHandshakeFixture()
	aPair := newSiblings(t, 2)
	b := newSigner(t)
	bob := f.endpoint(t, b, 1)
	alice := f.endpoint(t, aPair[0], 1)
	sibling := f.endpoint(t, aPair[1], 1)
	f.bundle(t, alice.conn, b.identity)
	r := buildInitiation(aPair[0], bob, &bob.onetime[0], nil)
	if resp := decodeResponse(t, alice.conn.Handle(r.frame("i1"))); resp.Type != "initiated" {
		t.Fatal(resp)
	}
	bob.events.take()
	accept := func(to, deviceID, ephemeral string) []byte {
		return []byte(`{"type":"accept","id":"a1","payload":{"to":"` + to + `","device":"` + deviceID + `","ephemeral":"` + ephemeral + `","confirm":"` + randomText(ConfirmSize) + `"}}`)
	}
	expectCode(t, bob.conn.Handle(accept(newSigner(t).identity, aPair[0].device.ID, r.Ephemeral)), CodeInvalidPayload)
	expectCode(t, bob.conn.Handle(accept(aPair[0].identity, aPair[1].device.ID, r.Ephemeral)), CodeInvalidPayload)
	expectCode(t, bob.conn.Handle(accept(aPair[0].identity, aPair[0].device.ID, randomText(KeySize))), CodeInvalidPayload)
	expectCode(t, alice.conn.Handle(accept(b.identity, b.device.ID, r.Ephemeral)), CodeInvalidPayload)
	expectCode(t, bob.conn.Handle([]byte(`{"type":"accept","id":"a1","payload":{"to":"`+aPair[0].identity+`","ephemeral":"`+r.Ephemeral+`","confirm":"`+randomText(ConfirmSize)+`"}}`)), CodeInvalidPayload)
	if resp := decodeResponse(t, bob.conn.Handle(accept(aPair[0].identity, aPair[0].device.ID, r.Ephemeral))); resp.Type != "accepted" {
		t.Fatalf("accept = %+v %s", resp, resp.Payload)
	}
	got := alice.events.take()
	if len(got) != 1 || !strings.Contains(got[0], `"type":"acceptance"`) || !strings.Contains(got[0], `"from":"`+b.identity+`","device":"`+b.device.ID+`"`) {
		t.Fatalf("acceptance = %v", got)
	}
	if leaked := sibling.events.take(); len(leaked) != 0 {
		t.Fatalf("sibling received %v", leaked)
	}
	expectCode(t, bob.conn.Handle(accept(aPair[0].identity, aPair[0].device.ID, r.Ephemeral)), CodeInvalidPayload)
}

func FuzzPrekeysPayload(f *testing.F) {
	a := newSigner(f)
	signed := signPrekey(a, true, 1)
	onetime := signPrekey(a, false, 2)
	f.Add(string(prekeysRequest(a.device.ID, signed, []prekeyPayload{onetime})))
	f.Add(string(prekeysRequest(a.device.ID, onetime, []prekeyPayload{signed})))
	f.Add(`{"type":"prekeys","id":"p1","payload":{"device":"","signed":null,"onetime":[]}}`)
	fx := newHandshakeFixture()
	f.Fuzz(func(t *testing.T, frame string) {
		session := fx.sessions.Open()
		defer fx.prekeys.Detach(session)
		defer session.Close()
		conn := fx.router.Conn(session, discard)
		authenticated(t, conn, a)
		resp := decodeResponse(t, conn.Handle([]byte(frame)))
		if resp.Type != "prekeys" {
			return
		}
		bundles, ok := fx.prekeys.Fetch(mustIdentity(t, a.identity))
		if !ok {
			t.Fatalf("accepted prekeys not stored: %s", frame)
		}
		key := mustIdentity(t, a.device.SigningKey())
		for _, b := range bundles {
			if b.Device != a.device.ID {
				t.Fatalf("stored prekeys for another device from %s", frame)
			}
			if key.Verify(SignedPrekeyMessage(decoded(a.identity), a.device.IDRaw, a.device.ExchangeRaw, b.Signed.ID, decoded(b.Signed.Key)), b.Signed.Signature) != nil {
				t.Fatalf("stored unsigned prekey from %s", frame)
			}
			if p := b.Onetime; p != nil && key.Verify(OnetimePrekeyMessage(decoded(a.identity), a.device.IDRaw, a.device.ExchangeRaw, p.ID, decoded(p.Key)), p.Signature) != nil {
				t.Fatalf("stored unsigned one-time prekey from %s", frame)
			}
		}
	})
}

func FuzzInitiatePayload(f *testing.F) {
	a, b := newSigner(f), newSigner(f)
	fx := newHandshakeFixture()
	session := fx.sessions.Open()
	ev := &events{}
	fx.prekeys.Attach(session, ev.push)
	nonce, _ := session.Challenge()
	if _, err := session.Authenticate(b.identity, b.device.ID, b.proof(nonce)); err != nil {
		f.Fatal(err)
	}
	bob := &endpoint{signer: b, session: session, events: ev}
	bob.signed = signPrekey(b, true, 1)
	if _, err := fx.prekeys.Publish(session, b.device.ID, prekey.Prekey{ID: 1, Key: bob.signed.Key, Signature: bob.signed.Signature}, nil); err != nil {
		f.Fatal(err)
	}
	valid := buildInitiation(a, bob, nil, nil)
	payload, _ := json.Marshal(valid)
	f.Add(string(payload))
	f.Add(strings.Replace(string(payload), `"version":3`, `"version":2`, 1))
	f.Add(strings.Replace(string(payload), `"onetime":null`, `"onetime":0`, 1))
	f.Add(`{"version":3,"to":"","device":"","signed":0,"onetime":null,"ephemeral":"","ratchet":"","proof":"","confirm":""}`)
	f.Fuzz(func(t *testing.T, body string) {
		s := fx.sessions.Open()
		defer fx.prekeys.Detach(s)
		defer s.Close()
		conn := fx.router.Conn(s, discard)
		authenticated(t, conn, a)
		ev.take()
		resp := decodeResponse(t, conn.Handle([]byte(`{"type":"initiate","id":"i1","payload":`+body+`}`)))
		delivered := ev.take()
		if resp.Type != "initiated" {
			if len(delivered) != 0 {
				t.Fatalf("rejected initiation delivered: %v", delivered)
			}
			return
		}
		var got initiationRequest
		if err := json.Unmarshal([]byte(body), &got); err != nil || len(delivered) != 1 {
			t.Fatalf("accepted %q delivered %v", body, delivered)
		}
		tr := transcriptFor(a, bob, bob.signed, nil, decoded(got.Ephemeral), decoded(got.Ratchet))
		if got.Onetime != nil || got.Signed != 1 || got.Device != b.device.ID || mustIdentity(t, a.device.SigningKey()).Verify(ProofMessage(tr), got.Proof) != nil {
			t.Fatalf("accepted unauthenticated initiation %q", body)
		}
	})
}
