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
	"github.com/Xhaann/ghost-x/server/prekey"
)

type fanout []auth.Observer

func (o fanout) Authenticated(s *auth.Session, id identity.Identity) {
	for _, observer := range o {
		observer.Authenticated(s, id)
	}
}

func (o fanout) Closed(s *auth.Session, id identity.Identity) {
	for _, observer := range o {
		observer.Closed(s, id)
	}
}

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
	direct   *direct.Registry
	prekeys  *prekey.Registry
}

func newHandshakeFixture() handshakeFixture {
	d := direct.NewRegistry()
	p := prekey.NewRegistry()
	return handshakeFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"publish":  Publish(d),
			"prekeys":  Prekeys(d, p),
			"bundle":   FetchBundle(p),
			"initiate": Initiate(d, p),
			"accept":   Accept(p),
		}),
		sessions: auth.NewRegistry(time.Now, fanout{d, p}),
		direct:   d,
		prekeys:  p,
	}
}

type device struct {
	party
	conn    *Conn
	session *auth.Session
	events  *events
	id      string
	signed  prekeyPayload
	onetime []prekeyPayload
}

func (f handshakeFixture) conn(t *testing.T, p party) (*Conn, *auth.Session, *events) {
	t.Helper()
	session := f.sessions.Open()
	ev := &events{}
	f.prekeys.Attach(session, ev.push)
	conn := f.router.Conn(session, discard)
	authenticated(t, conn, p.signer)
	return conn, session, ev
}

func signPrekey(p party, signedKind bool, deviceID string, id uint32) prekeyPayload {
	key := freshKey()
	build := OnetimePrekeyMessage
	if signedKind {
		build = SignedPrekeyMessage
	}
	return prekeyPayload{ID: id, Key: base64.RawURLEncoding.EncodeToString(key), Signature: p.sign(build(decoded(p.identity), p.keyRaw, decoded(deviceID), id, key))}
}

func prekeysRequest(deviceID string, signed prekeyPayload, onetime []prekeyPayload) []byte {
	payload, _ := json.Marshal(map[string]any{"device": deviceID, "signed": signed, "onetime": onetime})
	return fmt.Appendf(nil, `{"type":"prekeys","id":"p1","payload":%s}`, payload)
}

func (f handshakeFixture) device(t *testing.T, p party, n int) *device {
	t.Helper()
	conn, session, ev := f.conn(t, p)
	if resp := decodeResponse(t, conn.Handle(publishRequest(p.key, p.signature))); resp.Type != "published" {
		t.Fatalf("publish = %+v", resp)
	}
	d := &device{party: p, conn: conn, session: session, events: ev, id: randomText(DeviceIDSize)}
	d.signed = signPrekey(p, true, d.id, 1)
	for i := range n {
		d.onetime = append(d.onetime, signPrekey(p, false, d.id, uint32(10+i)))
	}
	resp := decodeResponse(t, conn.Handle(prekeysRequest(d.id, d.signed, d.onetime)))
	if resp.Type != "prekeys" || string(resp.Payload) != fmt.Sprintf(`{"available":%d}`, n) {
		t.Fatalf("prekeys = %+v %s", resp, resp.Payload)
	}
	return d
}

type initiationRequest struct {
	Version   int     `json:"version"`
	To        string  `json:"to"`
	Device    string  `json:"device"`
	Signed    uint32  `json:"signed"`
	Onetime   *uint32 `json:"onetime"`
	Ephemeral string  `json:"ephemeral"`
	Proof     string  `json:"proof"`
	Confirm   string  `json:"confirm"`
}

func (r initiationRequest) frame(id string) []byte {
	payload, _ := json.Marshal(r)
	return fmt.Appendf(nil, `{"type":"initiate","id":%q,"payload":%s}`, id, payload)
}

func buildInitiation(from party, to *device, onetime *prekeyPayload, signedOverride *prekeyPayload) initiationRequest {
	ephemeral := freshKey()
	signed := to.signed
	if signedOverride != nil {
		signed = *signedOverride
	}
	t := Transcript{
		Initiator:       decoded(from.identity),
		Responder:       decoded(to.identity),
		InitiatorStatic: from.keyRaw,
		ResponderStatic: to.keyRaw,
		Device:          decoded(to.id),
		Signed:          signed.ID,
		SignedKey:       decoded(signed.Key),
		Ephemeral:       ephemeral,
	}
	r := initiationRequest{Version: 1, To: to.identity, Device: to.id, Signed: signed.ID, Ephemeral: base64.RawURLEncoding.EncodeToString(ephemeral), Confirm: randomText(ConfirmSize)}
	if onetime != nil {
		id := onetime.ID
		t.Onetime = &id
		t.OnetimeKey = decoded(onetime.Key)
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

func TestPrekeysPublicationVerifiesEveryBinding(t *testing.T) {
	a, b := newParty(t), newParty(t)
	deviceID := randomText(DeviceIDSize)
	signed := signPrekey(a, true, deviceID, 1)
	onetime := []prekeyPayload{signPrekey(a, false, deviceID, 5), signPrekey(a, false, deviceID, 6)}
	key := exchangeRaw(t)
	high := append([]byte(nil), key...)
	high[31] |= 0x80
	sign := func(build func(owner, static, device []byte, id uint32, key []byte) []byte, owner string, static []byte, dev string, id uint32, k []byte, signer party) prekeyPayload {
		return prekeyPayload{ID: id, Key: base64.RawURLEncoding.EncodeToString(k), Signature: signer.sign(build(decoded(owner), static, decoded(dev), id, k))}
	}
	many := make([]prekeyPayload, prekey.MaxOnetime+1)
	for i := range many {
		many[i] = signPrekey(a, false, deviceID, uint32(100+i))
	}
	tests := map[string][]byte{
		"signed by another identity":     prekeysRequest(deviceID, sign(SignedPrekeyMessage, a.identity, a.keyRaw, deviceID, 1, key, b), onetime),
		"signed over another identity":   prekeysRequest(deviceID, sign(SignedPrekeyMessage, b.identity, a.keyRaw, deviceID, 1, key, a), onetime),
		"signed over another static key": prekeysRequest(deviceID, sign(SignedPrekeyMessage, a.identity, b.keyRaw, deviceID, 1, key, a), onetime),
		"signed for another device":      prekeysRequest(deviceID, sign(SignedPrekeyMessage, a.identity, a.keyRaw, randomText(DeviceIDSize), 1, key, a), onetime),
		"signed with another id":         prekeysRequest(deviceID, sign(SignedPrekeyMessage, a.identity, a.keyRaw, deviceID, 2, key, a), nil)[0:0],
		"signed as one-time":             prekeysRequest(deviceID, sign(OnetimePrekeyMessage, a.identity, a.keyRaw, deviceID, 1, key, a), onetime),
		"one-time as signed":             prekeysRequest(deviceID, signed, []prekeyPayload{sign(SignedPrekeyMessage, a.identity, a.keyRaw, deviceID, 5, key, a)}),
		"one-time by another identity":   prekeysRequest(deviceID, signed, []prekeyPayload{sign(OnetimePrekeyMessage, a.identity, a.keyRaw, deviceID, 5, key, b)}),
		"duplicate one-time ids":         prekeysRequest(deviceID, signed, []prekeyPayload{onetime[0], onetime[0]}),
		"one-time equals signed":         prekeysRequest(deviceID, signed, []prekeyPayload{{ID: 7, Key: signed.Key, Signature: a.sign(OnetimePrekeyMessage(decoded(a.identity), a.keyRaw, decoded(deviceID), 7, decoded(signed.Key)))}}),
		"non-canonical key":              prekeysRequest(deviceID, sign(SignedPrekeyMessage, a.identity, a.keyRaw, deviceID, 1, high, a), onetime),
		"too many one-time":              prekeysRequest(deviceID, signed, many),
		"short device":                   prekeysRequest(randomText(15), signed, onetime),
		"negative id":                    []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + deviceID + `","signed":{"id":-1,"key":"` + signed.Key + `","signature":"` + signed.Signature + `"},"onetime":[]}}`),
		"onetime object":                 []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + deviceID + `","signed":` + mustJSON(signed) + `,"onetime":{}}}`),
		"extra field":                    []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + deviceID + `","signed":` + mustJSON(signed) + `,"onetime":[],"private":"x"}}`),
		"private key in prekey":          []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + deviceID + `","signed":{"id":1,"key":"` + signed.Key + `","signature":"` + signed.Signature + `","private":"x"},"onetime":[]}}`),
		"missing signed":                 []byte(`{"type":"prekeys","id":"p1","payload":{"device":"` + deviceID + `","onetime":[]}}`),
	}
	delete(tests, "signed with another id")
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			f := newHandshakeFixture()
			conn, _, _ := f.conn(t, a)
			conn.Handle(publishRequest(a.key, a.signature))
			expectCode(t, conn.Handle(input), CodeInvalidPayload)
			if _, _, ok := f.prekeys.Fetch(mustIdentity(t, a.identity)); ok {
				t.Fatal("invalid prekeys stored")
			}
		})
	}
	f := newHandshakeFixture()
	conn, _, _ := f.conn(t, a)
	expectCode(t, conn.Handle(prekeysRequest(deviceID, signed, onetime)), CodeKeyRequired)
	unauthenticated := f.router.Conn(f.sessions.Open(), discard)
	expectCode(t, unauthenticated.Handle(prekeysRequest(deviceID, signed, onetime)), CodeAuthRequired)
}

func freshKey() []byte {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return private.PublicKey().Bytes()
}

func mustJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func TestBundleReservesAndReturnsSignedMaterial(t *testing.T) {
	f := newHandshakeFixture()
	a, b := newParty(t), newParty(t)
	bob := f.device(t, b, 2)
	conn, _, _ := f.conn(t, a)
	for i, want := range []*prekeyPayload{&bob.onetime[0], &bob.onetime[1], nil} {
		got := f.bundle(t, conn, b.identity)
		if got.Version != 1 || got.Identity != b.identity || got.Key != b.key || got.Signature != b.signature || len(got.Bundles) != 1 {
			t.Fatalf("bundle %d = %+v", i, got)
		}
		d := got.Bundles[0]
		if d.Device != bob.id || d.Signed != bob.signed {
			t.Fatalf("device bundle %d = %+v", i, d)
		}
		if (want == nil) != (d.Onetime == nil) || (want != nil && *d.Onetime != *want) {
			t.Fatalf("onetime %d = %+v, want %+v", i, d.Onetime, want)
		}
	}
	expectCode(t, conn.Handle([]byte(`{"type":"bundle","id":"b2","payload":{"identity":"`+newParty(t).identity+`"}}`)), CodeUnavailable)
	expectCode(t, conn.Handle([]byte(`{"type":"bundle","id":"b3","payload":{"identity":"x"}}`)), CodeInvalidPayload)
	expectCode(t, conn.Handle([]byte(`{"type":"bundle","id":"b4","payload":{"identity":"`+b.identity+`","verified":true}}`)), CodeInvalidPayload)
}

func TestInitiationRequiresAValidProofAndFreshPrekeys(t *testing.T) {
	f := newHandshakeFixture()
	a, b, c := newParty(t), newParty(t), newParty(t)
	bob := f.device(t, b, 3)
	alice, _, _ := f.conn(t, a)
	alice.Handle(publishRequest(a.key, a.signature))
	f.bundle(t, alice, b.identity)
	reserved := bob.onetime[0]

	bad := map[string][]byte{}
	r := buildInitiation(a, bob, &reserved, nil)
	forged := r
	forged.Proof = c.sign(decoded(r.Proof))
	bad["proof by another identity"] = forged.frame("i1")
	otherEphemeral := r
	otherEphemeral.Ephemeral = base64.RawURLEncoding.EncodeToString(exchangeRaw(t))
	bad["proof over another ephemeral"] = otherEphemeral.frame("i2")
	otherDevice := r
	otherDevice.Device = randomText(DeviceIDSize)
	bad["unknown device"] = otherDevice.frame("i3")
	versioned := r
	versioned.Version = 2
	bad["unsupported version"] = versioned.frame("i4")
	missingOnetime := r
	missingOnetime.Onetime = nil
	bad["one-time removed after signing"] = missingOnetime.frame("i5")
	codes := map[string]Code{
		"proof by another identity":      CodeInvalidPayload,
		"proof over another ephemeral":   CodeInvalidPayload,
		"unknown device":                 CodeUnavailable,
		"unsupported version":            CodeInvalidPayload,
		"one-time removed after signing": CodeInvalidPayload,
	}
	for name, input := range bad {
		expectCode(t, alice.Handle(input), codes[name])
	}
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
	want := fmt.Sprintf(`{"type":"initiation","payload":{"version":1,"from":%q,"key":%q,"signature":%q,"device":%q,"signed":1,"onetime":%d,"ephemeral":%q,"proof":%q,"confirm":%q}}`, a.identity, a.key, a.signature, bob.id, reserved.ID, r.Ephemeral, r.Proof, r.Confirm)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("delivered %v, want %s", got, want)
	}
	expectCode(t, alice.Handle(r.frame("i9")), CodeStaleSession)
	withoutOnetime := buildInitiation(a, bob, nil, nil)
	if resp := decodeResponse(t, alice.Handle(withoutOnetime.frame("i10"))); resp.Type != "initiated" {
		t.Fatalf("signed-only initiation = %+v", resp)
	}
	expectCode(t, alice.Handle(withoutOnetime.frame("i11")), CodeDuplicate)

	unpublished, _, _ := f.conn(t, c)
	expectCode(t, unpublished.Handle(buildInitiation(c, bob, nil, nil).frame("i12")), CodeKeyRequired)
}

func TestAcceptanceIsRoutedOnlyForDeliveredInitiations(t *testing.T) {
	f := newHandshakeFixture()
	a, b := newParty(t), newParty(t)
	bob := f.device(t, b, 1)
	alice := f.device(t, a, 1)
	f.bundle(t, alice.conn, b.identity)
	r := buildInitiation(a, bob, &bob.onetime[0], nil)
	if resp := decodeResponse(t, alice.conn.Handle(r.frame("i1"))); resp.Type != "initiated" {
		t.Fatal(resp)
	}
	bob.events.take()
	accept := func(to, ephemeral string) []byte {
		return []byte(`{"type":"accept","id":"a1","payload":{"to":"` + to + `","ephemeral":"` + ephemeral + `","confirm":"` + randomText(ConfirmSize) + `"}}`)
	}
	expectCode(t, bob.conn.Handle(accept(newParty(t).identity, r.Ephemeral)), CodeInvalidPayload)
	expectCode(t, bob.conn.Handle(accept(a.identity, randomText(KeySize))), CodeInvalidPayload)
	expectCode(t, alice.conn.Handle(accept(b.identity, r.Ephemeral)), CodeInvalidPayload)
	if resp := decodeResponse(t, bob.conn.Handle(accept(a.identity, r.Ephemeral))); resp.Type != "accepted" {
		t.Fatalf("accept = %+v %s", resp, resp.Payload)
	}
	got := alice.events.take()
	if len(got) != 1 || !strings.Contains(got[0], `"type":"acceptance"`) || !strings.Contains(got[0], `"from":"`+b.identity+`"`) {
		t.Fatalf("acceptance = %v", got)
	}
	expectCode(t, bob.conn.Handle(accept(a.identity, r.Ephemeral)), CodeInvalidPayload)
}

func FuzzPrekeysPayload(f *testing.F) {
	a := newParty(f)
	deviceID := randomText(DeviceIDSize)
	signed := signPrekey(a, true, deviceID, 1)
	onetime := signPrekey(a, false, deviceID, 2)
	f.Add(string(prekeysRequest(deviceID, signed, []prekeyPayload{onetime})))
	f.Add(string(prekeysRequest(deviceID, onetime, []prekeyPayload{signed})))
	f.Add(`{"type":"prekeys","id":"p1","payload":{"device":"","signed":null,"onetime":[]}}`)
	fx := newHandshakeFixture()
	f.Fuzz(func(t *testing.T, frame string) {
		session := fx.sessions.Open()
		defer fx.prekeys.Detach(session)
		defer fx.direct.Detach(session)
		defer session.Close()
		conn := fx.router.Conn(session, discard)
		authenticated(t, conn, a.signer)
		conn.Handle(publishRequest(a.key, a.signature))
		out := conn.Handle([]byte(frame))
		resp := decodeResponse(t, out)
		if resp.Type != "prekeys" {
			return
		}
		static, bundles, ok := fx.prekeys.Fetch(mustIdentity(t, a.identity))
		if !ok || static.Key != a.key {
			t.Fatalf("accepted prekeys without a bound static key: %s", frame)
		}
		owner := mustIdentity(t, a.identity)
		for _, b := range bundles {
			if owner.Verify(SignedPrekeyMessage(decoded(a.identity), a.keyRaw, decoded(b.Device), b.Signed.ID, decoded(b.Signed.Key)), b.Signed.Signature) != nil {
				t.Fatalf("stored unsigned prekey from %s", frame)
			}
			if p := b.Onetime; p != nil && owner.Verify(OnetimePrekeyMessage(decoded(a.identity), a.keyRaw, decoded(b.Device), p.ID, decoded(p.Key)), p.Signature) != nil {
				t.Fatalf("stored unsigned one-time prekey from %s", frame)
			}
		}
	})
}

func FuzzInitiatePayload(f *testing.F) {
	a, b := newParty(f), newParty(f)
	fx := newHandshakeFixture()
	session := fx.sessions.Open()
	ev := &events{}
	fx.prekeys.Attach(session, ev.push)
	nonce, _ := session.Challenge()
	if _, err := session.Authenticate(b.identity, b.sign(auth.Message(nonce))); err != nil {
		f.Fatal(err)
	}
	fx.direct.Publish(session, direct.Bundle{Key: b.key, Signature: b.signature})
	bob := &device{party: b, session: session, events: ev, id: randomText(DeviceIDSize)}
	bob.signed = signPrekey(b, true, bob.id, 1)
	if _, err := fx.prekeys.Publish(session, prekey.Static{Key: b.key, Signature: b.signature}, bob.id, prekey.Prekey{ID: 1, Key: bob.signed.Key, Signature: bob.signed.Signature}, nil); err != nil {
		f.Fatal(err)
	}
	valid := buildInitiation(a, bob, nil, nil)
	payload, _ := json.Marshal(valid)
	f.Add(string(payload))
	f.Add(strings.Replace(string(payload), `"version":1`, `"version":2`, 1))
	f.Add(strings.Replace(string(payload), `"onetime":null`, `"onetime":0`, 1))
	f.Add(`{"version":1,"to":"","device":"","signed":0,"onetime":null,"ephemeral":"","proof":"","confirm":""}`)
	f.Fuzz(func(t *testing.T, body string) {
		s := fx.sessions.Open()
		defer fx.prekeys.Detach(s)
		defer fx.direct.Detach(s)
		defer s.Close()
		conn := fx.router.Conn(s, discard)
		authenticated(t, conn, a.signer)
		conn.Handle(publishRequest(a.key, a.signature))
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
		tr := Transcript{Initiator: decoded(a.identity), Responder: decoded(b.identity), InitiatorStatic: a.keyRaw, ResponderStatic: b.keyRaw, Device: decoded(bob.id), Signed: got.Signed, SignedKey: decoded(bob.signed.Key), Ephemeral: decoded(got.Ephemeral)}
		if got.Onetime != nil || got.Signed != 1 || mustIdentity(t, a.identity).Verify(ProofMessage(tr), got.Proof) != nil {
			t.Fatalf("accepted unauthenticated initiation %q", body)
		}
	})
}
