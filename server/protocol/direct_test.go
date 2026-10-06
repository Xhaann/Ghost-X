package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/identity"
)

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
			"publish": Publish(d),
			"key":     Key(d),
		}),
		sessions: auth.NewRegistry(time.Now, d),
		direct:   d,
	}
}

func (f directFixture) conn() (*Conn, *auth.Session) {
	session := f.sessions.Open()
	return f.router.Conn(session, discard), session
}

func (f directFixture) published(t *testing.T, p party) *Conn {
	t.Helper()
	conn, _ := f.conn()
	authenticated(t, conn, p.signer)
	if resp := decodeResponse(t, conn.Handle(publishRequest(p.key, p.signature))); resp.Type != "published" {
		t.Fatalf("publish = %+v %s", resp, resp.Payload)
	}
	return conn
}

type party struct {
	signer
	key       string
	keyRaw    []byte
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

func publishRequest(key, signature string) []byte {
	return fmt.Appendf(nil, `{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, key, signature)
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestPublishBindsVerifiedKey(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	conn, _ := f.conn()
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
			conn, _ := f.conn()
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
	conn, _ := f.conn()
	expectCode(t, conn.Handle(publishRequest(a.key, a.signature)), CodeAuthRequired)
}

func TestPublishConflictRejected(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	f.published(t, a)
	second, _ := f.conn()
	authenticated(t, second, a.signer)

	other := newParty(t)
	expectCode(t, second.Handle(publishRequest(other.key, a.signer.sign(KeyMessage(a.identity, other.keyRaw)))), CodeInvalidPayload)
	if resp := decodeResponse(t, second.Handle(publishRequest(a.key, a.signature))); resp.Type != "published" {
		t.Fatalf("matching publish = %+v", resp)
	}
}

func TestKeyLookupReturnsPublishedKeyOnly(t *testing.T) {
	f := newDirectFixture()
	a, b := newParty(t), newParty(t)
	asker := f.published(t, a)
	f.published(t, b)

	resp := decodeResponse(t, asker.Handle([]byte(`{"type":"key","id":"q1","payload":{"identity":"`+b.identity+`"}}`)))
	want := `{"identity":"` + b.identity + `","key":"` + b.key + `","signature":"` + b.signature + `"}`
	if resp.Type != "key" || resp.ID != "q1" || string(resp.Payload) != want {
		t.Fatalf("key = %+v %s", resp, resp.Payload)
	}
	expectCode(t, asker.Handle([]byte(`{"type":"key","id":"q3","payload":{"identity":"`+newParty(t).identity+`"}}`)), CodeUnavailable)
	expectCode(t, asker.Handle([]byte(`{"type":"key","id":"q4","payload":{"identity":"bad"}}`)), CodeInvalidPayload)
	expectCode(t, asker.Handle([]byte(`{"type":"key","id":"q5","payload":{"identity":"`+b.identity+`","x":1}}`)), CodeInvalidPayload)
	unauthenticated, _ := f.conn()
	expectCode(t, unauthenticated.Handle([]byte(`{"type":"key","id":"q6","payload":{"identity":"`+b.identity+`"}}`)), CodeAuthRequired)
}

func TestPublishErrorsDoNotLeakDetails(t *testing.T) {
	f := newDirectFixture()
	a := newParty(t)
	conn := f.published(t, a)
	for _, out := range [][]byte{
		conn.Handle(publishRequest("x", "y")),
		conn.Handle([]byte(`{"type":"key","id":"q1","payload":{"identity":"bad"}}`)),
	} {
		for _, leak := range []string{"direct:", "identity:", "registry", "base64"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}
