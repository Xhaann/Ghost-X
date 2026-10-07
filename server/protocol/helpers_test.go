package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/device/devicetest"
	"github.com/Xhaann/ghost-x/server/identity"
)

var testDevices = mustDevices()

func mustDevices() *device.Registry {
	r, err := device.Open("")
	if err != nil {
		panic(err)
	}
	return r
}

type signer struct {
	owner    *devicetest.Identity
	device   *devicetest.Device
	identity string
}

func newSigner(t testing.TB) signer {
	t.Helper()
	return newSiblings(t, 1)[0]
}

func newSiblings(t testing.TB, n int) []signer {
	t.Helper()
	owner := devicetest.NewIdentity()
	var list []*devicetest.Device
	for range n {
		list = append(list, owner.NewDevice())
	}
	if err := testDevices.Publish(owner.Add(list...)); err != nil {
		t.Fatal(err)
	}
	out := make([]signer, n)
	for i, d := range list {
		out[i] = signer{owner: owner, device: d, identity: owner.Identity}
	}
	return out
}

func unregistered() signer {
	owner := devicetest.NewIdentity()
	return signer{owner: owner, device: owner.NewDevice(), identity: owner.Identity}
}

func (s signer) sign(message []byte) string {
	return s.device.Sign(message)
}

func (s signer) proof(nonce []byte) string {
	return s.device.AuthSignature(s.owner, nonce)
}

func (s signer) deviceID() string {
	return s.device.ID
}

func authenticate(conn *Conn, identity, deviceID, signature string) []byte {
	return conn.Handle(fmt.Appendf(nil, `{"type":"authenticate","id":"a1","payload":{"identity":%q,"device":%q,"signature":%q}}`, identity, deviceID, signature))
}

func authenticated(t *testing.T, conn *Conn, s signer) {
	t.Helper()
	resp := decodeResponse(t, authenticate(conn, s.identity, s.device.ID, s.proof(requestChallenge(t, conn))))
	if resp.Type != "authenticated" {
		t.Fatalf("authentication = %+v %s", resp, resp.Payload)
	}
}

func mustIdentity(t testing.TB, encoded string) identity.Identity {
	t.Helper()
	id, err := identity.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decoded(text string) []byte {
	raw, _ := base64.RawURLEncoding.DecodeString(text)
	return raw
}

type fanout []auth.Observer

func (o fanout) Authenticated(s *auth.Session, id identity.Identity, deviceID string) {
	for _, observer := range o {
		observer.Authenticated(s, id, deviceID)
	}
}

func (o fanout) Closed(s *auth.Session, id identity.Identity) {
	for _, observer := range o {
		observer.Closed(s, id)
	}
}

func ed25519Sign(s signer, message []byte) []byte {
	return ed25519.Sign(s.owner.Root, message)
}
