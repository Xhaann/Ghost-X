package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Xhaann/ghost-x/server/protocol"
)

func signedPrekey(k key, staticRaw []byte, deviceID string, id uint32, signed bool) (map[string]any, []byte) {
	raw := exchangeRaw(nil)
	build := protocol.OnetimePrekeyMessage
	if signed {
		build = protocol.SignedPrekeyMessage
	}
	signature := ed25519.Sign(k.private, build(decoded(k.identity), staticRaw, decoded(deviceID), id, raw))
	return map[string]any{"id": id, "key": base64.RawURLEncoding.EncodeToString(raw), "signature": base64.RawURLEncoding.EncodeToString(signature)}, raw
}

func TestAsynchronousInitiationWaitsForTheRecipient(t *testing.T) {
	_, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	bExchange, bSignature := bundleFor(t, bKey)
	b := connectPeerWith(t, url, bKey, bExchange, bSignature)
	deviceID := randomText(protocol.DeviceIDSize)
	signed, signedRaw := signedPrekey(bKey, b.staticRaw, deviceID, 1, true)
	onetime, onetimeRaw := signedPrekey(bKey, b.staticRaw, deviceID, 5, false)
	publish, _ := json.Marshal(map[string]any{"device": deviceID, "signed": signed, "onetime": []any{onetime}})
	b.write(t, `{"type":"prekeys","id":"p1","payload":`+string(publish)+`}`)
	if msg := b.next(t); msg.Type != "prekeys" || string(msg.Payload) != `{"available":1}` {
		t.Fatalf("prekeys = %+v %s", msg, msg.Payload)
	}
	b.conn.Close()

	a := connectPeer(t, url, aKey)
	a.write(t, `{"type":"bundle","id":"q1","payload":{"identity":"`+bKey.identity+`"}}`)
	bundle := a.next(t)
	if bundle.Type != "bundle" || !strings.Contains(string(bundle.Payload), `"onetime":{"id":5,`) {
		t.Fatalf("bundle = %+v %s", bundle, bundle.Payload)
	}
	ephemeral := exchangeRaw(t)
	ratchet := exchangeRaw(t)
	id := uint32(5)
	tr := protocol.Transcript{
		Initiator: decoded(aKey.identity), Responder: decoded(bKey.identity),
		InitiatorStatic: a.staticRaw, ResponderStatic: b.staticRaw,
		Device: decoded(deviceID), Signed: 1, SignedKey: signedRaw,
		Onetime: &id, OnetimeKey: onetimeRaw, Ephemeral: ephemeral, Ratchet: ratchet,
	}
	proof := base64.RawURLEncoding.EncodeToString(ed25519.Sign(aKey.private, protocol.ProofMessage(tr)))
	eph := base64.RawURLEncoding.EncodeToString(ephemeral)
	confirm := randomText(protocol.ConfirmSize)
	initiate := fmt.Sprintf(`{"type":"initiate","id":"i1","payload":{"version":2,"to":%q,"device":%q,"signed":1,"onetime":5,"ephemeral":%q,"ratchet":%q,"proof":%q,"confirm":%q}}`, bKey.identity, deviceID, eph, base64.RawURLEncoding.EncodeToString(ratchet), proof, confirm)
	a.write(t, initiate)
	if msg := a.next(t); msg.Type != "initiated" {
		t.Fatalf("initiate = %+v %s", msg, msg.Payload)
	}
	a.write(t, strings.Replace(initiate, `"id":"i1"`, `"id":"i2"`, 1))
	if msg := a.next(t); msg.Type != "error" || string(msg.Payload) != `{"code":"stale_session"}` {
		t.Fatalf("replayed initiation = %+v %s", msg, msg.Payload)
	}

	b2 := connectPeerWith(t, url, bKey, bExchange, bSignature)
	b2.write(t, `{"type":"prekeys","id":"p2","payload":`+string(publish)+`}`)
	reply, pushed := b2.next(t), b2.next(t)
	if reply.Type == "initiation" {
		reply, pushed = pushed, reply
	}
	if reply.Type != "prekeys" || pushed.Type != "initiation" || !strings.Contains(string(pushed.Payload), `"ephemeral":"`+eph+`"`) || !strings.Contains(string(pushed.Payload), `"from":"`+aKey.identity+`"`) {
		t.Fatalf("reconnect = %+v %s / %+v %s", reply, reply.Payload, pushed, pushed.Payload)
	}
	b2.write(t, fmt.Sprintf(`{"type":"accept","id":"c1","payload":{"to":%q,"ephemeral":%q,"confirm":%q}}`, aKey.identity, eph, randomText(protocol.ConfirmSize)))
	if msg := b2.next(t); msg.Type != "accepted" {
		t.Fatalf("accept = %+v %s", msg, msg.Payload)
	}
	if msg := a.next(t); msg.Type != "acceptance" || !strings.Contains(string(msg.Payload), `"from":"`+bKey.identity+`"`) {
		t.Fatalf("acceptance = %+v %s", msg, msg.Payload)
	}
}
