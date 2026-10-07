package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/device/devicetest"
	"github.com/Xhaann/ghost-x/server/protocol"
)

func signedPrekey(k key, id uint32, signed bool) (map[string]any, []byte) {
	raw := exchangeRaw(nil)
	build := protocol.OnetimePrekeyMessage
	if signed {
		build = protocol.SignedPrekeyMessage
	}
	signature := k.device.Sign(build(decoded(k.identity), k.device.IDRaw, k.device.ExchangeRaw, id, raw))
	return map[string]any{"id": id, "key": base64.RawURLEncoding.EncodeToString(raw), "signature": signature}, raw
}

func TestAsynchronousInitiationWaitsForTheRecipientDevice(t *testing.T) {
	_, url := startServer(t)
	aKey := newKey(t)
	bKeys := siblingKeys(t, 2)
	bKey := bKeys[0]
	b := connectPeer(t, url, bKey)
	signed, signedRaw := signedPrekey(bKey, 1, true)
	onetime, onetimeRaw := signedPrekey(bKey, 5, false)
	publish, _ := json.Marshal(map[string]any{"device": bKey.device.ID, "signed": signed, "onetime": []any{onetime}})
	b.write(t, `{"type":"prekeys","id":"p1","payload":`+string(publish)+`}`)
	if msg := b.next(t); msg.Type != "prekeys" || string(msg.Payload) != `{"available":1}` {
		t.Fatalf("prekeys = %+v %s", msg, msg.Payload)
	}
	b.conn.Close()
	sibling := connectPeer(t, url, bKeys[1])

	a := connectPeer(t, url, aKey)
	a.write(t, `{"type":"bundle","id":"q1","payload":{"identity":"`+bKey.identity+`"}}`)
	bundle := a.next(t)
	if bundle.Type != "bundle" || !strings.Contains(string(bundle.Payload), `"device":"`+bKey.device.ID+`"`) || !strings.Contains(string(bundle.Payload), `"onetime":{"id":5,`) {
		t.Fatalf("bundle = %+v %s", bundle, bundle.Payload)
	}
	ephemeral := exchangeRaw(t)
	ratchet := exchangeRaw(t)
	id := uint32(5)
	tr := protocol.Transcript{
		Initiator: decoded(aKey.identity), InitiatorDevice: aKey.device.IDRaw,
		Responder: decoded(bKey.identity), ResponderDevice: bKey.device.IDRaw,
		InitiatorStatic: aKey.device.ExchangeRaw, ResponderStatic: bKey.device.ExchangeRaw,
		Signed: 1, SignedKey: signedRaw,
		Onetime: &id, OnetimeKey: onetimeRaw, Ephemeral: ephemeral, Ratchet: ratchet,
	}
	proof := aKey.device.Sign(protocol.ProofMessage(tr))
	eph := base64.RawURLEncoding.EncodeToString(ephemeral)
	confirm := randomText(protocol.ConfirmSize)
	initiate := fmt.Sprintf(`{"type":"initiate","id":"i1","payload":{"version":3,"to":%q,"device":%q,"signed":1,"onetime":5,"ephemeral":%q,"ratchet":%q,"proof":%q,"confirm":%q}}`, bKey.identity, bKey.device.ID, eph, base64.RawURLEncoding.EncodeToString(ratchet), proof, confirm)
	a.write(t, initiate)
	if msg := a.next(t); msg.Type != "initiated" {
		t.Fatalf("initiate = %+v %s", msg, msg.Payload)
	}
	a.write(t, strings.Replace(initiate, `"id":"i1"`, `"id":"i2"`, 1))
	if msg := a.next(t); msg.Type != "error" || string(msg.Payload) != `{"code":"stale_session"}` {
		t.Fatalf("replayed initiation = %+v %s", msg, msg.Payload)
	}
	if leaked := sibling.barrier(t, "s1"); len(leaked) != 0 {
		t.Fatalf("sibling device received %v", leaked)
	}

	b2 := connectPeer(t, url, bKey)
	b2.write(t, `{"type":"prekeys","id":"p2","payload":`+string(publish)+`}`)
	reply, pushed := b2.next(t), b2.next(t)
	if reply.Type == "initiation" {
		reply, pushed = pushed, reply
	}
	if reply.Type != "prekeys" || pushed.Type != "initiation" || !strings.Contains(string(pushed.Payload), `"ephemeral":"`+eph+`"`) || !strings.Contains(string(pushed.Payload), `"from":"`+aKey.identity+`","device":"`+aKey.device.ID+`"`) {
		t.Fatalf("reconnect = %+v %s / %+v %s", reply, reply.Payload, pushed, pushed.Payload)
	}
	b2.write(t, fmt.Sprintf(`{"type":"accept","id":"c1","payload":{"to":%q,"device":%q,"ephemeral":%q,"confirm":%q}}`, aKey.identity, aKey.device.ID, eph, randomText(protocol.ConfirmSize)))
	if msg := b2.next(t); msg.Type != "accepted" {
		t.Fatalf("accept = %+v %s", msg, msg.Payload)
	}
	if msg := a.next(t); msg.Type != "acceptance" || !strings.Contains(string(msg.Payload), `"from":"`+bKey.identity+`","device":"`+bKey.device.ID+`"`) {
		t.Fatalf("acceptance = %+v %s", msg, msg.Payload)
	}
}

func TestRevocationDisconnectsAndBlocksTheDevice(t *testing.T) {
	srv, url := startServer(t)
	keys := siblingKeys(t, 2)
	keep, gone := keys[0], keys[1]
	a := joinPeer(t, url, keep)
	b := joinPeer(t, url, gone)
	b.fetch(t, "f0")
	sender := connectPeer(t, url, newKey(t))
	sender.write(t, sendFrame("s1", gone.identity, randomText(protocol.MessageIDSize), envelope(gone, ratchetText(100))))
	sender.expect(t, "queued", "s1")
	if got := deliveries(t, b.barrier(t, "p1")); len(got) != 1 {
		t.Fatalf("pre-revocation delivery %+v", got)
	}

	register(t, dialApp(t, url), keep.owner.Remove(gone.device))
	select {
	case _, ok := <-b.messages:
		for ok {
			_, ok = <-b.messages
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked device connection not closed")
	}
	if srv.devices.Authorized(gone.identity, gone.device.ID) {
		t.Fatal("revoked device still authorized")
	}
	if n := srv.queue.Queued(queueAddress(gone)); n != 0 {
		t.Fatalf("revoked device queue retained %d", n)
	}

	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, authenticateRequest(gone, challenge(t, conn))), "authentication_failed")
	expectError(t, roundTrip(t, conn, rosterFrame(gone.owner.Sign(1, []*devicetest.Device{keep.device, gone.device}))), "stale_roster")

	sender.write(t, sendFrame("s2", gone.identity, randomText(protocol.MessageIDSize), envelope(gone, ratchetText(100))))
	sender.expectError(t, "s2", "stale_devices")
	sender.write(t, sendFrame("s3", keep.identity, randomText(protocol.MessageIDSize), envelope(keep, ratchetText(100))))
	sender.expect(t, "queued", "s3")
	a.fetch(t, "f1")
	if msg := roundTrip(t, dialApp(t, url), `{"type":"devices","id":"d1","payload":{"identity":"`+keep.identity+`"}}`); msg.Type != "devices" || strings.Contains(string(msg.Payload), gone.device.ID) {
		t.Fatalf("roster after revocation = %s", msg.Payload)
	}
	a.write(t, pingRequest("still", 1))
	for msg := a.next(t); msg.Type != "pong"; msg = a.next(t) {
	}
}

func TestRevocationSurvivesServerRestart(t *testing.T) {
	cfg := testConfig()
	cfg.DeviceStore = filepath.Join(t.TempDir(), "devices.json")
	keys := siblingKeys(t, 2)
	first := startServerWith(t, cfg)
	conn := dialApp(t, first)
	register(t, conn, keys[0].roster)
	revoked := keys[0].owner.Remove(keys[1].device)
	register(t, conn, revoked)

	second := startServerWith(t, cfg)
	c := dialApp(t, second)
	expectError(t, roundTrip(t, c, rosterFrame(keys[0].roster)), "stale_roster")
	expectError(t, roundTrip(t, c, authenticateRequest(keys[1], challenge(t, c))), "authentication_failed")
	d := dialApp(t, second)
	if msg := roundTrip(t, d, authenticateRequest(keys[0], challenge(t, d))); msg.Type != "authenticated" {
		t.Fatalf("remaining device after restart = %+v %s", msg, msg.Payload)
	}
}

func TestUnregisteredDevicesCannotAuthenticate(t *testing.T) {
	_, url := startServer(t)
	k := newKey(t)
	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, authenticateRequest(k, challenge(t, conn))), "authentication_failed")
	other := newKey(t)
	forged := other.owner.Sign(1, []*devicetest.Device{k.device})
	expectError(t, roundTrip(t, conn, rosterFrame(forged)), "invalid_payload")
	expectError(t, roundTrip(t, conn, authenticateRequest(k, challenge(t, conn))), "authentication_failed")
}
