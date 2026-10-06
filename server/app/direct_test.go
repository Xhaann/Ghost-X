package app

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Xhaann/ghost-x/server/protocol"
)

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

type peer struct {
	conn      *websocket.Conn
	key       key
	exchange  string
	staticRaw []byte
	signature string
	keys      wireSession
	messages  chan message
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func exchangeRaw(t *testing.T) []byte {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private.PublicKey().Bytes()
}

func decoded(text string) []byte {
	raw, _ := base64.RawURLEncoding.DecodeString(text)
	return raw
}

func bundleFor(t *testing.T, k key) (string, string) {
	t.Helper()
	raw := exchangeRaw(t)
	signature := ed25519.Sign(k.private, protocol.KeyMessage(k.identity, raw))
	return base64.RawURLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(signature)
}

func sessionFor(t *testing.T, k key, staticRaw []byte, id string, epoch uint32) wireSession {
	t.Helper()
	raw := exchangeRaw(t)
	message := protocol.SessionMessage(decoded(k.identity), staticRaw, decoded(id), epoch, raw)
	return wireSession{
		Session:   id,
		Epoch:     epoch,
		Key:       base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, message)),
	}
}

func sessionFrame(id string, s wireSession) string {
	payload, _ := json.Marshal(s)
	return fmt.Sprintf(`{"type":"session","id":%q,"payload":%s}`, id, payload)
}

func connectPeer(t *testing.T, url string, k key) *peer {
	t.Helper()
	exchange, signature := bundleFor(t, k)
	return connectPeerWith(t, url, k, exchange, signature)
}

func connectPeerWith(t *testing.T, url string, k key, exchange, signature string) *peer {
	t.Helper()
	conn := dialApp(t, url)
	authenticateConn(t, conn, k)
	publish := fmt.Sprintf(`{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, exchange, signature)
	if msg := roundTrip(t, conn, publish); msg.Type != "published" {
		t.Fatalf("publish = %+v %s", msg, msg.Payload)
	}
	staticRaw := decoded(exchange)
	keys := sessionFor(t, k, staticRaw, randomText(protocol.SessionIDSize), 0)
	if msg := roundTrip(t, conn, sessionFrame("s0", keys)); msg.Type != "established" {
		t.Fatalf("session = %+v %s", msg, msg.Payload)
	}
	p := &peer{conn: conn, key: k, exchange: exchange, staticRaw: staticRaw, signature: signature, keys: keys, messages: make(chan message, 512)}
	go func() {
		defer close(p.messages)
		conn.SetReadDeadline(time.Time{})
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg message
			if json.Unmarshal(data, &msg) != nil {
				return
			}
			p.messages <- msg
		}
	}()
	return p
}

func (p *peer) rotate(t *testing.T) {
	t.Helper()
	next := sessionFor(t, p.key, p.staticRaw, p.keys.Session, p.keys.Epoch+1)
	id := fmt.Sprintf("r%d", next.Epoch)
	p.write(t, sessionFrame(id, next))
	if msg := p.next(t); msg.Type != "established" || msg.ID != id {
		t.Fatalf("rotate = %+v %s", msg, msg.Payload)
	}
	p.keys = next
}

func envelopeFor(s wireSession, n int) wireEnvelope {
	return wireEnvelope{Session: s.Session, Epoch: s.Epoch, Salt: randomText(protocol.SaltSize), IV: randomText(protocol.IVSize), Ciphertext: randomText(n)}
}

func sendFrame(id, to string, epoch uint32, envelopes ...wireEnvelope) string {
	payload, _ := json.Marshal(map[string]any{"to": to, "epoch": epoch, "envelopes": envelopes})
	return fmt.Sprintf(`{"type":"send","id":%q,"payload":%s}`, id, payload)
}

func (p *peer) write(t *testing.T, frame string) {
	t.Helper()
	if err := p.conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
		t.Fatal(err)
	}
}

func (p *peer) send(t *testing.T, id, to string, envelopes ...wireEnvelope) {
	t.Helper()
	p.write(t, sendFrame(id, to, p.keys.Epoch, envelopes...))
}

func (p *peer) next(t *testing.T) message {
	t.Helper()
	select {
	case msg, ok := <-p.messages:
		if !ok {
			t.Fatal("connection closed")
		}
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for message")
	}
	return message{}
}

func (p *peer) expectSent(t *testing.T, id string) {
	t.Helper()
	if msg := p.next(t); msg.Type != "sent" || msg.ID != id || string(msg.Payload) != `{}` {
		t.Fatalf("result = %+v %s, want sent %s", msg, msg.Payload, id)
	}
}

func (p *peer) expectError(t *testing.T, id, code string) {
	t.Helper()
	if msg := p.next(t); msg.Type != "error" || msg.ID != id || string(msg.Payload) != `{"code":"`+code+`"}` {
		t.Fatalf("result = %+v %s, want error %s %s", msg, msg.Payload, id, code)
	}
}

func deliveryJSON(id string, from *peer, sender wireSession, e wireEnvelope) string {
	s, _ := json.Marshal(sender)
	env, _ := json.Marshal(e)
	return `{"id":"` + id + `","from":"` + from.key.identity + `","key":"` + from.exchange + `","signature":"` + from.signature + `","sender":` + string(s) + `,"envelope":` + string(env) + `}`
}

func (p *peer) expectDelivery(t *testing.T, id string, from *peer, sender wireSession, e wireEnvelope) {
	t.Helper()
	msg := p.next(t)
	if msg.Type != "message" || msg.ID != "" || string(msg.Payload) != deliveryJSON(id, from, sender, e) {
		t.Fatalf("delivery = %+v %s", msg, msg.Payload)
	}
}

func (p *peer) barrier(t *testing.T, id string) {
	t.Helper()
	p.write(t, pingRequest(id, 1))
	if msg := p.next(t); msg.Type != "pong" || msg.ID != id {
		t.Fatalf("barrier = %+v, want pong %s", msg, id)
	}
}

func TestEncryptedEnvelopeRoutedToRecipientSession(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	first, second := envelopeFor(b.keys, 48), envelopeFor(a.keys, 64)
	a.send(t, "m1", b.key.identity, first)
	a.expectSent(t, "m1")
	b.expectDelivery(t, "m1", a, a.keys, first)

	b.send(t, "m2", a.key.identity, second)
	b.expectSent(t, "m2")
	a.expectDelivery(t, "m2", b, b.keys, second)
}

func TestKeyLookupListsLiveSessionsOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))
	b.rotate(t)

	a.write(t, `{"type":"key","id":"q1","payload":{"identity":"`+b.key.identity+`"}}`)
	msg := a.next(t)
	sessions, _ := json.Marshal([]wireSession{b.keys})
	want := `{"identity":"` + b.key.identity + `","key":"` + b.exchange + `","signature":"` + b.signature + `","sessions":` + string(sessions) + `}`
	if msg.Type != "key" || msg.ID != "q1" || string(msg.Payload) != want {
		t.Fatalf("key = %+v %s", msg, msg.Payload)
	}
}

func TestPlaintextAndStaticKeyFormatRejectedOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	a.write(t, `{"type":"send","id":"p1","payload":{"to":"`+b.key.identity+`","body":"plaintext secret"}}`)
	a.expectError(t, "p1", "invalid_payload")
	e := envelopeFor(b.keys, 32)
	a.write(t, `{"type":"send","id":"p2","payload":{"to":"`+b.key.identity+`","salt":"`+e.Salt+`","iv":"`+e.IV+`","ciphertext":"`+e.Ciphertext+`"}}`)
	a.expectError(t, "p2", "invalid_payload")
	b.barrier(t, "b1")
}

func TestEachRecipientSessionReceivesOnlyItsEnvelope(t *testing.T) {
	_, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	aExchange, aSignature := bundleFor(t, aKey)
	bExchange, bSignature := bundleFor(t, bKey)
	a := connectPeerWith(t, url, aKey, aExchange, aSignature)
	aOther := connectPeerWith(t, url, aKey, aExchange, aSignature)
	b1 := connectPeerWith(t, url, bKey, bExchange, bSignature)
	b2 := connectPeerWith(t, url, bKey, bExchange, bSignature)
	if b1.keys.Session == b2.keys.Session || a.keys.Session == aOther.keys.Session {
		t.Fatal("sessions share an identifier")
	}

	e1, e2 := envelopeFor(b1.keys, 40), envelopeFor(b2.keys, 41)
	a.send(t, "m1", bKey.identity, e1, e2)
	a.expectSent(t, "m1")
	b1.expectDelivery(t, "m1", a, a.keys, e1)
	b2.expectDelivery(t, "m1", a, a.keys, e2)

	a.send(t, "m2", bKey.identity, envelopeFor(b1.keys, 42))
	a.expectSent(t, "m2")
	b1.next(t)
	for i, p := range []*peer{b1, b2, a, aOther} {
		p.barrier(t, fmt.Sprintf("p%d", i))
	}
}

func TestMaximumMultiSessionSendFitsFrameLimit(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	bKey := newKey(t)
	exchange, signature := bundleFor(t, bKey)
	var bs []*peer
	var envelopes []wireEnvelope
	for range 4 {
		b := connectPeerWith(t, url, bKey, exchange, signature)
		bs = append(bs, b)
		envelopes = append(envelopes, envelopeFor(b.keys, protocol.MaxCiphertext))
	}
	a.send(t, "big", bKey.identity, envelopes...)
	a.expectSent(t, "big")
	for i, b := range bs {
		b.expectDelivery(t, "big", a, a.keys, envelopes[i])
	}
	conn := dialApp(t, url)
	authenticateConn(t, conn, bKey)
	if msg := roundTrip(t, conn, fmt.Sprintf(`{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, exchange, signature)); msg.Type != "published" {
		t.Fatal(msg)
	}
	expectError(t, roundTrip(t, conn, sessionFrame("s0", sessionFor(t, bKey, decoded(exchange), randomText(protocol.SessionIDSize), 0))), "session_limit")
}

func TestRotationOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))
	first := b.keys
	b.rotate(t)
	previous := b.keys
	b.rotate(t)

	a.send(t, "m1", b.key.identity, envelopeFor(first, 32))
	a.expectError(t, "m1", "recipient_unavailable")
	e := envelopeFor(previous, 32)
	a.send(t, "m2", b.key.identity, e)
	a.expectSent(t, "m2")
	b.expectDelivery(t, "m2", a, a.keys, e)

	senderFirst := a.keys
	a.rotate(t)
	a.rotate(t)
	a.write(t, sendFrame("m3", b.key.identity, senderFirst.Epoch, envelopeFor(b.keys, 32)))
	a.expectError(t, "m3", "stale_session")
	a.write(t, sessionFrame("bad", sessionFor(t, a.key, a.staticRaw, a.keys.Session, a.keys.Epoch)))
	a.expectError(t, "bad", "stale_session")
	current := envelopeFor(b.keys, 32)
	a.send(t, "m4", b.key.identity, current)
	a.expectSent(t, "m4")
	b.expectDelivery(t, "m4", a, a.keys, current)
}

func TestSecondSessionCannotBindDifferentKey(t *testing.T) {
	_, url := startServer(t)
	bKey := newKey(t)
	connectPeer(t, url, bKey)

	conn := dialApp(t, url)
	authenticateConn(t, conn, bKey)
	exchange, signature := bundleFor(t, bKey)
	expectError(t, roundTrip(t, conn, fmt.Sprintf(`{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, exchange, signature)), "invalid_payload")
}

func TestEncryptedSendFailures(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))
	c := newKey(t)

	a.send(t, "m1", c.identity, envelopeFor(b.keys, 32))
	a.expectError(t, "m1", "recipient_unavailable")

	e := envelopeFor(b.keys, 32)
	a.send(t, "m2", b.key.identity, e)
	a.expectSent(t, "m2")
	a.send(t, "m2", b.key.identity, e)
	a.expectError(t, "m2", "duplicate_message")
	b.expectDelivery(t, "m2", a, a.keys, e)
	b.barrier(t, "b1")

	env, _ := json.Marshal(e)
	a.write(t, `{"type":"send","id":"m3","payload":{"to":"`+b.key.identity+`","from":"`+c.identity+`","epoch":0,"envelopes":[`+string(env)+`]}}`)
	a.expectError(t, "m3", "invalid_payload")
	a.write(t, `{"type":"send","id":"m6","payload":{"to":"`+b.key.identity+`","epoch":0,"envelopes":[`+string(env)+`],"sender":{}}}`)
	a.expectError(t, "m6", "invalid_payload")

	a.send(t, "m4", b.key.identity, envelopeFor(b.keys, protocol.MaxCiphertext+1))
	a.expectError(t, "m4", "message_too_large")
	big := envelopeFor(b.keys, protocol.MaxCiphertext)
	a.send(t, "m5", b.key.identity, big)
	a.expectSent(t, "m5")
	b.expectDelivery(t, "m5", a, a.keys, big)
}

func TestEncryptedSendRequiresAuthenticationAndSession(t *testing.T) {
	_, url := startServer(t)
	b := connectPeer(t, url, newKey(t))
	aKey := newKey(t)

	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, sendFrame("m1", b.key.identity, 0, envelopeFor(b.keys, 32))), "authentication_required")
	expectError(t, roundTrip(t, conn, sessionFrame("s1", sessionFor(t, aKey, exchangeRaw(t), randomText(protocol.SessionIDSize), 0))), "authentication_required")
	authenticateConn(t, conn, aKey)
	expectError(t, roundTrip(t, conn, sendFrame("m2", b.key.identity, 0, envelopeFor(b.keys, 32))), "key_required")
	exchange, signature := bundleFor(t, aKey)
	if msg := roundTrip(t, conn, fmt.Sprintf(`{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, exchange, signature)); msg.Type != "published" {
		t.Fatal(msg)
	}
	expectError(t, roundTrip(t, conn, sendFrame("m3", b.key.identity, 0, envelopeFor(b.keys, 32))), "key_required")
	b.barrier(t, "b1")
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	huge := envelopeFor(a.keys, 1)
	huge.Ciphertext = strings.Repeat("A", 40<<10)
	a.write(t, sendFrame("m1", a.key.identity, 0, huge))
	select {
	case _, ok := <-a.messages:
		if ok {
			t.Fatal("oversized frame was processed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized frame did not close the connection")
	}
}

func TestReconnectRequiresFreshSession(t *testing.T) {
	_, url := startServer(t)
	aKey := newKey(t)
	exchange, signature := bundleFor(t, aKey)
	b := connectPeer(t, url, newKey(t))
	first := connectPeerWith(t, url, aKey, exchange, signature)
	old := first.keys
	first.conn.Close()
	waitUntil(t, "old session removed", func() bool {
		b.write(t, `{"type":"key","id":"q","payload":{"identity":"`+aKey.identity+`"}}`)
		msg := b.next(t)
		return msg.Type == "error"
	})

	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, sendFrame("m1", b.key.identity, 0, envelopeFor(b.keys, 32))), "authentication_required")
	authenticateConn(t, conn, aKey)
	expectError(t, roundTrip(t, conn, sendFrame("m2", b.key.identity, 0, envelopeFor(b.keys, 32))), "key_required")
	if msg := roundTrip(t, conn, fmt.Sprintf(`{"type":"publish","id":"k1","payload":{"key":%q,"signature":%q}}`, exchange, signature)); msg.Type != "published" {
		t.Fatal(msg)
	}
	expectError(t, roundTrip(t, conn, sessionFrame("s1", sessionFor(t, aKey, decoded(exchange), randomText(protocol.SessionIDSize), 1))), "stale_session")
	fresh := sessionFor(t, aKey, decoded(exchange), randomText(protocol.SessionIDSize), 0)
	if msg := roundTrip(t, conn, sessionFrame("s2", fresh)); msg.Type != "established" {
		t.Fatal(msg)
	}
	b.send(t, "to-old", aKey.identity, envelopeFor(old, 32))
	b.expectError(t, "to-old", "recipient_unavailable")
}

func TestConcurrentEncryptedMessagingWithRotation(t *testing.T) {
	_, url := startServer(t)
	const peers = 5
	const perPair = 8
	all := make([]*peer, peers)
	for i := range all {
		all[i] = connectPeer(t, url, newKey(t))
	}
	targets := make([]wireSession, peers)
	for i, p := range all {
		targets[i] = p.keys
	}

	var wg sync.WaitGroup
	for i, sender := range all {
		wg.Go(func() {
			n := 0
			for j := range all {
				if i == j {
					continue
				}
				for range perPair {
					n++
					sender.write(t, sendFrame(fmt.Sprintf("m%d", n), all[j].key.identity, 0, envelopeFor(targets[j], 24)))
				}
			}
			for epoch := uint32(1); epoch <= 3; epoch++ {
				sender.write(t, sessionFrame(fmt.Sprintf("r%d", epoch), sessionFor(t, sender.key, sender.staticRaw, targets[i].Session, epoch)))
			}
		})
	}
	wg.Wait()

	for _, p := range all {
		results, rotations, received := 0, 0, 0
		for results < (peers-1)*perPair || rotations < 3 {
			msg := p.next(t)
			switch msg.Type {
			case "sent":
				results++
			case "error":
				if string(msg.Payload) != `{"code":"recipient_unavailable"}` {
					t.Fatalf("unexpected error %s", msg.Payload)
				}
				results++
			case "established":
				rotations++
			case "message":
				received++
				var payload struct {
					From     string       `json:"from"`
					Envelope wireEnvelope `json:"envelope"`
				}
				json.Unmarshal(msg.Payload, &payload)
				if payload.From == p.key.identity || payload.Envelope.Session != p.keys.Session {
					t.Fatalf("misrouted %s", msg.Payload)
				}
			default:
				t.Fatalf("unexpected %+v %s", msg, msg.Payload)
			}
		}
	}
}

func TestRecipientDisconnectDuringEncryptedDelivery(t *testing.T) {
	srv, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	bKey := newKey(t)
	exchange, signature := bundleFor(t, bKey)

	for i := range 20 {
		b := connectPeerWith(t, url, bKey, exchange, signature)
		var wg sync.WaitGroup
		wg.Go(func() { a.send(t, fmt.Sprintf("m%d", i), bKey.identity, envelopeFor(b.keys, 24)) })
		wg.Go(func() { b.conn.Close() })
		wg.Wait()
		msg := a.next(t)
		if msg.Type != "sent" && string(msg.Payload) != `{"code":"recipient_unavailable"}` {
			t.Fatalf("result = %+v %s", msg, msg.Payload)
		}
	}
	waitUntil(t, "recipient sessions removed", func() bool { return srv.sessions.Len() == 1 })
}
