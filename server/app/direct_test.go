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

	"github.com/Xhaann/ghost-x/server/identity"
	"github.com/Xhaann/ghost-x/server/protocol"
)

type peer struct {
	conn      *websocket.Conn
	key       key
	exchange  string
	staticRaw []byte
	signature string
	messages  chan message
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func exchangeRaw(t *testing.T) []byte {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
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
	p := &peer{conn: conn, key: k, exchange: exchange, staticRaw: decoded(exchange), signature: signature, messages: make(chan message, 512)}
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

func joinPeer(t *testing.T, url string, k key, exchange, signature string) *peer {
	t.Helper()
	p := connectPeerWith(t, url, k, exchange, signature)
	deviceID := randomText(protocol.DeviceIDSize)
	signed, _ := signedPrekey(k, p.staticRaw, deviceID, 1, true)
	payload, _ := json.Marshal(map[string]any{"device": deviceID, "signed": signed, "onetime": []any{}})
	p.write(t, fmt.Sprintf(`{"type":"prekeys","id":"p1","payload":%s}`, payload))
	if msg := p.next(t); msg.Type != "prekeys" {
		t.Fatalf("prekeys = %+v %s", msg, msg.Payload)
	}
	return p
}

func (p *peer) write(t *testing.T, frame string) {
	t.Helper()
	if err := p.conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
		t.Fatal(err)
	}
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

func (p *peer) barrier(t *testing.T, id string) []message {
	t.Helper()
	p.write(t, pingRequest(id, 1))
	var before []message
	for {
		msg := p.next(t)
		if msg.Type == "pong" && msg.ID == id {
			return before
		}
		before = append(before, msg)
	}
}

func (p *peer) expect(t *testing.T, typ, id string) {
	t.Helper()
	if msg := p.next(t); msg.Type != typ || msg.ID != id {
		t.Fatalf("result = %+v %s, want %s %s", msg, msg.Payload, typ, id)
	}
}

func (p *peer) expectError(t *testing.T, id, code string) {
	t.Helper()
	if msg := p.next(t); msg.Type != "error" || msg.ID != id || string(msg.Payload) != `{"code":"`+code+`"}` {
		t.Fatalf("result = %+v %s, want error %s %s", msg, msg.Payload, id, code)
	}
}

func mustParse(t *testing.T, encoded string) identity.Identity {
	t.Helper()
	id, err := identity.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func ratchetText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	b[0] = protocol.RatchetVersion
	return base64.RawURLEncoding.EncodeToString(b)
}

func sendFrame(request, to, id, ciphertext string) string {
	return fmt.Sprintf(`{"type":"send","id":%q,"payload":{"to":%q,"id":%q,"ciphertext":%q}}`, request, to, id, ciphertext)
}

type delivery struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Key        string `json:"key"`
	Signature  string `json:"signature"`
	Ciphertext string `json:"ciphertext"`
}

type receipt struct {
	To     string `json:"to"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (p *peer) fetch(t *testing.T, request string) []message {
	t.Helper()
	p.write(t, fmt.Sprintf(`{"type":"fetch","id":%q,"payload":{}}`, request))
	var pushed []message
	for {
		msg := p.next(t)
		if msg.Type == "fetched" && msg.ID == request {
			return pushed
		}
		pushed = append(pushed, msg)
	}
}

func deliveries(t *testing.T, msgs []message) []delivery {
	t.Helper()
	var out []delivery
	for _, m := range msgs {
		if m.Type != "message" {
			continue
		}
		var d delivery
		if err := json.Unmarshal(m.Payload, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func receipts(t *testing.T, msgs []message) []receipt {
	t.Helper()
	var out []receipt
	for _, m := range msgs {
		if m.Type != "receipt" {
			continue
		}
		var r receipt
		if err := json.Unmarshal(m.Payload, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestOfflineDeliveryOverWebSocket(t *testing.T) {
	srv, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	bExchange, bSignature := bundleFor(t, bKey)
	b := joinPeer(t, url, bKey, bExchange, bSignature)
	b.conn.Close()
	a := connectPeer(t, url, aKey)
	a.fetch(t, "fa")
	waitUntil(t, "recipient offline", func() bool { return srv.sessions.Len() == 1 })

	var sent []delivery
	for i := range 5 {
		id, ciphertext := randomText(protocol.MessageIDSize), ratchetText(120+i)
		a.write(t, sendFrame(fmt.Sprintf("s%d", i), bKey.identity, id, ciphertext))
		a.expect(t, "queued", fmt.Sprintf("s%d", i))
		sent = append(sent, delivery{ID: id, From: aKey.identity, Key: a.exchange, Signature: a.signature, Ciphertext: ciphertext})
	}
	if n := srv.queue.Queued(mustParse(t, bKey.identity)); n != 5 {
		t.Fatalf("queued %d", n)
	}

	again := connectPeerWith(t, url, bKey, bExchange, bSignature)
	got := deliveries(t, again.fetch(t, "fb"))
	if len(got) != len(sent) {
		t.Fatalf("delivered %d of %d", len(got), len(sent))
	}
	for i := range sent {
		if got[i] != sent[i] {
			t.Fatalf("delivery %d = %+v, want %+v", i, got[i], sent[i])
		}
	}
	for _, d := range got {
		again.write(t, fmt.Sprintf(`{"type":"ack","id":"a-%s","payload":{"from":%q,"id":%q}}`, d.ID[:8], d.From, d.ID))
		again.expect(t, "acked", "a-"+d.ID[:8])
	}
	if n := srv.queue.Queued(mustParse(t, bKey.identity)); n != 0 {
		t.Fatalf("%d left after acknowledgment", n)
	}
	notes := receipts(t, a.barrier(t, "b1"))
	if len(notes) != len(sent) {
		t.Fatalf("receipts %+v", notes)
	}
	for i, r := range notes {
		if r != (receipt{To: bKey.identity, ID: sent[i].ID, Status: "delivered"}) {
			t.Fatalf("receipt %d = %+v", i, r)
		}
		a.write(t, fmt.Sprintf(`{"type":"clear","id":"c%d","payload":{"to":%q,"id":%q}}`, i, r.To, r.ID))
		a.expect(t, "cleared", fmt.Sprintf("c%d", i))
	}
	if n := srv.queue.Receipts(mustParse(t, aKey.identity)); n != 0 {
		t.Fatalf("%d receipts left", n)
	}
}

func TestUnacknowledgedDeliveryIsRetainedAcrossRecipientCrash(t *testing.T) {
	srv, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	bExchange, bSignature := bundleFor(t, bKey)
	b := joinPeer(t, url, bKey, bExchange, bSignature)
	b.fetch(t, "f0")
	a := connectPeer(t, url, aKey)
	id, ciphertext := randomText(protocol.MessageIDSize), ratchetText(150)
	a.write(t, sendFrame("s1", bKey.identity, id, ciphertext))
	a.expect(t, "queued", "s1")
	if got := deliveries(t, b.barrier(t, "p1")); len(got) != 1 || got[0].ID != id {
		t.Fatalf("live delivery %+v", got)
	}
	b.conn.Close()
	waitUntil(t, "crashed recipient detached", func() bool { return srv.sessions.Len() == 1 })
	if n := srv.queue.Queued(mustParse(t, bKey.identity)); n != 1 {
		t.Fatalf("transmitted message lost after crash: %d", n)
	}
	again := connectPeerWith(t, url, bKey, bExchange, bSignature)
	got := deliveries(t, again.fetch(t, "f1"))
	if len(got) != 1 || got[0].ID != id || got[0].Ciphertext != ciphertext {
		t.Fatalf("redelivery %+v", got)
	}
	again.write(t, fmt.Sprintf(`{"type":"ack","id":"a1","payload":{"from":%q,"id":%q}}`, aKey.identity, id))
	again.expect(t, "acked", "a1")
	again.write(t, fmt.Sprintf(`{"type":"ack","id":"a2","payload":{"from":%q,"id":%q}}`, aKey.identity, id))
	again.expect(t, "acked", "a2")
	if got := receipts(t, a.barrier(t, "p2")); len(got) != 0 {
		t.Fatalf("sender not subscribed but received %+v", got)
	}
	notes := receipts(t, a.fetch(t, "fa"))
	if len(notes) != 1 || notes[0].ID != id || notes[0].Status != "delivered" {
		t.Fatalf("stored receipt %+v", notes)
	}
}

func TestQueueIsMemoryOnlyAcrossServerRestart(t *testing.T) {
	srv, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	bExchange, bSignature := bundleFor(t, bKey)
	joinPeer(t, url, bKey, bExchange, bSignature).conn.Close()
	a := connectPeer(t, url, aKey)
	a.write(t, sendFrame("s1", bKey.identity, randomText(protocol.MessageIDSize), ratchetText(100)))
	a.expect(t, "queued", "s1")
	if n := srv.queue.Queued(mustParse(t, bKey.identity)); n != 1 {
		t.Fatalf("queued %d", n)
	}
	_, restarted := startServer(t)
	b := joinPeer(t, restarted, bKey, bExchange, bSignature)
	if got := deliveries(t, b.fetch(t, "f1")); len(got) != 0 {
		t.Fatalf("restarted server delivered %+v", got)
	}
}

func TestSendValidationOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	bExchange, bSignature := bundleFor(t, bKey)
	joinPeer(t, url, bKey, bExchange, bSignature)
	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, sendFrame("m1", bKey.identity, randomText(16), ratchetText(100))), "authentication_required")
	authenticateConn(t, conn, aKey)
	expectError(t, roundTrip(t, conn, sendFrame("m2", bKey.identity, randomText(16), ratchetText(100))), "key_required")
	a := connectPeer(t, url, aKey)
	a.write(t, sendFrame("m3", bKey.identity, randomText(16), base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("plaintext ", 12)))))
	a.expectError(t, "m3", "invalid_payload")
	a.write(t, sendFrame("m4", newKey(t).identity, randomText(16), ratchetText(100)))
	a.expectError(t, "m4", "recipient_unavailable")
	a.write(t, `{"type":"session","id":"m5","payload":{}}`)
	a.expectError(t, "m5", "unsupported_type")
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	a.write(t, sendFrame("m1", a.key.identity, randomText(16), strings.Repeat("A", 40<<10)))
	select {
	case _, ok := <-a.messages:
		if ok {
			t.Fatal("oversized frame was processed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized frame did not close the connection")
	}
}

func TestReconnectStormDeliversEveryMessage(t *testing.T) {
	srv, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	bExchange, bSignature := bundleFor(t, bKey)
	joinPeer(t, url, bKey, bExchange, bSignature).conn.Close()
	a := connectPeer(t, url, aKey)
	const total = 60
	ids := make([]string, total)
	for i := range ids {
		ids[i] = randomText(protocol.MessageIDSize)
	}
	received := map[string]int{}
	var wg sync.WaitGroup
	var writeErr error
	wg.Go(func() {
		for i, id := range ids {
			if err := a.conn.WriteMessage(websocket.TextMessage, []byte(sendFrame(fmt.Sprintf("s%d", i), bKey.identity, id, ratchetText(100)))); err != nil {
				writeErr = err
				return
			}
		}
	})
	for round := range 15 {
		b := connectPeerWith(t, url, bKey, bExchange, bSignature)
		for _, d := range deliveries(t, b.fetch(t, fmt.Sprintf("f%d", round))) {
			received[d.ID]++
			if round%2 == 0 {
				b.write(t, fmt.Sprintf(`{"type":"ack","id":"a","payload":{"from":%q,"id":%q}}`, d.From, d.ID))
			}
		}
		b.conn.Close()
	}
	wg.Wait()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	for i := range ids {
		a.expect(t, "queued", fmt.Sprintf("s%d", i))
	}
	for range 40 {
		if srv.queue.Queued(mustParse(t, bKey.identity)) == 0 {
			break
		}
		b := connectPeerWith(t, url, bKey, bExchange, bSignature)
		pending := deliveries(t, b.fetch(t, "drain"))
		for round := 0; len(pending) > 0; round++ {
			for _, d := range pending {
				received[d.ID]++
				b.write(t, fmt.Sprintf(`{"type":"ack","id":"a-%s","payload":{"from":%q,"id":%q}}`, d.ID[:6], d.From, d.ID))
			}
			pending = deliveries(t, b.barrier(t, fmt.Sprintf("d%d", round)))
		}
		b.conn.Close()
	}
	if n := srv.queue.Queued(mustParse(t, bKey.identity)); n != 0 {
		t.Fatalf("%d messages stranded", n)
	}
	if len(received) != total {
		t.Fatalf("received %d distinct of %d", len(received), total)
	}
	for _, id := range ids {
		if received[id] == 0 {
			t.Fatalf("message %s never delivered", id)
		}
	}
	if used, bytes, _ := srv.queue.Usage(); used != 0 || bytes != 0 {
		t.Fatalf("queue usage %d %d", used, bytes)
	}
}
