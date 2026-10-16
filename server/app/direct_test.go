package app

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Xhaann/ghost-x/server/config"
	"github.com/Xhaann/ghost-x/server/protocol"
	"github.com/Xhaann/ghost-x/server/queue"
)

type peer struct {
	conn     *websocket.Conn
	frame    func([]byte) error
	key      key
	messages chan message
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

func startServerWith(t *testing.T, cfg config.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return "ws://" + ln.Addr().String() + "/ws"
}

func connectPeer(t *testing.T, url string, k key) *peer {
	t.Helper()
	conn := dialApp(t, url)
	authenticateConn(t, conn, k)
	p := &peer{conn: conn, key: k, messages: make(chan message, 512)}
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

func joinPeer(t *testing.T, url string, k key) *peer {
	t.Helper()
	p := connectPeer(t, url, k)
	signed, _ := signedPrekey(k, 1, true)
	payload, _ := json.Marshal(map[string]any{"device": k.device.ID, "signed": signed, "onetime": []any{}})
	p.write(t, fmt.Sprintf(`{"type":"prekeys","id":"p1","payload":%s}`, payload))
	if msg := p.next(t); msg.Type != "prekeys" {
		t.Fatalf("prekeys = %+v %s", msg, msg.Payload)
	}
	return p
}

func (p *peer) write(t *testing.T, frame string) {
	t.Helper()
	send := p.frame
	if send == nil {
		send = func(data []byte) error { return p.conn.WriteMessage(websocket.TextMessage, data) }
	}
	if err := send([]byte(frame)); err != nil {
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

func ratchetText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	b[0] = protocol.RatchetVersion
	return base64.RawURLEncoding.EncodeToString(b)
}

func envelope(to key, ciphertext string) string {
	return fmt.Sprintf(`{"device":%q,"ciphertext":%q}`, to.device.ID, ciphertext)
}

func sendFrame(request, to, id string, envelopes ...string) string {
	return fmt.Sprintf(`{"type":"send","id":%q,"payload":{"to":%q,"id":%q,"envelopes":[%s]}}`, request, to, id, strings.Join(envelopes, ","))
}

func ackFrame(request string, d delivery) string {
	return fmt.Sprintf(`{"type":"ack","id":%q,"payload":{"from":%q,"device":%q,"id":%q}}`, request, d.From, d.Device, d.ID)
}

func queueAddress(k key) string {
	return queue.Address(k.identity, k.device.ID)
}

type delivery struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Device     string `json:"device"`
	Ciphertext string `json:"ciphertext"`
}

type receipt struct {
	To     string `json:"to"`
	Device string `json:"device"`
	ID     string `json:"id"`
	Status string `json:"status"`
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
	b := joinPeer(t, url, bKey)
	b.conn.Close()
	a := connectPeer(t, url, aKey)
	a.fetch(t, "fa")
	waitUntil(t, "recipient offline", func() bool { return srv.sessions.Len() == 1 })

	var sent []delivery
	for i := range 5 {
		id, ciphertext := randomText(protocol.MessageIDSize), ratchetText(120+i)
		a.write(t, sendFrame(fmt.Sprintf("s%d", i), bKey.identity, id, envelope(bKey, ciphertext)))
		a.expect(t, "queued", fmt.Sprintf("s%d", i))
		sent = append(sent, delivery{ID: id, From: aKey.identity, Device: aKey.device.ID, Ciphertext: ciphertext})
	}
	if n := srv.queue.Queued(queueAddress(bKey)); n != 5 {
		t.Fatalf("queued %d", n)
	}

	again := connectPeer(t, url, bKey)
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
		again.write(t, ackFrame("a-"+d.ID[:8], d))
		again.expect(t, "acked", "a-"+d.ID[:8])
	}
	if n := srv.queue.Queued(queueAddress(bKey)); n != 0 {
		t.Fatalf("%d left after acknowledgment", n)
	}
	notes := receipts(t, a.barrier(t, "b1"))
	if len(notes) != len(sent) {
		t.Fatalf("receipts %+v", notes)
	}
	for i, r := range notes {
		if r != (receipt{To: bKey.identity, Device: bKey.device.ID, ID: sent[i].ID, Status: "delivered"}) {
			t.Fatalf("receipt %d = %+v", i, r)
		}
		a.write(t, fmt.Sprintf(`{"type":"clear","id":"c%d","payload":{"to":%q,"device":%q,"id":%q}}`, i, r.To, r.Device, r.ID))
		a.expect(t, "cleared", fmt.Sprintf("c%d", i))
	}
	if n := srv.queue.Receipts(queueAddress(aKey)); n != 0 {
		t.Fatalf("%d receipts left", n)
	}
}

func TestMixedOnlineAndOfflineRecipientDevices(t *testing.T) {
	srv, url := startServer(t)
	aKeys := siblingKeys(t, 2)
	bKeys := siblingKeys(t, 3)
	a0 := connectPeer(t, url, aKeys[0])
	a1 := connectPeer(t, url, aKeys[1])
	a0.fetch(t, "fa0")
	a1.fetch(t, "fa1")
	online := connectPeer(t, url, bKeys[0])
	online.fetch(t, "f0")
	revoked := connectPeer(t, url, bKeys[2])
	register(t, dialApp(t, url), bKeys[0].owner.Remove(bKeys[2].device))
	waitUntil(t, "revoked device disconnected", func() bool {
		select {
		case _, ok := <-revoked.messages:
			return !ok
		default:
			return false
		}
	})
	id := randomText(protocol.MessageIDSize)
	c0, c1 := ratchetText(100), ratchetText(101)
	a0.write(t, sendFrame("s1", bKeys[0].identity, id, envelope(bKeys[0], c0), envelope(bKeys[1], c1), envelope(bKeys[2], ratchetText(102))))
	a0.expectError(t, "s1", "stale_devices")
	a0.write(t, sendFrame("s2", bKeys[0].identity, id, envelope(bKeys[0], c0), envelope(bKeys[1], c1)))
	a0.expect(t, "queued", "s2")

	got := deliveries(t, online.barrier(t, "p1"))
	if len(got) != 1 || got[0].Ciphertext != c0 || got[0].Device != aKeys[0].device.ID {
		t.Fatalf("online device received %+v", got)
	}
	if srv.queue.Queued(queueAddress(bKeys[1])) != 1 {
		t.Fatal("offline device envelope not queued")
	}
	online.write(t, ackFrame("a0", got[0]))
	online.expect(t, "acked", "a0")
	offline := connectPeer(t, url, bKeys[1])
	later := deliveries(t, offline.fetch(t, "f1"))
	if len(later) != 1 || later[0].Ciphertext != c1 || later[0].ID != id {
		t.Fatalf("offline device received %+v", later)
	}
	offline.write(t, ackFrame("a1", later[0]))
	offline.expect(t, "acked", "a1")
	notes := receipts(t, a0.barrier(t, "p2"))
	if len(notes) != 2 || notes[0].Device == notes[1].Device {
		t.Fatalf("per-device receipts %+v", notes)
	}
	if leaked := receipts(t, a1.barrier(t, "p3")); len(leaked) != 0 {
		t.Fatalf("receipts delivered to the sibling sender device %+v", leaked)
	}
	if srv.queue.Queued(queueAddress(bKeys[2])) != 0 {
		t.Fatal("revoked device received a queue entry")
	}
}

func TestUnacknowledgedDeliveryIsRetainedAcrossRecipientCrash(t *testing.T) {
	srv, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	b := joinPeer(t, url, bKey)
	b.fetch(t, "f0")
	a := connectPeer(t, url, aKey)
	id, ciphertext := randomText(protocol.MessageIDSize), ratchetText(150)
	a.write(t, sendFrame("s1", bKey.identity, id, envelope(bKey, ciphertext)))
	a.expect(t, "queued", "s1")
	if got := deliveries(t, b.barrier(t, "p1")); len(got) != 1 || got[0].ID != id {
		t.Fatalf("live delivery %+v", got)
	}
	b.conn.Close()
	waitUntil(t, "crashed recipient detached", func() bool { return srv.sessions.Len() == 1 })
	if n := srv.queue.Queued(queueAddress(bKey)); n != 1 {
		t.Fatalf("transmitted message lost after crash: %d", n)
	}
	again := connectPeer(t, url, bKey)
	got := deliveries(t, again.fetch(t, "f1"))
	if len(got) != 1 || got[0].ID != id || got[0].Ciphertext != ciphertext {
		t.Fatalf("redelivery %+v", got)
	}
	again.write(t, ackFrame("a1", got[0]))
	again.expect(t, "acked", "a1")
	again.write(t, ackFrame("a2", got[0]))
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
	cfg := testConfig()
	aKey, bKey := newKey(t), newKey(t)
	first := startServerWith(t, cfg)
	joinPeer(t, first, bKey).conn.Close()
	a := connectPeer(t, first, aKey)
	a.write(t, sendFrame("s1", bKey.identity, randomText(protocol.MessageIDSize), envelope(bKey, ratchetText(100))))
	a.expect(t, "queued", "s1")
	restarted := startServerWith(t, cfg)
	b := joinPeer(t, restarted, bKey)
	if got := deliveries(t, b.fetch(t, "f1")); len(got) != 0 {
		t.Fatalf("restarted server delivered %+v", got)
	}
}

func TestSendValidationOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	joinPeer(t, url, bKey)
	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, sendFrame("m1", bKey.identity, randomText(16), envelope(bKey, ratchetText(100)))), "authentication_required")
	a := connectPeer(t, url, aKey)
	a.write(t, sendFrame("m3", bKey.identity, randomText(16), envelope(bKey, base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("plaintext ", 12))))))
	a.expectError(t, "m3", "invalid_payload")
	stranger := newKey(t)
	a.write(t, sendFrame("m4", stranger.identity, randomText(16), envelope(stranger, ratchetText(100))))
	a.expectError(t, "m4", "stale_devices")
	a.write(t, `{"type":"session","id":"m5","payload":{}}`)
	a.expectError(t, "m5", "unsupported_type")
	a.write(t, `{"type":"publish","id":"m6","payload":{}}`)
	a.expectError(t, "m6", "unsupported_type")
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	srv, url := startServer(t)
	k := newKey(t)
	conn := dialApp(t, url)
	authenticateConn(t, conn, k)
	expectOversizedRejected(t, srv, conn, []byte(sendFrame("m1", k.identity, randomText(16), envelope(k, strings.Repeat("A", 40<<10)))))
}

func TestReconnectStormDeliversEveryMessage(t *testing.T) {
	srv, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	joinPeer(t, url, bKey).conn.Close()
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
			if err := a.conn.WriteMessage(websocket.TextMessage, []byte(sendFrame(fmt.Sprintf("s%d", i), bKey.identity, id, envelope(bKey, ratchetText(100))))); err != nil {
				writeErr = err
				return
			}
		}
	})
	for round := range 15 {
		b := connectPeer(t, url, bKey)
		for _, d := range deliveries(t, b.fetch(t, fmt.Sprintf("f%d", round))) {
			received[d.ID]++
			if round%2 == 0 {
				b.write(t, ackFrame("a", d))
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
		if srv.queue.Queued(queueAddress(bKey)) == 0 {
			break
		}
		b := connectPeer(t, url, bKey)
		pending := deliveries(t, b.fetch(t, "drain"))
		for round := 0; len(pending) > 0; round++ {
			for _, d := range pending {
				received[d.ID]++
				b.write(t, ackFrame("a-"+d.ID[:6], d))
			}
			pending = deliveries(t, b.barrier(t, fmt.Sprintf("d%d", round)))
		}
		b.conn.Close()
	}
	if n := srv.queue.Queued(queueAddress(bKey)); n != 0 {
		t.Fatalf("%d messages stranded", n)
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
