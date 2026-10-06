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

type peer struct {
	conn      *websocket.Conn
	key       key
	exchange  string
	signature string
	messages  chan message
}

type sealed struct {
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newSealed(n int) sealed {
	return sealed{Salt: randomText(protocol.SaltSize), IV: randomText(protocol.IVSize), Ciphertext: randomText(n)}
}

func bundleFor(t *testing.T, k key) (string, string) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := private.PublicKey().Bytes()
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
	p := &peer{conn: conn, key: k, exchange: exchange, signature: signature, messages: make(chan message, 512)}
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

func sendFrame(id, to string, s sealed) string {
	payload, _ := json.Marshal(map[string]string{"to": to, "salt": s.Salt, "iv": s.IV, "ciphertext": s.Ciphertext})
	return fmt.Sprintf(`{"type":"send","id":%q,"payload":%s}`, id, payload)
}

func (p *peer) write(t *testing.T, frame string) {
	t.Helper()
	if err := p.conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
		t.Fatal(err)
	}
}

func (p *peer) send(t *testing.T, id, to string, s sealed) {
	t.Helper()
	p.write(t, sendFrame(id, to, s))
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

func (p *peer) expectDelivery(t *testing.T, id string, from *peer, s sealed) {
	t.Helper()
	msg := p.next(t)
	var payload map[string]string
	json.Unmarshal(msg.Payload, &payload)
	want := map[string]string{
		"id": id, "from": from.key.identity, "key": from.exchange, "signature": from.signature,
		"salt": s.Salt, "iv": s.IV, "ciphertext": s.Ciphertext,
	}
	if msg.Type != "message" || msg.ID != "" || len(payload) != len(want) {
		t.Fatalf("delivery = %+v %s", msg, msg.Payload)
	}
	for k, v := range want {
		if payload[k] != v {
			t.Fatalf("delivery %s = %q, want %q", k, payload[k], v)
		}
	}
}

func (p *peer) barrier(t *testing.T, id string) {
	t.Helper()
	p.write(t, pingRequest(id, 1))
	if msg := p.next(t); msg.Type != "pong" || msg.ID != id {
		t.Fatalf("barrier = %+v, want pong %s", msg, id)
	}
}

func TestEncryptedEnvelopeRoutedUnchanged(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	first, second := newSealed(48), newSealed(64)
	a.send(t, "m1", b.key.identity, first)
	a.expectSent(t, "m1")
	b.expectDelivery(t, "m1", a, first)

	b.send(t, "m2", a.key.identity, second)
	b.expectSent(t, "m2")
	a.expectDelivery(t, "m2", b, second)
}

func TestKeyLookupOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	a.write(t, `{"type":"key","id":"q1","payload":{"identity":"`+b.key.identity+`"}}`)
	msg := a.next(t)
	want := `{"identity":"` + b.key.identity + `","key":"` + b.exchange + `","signature":"` + b.signature + `"}`
	if msg.Type != "key" || msg.ID != "q1" || string(msg.Payload) != want {
		t.Fatalf("key = %+v %s", msg, msg.Payload)
	}
}

func TestPlaintextRejectedOverWebSocket(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	a.write(t, `{"type":"send","id":"p1","payload":{"to":"`+b.key.identity+`","body":"plaintext secret"}}`)
	a.expectError(t, "p1", "invalid_payload")
	b.barrier(t, "b1")
}

func TestEncryptedMessageReachesEveryRecipientSessionOnce(t *testing.T) {
	_, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	aExchange, aSignature := bundleFor(t, aKey)
	bExchange, bSignature := bundleFor(t, bKey)
	a := connectPeerWith(t, url, aKey, aExchange, aSignature)
	aOther := connectPeerWith(t, url, aKey, aExchange, aSignature)
	b1 := connectPeerWith(t, url, bKey, bExchange, bSignature)
	b2 := connectPeerWith(t, url, bKey, bExchange, bSignature)

	s := newSealed(40)
	a.send(t, "m1", bKey.identity, s)
	a.expectSent(t, "m1")
	for _, b := range []*peer{b1, b2} {
		b.expectDelivery(t, "m1", a, s)
		b.barrier(t, "p1")
	}
	a.barrier(t, "p2")
	aOther.barrier(t, "p3")
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

	a.send(t, "m1", c.identity, newSealed(32))
	a.expectError(t, "m1", "recipient_unavailable")

	s := newSealed(32)
	a.send(t, "m2", b.key.identity, s)
	a.expectSent(t, "m2")
	a.send(t, "m2", b.key.identity, s)
	a.expectError(t, "m2", "duplicate_message")
	b.expectDelivery(t, "m2", a, s)
	b.barrier(t, "b1")

	forged := `{"type":"send","id":"m3","payload":{"to":"` + b.key.identity + `","from":"` + c.identity + `","salt":"` + s.Salt + `","iv":"` + s.IV + `","ciphertext":"` + s.Ciphertext + `"}}`
	a.write(t, forged)
	a.expectError(t, "m3", "invalid_payload")

	a.send(t, "m4", b.key.identity, newSealed(protocol.MaxCiphertext+1))
	a.expectError(t, "m4", "message_too_large")
	big := newSealed(protocol.MaxCiphertext)
	a.send(t, "m5", b.key.identity, big)
	a.expectSent(t, "m5")
	b.expectDelivery(t, "m5", a, big)
}

func TestEncryptedSendRequiresAuthenticationAndKey(t *testing.T) {
	_, url := startServer(t)
	b := connectPeer(t, url, newKey(t))

	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, sendFrame("m1", b.key.identity, newSealed(32))), "authentication_required")
	authenticateConn(t, conn, newKey(t))
	expectError(t, roundTrip(t, conn, sendFrame("m2", b.key.identity, newSealed(32))), "key_required")
	b.barrier(t, "b1")
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	a.write(t, sendFrame("m1", a.key.identity, sealed{Salt: "x", IV: "x", Ciphertext: strings.Repeat("A", 40<<10)}))
	select {
	case _, ok := <-a.messages:
		if ok {
			t.Fatal("oversized frame was processed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized frame did not close the connection")
	}
}

func TestReconnectRequiresAuthenticationAndKeyAgain(t *testing.T) {
	_, url := startServer(t)
	aKey := newKey(t)
	b := connectPeer(t, url, newKey(t))
	first := connectPeer(t, url, aKey)
	first.conn.Close()

	conn := dialApp(t, url)
	expectError(t, roundTrip(t, conn, sendFrame("m1", b.key.identity, newSealed(32))), "authentication_required")
	authenticateConn(t, conn, aKey)
	expectError(t, roundTrip(t, conn, sendFrame("m2", b.key.identity, newSealed(32))), "key_required")
	b.barrier(t, "p1")
}

func TestConcurrentEncryptedMessaging(t *testing.T) {
	_, url := startServer(t)
	const peers = 6
	const perPair = 10
	all := make([]*peer, peers)
	for i := range all {
		all[i] = connectPeer(t, url, newKey(t))
	}

	var wg sync.WaitGroup
	for i, sender := range all {
		wg.Go(func() {
			n := 0
			for j, recipient := range all {
				if i == j {
					continue
				}
				for range perPair {
					n++
					sender.send(t, fmt.Sprintf("m%d", n), recipient.key.identity, newSealed(24))
				}
			}
		})
	}
	wg.Wait()

	for _, p := range all {
		sent, received := 0, map[string]int{}
		for sent < (peers-1)*perPair || total(received) < (peers-1)*perPair {
			msg := p.next(t)
			switch msg.Type {
			case "sent":
				sent++
			case "message":
				var payload map[string]string
				json.Unmarshal(msg.Payload, &payload)
				received[payload["from"]]++
			default:
				t.Fatalf("unexpected %+v %s", msg, msg.Payload)
			}
		}
		for from, n := range received {
			if n != perPair || from == p.key.identity {
				t.Fatalf("received %d from %s", n, from)
			}
		}
	}
}

func total(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

func TestRecipientDisconnectDuringEncryptedDelivery(t *testing.T) {
	srv, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	bKey := newKey(t)
	exchange, signature := bundleFor(t, bKey)

	for i := range 20 {
		b := connectPeerWith(t, url, bKey, exchange, signature)
		var wg sync.WaitGroup
		wg.Go(func() { a.send(t, fmt.Sprintf("m%d", i), bKey.identity, newSealed(24)) })
		wg.Go(func() { b.conn.Close() })
		wg.Wait()
		msg := a.next(t)
		if msg.Type != "sent" && string(msg.Payload) != `{"code":"recipient_unavailable"}` {
			t.Fatalf("result = %+v %s", msg, msg.Payload)
		}
	}
	waitUntil(t, "recipient sessions removed", func() bool { return srv.sessions.Len() == 1 })
}
