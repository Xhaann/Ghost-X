package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type peer struct {
	conn     *websocket.Conn
	key      key
	messages chan message
}

func connectPeer(t *testing.T, url string, k key) *peer {
	t.Helper()
	conn := dialApp(t, url)
	authenticateConn(t, conn, k)
	p := &peer{conn: conn, key: k, messages: make(chan message, 256)}
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

func (p *peer) send(t *testing.T, id, to, body string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"to": to, "body": body})
	request := fmt.Sprintf(`{"type":"send","id":%q,"payload":%s}`, id, payload)
	if err := p.conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
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

func (p *peer) expectMessage(t *testing.T, from, body string) {
	t.Helper()
	p.expectMessageID(t, "", from, body)
}

func (p *peer) expectMessageID(t *testing.T, id, from, body string) {
	t.Helper()
	msg := p.next(t)
	var payload map[string]string
	json.Unmarshal(msg.Payload, &payload)
	if msg.Type != "message" || msg.ID != "" || len(payload) != 3 || payload["from"] != from || payload["body"] != body || (id != "" && payload["id"] != id) {
		t.Fatalf("delivery = %+v %s, want from %s body %q", msg, msg.Payload, from, body)
	}
}

func (p *peer) barrier(t *testing.T, id string) {
	t.Helper()
	if err := p.conn.WriteMessage(websocket.TextMessage, []byte(pingRequest(id, 1))); err != nil {
		t.Fatal(err)
	}
	if msg := p.next(t); msg.Type != "pong" || msg.ID != id {
		t.Fatalf("barrier = %+v, want pong %s", msg, id)
	}
}

func TestDirectMessageDelivered(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	a.send(t, "m1", b.key.identity, "hello from a")
	a.expectSent(t, "m1")
	b.expectMessageID(t, "m1", a.key.identity, "hello from a")

	b.send(t, "m2", a.key.identity, "hello from b")
	b.expectSent(t, "m2")
	a.expectMessageID(t, "m2", b.key.identity, "hello from b")
}

func TestDirectMessageReachesEveryRecipientSessionOnce(t *testing.T) {
	_, url := startServer(t)
	aKey, bKey := newKey(t), newKey(t)
	a := connectPeer(t, url, aKey)
	aOther := connectPeer(t, url, aKey)
	b1 := connectPeer(t, url, bKey)
	b2 := connectPeer(t, url, bKey)

	a.send(t, "m1", bKey.identity, "one")
	a.expectSent(t, "m1")
	a.send(t, "m2", bKey.identity, "two")
	a.expectSent(t, "m2")

	for _, b := range []*peer{b1, b2} {
		b.expectMessage(t, aKey.identity, "one")
		b.expectMessage(t, aKey.identity, "two")
		b.barrier(t, "p1")
	}
	a.barrier(t, "p2")
	aOther.barrier(t, "p3")
}

func TestDirectMessageUnavailableRecipient(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	absent := newKey(t)

	a.send(t, "m1", absent.identity, "x")
	a.expectError(t, "m1", "recipient_unavailable")

	b := connectPeer(t, url, absent)
	b.conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.send(t, "m2", absent.identity, "x")
		msg := a.next(t)
		if msg.Type == "error" && string(msg.Payload) == `{"code":"recipient_unavailable"}` {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recipient still reachable after disconnect: %+v", msg)
		}
	}
}

func TestDirectMessageRequiresAuthentication(t *testing.T) {
	_, url := startServer(t)
	b := connectPeer(t, url, newKey(t))
	conn := dialApp(t, url)

	payload, _ := json.Marshal(map[string]string{"to": b.key.identity, "body": "x"})
	expectError(t, roundTrip(t, conn, `{"type":"send","id":"m1","payload":`+string(payload)+`}`), "authentication_required")
	challenge(t, conn)
	expectError(t, roundTrip(t, conn, `{"type":"send","id":"m2","payload":`+string(payload)+`}`), "authentication_required")

	b.barrier(t, "p1")
}

func TestDirectMessageRejectsForgedSender(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))
	c := newKey(t)

	forged := `{"type":"send","id":"m1","payload":{"to":"` + b.key.identity + `","body":"x","from":"` + c.identity + `"}}`
	if err := a.conn.WriteMessage(websocket.TextMessage, []byte(forged)); err != nil {
		t.Fatal(err)
	}
	a.expectError(t, "m1", "invalid_payload")

	a.send(t, "m2", b.key.identity, "genuine")
	a.expectSent(t, "m2")
	b.expectMessage(t, a.key.identity, "genuine")
}

func TestDirectMessageSizeLimits(t *testing.T) {
	_, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	b := connectPeer(t, url, newKey(t))

	a.send(t, "m1", b.key.identity, strings.Repeat("a", 4097))
	a.expectError(t, "m1", "message_too_large")
	a.send(t, "m2", b.key.identity, strings.Repeat("a", 4096))
	a.expectSent(t, "m2")
	b.expectMessage(t, a.key.identity, strings.Repeat("a", 4096))

	a.send(t, "m3", b.key.identity, strings.Repeat("a", 40<<10))
	select {
	case _, ok := <-a.messages:
		if ok {
			t.Fatal("oversized frame was processed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized frame did not close the connection")
	}
}

func TestDirectMessageAfterReconnectRequiresAuthentication(t *testing.T) {
	_, url := startServer(t)
	aKey := newKey(t)
	b := connectPeer(t, url, newKey(t))
	first := connectPeer(t, url, aKey)
	first.conn.Close()

	conn := dialApp(t, url)
	payload, _ := json.Marshal(map[string]string{"to": b.key.identity, "body": "x"})
	expectError(t, roundTrip(t, conn, `{"type":"send","id":"m1","payload":`+string(payload)+`}`), "authentication_required")
	b.barrier(t, "p1")
}

func TestConcurrentDirectMessaging(t *testing.T) {
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
					sender.send(t, fmt.Sprintf("m%d", n), recipient.key.identity, sender.key.identity)
				}
			}
		})
	}
	wg.Wait()

	for _, p := range all {
		sent, received := 0, map[string]int{}
		for sent < (peers-1)*perPair || len(received) < peers-1 || total(received) < (peers-1)*perPair {
			msg := p.next(t)
			switch msg.Type {
			case "sent":
				sent++
			case "message":
				var payload map[string]string
				json.Unmarshal(msg.Payload, &payload)
				if payload["from"] != payload["body"] {
					t.Fatalf("sender mismatch: from %s body %s", payload["from"], payload["body"])
				}
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

func TestRecipientDisconnectDuringDelivery(t *testing.T) {
	srv, url := startServer(t)
	a := connectPeer(t, url, newKey(t))
	bKey := newKey(t)

	for range 20 {
		b := connectPeer(t, url, bKey)
		var wg sync.WaitGroup
		wg.Go(func() { a.send(t, "m1", bKey.identity, "race") })
		wg.Go(func() { b.conn.Close() })
		wg.Wait()
		msg := a.next(t)
		if msg.Type != "sent" && string(msg.Payload) != `{"code":"recipient_unavailable"}` {
			t.Fatalf("result = %+v %s", msg, msg.Payload)
		}
	}
	waitUntil(t, "recipient sessions removed", func() bool { return srv.sessions.Len() == 1 })
}
