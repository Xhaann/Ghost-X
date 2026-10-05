package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Xhaann/ghost-x/server/protocol"
)

type message struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

func startApp(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- New(testConfig()).Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	})
	return "ws://" + ln.Addr().String() + "/ws"
}

func dialApp(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp.Body.Close()
	t.Cleanup(func() { conn.Close() })
	return conn
}

func roundTrip(t *testing.T, conn *websocket.Conn, request string) message {
	t.Helper()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var msg message
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("response %q: %v", data, err)
	}
	return msg
}

func pingRequest(id string, sentAt int64) string {
	return fmt.Sprintf(`{"type":"ping","id":%q,"payload":{"sentAt":%d}}`, id, sentAt)
}

func TestProtocolPing(t *testing.T) {
	conn := dialApp(t, startApp(t))
	sentAt := time.Now().UnixMilli()

	msg := roundTrip(t, conn, pingRequest("p1", sentAt))

	if msg.Type != "pong" || msg.ID != "p1" {
		t.Fatalf("response = %+v, want pong p1", msg)
	}
	var payload struct {
		SentAt     int64 `json:"sentAt"`
		ReceivedAt int64 `json:"receivedAt"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SentAt != sentAt || payload.ReceivedAt < sentAt {
		t.Errorf("payload = %+v, sentAt %d", payload, sentAt)
	}
}

func TestProtocolErrorKeepsConnection(t *testing.T) {
	conn := dialApp(t, startApp(t))

	for _, tt := range []struct {
		request string
		code    string
	}{
		{`not json`, "invalid_message"},
		{`{"type":"nope","id":"e1"}`, "unsupported_type"},
		{`{"type":"ping","id":"e2","payload":{"sentAt":"x"}}`, "invalid_payload"},
	} {
		msg := roundTrip(t, conn, tt.request)
		want := `{"code":"` + tt.code + `"}`
		if msg.Type != "error" || string(msg.Payload) != want {
			t.Errorf("response to %s = %+v, want error %s", tt.request, msg, want)
		}
	}

	if msg := roundTrip(t, conn, pingRequest("p2", 1)); msg.Type != "pong" || msg.ID != "p2" {
		t.Errorf("response after errors = %+v, want pong p2", msg)
	}
}

func TestProtocolOversizedMessage(t *testing.T) {
	conn := dialApp(t, startApp(t))

	padding := bytes.Repeat([]byte(" "), 33<<10)
	request := append([]byte(pingRequest("p1", 1)), padding...)
	if err := conn.WriteMessage(websocket.TextMessage, request); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := conn.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseMessageTooBig) {
		t.Fatalf("read error = %v, want close code %d", err, websocket.CloseMessageTooBig)
	}
}

func TestProtocolConcurrentClients(t *testing.T) {
	url := startApp(t)
	const clients = 20
	const pings = 25

	var wg sync.WaitGroup
	for c := range clients {
		conn := dialApp(t, url)
		wg.Go(func() {
			for i := range pings {
				id := fmt.Sprintf("c%d_%d", c, i)
				if err := conn.WriteMessage(websocket.TextMessage, []byte(pingRequest(id, int64(i)))); err != nil {
					t.Error(err)
					return
				}
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for i := range pings {
				_, data, err := conn.ReadMessage()
				if err != nil {
					t.Error(err)
					return
				}
				var msg message
				if err := json.Unmarshal(data, &msg); err != nil {
					t.Error(err)
					return
				}
				if want := fmt.Sprintf("c%d_%d", c, i); msg.Type != "pong" || msg.ID != want {
					t.Errorf("response = %+v, want pong %s", msg, want)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestProtocolIdentityProof(t *testing.T) {
	conn := dialApp(t, startApp(t))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := base64.RawURLEncoding.EncodeToString(public)

	challenge := roundTrip(t, conn, `{"type":"challenge","id":"c1","payload":{}}`)
	if challenge.Type != "challenge" || challenge.ID != "c1" {
		t.Fatalf("challenge = %+v", challenge)
	}
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(challenge.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(payload.Nonce)
	if err != nil {
		t.Fatal(err)
	}

	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, protocol.ProofMessage(nonce)))
	request := fmt.Sprintf(`{"type":"prove","id":"p1","payload":{"identity":%q,"signature":%q}}`, identity, signature)

	proven := roundTrip(t, conn, request)
	if proven.Type != "proven" || string(proven.Payload) != `{"identity":"`+identity+`"}` {
		t.Fatalf("proof response = %+v", proven)
	}

	replay := roundTrip(t, conn, request)
	if replay.Type != "error" || string(replay.Payload) != `{"code":"invalid_proof"}` {
		t.Fatalf("replay response = %+v", replay)
	}

	if msg := roundTrip(t, conn, pingRequest("p2", 1)); msg.Type != "pong" {
		t.Fatalf("ping after proof = %+v", msg)
	}
}
