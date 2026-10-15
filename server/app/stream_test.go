package app

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/stream"
)

func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func serveLocal(t *testing.T, srv *Server) string {
	t.Helper()
	path := filepath.Join(socketDir(t), "s")
	ln, err := listenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.stream.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return path
}

type localPeer struct {
	*peer
	nc net.Conn
}

func dialLocal(t *testing.T, path string) *localPeer {
	t.Helper()
	nc, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	p := &peer{messages: make(chan message, 512), frame: func(data []byte) error {
		_, err := nc.Write(stream.Encode(data))
		return err
	}}
	go func() {
		defer close(p.messages)
		header := make([]byte, stream.HeaderSize)
		for {
			if _, err := io.ReadFull(nc, header); err != nil {
				return
			}
			data := make([]byte, binary.BigEndian.Uint32(header))
			if _, err := io.ReadFull(nc, data); err != nil {
				return
			}
			var msg message
			if json.Unmarshal(data, &msg) != nil {
				return
			}
			p.messages <- msg
		}
	}()
	return &localPeer{peer: p, nc: nc}
}

func (p *localPeer) challenge(t *testing.T) []byte {
	t.Helper()
	p.write(t, `{"type":"challenge","id":"c1","payload":{}}`)
	msg := p.next(t)
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if msg.Type != "challenge" || json.Unmarshal(msg.Payload, &payload) != nil {
		t.Fatalf("challenge = %+v %s", msg, msg.Payload)
	}
	nonce, _ := base64.RawURLEncoding.DecodeString(payload.Nonce)
	return nonce
}

func (p *localPeer) authenticate(t *testing.T, k key) {
	t.Helper()
	p.write(t, rosterFrame(k.roster))
	if msg := p.next(t); msg.Type != "registered" && string(msg.Payload) != `{"code":"stale_roster"}` {
		t.Fatalf("register = %+v %s", msg, msg.Payload)
	}
	p.write(t, authenticateRequest(k, p.challenge(t)))
	if msg := p.next(t); msg.Type != "authenticated" || string(msg.Payload) != `{"identity":"`+k.identity+`","device":"`+k.device.ID+`"}` {
		t.Fatalf("authenticate = %+v %s", msg, msg.Payload)
	}
	p.key = k
}

func (p *localPeer) closed(t *testing.T) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-p.messages:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("local connection still open")
		}
	}
}

func TestTheSameProtocolRunsOverTheLocalCarrier(t *testing.T) {
	srv, url := startServer(t)
	path := serveLocal(t, srv)
	a := dialLocal(t, path)
	ka := newKey(t)
	a.authenticate(t, ka)
	a.write(t, pingRequest("p1", 7))
	a.expect(t, "pong", "p1")
	a.write(t, `{"type":"whoami","id":"w1","payload":{}}`)
	if msg := a.next(t); msg.Type != "whoami" || string(msg.Payload) != `{"identity":"`+ka.identity+`","device":"`+ka.device.ID+`"}` {
		t.Fatalf("whoami = %+v %s", msg, msg.Payload)
	}

	kb := newKey(t)
	b := joinPeer(t, url, kb)
	id := randomText(16)
	a.write(t, sendFrame("s1", kb.identity, id, envelope(kb, ratchetText(200))))
	a.expect(t, "queued", "s1")
	got := deliveries(t, b.fetch(t, "f1"))
	if len(got) != 1 || got[0].From != ka.identity || got[0].Device != ka.device.ID || got[0].ID != id {
		t.Fatalf("delivery over websocket = %+v", got)
	}
	b.write(t, ackFrame("k1", got[0]))
	b.expect(t, "acked", "k1")
	a.write(t, `{"type":"fetch","id":"f2","payload":{}}`)
	var notes []receipt
	for _, msg := range a.barrier(t, "b1") {
		if msg.Type == "receipt" {
			var r receipt
			json.Unmarshal(msg.Payload, &r)
			notes = append(notes, r)
		}
	}
	if len(notes) != 1 || notes[0].To != kb.identity || notes[0].Device != kb.device.ID || notes[0].Status != "delivered" {
		t.Fatalf("receipt over the local carrier = %+v", notes)
	}

	reply := randomText(16)
	b.write(t, sendFrame("s2", ka.identity, reply, envelope(ka, ratchetText(150))))
	b.expect(t, "queued", "s2")
	var pushed []delivery
	for _, msg := range a.barrier(t, "b2") {
		if msg.Type == "message" {
			var d delivery
			json.Unmarshal(msg.Payload, &d)
			pushed = append(pushed, d)
		}
	}
	if len(pushed) != 1 || pushed[0].ID != reply || pushed[0].From != kb.identity {
		t.Fatalf("push over the local carrier = %+v", pushed)
	}
}

func TestTheLocalCarrierGrantsNoAuthority(t *testing.T) {
	srv, url := startServer(t)
	path := serveLocal(t, srv)
	k := newKey(t)
	a := dialLocal(t, path)
	a.write(t, sendFrame("s1", newKey(t).identity, randomText(16), envelope(k, ratchetText(200))))
	a.expectError(t, "s1", "authentication_required")
	a.write(t, `{"type":"fetch","id":"f1","payload":{}}`)
	a.expectError(t, "f1", "authentication_required")
	a.write(t, `{"type":"nonsense","id":"n1","payload":{}}`)
	a.expectError(t, "n1", "unsupported_type")
	a.write(t, `not json`)
	if msg := a.next(t); msg.Type != "error" || string(msg.Payload) != `{"code":"invalid_message"}` {
		t.Fatalf("malformed frame = %+v %s", msg, msg.Payload)
	}

	ws := dialApp(t, url)
	register(t, ws, k.roster)
	proof := authenticateRequest(k, challenge(t, ws))
	a.write(t, proof)
	a.expectError(t, "a1", "authentication_failed")
	a.challenge(t)
	a.write(t, proof)
	a.expectError(t, "a1", "authentication_failed")

	c := dialLocal(t, path)
	nonce := c.challenge(t)
	c.write(t, fmt.Sprintf(`{"type":"authenticate","id":"a2","payload":{"identity":"not-an-identity","device":%q,"signature":%q}}`, k.device.ID, k.device.AuthSignature(k.owner, nonce)))
	if msg := c.next(t); msg.Type != "error" {
		t.Fatalf("invalid identity = %+v %s", msg, msg.Payload)
	}
	c.challenge(t)
	c.write(t, fmt.Sprintf(`{"type":"authenticate","id":"a3","payload":{"identity":%q,"device":"short","signature":"x"}}`, k.identity))
	if msg := c.next(t); msg.Type != "error" {
		t.Fatalf("invalid device = %+v %s", msg, msg.Payload)
	}

	b := dialLocal(t, path)
	b.authenticate(t, k)
	kr := newKey(t)
	joinPeer(t, url, kr)
	duplicate := randomText(16)
	frame := sendFrame("d1", kr.identity, duplicate, envelope(kr, ratchetText(200)))
	b.write(t, frame)
	b.expect(t, "queued", "d1")
	b.write(t, frame)
	b.expectError(t, "d1", "duplicate_message")
	b.write(t, sendFrame("s2", newKey(t).identity, randomText(16), fmt.Sprintf(`{"device":%q,"ciphertext":%q}`, k.device.ID, base64.RawURLEncoding.EncodeToString([]byte("plaintext body that is not a ratchet message at all, padded to length")))))
	b.expectError(t, "s2", "invalid_payload")
}

func TestRevocationEndsLocalConnections(t *testing.T) {
	srv, url := startServer(t)
	path := serveLocal(t, srv)
	pair := siblingKeys(t, 2)
	kept := dialLocal(t, path)
	kept.authenticate(t, pair[0])
	revoked := dialLocal(t, path)
	revoked.authenticate(t, pair[1])

	ws := dialApp(t, url)
	register(t, ws, pair[0].owner.Remove(pair[1].device))
	revoked.closed(t)

	kept.write(t, pingRequest("p1", 1))
	kept.expect(t, "pong", "p1")
	again := dialLocal(t, path)
	again.write(t, authenticateRequest(pair[1], again.challenge(t)))
	again.expectError(t, "a1", "authentication_failed")
}

func TestDisconnectsOnTheLocalCarrierReleaseStateAndKeepUndeliveredMessages(t *testing.T) {
	srv, url := startServer(t)
	path := serveLocal(t, srv)
	baseline := srv.sessions.Len()
	half := dialLocal(t, path)
	half.challenge(t)
	waitUntil(t, "challenged session", func() bool { return srv.sessions.Len() == baseline+1 })
	half.nc.Close()
	waitUntil(t, "session released", func() bool { return srv.sessions.Len() == baseline })

	ka, kb := newKey(t), newKey(t)
	sender := joinPeer(t, url, ka)
	receiver := dialLocal(t, path)
	receiver.authenticate(t, kb)
	id := randomText(16)
	sender.write(t, sendFrame("s1", kb.identity, id, envelope(kb, ratchetText(200))))
	sender.expect(t, "queued", "s1")
	pushed := deliveries(t, receiver.fetch(t, "f1"))
	if len(pushed) != 1 || pushed[0].ID != id {
		t.Fatalf("pushed = %+v", pushed)
	}
	receiver.nc.Close()
	receiver.closed(t)

	again := connectPeer(t, url, kb)
	redelivered := deliveries(t, again.fetch(t, "f2"))
	if len(redelivered) != 1 || redelivered[0].ID != id {
		t.Fatalf("unacknowledged message lost across a carrier change: %+v", redelivered)
	}
}

func TestMalformedLocalFramesCloseOnlyThatConnection(t *testing.T) {
	srv, _ := startServer(t)
	path := serveLocal(t, srv)
	oversized := make([]byte, stream.HeaderSize)
	binary.BigEndian.PutUint32(oversized, 32<<10+1)
	for name, data := range map[string][]byte{
		"empty":         make([]byte, stream.HeaderSize),
		"oversized":     oversized,
		"invalid utf-8": stream.Encode([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			p := dialLocal(t, path)
			if _, err := p.nc.Write(data); err != nil {
				t.Fatal(err)
			}
			p.closed(t)
		})
	}
	healthy := dialLocal(t, path)
	healthy.write(t, pingRequest("p1", 1))
	healthy.expect(t, "pong", "p1")
}

func TestUnauthenticatedLocalConnectionClosedAtDeadline(t *testing.T) {
	srv, _ := serveWithDeadline(t, 200*time.Millisecond)
	path := serveLocal(t, srv)
	p := dialLocal(t, path)
	p.challenge(t)
	if srv.sessions.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", srv.sessions.Len())
	}

	p.closed(t)
	waitUntil(t, "expired session removed", func() bool { return srv.sessions.Len() == 0 })
	waitUntil(t, "local connection released", func() bool { return srv.stream.Len() == 0 })
}

func TestAuthenticatedLocalConnectionOutlivesDeadline(t *testing.T) {
	srv, _ := serveWithDeadline(t, 500*time.Millisecond)
	path := serveLocal(t, srv)
	p := dialLocal(t, path)
	p.authenticate(t, newKey(t))

	idle := dialLocal(t, path)
	idle.closed(t)
	p.write(t, pingRequest("p1", 1))
	p.expect(t, "pong", "p1")
	waitUntil(t, "only the authenticated session", func() bool { return srv.sessions.Len() == 1 })
	waitUntil(t, "only the authenticated local connection", func() bool { return srv.stream.Len() == 1 })
	if srv.sessions.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", srv.sessions.Authenticated())
	}
}

func TestFailedLocalAuthenticationClosesConnection(t *testing.T) {
	srv, _ := startServer(t)
	path := serveLocal(t, srv)
	p := dialLocal(t, path)
	k := newKey(t)

	for range auth.MaxFailures - 1 {
		p.write(t, authenticateRequest(k, p.challenge(t)))
		if msg := p.next(t); msg.Type != "error" {
			t.Fatalf("unregistered authentication = %+v %s", msg, msg.Payload)
		}
	}
	p.write(t, authenticateRequest(k, p.challenge(t)))
	p.closed(t)
	waitUntil(t, "failed session removed", func() bool { return srv.sessions.Len() == 0 })
	waitUntil(t, "local connection released", func() bool { return srv.stream.Len() == 0 })
}

func TestShutdownClosesLocalConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	path := serveLocal(t, srv)
	p := dialLocal(t, path)
	p.authenticate(t, newKey(t))
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p.closed(t)
	if srv.stream.Len() != 0 {
		t.Fatalf("local connections after shutdown: %d", srv.stream.Len())
	}
}

func TestLocalSocketIsPrivateAndNeverReplacesOtherFiles(t *testing.T) {
	dir := socketDir(t)
	path := filepath.Join(dir, "s")
	ln, err := listenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(path)
	if info.Mode().Type() != fs.ModeSocket || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v", info.Mode())
	}
	ln.Close()
	os.Remove(path)
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	replaced, err := listenLocal(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	replaced.Close()

	file := filepath.Join(dir, "f")
	os.WriteFile(file, []byte("keep"), 0o600)
	if _, err := listenLocal(file); err == nil {
		t.Fatal("regular file replaced by a socket")
	}
	if data, _ := os.ReadFile(file); string(data) != "keep" {
		t.Fatal("regular file modified")
	}
}

func TestRunServesAndRemovesTheConfiguredLocalSocket(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	cfg := testConfig()
	cfg.LocalSocket = path
	srv := newServer(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitUntil(t, "local socket", func() bool {
		nc, err := net.Dial("unix", path)
		if err == nil {
			nc.Close()
		}
		return err == nil
	})
	p := dialLocal(t, path)
	p.write(t, pingRequest("p1", 1))
	p.expect(t, "pong", "p1")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("local socket left behind: %v", err)
	}
}
