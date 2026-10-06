package protocol

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/presence"
)

type response struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

func decodeResponse(t *testing.T, data []byte) response {
	t.Helper()
	var resp response
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("response %q is not valid JSON: %v", data, err)
	}
	return resp
}

func errorCode(t *testing.T, resp response) Code {
	t.Helper()
	if resp.Type != "error" {
		t.Fatalf("type = %q, want error", resp.Type)
	}
	var payload struct {
		Code Code `json:"code"`
	}
	if err := json.Unmarshal(resp.Payload, &payload); err != nil {
		t.Fatalf("error payload %q: %v", resp.Payload, err)
	}
	return payload.Code
}

func discard([]byte) {}

func testSession() *auth.Session {
	return auth.NewRegistry(time.Now, nil).Open()
}

func newTestRouter() *Router {
	return NewRouter(map[string]Handler{
		"ping":         Ping(time.Now),
		"challenge":    Challenge(),
		"authenticate": Authenticate(),
	}, map[string]ProtectedHandler{
		"whoami":   WhoAmI(),
		"presence": Presence(presence.NewRegistry()),
		"send":     Send(direct.NewRegistry()),
	})
}

func TestRouterPing(t *testing.T) {
	before := time.Now().UnixMilli()
	sentAt := strconv.FormatInt(before, 10)
	data := newTestRouter().Conn(testSession(), discard).Handle([]byte(`{"type":"ping","id":"r1","payload":{"sentAt":` + sentAt + `}}`))
	after := time.Now().UnixMilli()

	resp := decodeResponse(t, data)
	if resp.Type != "pong" || resp.ID != "r1" {
		t.Fatalf("response = %s", data)
	}
	var payload pong
	if err := json.Unmarshal(resp.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SentAt != before {
		t.Errorf("sentAt = %d, want %d", payload.SentAt, before)
	}
	if payload.ReceivedAt < before || payload.ReceivedAt > after {
		t.Errorf("receivedAt = %d, want within [%d, %d]", payload.ReceivedAt, before, after)
	}
}

func TestRouterErrors(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		code   Code
		wantID string
	}{
		{"malformed json", `{"type":`, CodeInvalidMessage, ""},
		{"missing id", `{"type":"ping","payload":{"sentAt":1}}`, CodeInvalidMessage, ""},
		{"invalid type field", `{"type":7,"id":"r2"}`, CodeInvalidMessage, "r2"},
		{"unknown type", `{"type":"unknown","id":"r3"}`, CodeUnsupportedType, "r3"},
		{"type case differs", `{"type":"PING","id":"r4","payload":{"sentAt":1}}`, CodeUnsupportedType, "r4"},
		{"missing payload", `{"type":"ping","id":"r5"}`, CodeInvalidPayload, "r5"},
		{"null payload", `{"type":"ping","id":"r6","payload":null}`, CodeInvalidPayload, "r6"},
		{"array payload", `{"type":"ping","id":"r7","payload":[]}`, CodeInvalidPayload, "r7"},
		{"empty payload", `{"type":"ping","id":"r8","payload":{}}`, CodeInvalidPayload, "r8"},
		{"string sentAt", `{"type":"ping","id":"r9","payload":{"sentAt":"1"}}`, CodeInvalidPayload, "r9"},
		{"null sentAt", `{"type":"ping","id":"r10","payload":{"sentAt":null}}`, CodeInvalidPayload, "r10"},
		{"fractional sentAt", `{"type":"ping","id":"r11","payload":{"sentAt":1.5}}`, CodeInvalidPayload, "r11"},
		{"negative sentAt", `{"type":"ping","id":"r12","payload":{"sentAt":-1}}`, CodeInvalidPayload, "r12"},
		{"unsafe sentAt", `{"type":"ping","id":"r13","payload":{"sentAt":9007199254740992}}`, CodeInvalidPayload, "r13"},
		{"extra payload field", `{"type":"ping","id":"r14","payload":{"sentAt":1,"x":1}}`, CodeInvalidPayload, "r14"},
		{"duplicate payload field", `{"type":"ping","id":"r15","payload":{"sentAt":1,"sentAt":2}}`, CodeInvalidPayload, "r15"},
	}

	router := newTestRouter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := decodeResponse(t, router.Conn(testSession(), discard).Handle([]byte(tt.input)))
			if code := errorCode(t, resp); code != tt.code {
				t.Errorf("code = %q, want %q", code, tt.code)
			}
			if resp.ID != tt.wantID {
				t.Errorf("id = %q, want %q", resp.ID, tt.wantID)
			}
		})
	}
}

func TestRouterHidesInternalErrors(t *testing.T) {
	internal := errors.New("open /var/lib/ghost-x/state: permission denied")
	router := NewRouter(map[string]Handler{
		"fail": func(*Conn, []byte) (Reply, error) { return Reply{}, internal },
	}, nil)

	data := router.Conn(testSession(), discard).Handle([]byte(`{"type":"fail","id":"r1"}`))

	if code := errorCode(t, decodeResponse(t, data)); code != CodeInternalError {
		t.Errorf("code = %q, want %q", code, CodeInternalError)
	}
	if strings.Contains(string(data), "permission") || strings.Contains(string(data), "/var") {
		t.Errorf("response leaks internal error: %s", data)
	}
}

func TestRouterUnencodableReply(t *testing.T) {
	router := NewRouter(map[string]Handler{
		"bad": func(*Conn, []byte) (Reply, error) { return Reply{Type: "bad", Payload: make(chan int)}, nil },
	}, nil)

	resp := decodeResponse(t, router.Conn(testSession(), discard).Handle([]byte(`{"type":"bad","id":"r1"}`)))

	if code := errorCode(t, resp); code != CodeInternalError {
		t.Errorf("code = %q, want %q", code, CodeInternalError)
	}
	if resp.ID != "r1" {
		t.Errorf("id = %q, want r1", resp.ID)
	}
}

func TestRouterIgnoresLaterHandlerChanges(t *testing.T) {
	handlers := map[string]Handler{"ping": Ping(time.Now)}
	router := NewRouter(handlers, nil)
	delete(handlers, "ping")

	resp := decodeResponse(t, router.Conn(testSession(), discard).Handle([]byte(`{"type":"ping","id":"r1","payload":{"sentAt":1}}`)))
	if resp.Type != "pong" {
		t.Errorf("type = %q, want pong", resp.Type)
	}
}

func TestRouterConcurrent(t *testing.T) {
	router := newTestRouter()
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 200 {
				id := "g" + strconv.Itoa(g) + "_" + strconv.Itoa(i)
				resp := decodeResponse(t, router.Conn(testSession(), discard).Handle([]byte(`{"type":"ping","id":"`+id+`","payload":{"sentAt":`+strconv.Itoa(i)+`}}`)))
				if resp.Type != "pong" || resp.ID != id {
					t.Errorf("response = %+v, want pong %s", resp, id)
					return
				}
			}
		})
	}
	wg.Wait()
}

func FuzzRouterHandle(f *testing.F) {
	for _, seed := range []string{
		``,
		`{}`,
		`{"type":"ping","id":"a","payload":{"sentAt":1}}`,
		`{"type":"ping","id":"a","payload":{"sentAt":1e400}}`,
		`{"type":"ping","id":"a","payload":{"sentAt":-0}}`,
		`{"type":"ping","id":"a","payload":{"sentAt":01}}`,
		`{"type":"\ud800","id":"a"}`,
		`{"type":"ping","id":"a","payload":` + strings.Repeat("[", 10000) + `}`,
		`{"type":"ping","id":"a","payload":{"sentAt":1}` + strings.Repeat(" ", 100),
		"{\"type\":\"ping\",\"id\":\"a\"}\x00",
		`{"type":"challenge","id":"a","payload":{}}`,
		`{"type":"whoami","id":"a","payload":{}}`,
		`{"type":"presence","id":"a","payload":{}}`,
		`{"type":"send","id":"a","payload":{"to":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","body":"x"}}`,
		`{"type":"present","id":"a","payload":{"identity":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`,
		`{"type":"authenticate","id":"a","payload":{"identity":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"x"}}`,
	} {
		f.Add([]byte(seed))
	}

	router := newTestRouter()
	f.Fuzz(func(t *testing.T, data []byte) {
		out := router.Conn(testSession(), discard).Handle(data)
		if !json.Valid(out) || !utf8.Valid(out) {
			t.Fatalf("invalid response %q for input %q", out, data)
		}
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Type != "pong" && resp.Type != "challenge" && resp.Type != "error" {
			t.Fatalf("unexpected response type %q", resp.Type)
		}
	})
}
