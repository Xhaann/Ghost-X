package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/direct"
)

type mailbox struct {
	mu       sync.Mutex
	messages []string
}

func (m *mailbox) deliver(msg direct.Message) bool {
	m.mu.Lock()
	m.messages = append(m.messages, string(EncodeMessage(msg)))
	m.mu.Unlock()
	return true
}

func (m *mailbox) all() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.messages...)
}

type directFixture struct {
	router   *Router
	sessions *auth.Registry
	direct   *direct.Registry
}

func newDirectFixture() directFixture {
	d := direct.NewRegistry()
	return directFixture{
		router: NewRouter(map[string]Handler{
			"challenge":    Challenge(),
			"authenticate": Authenticate(),
		}, map[string]ProtectedHandler{
			"send": Send(d),
		}),
		sessions: auth.NewRegistry(time.Now, d),
		direct:   d,
	}
}

func (f directFixture) conn() (*Conn, *auth.Session, *mailbox) {
	session := f.sessions.Open()
	box := &mailbox{}
	f.direct.Attach(session, box.deliver)
	return f.router.Conn(session, discard), session, box
}

func (f directFixture) authenticatedConn(t *testing.T, s signer) (*Conn, *auth.Session, *mailbox) {
	t.Helper()
	conn, session, box := f.conn()
	authenticated(t, conn, s)
	return conn, session, box
}

func sendRequest(id, to, body string) []byte {
	payload, _ := json.Marshal(struct {
		To   string `json:"to"`
		Body string `json:"body"`
	}{to, body})
	return fmt.Appendf(nil, `{"type":"send","id":%q,"payload":%s}`, id, payload)
}

func delivered(id, from, body string) string {
	return string(EncodeMessage(direct.Message{ID: id, From: from, Body: body}))
}

func TestSendDeliversWithSessionIdentity(t *testing.T) {
	f := newDirectFixture()
	a, b := newSigner(t), newSigner(t)
	sender, _, senderBox := f.authenticatedConn(t, a)
	_, _, box := f.authenticatedConn(t, b)

	resp := decodeResponse(t, sender.Handle(sendRequest("m1", b.identity, "hello")))

	if resp.Type != "sent" || resp.ID != "m1" || string(resp.Payload) != `{}` {
		t.Fatalf("response = %+v %s", resp, resp.Payload)
	}
	if got := box.all(); len(got) != 1 || got[0] != delivered("m1", a.identity, "hello") {
		t.Fatalf("recipient got %v", got)
	}
	if len(senderBox.all()) != 0 {
		t.Fatalf("sender received %v", senderBox.all())
	}
}

func TestSendEncodingIsExact(t *testing.T) {
	data := EncodeMessage(direct.Message{ID: "m1", From: "A", Body: "line\n\"q\" <b>"})

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || string(decoded["type"]) != `"message"` {
		t.Fatalf("envelope = %s", data)
	}
	if _, hasID := decoded["id"]; hasID {
		t.Fatalf("delivered message carries an id: %s", data)
	}
	var payload map[string]string
	if err := json.Unmarshal(decoded["payload"], &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 3 || payload["id"] != "m1" || payload["from"] != "A" || payload["body"] != "line\n\"q\" <b>" {
		t.Fatalf("payload = %v", payload)
	}
}

func TestSendRequiresAuthentication(t *testing.T) {
	f := newDirectFixture()
	b := newSigner(t)
	_, _, box := f.authenticatedConn(t, b)
	conn, _, _ := f.conn()

	expectCode(t, conn.Handle(sendRequest("m1", b.identity, "x")), CodeAuthRequired)
	requestChallenge(t, conn)
	expectCode(t, conn.Handle(sendRequest("m1", b.identity, "x")), CodeAuthRequired)
	expectCode(t, conn.Handle([]byte(`{"type":"send","id":"m1","payload":{"x":1}}`)), CodeAuthRequired)

	if len(box.all()) != 0 {
		t.Fatalf("unauthenticated send delivered %v", box.all())
	}
}

func TestSendRejectsForgedSender(t *testing.T) {
	f := newDirectFixture()
	a, b, c := newSigner(t), newSigner(t), newSigner(t)
	sender, _, _ := f.authenticatedConn(t, a)
	_, _, box := f.authenticatedConn(t, b)
	f.authenticatedConn(t, c)

	for _, input := range []string{
		`{"type":"send","id":"m1","payload":{"to":"` + b.identity + `","body":"x","from":"` + c.identity + `"}}`,
		`{"type":"send","id":"m1","payload":{"to":"` + b.identity + `","body":"x","sender":"` + c.identity + `"}}`,
		`{"type":"send","id":"m1","payload":{"to":"` + b.identity + `","body":"x"},"from":"` + c.identity + `"}`,
	} {
		resp := decodeResponse(t, sender.Handle([]byte(input)))
		if resp.Type != "error" {
			t.Fatalf("forged sender accepted: %s", input)
		}
	}
	if len(box.all()) != 0 {
		t.Fatalf("forged message delivered: %v", box.all())
	}

	sender.Handle(sendRequest("m2", b.identity, "real"))
	if got := box.all(); len(got) != 1 || got[0] != delivered("m2", a.identity, "real") {
		t.Fatalf("delivered %v, want sender %s", got, a.identity)
	}
}

func TestSendValidation(t *testing.T) {
	f := newDirectFixture()
	a, b := newSigner(t), newSigner(t)
	sender, _, _ := f.authenticatedConn(t, a)
	_, _, box := f.authenticatedConn(t, b)
	to := b.identity

	tests := map[string]struct {
		input string
		code  Code
	}{
		"missing payload":      {`{"type":"send","id":"m1"}`, CodeInvalidPayload},
		"null payload":         {`{"type":"send","id":"m1","payload":null}`, CodeInvalidPayload},
		"array payload":        {`{"type":"send","id":"m1","payload":[]}`, CodeInvalidPayload},
		"missing to":           {`{"type":"send","id":"m1","payload":{"body":"x"}}`, CodeInvalidPayload},
		"missing body":         {`{"type":"send","id":"m1","payload":{"to":"` + to + `"}}`, CodeInvalidPayload},
		"empty body":           {string(sendRequest("m1", to, "")), CodeInvalidPayload},
		"numeric body":         {`{"type":"send","id":"m1","payload":{"to":"` + to + `","body":1}}`, CodeInvalidPayload},
		"null body":            {`{"type":"send","id":"m1","payload":{"to":"` + to + `","body":null}}`, CodeInvalidPayload},
		"control character":    {string(sendRequest("m1", to, "a\x00b")), CodeInvalidPayload},
		"escape character":     {string(sendRequest("m1", to, "a\x1bb")), CodeInvalidPayload},
		"delete character":     {string(sendRequest("m1", to, "a\x7fb")), CodeInvalidPayload},
		"duplicate body":       {`{"type":"send","id":"m1","payload":{"to":"` + to + `","body":"x","body":"y"}}`, CodeInvalidPayload},
		"duplicate to":         {`{"type":"send","id":"m1","payload":{"to":"` + to + `","to":"` + to + `","body":"x"}}`, CodeInvalidPayload},
		"wrong case field":     {`{"type":"send","id":"m1","payload":{"To":"` + to + `","body":"x"}}`, CodeInvalidPayload},
		"multiple recipients":  {`{"type":"send","id":"m1","payload":{"to":["` + to + `"],"body":"x"}}`, CodeInvalidPayload},
		"invalid recipient":    {string(sendRequest("m1", "not-an-identity", "x")), CodeInvalidPayload},
		"padded recipient":     {string(sendRequest("m1", to+"=", "x")), CodeInvalidPayload},
		"small order key":      {string(sendRequest("m1", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "x")), CodeInvalidPayload},
		"oversized body":       {string(sendRequest("m1", to, strings.Repeat("a", MaxBodySize+1))), CodeTooLarge},
		"oversized multibyte":  {string(sendRequest("m1", to, strings.Repeat("é", MaxBodySize/2+1))), CodeTooLarge},
		"oversized raw":        {`{"type":"send","id":"m1","payload":{"to":"` + to + `","body":"` + strings.Repeat(`a`, MaxBodySize+1) + `"}}`, CodeTooLarge},
		"invalid message id":   {`{"type":"send","id":"bad id","payload":{"to":"` + to + `","body":"x"}}`, CodeInvalidMessage},
		"missing message id":   {`{"type":"send","payload":{"to":"` + to + `","body":"x"}}`, CodeInvalidMessage},
		"oversized message id": {`{"type":"send","id":"` + strings.Repeat("a", 65) + `","payload":{"to":"` + to + `","body":"x"}}`, CodeInvalidMessage},
		"wrong type case":      {`{"type":"Send","id":"m1","payload":{"to":"` + to + `","body":"x"}}`, CodeUnsupportedType},
		"broadcast type":       {`{"type":"broadcast","id":"m1","payload":{"body":"x"}}`, CodeUnsupportedType},
		"malformed json":       {`{"type":"send","id":"m1","payload":{"to":`, CodeInvalidMessage},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			expectCode(t, sender.Handle([]byte(tt.input)), tt.code)
		})
	}
	if len(box.all()) != 0 {
		t.Fatalf("invalid requests delivered %v", box.all())
	}
}

func TestSendBodyBoundaries(t *testing.T) {
	f := newDirectFixture()
	a, b := newSigner(t), newSigner(t)
	sender, _, _ := f.authenticatedConn(t, a)
	_, _, box := f.authenticatedConn(t, b)

	for _, body := range []string{
		"x",
		strings.Repeat("a", MaxBodySize),
		strings.Repeat("é", MaxBodySize/2),
		"tab\tnewline\nreturn\r",
		"emoji 😀 and 中文",
	} {
		if resp := decodeResponse(t, sender.Handle(sendRequest("m1", b.identity, body))); resp.Type != "sent" {
			t.Fatalf("body of %d bytes rejected: %+v %s", len(body), resp, resp.Payload)
		}
	}
	if len(box.all()) != 5 {
		t.Fatalf("delivered %d messages, want 5", len(box.all()))
	}
}

func TestSendUnavailableRecipient(t *testing.T) {
	f := newDirectFixture()
	a, b := newSigner(t), newSigner(t)
	sender, _, _ := f.authenticatedConn(t, a)

	expectCode(t, sender.Handle(sendRequest("m1", b.identity, "x")), CodeUnavailable)

	_, session, _ := f.authenticatedConn(t, b)
	session.Close()
	expectCode(t, sender.Handle(sendRequest("m2", b.identity, "x")), CodeUnavailable)
}

func TestSendAfterSenderClose(t *testing.T) {
	f := newDirectFixture()
	a, b := newSigner(t), newSigner(t)
	sender, session, _ := f.authenticatedConn(t, a)
	_, _, box := f.authenticatedConn(t, b)

	session.Close()

	expectCode(t, sender.Handle(sendRequest("m1", b.identity, "x")), CodeAuthRequired)
	if len(box.all()) != 0 {
		t.Fatalf("closed session delivered %v", box.all())
	}
}

func TestSendErrorsDoNotLeakDetails(t *testing.T) {
	f := newDirectFixture()
	a, b := newSigner(t), newSigner(t)
	sender, _, _ := f.authenticatedConn(t, a)
	for _, out := range [][]byte{
		sender.Handle(sendRequest("m1", b.identity, "x")),
		sender.Handle(sendRequest("m1", "bad", "x")),
		sender.Handle(sendRequest("m1", b.identity, strings.Repeat("a", MaxBodySize+1))),
	} {
		for _, leak := range []string{"direct:", "identity:", "session", "registry"} {
			if strings.Contains(string(out), leak) {
				t.Fatalf("response %s leaks %q", out, leak)
			}
		}
	}
}

func FuzzSendPayload(f *testing.F) {
	s := newSigner(f)
	f.Add(`{"to":"RECIPIENT","body":"x"}`)
	f.Add(`{"to":"` + s.identity + `","body":""}`)
	f.Add(`{"to":"` + s.identity + `","body":"x","from":"` + s.identity + `"}`)
	f.Add(`{"to":1,"body":[]}`)
	f.Add(`null`)
	f.Add(`{"to":"` + strings.Repeat("A", 43) + `","body":"\u0000"}`)

	fx := newDirectFixture()
	recipient := newSigner(f)
	receiverSession := fx.sessions.Open()
	box := &mailbox{}
	fx.direct.Attach(receiverSession, box.deliver)
	nonce, err := receiverSession.Challenge()
	if err != nil {
		f.Fatal(err)
	}
	if _, err := receiverSession.Authenticate(recipient.identity, recipient.sign(auth.Message(nonce))); err != nil {
		f.Fatal(err)
	}
	defer receiverSession.Close()

	f.Fuzz(func(t *testing.T, payload string) {
		sender, session, _ := fx.conn()
		defer session.Close()
		nonce := requestChallenge(t, sender)
		if resp := decodeResponse(t, authenticate(sender, s.identity, s.sign(auth.Message(nonce)))); resp.Type != "authenticated" {
			t.Fatalf("authentication = %+v", resp)
		}
		before := len(box.all())
		payload = strings.ReplaceAll(payload, "RECIPIENT", recipient.identity)
		out := sender.Handle([]byte(`{"type":"send","id":"m1","payload":` + payload + `}`))
		var resp response
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("invalid response %q", out)
		}
		after := box.all()
		if resp.Type == "sent" {
			if len(after) != before+1 || !strings.Contains(after[len(after)-1], `"from":"`+s.identity+`"`) {
				t.Fatalf("sent without exactly one delivery from session identity: %v", after[before:])
			}
		} else if len(after) != before {
			t.Fatalf("rejected request delivered %v", after[before:])
		}
	})
}

func TestDeliveredMessageCarriesSenderRequestID(t *testing.T) {
	f := newDirectFixture()
	a, b, c := newSigner(t), newSigner(t), newSigner(t)
	senderA, _, _ := f.authenticatedConn(t, a)
	senderC, _, _ := f.authenticatedConn(t, c)
	_, _, box := f.authenticatedConn(t, b)

	senderA.Handle(sendRequest("a1", b.identity, "first"))
	senderC.Handle(sendRequest("c1", b.identity, "other"))
	senderA.Handle(sendRequest("a2", b.identity, "second"))
	senderA.Handle([]byte(`{"type":"ping","id":"p9","payload":{"sentAt":1}}`))
	senderA.Handle(sendRequest("a3", b.identity, "third"))

	want := []string{
		delivered("a1", a.identity, "first"),
		delivered("c1", c.identity, "other"),
		delivered("a2", a.identity, "second"),
		delivered("a3", a.identity, "third"),
	}
	if got := box.all(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("delivered %v, want %v", got, want)
	}
}
