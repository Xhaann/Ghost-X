package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeValid(t *testing.T) {
	req, err := Decode([]byte(`{"type":"ping","id":"a1_B-2","payload":{"sentAt":1}}`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if req.Type != "ping" || req.ID != "a1_B-2" || string(req.Payload) != `{"sentAt":1}` {
		t.Errorf("Decode() = %+v", req)
	}
}

func TestDecodeWithoutPayload(t *testing.T) {
	req, err := Decode([]byte(` { "id" : "x" , "type" : "ping" } `))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if req.Payload != nil {
		t.Errorf("Payload = %q, want nil", req.Payload)
	}
}

func TestDecodeInvalid(t *testing.T) {
	longID := strings.Repeat("a", maxIDLength+1)
	tests := []struct {
		name   string
		input  string
		wantID string
	}{
		{"empty", ``, ""},
		{"whitespace", `   `, ""},
		{"truncated", `{"type":"ping","id":"x"`, ""},
		{"array", `[]`, ""},
		{"null", `null`, ""},
		{"string", `"ping"`, ""},
		{"number", `1`, ""},
		{"trailing value", `{"type":"ping","id":"x"}{}`, ""},
		{"trailing garbage", `{"type":"ping","id":"x"}x`, ""},
		{"unknown field", `{"type":"ping","id":"x","extra":1}`, ""},
		{"wrong case field", `{"Type":"ping","id":"x"}`, ""},
		{"duplicate field", `{"type":"ping","type":"other","id":"x"}`, ""},
		{"missing id", `{"type":"ping"}`, ""},
		{"null id", `{"type":"ping","id":null}`, ""},
		{"numeric id", `{"type":"ping","id":5}`, ""},
		{"empty id", `{"type":"ping","id":""}`, ""},
		{"long id", `{"type":"ping","id":"` + longID + `"}`, ""},
		{"id with space", `{"type":"ping","id":"a b"}`, ""},
		{"id with control", `{"type":"ping","id":"a\u0000"}`, ""},
		{"id with unicode", `{"type":"ping","id":"é"}`, ""},
		{"missing type", `{"id":"x"}`, "x"},
		{"null type", `{"type":null,"id":"x"}`, "x"},
		{"numeric type", `{"type":1,"id":"x"}`, "x"},
		{"object type", `{"type":{},"id":"x"}`, "x"},
		{"empty type", `{"type":"","id":"x"}`, "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := Decode([]byte(tt.input))
			var protoErr *Error
			if !errors.As(err, &protoErr) || protoErr.Code != CodeInvalidMessage {
				t.Fatalf("Decode() error = %v, want %s", err, CodeInvalidMessage)
			}
			if req.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", req.ID, tt.wantID)
			}
		})
	}
}

func TestDecodeSafeInteger(t *testing.T) {
	valid := map[string]int64{"0": 0, "42": 42, "9007199254740991": maxSafeInteger}
	for input, want := range valid {
		got, err := decodeSafeInteger([]byte(input))
		if err != nil || got != want {
			t.Errorf("decodeSafeInteger(%s) = %d, %v; want %d", input, got, err, want)
		}
	}

	for _, input := range []string{"", "null", "-1", "1.5", "1e3", "1E3", "9007199254740992", "99999999999999999999", `"1"`, "true", "[]", "{}"} {
		if _, err := decodeSafeInteger([]byte(input)); err == nil {
			t.Errorf("decodeSafeInteger(%s) error = nil, want error", input)
		}
	}
}
