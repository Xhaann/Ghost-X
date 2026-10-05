package protocol

import "encoding/json"

const maxIDLength = 64

type Code string

const (
	CodeInvalidMessage  Code = "invalid_message"
	CodeUnsupportedType Code = "unsupported_type"
	CodeInvalidPayload  Code = "invalid_payload"
	CodeInvalidProof    Code = "invalid_proof"
	CodeInternalError   Code = "internal_error"
)

type Error struct {
	Code Code
}

func (e *Error) Error() string {
	return "protocol: " + string(e.Code)
}

type Request struct {
	Type    string
	ID      string
	Payload []byte
}

type Reply struct {
	Type    string
	Payload any
}

type envelope struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Payload any    `json:"payload"`
}

type errorPayload struct {
	Code Code `json:"code"`
}

func Decode(data []byte) (Request, error) {
	fields, err := decodeObject(data, "type", "id", "payload")
	if err != nil {
		return Request{}, &Error{Code: CodeInvalidMessage}
	}

	id, err := decodeString(fields["id"])
	if err != nil || !validID(id) {
		return Request{}, &Error{Code: CodeInvalidMessage}
	}

	typ, err := decodeString(fields["type"])
	if err != nil || typ == "" {
		return Request{ID: id}, &Error{Code: CodeInvalidMessage}
	}

	return Request{Type: typ, ID: id, Payload: fields["payload"]}, nil
}

func validID(id string) bool {
	if id == "" || len(id) > maxIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func encode(typ, id string, payload any) []byte {
	data, err := json.Marshal(envelope{Type: typ, ID: id, Payload: payload})
	if err != nil {
		data, _ = json.Marshal(envelope{Type: "error", ID: id, Payload: errorPayload{Code: CodeInternalError}})
	}
	return data
}

func encodeError(id string, code Code) []byte {
	return encode("error", id, errorPayload{Code: code})
}
