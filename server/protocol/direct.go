package protocol

import (
	"errors"

	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/identity"
)

const MaxBodySize = 4096

const maxRawBody = MaxBodySize*6 + 2

type messagePayload struct {
	From string `json:"from"`
	Body string `json:"body"`
}

func Send(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "to", "body")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if len(fields["body"]) > maxRawBody {
			return Reply{}, &Error{Code: CodeTooLarge}
		}
		body, err := decodeString(fields["body"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if len(body) > MaxBodySize {
			return Reply{}, &Error{Code: CodeTooLarge}
		}
		if !validBody(body) {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		encoded, err := decodeString(fields["to"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		recipient, err := identity.Parse(encoded)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}

		switch err := registry.Send(c.session, recipient, body); {
		case errors.Is(err, direct.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, direct.ErrUnavailable):
			return Reply{}, &Error{Code: CodeUnavailable}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "sent", Payload: struct{}{}}, nil
	}
}

func EncodeMessage(m direct.Message) []byte {
	return encode("message", "", messagePayload{From: m.From, Body: m.Body})
}

func validBody(body string) bool {
	if body == "" {
		return false
	}
	for _, r := range body {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return false
		}
	}
	return true
}
