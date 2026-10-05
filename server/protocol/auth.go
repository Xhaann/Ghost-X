package protocol

import (
	"encoding/base64"
	"errors"

	"github.com/Xhaann/ghost-x/server/auth"
)

type challengePayload struct {
	Nonce string `json:"nonce"`
}

type identityPayload struct {
	Identity string `json:"identity"`
}

func Challenge() Handler {
	return func(c *Conn, payload []byte) (Reply, error) {
		if _, err := decodeObject(payload); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		nonce, err := c.session.Challenge()
		if err != nil {
			return Reply{}, authError(err)
		}
		return Reply{
			Type:    "challenge",
			Payload: challengePayload{Nonce: base64.RawURLEncoding.EncodeToString(nonce)},
		}, nil
	}
}

func Authenticate() Handler {
	return func(c *Conn, payload []byte) (Reply, error) {
		var encoded, signature string
		fields, err := decodeObject(payload, "identity", "signature")
		if err == nil {
			encoded, err = decodeString(fields["identity"])
		}
		if err == nil {
			signature, err = decodeString(fields["signature"])
		}
		if err != nil {
			encoded, signature = "", ""
		}

		id, authErr := c.session.Authenticate(encoded, signature)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if authErr != nil {
			return Reply{}, authError(authErr)
		}
		return Reply{Type: "authenticated", Payload: identityPayload{Identity: id.String()}}, nil
	}
}

func authError(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidIdentity):
		return &Error{Code: CodeInvalidPayload}
	case errors.Is(err, auth.ErrFailed), errors.Is(err, auth.ErrClosed):
		return &Error{Code: CodeAuthFailed}
	}
	return err
}
