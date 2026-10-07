package protocol

import (
	"encoding/base64"
	"errors"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

type challengePayload struct {
	Nonce string `json:"nonce"`
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
		var encoded, deviceID, signature string
		fields, err := decodeObject(payload, "identity", "device", "signature")
		if err == nil {
			encoded, err = decodeString(fields["identity"])
		}
		if err == nil {
			deviceID, err = decodeString(fields["device"])
		}
		if err == nil {
			signature, err = decodeString(fields["signature"])
		}
		if err != nil {
			encoded, deviceID, signature = "", "", ""
		}

		id, authErr := c.session.Authenticate(encoded, deviceID, signature)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if authErr != nil {
			return Reply{}, authError(authErr)
		}
		return Reply{Type: "authenticated", Payload: authenticatedPayload{Identity: id.String(), Device: deviceID}}, nil
	}
}

func WhoAmI() ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		if _, err := decodeObject(payload); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		deviceID, _ := c.session.Device()
		return Reply{Type: "whoami", Payload: authenticatedPayload{Identity: id.String(), Device: deviceID}}, nil
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
