package protocol

import (
	"encoding/base64"
	"errors"

	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	MaxBodySize   = 4096
	KeySize       = 32
	SaltSize      = 32
	IVSize        = 12
	TagSize       = 16
	MaxCiphertext = MaxBodySize + TagSize
	MinCiphertext = 1 + TagSize
)

const keyContext = "ghostx/encryption/key/v1\x00"

var maxCiphertextText = base64.RawURLEncoding.EncodedLen(MaxCiphertext)

var strict = base64.RawURLEncoding.Strict()

type bundlePayload struct {
	Identity  string `json:"identity"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type messagePayload struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Key        string `json:"key"`
	Signature  string `json:"signature"`
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func KeyMessage(owner string, key []byte) []byte {
	return append(append([]byte(keyContext), owner...), key...)
}

func Publish(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "key", "signature")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		key, keyRaw, err := decodeFixed(fields["key"], KeySize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		signature, err := decodeString(fields["signature"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if err := id.Verify(KeyMessage(id.String(), keyRaw), signature); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		switch err := registry.Publish(c.session, direct.Bundle{Key: key, Signature: signature}); {
		case errors.Is(err, direct.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, direct.ErrKeyConflict):
			return Reply{}, &Error{Code: CodeInvalidPayload}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "published", Payload: struct{}{}}, nil
	}
}

func Key(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "identity")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		encoded, err := decodeString(fields["identity"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		owner, err := identity.Parse(encoded)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		bundle, ok := registry.Bundle(owner)
		if !ok {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		return Reply{Type: "key", Payload: bundlePayload{
			Identity:  owner.String(),
			Key:       bundle.Key,
			Signature: bundle.Signature,
		}}, nil
	}
}

func Send(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "to", "salt", "iv", "ciphertext")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if len(fields["ciphertext"]) > maxCiphertextText+2 {
			return Reply{}, &Error{Code: CodeTooLarge}
		}
		ciphertext, err := decodeString(fields["ciphertext"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if len(ciphertext) > maxCiphertextText {
			return Reply{}, &Error{Code: CodeTooLarge}
		}
		raw, err := strict.DecodeString(ciphertext)
		if err != nil || len(raw) < MinCiphertext {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		salt, _, err := decodeFixed(fields["salt"], SaltSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		iv, _, err := decodeFixed(fields["iv"], IVSize)
		if err != nil {
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

		envelope := direct.Envelope{Salt: salt, IV: iv, Ciphertext: ciphertext}
		switch err := registry.Send(c.session, recipient, c.request, envelope); {
		case errors.Is(err, direct.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, direct.ErrNoKey):
			return Reply{}, &Error{Code: CodeKeyRequired}
		case errors.Is(err, direct.ErrDuplicate):
			return Reply{}, &Error{Code: CodeDuplicate}
		case errors.Is(err, direct.ErrUnavailable):
			return Reply{}, &Error{Code: CodeUnavailable}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "sent", Payload: struct{}{}}, nil
	}
}

func EncodeMessage(m direct.Message) []byte {
	return encode("message", "", messagePayload{
		ID:         m.ID,
		From:       m.From,
		Key:        m.Sender.Key,
		Signature:  m.Sender.Signature,
		Salt:       m.Envelope.Salt,
		IV:         m.Envelope.IV,
		Ciphertext: m.Envelope.Ciphertext,
	})
}

func decodeFixed(raw []byte, size int) (string, []byte, error) {
	text, err := decodeString(raw)
	if err != nil {
		return "", nil, err
	}
	if len(text) != base64.RawURLEncoding.EncodedLen(size) {
		return "", nil, errMalformed
	}
	decoded, err := strict.DecodeString(text)
	if err != nil || len(decoded) != size {
		return "", nil, errMalformed
	}
	return text, decoded, nil
}
