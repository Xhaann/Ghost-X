package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"

	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	MaxBodySize    = 4096
	KeySize        = 32
	TagSize        = 16
	MaxID          = 1<<31 - 1
	MessageIDSize  = 16
	MessageIDText  = 22
	RatchetVersion = 1
	RatchetHeader  = 1 + 16 + 32 + 4 + 4
	MaxCiphertext  = RatchetHeader + MessageIDText + MaxBodySize + TagSize
	MinCiphertext  = RatchetHeader + MessageIDText + 1 + TagSize
)

const keyContext = "ghostx/encryption/key/v1\x00"

var maxCiphertextText = base64.RawURLEncoding.EncodedLen(MaxCiphertext)

var strict = base64.RawURLEncoding.Strict()

var idPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`)

type bundlePayload struct {
	Identity  string `json:"identity"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

func KeyMessage(owner string, key []byte) []byte {
	return append(append([]byte(keyContext), owner...), key...)
}

func CanonicalExchangeKey(raw []byte) bool {
	if len(raw) != KeySize || raw[31]&0x80 != 0 {
		return false
	}
	if raw[31] != 0x7f {
		return true
	}
	for i := 30; i >= 1; i-- {
		if raw[i] != 0xff {
			return true
		}
	}
	return raw[0] < 0xed
}

func Publish(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "key", "signature")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		key, keyRaw, err := decodeFixed(fields["key"], KeySize)
		if err != nil || !CanonicalExchangeKey(keyRaw) {
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

func decodeEpoch(raw json.RawMessage) (uint32, error) {
	if !idPattern.Match(raw) {
		return 0, errMalformed
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || value > MaxID {
		return 0, errMalformed
	}
	return uint32(value), nil
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
