package protocol

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"

	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	MaxBodySize   = 4096
	KeySize       = 32
	SessionIDSize = 16
	SaltSize      = 32
	IVSize        = 12
	TagSize       = 16
	MaxCiphertext = MaxBodySize + TagSize
	MinCiphertext = 1 + TagSize
)

const (
	keyContext     = "ghostx/encryption/key/v1\x00"
	sessionContext = "ghostx/session/v1\x00"
)

var maxCiphertextText = base64.RawURLEncoding.EncodedLen(MaxCiphertext)

var strict = base64.RawURLEncoding.Strict()

var epochPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`)

type bundlePayload struct {
	Identity  string          `json:"identity"`
	Key       string          `json:"key"`
	Signature string          `json:"signature"`
	Sessions  []sessionBundle `json:"sessions"`
}

type sessionBundle struct {
	Session   string `json:"session"`
	Epoch     uint32 `json:"epoch"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type envelopePayload struct {
	Session    string `json:"session"`
	Epoch      uint32 `json:"epoch"`
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

type messagePayload struct {
	ID        string          `json:"id"`
	From      string          `json:"from"`
	Key       string          `json:"key"`
	Signature string          `json:"signature"`
	Sender    sessionBundle   `json:"sender"`
	Envelope  envelopePayload `json:"envelope"`
}

func KeyMessage(owner string, key []byte) []byte {
	return append(append([]byte(keyContext), owner...), key...)
}

func SessionMessage(owner, staticKey, session []byte, epoch uint32, key []byte) []byte {
	out := make([]byte, 0, len(sessionContext)+32+32+16+4+32)
	out = append(out, sessionContext...)
	out = append(out, owner...)
	out = append(out, staticKey...)
	out = append(out, session...)
	out = binary.BigEndian.AppendUint32(out, epoch)
	return append(out, key...)
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

func Establish(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "session", "epoch", "key", "signature")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		session, sessionRaw, err := decodeFixed(fields["session"], SessionIDSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		epoch, err := decodeEpoch(fields["epoch"])
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
		static, ok := registry.Bundle(id)
		if !ok {
			return Reply{}, &Error{Code: CodeKeyRequired}
		}
		staticRaw, err := strict.DecodeString(static.Key)
		if err != nil {
			return Reply{}, err
		}
		owner, err := strict.DecodeString(id.String())
		if err != nil {
			return Reply{}, err
		}
		if err := id.Verify(SessionMessage(owner, staticRaw, sessionRaw, epoch, keyRaw), signature); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		bundle := direct.SessionBundle{ID: session, Epoch: epoch, Key: key, Signature: signature}
		switch err := registry.Establish(c.session, static.Key, bundle); {
		case errors.Is(err, direct.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, direct.ErrNoKey):
			return Reply{}, &Error{Code: CodeKeyRequired}
		case errors.Is(err, direct.ErrStale):
			return Reply{}, &Error{Code: CodeStaleSession}
		case errors.Is(err, direct.ErrSessionLimit):
			return Reply{}, &Error{Code: CodeSessionLimit}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "established", Payload: struct{}{}}, nil
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
		bundle, sessions, ok := registry.Lookup(owner)
		if !ok {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		out := make([]sessionBundle, 0, len(sessions))
		for _, s := range sessions {
			out = append(out, encodeSession(s))
		}
		return Reply{Type: "key", Payload: bundlePayload{
			Identity:  owner.String(),
			Key:       bundle.Key,
			Signature: bundle.Signature,
			Sessions:  out,
		}}, nil
	}
}

func Send(registry *direct.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "to", "epoch", "envelopes")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		epoch, err := decodeEpoch(fields["epoch"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		envelopes, err := decodeEnvelopes(fields["envelopes"])
		if err != nil {
			return Reply{}, err
		}
		encoded, err := decodeString(fields["to"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		recipient, err := identity.Parse(encoded)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}

		switch err := registry.Send(c.session, recipient, c.request, epoch, envelopes); {
		case errors.Is(err, direct.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, direct.ErrNoKey):
			return Reply{}, &Error{Code: CodeKeyRequired}
		case errors.Is(err, direct.ErrStale):
			return Reply{}, &Error{Code: CodeStaleSession}
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
		ID:        m.ID,
		From:      m.From,
		Key:       m.Sender.Key,
		Signature: m.Sender.Signature,
		Sender:    encodeSession(m.Session),
		Envelope: envelopePayload{
			Session:    m.Envelope.Session,
			Epoch:      m.Envelope.Epoch,
			Salt:       m.Envelope.Salt,
			IV:         m.Envelope.IV,
			Ciphertext: m.Envelope.Ciphertext,
		},
	})
}

func encodeSession(s direct.SessionBundle) sessionBundle {
	return sessionBundle{Session: s.ID, Epoch: s.Epoch, Key: s.Key, Signature: s.Signature}
}

func decodeEnvelopes(raw json.RawMessage) ([]direct.Envelope, error) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, &Error{Code: CodeInvalidPayload}
	}
	if len(items) == 0 || len(items) > direct.MaxSessions {
		return nil, &Error{Code: CodeInvalidPayload}
	}
	seen := make(map[string]struct{}, len(items))
	envelopes := make([]direct.Envelope, 0, len(items))
	for _, item := range items {
		envelope, err := decodeEnvelope(item)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[envelope.Session]; dup {
			return nil, &Error{Code: CodeInvalidPayload}
		}
		seen[envelope.Session] = struct{}{}
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
}

func decodeEnvelope(raw json.RawMessage) (direct.Envelope, error) {
	fields, err := decodeObject(raw, "session", "epoch", "salt", "iv", "ciphertext")
	if err != nil {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	if len(fields["ciphertext"]) > maxCiphertextText+2 {
		return direct.Envelope{}, &Error{Code: CodeTooLarge}
	}
	ciphertext, err := decodeString(fields["ciphertext"])
	if err != nil {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	if len(ciphertext) > maxCiphertextText {
		return direct.Envelope{}, &Error{Code: CodeTooLarge}
	}
	decoded, err := strict.DecodeString(ciphertext)
	if err != nil || len(decoded) < MinCiphertext {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	session, _, err := decodeFixed(fields["session"], SessionIDSize)
	if err != nil {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	epoch, err := decodeEpoch(fields["epoch"])
	if err != nil {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	salt, _, err := decodeFixed(fields["salt"], SaltSize)
	if err != nil {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	iv, _, err := decodeFixed(fields["iv"], IVSize)
	if err != nil {
		return direct.Envelope{}, &Error{Code: CodeInvalidPayload}
	}
	return direct.Envelope{Session: session, Epoch: epoch, Salt: salt, IV: iv, Ciphertext: ciphertext}, nil
}

func decodeEpoch(raw json.RawMessage) (uint32, error) {
	if !epochPattern.Match(raw) {
		return 0, errMalformed
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || value > direct.MaxEpoch {
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
