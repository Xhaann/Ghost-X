package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/identity"
	"github.com/Xhaann/ghost-x/server/prekey"
)

const (
	DeviceIDSize     = 16
	ConfirmSize      = 32
	HandshakeVersion = 3
)

const (
	signedContext     = "ghostx/prekey/signed/v2\x00"
	onetimeContext    = "ghostx/prekey/onetime/v2\x00"
	transcriptContext = "ghostx/x3dh/v3\x00"
	proofContext      = "ghostx/x3dh/initiate/v3\x00"
)

type prekeyPayload struct {
	ID        uint32 `json:"id"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type deviceBundlePayload struct {
	Device  string         `json:"device"`
	Signed  prekeyPayload  `json:"signed"`
	Onetime *prekeyPayload `json:"onetime"`
}

type prekeyBundlePayload struct {
	Version  int                   `json:"version"`
	Identity string                `json:"identity"`
	Bundles  []deviceBundlePayload `json:"bundles"`
}

type initiationPayload struct {
	Version   int     `json:"version"`
	From      string  `json:"from"`
	Device    string  `json:"device"`
	Signed    uint32  `json:"signed"`
	Onetime   *uint32 `json:"onetime"`
	Ephemeral string  `json:"ephemeral"`
	Ratchet   string  `json:"ratchet"`
	Proof     string  `json:"proof"`
	Confirm   string  `json:"confirm"`
}

type acceptancePayload struct {
	From      string `json:"from"`
	Device    string `json:"device"`
	Ephemeral string `json:"ephemeral"`
	Confirm   string `json:"confirm"`
}

func prekeyMessage(context string, owner, deviceID, exchange []byte, id uint32, key []byte) []byte {
	out := make([]byte, 0, len(context)+32+16+32+4+32)
	out = append(out, context...)
	out = append(out, owner...)
	out = append(out, deviceID...)
	out = append(out, exchange...)
	out = binary.BigEndian.AppendUint32(out, id)
	return append(out, key...)
}

func SignedPrekeyMessage(owner, deviceID, exchange []byte, id uint32, key []byte) []byte {
	return prekeyMessage(signedContext, owner, deviceID, exchange, id, key)
}

func OnetimePrekeyMessage(owner, deviceID, exchange []byte, id uint32, key []byte) []byte {
	return prekeyMessage(onetimeContext, owner, deviceID, exchange, id, key)
}

type Transcript struct {
	Initiator, InitiatorDevice       []byte
	Responder, ResponderDevice       []byte
	InitiatorStatic, ResponderStatic []byte
	Signed                           uint32
	SignedKey                        []byte
	Onetime                          *uint32
	OnetimeKey                       []byte
	Ephemeral                        []byte
	Ratchet                          []byte
}

func (t Transcript) Bytes() []byte {
	out := append([]byte(transcriptContext), t.Initiator...)
	out = append(out, t.InitiatorDevice...)
	out = append(out, t.Responder...)
	out = append(out, t.ResponderDevice...)
	out = append(out, t.InitiatorStatic...)
	out = append(out, t.ResponderStatic...)
	out = binary.BigEndian.AppendUint32(out, t.Signed)
	out = append(out, t.SignedKey...)
	if t.Onetime != nil {
		out = append(out, 1)
		out = binary.BigEndian.AppendUint32(out, *t.Onetime)
		out = append(out, t.OnetimeKey...)
	} else {
		out = append(out, 0)
	}
	out = append(out, t.Ephemeral...)
	return append(out, t.Ratchet...)
}

func ProofMessage(t Transcript) []byte {
	return append([]byte(proofContext), t.Bytes()...)
}

func decodePrekey(raw json.RawMessage) (prekey.Prekey, []byte, error) {
	fields, err := decodeObject(raw, "id", "key", "signature")
	if err != nil {
		return prekey.Prekey{}, nil, err
	}
	id, err := decodeEpoch(fields["id"])
	if err != nil {
		return prekey.Prekey{}, nil, err
	}
	key, keyRaw, err := decodeFixed(fields["key"], KeySize)
	if err != nil || !CanonicalExchangeKey(keyRaw) {
		return prekey.Prekey{}, nil, errMalformed
	}
	signature, err := decodeString(fields["signature"])
	if err != nil {
		return prekey.Prekey{}, nil, err
	}
	return prekey.Prekey{ID: id, Key: key, Signature: signature}, keyRaw, nil
}

func ownerRaw(id identity.Identity) []byte {
	raw, _ := strict.DecodeString(id.String())
	return raw
}

func Prekeys(devices *device.Registry, prekeys *prekey.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "device", "signed", "onetime")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		deviceID, deviceRaw, err := decodeFixed(fields["device"], DeviceIDSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		own, _ := c.session.Device()
		if deviceID != own {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		key, entry, ok := devices.Key(id.String(), deviceID)
		if !ok {
			return Reply{}, &Error{Code: CodeRevoked}
		}
		exchange := decodedText(entry.Exchange)
		owner := ownerRaw(id)
		signed, signedRaw, err := decodePrekey(fields["signed"])
		if err != nil || key.Verify(SignedPrekeyMessage(owner, deviceRaw, exchange, signed.ID, signedRaw), signed.Signature) != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		var items []json.RawMessage
		if raw := fields["onetime"]; len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil || len(items) > prekey.MaxOnetime {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		onetime := make([]prekey.Prekey, 0, len(items))
		seen := make(map[uint32]struct{}, len(items))
		for _, item := range items {
			p, keyRaw, err := decodePrekey(item)
			if err != nil || key.Verify(OnetimePrekeyMessage(owner, deviceRaw, exchange, p.ID, keyRaw), p.Signature) != nil {
				return Reply{}, &Error{Code: CodeInvalidPayload}
			}
			if _, dup := seen[p.ID]; dup || p.Key == signed.Key {
				return Reply{}, &Error{Code: CodeInvalidPayload}
			}
			seen[p.ID] = struct{}{}
			onetime = append(onetime, p)
		}
		available, err := prekeys.Publish(c.session, deviceID, signed, onetime)
		switch {
		case errors.Is(err, prekey.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, prekey.ErrRevoked):
			return Reply{}, &Error{Code: CodeRevoked}
		case errors.Is(err, prekey.ErrInvalid):
			return Reply{}, &Error{Code: CodeInvalidPayload}
		case errors.Is(err, prekey.ErrLimit):
			return Reply{}, &Error{Code: CodeSessionLimit}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "prekeys", Payload: struct {
			Available int `json:"available"`
		}{available}}, nil
	}
}

func encodePrekey(p prekey.Prekey) prekeyPayload {
	return prekeyPayload{ID: p.ID, Key: p.Key, Signature: p.Signature}
}

func FetchBundle(prekeys *prekey.Registry) ProtectedHandler {
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
		bundles, ok := prekeys.Fetch(owner)
		if !ok {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		out := prekeyBundlePayload{Version: HandshakeVersion, Identity: owner.String(), Bundles: make([]deviceBundlePayload, 0, len(bundles))}
		for _, b := range bundles {
			d := deviceBundlePayload{Device: b.Device, Signed: encodePrekey(b.Signed)}
			if b.Onetime != nil {
				p := encodePrekey(*b.Onetime)
				d.Onetime = &p
			}
			out.Bundles = append(out.Bundles, d)
		}
		return Reply{Type: "bundle", Payload: out}, nil
	}
}

func decodeOptionalID(raw json.RawMessage) (*uint32, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	id, err := decodeEpoch(raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func Initiate(devices *device.Registry, prekeys *prekey.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "version", "to", "device", "signed", "onetime", "ephemeral", "ratchet", "proof", "confirm")
		if err != nil || string(fields["version"]) != "3" {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		to, err := decodeIdentity(fields["to"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		target, targetRaw, err := decodeFixed(fields["device"], DeviceIDSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		signed, err := decodeEpoch(fields["signed"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		onetime, err := decodeOptionalID(fields["onetime"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		ephemeral, ephemeralRaw, err := decodeFixed(fields["ephemeral"], KeySize)
		if err != nil || !CanonicalExchangeKey(ephemeralRaw) {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		ratchet, ratchetRaw, err := decodeFixed(fields["ratchet"], KeySize)
		if err != nil || !CanonicalExchangeKey(ratchetRaw) {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		proof, err := decodeString(fields["proof"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		confirm, _, err := decodeFixed(fields["confirm"], ConfirmSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		own, _ := c.session.Device()
		senderKey, sender, ok := devices.Key(id.String(), own)
		if !ok {
			return Reply{}, &Error{Code: CodeRevoked}
		}
		_, recipient, ok := devices.Key(to.String(), target)
		if !ok {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		current, previous, ok := prekeys.Device(to, target)
		if !ok {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		spk := current
		if signed != current.ID {
			if previous == nil || signed != previous.ID {
				return Reply{}, &Error{Code: CodeStaleSession}
			}
			spk = *previous
		}
		t := Transcript{
			Initiator:       ownerRaw(id),
			InitiatorDevice: decodedText(own),
			Responder:       ownerRaw(to),
			ResponderDevice: targetRaw,
			InitiatorStatic: decodedText(sender.Exchange),
			ResponderStatic: decodedText(recipient.Exchange),
			Signed:          signed,
			SignedKey:       decodedText(spk.Key),
			Onetime:         onetime,
			Ephemeral:       ephemeralRaw,
			Ratchet:         ratchetRaw,
		}
		if onetime != nil {
			key, ok := prekeys.Onetime(to, target, *onetime)
			if !ok {
				return Reply{}, &Error{Code: CodeStaleSession}
			}
			t.OnetimeKey = decodedText(key)
		}
		if err := senderKey.Verify(ProofMessage(t), proof); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		init := prekey.Initiation{
			Device:    target,
			Signed:    signed,
			Onetime:   onetime,
			Ephemeral: ephemeral,
			Ratchet:   ratchet,
			Proof:     proof,
			Confirm:   confirm,
		}
		switch err := prekeys.Initiate(c.session, to, init, spk.Key); {
		case errors.Is(err, prekey.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, prekey.ErrRevoked):
			return Reply{}, &Error{Code: CodeRevoked}
		case errors.Is(err, prekey.ErrUnavailable):
			return Reply{}, &Error{Code: CodeUnavailable}
		case errors.Is(err, prekey.ErrInvalid):
			return Reply{}, &Error{Code: CodeStaleSession}
		case errors.Is(err, prekey.ErrDuplicate):
			return Reply{}, &Error{Code: CodeDuplicate}
		case errors.Is(err, prekey.ErrLimit):
			return Reply{}, &Error{Code: CodePendingLimit}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "initiated", Payload: struct{}{}}, nil
	}
}

func Accept(prekeys *prekey.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "to", "device", "ephemeral", "confirm")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		to, err := decodeIdentity(fields["to"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		target, _, err := decodeFixed(fields["device"], DeviceIDSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		ephemeral, _, err := decodeFixed(fields["ephemeral"], KeySize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		confirm, _, err := decodeFixed(fields["confirm"], ConfirmSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		switch err := prekeys.Accept(c.session, to, target, ephemeral, confirm); {
		case errors.Is(err, prekey.ErrUnauthenticated):
			return Reply{}, &Error{Code: CodeAuthRequired}
		case errors.Is(err, prekey.ErrRevoked):
			return Reply{}, &Error{Code: CodeRevoked}
		case errors.Is(err, prekey.ErrInvalid):
			return Reply{}, &Error{Code: CodeInvalidPayload}
		case errors.Is(err, prekey.ErrLimit):
			return Reply{}, &Error{Code: CodePendingLimit}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "accepted", Payload: struct{}{}}, nil
	}
}

func decodedText(text string) []byte {
	raw, _ := strict.DecodeString(text)
	return raw
}

func EncodeEvent(e prekey.Event) []byte {
	if e.Acceptance != nil {
		a := e.Acceptance
		return encode("acceptance", "", acceptancePayload{From: a.From, Device: a.FromDevice, Ephemeral: a.Ephemeral, Confirm: a.Confirm})
	}
	i := e.Initiation
	return encode("initiation", "", initiationPayload{
		Version:   HandshakeVersion,
		From:      i.From,
		Device:    i.FromDevice,
		Signed:    i.Signed,
		Onetime:   i.Onetime,
		Ephemeral: i.Ephemeral,
		Ratchet:   i.Ratchet,
		Proof:     i.Proof,
		Confirm:   i.Confirm,
	})
}
