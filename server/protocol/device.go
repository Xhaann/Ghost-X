package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"

	"github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	MaxBodySize       = 4096
	KeySize           = 32
	TagSize           = 16
	MaxID             = 1<<31 - 1
	MessageIDSize     = 16
	MessageIDText     = 22
	RatchetVersion    = 1
	RatchetHeader     = 1 + 16 + 32 + 4 + 4
	MaxCiphertext     = RatchetHeader + MessageIDText + MaxBodySize + TagSize
	MinCiphertext     = RatchetHeader + MessageIDText + 1 + TagSize
	MaxDevicesPerSend = 4
	MaxRegistrations  = 8
	MaxLookups        = 256
)

var maxCiphertextText = base64.RawURLEncoding.EncodedLen(MaxCiphertext)

var strict = base64.RawURLEncoding.Strict()

var idPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`)

type devicePayload struct {
	ID       string `json:"id"`
	Signing  string `json:"signing"`
	Exchange string `json:"exchange"`
}

type rosterPayload struct {
	Identity  string          `json:"identity"`
	Version   uint32          `json:"version"`
	Devices   []devicePayload `json:"devices"`
	Signature string          `json:"signature"`
}

type registeredPayload struct {
	Version uint32 `json:"version"`
}

type authenticatedPayload struct {
	Identity string `json:"identity"`
	Device   string `json:"device"`
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

func EncodeRoster(r device.Roster) rosterPayload {
	out := rosterPayload{Identity: r.Identity, Version: r.Version, Signature: r.Signature, Devices: make([]devicePayload, 0, len(r.Devices))}
	for _, d := range r.Devices {
		out.Devices = append(out.Devices, devicePayload{ID: d.ID, Signing: d.Signing, Exchange: d.Exchange})
	}
	return out
}

func decodeRoster(payload []byte) (device.Roster, error) {
	fields, err := decodeObject(payload, "identity", "version", "devices", "signature")
	if err != nil || len(fields) != 4 {
		return device.Roster{}, errMalformed
	}
	owner, err := decodeString(fields["identity"])
	if err != nil {
		return device.Roster{}, err
	}
	version, err := decodeEpoch(fields["version"])
	if err != nil || version == 0 {
		return device.Roster{}, errMalformed
	}
	signature, err := decodeString(fields["signature"])
	if err != nil {
		return device.Roster{}, err
	}
	var items []json.RawMessage
	if raw := fields["devices"]; len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil || len(items) == 0 || len(items) > device.MaxDevices {
		return device.Roster{}, errMalformed
	}
	devices := make([]device.Device, 0, len(items))
	for _, item := range items {
		f, err := decodeObject(item, "id", "signing", "exchange")
		if err != nil || len(f) != 3 {
			return device.Roster{}, errMalformed
		}
		id, _, err := decodeFixed(f["id"], device.IDSize)
		if err != nil {
			return device.Roster{}, err
		}
		signing, _, err := decodeFixed(f["signing"], KeySize)
		if err != nil {
			return device.Roster{}, err
		}
		exchange, _, err := decodeFixed(f["exchange"], KeySize)
		if err != nil {
			return device.Roster{}, err
		}
		devices = append(devices, device.Device{ID: id, Signing: signing, Exchange: exchange})
	}
	return device.Roster{Identity: owner, Version: version, Devices: devices, Signature: signature}, nil
}

func Register(devices *device.Registry) Handler {
	return func(c *Conn, payload []byte) (Reply, error) {
		if c.registrations >= MaxRegistrations {
			return Reply{}, &Error{Code: CodeRateLimited}
		}
		c.registrations++
		roster, err := decodeRoster(payload)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		switch err := devices.Publish(roster); {
		case errors.Is(err, device.ErrInvalid):
			return Reply{}, &Error{Code: CodeInvalidPayload}
		case errors.Is(err, device.ErrStale):
			return Reply{}, &Error{Code: CodeStaleRoster}
		case errors.Is(err, device.ErrLimit):
			return Reply{}, &Error{Code: CodeRegistryFull}
		case errors.Is(err, device.ErrReused):
			return Reply{}, &Error{Code: CodeRevoked}
		case errors.Is(err, device.ErrRate):
			return Reply{}, &Error{Code: CodeRateLimited}
		case err != nil:
			return Reply{}, err
		}
		return Reply{Type: "registered", Payload: registeredPayload{Version: roster.Version}}, nil
	}
}

func Devices(devices *device.Registry) Handler {
	return func(c *Conn, payload []byte) (Reply, error) {
		if c.lookups >= MaxLookups {
			return Reply{}, &Error{Code: CodeRateLimited}
		}
		c.lookups++
		fields, err := decodeObject(payload, "identity")
		if err != nil || len(fields) != 1 {
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
		roster, ok := devices.Roster(owner.String())
		if !ok {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		return Reply{Type: "devices", Payload: EncodeRoster(roster)}, nil
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
