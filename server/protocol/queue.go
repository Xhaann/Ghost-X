package protocol

import (
	"encoding/json"
	"errors"

	"github.com/Xhaann/ghost-x/server/identity"
	"github.com/Xhaann/ghost-x/server/queue"
)

type queuedPayload struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Device     string `json:"device"`
	Ciphertext string `json:"ciphertext"`
}

type receiptPayload struct {
	To     string `json:"to"`
	Device string `json:"device"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

func Send(messages *queue.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "to", "id", "envelopes")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		envelopes, err := decodeEnvelopes(fields["envelopes"])
		if err != nil {
			return Reply{}, err
		}
		messageID, _, err := decodeFixed(fields["id"], MessageIDSize)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		recipient, err := decodeIdentity(fields["to"])
		if err != nil || recipient.String() == id.String() {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if err := messages.Enqueue(c.session, recipient, messageID, envelopes); err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "queued", Payload: struct{}{}}, nil
	}
}

func decodeEnvelopes(raw json.RawMessage) ([]queue.Envelope, error) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil || len(items) == 0 || len(items) > MaxDevicesPerSend {
		return nil, &Error{Code: CodeInvalidPayload}
	}
	out := make([]queue.Envelope, 0, len(items))
	for _, item := range items {
		fields, err := decodeObject(item, "device", "ciphertext")
		if err != nil || len(fields) != 2 {
			return nil, &Error{Code: CodeInvalidPayload}
		}
		deviceID, _, err := decodeFixed(fields["device"], DeviceIDSize)
		if err != nil {
			return nil, &Error{Code: CodeInvalidPayload}
		}
		ciphertext, err := decodeCiphertext(fields["ciphertext"])
		if err != nil {
			return nil, err
		}
		for _, e := range out {
			if e.Device == deviceID {
				return nil, &Error{Code: CodeInvalidPayload}
			}
		}
		out = append(out, queue.Envelope{Device: deviceID, Ciphertext: ciphertext})
	}
	return out, nil
}

func Fetch(messages *queue.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		if _, err := decodeObject(payload); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		if err := messages.Subscribe(c.session); err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "fetched", Payload: struct{}{}}, nil
	}
}

func Ack(messages *queue.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		peer, deviceID, messageID, err := decodeReference(payload, "from")
		if err != nil {
			return Reply{}, err
		}
		if err := messages.Ack(c.session, peer, deviceID, messageID); err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "acked", Payload: struct{}{}}, nil
	}
}

func Clear(messages *queue.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		peer, deviceID, messageID, err := decodeReference(payload, "to")
		if err != nil {
			return Reply{}, err
		}
		if err := messages.Clear(c.session, peer, deviceID, messageID); err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "cleared", Payload: struct{}{}}, nil
	}
}

func EncodePush(p queue.Push) []byte {
	if p.Receipt != nil {
		return encode("receipt", "", receiptPayload{To: p.Receipt.To, Device: p.Receipt.Device, ID: p.Receipt.ID, Status: string(p.Receipt.Status)})
	}
	m := p.Message
	return encode("message", "", queuedPayload{
		ID:         m.ID,
		From:       m.From,
		Device:     m.FromDevice,
		Ciphertext: m.Ciphertext,
	})
}

func decodeReference(payload []byte, peerField string) (identity.Identity, string, string, error) {
	fields, err := decodeObject(payload, peerField, "device", "id")
	if err != nil || len(fields) != 3 {
		return identity.Identity{}, "", "", &Error{Code: CodeInvalidPayload}
	}
	peer, err := decodeIdentity(fields[peerField])
	if err != nil {
		return identity.Identity{}, "", "", &Error{Code: CodeInvalidPayload}
	}
	deviceID, _, err := decodeFixed(fields["device"], DeviceIDSize)
	if err != nil {
		return identity.Identity{}, "", "", &Error{Code: CodeInvalidPayload}
	}
	messageID, _, err := decodeFixed(fields["id"], MessageIDSize)
	if err != nil {
		return identity.Identity{}, "", "", &Error{Code: CodeInvalidPayload}
	}
	return peer, deviceID, messageID, nil
}

func decodeIdentity(raw json.RawMessage) (identity.Identity, error) {
	encoded, err := decodeString(raw)
	if err != nil {
		return identity.Identity{}, err
	}
	return identity.Parse(encoded)
}

func decodeCiphertext(raw json.RawMessage) (string, error) {
	if len(raw) > maxCiphertextText+2 {
		return "", &Error{Code: CodeTooLarge}
	}
	ciphertext, err := decodeString(raw)
	if err != nil {
		return "", &Error{Code: CodeInvalidPayload}
	}
	if len(ciphertext) > maxCiphertextText {
		return "", &Error{Code: CodeTooLarge}
	}
	decoded, err := strict.DecodeString(ciphertext)
	if err != nil || len(decoded) < MinCiphertext || decoded[0] != RatchetVersion {
		return "", &Error{Code: CodeInvalidPayload}
	}
	return ciphertext, nil
}

func queueError(err error) error {
	switch {
	case errors.Is(err, queue.ErrUnauthenticated):
		return &Error{Code: CodeAuthRequired}
	case errors.Is(err, queue.ErrDuplicate):
		return &Error{Code: CodeDuplicate}
	case errors.Is(err, queue.ErrFull):
		return &Error{Code: CodeQueueFull}
	case errors.Is(err, queue.ErrInvalid):
		return &Error{Code: CodeInvalidPayload}
	case errors.Is(err, queue.ErrRevoked):
		return &Error{Code: CodeStaleDevices}
	}
	return err
}
