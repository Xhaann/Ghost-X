package protocol

import (
	"encoding/json"
	"errors"

	"github.com/Xhaann/ghost-x/server/direct"
	"github.com/Xhaann/ghost-x/server/identity"
	"github.com/Xhaann/ghost-x/server/prekey"
	"github.com/Xhaann/ghost-x/server/queue"
)

type queuedPayload struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Key        string `json:"key"`
	Signature  string `json:"signature"`
	Ciphertext string `json:"ciphertext"`
}

type receiptPayload struct {
	To     string `json:"to"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

func Send(keys *direct.Registry, prekeys *prekey.Registry, messages *queue.Registry) ProtectedHandler {
	return func(c *Conn, id identity.Identity, payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "to", "id", "ciphertext")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		ciphertext, err := decodeCiphertext(fields["ciphertext"])
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
		static, ok := keys.Static(c.session)
		if !ok {
			return Reply{}, &Error{Code: CodeKeyRequired}
		}
		if !prekeys.Known(recipient) {
			return Reply{}, &Error{Code: CodeUnavailable}
		}
		err = messages.Enqueue(c.session, recipient, queue.Message{
			ID:         messageID,
			Key:        static.Key,
			Signature:  static.Signature,
			Ciphertext: ciphertext,
		})
		if err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "queued", Payload: struct{}{}}, nil
	}
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
		peer, messageID, err := decodeReference(payload, "from")
		if err != nil {
			return Reply{}, err
		}
		if err := messages.Ack(c.session, peer, messageID); err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "acked", Payload: struct{}{}}, nil
	}
}

func Clear(messages *queue.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		peer, messageID, err := decodeReference(payload, "to")
		if err != nil {
			return Reply{}, err
		}
		if err := messages.Clear(c.session, peer, messageID); err != nil {
			return Reply{}, queueError(err)
		}
		return Reply{Type: "cleared", Payload: struct{}{}}, nil
	}
}

func EncodePush(p queue.Push) []byte {
	if p.Receipt != nil {
		return encode("receipt", "", receiptPayload{To: p.Receipt.To, ID: p.Receipt.ID, Status: string(p.Receipt.Status)})
	}
	m := p.Message
	return encode("message", "", queuedPayload{
		ID:         m.ID,
		From:       m.From,
		Key:        m.Key,
		Signature:  m.Signature,
		Ciphertext: m.Ciphertext,
	})
}

func decodeReference(payload []byte, peerField string) (identity.Identity, string, error) {
	fields, err := decodeObject(payload, peerField, "id")
	if err != nil {
		return identity.Identity{}, "", &Error{Code: CodeInvalidPayload}
	}
	peer, err := decodeIdentity(fields[peerField])
	if err != nil {
		return identity.Identity{}, "", &Error{Code: CodeInvalidPayload}
	}
	messageID, _, err := decodeFixed(fields["id"], MessageIDSize)
	if err != nil {
		return identity.Identity{}, "", &Error{Code: CodeInvalidPayload}
	}
	return peer, messageID, nil
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
	}
	return err
}
