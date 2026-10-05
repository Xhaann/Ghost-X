package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/Xhaann/ghost-x/server/identity"
)

const (
	challengeSize = 32
	challengeTTL  = 30 * time.Second
)

const proofContext = "ghostx/identity/proof/v1\x00"

type challengePayload struct {
	Nonce string `json:"nonce"`
}

type provenPayload struct {
	Identity string `json:"identity"`
}

func ProofMessage(nonce []byte) []byte {
	return append([]byte(proofContext), nonce...)
}

func Challenge(now func() time.Time) Handler {
	return func(c *Conn, payload []byte) (Reply, error) {
		if _, err := decodeObject(payload); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		nonce := make([]byte, challengeSize)
		if _, err := rand.Read(nonce); err != nil {
			return Reply{}, err
		}
		c.challenge = nonce
		c.expires = now().Add(challengeTTL)
		return Reply{
			Type:    "challenge",
			Payload: challengePayload{Nonce: base64.RawURLEncoding.EncodeToString(nonce)},
		}, nil
	}
}

func Prove(now func() time.Time) Handler {
	return func(c *Conn, payload []byte) (Reply, error) {
		nonce, expires := c.challenge, c.expires
		c.challenge = nil

		fields, err := decodeObject(payload, "identity", "signature")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		encoded, err := decodeString(fields["identity"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		signature, err := decodeString(fields["signature"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		id, err := identity.Parse(encoded)
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}

		if nonce == nil || !now().Before(expires) {
			return Reply{}, &Error{Code: CodeInvalidProof}
		}
		if err := id.Verify(ProofMessage(nonce), signature); err != nil {
			return Reply{}, &Error{Code: CodeInvalidProof}
		}
		return Reply{Type: "proven", Payload: provenPayload{Identity: id.String()}}, nil
	}
}
