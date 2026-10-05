package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"filippo.io/edwards25519"
)

const (
	EncodedLength          = 43
	EncodedSignatureLength = 86
)

var (
	ErrInvalidIdentity  = errors.New("identity: invalid identity")
	ErrInvalidSignature = errors.New("identity: invalid signature")
)

var encoding = base64.RawURLEncoding.Strict()

var groupOrderMinusOne = mustScalar([]byte{
	0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
})

type Identity struct {
	key ed25519.PublicKey
}

func Parse(encoded string) (Identity, error) {
	raw, err := decode(encoded, EncodedLength, ed25519.PublicKeySize)
	if err != nil || !primeOrder(raw) {
		return Identity{}, ErrInvalidIdentity
	}
	return Identity{key: ed25519.PublicKey(raw)}, nil
}

func (id Identity) String() string {
	return encoding.EncodeToString(id.key)
}

func (id Identity) Equal(other Identity) bool {
	return id.key.Equal(other.key)
}

func (id Identity) Verify(message []byte, signature string) error {
	sig, err := decode(signature, EncodedSignatureLength, ed25519.SignatureSize)
	if err != nil || len(id.key) != ed25519.PublicKeySize || !ed25519.Verify(id.key, message, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func decode(encoded string, encodedLength, size int) ([]byte, error) {
	if len(encoded) != encodedLength {
		return nil, errors.New("identity: invalid length")
	}
	raw, err := encoding.DecodeString(encoded)
	if err != nil || len(raw) != size {
		return nil, errors.New("identity: invalid encoding")
	}
	return raw, nil
}

func primeOrder(raw []byte) bool {
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return false
	}
	if string(point.Bytes()) != string(raw) {
		return false
	}
	if point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	check := new(edwards25519.Point).ScalarMult(groupOrderMinusOne, point)
	check.Add(check, point)
	return check.Equal(edwards25519.NewIdentityPoint()) == 1
}

func mustScalar(b []byte) *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		panic(err)
	}
	return s
}
