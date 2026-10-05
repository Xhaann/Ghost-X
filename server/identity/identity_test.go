package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"filippo.io/edwards25519"
)

var smallOrder = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"0000000000000000000000000000000000000000000000000000000000000080",
}

func generate(t testing.TB) (ed25519.PrivateKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private, base64.RawURLEncoding.EncodeToString(public)
}

func sign(private ed25519.PrivateKey, message []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
}

func mustParse(t *testing.T, encoded string) Identity {
	t.Helper()
	id, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", encoded, err)
	}
	return id
}

func encodeHex(t *testing.T, h string) string {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestParseRoundTrip(t *testing.T) {
	for range 100 {
		_, encoded := generate(t)
		id := mustParse(t, encoded)
		if len(encoded) != EncodedLength {
			t.Fatalf("encoded length = %d, want %d", len(encoded), EncodedLength)
		}
		if id.String() != encoded {
			t.Fatalf("String() = %q, want %q", id.String(), encoded)
		}
		if !id.Equal(mustParse(t, encoded)) {
			t.Fatal("identity not equal to itself")
		}
	}
}

func TestIdentitiesAreUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for range 1000 {
		_, encoded := generate(t)
		if _, dup := seen[encoded]; dup {
			t.Fatal("duplicate identity generated")
		}
		seen[encoded] = struct{}{}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	_, valid := generate(t)
	nonCanonicalTail := valid[:EncodedLength-1] + string(flipLowBits(valid[EncodedLength-1]))

	tests := map[string]string{
		"empty":              "",
		"short":              valid[:EncodedLength-1],
		"long":               valid + "A",
		"padded":             valid + "=",
		"oversized":          strings.Repeat("A", 1<<20),
		"standard alphabet":  "+" + valid[1:],
		"whitespace":         " " + valid[1:],
		"non-canonical tail": nonCanonicalTail,
		"invalid character":  valid[:10] + "*" + valid[11:],
		"hex":                hex.EncodeToString(make([]byte, 32))[:EncodedLength],
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(input); !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("Parse() error = %v, want %v", err, ErrInvalidIdentity)
			}
		})
	}
}

func flipLowBits(c byte) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, c)
	return alphabet[i^1]
}

func TestParseRejectsSmallOrderPoints(t *testing.T) {
	for _, h := range smallOrder {
		t.Run(h[:8], func(t *testing.T) {
			if _, err := Parse(encodeHex(t, h)); !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("Parse() error = %v, want %v", err, ErrInvalidIdentity)
			}
		})
	}
}

func TestParseRejectsTorsionComponent(t *testing.T) {
	_, encoded := generate(t)
	raw, _ := base64.RawURLEncoding.DecodeString(encoded)
	honest, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	torsionBytes, _ := hex.DecodeString(smallOrder[2])
	torsion, err := new(edwards25519.Point).SetBytes(torsionBytes)
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(honest, torsion)

	if _, err := Parse(base64.RawURLEncoding.EncodeToString(mixed.Bytes())); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("Parse() error = %v, want %v", err, ErrInvalidIdentity)
	}
}

func TestParseRejectsNonCanonicalPoints(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for k := range int64(19) {
		for _, sign := range []byte{0, 0x80} {
			y := new(big.Int).Add(p, big.NewInt(k))
			raw := make([]byte, 32)
			y.FillBytes(raw)
			raw = reverse(raw)
			raw[31] |= sign
			if _, err := Parse(base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrInvalidIdentity) {
				t.Errorf("y = p+%d sign %x: Parse() error = %v, want %v", k, sign, err, ErrInvalidIdentity)
			}
		}
	}
}

func TestVerify(t *testing.T) {
	private, encoded := generate(t)
	id := mustParse(t, encoded)
	message := []byte("ghostx test message")
	signature := sign(private, message)

	if err := id.Verify(message, signature); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := id.Verify(append([]byte{}, message...), signature); err != nil {
		t.Fatalf("Verify() repeated error = %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	private, encoded := generate(t)
	otherPrivate, otherEncoded := generate(t)
	id := mustParse(t, encoded)
	message := []byte("ghostx test message")
	signature := sign(private, message)
	raw, _ := base64.RawURLEncoding.DecodeString(signature)

	malleated := append([]byte{}, raw...)
	s := new(big.Int).SetBytes(reverse(malleated[32:]))
	order, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	s.Add(s, order)
	sBytes := make([]byte, 32)
	s.FillBytes(sBytes)
	copy(malleated[32:], reverse(sBytes))

	tests := map[string]struct {
		id        Identity
		message   []byte
		signature string
	}{
		"modified message":  {id, []byte("ghostx test messagE"), signature},
		"empty message":     {id, nil, signature},
		"wrong identity":    {mustParse(t, otherEncoded), message, signature},
		"other signer":      {id, message, sign(otherPrivate, message)},
		"empty signature":   {id, message, ""},
		"short signature":   {id, message, signature[:EncodedSignatureLength-1]},
		"long signature":    {id, message, signature + "A"},
		"padded signature":  {id, message, signature + "=="},
		"oversized":         {id, message, strings.Repeat("A", 1<<20)},
		"invalid character": {id, message, signature[:5] + "*" + signature[6:]},
		"flipped bit":       {id, message, base64.RawURLEncoding.EncodeToString(flip(raw, 10))},
		"malleated s":       {id, message, base64.RawURLEncoding.EncodeToString(malleated)},
		"zero signature":    {id, message, base64.RawURLEncoding.EncodeToString(make([]byte, 64))},
		"zero identity":     {Identity{}, message, signature},
		"non-canonical tail": {id, message, signature[:EncodedSignatureLength-1] +
			string(flipLowBits(signature[EncodedSignatureLength-1]))},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tt.id.Verify(tt.message, tt.signature); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Verify() error = %v, want %v", err, ErrInvalidSignature)
			}
		})
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func flip(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 1
	return out
}

func TestConcurrentVerify(t *testing.T) {
	private, encoded := generate(t)
	id := mustParse(t, encoded)
	message := []byte("ghostx test message")
	signature := sign(private, message)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				if err := id.Verify(message, signature); err != nil {
					t.Error(err)
					return
				}
				if _, err := Parse(encoded); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func FuzzParse(f *testing.F) {
	_, valid := generate(f)
	f.Add(valid)
	f.Add("")
	f.Add(strings.Repeat("A", EncodedLength))
	f.Add(strings.Repeat("_", EncodedLength))
	for _, h := range smallOrder {
		raw, _ := hex.DecodeString(h)
		f.Add(base64.RawURLEncoding.EncodeToString(raw))
	}

	f.Fuzz(func(t *testing.T, input string) {
		id, err := Parse(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if id.String() != input {
			t.Fatalf("accepted non-canonical identity %q", input)
		}
		if id.Verify([]byte("x"), strings.Repeat("A", EncodedSignatureLength)) == nil {
			t.Fatal("zero signature verified")
		}
	})
}

func FuzzVerify(f *testing.F) {
	private, encoded := generate(f)
	f.Add([]byte("message"), sign(private, []byte("message")))
	f.Add([]byte{}, "")
	f.Add([]byte("message"), strings.Repeat("A", EncodedSignatureLength))

	id, err := Parse(encoded)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, message []byte, signature string) {
		err := id.Verify(message, signature)
		if err != nil && !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("unexpected error %v", err)
		}
		if err == nil && signature != sign(private, message) {
			t.Fatalf("accepted signature not produced by the key")
		}
	})
}
