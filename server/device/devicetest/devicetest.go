package devicetest

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"sync/atomic"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/device"
)

var encoding = base64.RawURLEncoding

var counter atomic.Uint64

func seed(label string) []byte {
	h := sha256.New()
	h.Write([]byte("ghostx/devicetest/" + label + "\x00"))
	h.Write(binary.BigEndian.AppendUint64(nil, counter.Add(1)))
	return h.Sum(nil)
}

func signingKey(label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(seed(label))
	return private.Public().(ed25519.PublicKey), private
}

func NewExchange() *ecdh.PrivateKey {
	private, err := ecdh.X25519().NewPrivateKey(seed("exchange"))
	if err != nil {
		panic(err)
	}
	return private
}

type Device struct {
	ID          string
	IDRaw       []byte
	Signing     ed25519.PrivateKey
	SigningRaw  []byte
	Exchange    *ecdh.PrivateKey
	ExchangeRaw []byte
}

type Identity struct {
	Root     ed25519.PrivateKey
	Raw      []byte
	Identity string
	Devices  []*Device
	Version  uint32
}

func NewIdentity() *Identity {
	public, private := signingKey("root")
	return &Identity{Root: private, Raw: public, Identity: encoding.EncodeToString(public)}
}

func (i *Identity) NewDevice() *Device {
	public, private := signingKey("device")
	exchange := NewExchange()
	id := device.DeriveID(i.Raw, public)
	return &Device{
		ID:          encoding.EncodeToString(id),
		IDRaw:       id,
		Signing:     private,
		SigningRaw:  public,
		Exchange:    exchange,
		ExchangeRaw: exchange.PublicKey().Bytes(),
	}
}

func (i *Identity) Add(devices ...*Device) device.Roster {
	i.Devices = append(i.Devices, devices...)
	return i.Next()
}

func (i *Identity) Remove(d *Device) device.Roster {
	i.Devices = slices.DeleteFunc(i.Devices, func(x *Device) bool { return x == d })
	return i.Next()
}

func (i *Identity) Next() device.Roster {
	i.Version++
	return i.Sign(i.Version, i.Devices)
}

func (i *Identity) Sign(version uint32, devices []*Device) device.Roster {
	sorted := slices.Clone(devices)
	slices.SortFunc(sorted, func(a, b *Device) int {
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	parts := make([][3][]byte, 0, len(sorted))
	listed := make([]device.Device, 0, len(sorted))
	for _, d := range sorted {
		parts = append(parts, [3][]byte{d.IDRaw, d.SigningRaw, d.ExchangeRaw})
		listed = append(listed, device.Device{ID: d.ID, Signing: encoding.EncodeToString(d.SigningRaw), Exchange: encoding.EncodeToString(d.ExchangeRaw)})
	}
	signature := ed25519.Sign(i.Root, device.Message(i.Raw, version, parts))
	return device.Roster{Identity: i.Identity, Version: version, Devices: listed, Signature: encoding.EncodeToString(signature)}
}

func (d *Device) Sign(message []byte) string {
	return encoding.EncodeToString(ed25519.Sign(d.Signing, message))
}

func (d *Device) AuthSignature(i *Identity, nonce []byte) string {
	return d.Sign(auth.Message(nonce, i.Raw, d.IDRaw))
}

func (d *Device) ExchangeKey() string {
	return encoding.EncodeToString(d.ExchangeRaw)
}

func (d *Device) SigningKey() string {
	return encoding.EncodeToString(d.SigningRaw)
}
