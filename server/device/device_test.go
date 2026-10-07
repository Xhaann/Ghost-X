package device_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/device/devicetest"
	"github.com/Xhaann/ghost-x/server/identity"
)

func open(t *testing.T) (*device.Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "devices.json")
	r, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return r, path
}

func admit(r *device.Registry, session any, id *devicetest.Identity, d *devicetest.Device) error {
	owner, err := identity.Parse(id.Identity)
	if err != nil {
		return err
	}
	message := []byte("challenge")
	signature := d.Sign(message)
	return r.Admit(session, owner, d.ID, func(key identity.Identity) bool {
		return key.Verify(message, signature) == nil
	})
}

func TestRosterBindsDevicesToTheIdentity(t *testing.T) {
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	roster := id.Add(a, b)
	if _, err := device.Verify(roster); err != nil {
		t.Fatalf("valid roster rejected: %v", err)
	}
	other := devicetest.NewIdentity()
	foreign := other.NewDevice()
	mutate := map[string]func(r *device.Roster){
		"identity":         func(r *device.Roster) { r.Identity = other.Identity },
		"version":          func(r *device.Roster) { r.Version++ },
		"zero version":     func(r *device.Roster) { r.Version = 0 },
		"device id":        func(r *device.Roster) { r.Devices[0].ID = foreign.ID },
		"signing key":      func(r *device.Roster) { r.Devices[0].Signing = foreign.SigningKey() },
		"exchange key":     func(r *device.Roster) { r.Devices[0].Exchange = foreign.ExchangeKey() },
		"signature":        func(r *device.Roster) { r.Signature = other.Next().Signature },
		"dropped device":   func(r *device.Roster) { r.Devices = r.Devices[:1] },
		"reordered":        func(r *device.Roster) { r.Devices[0], r.Devices[1] = r.Devices[1], r.Devices[0] },
		"duplicate":        func(r *device.Roster) { r.Devices[1] = r.Devices[0] },
		"empty":            func(r *device.Roster) { r.Devices = nil },
		"padded id":        func(r *device.Roster) { r.Devices[0].ID += "=" },
		"short key":        func(r *device.Roster) { r.Devices[0].Exchange = r.Devices[0].Exchange[:42] },
		"identity as key":  func(r *device.Roster) { r.Devices[0].Signing = id.Identity },
		"malformed sig":    func(r *device.Roster) { r.Signature = "x" },
		"oversized roster": func(r *device.Roster) { r.Devices = append(r.Devices, r.Devices[0], r.Devices[1], r.Devices[0]) },
	}
	for name, change := range mutate {
		r := roster
		r.Devices = append([]device.Device(nil), roster.Devices...)
		change(&r)
		if _, err := device.Verify(r); err == nil {
			t.Fatalf("%s mutation accepted", name)
		}
	}
	crossed := other.Sign(1, []*devicetest.Device{a})
	if _, err := device.Verify(crossed); err == nil {
		t.Fatal("device bound to another identity accepted")
	}
	tooMany := devicetest.NewIdentity()
	var five []*devicetest.Device
	for range device.MaxDevices + 1 {
		five = append(five, tooMany.NewDevice())
	}
	if _, err := device.Verify(tooMany.Sign(1, five)); err == nil {
		t.Fatal("roster above the device limit accepted")
	}
}

func TestDeviceIDIsDerivedFromIdentityAndKey(t *testing.T) {
	id := devicetest.NewIdentity()
	d := id.NewDevice()
	other := devicetest.NewIdentity()
	if string(device.DeriveID(id.Raw, d.SigningRaw)) != string(d.IDRaw) {
		t.Fatal("device id not derived from identity and key")
	}
	if string(device.DeriveID(other.Raw, d.SigningRaw)) == string(d.IDRaw) {
		t.Fatal("device id not bound to the identity")
	}
}

func TestRosterDeviceOrderIsCanonical(t *testing.T) {
	id := devicetest.NewIdentity()
	sorted := id.Sign(1, []*devicetest.Device{id.NewDevice(), id.NewDevice(), id.NewDevice()})
	if _, err := device.Verify(sorted); err != nil {
		t.Fatal(err)
	}
	reversed := slices.Clone(sorted.Devices)
	slices.Reverse(reversed)
	parts := make([][3][]byte, 0, len(reversed))
	for _, d := range reversed {
		raw := func(text string) []byte {
			b, err := base64.RawURLEncoding.DecodeString(text)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		parts = append(parts, [3][]byte{raw(d.ID), raw(d.Signing), raw(d.Exchange)})
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.Root, device.Message(id.Raw, 1, parts)))
	unsorted := device.Roster{Identity: id.Identity, Version: 1, Devices: reversed, Signature: signature}
	if _, err := device.Verify(unsorted); !errors.Is(err, device.ErrInvalid) {
		t.Fatalf("root-signed roster in non-canonical order verified: %v", err)
	}
	r, _ := open(t)
	if err := r.Publish(unsorted); !errors.Is(err, device.ErrInvalid) {
		t.Fatalf("non-canonical roster published: %v", err)
	}
	if r.Len() != 0 {
		t.Fatal("non-canonical roster stored")
	}
}

func TestPublishIsMonotonicAndReplaySafe(t *testing.T) {
	r, _ := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	first := id.Add(a)
	if err := r.Publish(first); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(first); err != nil {
		t.Fatalf("identical replay should be a no-op: %v", err)
	}
	second := id.Add(b)
	if err := r.Publish(second); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(first); !errors.Is(err, device.ErrStale) {
		t.Fatalf("rollback = %v", err)
	}
	conflict := id.Sign(second.Version, []*devicetest.Device{b})
	if err := r.Publish(conflict); !errors.Is(err, device.ErrStale) {
		t.Fatalf("same version different devices = %v", err)
	}
	third := id.Remove(b)
	if err := r.Publish(third); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(second); !errors.Is(err, device.ErrStale) {
		t.Fatalf("revocation replay = %v", err)
	}
	if r.Authorized(id.Identity, b.ID) || !r.Authorized(id.Identity, a.ID) {
		t.Fatal("revocation not applied")
	}
	forged := third
	forged.Version = 9
	if err := r.Publish(forged); !errors.Is(err, device.ErrInvalid) {
		t.Fatalf("unsigned version bump = %v", err)
	}
}

func TestRevocationSurvivesRestart(t *testing.T) {
	r, path := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	withB := id.Add(a, b)
	if err := r.Publish(withB); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(id.Remove(b)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("store = %v %v", info, err)
	}
	reopened, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Authorized(id.Identity, b.ID) {
		t.Fatal("revoked device authorized after restart")
	}
	if err := reopened.Publish(withB); !errors.Is(err, device.ErrStale) {
		t.Fatalf("stale roster after restart = %v", err)
	}
	if err := admit(reopened, "s", id, b); !errors.Is(err, device.ErrRevoked) {
		t.Fatalf("revoked device admitted = %v", err)
	}
	if err := admit(reopened, "s", id, a); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, secret := range []string{
		base64.RawURLEncoding.EncodeToString(a.Signing.Seed()),
		base64.RawURLEncoding.EncodeToString(b.Signing.Seed()),
		base64.RawURLEncoding.EncodeToString(id.Root.Seed()),
		base64.RawURLEncoding.EncodeToString(a.Exchange.Bytes()),
	} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private material persisted")
		}
	}
}

func TestCorruptedStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"garbage":        "{",
		"tampered":       "",
		"duplicate":      "",
		"revoked listed": "",
		"old format":     "",
	} {
		path := filepath.Join(dir, name+".json")
		id := devicetest.NewIdentity()
		roster := id.Add(id.NewDevice())
		switch name {
		case "tampered":
			roster.Version++
			data, _ := json.Marshal([]map[string]any{{"roster": roster, "revoked": []string{}}})
			content = string(data)
		case "revoked listed":
			data, _ := json.Marshal([]map[string]any{{"roster": roster, "revoked": []string{roster.Devices[0].ID}}})
			content = string(data)
		case "old format":
			data, _ := json.Marshal([]device.Roster{roster})
			content = string(data)
		case "duplicate":
			entry := map[string]any{"roster": roster, "revoked": []string{}}
			data, _ := json.Marshal([]map[string]any{entry, entry})
			content = string(data)
		}
		os.WriteFile(path, []byte(content), 0o600)
		if _, err := device.Open(path); err == nil {
			t.Fatalf("%s store accepted", name)
		}
	}
}

func TestAdmissionRequiresAnAuthorizedDeviceKey(t *testing.T) {
	r, _ := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	if err := admit(r, "s0", id, a); !errors.Is(err, device.ErrRevoked) {
		t.Fatalf("unregistered identity admitted = %v", err)
	}
	r.Publish(id.Add(a))
	if err := admit(r, "s1", id, b); !errors.Is(err, device.ErrRevoked) {
		t.Fatalf("unlisted device admitted = %v", err)
	}
	owner, _ := identity.Parse(id.Identity)
	message := []byte("challenge")
	if err := r.Admit("s2", owner, a.ID, func(key identity.Identity) bool {
		return key.Verify(message, b.Sign(message)) == nil
	}); !errors.Is(err, device.ErrSignature) {
		t.Fatalf("other device's signature accepted = %v", err)
	}
	if err := r.Admit("s3", owner, a.ID, func(key identity.Identity) bool {
		return key.Verify(message, base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.Root, message))) == nil
	}); !errors.Is(err, device.ErrSignature) {
		t.Fatalf("root key accepted as a device key = %v", err)
	}
	other := devicetest.NewIdentity()
	r.Publish(other.Add(other.NewDevice()))
	if err := admit(r, "s4", other, a); !errors.Is(err, device.ErrRevoked) {
		t.Fatalf("device admitted under another identity = %v", err)
	}
}

func TestRevocationKicksOnlyTheRevokedDevice(t *testing.T) {
	r, _ := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	r.Publish(id.Add(a, b))
	var kickedA, kickedB atomic.Int32
	var revoked []string
	r.OnRevoke(func(owner, d string) { revoked = append(revoked, owner+"/"+d) })
	r.Attach("a", func() { kickedA.Add(1) })
	r.Attach("b", func() { kickedB.Add(1) })
	if err := admit(r, "a", id, a); err != nil {
		t.Fatal(err)
	}
	if err := admit(r, "b", id, b); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(id.Remove(b)); err != nil {
		t.Fatal(err)
	}
	if kickedB.Load() != 1 || kickedA.Load() != 0 {
		t.Fatalf("kicks a=%d b=%d", kickedA.Load(), kickedB.Load())
	}
	if len(revoked) != 1 || revoked[0] != id.Identity+"/"+b.ID {
		t.Fatalf("revoked = %v", revoked)
	}
	if err := admit(r, "b2", id, b); !errors.Is(err, device.ErrRevoked) {
		t.Fatalf("revoked device re-admitted = %v", err)
	}
	if err := r.Publish(id.Next()); err != nil {
		t.Fatal(err)
	}
	if kickedB.Load() != 1 || len(revoked) != 1 {
		t.Fatal("revocation repeated for an already removed device")
	}
}

func TestPersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	r, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	if err := r.Publish(id.Add(a, b)); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if err := r.Publish(id.Remove(b)); !errors.Is(err, device.ErrPersist) {
		t.Fatalf("unpersisted revocation = %v", err)
	}
	if !r.Authorized(id.Identity, b.ID) {
		t.Fatal("in-memory state diverged from storage")
	}
}

func TestIdentityLimit(t *testing.T) {
	r, _ := open(t)
	if r.Len() != 0 {
		t.Fatal("not empty")
	}
	if device.MaxIdentities < 1024 || device.MaxDevices != 4 {
		t.Fatal("unexpected limits")
	}
}

func TestConcurrentPublishAdmitAndRevoke(t *testing.T) {
	r, _ := open(t)
	id := devicetest.NewIdentity()
	devices := []*devicetest.Device{id.NewDevice(), id.NewDevice(), id.NewDevice()}
	rosters := []device.Roster{id.Add(devices...)}
	for _, d := range devices[1:] {
		rosters = append(rosters, id.Remove(d))
	}
	var kicked atomic.Int32
	var wg sync.WaitGroup
	for i := range 40 {
		session := i
		r.Attach(session, func() { kicked.Add(1) })
		wg.Go(func() { admit(r, session, id, devices[session%3]) })
		wg.Go(func() { r.Publish(rosters[session%len(rosters)]) })
		wg.Go(func() { r.Authorized(id.Identity, devices[session%3].ID) })
	}
	wg.Wait()
	for _, d := range devices[1:] {
		if r.Authorized(id.Identity, d.ID) {
			t.Fatal("final state authorizes a revoked device")
		}
	}
	for i := range 40 {
		r.Detach(i)
	}
}

func TestRevokedDevicesCannotBeAuthorizedAgain(t *testing.T) {
	r, path := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	if err := r.Publish(id.Add(a, b)); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(id.Remove(b)); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(id.Add(b)); !errors.Is(err, device.ErrReused) {
		t.Fatalf("re-adding a revoked device = %v", err)
	}
	reopened, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Publish(id.Next()); !errors.Is(err, device.ErrReused) {
		t.Fatalf("re-adding a revoked device after restart = %v", err)
	}
	fresh := id.NewDevice()
	id.Devices = []*devicetest.Device{a, fresh}
	if err := reopened.Publish(id.Next()); err != nil {
		t.Fatalf("a newly generated device = %v", err)
	}
}
