package device_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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
		"garbage":        "{\n",
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
	os.Chmod(path, 0o400)
	defer os.Chmod(path, 0o600)
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

func lines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func TestPreviousStoreFormatMigratesIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	id.Add(a, b)
	current := id.Remove(b)
	other := devicetest.NewIdentity()
	second := other.Add(other.NewDevice())
	data, _ := json.Marshal([]map[string]any{
		{"roster": current, "revoked": []string{b.ID}},
		{"roster": second, "revoked": []string{}},
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 2 || !r.Authorized(id.Identity, a.ID) || r.Authorized(id.Identity, b.ID) {
		t.Fatal("migrated state differs")
	}
	if err := r.Publish(id.Add(b)); !errors.Is(err, device.ErrReused) {
		t.Fatalf("revocation lost in migration: %v", err)
	}
	if got := lines(t, path); len(got) != 2 || !strings.HasPrefix(got[0], "{") {
		t.Fatalf("store not converted: %q", got)
	}
	reopened, err := device.Open(path)
	if err != nil || reopened.Len() != 2 || reopened.Authorized(id.Identity, b.ID) {
		t.Fatalf("converted store reopen = %v", err)
	}
}

func TestEachChangeAppendsOneRecordAndTheLogStaysBounded(t *testing.T) {
	r, path := open(t)
	id := devicetest.NewIdentity()
	d := id.NewDevice()
	if err := r.Publish(id.Add(d)); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(id.Sign(id.Version, id.Devices)); err != nil {
		t.Fatal(err)
	}
	if n := len(lines(t, path)); n != 1 {
		t.Fatalf("identical replay appended: %d lines", n)
	}
	for range 1100 {
		extra := id.NewDevice()
		if err := r.Publish(id.Add(extra)); err != nil {
			t.Fatal(err)
		}
		if err := r.Publish(id.Remove(extra)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(lines(t, path)); n > 2*r.Len()+1025 {
		t.Fatalf("log grew without compaction: %d lines", n)
	}
	reopened, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := r.Roster(id.Identity)
	again, _ := reopened.Roster(id.Identity)
	if again.Version != current.Version || again.Signature != current.Signature {
		t.Fatal("reopened state differs after compaction")
	}
	if err := reopened.Publish(id.Add(id.Devices[0])); err == nil {
		t.Fatal("device accepted twice")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestAnUnacknowledgedTornRecordIsDroppedAndCorruptionFailsClosed(t *testing.T) {
	r, path := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	if err := r.Publish(id.Add(a, b)); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(id.Remove(b)); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(path)
	next, _ := json.Marshal(map[string]any{"roster": id.Add(id.NewDevice()), "revoked": []string{b.ID}})
	for cut := 1; cut < len(next); cut += len(next) / 7 {
		os.WriteFile(path, append(slices.Clone(good), next[:cut]...), 0o600)
		reopened, err := device.Open(path)
		if err != nil {
			t.Fatalf("torn tail of %d bytes: %v", cut, err)
		}
		if reopened.Authorized(id.Identity, b.ID) || !reopened.Authorized(id.Identity, a.ID) {
			t.Fatal("torn tail changed acknowledged state")
		}
		if data, _ := os.ReadFile(path); string(data) != string(good) {
			t.Fatal("torn tail not removed")
		}
	}
	records := lines(t, path)
	for name, content := range map[string]string{
		"corrupt line":       records[0] + "\n{\n" + records[1] + "\n",
		"version regression": records[1] + "\n" + records[0] + "\n",
		"replayed line":      records[0] + "\n" + records[0] + "\n",
		"tampered signature": strings.Replace(records[1], `"signature":"`, `"signature":"A`, 1) + "\n",
	} {
		os.WriteFile(path, []byte(content), 0o600)
		if _, err := device.Open(path); !errors.Is(err, device.ErrCorrupted) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestConcurrentPublishesNeverLoseAnUpdate(t *testing.T) {
	r, path := open(t)
	ids := make([]*devicetest.Identity, 24)
	rosters := make([][]device.Roster, len(ids))
	for i := range ids {
		ids[i] = devicetest.NewIdentity()
		for range 4 {
			rosters[i] = append(rosters[i], ids[i].Add(ids[i].NewDevice()))
		}
	}
	var wg sync.WaitGroup
	for i := range ids {
		for _, roster := range rosters[i] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := r.Publish(roster)
				if err != nil && !errors.Is(err, device.ErrStale) {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	reopened, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		live, _ := r.Roster(id.Identity)
		disk, _ := reopened.Roster(id.Identity)
		if live.Signature != disk.Signature || live.Version != disk.Version {
			t.Fatalf("identity %d: memory v%d, disk v%d", i, live.Version, disk.Version)
		}
		if final := rosters[i][3]; live.Version != final.Version {
			if err := r.Publish(final); err != nil {
				t.Fatalf("identity %d cannot reach its newest roster: %v", i, err)
			}
		}
	}
}

func TestAStalledWriterNeverBlocksAuthorization(t *testing.T) {
	r, _ := open(t)
	id := devicetest.NewIdentity()
	d := id.NewDevice()
	if err := r.Publish(id.Add(d)); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	r.SetLimits(device.Limits{Rate: 1000, Burst: 1000, IdentityRate: 1000, IdentityBurst: 1000, Now: func() time.Time {
		once.Do(func() {
			close(entered)
			<-release
		})
		return time.Now()
	}})
	other := devicetest.NewIdentity()
	done := make(chan error, 1)
	go func() { done <- r.Publish(other.Add(other.NewDevice())) }()
	<-entered
	finished := make(chan struct{})
	go func() {
		r.Authorized(id.Identity, d.ID)
		r.Key(id.Identity, d.ID)
		r.Roster(id.Identity)
		admit(r, "reader", id, d)
		r.Release("reader")
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("readers blocked behind a registry write")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRosterChangesAreRateLimitedGloballyAndPerIdentity(t *testing.T) {
	r, _ := open(t)
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	r.SetLimits(device.Limits{Rate: 1, Burst: 10, IdentityRate: 0.1, IdentityBurst: 3, Now: clock})
	id := devicetest.NewIdentity()
	d := id.NewDevice()
	first := id.Add(d)
	for i := range 3 {
		roster := first
		if i > 0 {
			roster = id.Next()
		}
		if err := r.Publish(roster); err != nil {
			t.Fatalf("change %d: %v", i, err)
		}
	}
	if err := r.Publish(id.Sign(id.Version, id.Devices)); err != nil {
		t.Fatalf("identical replay was limited: %v", err)
	}
	if err := r.Publish(id.Next()); !errors.Is(err, device.ErrRate) {
		t.Fatalf("fourth change = %v", err)
	}
	advance(10 * time.Second)
	if err := r.Publish(id.Sign(id.Version, id.Devices)); err != nil {
		t.Fatalf("change after refill: %v", err)
	}
	var wg sync.WaitGroup
	var accepted, limited atomic.Int32
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := devicetest.NewIdentity()
			switch err := r.Publish(other.Add(other.NewDevice())); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, device.ErrRate):
				limited.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 9 || limited.Load() != 31 {
		t.Fatalf("concurrent new identities: %d accepted, %d limited", accepted.Load(), limited.Load())
	}
	before := r.Len()
	advance(5 * time.Second)
	for range 5 {
		other := devicetest.NewIdentity()
		if err := r.Publish(other.Add(other.NewDevice())); err != nil {
			t.Fatal(err)
		}
	}
	if r.Len() != before+5 {
		t.Fatal("refill not applied")
	}
}

func TestTheRegistryRefusesNewIdentitiesAtCapacity(t *testing.T) {
	r, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	var first *devicetest.Identity
	for i := range device.MaxIdentities {
		id := devicetest.NewIdentity()
		if err := r.Publish(id.Add(id.NewDevice())); err != nil {
			t.Fatalf("identity %d: %v", i, err)
		}
		if first == nil {
			first = id
		}
	}
	extra := devicetest.NewIdentity()
	if err := r.Publish(extra.Add(extra.NewDevice())); !errors.Is(err, device.ErrLimit) {
		t.Fatalf("identity beyond capacity = %v", err)
	}
	if r.Len() != device.MaxIdentities {
		t.Fatalf("Len() = %d", r.Len())
	}
	if err := r.Publish(first.Add(first.NewDevice())); err != nil {
		t.Fatalf("existing identity blocked at capacity: %v", err)
	}
}

func TestDiskWritesNeverHoldTheReaderLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	r, err := device.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := devicetest.NewIdentity()
	d := id.NewDevice()
	if err := r.Publish(id.Add(d)); err != nil {
		t.Fatal(err)
	}
	stored, _ := os.ReadFile(path)
	os.Remove(path)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	other := devicetest.NewIdentity()
	done := make(chan error, 1)
	go func() { done <- r.Publish(other.Add(other.NewDevice())) }()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("write did not block on the pipe: %v", err)
	default:
	}
	finished := make(chan struct{})
	go func() {
		r.Authorized(id.Identity, d.ID)
		r.Key(id.Identity, d.ID)
		r.Roster(id.Identity)
		admit(r, "reader", id, d)
		r.Release("reader")
		r.Len()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("readers blocked behind a disk write")
	}
	reader, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, reader)
	<-done
	reader.Close()
	os.Remove(path)
	os.WriteFile(path, stored, 0o600)
}

func TestUnacknowledgedBytesAreRemovedBeforeTheNextRecord(t *testing.T) {
	r, path := open(t)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	if err := r.Publish(id.Add(a)); err != nil {
		t.Fatal(err)
	}
	acknowledged, _ := os.ReadFile(path)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"roster":{"identity":"torn`)
	f.Close()
	if err := r.Publish(id.Add(b)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), string(acknowledged)) || strings.Contains(string(data), "torn") {
		t.Fatal("unacknowledged bytes survived the next append")
	}
	reopened, err := device.Open(path)
	if err != nil || !reopened.Authorized(id.Identity, b.ID) {
		t.Fatalf("store after recovery: %v", err)
	}
	os.WriteFile(path, acknowledged[:len(acknowledged)/2], 0o600)
	c := id.NewDevice()
	if err := r.Publish(id.Add(c)); !errors.Is(err, device.ErrPersist) {
		t.Fatalf("append after the store shrank = %v", err)
	}
	if r.Authorized(id.Identity, c.ID) {
		t.Fatal("unpersisted change applied")
	}
}

func FuzzOpenStore(f *testing.F) {
	seed := devicetest.NewIdentity()
	roster := seed.Add(seed.NewDevice())
	line, _ := json.Marshal(map[string]any{"roster": roster, "revoked": []string{}})
	legacy, _ := json.Marshal([]map[string]any{{"roster": roster, "revoked": []string{}}})
	f.Add(append(line, '\n'))
	f.Add(legacy)
	f.Add(append(append(append([]byte{}, line...), '\n'), line[:20]...))
	f.Add([]byte("{\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "devices.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := device.Open(path)
		if err != nil {
			return
		}
		if r.Len() > device.MaxIdentities {
			t.Fatalf("loaded %d identities", r.Len())
		}
		next := devicetest.NewIdentity()
		if err := r.Publish(next.Add(next.NewDevice())); err != nil && !errors.Is(err, device.ErrLimit) {
			t.Fatalf("publish after loading = %v", err)
		}
		reopened, err := device.Open(path)
		if err != nil {
			t.Fatalf("store unreadable after a publish: %v", err)
		}
		if reopened.Len() != r.Len() {
			t.Fatalf("reopened %d identities, had %d", reopened.Len(), r.Len())
		}
	})
}
