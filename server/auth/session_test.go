package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/identity"
)

type clock struct {
	now atomic.Int64
}

func newClock() *clock {
	c := &clock{}
	c.now.Store(time.Now().UnixNano())
	return c
}

func (c *clock) Now() time.Time {
	return time.Unix(0, c.now.Load())
}

func (c *clock) Advance(d time.Duration) {
	c.now.Add(int64(d))
}

type directory struct {
	mu       sync.Mutex
	keys     map[string]identity.Identity
	admitted map[any]string
	released atomic.Int64
}

var known = &directory{keys: map[string]identity.Identity{}, admitted: map[any]string{}}

func (d *directory) Admit(session any, owner identity.Identity, device string, verify func(identity.Identity) bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key, ok := d.keys[owner.String()+"/"+device]
	if !ok {
		return errors.New("unknown device")
	}
	if !verify(key) {
		return errors.New("bad signature")
	}
	d.admitted[session] = device
	return nil
}

func (d *directory) Release(session any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.admitted, session)
	d.released.Add(1)
}

func (d *directory) revoke(s signer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.keys, s.identity+"/"+s.device)
}

type signer struct {
	root      ed25519.PrivateKey
	private   ed25519.PrivateKey
	identity  string
	device    string
	owner     []byte
	deviceRaw []byte
	unlisted  bool
}

func newSigner(t testing.TB) signer {
	t.Helper()
	return newDevice(t, true)
}

func newDevice(t testing.TB, listed bool) signer {
	t.Helper()
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceRaw := make([]byte, DeviceIDSize)
	rand.Read(deviceRaw)
	s := signer{
		root:      root,
		private:   private,
		identity:  base64.RawURLEncoding.EncodeToString(rootPublic),
		device:    base64.RawURLEncoding.EncodeToString(deviceRaw),
		owner:     rootPublic,
		deviceRaw: deviceRaw,
		unlisted:  !listed,
	}
	if listed {
		key, _ := identity.Parse(base64.RawURLEncoding.EncodeToString(public))
		known.mu.Lock()
		known.keys[s.identity+"/"+s.device] = key
		known.mu.Unlock()
	}
	return s
}

func (s signer) sign(message []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, message))
}

func (s signer) proof(nonce []byte) string {
	return s.sign(Message(nonce, s.owner, s.deviceRaw))
}

func (s signer) prove(t testing.TB, session *Session) error {
	t.Helper()
	nonce, err := session.Challenge()
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}
	_, err = session.Authenticate(s.identity, s.device, s.proof(nonce))
	return err
}

func TestNewSessionIsUnauthenticated(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	s := r.Open()

	if s.State() != Unauthenticated {
		t.Fatalf("State() = %v, want %v", s.State(), Unauthenticated)
	}
	if _, ok := s.Identity(); ok {
		t.Fatal("new session has an identity")
	}
	if r.Len() != 1 || r.Authenticated() != 0 {
		t.Fatalf("Len() = %d, Authenticated() = %d", r.Len(), r.Authenticated())
	}
}

func TestAuthenticate(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	s := r.Open()
	signer := newSigner(t)

	if err := signer.prove(t, s); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	id, ok := s.Identity()
	if !ok || id.String() != signer.identity {
		t.Fatalf("Identity() = %v, %v", id, ok)
	}
	if s.State() != Authenticated || r.Authenticated() != 1 {
		t.Fatalf("State() = %v, Authenticated() = %d", s.State(), r.Authenticated())
	}
}

func TestMessageIsDomainSeparated(t *testing.T) {
	nonce := make([]byte, ChallengeSize)
	owner := []byte(strings.Repeat("o", 32))
	device := []byte(strings.Repeat("d", DeviceIDSize))
	want := append(append(append([]byte("ghostx/session/authenticate/v2\x00"), nonce...), owner...), device...)
	if got := Message(nonce, owner, device); string(got) != string(want) {
		t.Fatalf("Message() = %q, want %q", got, want)
	}
}

func TestChallengesAreUniqueAndCopied(t *testing.T) {
	s := NewRegistry(time.Now, nil, known).Open()
	seen := make(map[string]struct{})
	for range 100 {
		nonce, err := s.Challenge()
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != ChallengeSize {
			t.Fatalf("nonce length = %d", len(nonce))
		}
		if _, dup := seen[string(nonce)]; dup {
			t.Fatal("duplicate challenge")
		}
		seen[string(nonce)] = struct{}{}
	}

	signer := newSigner(t)
	nonce, _ := s.Challenge()
	signed := signer.proof(nonce)
	nonce[0] ^= 0xff
	if _, err := s.Authenticate(signer.identity, signer.device, signed); err != nil {
		t.Fatalf("Authenticate() after mutating returned nonce = %v", err)
	}
}

func TestAuthenticateRejected(t *testing.T) {
	signer := newSigner(t)
	other := newSigner(t)

	tests := map[string]func(t *testing.T, c *clock, s *Session) error{
		"no challenge": func(t *testing.T, c *clock, s *Session) error {
			_, err := s.Authenticate(signer.identity, signer.device, signer.proof(make([]byte, ChallengeSize)))
			return err
		},
		"expired challenge": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			c.Advance(ChallengeTTL)
			_, err := s.Authenticate(signer.identity, signer.device, signer.proof(nonce))
			return err
		},
		"superseded challenge": func(t *testing.T, c *clock, s *Session) error {
			first, _ := s.Challenge()
			s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.device, signer.proof(first))
			return err
		},
		"reused challenge": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			if _, err := s.Authenticate(signer.identity, signer.device, other.proof(nonce)); !errors.Is(err, ErrFailed) {
				t.Fatalf("first attempt = %v", err)
			}
			_, err := s.Authenticate(signer.identity, signer.device, signer.proof(nonce))
			return err
		},
		"signed by other key": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.device, other.proof(nonce))
			return err
		},
		"claims other identity": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(other.identity, other.device, signer.proof(nonce))
			return err
		},
		"raw nonce": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.device, signer.sign(nonce))
			return err
		},
		"identity proof context": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.device, signer.sign(append([]byte("ghostx/identity/proof/v1\x00"), nonce...)))
			return err
		},
		"malformed signature": func(t *testing.T, c *clock, s *Session) error {
			s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.device, "x")
			return err
		},
		"oversized signature": func(t *testing.T, c *clock, s *Session) error {
			s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.device, strings.Repeat("A", 1<<20))
			return err
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			r := NewRegistry(c.Now, nil, known)
			s := r.Open()
			if err := run(t, c, s); !errors.Is(err, ErrFailed) {
				t.Fatalf("error = %v, want %v", err, ErrFailed)
			}
			if _, ok := s.Identity(); ok || r.Authenticated() != 0 {
				t.Fatal("rejected attempt authenticated the session")
			}
		})
	}
}

func TestExpiryBoundary(t *testing.T) {
	c := newClock()
	s := NewRegistry(c.Now, nil, known).Open()
	signer := newSigner(t)

	nonce, _ := s.Challenge()
	c.Advance(ChallengeTTL - time.Nanosecond)
	if _, err := s.Authenticate(signer.identity, signer.device, signer.proof(nonce)); err != nil {
		t.Fatalf("Authenticate() before expiry = %v", err)
	}
}

func TestMalformedIdentityConsumesChallenge(t *testing.T) {
	s := NewRegistry(time.Now, nil, known).Open()
	signer := newSigner(t)

	nonce, _ := s.Challenge()
	for _, bad := range []string{"", "x", signer.identity + "=", strings.Repeat("A", 1<<20), base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))} {
		if _, err := s.Authenticate(bad, signer.device, signer.proof(nonce)); !errors.Is(err, ErrInvalidIdentity) && !errors.Is(err, ErrFailed) {
			t.Fatalf("Authenticate(%.10q) error = %v", bad, err)
		}
	}
	if _, err := s.Authenticate(signer.identity, signer.device, signer.proof(nonce)); err == nil {
		t.Fatal("challenge survived malformed attempt")
	}
}

func TestChallengesAreBoundToSession(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	first, second := r.Open(), r.Open()
	signer := newSigner(t)

	nonce, _ := first.Challenge()
	second.Challenge()
	if _, err := second.Authenticate(signer.identity, signer.device, signer.proof(nonce)); !errors.Is(err, ErrFailed) {
		t.Fatalf("cross-session proof error = %v, want %v", err, ErrFailed)
	}
	if _, err := first.Authenticate(signer.identity, signer.device, signer.proof(nonce)); err != nil {
		t.Fatalf("original session error = %v", err)
	}
	if _, ok := second.Identity(); ok {
		t.Fatal("second session authenticated by first session's proof")
	}
}

func TestFailuresLockSession(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	s := r.Open()
	signer := newSigner(t)
	other := newSigner(t)

	for i := range MaxFailures {
		nonce, err := s.Challenge()
		if err != nil {
			t.Fatalf("Challenge() after %d failures = %v", i, err)
		}
		s.Authenticate(signer.identity, signer.device, other.proof(nonce))
	}

	if s.State() != Failed {
		t.Fatalf("State() = %v, want %v", s.State(), Failed)
	}
	if _, err := s.Challenge(); !errors.Is(err, ErrFailed) {
		t.Fatalf("Challenge() after lock = %v", err)
	}
	if _, err := s.Authenticate(signer.identity, signer.device, signer.proof(nil)); !errors.Is(err, ErrFailed) {
		t.Fatalf("Authenticate() after lock = %v", err)
	}
}

func TestAuthenticatedSessionCannotReauthenticate(t *testing.T) {
	s := NewRegistry(time.Now, nil, known).Open()
	signer := newSigner(t)
	other := newSigner(t)

	if err := signer.prove(t, s); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Challenge(); !errors.Is(err, ErrFailed) {
		t.Fatalf("Challenge() after authentication = %v", err)
	}
	if _, err := s.Authenticate(other.identity, other.device, other.proof(nil)); !errors.Is(err, ErrFailed) {
		t.Fatalf("Authenticate() after authentication = %v", err)
	}
	if id, ok := s.Identity(); !ok || id.String() != signer.identity {
		t.Fatal("identity changed after duplicate authentication")
	}
}

func TestCloseDestroysSession(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	s := r.Open()
	signer := newSigner(t)

	nonce, _ := s.Challenge()
	s.Close()
	s.Close()

	if _, err := s.Authenticate(signer.identity, signer.device, signer.proof(nonce)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate() after close = %v, want %v", err, ErrClosed)
	}
	if _, err := s.Challenge(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Challenge() after close = %v", err)
	}
	if r.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", r.Len())
	}
}

func TestCloseClearsAuthentication(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	s := r.Open()
	if err := newSigner(t).prove(t, s); err != nil {
		t.Fatal(err)
	}

	s.Close()

	if _, ok := s.Identity(); ok {
		t.Fatal("closed session still authenticated")
	}
	if s.State() != Closed || r.Authenticated() != 0 || r.Len() != 0 {
		t.Fatalf("State() = %v, Authenticated() = %d, Len() = %d", s.State(), r.Authenticated(), r.Len())
	}
}

func TestSameIdentityOnIndependentSessions(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	signer := newSigner(t)
	first, second := r.Open(), r.Open()

	if err := signer.prove(t, first); err != nil {
		t.Fatal(err)
	}
	if _, ok := second.Identity(); ok {
		t.Fatal("second session authenticated without proof")
	}
	if err := signer.prove(t, second); err != nil {
		t.Fatal(err)
	}
	if r.Authenticated() != 2 {
		t.Fatalf("Authenticated() = %d, want 2", r.Authenticated())
	}

	first.Close()
	if id, ok := second.Identity(); !ok || id.String() != signer.identity {
		t.Fatal("closing one session affected another")
	}
	if r.Authenticated() != 1 {
		t.Fatalf("Authenticated() = %d, want 1", r.Authenticated())
	}
}

func TestConcurrentAuthentication(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	signer := newSigner(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			s := r.Open()
			defer s.Close()
			if err := signer.prove(t, s); err != nil {
				t.Error(err)
			}
			r.Authenticated()
		})
	}
	wg.Wait()
	if r.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", r.Len())
	}
}

func TestConcurrentAttemptsOnOneSession(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	s := r.Open()
	signer := newSigner(t)
	nonce, _ := s.Challenge()
	signature := signer.proof(nonce)

	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := s.Authenticate(signer.identity, signer.device, signature); err == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successful authentications = %d, want 1", successes.Load())
	}
}

func TestConcurrentCloseDuringAuthentication(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	signer := newSigner(t)
	for range 50 {
		s := r.Open()
		nonce, _ := s.Challenge()
		signature := signer.proof(nonce)
		var wg sync.WaitGroup
		wg.Go(func() { s.Authenticate(signer.identity, signer.device, signature) })
		wg.Go(func() { s.Close() })
		wg.Wait()
		if _, ok := s.Identity(); ok {
			t.Fatal("closed session reports authenticated")
		}
	}
	if r.Len() != 0 || r.Authenticated() != 0 {
		t.Fatalf("Len() = %d, Authenticated() = %d", r.Len(), r.Authenticated())
	}
}

func FuzzAuthenticate(f *testing.F) {
	signer := newSigner(f)
	f.Add(signer.identity, signer.device, signer.sign([]byte("x")))
	f.Add("", "", "")
	f.Add(strings.Repeat("A", 43), strings.Repeat("A", 22), strings.Repeat("A", 86))

	r := NewRegistry(time.Now, nil, known)
	f.Fuzz(func(t *testing.T, encoded, device, signature string) {
		s := r.Open()
		defer s.Close()
		s.Challenge()
		if _, err := s.Authenticate(encoded, device, signature); err == nil {
			t.Fatalf("accepted forged authentication %q %q", encoded, signature)
		}
		if _, ok := s.Identity(); ok {
			t.Fatal("session authenticated after rejected attempt")
		}
	})
}

func TestDeviceAdmission(t *testing.T) {
	owner := newSigner(t)
	unlisted := newDevice(t, false)
	other := newSigner(t)
	tests := map[string]func(s *Session) error{
		"unlisted device": func(s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(unlisted.identity, unlisted.device, unlisted.proof(nonce))
			return err
		},
		"root key instead of device key": func(s *Session) error {
			nonce, _ := s.Challenge()
			sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(owner.root, Message(nonce, owner.owner, owner.deviceRaw)))
			_, err := s.Authenticate(owner.identity, owner.device, sig)
			return err
		},
		"device of another identity": func(s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(owner.identity, other.device, other.proof(nonce))
			return err
		},
		"proof bound to another device": func(s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(owner.identity, owner.device, owner.sign(Message(nonce, owner.owner, other.deviceRaw)))
			return err
		},
		"proof bound to another identity": func(s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(owner.identity, owner.device, owner.sign(Message(nonce, other.owner, owner.deviceRaw)))
			return err
		},
		"malformed device": func(s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(owner.identity, owner.device+"A", owner.proof(nonce))
			return err
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			r := NewRegistry(time.Now, nil, known)
			s := r.Open()
			if err := run(s); err == nil {
				t.Fatal("accepted")
			}
			if _, ok := s.Device(); ok {
				t.Fatal("device recorded for rejected attempt")
			}
		})
	}
	if err := newDevice(t, true).prove(t, NewRegistry(time.Now, nil, nil).Open()); !errors.Is(err, ErrFailed) {
		t.Fatalf("registry without devices = %v", err)
	}
}

func TestRevokedDeviceCannotAuthenticateAndCloseReleases(t *testing.T) {
	r := NewRegistry(time.Now, nil, known)
	signer := newSigner(t)
	s := r.Open()
	if err := signer.prove(t, s); err != nil {
		t.Fatal(err)
	}
	if device, ok := s.Device(); !ok || device != signer.device {
		t.Fatalf("Device() = %q %v", device, ok)
	}
	before := known.released.Load()
	s.Close()
	if known.released.Load() != before+1 {
		t.Fatal("closing did not release the device admission")
	}
	known.revoke(signer)
	if err := signer.prove(t, r.Open()); !errors.Is(err, ErrFailed) {
		t.Fatalf("revoked device = %v", err)
	}
}
