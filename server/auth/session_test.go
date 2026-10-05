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

type signer struct {
	private  ed25519.PrivateKey
	identity string
}

func newSigner(t testing.TB) signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{private: private, identity: base64.RawURLEncoding.EncodeToString(public)}
}

func (s signer) sign(message []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, message))
}

func (s signer) prove(t testing.TB, session *Session) error {
	t.Helper()
	nonce, err := session.Challenge()
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}
	_, err = session.Authenticate(s.identity, s.sign(Message(nonce)))
	return err
}

func TestNewSessionIsUnauthenticated(t *testing.T) {
	r := NewRegistry(time.Now)
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
	r := NewRegistry(time.Now)
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
	want := append([]byte("ghostx/session/authenticate/v1\x00"), nonce...)
	if got := Message(nonce); string(got) != string(want) {
		t.Fatalf("Message() = %q, want %q", got, want)
	}
}

func TestChallengesAreUniqueAndCopied(t *testing.T) {
	s := NewRegistry(time.Now).Open()
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
	signed := Message(nonce)
	nonce[0] ^= 0xff
	if _, err := s.Authenticate(signer.identity, signer.sign(signed)); err != nil {
		t.Fatalf("Authenticate() after mutating returned nonce = %v", err)
	}
}

func TestAuthenticateRejected(t *testing.T) {
	signer := newSigner(t)
	other := newSigner(t)

	tests := map[string]func(t *testing.T, c *clock, s *Session) error{
		"no challenge": func(t *testing.T, c *clock, s *Session) error {
			_, err := s.Authenticate(signer.identity, signer.sign(Message(make([]byte, ChallengeSize))))
			return err
		},
		"expired challenge": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			c.Advance(ChallengeTTL)
			_, err := s.Authenticate(signer.identity, signer.sign(Message(nonce)))
			return err
		},
		"superseded challenge": func(t *testing.T, c *clock, s *Session) error {
			first, _ := s.Challenge()
			s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.sign(Message(first)))
			return err
		},
		"reused challenge": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			if _, err := s.Authenticate(signer.identity, other.sign(Message(nonce))); !errors.Is(err, ErrFailed) {
				t.Fatalf("first attempt = %v", err)
			}
			_, err := s.Authenticate(signer.identity, signer.sign(Message(nonce)))
			return err
		},
		"signed by other key": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(signer.identity, other.sign(Message(nonce)))
			return err
		},
		"claims other identity": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(other.identity, signer.sign(Message(nonce)))
			return err
		},
		"raw nonce": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.sign(nonce))
			return err
		},
		"identity proof context": func(t *testing.T, c *clock, s *Session) error {
			nonce, _ := s.Challenge()
			_, err := s.Authenticate(signer.identity, signer.sign(append([]byte("ghostx/identity/proof/v1\x00"), nonce...)))
			return err
		},
		"malformed signature": func(t *testing.T, c *clock, s *Session) error {
			s.Challenge()
			_, err := s.Authenticate(signer.identity, "x")
			return err
		},
		"oversized signature": func(t *testing.T, c *clock, s *Session) error {
			s.Challenge()
			_, err := s.Authenticate(signer.identity, strings.Repeat("A", 1<<20))
			return err
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			r := NewRegistry(c.Now)
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
	s := NewRegistry(c.Now).Open()
	signer := newSigner(t)

	nonce, _ := s.Challenge()
	c.Advance(ChallengeTTL - time.Nanosecond)
	if _, err := s.Authenticate(signer.identity, signer.sign(Message(nonce))); err != nil {
		t.Fatalf("Authenticate() before expiry = %v", err)
	}
}

func TestMalformedIdentityConsumesChallenge(t *testing.T) {
	s := NewRegistry(time.Now).Open()
	signer := newSigner(t)

	nonce, _ := s.Challenge()
	for _, bad := range []string{"", "x", signer.identity + "=", strings.Repeat("A", 1<<20), base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))} {
		if _, err := s.Authenticate(bad, signer.sign(Message(nonce))); !errors.Is(err, ErrInvalidIdentity) && !errors.Is(err, ErrFailed) {
			t.Fatalf("Authenticate(%.10q) error = %v", bad, err)
		}
	}
	if _, err := s.Authenticate(signer.identity, signer.sign(Message(nonce))); err == nil {
		t.Fatal("challenge survived malformed attempt")
	}
}

func TestChallengesAreBoundToSession(t *testing.T) {
	r := NewRegistry(time.Now)
	first, second := r.Open(), r.Open()
	signer := newSigner(t)

	nonce, _ := first.Challenge()
	second.Challenge()
	if _, err := second.Authenticate(signer.identity, signer.sign(Message(nonce))); !errors.Is(err, ErrFailed) {
		t.Fatalf("cross-session proof error = %v, want %v", err, ErrFailed)
	}
	if _, err := first.Authenticate(signer.identity, signer.sign(Message(nonce))); err != nil {
		t.Fatalf("original session error = %v", err)
	}
	if _, ok := second.Identity(); ok {
		t.Fatal("second session authenticated by first session's proof")
	}
}

func TestFailuresLockSession(t *testing.T) {
	r := NewRegistry(time.Now)
	s := r.Open()
	signer := newSigner(t)
	other := newSigner(t)

	for i := range MaxFailures {
		nonce, err := s.Challenge()
		if err != nil {
			t.Fatalf("Challenge() after %d failures = %v", i, err)
		}
		s.Authenticate(signer.identity, other.sign(Message(nonce)))
	}

	if s.State() != Failed {
		t.Fatalf("State() = %v, want %v", s.State(), Failed)
	}
	if _, err := s.Challenge(); !errors.Is(err, ErrFailed) {
		t.Fatalf("Challenge() after lock = %v", err)
	}
	if _, err := s.Authenticate(signer.identity, signer.sign(Message(nil))); !errors.Is(err, ErrFailed) {
		t.Fatalf("Authenticate() after lock = %v", err)
	}
}

func TestAuthenticatedSessionCannotReauthenticate(t *testing.T) {
	s := NewRegistry(time.Now).Open()
	signer := newSigner(t)
	other := newSigner(t)

	if err := signer.prove(t, s); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Challenge(); !errors.Is(err, ErrFailed) {
		t.Fatalf("Challenge() after authentication = %v", err)
	}
	if _, err := s.Authenticate(other.identity, other.sign(Message(nil))); !errors.Is(err, ErrFailed) {
		t.Fatalf("Authenticate() after authentication = %v", err)
	}
	if id, ok := s.Identity(); !ok || id.String() != signer.identity {
		t.Fatal("identity changed after duplicate authentication")
	}
}

func TestCloseDestroysSession(t *testing.T) {
	r := NewRegistry(time.Now)
	s := r.Open()
	signer := newSigner(t)

	nonce, _ := s.Challenge()
	s.Close()
	s.Close()

	if _, err := s.Authenticate(signer.identity, signer.sign(Message(nonce))); !errors.Is(err, ErrClosed) {
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
	r := NewRegistry(time.Now)
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
	r := NewRegistry(time.Now)
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
	r := NewRegistry(time.Now)
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
	r := NewRegistry(time.Now)
	s := r.Open()
	signer := newSigner(t)
	nonce, _ := s.Challenge()
	signature := signer.sign(Message(nonce))

	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := s.Authenticate(signer.identity, signature); err == nil {
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
	r := NewRegistry(time.Now)
	signer := newSigner(t)
	for range 50 {
		s := r.Open()
		nonce, _ := s.Challenge()
		signature := signer.sign(Message(nonce))
		var wg sync.WaitGroup
		wg.Go(func() { s.Authenticate(signer.identity, signature) })
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
	f.Add(signer.identity, signer.sign([]byte("x")))
	f.Add("", "")
	f.Add(strings.Repeat("A", 43), strings.Repeat("A", 86))

	r := NewRegistry(time.Now)
	f.Fuzz(func(t *testing.T, encoded, signature string) {
		s := r.Open()
		defer s.Close()
		s.Challenge()
		if _, err := s.Authenticate(encoded, signature); err == nil {
			t.Fatalf("accepted forged authentication %q %q", encoded, signature)
		}
		if _, ok := s.Identity(); ok {
			t.Fatal("session authenticated after rejected attempt")
		}
	})
}
