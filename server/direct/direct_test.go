package direct

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

type key struct {
	private  ed25519.PrivateKey
	identity identity.Identity
}

func newKey(t testing.TB) key {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Parse(base64.RawURLEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	return key{private: private, identity: id}
}

func randomText(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newBundle(t testing.TB) Bundle {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Key: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), Signature: randomText(64)}
}

type fixture struct {
	direct   *Registry
	sessions *auth.Registry
}

func newFixture() fixture {
	d := NewRegistry()
	return fixture{direct: d, sessions: auth.NewRegistry(time.Now, d)}
}

func (f fixture) authenticated(t testing.TB, k key) *auth.Session {
	t.Helper()
	s := f.sessions.Open()
	nonce, err := s.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, auth.Message(nonce)))
	if _, err := s.Authenticate(k.identity.String(), signature); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f fixture) published(t testing.TB, k key, b Bundle) *auth.Session {
	t.Helper()
	s := f.authenticated(t, k)
	if err := f.direct.Publish(s, b); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	return s
}

func TestPublishRequiresAuthentication(t *testing.T) {
	f := newFixture()
	s := f.sessions.Open()
	if err := f.direct.Publish(s, newBundle(t)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Publish() = %v", err)
	}
	if _, ok := f.direct.Static(s); ok {
		t.Fatal("unauthenticated session has a static key")
	}
}

func TestPublishBindsOneKeyPerIdentity(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	first, second := newBundle(t), newBundle(t)
	s1 := f.published(t, a, first)
	s2 := f.authenticated(t, a)
	if err := f.direct.Publish(s2, second); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("conflicting key = %v", err)
	}
	if err := f.direct.Publish(s2, first); err != nil {
		t.Fatalf("same key = %v", err)
	}
	if err := f.direct.Publish(s1, second); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("replacing shared key = %v", err)
	}
	s2.Close()
	if err := f.direct.Publish(s1, second); err != nil {
		t.Fatalf("sole session replacement = %v", err)
	}
	if got, _ := f.direct.Bundle(a.identity); got != second {
		t.Fatalf("bundle = %+v", got)
	}
	if got, ok := f.direct.Static(s1); !ok || got != second {
		t.Fatalf("static = %+v %v", got, ok)
	}
}

func TestStaticRequiresThisSessionsPublication(t *testing.T) {
	f := newFixture()
	a := newKey(t)
	bundle := newBundle(t)
	f.published(t, a, bundle)
	other := f.authenticated(t, a)
	if _, ok := f.direct.Static(other); ok {
		t.Fatal("session that never published has a static key")
	}
}

func TestDetachReleasesAllState(t *testing.T) {
	f := newFixture()
	k := newKey(t)
	bundle := newBundle(t)
	var sessions []*auth.Session
	for range 4 {
		sessions = append(sessions, f.published(t, k, bundle))
	}
	for _, s := range sessions {
		s.Close()
		f.direct.Detach(s)
		f.direct.Detach(s)
	}
	if n := len(f.direct.identities) + len(f.direct.keys); n != 0 {
		t.Fatalf("leaked %d entries", n)
	}
	if _, ok := f.direct.Bundle(k.identity); ok {
		t.Fatal("bundle survived its last session")
	}
}

func TestConcurrentPublishAndClose(t *testing.T) {
	f := newFixture()
	k := newKey(t)
	bundle := newBundle(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := f.published(t, k, bundle)
			f.direct.Static(s)
			f.direct.Bundle(k.identity)
			s.Close()
			f.direct.Detach(s)
		}()
	}
	wg.Wait()
	if n := len(f.direct.identities) + len(f.direct.keys); n != 0 {
		t.Fatalf("leaked %d entries", n)
	}
}
