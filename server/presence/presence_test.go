package presence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
)

type key struct {
	private  ed25519.PrivateKey
	identity string
}

func newKey(t testing.TB) key {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key{private: private, identity: base64.RawURLEncoding.EncodeToString(public)}
}

func (k key) authenticate(t testing.TB, s *auth.Session) error {
	t.Helper()
	nonce, err := s.Challenge()
	if err != nil {
		return err
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, auth.Message(nonce)))
	_, err = s.Authenticate(k.identity, signature)
	return err
}

type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) deliver(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) log() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

type fixture struct {
	presence *Registry
	sessions *auth.Registry
}

func newFixture() fixture {
	p := NewRegistry()
	return fixture{presence: p, sessions: auth.NewRegistry(time.Now, p)}
}

func (f fixture) authenticated(t *testing.T, k key) *auth.Session {
	t.Helper()
	s := f.sessions.Open()
	if err := k.authenticate(t, s); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return s
}

func (f fixture) watch(t *testing.T) (*recorder, key) {
	t.Helper()
	watcher := newKey(t)
	rec := &recorder{}
	if err := f.presence.Subscribe(f.authenticated(t, watcher), rec.deliver); err != nil {
		t.Fatal(err)
	}
	return rec, watcher
}

func present(id string) Event { return Event{Identity: id, Present: true} }
func absent(id string) Event  { return Event{Identity: id, Present: false} }

func expectLog(t *testing.T, rec *recorder, want ...Event) {
	t.Helper()
	if got := rec.log(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestUnauthenticatedSessionIsNotPresent(t *testing.T) {
	f := newFixture()
	s := f.sessions.Open()
	s.Challenge()

	if got := f.presence.Present(); len(got) != 0 {
		t.Fatalf("Present() = %v, want empty", got)
	}
	if err := f.presence.Subscribe(s, func(Event) {}); !errors.Is(err, ErrNotPresent) {
		t.Fatalf("Subscribe() = %v, want %v", err, ErrNotPresent)
	}
}

func TestFailedAuthenticationIsNotPresent(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)
	other := newKey(t)
	s := f.sessions.Open()

	for range auth.MaxFailures {
		nonce, _ := s.Challenge()
		s.Authenticate(k.identity, base64.RawURLEncoding.EncodeToString(ed25519.Sign(other.private, auth.Message(nonce))))
	}
	s.Close()

	if got := f.presence.Present(); !slices.Equal(got, []string{watcher.identity}) {
		t.Fatalf("Present() = %v", got)
	}
	expectLog(t, rec, present(watcher.identity))
}

func TestAuthenticationCreatesPresence(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)

	f.authenticated(t, k)

	want := []string{watcher.identity, k.identity}
	slices.Sort(want)
	if got := f.presence.Present(); !slices.Equal(got, want) {
		t.Fatalf("Present() = %v, want %v", got, want)
	}
	expectLog(t, rec, present(watcher.identity), present(k.identity))
}

func TestPresenceFollowsFirstAndLastSession(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)

	first := f.authenticated(t, k)
	second := f.authenticated(t, k)
	first.Close()
	if !slices.Contains(f.presence.Present(), k.identity) {
		t.Fatal("identity absent while a session remains")
	}
	second.Close()

	expectLog(t, rec, present(watcher.identity), present(k.identity), absent(k.identity))
	if slices.Contains(f.presence.Present(), k.identity) {
		t.Fatal("identity present after last session closed")
	}
}

func TestIdentitiesAreTrackedIndependently(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	a, b := newKey(t), newKey(t)

	sa := f.authenticated(t, a)
	sb := f.authenticated(t, b)
	sa.Close()

	if got := f.presence.Present(); !slices.Contains(got, b.identity) || slices.Contains(got, a.identity) {
		t.Fatalf("Present() = %v", got)
	}
	sb.Close()
	expectLog(t, rec, present(watcher.identity), present(a.identity), present(b.identity), absent(a.identity), absent(b.identity))
}

func TestRepeatedLifecycleEventsAreHarmless(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)

	s := f.authenticated(t, k)
	id, _ := s.Identity()
	f.presence.Authenticated(s, id)
	s.Close()
	s.Close()
	f.presence.Closed(s, id)
	f.presence.Closed(f.sessions.Open(), id)

	expectLog(t, rec, present(watcher.identity), present(k.identity), absent(k.identity))
}

func TestSubscribeDeliversSortedSnapshot(t *testing.T) {
	f := newFixture()
	keys := []key{newKey(t), newKey(t), newKey(t)}
	for _, k := range keys {
		f.authenticated(t, k)
	}

	rec, watcher := f.watch(t)

	var want []Event
	for _, id := range f.presence.Present() {
		want = append(want, present(id))
	}
	if len(want) != 4 || !slices.Contains(f.presence.Present(), watcher.identity) {
		t.Fatalf("Present() = %v", f.presence.Present())
	}
	expectLog(t, rec, want...)
}

func TestSubscribeIsIdempotent(t *testing.T) {
	f := newFixture()
	k := newKey(t)
	s := f.authenticated(t, k)
	rec := &recorder{}

	if err := f.presence.Subscribe(s, rec.deliver); err != nil {
		t.Fatal(err)
	}
	if err := f.presence.Subscribe(s, rec.deliver); err != nil {
		t.Fatal(err)
	}

	expectLog(t, rec, present(k.identity))
}

func TestClosedSubscriberStopsReceiving(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	other := newKey(t)

	stopped := &recorder{}
	k := newKey(t)
	s := f.authenticated(t, k)
	if err := f.presence.Subscribe(s, stopped.deliver); err != nil {
		t.Fatal(err)
	}
	s.Close()
	f.authenticated(t, other)

	if err := f.presence.Subscribe(s, stopped.deliver); !errors.Is(err, ErrNotPresent) {
		t.Fatalf("Subscribe() after close = %v", err)
	}
	snapshot := []string{watcher.identity, k.identity}
	slices.Sort(snapshot)
	expectLog(t, stopped, present(snapshot[0]), present(snapshot[1]))
	expectLog(t, rec, present(watcher.identity), present(k.identity), absent(k.identity), present(other.identity))
}

func TestConcurrentSessionsForOneIdentity(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)
	sessions := make([]*auth.Session, 32)

	var wg sync.WaitGroup
	for i := range sessions {
		wg.Go(func() {
			s := f.sessions.Open()
			if err := k.authenticate(t, s); err != nil {
				t.Error(err)
			}
			sessions[i] = s
		})
	}
	wg.Wait()
	for _, s := range sessions {
		wg.Go(s.Close)
	}
	wg.Wait()

	expectLog(t, rec, present(watcher.identity), present(k.identity), absent(k.identity))
}

func TestConcurrentDifferentIdentities(t *testing.T) {
	f := newFixture()
	rec, _ := f.watch(t)
	keys := make([]key, 16)
	for i := range keys {
		keys[i] = newKey(t)
	}

	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Go(func() {
			s := f.sessions.Open()
			if err := k.authenticate(t, s); err != nil {
				t.Error(err)
			}
			s.Close()
		})
	}
	wg.Wait()

	counts := map[Event]int{}
	for _, e := range rec.log()[1:] {
		counts[e]++
	}
	for _, k := range keys {
		if counts[present(k.identity)] != 1 || counts[absent(k.identity)] != 1 {
			t.Fatalf("identity %s: present %d, absent %d", k.identity, counts[present(k.identity)], counts[absent(k.identity)])
		}
	}
	if len(f.presence.Present()) != 1 {
		t.Fatalf("Present() = %v", f.presence.Present())
	}
}

func TestAuthenticationRacingClose(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)

	for range 200 {
		s := f.sessions.Open()
		nonce, _ := s.Challenge()
		signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, auth.Message(nonce)))
		var wg sync.WaitGroup
		wg.Go(func() { s.Authenticate(k.identity, signature) })
		wg.Go(s.Close)
		wg.Wait()
	}

	if got := f.presence.Present(); !slices.Equal(got, []string{watcher.identity}) {
		t.Fatalf("Present() = %v", got)
	}
	events := rec.log()[1:]
	for i, e := range events {
		if e.Identity != k.identity || e.Present != (i%2 == 0) {
			t.Fatalf("event %d = %v, want alternating transitions", i, e)
		}
	}
	if len(events)%2 != 0 {
		t.Fatalf("unbalanced transitions: %d", len(events))
	}
}

func TestConcurrentOverlappingSessionsKeepPresence(t *testing.T) {
	f := newFixture()
	rec, watcher := f.watch(t)
	k := newKey(t)
	anchor := f.authenticated(t, k)

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			s := f.sessions.Open()
			if err := k.authenticate(t, s); err != nil {
				t.Error(err)
			}
			s.Close()
		})
	}
	wg.Wait()
	anchor.Close()

	expectLog(t, rec, present(watcher.identity), present(k.identity), absent(k.identity))
}
