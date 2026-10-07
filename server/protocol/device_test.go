package protocol

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/device"
	"github.com/Xhaann/ghost-x/server/device/devicetest"
)

func deviceRouter(r *device.Registry) *Router {
	return NewRouter(map[string]Handler{
		"register": Register(r),
		"devices":  Devices(r),
	}, nil)
}

func registerFrame(r device.Roster) []byte {
	payload, _ := json.Marshal(EncodeRoster(r))
	return fmt.Appendf(nil, `{"type":"register","id":"r1","payload":%s}`, payload)
}

func lookupFrame(identity string) []byte {
	return fmt.Appendf(nil, `{"type":"devices","id":"d1","payload":{"identity":%q}}`, identity)
}

func freshRegistry(t testing.TB) *device.Registry {
	t.Helper()
	r, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterAndLookupRoster(t *testing.T) {
	r := freshRegistry(t)
	conn := deviceRouter(r).Conn(auth.NewRegistry(time.Now, nil, r).Open(), discard)
	id := devicetest.NewIdentity()
	a, b := id.NewDevice(), id.NewDevice()
	first := id.Add(a)
	resp := decodeResponse(t, conn.Handle(registerFrame(first)))
	if resp.Type != "registered" || string(resp.Payload) != `{"version":1}` {
		t.Fatalf("register = %+v %s", resp, resp.Payload)
	}
	second := id.Add(b)
	if resp := decodeResponse(t, conn.Handle(registerFrame(second))); resp.Type != "registered" {
		t.Fatalf("second = %+v", resp)
	}
	lookup := decodeResponse(t, conn.Handle(lookupFrame(id.Identity)))
	want, _ := json.Marshal(EncodeRoster(second))
	if lookup.Type != "devices" || string(lookup.Payload) != string(want) {
		t.Fatalf("lookup = %+v %s", lookup, lookup.Payload)
	}
	if resp := decodeResponse(t, conn.Handle(registerFrame(second))); resp.Type != "registered" {
		t.Fatalf("idempotent replay = %+v", resp)
	}
	expectCode(t, conn.Handle(registerFrame(first)), CodeStaleRoster)
	expectCode(t, conn.Handle(lookupFrame(devicetest.NewIdentity().Identity)), CodeUnavailable)
	expectCode(t, conn.Handle(lookupFrame("x")), CodeInvalidPayload)
	expectCode(t, conn.Handle([]byte(`{"type":"devices","id":"d1","payload":{"identity":"`+id.Identity+`","device":"x"}}`)), CodeInvalidPayload)
}

func TestRegisterRejectsForgedOrMalformedRosters(t *testing.T) {
	id := devicetest.NewIdentity()
	other := devicetest.NewIdentity()
	d := id.NewDevice()
	valid := id.Add(d)
	encoded, _ := json.Marshal(EncodeRoster(valid))
	body := string(encoded)
	crossed := other.Sign(1, []*devicetest.Device{d})
	signedByOther := valid
	signedByOther.Signature = other.Sign(1, []*devicetest.Device{other.NewDevice()}).Signature
	cases := map[string]string{
		"signed by another identity": mustJSON(EncodeRoster(signedByOther)),
		"device of another identity": mustJSON(EncodeRoster(crossed)),
		"version zero":               strings.Replace(body, `"version":1`, `"version":0`, 1),
		"negative version":           strings.Replace(body, `"version":1`, `"version":-1`, 1),
		"float version":              strings.Replace(body, `"version":1`, `"version":1.0`, 1),
		"padded version":             strings.Replace(body, `"version":1`, `"version":01`, 1),
		"huge version":               strings.Replace(body, `"version":1`, `"version":4294967296`, 1),
		"extra field":                strings.Replace(body, `{"identity"`, `{"root":"x","identity"`, 1),
		"device extra field":         strings.Replace(body, `{"id"`, `{"private":"x","id"`, 1),
		"devices object":             `{"identity":"` + id.Identity + `","version":1,"devices":{"x":1},"signature":"` + valid.Signature + `"}`,
		"empty devices":              `{"identity":"` + id.Identity + `","version":1,"devices":[],"signature":"` + valid.Signature + `"}`,
		"missing signature":          `{"identity":"` + id.Identity + `","version":1,"devices":[]}`,
		"null":                       `null`,
	}
	r := freshRegistry(t)
	router := deviceRouter(r)
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			conn := router.Conn(auth.NewRegistry(time.Now, nil, r).Open(), discard)
			resp := decodeResponse(t, conn.Handle([]byte(`{"type":"register","id":"r1","payload":`+payload+`}`)))
			if code := errorCode(t, resp); code != CodeInvalidPayload && code != CodeInvalidMessage {
				t.Fatalf("code = %q", code)
			}
		})
	}
	if r.Len() != 0 {
		t.Fatal("forged roster stored")
	}
}

func TestRegistrationAndLookupsAreRateLimited(t *testing.T) {
	r := freshRegistry(t)
	conn := deviceRouter(r).Conn(auth.NewRegistry(time.Now, nil, r).Open(), discard)
	for range MaxRegistrations {
		id := devicetest.NewIdentity()
		if resp := decodeResponse(t, conn.Handle(registerFrame(id.Add(id.NewDevice())))); resp.Type != "registered" {
			t.Fatal(resp)
		}
	}
	id := devicetest.NewIdentity()
	expectCode(t, conn.Handle(registerFrame(id.Add(id.NewDevice()))), CodeRateLimited)
	for range MaxLookups {
		conn.Handle(lookupFrame(id.Identity))
	}
	expectCode(t, conn.Handle(lookupFrame(id.Identity)), CodeRateLimited)
	fresh := deviceRouter(r).Conn(auth.NewRegistry(time.Now, nil, r).Open(), discard)
	if resp := decodeResponse(t, fresh.Handle(registerFrame(id.Next()))); resp.Type != "registered" {
		t.Fatalf("new connection = %+v", resp)
	}
}

func FuzzRegisterPayload(f *testing.F) {
	id := devicetest.NewIdentity()
	valid := id.Add(id.NewDevice())
	encoded, _ := json.Marshal(EncodeRoster(valid))
	f.Add(string(encoded))
	f.Add(strings.Replace(string(encoded), `"version":1`, `"version":2`, 1))
	f.Add(`{"identity":"","version":1,"devices":[{"id":"","signing":"","exchange":""}],"signature":""}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, payload string) {
		r := freshRegistry(t)
		conn := deviceRouter(r).Conn(auth.NewRegistry(time.Now, nil, r).Open(), discard)
		resp := decodeResponse(t, conn.Handle([]byte(`{"type":"register","id":"r1","payload":`+payload+`}`)))
		if resp.Type != "registered" {
			if r.Len() != 0 {
				t.Fatal("rejected roster stored")
			}
			return
		}
		roster, err := decodeRoster([]byte(payload))
		if err != nil {
			t.Fatalf("accepted undecodable roster %q", payload)
		}
		owner, err := device.Verify(roster)
		if err != nil || owner.String() != roster.Identity {
			t.Fatalf("accepted unsigned roster %q", payload)
		}
		stored, ok := r.Roster(roster.Identity)
		if !ok || r.Len() != 1 || stored.Version != roster.Version || stored.Signature != roster.Signature || !slices.Equal(stored.Devices, roster.Devices) {
			t.Fatalf("stored roster differs from the accepted one %q", payload)
		}
	})
}
