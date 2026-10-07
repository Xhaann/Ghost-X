package protocol

import (
	"errors"

	"github.com/Xhaann/ghost-x/server/identity"
	"github.com/Xhaann/ghost-x/server/presence"
)

func Presence(registry *presence.Registry) ProtectedHandler {
	return func(c *Conn, _ identity.Identity, payload []byte) (Reply, error) {
		if _, err := decodeObject(payload); err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		push := c.push
		err := registry.Subscribe(c.session, func(e presence.Event) {
			push(encodePresence(e))
		})
		if errors.Is(err, presence.ErrNotPresent) {
			return Reply{}, &Error{Code: CodeAuthRequired}
		}
		if err != nil {
			return Reply{}, err
		}
		return Reply{Type: "presence", Payload: struct{}{}}, nil
	}
}

func encodePresence(e presence.Event) []byte {
	typ := "absent"
	if e.Present {
		typ = "present"
	}
	return encode(typ, "", identityPayload{Identity: e.Identity})
}

type identityPayload struct {
	Identity string `json:"identity"`
}
