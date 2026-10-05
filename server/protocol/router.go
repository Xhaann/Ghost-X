package protocol

import (
	"errors"
	"maps"

	"github.com/Xhaann/ghost-x/server/auth"
)

type Handler func(c *Conn, payload []byte) (Reply, error)

type Router struct {
	handlers map[string]Handler
}

type Conn struct {
	router  *Router
	session *auth.Session
}

func NewRouter(handlers map[string]Handler) *Router {
	return &Router{handlers: maps.Clone(handlers)}
}

func (r *Router) Conn(session *auth.Session) *Conn {
	return &Conn{router: r, session: session}
}

func (c *Conn) Handle(data []byte) []byte {
	req, err := Decode(data)
	if err != nil {
		return encodeError(req.ID, codeOf(err))
	}

	handler, ok := c.router.handlers[req.Type]
	if !ok {
		return encodeError(req.ID, CodeUnsupportedType)
	}

	reply, err := handler(c, req.Payload)
	if err != nil {
		return encodeError(req.ID, codeOf(err))
	}
	return encode(reply.Type, req.ID, reply.Payload)
}

func codeOf(err error) Code {
	var protoErr *Error
	if errors.As(err, &protoErr) {
		return protoErr.Code
	}
	return CodeInternalError
}
