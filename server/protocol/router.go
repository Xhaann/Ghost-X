package protocol

import (
	"errors"
	"maps"
	"time"
)

type Handler func(c *Conn, payload []byte) (Reply, error)

type Router struct {
	handlers map[string]Handler
}

type Conn struct {
	router    *Router
	challenge []byte
	expires   time.Time
}

func NewRouter(handlers map[string]Handler) *Router {
	return &Router{handlers: maps.Clone(handlers)}
}

func (r *Router) Conn() *Conn {
	return &Conn{router: r}
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
