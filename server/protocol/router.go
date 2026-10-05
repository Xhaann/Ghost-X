package protocol

import (
	"errors"
	"maps"
)

type Handler func(payload []byte) (Reply, error)

type Router struct {
	handlers map[string]Handler
}

func NewRouter(handlers map[string]Handler) *Router {
	return &Router{handlers: maps.Clone(handlers)}
}

func (r *Router) Handle(data []byte) []byte {
	req, err := Decode(data)
	if err != nil {
		return encodeError(req.ID, codeOf(err))
	}

	handler, ok := r.handlers[req.Type]
	if !ok {
		return encodeError(req.ID, CodeUnsupportedType)
	}

	reply, err := handler(req.Payload)
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
