package protocol

import (
	"errors"
	"maps"

	"github.com/Xhaann/ghost-x/server/auth"
	"github.com/Xhaann/ghost-x/server/identity"
)

type Handler func(c *Conn, payload []byte) (Reply, error)

type ProtectedHandler func(c *Conn, id identity.Identity, payload []byte) (Reply, error)

type Router struct {
	public    map[string]Handler
	protected map[string]ProtectedHandler
}

type Conn struct {
	router        *Router
	session       *auth.Session
	push          func([]byte)
	request       string
	registrations int
	lookups       int
}

func NewRouter(public map[string]Handler, protected map[string]ProtectedHandler) *Router {
	for name := range protected {
		if _, ok := public[name]; ok {
			panic("protocol: route registered as public and protected: " + name)
		}
	}
	return &Router{public: maps.Clone(public), protected: maps.Clone(protected)}
}

func (r *Router) Conn(session *auth.Session, push func([]byte)) *Conn {
	return &Conn{router: r, session: session, push: push}
}

func (c *Conn) Handle(data []byte) []byte {
	req, err := Decode(data)
	if err != nil {
		return encodeError(req.ID, codeOf(err))
	}

	c.request = req.ID
	reply, err := c.dispatch(req)
	if err != nil {
		return encodeError(req.ID, codeOf(err))
	}
	return encode(reply.Type, req.ID, reply.Payload)
}

func (c *Conn) dispatch(req Request) (Reply, error) {
	if handler, ok := c.router.public[req.Type]; ok {
		return handler(c, req.Payload)
	}
	if handler, ok := c.router.protected[req.Type]; ok {
		id, authenticated := c.session.Identity()
		if !authenticated {
			return Reply{}, &Error{Code: CodeAuthRequired}
		}
		return handler(c, id, req.Payload)
	}
	return Reply{}, &Error{Code: CodeUnsupportedType}
}

func codeOf(err error) Code {
	var protoErr *Error
	if errors.As(err, &protoErr) {
		return protoErr.Code
	}
	return CodeInternalError
}
