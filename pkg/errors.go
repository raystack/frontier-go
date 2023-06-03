package pkg

import "errors"

var (
	ErrMissingHost    = errors.New("missing shield host")
	ErrInvalidHeader  = errors.New("invalid auth header")
	ErrInvalidToken   = errors.New("failed to verify a valid token")
	ErrJWKsFetch      = errors.New("failed to fetch jwks")
	ErrInvalidSession = errors.New("invalid session, failed to fetch user")
	ErrInternalServer = errors.New("internal server error")
)
