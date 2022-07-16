package tlsconfig

import "errors"

var (
	ErrReadPEMFile  = errors.New("unable to read PEM file")
	ErrMalformedPEM = errors.New("malformed PEM")
)
