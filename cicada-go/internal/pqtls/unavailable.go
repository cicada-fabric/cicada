//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

import (
	"context"
	"net"
)

func Available() error                                       { return ErrUnavailable }
func checkMaterial(Config) error                             { return ErrUnavailable }
func dial(context.Context, string, Config) (net.Conn, error) { return nil, ErrUnavailable }
func listen(string, Config) (net.Listener, error)            { return nil, ErrUnavailable }
