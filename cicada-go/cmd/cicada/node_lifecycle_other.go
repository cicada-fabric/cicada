//go:build !linux

package main

import (
	"errors"
	"io"
)

func nodeLifecycleCommand(string, []string, io.Writer) error {
	return errors.New("NODE_SERVICE_UNSUPPORTED: Linux systemd user services are required")
}
