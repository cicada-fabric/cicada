//go:build !linux

package main

import (
	"errors"
	"io"
)

func nativeThreadOperatorCommand(string, []string, io.Writer) error {
	return errors.New("terminal Thread registration is supported on Linux")
}
