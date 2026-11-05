//go:build !linux

package main

import (
	"errors"
	"io"
)

func groupLocksOperatorCommand(action string, args []string, out io.Writer) error {
	if _, err := parseGroupLocksCLIArguments(action, args); err != nil {
		return err
	}
	return errors.New("native Thread operator requires the supported Linux Runtime record and local Node socket")
}
