//go:build windows

package codexapp

import (
	"errors"
	"os/exec"
	"time"
)

func configureAppServerProcess(command *exec.Cmd) {
	command.WaitDelay = 5 * time.Second
}

func waitAppServerProcessTree(command *exec.Cmd) error {
	if command == nil || command.ProcessState == nil || !command.ProcessState.Exited() {
		return errors.New("Codex app-server process exit was not confirmed")
	}
	return errors.New("Windows app-server descendant stop is not yet supported")
}
