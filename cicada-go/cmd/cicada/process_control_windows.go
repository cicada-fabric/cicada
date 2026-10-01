//go:build windows

package main

import (
	"errors"
	"os/exec"
	"time"
)

func configureChildProcess(command *exec.Cmd) {
	command.WaitDelay = 5 * time.Second
}

// Windows currently confirms the direct child through Cmd.Wait. Job-object
// tree ownership is a separate platform follow-up; never treat a failed
// direct wait as a confirmed stop.
func waitChildProcessTree(command *exec.Cmd) error {
	if command == nil || command.ProcessState == nil || !command.ProcessState.Exited() {
		return errors.New("direct child process exit was not confirmed")
	}
	return nil
}
