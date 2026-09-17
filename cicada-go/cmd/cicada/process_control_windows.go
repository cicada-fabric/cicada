//go:build windows

package main

import (
	"os/exec"
	"time"
)

func configureChildProcess(command *exec.Cmd) {
	command.WaitDelay = 5 * time.Second
}
