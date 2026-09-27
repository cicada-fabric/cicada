//go:build windows

package workspace

import (
	"os/exec"
	"time"
)

// Windows CommandContext terminates the direct child when its context expires.
// Keep a bounded wait for descendants that still hold stdout or stderr open.
func configureChildProcess(command *exec.Cmd) {
	command.WaitDelay = 5 * time.Second
}
