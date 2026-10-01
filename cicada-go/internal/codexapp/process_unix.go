//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package codexapp

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureAppServerProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 5 * time.Second
}

func waitAppServerProcessTree(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	processGroup := -command.Process.Pid
	err := syscall.Kill(processGroup, syscall.SIGKILL)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Kill(processGroup, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("Codex app-server process group did not stop within the bounded wait")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
