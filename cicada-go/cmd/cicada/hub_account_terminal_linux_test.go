//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"golang.org/x/sys/unix"
)

func TestHubAccountAppCodeDisplayRequiresAndUsesInteractiveTTY(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := hubSetupCommand([]string{"--owner-label", "Synthetic terminal owner", "--origin", "https://terminal.synthetic.invalid",
		"--public-config", filepath.Join(root, "connection.json"), "--state-dir", stateDir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0700); err != nil {
		t.Fatal(err)
	}
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	if err = unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	claimPath := filepath.Join(privateDir, "owner-claim.json")
	if err = hubAccountClaimIssueCommand([]string{"--state-dir", stateDir, "--claim-file", claimPath, "--show-app-code"}, terminal, terminal); err != nil {
		t.Fatal(err)
	}
	cardBytes, err := os.ReadFile(claimPath)
	if err != nil {
		t.Fatal(err)
	}
	card, err := wire.DecodeClaimCard(cardBytes)
	if err != nil {
		t.Fatal(err)
	}
	var displayed []byte
	buf := make([]byte, 4096)
	poll := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
	for {
		ready, pollErr := unix.Poll(poll, 0)
		if pollErr != nil {
			t.Fatal(pollErr)
		}
		if ready == 0 || poll[0].Revents&unix.POLLIN == 0 {
			break
		}
		n, readErr := unix.Read(int(master.Fd()), buf)
		displayed = append(displayed, buf[:n]...)
		if readErr != nil {
			if readErr == syscall.EAGAIN || readErr == syscall.EWOULDBLOCK {
				break
			}
			t.Fatal(readErr)
		}
		if n == 0 {
			break
		}
	}
	activation, err := wire.DecodeOwnerAccountClaimCode(strings.TrimSpace(string(displayed)))
	if err != nil || activation != card {
		t.Fatal("explicit TTY display omitted the exact canonical App activation code")
	}
	if info, err := os.Stat(claimPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("displayed claim file mode=%v err=%v, want 0600", modeOf(info), err)
	}
}
