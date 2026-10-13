//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"golang.org/x/sys/unix"
)

func TestClientOperatorApprovalRejectsRedirectedOutputWithTerminalInput(t *testing.T) {
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
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	var redirected bytes.Buffer
	if err = clientOperatorApproval(slave, &redirected, clientoperator.NodeCandidate{}); err == nil {
		t.Fatal("accepted approval without visible terminal details")
	}
	if redirected.Len() != 0 {
		t.Fatal("printed confirmation tuple to hidden destination")
	}
}
