//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownersigner"
	"golang.org/x/sys/unix"
)

func TestOwnerSignerGrantReviewRejectsRedirectedOutputWithTerminalInput(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	terminalInput, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer terminalInput.Close()

	var redirectedOutput bytes.Buffer
	review := ownersigner.GrantReview{
		AccountID: "account_synthetic", OwnerID: "owner_synthetic", OwnerKeyID: "owner_key_synthetic",
		HubID: "hub_synthetic", DeviceID: "browser_synthetic", DeviceKeyID: "device_key_synthetic",
		DeviceFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Purpose:           e2ee.OwnerDevicePurposeControl,
		IssuedAt:          time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}
	err = ownerSignerGrantReview(terminalInput, &redirectedOutput)(review)
	if err == nil {
		t.Fatal("grant review accepted output that is not visible on a terminal")
	}
	if redirectedOutput.Len() != 0 {
		t.Fatal("grant scope was written to redirected output before refusing review")
	}
}
