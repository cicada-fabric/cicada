package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestOwnerSignerGrantSummaryWritesSamePublicJSONExclusively(t *testing.T) {
	owner, _ := syntheticAdapterPublicIdentity(t, 31)
	issued := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	expires := time.Date(2026, 10, 14, 11, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	summary := ownerSignerGrantSummary{
		Format: "cicada.owner-device-grant-summary.v1", State: "GRANT_WRITTEN",
		HubID: "hub_synthetic", OwnerID: "owner_synthetic", OwnerKeyID: owner.ID, OwnerPublic: owner,
		DeviceID: "browser_synthetic", DeviceKeyID: "device_key_synthetic", DeviceFingerprint: strings.Repeat("a", 64),
		Purpose: e2ee.OwnerDevicePurposeControl, IssuedAt: issued, ExpiresAt: expires,
		GrantFile: filepath.Join(t.TempDir(), "grant.json"),
	}
	path := filepath.Join(t.TempDir(), "grant-summary.json")
	var stdout bytes.Buffer
	if err := writeOwnerSignerGrantSummary(&stdout, path, summary); err != nil {
		t.Fatalf("write grant summary: %v", err)
	}
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileBytes, append(bytes.TrimSpace(stdout.Bytes()), '\n')) {
		t.Fatal("summary file differs from the public JSON printed to stdout")
	}
	var decoded ownerSignerGrantSummary
	if err := json.Unmarshal(fileBytes, &decoded); err != nil || !reflect.DeepEqual(decoded, summary) {
		t.Fatal("summary file does not contain the expected public-only v1 fields")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatal("public grant summary must be mode 0644 on Unix")
		}
	}
	before := append([]byte(nil), fileBytes...)
	stdout.Reset()
	if err := writeOwnerSignerGrantSummary(&stdout, path, summary); err == nil {
		t.Fatal("existing summary output was overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || stdout.Len() != 0 {
		t.Fatal("failed summary retry changed output")
	}
}

func TestOwnerSignerGrantSummaryRejectsUnsafeDisplayPath(t *testing.T) {
	owner, _ := syntheticAdapterPublicIdentity(t, 32)
	summary := ownerSignerGrantSummary{
		Format: "cicada.owner-device-grant-summary.v1", State: "GRANT_WRITTEN",
		HubID: "hub_synthetic", OwnerID: "owner_synthetic", OwnerKeyID: owner.ID, OwnerPublic: owner,
		DeviceID: "browser_synthetic", DeviceKeyID: "device_key_synthetic", DeviceFingerprint: strings.Repeat("b", 64),
		Purpose:  e2ee.OwnerDevicePurposeControl,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		GrantFile: "grant\n\x1b[31mforged terminal line",
	}
	var stdout bytes.Buffer
	if err := writeOwnerSignerGrantSummary(&stdout, "", summary); err == nil || stdout.Len() != 0 {
		t.Fatal("unsafe grant path was emitted to the terminal")
	}
}
