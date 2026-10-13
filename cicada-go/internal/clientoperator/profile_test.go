package clientoperator

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func syntheticPins(t *testing.T) (HubIdentity, e2ee.PublicIdentity) {
	t.Helper()
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return HubIdentity{Contract: "android-hub-v1", HubID: "hub-synthetic-operator", Public: hub.Public(), KeyVersion: 1, Suite: Suite}, owner.Public()
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestProfilePinsCustodyAndExclusiveLock(t *testing.T) {
	hub, owner := syntheticPins(t)
	dir := privateTempDir(t)
	p, err := Prepare(dir, "https://hub.synthetic.invalid", "synthetic-owner", hub, owner, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("second profile writer: %v", err)
	}
	manifest := p.Manifest()
	if manifest.DevicePublicIdentity.ID == owner.ID || manifest.DevicePublicIdentity.ID == hub.Public.ID {
		t.Fatal("Client inherited another role's key")
	}
	if _, err = p.WriteManifest(); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest().DeviceID != manifest.DeviceID || p.Manifest().DeviceKeyFingerprint != manifest.DeviceKeyFingerprint {
		t.Fatal("reopen rotated identity")
	}
	p.Close()
	if _, err = Prepare(dir, "https://hub.synthetic.invalid", "synthetic-owner", hub, owner, false); err == nil {
		t.Fatal("overwrote existing profile")
	}
	if err = os.Chmod(filepath.Join(dir, "client.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil {
		t.Fatal("accepted public private key file")
	}
}

func TestProfileRejectsSymlinksAndLooseDirectory(t *testing.T) {
	hub, owner := syntheticPins(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(alias, "https://hub.synthetic.invalid", "synthetic-owner", hub, owner, false); err == nil {
		t.Fatal("accepted profile symlink")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(dir, "https://hub.synthetic.invalid", "synthetic-owner", hub, owner, false); err == nil {
		t.Fatal("accepted loose profile permissions")
	}
}

func TestProfileManifestResumeNeverRekeysOrReplacesDifferentExport(t *testing.T) {
	hub, owner := syntheticPins(t)
	dir := privateTempDir(t)
	p, err := Prepare(dir, "https://hub.synthetic.invalid", "synthetic-owner", hub, owner, false)
	if err != nil {
		t.Fatal(err)
	}
	manifest := p.Manifest()
	p.Close() // crash after identity commit, before export
	p, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	path, err := p.WriteManifest()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.WriteManifest(); err != nil {
		t.Fatal(err)
	}
	if p.Manifest().DeviceKeyFingerprint != manifest.DeviceKeyFingerprint {
		t.Fatal("manifest recovery rekeyed")
	}
	if err = os.WriteFile(path, []byte("partial synthetic export"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = p.WriteManifest(); err == nil {
		t.Fatal("silently replaced mismatched public export")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = p.WriteManifest(); err != nil {
		t.Fatal(err)
	}
}

func TestProfileOriginPolicy(t *testing.T) {
	for _, value := range []string{"http://127.0.0.1", "http://localhost", "http://192.0.2.1", "https://user:secret@hub.synthetic.invalid", "https://hub.synthetic.invalid?secret=x", "https://hub.synthetic.invalid?", "https://hub.synthetic.invalid/#x", "file:///tmp/key", "https://hub.synthetic.invalid/path"} {
		t.Run(value, func(t *testing.T) {
			if _, err := canonicalOrigin(value, false); err == nil {
				t.Fatal("accepted unsafe origin")
			}
		})
	}
	for _, value := range []string{"http://127.0.0.1:1234", "http://[::1]:1234"} {
		if _, err := canonicalOrigin(value, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := canonicalOrigin("http://localhost:1234", true); err == nil {
		t.Fatal("accepted DNS loopback HTTP")
	}
}
