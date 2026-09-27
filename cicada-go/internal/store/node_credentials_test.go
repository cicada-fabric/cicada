package store

import (
	"path/filepath"
	"testing"
)

func TestNodeCredentialRotationKeepsOnlyDigestAndInvalidatesOldCredential(t *testing.T) {
	persistence, err := New(filepath.Join(t.TempDir(), "node-credentials.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	first, err := persistence.RotateNodeCredential("node-a", "digest-one")
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || first.CredentialHash != "digest-one" {
		t.Fatalf("unexpected initial credential: %#v", first)
	}
	second, err := persistence.RotateNodeCredential("node-a", "digest-two")
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 || second.CredentialHash != "digest-two" {
		t.Fatalf("unexpected rotated credential: %#v", second)
	}
	if _, err := persistence.GetNodeCredentialByHash("digest-one"); err != ErrNodeCredentialNotFound {
		t.Fatalf("old node credential remained valid: %v", err)
	}
	resolved, err := persistence.GetNodeCredentialByHash("digest-two")
	if err != nil || resolved.NodeID != "node-a" {
		t.Fatalf("rotated credential did not authenticate: %#v err=%v", resolved, err)
	}
}
