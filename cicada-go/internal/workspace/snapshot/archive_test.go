package snapshot

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackInspectAndUnpackAreContentAddressed(t *testing.T) {
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "result.txt"), []byte("ready"), 0o640); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	packed, err := Pack(context.Background(), source, &archive)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "workspace.tar")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := Inspect(archivePath)
	if err != nil || inspected != packed {
		t.Fatalf("inspect=%#v packed=%#v err=%v", inspected, packed, err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	restored, err := UnpackFile(context.Background(), archivePath, target)
	if err != nil || restored != packed {
		t.Fatalf("restore=%#v packed=%#v err=%v", restored, packed, err)
	}
	content, err := os.ReadFile(filepath.Join(target, "nested", "result.txt"))
	if err != nil || string(content) != "ready" {
		t.Fatalf("restored content=%q err=%v", content, err)
	}
}

func TestUnpackPreservesExistingTargetOldSibling(t *testing.T) {
	root := t.TempDir()
	archivePath := writeSnapshotArchive(t, root, "new snapshot")
	target := filepath.Join(root, "workspace")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "original.txt"), []byte("original target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target+".old", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target+".old", "sentinel.txt"), []byte("keep existing sibling"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := UnpackFile(context.Background(), archivePath, target); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(target, "snapshot.txt"))
	if err != nil || string(content) != "new snapshot" {
		t.Fatalf("restored target content=%q err=%v", content, err)
	}
	sentinel, err := os.ReadFile(filepath.Join(target+".old", "sentinel.txt"))
	if err != nil || string(sentinel) != "keep existing sibling" {
		t.Fatalf("preexisting target.old sentinel=%q err=%v", sentinel, err)
	}
}

func TestUnpackRestoresOriginalTargetWhenReplacementFails(t *testing.T) {
	root := t.TempDir()
	archivePath := writeSnapshotArchive(t, root, "new snapshot")
	target := filepath.Join(root, "workspace")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "original.txt"), []byte("original target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target+".old", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target+".old", "sentinel.txt"), []byte("keep existing sibling"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaceFailed := false
	rename := func(old, new string) error {
		if new == target && old != target && !replaceFailed {
			replaceFailed = true
			return errors.New("synthetic replacement failure")
		}
		return os.Rename(old, new)
	}
	if _, err := unpackFile(context.Background(), archivePath, target, rename); err == nil || !strings.Contains(err.Error(), "synthetic replacement failure") {
		t.Fatalf("restore error=%v, want injected replacement error", err)
	}
	if !replaceFailed {
		t.Fatal("replacement failure was not injected")
	}
	content, err := os.ReadFile(filepath.Join(target, "original.txt"))
	if err != nil || string(content) != "original target" {
		t.Fatalf("original target was not restored: content=%q err=%v", content, err)
	}
	sentinel, err := os.ReadFile(filepath.Join(target+".old", "sentinel.txt"))
	if err != nil || string(sentinel) != "keep existing sibling" {
		t.Fatalf("preexisting target.old sentinel=%q err=%v", sentinel, err)
	}
	backups, err := filepath.Glob(filepath.Join(root, ".cicada-snapshot-backup-*"))
	if err != nil || len(backups) != 0 {
		t.Fatalf("owned backup not cleaned after successful rollback: backups=%v err=%v", backups, err)
	}
}

func writeSnapshotArchive(t *testing.T, root, content string) string {
	t.Helper()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "snapshot.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := Pack(context.Background(), source, &archive); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "snapshot.tar")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func TestSnapshotRejectsSymlinksAndTraversal(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(context.Background(), root, io.Discard); err == nil {
		t.Fatal("expected symlink rejection")
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unsafe.tar")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("unexpected traversal result: %v", err)
	}
}
