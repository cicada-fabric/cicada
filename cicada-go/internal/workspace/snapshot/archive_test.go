package snapshot

import (
	"archive/tar"
	"bytes"
	"context"
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
