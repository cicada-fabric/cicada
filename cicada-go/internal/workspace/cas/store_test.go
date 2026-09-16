package cas

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreDeduplicatesAndOpensValidatedArchives(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "answer.txt"), []byte("42"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.PutPath(context.Background(), workspace)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.PutPath(context.Background(), workspace)
	if err != nil || first != second {
		t.Fatalf("deduplication failed: first=%#v second=%#v err=%v", first, second, err)
	}
	file, opened, err := store.Open(first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if opened != first {
		t.Fatalf("opened metadata=%#v first=%#v", opened, first)
	}
	if _, err := store.Put(context.Background(), bytes.NewReader([]byte("not a tar"))); err == nil {
		t.Fatal("expected invalid archive rejection")
	}
}

func TestObjectPathRejectsUntrustedDigest(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"", "../escape", "abcd", "zz" + string(make([]byte, 62))} {
		if _, _, err := store.Open(digest); err == nil {
			t.Fatalf("digest %q was accepted", digest)
		}
	}
}
