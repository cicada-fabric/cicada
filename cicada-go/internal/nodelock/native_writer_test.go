package nodelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeWriterSerializesAcrossHubScopesAndPersistsEpoch(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireNativeWriter(context.Background(), root, "uid:1000", "codex", "synthetic-thread")
	if err != nil {
		t.Fatal(err)
	}
	if first.Epoch != 1 {
		t.Fatalf("first epoch=%d", first.Epoch)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	if _, err := AcquireNativeWriter(ctx, root, "uid:1000", "codex", "synthetic-thread"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same physical Thread had a second writer: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireNativeWriter(context.Background(), root, "uid:1000", "codex", "synthetic-thread")
	if err != nil {
		t.Fatal(err)
	}
	if second.Epoch != 2 {
		t.Fatalf("second epoch=%d", second.Epoch)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".native-writers"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("writer registry contents: %v %v", entries, err)
	}
	for _, entry := range entries {
		if entry.Name() == "synthetic-thread" {
			t.Fatal("native ID leaked into registry filename")
		}
	}
}
