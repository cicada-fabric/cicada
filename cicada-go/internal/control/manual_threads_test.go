package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualThreadQueueUsesOfficialCodexCommand(t *testing.T) {
	root := t.TempDir()
	argsFile := filepath.Join(root, "codex-args")
	codex := filepath.Join(root, "fake-codex")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shellQuote(argsFile) + "\n"
	if err := os.WriteFile(codex, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		CodexBinary: codex,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	for _, name := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(root, "workspace", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := controlPlane.RegisterThreadSession(ThreadSessionInput{
		ThreadID: "11111111-1111-4111-8111-111111111111", Label: "A", Workspace: filepath.Join(root, "workspace", "a"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.RegisterThreadSession(ThreadSessionInput{
		ThreadID: "22222222-2222-4222-8222-222222222222", Label: "B", Workspace: filepath.Join(root, "workspace", "b"),
	}); err != nil {
		t.Fatal(err)
	}
	delivery, err := controlPlane.QueueThreadSessionMessage(ThreadQueueInput{
		FromThreadID: "11111111-1111-4111-8111-111111111111",
		ToThreadID:   "22222222-2222-4222-8222-222222222222",
		Message:      "compare the two results",
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Status != "delivered" || delivery.DeliveredAt == "" {
		t.Fatalf("unexpected delivery: %#v", delivery)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	output := string(args)
	for _, expected := range []string{"queue", "--thread", "22222222-2222-4222-8222-222222222222", "--message", "compare the two results"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("codex queue argument %q missing from %q", expected, output)
		}
	}
	deliveries, err := controlPlane.ThreadDeliveries(10)
	if err != nil || len(deliveries) != 1 || deliveries[0].ID != delivery.ID {
		t.Fatalf("delivery was not durable: %#v err=%v", deliveries, err)
	}
}

func TestManualThreadQueueRejectsUnregisteredThread(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	_, err = controlPlane.QueueThreadSessionMessage(ThreadQueueInput{
		FromThreadID: "11111111-1111-4111-8111-111111111111",
		ToThreadID:   "22222222-2222-4222-8222-222222222222",
		Message:      "hello",
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected unregistered thread error, got %v", err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
