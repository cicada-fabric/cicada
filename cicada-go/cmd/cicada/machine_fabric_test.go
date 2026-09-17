package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestMachineFabricDeliveryUsesExactCodexThread(t *testing.T) {
	root := t.TempDir()
	arguments := filepath.Join(root, "arguments")
	binary := filepath.Join(root, "codex")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + arguments + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", binary)
	delivery := control.MachineFabricDelivery{
		MessageID: "msg_test", RequestID: "rq_test", Kind: "ask",
		EndpointID: "ep_test", Harness: "codex", NativeSessionID: "thread-exact",
		Prompt: "Cicada request rq_test",
	}
	if deliveryError := executeMachineFabricDelivery(context.Background(), delivery); deliveryError != "" {
		t.Fatalf("delivery failed: %s", deliveryError)
	}
	data, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, expected := range []string{"queue\n", "--thread\n", "thread-exact\n", "--message\n", "Cicada request rq_test\n"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("missing %q in argv %q", expected, got)
		}
	}
}

func TestMachineFabricDeliveryRejectsUnsupportedHarness(t *testing.T) {
	deliveryError := executeMachineFabricDelivery(context.Background(), control.MachineFabricDelivery{
		Harness: "claude-code", NativeSessionID: "session", Prompt: "hello",
	})
	if !strings.Contains(deliveryError, "not available") {
		t.Fatalf("unexpected error: %q", deliveryError)
	}
}
