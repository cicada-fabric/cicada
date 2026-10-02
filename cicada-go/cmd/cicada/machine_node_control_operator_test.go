package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMachineNodeControlOperatorRejectsSelectedNodeQuarantineWithAlternateWriterRoot(t *testing.T) {
	for _, hold := range []string{"node", "registration", "writer-root"} {
		t.Run(hold, func(t *testing.T) {
			state, writer := t.TempDir(), t.TempDir()
			path := filepath.Join(machineNodeStateDir(state, "synthetic-operator"), "recovery-pending.json")
			if hold == "registration" {
				path = filepath.Join(state, "nodes", ".recovery-pending", "node-synthetic-operator.json")
			}
			if hold == "writer-root" {
				path = filepath.Join(writer, ".writer-root-recovery-pending.json")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("synthetic malformed hold"), 0400); err != nil {
				t.Fatal(err)
			}
			before, _ := recoveryTreeDigest(state)
			writerBefore, _ := recoveryTreeDigest(writer)
			for _, action := range []string{"inspect", "mark-uncertain", "reconcile-provider"} {
				var output bytes.Buffer
				err := machineNodeControlOperatorCommand([]string{action, "--state-dir", state, "--writer-root", writer, "--node-id", "synthetic-operator"}, &output)
				if err == nil || !strings.Contains(err.Error(), "quarantine") || output.Len() != 0 {
					t.Fatalf("operator reached writable open: %v", err)
				}
			}
			after, _ := recoveryTreeDigest(state)
			writerAfter, _ := recoveryTreeDigest(writer)
			if before != after || writerBefore != writerAfter {
				t.Fatal("rejected operator prepared paths or changed recovery state")
			}
		})
	}
}
