package nodelock

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectResourceExecutionExistingReadOnly(t *testing.T) {
	root := t.TempDir()
	if record, err := InspectResourceExecutionExisting(root, "gpu/0"); err != nil || record != nil {
		t.Fatal("missing read-only record", err)
	}
	if _, err := os.Stat(filepath.Join(root, "nodes")); !os.IsNotExist(err) {
		t.Fatal("inspection initialized locks")
	}
	manager, err := OpenResourceExecutionManager(root)
	if err != nil {
		t.Fatal(err)
	}
	request := ResourceExecutionRequest{ResourceID: "gpu/0", LeaseID: "synthetic-lease", FencingEpoch: 1, ExecutionID: "synthetic-execution"}
	execution, err := manager.Begin(request)
	if err != nil {
		t.Fatal(err)
	}
	defer execution.Close()
	_, path, err := resourceExecutionPaths(root, request.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := InspectResourceExecutionExisting(root, request.ResourceID)
	if err != nil || record == nil || record.ExecutionID != request.ExecutionID || record.LeaseID != request.LeaseID || record.State != ResourceExecutionStarting {
		t.Fatal("original execution missing", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("readonly inspection changed execution artifact", err)
	}
	if other, err := InspectResourceExecutionExisting(root, "gpu/1"); err != nil || other != nil {
		t.Fatal("unrelated resource borrowed execution", err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = InspectResourceExecutionExisting(root, request.ResourceID); err == nil {
		t.Fatal("unsafe marker accepted")
	}
}
