package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/server"
)

func TestMachineSnapshotRoundTripThroughControl(t *testing.T) {
	root := t.TempDir()
	workspacePath := filepath.Join(root, "workspace", "worker")
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	workspace, err := controlPlane.CreateWorkspace(control.WorkspaceInput{Path: workspacePath, Source: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspacePath, "answer.txt"), []byte("snapshot-ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(server.NewHandler(controlPlane))
	defer api.Close()
	job := machineJob{WorkspaceID: workspace.ID, Workspace: workspacePath}
	digest, err := uploadMachineSnapshot(context.Background(), api.URL, job, workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("snapshot upload returned an empty digest")
	}
	if err := os.Remove(filepath.Join(workspacePath, "answer.txt")); err != nil {
		t.Fatal(err)
	}
	job.WorkspaceSnapshotDigest = digest
	if err := downloadMachineSnapshot(context.Background(), api.URL, job, workspacePath); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(workspacePath, "answer.txt"))
	if err != nil || string(content) != "snapshot-ready" {
		t.Fatalf("restored snapshot content=%q err=%v", content, err)
	}
}

func TestMachineAgentPersistsSnapshotForRecovery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_WORKSPACE_ROOT", filepath.Join(root, "workspace"))
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	if _, err := controlPlane.RegisterMachine("agent-snapshot", "Agent snapshot", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	workspace, err := controlPlane.CreateWorkspace(control.WorkspaceInput{Path: filepath.Join(root, "workspace", "worker"), Source: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(server.NewHandler(controlPlane))
	defer api.Close()
	job := machineJob{
		MachineID: "agent-snapshot", WorkspaceID: workspace.ID, Workspace: workspace.Path,
		Harness: "shell", Resources: map[string]any{"argv": []any{"/bin/sh", "-c", "printf recovered > recovered.txt"}},
	}
	result := executeMachineJobWithHeartbeats(context.Background(), api.URL, job.MachineID, time.Second, job)
	if result.Status != "completed" || result.WorkspaceSnapshotDigest == "" {
		t.Fatalf("agent did not upload completed snapshot: %#v", result)
	}
	if err := os.Remove(filepath.Join(workspace.Path, "recovered.txt")); err != nil {
		t.Fatal(err)
	}
	job.WorkspaceSnapshotDigest = result.WorkspaceSnapshotDigest
	job.Resources = map[string]any{"argv": []any{"/bin/true"}}
	result = executeMachineJobWithHeartbeats(context.Background(), api.URL, job.MachineID, time.Second, job)
	if result.Status != "completed" {
		t.Fatalf("agent did not resume from snapshot: %#v", result)
	}
	content, err := os.ReadFile(filepath.Join(workspace.Path, "recovered.txt"))
	if err != nil || string(content) != "recovered" {
		t.Fatalf("snapshot file was not restored: %q err=%v", content, err)
	}
}
