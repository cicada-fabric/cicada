package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoteRecoveryCarriesWorkspaceSnapshotDigest(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		MaxRecoveries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	if _, err := controlPlane.RegisterMachine("remote-snapshot", "Remote snapshot", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "preserve remote files", MachineID: "remote-snapshot", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/bin/true"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-snapshot"); err != nil {
		t.Fatal(err)
	}
	workspace, err := controlPlane.Workspaces(goal.ID)
	if err != nil || len(workspace) != 1 {
		t.Fatalf("workspace lookup failed: %#v err=%v", workspace, err)
	}
	if err := os.WriteFile(filepath.Join(workspace[0].Path, "partial.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := controlPlane.SnapshotWorkspace(workspace[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := controlPlane.CompleteRemoteWorker(goal.Worker.ID, "remote-snapshot", "failed", "partial", "", "worker stopped", "", snapshot.Digest)
	if err != nil || worker.Status != "queued" {
		t.Fatalf("failed remote worker was not requeued: %#v err=%v", worker, err)
	}
	job, err := controlPlane.ClaimRemoteWorker(goal.Worker.ID, "remote-snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if job.WorkspaceSnapshotDigest != snapshot.Digest {
		t.Fatalf("snapshot digest was not carried to recovery job: got=%q want=%q", job.WorkspaceSnapshotDigest, snapshot.Digest)
	}
}
