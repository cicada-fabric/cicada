package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func newBoundSnapshotControlJob(t *testing.T) (*Control, string, *store.NodeDeviceBinding, string, MachineJob) {
	t.Helper()
	c, ownerID, _ := newNodeBindingControl(t)
	nodeToken, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "snapshot-node"
	challenge, err := c.StartNodeDeviceBinding(nodeID, "Snapshot Node", credentialDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.ConfirmNodeDeviceCode(ownerID, "android", challenge.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.RecordBoundNodeMachineHeartbeat(credentialDigest, "available",
		map[string]any{"harnesses": []string{"codex"}}); err != nil {
		t.Fatal(err)
	}
	goal, err := c.CreateGoalForOwner(ownerID, GoalInput{
		Objective: "preserve a remote workspace", MachineID: nodeID, Harness: "codex",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, attempt := "running", 1
	worker, err := c.store.UpdateWorker(goal.Worker.ID, store.WorkerUpdate{Status: &status, Attempt: &attempt})
	if err != nil {
		t.Fatal(err)
	}
	job := c.machineJob(*goal, *worker, nil)
	if job.Attempt != 1 || job.WorkspaceID == "" {
		t.Fatalf("claimed job lacks attempt/workspace binding: %+v", job)
	}
	if nodeToken == "" {
		t.Fatal("fixture Node token was empty")
	}
	return c, ownerID, binding, credentialDigest, job
}

func makeControlSnapshotArchive(t *testing.T, content string) ([]byte, snapshot.Snapshot) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "result.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	metadata, err := snapshot.Pack(context.Background(), root, &archive)
	if err != nil {
		t.Fatal(err)
	}
	return archive.Bytes(), metadata
}

func TestBoundNodeWorkspaceSnapshotStreamsAndAttachesOnlyExpectedDigest(t *testing.T) {
	c, _, _, credentialDigest, job := newBoundSnapshotControlJob(t)
	archive, expected := makeControlSnapshotArchive(t, "workspace result")
	stored, err := c.ReceiveBoundNodeWorkspaceSnapshot(context.Background(), credentialDigest,
		job.MachineID, job.WorkerID, job.Attempt, job.WorkspaceID, expected.Digest, bytes.NewReader(archive))
	if err != nil || stored.Digest != expected.Digest || stored.Size != expected.Size {
		t.Fatalf("snapshot upload failed: %#v err=%v", stored, err)
	}
	file, downloaded, err := c.OpenBoundNodeWorkspaceSnapshot(credentialDigest,
		job.MachineID, job.WorkerID, job.Attempt, job.WorkspaceID, expected.Digest)
	if err != nil {
		t.Fatalf("open current snapshot: %v", err)
	}
	defer file.Close()
	if downloaded.Digest != expected.Digest {
		t.Fatalf("download returned a different current digest: %#v", downloaded)
	}
	actual, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(actual, archive) {
		t.Fatalf("download bytes differ: equal=%v err=%v", bytes.Equal(actual, archive), err)
	}
	if _, _, err := c.OpenBoundNodeWorkspaceSnapshot(credentialDigest,
		job.MachineID, job.WorkerID, job.Attempt, job.WorkspaceID, "0000000000000000000000000000000000000000000000000000000000000000"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-current digest was opened: %v", err)
	}
}

type gatedSnapshotReader struct {
	data    []byte
	sent    bool
	blocked chan struct{}
	resume  chan struct{}
}

func (r *gatedSnapshotReader) Read(buffer []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(buffer, r.data), nil
	}
	select {
	case <-r.blocked:
	default:
		close(r.blocked)
	}
	<-r.resume
	return 0, io.EOF
}

func TestBoundNodeWorkspaceSnapshotRevocationDuringStreamCannotPublish(t *testing.T) {
	c, ownerID, binding, credentialDigest, job := newBoundSnapshotControlJob(t)
	archive, expected := makeControlSnapshotArchive(t, "revocation result")
	reader := &gatedSnapshotReader{data: archive, blocked: make(chan struct{}), resume: make(chan struct{})}
	type uploadResult struct {
		metadata snapshot.Snapshot
		err      error
	}
	done := make(chan uploadResult, 1)
	go func() {
		metadata, err := c.ReceiveBoundNodeWorkspaceSnapshot(context.Background(), credentialDigest,
			job.MachineID, job.WorkerID, job.Attempt, job.WorkspaceID, expected.Digest, reader)
		done <- uploadResult{metadata: metadata, err: err}
	}()
	<-reader.blocked
	if _, err := c.RevokeNodeDeviceBinding(ownerID, binding.ID, binding.Version); err != nil {
		t.Fatal(err)
	}
	close(reader.resume)
	result := <-done
	if !errors.Is(result.err, store.ErrNodeWorkerNotAuthorized) {
		t.Fatalf("revoked Node upload unexpectedly succeeded: metadata=%#v err=%v", result.metadata, result.err)
	}
	workspaces, err := c.Workspaces(job.GoalID)
	if err != nil || len(workspaces) != 1 || workspaces[0].SnapshotDigest != "" {
		t.Fatalf("revoked upload published Workspace pointer: %#v err=%v", workspaces, err)
	}
	if file, object, err := c.snapshotStore.Open(expected.Digest); err != nil {
		t.Fatalf("test did not exercise post-ingest authorization: %v", err)
	} else {
		_ = file.Close()
		if object.Digest != expected.Digest {
			t.Fatalf("orphaned CAS object has wrong digest: %#v", object)
		}
	}
}

func TestConcurrentDifferentBoundNodeSnapshotUploadsCannotOverwrite(t *testing.T) {
	c, _, _, credentialDigest, job := newBoundSnapshotControlJob(t)
	firstArchive, firstMetadata := makeControlSnapshotArchive(t, "first result")
	secondArchive, secondMetadata := makeControlSnapshotArchive(t, "second result")
	firstReader := &gatedSnapshotReader{data: firstArchive, blocked: make(chan struct{}), resume: make(chan struct{})}
	secondReader := &gatedSnapshotReader{data: secondArchive, blocked: make(chan struct{}), resume: make(chan struct{})}
	type result struct {
		digest string
		err    error
	}
	results := make(chan result, 2)
	for _, upload := range []struct {
		reader   *gatedSnapshotReader
		metadata snapshot.Snapshot
	}{{firstReader, firstMetadata}, {secondReader, secondMetadata}} {
		upload := upload
		go func() {
			stored, err := c.ReceiveBoundNodeWorkspaceSnapshot(context.Background(), credentialDigest,
				job.MachineID, job.WorkerID, job.Attempt, job.WorkspaceID, upload.metadata.Digest, upload.reader)
			results <- result{digest: stored.Digest, err: err}
		}()
	}
	<-firstReader.blocked
	<-secondReader.blocked
	close(firstReader.resume)
	close(secondReader.resume)
	one, two := <-results, <-results
	successes := 0
	winningDigest := ""
	for _, item := range []result{one, two} {
		if item.err == nil {
			successes++
			winningDigest = item.digest
		} else if !errors.Is(item.err, store.ErrNodeWorkerUnavailable) {
			t.Fatalf("divergent concurrent upload failed unexpectedly: %v", item.err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected one divergent concurrent upload to win, got %d results: %#v %#v", successes, one, two)
	}
	if winningDigest != firstMetadata.Digest && winningDigest != secondMetadata.Digest {
		t.Fatalf("winner returned unexpected digest %q", winningDigest)
	}
	workspaces, err := c.Workspaces(job.GoalID)
	if err != nil || len(workspaces) != 1 || workspaces[0].SnapshotDigest != winningDigest {
		t.Fatalf("Workspace pointer diverged from the one successful upload: %#v err=%v", workspaces, err)
	}
}
