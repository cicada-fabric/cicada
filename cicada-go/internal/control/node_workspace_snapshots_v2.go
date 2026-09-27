package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

var (
	ErrNodeWorkspaceSnapshotInvalidArchive = errors.New("invalid workspace snapshot archive")
	ErrNodeWorkspaceSnapshotDigestMismatch = errors.New("workspace snapshot digest mismatch")
)

// ReceiveBoundNodeWorkspaceSnapshot accepts a streamed archive for one
// currently running Node Worker attempt. It checks authorization before disk
// ingestion, verifies the caller's expected digest against the archive, then
// repeats the complete authorization guard in the transaction that publishes
// the Workspace pointer.
func (c *Control) ReceiveBoundNodeWorkspaceSnapshot(ctx context.Context, credentialDigest, nodeID, workerID string, attempt int, workspaceID, expectedDigest string, input io.Reader) (snapshot.Snapshot, error) {
	expectedDigest = strings.TrimSpace(expectedDigest)
	if !isWorkspaceSnapshotDigest(expectedDigest) {
		return snapshot.Snapshot{}, ErrNodeWorkspaceSnapshotDigestMismatch
	}
	previousDigest, err := c.store.CheckBoundNodeWorkerWorkspaceSnapshot(
		credentialDigest, nodeID, workerID, attempt, workspaceID)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	result, err := c.snapshotStore.Put(ctx, input)
	if err != nil {
		var pathErr *os.PathError
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &pathErr) || errors.As(err, &maxBytesErr) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return snapshot.Snapshot{}, err
		}
		return snapshot.Snapshot{}, fmt.Errorf("%w: %v", ErrNodeWorkspaceSnapshotInvalidArchive, err)
	}
	if result.Digest != expectedDigest {
		return snapshot.Snapshot{}, ErrNodeWorkspaceSnapshotDigestMismatch
	}
	workspace, err := c.store.AttachBoundNodeWorkerWorkspaceSnapshot(
		credentialDigest, nodeID, workerID, attempt, workspaceID, previousDigest, result.Digest)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	c.recordWorkspaceSnapshot(workspace, result)
	return result, nil
}

// OpenBoundNodeWorkspaceSnapshot opens only the current CAS object attached to
// this Workspace, and only for its live Node, running Worker attempt and
// exact workspace relation.
func (c *Control) OpenBoundNodeWorkspaceSnapshot(credentialDigest, nodeID, workerID string, attempt int, workspaceID, digest string) (*os.File, snapshot.Snapshot, error) {
	digest = strings.TrimSpace(digest)
	if !isWorkspaceSnapshotDigest(digest) {
		return nil, snapshot.Snapshot{}, os.ErrNotExist
	}
	workspace, err := c.store.GetBoundNodeWorkerWorkspaceSnapshot(
		credentialDigest, nodeID, workerID, attempt, workspaceID, digest)
	if err != nil {
		return nil, snapshot.Snapshot{}, err
	}
	return c.snapshotStore.Open(workspace.SnapshotDigest)
}

func isWorkspaceSnapshotDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
