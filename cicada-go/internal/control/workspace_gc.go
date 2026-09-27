package control

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

// SnapshotGCResult is the operator-visible result of one CAS collection pass.
type SnapshotGCResult struct {
	Scanned      int    `json:"scanned"`
	Retained     int    `json:"retained"`
	Removed      int    `json:"removed"`
	RemovedBytes int64  `json:"removed_bytes"`
	KeepFor      string `json:"keep_for"`
}

// CollectWorkspaceSnapshots removes only old CAS objects with no durable
// workspace or snapshot-artifact reference. A crash between archive upload
// and database commit is therefore recoverable within the grace period.
func (c *Control) CollectWorkspaceSnapshots(ctx context.Context) (SnapshotGCResult, error) {
	if c == nil || c.snapshotStore == nil || c.store == nil {
		return SnapshotGCResult{}, errors.New("snapshot collection is not initialized")
	}
	referenced, err := c.store.WorkspaceSnapshotDigests()
	if err != nil {
		return SnapshotGCResult{}, err
	}
	keepFor := c.config.SnapshotGCKeepFor
	if keepFor <= 0 {
		keepFor = 24 * time.Hour
	}
	collected, err := c.snapshotStore.Collect(ctx, referenced, time.Now().UTC().Add(-keepFor))
	if err != nil {
		return SnapshotGCResult{}, err
	}
	result := SnapshotGCResult{
		Scanned: collected.Scanned, Retained: collected.Retained,
		Removed: collected.Removed, RemovedBytes: collected.RemovedBytes,
		KeepFor: keepFor.String(),
	}
	return result, nil
}

func (c *Control) snapshotGCLoop() {
	interval := c.config.SnapshotGCInterval
	if interval < 0 {
		return
	}
	if interval == 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _ = c.CollectWorkspaceSnapshots(context.Background())
		case <-c.shutdown:
			return
		}
	}
}

// OpenSnapshotByDigest is used by an authenticated Control-to-Control
// replication client. The caller must already have passed the HTTP API bearer
// boundary; the CAS still validates the digest and archive before streaming.
func (c *Control) OpenSnapshotByDigest(digest string) (*os.File, snapshot.Snapshot, error) {
	return c.snapshotStore.Open(strings.TrimSpace(digest))
}

// ReceiveReplicatedSnapshot stores an archive received from another Control,
// verifies that it has the requested digest, and optionally attaches it to a
// local Workspace with the same stable path. It does not trust the source's
// metadata or overwrite a different workspace.
func (c *Control) ReceiveReplicatedSnapshot(digest string, input io.Reader, workspacePath string) (snapshot.Snapshot, *store.Workspace, error) {
	digest = strings.TrimSpace(digest)
	if digest == "" {
		return snapshot.Snapshot{}, nil, errors.New("snapshot digest is required")
	}
	result, err := c.snapshotStore.Put(context.Background(), input)
	if err != nil {
		return snapshot.Snapshot{}, nil, err
	}
	if result.Digest != digest {
		return snapshot.Snapshot{}, nil, errors.New("replicated snapshot digest does not match the requested digest")
	}
	workspacePath = strings.TrimSpace(workspacePath)
	if workspacePath == "" {
		return result, nil, nil
	}
	workspaces, err := c.store.ListWorkspaces("")
	if err != nil {
		return snapshot.Snapshot{}, nil, err
	}
	for _, workspace := range workspaces {
		if workspace.Path != workspacePath {
			continue
		}
		updated, updateErr := c.store.UpdateWorkspaceSnapshot(workspace.ID, result.Digest)
		if updateErr != nil {
			return snapshot.Snapshot{}, nil, updateErr
		}
		if updated == nil {
			return snapshot.Snapshot{}, nil, os.ErrNotExist
		}
		c.recordWorkspaceSnapshot(updated, result)
		return result, updated, nil
	}
	return result, nil, nil
}
