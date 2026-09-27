package control

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
	workspaceprep "github.com/cicada-ai/cicada/internal/workspace"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

// SnapshotWorkspace stores an immutable content-addressed copy of a local
// workspace. The digest is persisted separately from the source revision so a
// later Worker can resume modified files on another Machine.
func (c *Control) SnapshotWorkspace(id string) (snapshot.Snapshot, error) {
	workspace, err := c.store.GetWorkspace(strings.TrimSpace(id))
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if workspace == nil {
		return snapshot.Snapshot{}, os.ErrNotExist
	}
	if _, err := c.CheckPermission("workspace", workspace.ID, "workspace.snapshot", ""); err != nil {
		return snapshot.Snapshot{}, err
	}
	path, err := workspaceprep.ResolveWithin(c.config.WorkspaceRoot, workspace.Path)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	result, err := c.snapshotStore.PutPath(context.Background(), path)
	if err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("snapshot workspace: %w", err)
	}
	if _, err := c.store.UpdateWorkspaceSnapshot(workspace.ID, result.Digest); err != nil {
		return snapshot.Snapshot{}, err
	}
	c.recordWorkspaceSnapshot(workspace, result)
	return result, nil
}

// ReceiveWorkspaceSnapshot validates and stores a snapshot uploaded by a
// remote Machine. The HTTP boundary authenticates the caller before this is
// reached; the digest and archive are still checked independently.
func (c *Control) ReceiveWorkspaceSnapshot(id string, input io.Reader) (snapshot.Snapshot, error) {
	workspace, err := c.store.GetWorkspace(strings.TrimSpace(id))
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if workspace == nil {
		return snapshot.Snapshot{}, os.ErrNotExist
	}
	if _, err := c.CheckPermission("workspace", workspace.ID, "workspace.snapshot", ""); err != nil {
		return snapshot.Snapshot{}, err
	}
	result, err := c.snapshotStore.Put(context.Background(), input)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if _, err := c.store.UpdateWorkspaceSnapshot(workspace.ID, result.Digest); err != nil {
		return snapshot.Snapshot{}, err
	}
	c.recordWorkspaceSnapshot(workspace, result)
	return result, nil
}

func (c *Control) OpenWorkspaceSnapshot(id, digest string) (*os.File, snapshot.Snapshot, error) {
	workspace, err := c.store.GetWorkspace(strings.TrimSpace(id))
	if err != nil {
		return nil, snapshot.Snapshot{}, err
	}
	if workspace == nil {
		return nil, snapshot.Snapshot{}, os.ErrNotExist
	}
	if workspace.SnapshotDigest == "" || workspace.SnapshotDigest != strings.TrimSpace(digest) {
		return nil, snapshot.Snapshot{}, os.ErrNotExist
	}
	if _, err := c.CheckPermission("workspace", workspace.ID, "workspace.snapshot", ""); err != nil {
		return nil, snapshot.Snapshot{}, err
	}
	return c.snapshotStore.Open(workspace.SnapshotDigest)
}

func (c *Control) recordWorkspaceSnapshot(workspace *store.Workspace, result snapshot.Snapshot) {
	_, _ = c.store.AppendEvent(workspace.GoalID, "", "WorkspaceSnapshotStored", map[string]any{
		"workspace_id": workspace.ID, "digest": result.Digest,
		"size": result.Size, "file_count": result.FileCount,
	})
	_, _ = c.store.CreateArtifact(store.Artifact{
		GoalID: workspace.GoalID, WorkspaceID: workspace.ID,
		Name: "workspace-snapshot-" + result.Digest[:12], Path: "snapshot:" + result.Digest,
		Kind: "workspace-snapshot", Digest: result.Digest,
		Evidence: fmt.Sprintf("%d bytes, %d files", result.Size, result.FileCount),
	})
}

func (c *Control) recordWorkspaceSnapshotDigest(goalID, path, digest string) {
	file, _, err := c.snapshotStore.Open(strings.TrimSpace(digest))
	if err != nil {
		return
	}
	_ = file.Close()
	workspaces, err := c.store.ListWorkspaces(goalID)
	if err != nil {
		return
	}
	for _, workspace := range workspaces {
		if workspace.Path == path {
			_, _ = c.store.UpdateWorkspaceSnapshot(workspace.ID, digest)
			return
		}
	}
}
