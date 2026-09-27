package control

import (
	"github.com/cicada-ai/cicada/internal/store"
	workspaceprep "github.com/cicada-ai/cicada/internal/workspace"
)

func (c *Control) checkWorkspaceSourcePermission(goal store.Goal) error {
	source, err := workspaceprep.SourceFromResources(goal.Resources)
	if err != nil || source == nil {
		return err
	}
	_, err = c.CheckPermission("goal", goal.ID, "workspace.clone", source.Hostname())
	return err
}

func (c *Control) recordWorkspacePrepared(goalID, workerID, path, revision string, created bool) {
	workspaces, err := c.store.ListWorkspaces(goalID)
	if err == nil {
		for _, workspace := range workspaces {
			if workspace.Path == path {
				_, _ = c.store.UpdateWorkspace(workspace.ID, "active", revision)
				break
			}
		}
	}
	_, _ = c.store.AppendEvent(goalID, workerID, "WorkspacePrepared", map[string]any{
		"path": path, "revision": revision, "created": created, "source": "git",
	})
}
