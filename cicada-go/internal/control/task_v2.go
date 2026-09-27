package control

import (
	"errors"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// Control owns Task creation and graph topology as manager. The same durable
// Task rows are then claimed and updated by authorized Fabric members.
func (c *Control) CreateSharedTask(groupID string, input store.SharedTask) (*store.SharedTask, error) {
	group, err := c.store.GetGroup(groupID)
	if err != nil {
		return nil, err
	}
	if group.State != store.GroupStateActive {
		return nil, errors.New("group is not active")
	}
	if input.GroupID != "" && input.GroupID != groupID {
		return nil, errors.New("task group does not match route")
	}
	input.GroupID = groupID
	input.ID = "" // caller cannot replace an existing record through create
	return c.store.CreateSharedTask(input)
}

func (c *Control) SharedTasks(groupID string, limit int) ([]store.SharedTask, error) {
	if _, err := c.store.GetGroup(groupID); err != nil {
		return nil, err
	}
	return c.store.ListSharedTasks(groupID, limit)
}

func (c *Control) AddSharedTaskDependency(groupID, taskID, dependsOnID string, revision int64) (*store.SharedTask, error) {
	if strings.TrimSpace(dependsOnID) == "" {
		return nil, store.ErrSharedTaskDependency
	}
	task, err := c.store.GetSharedTask(taskID)
	if err != nil {
		return nil, err
	}
	if task.GroupID != groupID {
		return nil, store.ErrSharedTaskNotFound
	}
	return c.store.AddSharedTaskDependency(taskID, dependsOnID, revision, c.Identity().ID)
}

func (c *Control) ReadySharedTask(groupID, taskID string, revision int64) (*store.SharedTask, error) {
	task, err := c.store.GetSharedTask(taskID)
	if err != nil {
		return nil, err
	}
	if task.GroupID != groupID {
		return nil, store.ErrSharedTaskNotFound
	}
	return c.store.ReadySharedTask(taskID, revision, c.Identity().ID)
}

func (c *Control) ReconcileExpiredSharedTask(groupID, taskID string, revision int64) (*store.SharedTask, error) {
	task, err := c.store.GetSharedTask(taskID)
	if err != nil {
		return nil, err
	}
	if task.GroupID != groupID {
		return nil, store.ErrSharedTaskNotFound
	}
	return c.store.ReconcileExpiredSharedTaskClaim(taskID, revision, c.Identity().ID)
}
