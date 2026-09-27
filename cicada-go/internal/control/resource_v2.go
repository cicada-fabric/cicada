package control

import "github.com/cicada-ai/cicada/internal/store"

func (c *Control) AcquireResourceLease(input store.ResourceLeaseRequest) (*store.ResourceLease, error) {
	group, err := c.store.GetGroup(input.GroupID)
	if err != nil {
		return nil, err
	}
	if group.State != store.GroupStateActive {
		return nil, store.ErrGroupNotFound
	}
	return c.store.AcquireResourceLease(input)
}

func (c *Control) ResourceLease(id string) (*store.ResourceLease, error) {
	return c.store.GetResourceLease(id)
}

func (c *Control) ReconcileResourceLease(resourceID string, epoch int64, stoppedConfirmed bool, evidence string) error {
	return c.store.ReconcileResourceLease(resourceID, epoch, stoppedConfirmed, evidence)
}
