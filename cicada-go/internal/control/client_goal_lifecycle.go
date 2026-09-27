package control

import (
	"github.com/cicada-ai/cicada/internal/store"
)

// ChangeClientGoalLifecycle changes only queued, owner-attributed remote work.
// It deliberately rejects running work: a UI pause cannot stop a native
// runtime or prove that its side effects have ceased.
func (c *Control) ChangeClientGoalLifecycle(ownerID, deviceID, requestID, goalID, action string, expectedVersion int64) (*store.Goal, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.store.ChangeOwnedQueuedGoalLifecycle(ownerID, deviceID, requestID, goalID, action, expectedVersion)
}
