package control

import (
	"encoding/json"

	"github.com/cicada-ai/cicada/internal/store"
)

// CreateBoundNodeWorkerApproval persists a remote Codex approval and exposes
// only its non-sensitive lifecycle metadata in the event and notification
// streams. The source request remains available through the encrypted Client
// approval RPC.
func (c *Control) CreateBoundNodeWorkerApproval(credentialDigest, nodeID, workerID string,
	attempt int, requestID, method string, request json.RawMessage) (*store.Approval, bool, error) {
	approval, created, err := c.store.CreateBoundNodeApproval(credentialDigest, nodeID,
		workerID, attempt, requestID, method, request)
	if err != nil || !created {
		return approval, created, err
	}
	_, _ = c.store.AppendEvent(approval.GoalID, approval.WorkerID, "ApprovalRequested", map[string]any{
		"approval_id": approval.ID, "method": approval.Method, "attempt": approval.Attempt,
	})
	c.notify(approval.GoalID, "approval.requested", "P1", "Approval required",
		"Codex is waiting for a human decision for "+approval.Method+" (approval "+approval.ID+").")
	return approval, true, nil
}

func (c *Control) BoundNodeWorkerApproval(credentialDigest, nodeID, workerID string,
	attempt int, approvalID string) (*store.Approval, error) {
	return c.store.GetBoundNodeApproval(credentialDigest, nodeID, workerID, attempt, approvalID)
}
