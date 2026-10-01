package control

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

type boundNodeResultFence struct {
	credentialDigest string
	nodeID           string
	nodeControlRPC   *store.NodeControlRPCInput
}

// CompleteRemoteWorker persists a result returned by the legacy machine API
// and advances the normal Goal completion/recovery state machine.
func (c *Control) CompleteRemoteWorker(workerID, machineID, status, summary, threadID, failure string, workspaceRevision ...string) (*store.Worker, error) {
	worker, err := c.store.GetWorker(strings.TrimSpace(workerID))
	if err != nil {
		return nil, err
	}
	if worker == nil || worker.MachineID != machineID {
		return nil, os.ErrNotExist
	}
	if worker.Status != "running" {
		return nil, ErrWorkerUnavailable
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "completed" && status != "failed" {
		return nil, errors.New("worker result status must be completed or failed")
	}
	verifying, err := c.store.TransitionWorkerStatus(worker.ID, machineID, "running", "verifying")
	if err != nil {
		return nil, err
	}
	if verifying == nil {
		return nil, ErrWorkerUnavailable
	}
	return c.completeRemoteWorkerAdmitted(verifying, status, summary, threadID, failure, nil, "", workspaceRevision...)
}

// CompleteBoundNodeRemoteWorker admits a result only when the credential is
// still active, bound to nodeID, and owns this Worker through its Goal. The
// attempt is fenced before any workspace or completion processing begins.
func (c *Control) CompleteBoundNodeRemoteWorker(credentialDigest, nodeID, workerID string, attempt int, status, summary, threadID, failure, workspaceRevision string) (*store.Worker, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "completed" && status != "failed" {
		return nil, errors.New("worker result status must be completed or failed")
	}
	worker, err := c.store.BeginBoundNodeWorkerResult(credentialDigest, nodeID, workerID, attempt)
	if err != nil {
		return nil, err
	}
	return c.completeRemoteWorkerAdmitted(worker, status, summary, threadID, failure,
		&boundNodeResultFence{credentialDigest: credentialDigest, nodeID: nodeID}, "", workspaceRevision)
}

// CompleteBoundNodeRemoteWorkerNodeControl admits and commits a Worker result
// only while the exact encrypted request and its key epoch remain active.
func (c *Control) CompleteBoundNodeRemoteWorkerNodeControl(input store.NodeControlRPCInput,
	workerID string, attempt int, status, summary, threadID, failure, workspaceRevision,
	resourceStopState string) (*store.Worker, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "completed" && status != "failed" {
		return nil, errors.New("worker result status must be completed or failed")
	}
	resourceStopState = strings.ToUpper(strings.TrimSpace(resourceStopState))
	if resourceStopState != "" && resourceStopState != "UNVERIFIED" {
		return nil, errors.New("worker resource stop state is invalid")
	}
	worker, err := c.store.BeginBoundNodeWorkerResultNodeControl(input, workerID, attempt)
	if err != nil {
		return nil, err
	}
	fence := &boundNodeResultFence{credentialDigest: input.CredentialDigest,
		nodeID: input.NodeID, nodeControlRPC: &input}
	return c.completeRemoteWorkerAdmitted(worker, status, summary, threadID, failure, fence,
		resourceStopState, workspaceRevision)
}

func (c *Control) completeRemoteWorkerAdmitted(worker *store.Worker, status, summary, threadID, failure string,
	fence *boundNodeResultFence, resourceStopState string, workspaceRevision ...string) (*store.Worker, error) {
	if worker == nil {
		return nil, ErrWorkerUnavailable
	}
	summary = tail(strings.TrimSpace(summary), 16000)
	if threadID == "" {
		threadID = worker.ThreadID
	}
	if status == "completed" {
		if summary == "" {
			summary = readSummary(worker.ResponseFile)
		}
		goal, goalErr := c.store.GetGoal(worker.GoalID)
		if goalErr != nil {
			return nil, goalErr
		}
		if goal == nil {
			return nil, os.ErrNotExist
		}
		verdict := c.verifyCompletion(context.Background(), *goal, *worker, summary)
		if !verdict.Accepted {
			if verdict.RequiresAttention {
				return c.failRemoteCompletionVerification(goal, worker, summary, threadID, verdict,
					fence, workspaceRevision...)
			}
			return c.rejectRemoteCompletion(goal, worker, summary, threadID, verdict, fence, workspaceRevision...)
		}
		completionWarning := ""
		if resourceStopState == "UNVERIFIED" {
			completionWarning = "business result completed; physical resource stop is unverified and the Node resource remains quarantined"
		}
		updated, err := c.finishRemoteResult(worker, "completed", store.WorkerUpdate{
			ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: stringPtr(completionWarning),
			ThreadID: stringPtr(threadID), Summary: &summary,
		}, fence)
		if err != nil {
			return nil, err
		}
		c.recordCompletionVerdict(goal.ID, worker.ID, verdict)
		c.recordAdmittedWorkspaceRevision(worker, fence, workspaceRevision...)
		artifact, artifactErr := c.store.CreateArtifact(store.Artifact{
			GoalID: worker.GoalID, WorkerID: worker.ID, Name: "worker-final-message",
			Path: worker.ResponseFile, Kind: "worker-summary", Evidence: summary,
		})
		evidence := []any{}
		if artifactErr == nil && artifact != nil {
			evidence = append(evidence, map[string]any{"artifact_id": artifact.ID, "kind": artifact.Kind, "path": artifact.Path})
			_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "ArtifactProduced", map[string]any{"artifact_id": artifact.ID, "path": artifact.Path, "kind": artifact.Kind})
		}
		_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerCompleted", map[string]any{"summary": tail(summary, 4000), "remote": true})
		if resourceStopState == "UNVERIFIED" {
			_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerResourceStopUnverified",
				map[string]any{"state": resourceStopState})
		}
		if c.completeGoalWhenWorkersFinish(goal, worker.ID, summary, evidence) {
			c.notify(goal.ID, "goal.completed", "P2", "Goal completed", summary)
		}
		_ = c.store.SetMachineStatus(worker.MachineID, "available")
		return updated, nil
	}

	if failure == "" {
		failure = summary
	}
	failure = tail(strings.TrimSpace(failure), 4000)
	if failure == "" {
		failure = "remote worker failed without an error message"
	}
	if worker.Attempt > c.config.MaxRecoveries {
		failed, err := c.finishRemoteResult(worker, "failed", store.WorkerUpdate{
			ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &failure,
			Summary: &summary, ThreadID: stringPtr(threadID),
		}, fence)
		if err != nil {
			return nil, err
		}
		c.recordAdmittedWorkspaceRevision(worker, fence, workspaceRevision...)
		_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerFailed", map[string]any{"error": failure, "remote": true})
		goal, goalErr := c.store.GetGoal(worker.GoalID)
		if goalErr == nil && goal != nil {
			c.finishFailure(goal, worker.ID, worker.Attempt, failure)
		}
		_ = c.store.SetMachineStatus(worker.MachineID, "available")
		return failed, nil
	}
	queued, err := c.finishRemoteResult(worker, "queued", store.WorkerUpdate{
		ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &failure,
		Summary: &summary, ThreadID: stringPtr(threadID),
	}, fence)
	if err != nil {
		return nil, err
	}
	c.recordAdmittedWorkspaceRevision(worker, fence, workspaceRevision...)
	_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerFailed", map[string]any{"error": failure, "remote": true})
	_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerRecovered", map[string]any{"attempt": worker.Attempt + 1, "remote": true})
	_ = c.store.SetMachineStatus(worker.MachineID, "available")
	return queued, nil
}

func (c *Control) recordAdmittedWorkspaceRevision(worker *store.Worker, fence *boundNodeResultFence, workspaceRevision ...string) {
	if worker == nil || fence != nil {
		return
	}
	if len(workspaceRevision) > 0 && strings.TrimSpace(workspaceRevision[0]) != "" {
		c.recordWorkspacePrepared(worker.GoalID, worker.ID, worker.Workspace, strings.TrimSpace(workspaceRevision[0]), false)
	}
	// Scoped snapshot upload commits this pointer through its own attempt fence.
	// Legacy v1 still reports the digest through its existing result contract.
	if len(workspaceRevision) > 1 && strings.TrimSpace(workspaceRevision[1]) != "" {
		c.recordWorkspaceSnapshotDigest(worker.GoalID, worker.Workspace, strings.TrimSpace(workspaceRevision[1]))
	}
}

func (c *Control) finishRemoteResult(worker *store.Worker, nextStatus string, update store.WorkerUpdate, fence *boundNodeResultFence) (*store.Worker, error) {
	var updated *store.Worker
	var err error
	if fence != nil {
		if fence.nodeControlRPC != nil {
			updated, err = c.store.UpdateBoundNodeWorkerAtAttemptNodeControl(*fence.nodeControlRPC,
				worker.ID, "verifying", nextStatus, worker.Attempt, update)
		} else {
			updated, err = c.store.UpdateBoundNodeWorkerAtAttempt(fence.credentialDigest, fence.nodeID,
				worker.ID, "verifying", nextStatus, worker.Attempt, update)
		}
	} else {
		updated, err = c.store.UpdateWorkerAtAttempt(worker.ID, worker.MachineID,
			"verifying", nextStatus, worker.Attempt, update)
	}
	if err != nil {
		if fence != nil && errors.Is(err, store.ErrNodeWorkerNotAuthorized) {
			recovered, recoveryErr := c.store.RecoverBoundNodeWorkerAfterRevocation(worker.ID, worker.MachineID, worker.Attempt)
			if recoveryErr == nil && recovered != nil {
				_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerResultDiscarded", map[string]any{
					"attempt": worker.Attempt, "reason": "Node binding revoked during result verification",
				})
			}
		}
		return nil, err
	}
	if updated == nil {
		return nil, ErrWorkerUnavailable
	}
	return updated, nil
}

func (c *Control) failRemoteCompletionVerification(goal *store.Goal, worker *store.Worker,
	summary, threadID string, verdict completionVerdict, fence *boundNodeResultFence,
	workspaceRevision ...string) (*store.Worker, error) {
	message := tail("Required completion verification is unavailable: "+verdict.Rationale, 4000)
	updated, err := c.finishRemoteResult(worker, "failed", store.WorkerUpdate{
		ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &message,
		ThreadID: stringPtr(threadID), Summary: &summary,
	}, fence)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, ErrWorkerUnavailable
	}
	c.recordCompletionVerdict(goal.ID, worker.ID, verdict)
	c.recordAdmittedWorkspaceRevision(worker, fence, workspaceRevision...)
	c.finishCompletionVerificationFailure(goal, worker.ID, worker.Attempt, message)
	return updated, nil
}

func (c *Control) rejectRemoteCompletion(goal *store.Goal, worker *store.Worker, summary, threadID string, verdict completionVerdict, fence *boundNodeResultFence, workspaceRevision ...string) (*store.Worker, error) {
	message := tail(verdict.Rationale, 4000)
	if message == "" {
		message = "Monitor rejected the completion claim."
	}
	if worker.Attempt > c.config.MaxRecoveries {
		failed, err := c.finishRemoteResult(worker, "failed", store.WorkerUpdate{
			ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &message,
			Summary: &summary, ThreadID: stringPtr(threadID),
		}, fence)
		if err != nil {
			return nil, err
		}
		c.recordCompletionVerdict(goal.ID, worker.ID, verdict)
		c.recordAdmittedWorkspaceRevision(worker, fence, workspaceRevision...)
		c.finishFailure(goal, worker.ID, worker.Attempt, "completion verification failed: "+message)
		_ = c.store.SetMachineStatus(worker.MachineID, "available")
		return failed, nil
	}
	prompt := verdict.Correction
	if prompt == "" {
		prompt = "Re-check the Goal success criteria and provide stronger evidence before completing."
	}
	queued, err := c.finishRemoteResult(worker, "queued", store.WorkerUpdate{
		ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &message,
		Summary: &summary, ThreadID: stringPtr(threadID), Prompt: &prompt,
	}, fence)
	if err != nil {
		return nil, err
	}
	c.recordCompletionVerdict(goal.ID, worker.ID, verdict)
	c.recordAdmittedWorkspaceRevision(worker, fence, workspaceRevision...)
	_, _ = c.store.AppendEvent(goal.ID, worker.ID, "WorkerRecovered", map[string]any{
		"attempt": worker.Attempt + 1, "remote": true, "reason": "completion verification rejected",
	})
	_ = c.store.SetMachineStatus(worker.MachineID, "available")
	return queued, nil
}
