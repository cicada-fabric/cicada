package control

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// CompleteRemoteWorker persists a result returned by an agent and advances
// the normal Goal completion/recovery state machine.
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
	worker = verifying
	if len(workspaceRevision) > 0 && strings.TrimSpace(workspaceRevision[0]) != "" {
		c.recordWorkspacePrepared(worker.GoalID, worker.ID, worker.Workspace, strings.TrimSpace(workspaceRevision[0]), false)
	}
	if len(workspaceRevision) > 1 && strings.TrimSpace(workspaceRevision[1]) != "" {
		c.recordWorkspaceSnapshotDigest(worker.GoalID, worker.Workspace, strings.TrimSpace(workspaceRevision[1]))
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
		c.recordCompletionVerdict(goal.ID, worker.ID, verdict)
		if !verdict.Accepted {
			return c.rejectRemoteCompletion(goal, worker, summary, threadID, verdict)
		}
		completed, err := c.store.TransitionWorkerStatus(worker.ID, machineID, "verifying", "completed")
		if err != nil {
			return nil, err
		}
		if completed == nil {
			return nil, ErrWorkerUnavailable
		}
		updated, err := c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
			ClearPID: true, EndedAt: stringPtr(storeNow()),
			LastError: stringPtr(""), ThreadID: stringPtr(threadID), Summary: &summary,
		})
		if err != nil {
			return nil, err
		}
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
		if c.completeGoalWhenWorkersFinish(goal, worker.ID, summary, evidence) {
			c.notify(goal.ID, "goal.completed", "P2", "Goal completed", summary)
		}
		_ = c.store.SetMachineStatus(machineID, "available")
		return updated, nil
	}

	if failure == "" {
		failure = summary
	}
	failure = tail(strings.TrimSpace(failure), 4000)
	if failure == "" {
		failure = "remote worker failed without an error message"
	}
	_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerFailed", map[string]any{"error": failure, "remote": true})
	if worker.Attempt > c.config.MaxRecoveries {
		failed, transitionErr := c.store.TransitionWorkerStatus(worker.ID, machineID, "verifying", "failed")
		if transitionErr != nil {
			return nil, transitionErr
		}
		if failed == nil {
			return nil, ErrWorkerUnavailable
		}
		_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
			ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &failure,
			Summary: &summary, ThreadID: stringPtr(threadID),
		})
		goal, goalErr := c.store.GetGoal(worker.GoalID)
		if goalErr == nil && goal != nil {
			c.finishFailure(goal, worker.ID, worker.Attempt, failure)
		}
		_ = c.store.SetMachineStatus(machineID, "available")
		return c.store.GetWorker(worker.ID)
	}
	queued, transitionErr := c.store.TransitionWorkerStatus(worker.ID, machineID, "verifying", "queued")
	if transitionErr != nil {
		return nil, transitionErr
	}
	if queued == nil {
		return nil, ErrWorkerUnavailable
	}
	_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
		ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &failure,
		Summary: &summary, ThreadID: stringPtr(threadID),
	})
	_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerRecovered", map[string]any{"attempt": worker.Attempt + 1, "remote": true})
	_ = c.store.SetMachineStatus(machineID, "available")
	return c.store.GetWorker(worker.ID)
}

func (c *Control) rejectRemoteCompletion(goal *store.Goal, worker *store.Worker, summary, threadID string, verdict completionVerdict) (*store.Worker, error) {
	message := tail(verdict.Rationale, 4000)
	if message == "" {
		message = "Monitor rejected the completion claim."
	}
	if worker.Attempt > c.config.MaxRecoveries {
		failed, err := c.store.TransitionWorkerStatus(worker.ID, worker.MachineID, "verifying", "failed")
		if err != nil {
			return nil, err
		}
		if failed == nil {
			return nil, ErrWorkerUnavailable
		}
		_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
			ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &message,
			Summary: &summary, ThreadID: stringPtr(threadID),
		})
		c.finishFailure(goal, worker.ID, worker.Attempt, "completion verification failed: "+message)
		_ = c.store.SetMachineStatus(worker.MachineID, "available")
		return c.store.GetWorker(worker.ID)
	}
	queued, err := c.store.TransitionWorkerStatus(worker.ID, worker.MachineID, "verifying", "queued")
	if err != nil {
		return nil, err
	}
	if queued == nil {
		return nil, ErrWorkerUnavailable
	}
	prompt := verdict.Correction
	if prompt == "" {
		prompt = "Re-check the Goal success criteria and provide stronger evidence before completing."
	}
	_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
		ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &message,
		Summary: &summary, ThreadID: stringPtr(threadID), Prompt: &prompt,
	})
	_, _ = c.store.AppendEvent(goal.ID, worker.ID, "WorkerRecovered", map[string]any{
		"attempt": worker.Attempt + 1, "remote": true, "reason": "completion verification rejected",
	})
	_ = c.store.SetMachineStatus(worker.MachineID, "available")
	return c.store.GetWorker(worker.ID)
}
