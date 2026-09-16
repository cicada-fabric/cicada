package control

import (
	"errors"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// CompleteRemoteWorker persists a result returned by an agent and advances
// the normal Goal completion/recovery state machine.
func (c *Control) CompleteRemoteWorker(workerID, machineID, status, summary, threadID, failure string) (*store.Worker, error) {
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
	summary = tail(strings.TrimSpace(summary), 16000)
	if threadID == "" {
		threadID = worker.ThreadID
	}
	if status == "completed" {
		if summary == "" {
			summary = readSummary(worker.ResponseFile)
		}
		completed := "completed"
		updated, err := c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
			Status: &completed, ClearPID: true, EndedAt: stringPtr(storeNow()),
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
		goal, goalErr := c.store.GetGoal(worker.GoalID)
		if goalErr == nil && goal != nil && c.completeGoalWhenWorkersFinish(goal, worker.ID, summary, evidence) {
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
	recovering := "recovering"
	_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
		Status: &recovering, ClearPID: true, EndedAt: stringPtr(storeNow()),
		LastError: &failure, Summary: &summary, ThreadID: stringPtr(threadID),
	})
	_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerFailed", map[string]any{"error": failure, "remote": true})
	if worker.Attempt > c.config.MaxRecoveries {
		goal, goalErr := c.store.GetGoal(worker.GoalID)
		if goalErr == nil && goal != nil {
			c.finishFailure(goal, worker.ID, worker.Attempt, failure)
		}
		_ = c.store.SetMachineStatus(machineID, "available")
		return c.store.GetWorker(worker.ID)
	}
	queued := "queued"
	_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{Status: &queued})
	_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerRecovered", map[string]any{"attempt": worker.Attempt + 1, "remote": true})
	_ = c.store.SetMachineStatus(machineID, "available")
	return c.store.GetWorker(worker.ID)
}
