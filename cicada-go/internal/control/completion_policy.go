package control

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

func (c *Control) recordCompletionVerdict(goalID, workerID string, verdict completionVerdict) {
	eventType := "WorkerCompletionVerified"
	if verdict.Source == "unavailable" {
		eventType = "WorkerCompletionVerificationUnavailable"
	} else if !verdict.Accepted {
		eventType = "WorkerCompletionRejected"
	}
	_, _ = c.store.AppendEvent(goalID, workerID, eventType, map[string]any{
		"source": verdict.Source, "confidence": verdict.Confidence,
		"rationale": verdict.Rationale, "correction": verdict.Correction,
	})
}

func (c *Control) finishCompletionVerificationFailure(goal *store.Goal, workerID string, attempt int, message string) {
	if goal == nil {
		return
	}
	message = tail(strings.TrimSpace(message), 4000)
	if message == "" {
		message = "Required completion verification is unavailable; the Worker result was retained for review."
	}
	_, _ = c.store.UpdateGoal(goal.ID, "failed", message)
	_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerFailed", map[string]any{
		"error": message, "reason": "required_completion_verification_unavailable",
	})
	_, _ = c.store.AppendEvent(goal.ID, workerID, "GoalBlocked", map[string]any{
		"attempt": attempt, "reason": message,
	})
	c.parkFailedIdeaResearch(goal, message)
	c.notify(goal.ID, "goal.blocked", "P0", "Goal needs attention", message)
	_ = c.store.SetMachineStatus(goal.MachineID, "available")
}

func (c *Control) rejectLocalCompletion(goal *store.Goal, workerID string, attempt int, summary string, verdict completionVerdict) (string, bool) {
	message := tail(verdict.Rationale, 4000)
	if message == "" {
		message = "Monitor rejected the completion claim."
	}
	recovering := "recovering"
	_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{
		Status: &recovering, ClearPID: true, EndedAt: stringPtr(storeNow()),
		LastError: &message, Summary: &summary,
	})
	if attempt > c.config.MaxRecoveries {
		c.finishFailure(goal, workerID, attempt, "completion verification failed: "+message)
		return "", false
	}
	_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerRecovered", map[string]any{
		"attempt": attempt + 1, "reason": "completion verification rejected",
	})
	prompt := verdict.Correction
	if prompt == "" {
		prompt = "Re-check the Goal success criteria and provide stronger evidence before completing."
	}
	return "The monitor rejected the previous completion claim. Address this correction, verify the result, and continue:\n\n" + prompt, true
}
