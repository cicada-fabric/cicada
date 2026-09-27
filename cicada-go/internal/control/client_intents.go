package control

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// DispatchClientIntentAsync schedules an already accepted intent. It is safe
// to call more than once: the durable QUEUED -> RUNNING claim selects one
// executor. Call this only after the encrypted RPC response has been durably
// cached, so a Client retry cannot race ahead of the acceptance response.
func (c *Control) DispatchClientIntentAsync(intentID string) error {
	intentID = strings.TrimSpace(intentID)
	if intentID == "" {
		return store.ErrClientIntentNotFound
	}
	job, err := c.store.GetClientIntent(intentID)
	if err != nil {
		return err
	}
	if job.State != store.ClientIntentQueued {
		return nil
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("Control is shutting down")
	}
	c.wg.Add(1)
	c.mu.Unlock()
	go c.runClientIntentAsync(intentID)
	return nil
}

// RecoverClientIntents is a startup hook. It must run before serving Client
// requests: RUNNING operations from a previous process are reconciled to DONE
// when their normal Intent is already terminal, and otherwise fenced as
// UNCERTAIN. QUEUED operations remain safe to dispatch and are scheduled here.
func (c *Control) RecoverClientIntents() (int, error) {
	queued, err := c.store.RecoverClientIntents()
	if err != nil {
		return 0, err
	}
	dispatched := 0
	for _, job := range queued {
		if err := c.DispatchClientIntentAsync(job.IntentID); err != nil {
			return dispatched, err
		}
		dispatched++
	}
	return dispatched, nil
}

func (c *Control) runClientIntentAsync(intentID string) {
	defer c.wg.Done()
	claimed, won, err := c.store.ClaimClientIntent(intentID)
	if err != nil || !won {
		return
	}
	finished := false
	defer func() {
		if recovered := recover(); recovered != nil && !finished {
			// A panic may have happened after a business side effect. Preserve the
			// uncertainty; never put this request back in QUEUED for blind replay.
			_ = c.store.MarkClientIntentUncertain(intentID, "Control interrupted while processing accepted intent")
		}
	}()

	var input IntentInput
	if err := json.Unmarshal(claimed.Input, &input); err != nil {
		failed, resolveErr := c.store.ResolveIntent(intentID, "", "failed", map[string]any{}, "",
			"stored Client intent input could not be decoded")
		if resolveErr == nil && failed != nil && isTerminalIntentStatus(failed.Status) &&
			c.store.CompleteClientIntent(intentID) == nil {
			finished = true
			return
		}
		_ = c.store.MarkClientIntentUncertain(intentID, "Control could not durably record the stored input error")
		finished = true
		return
	}

	_, routeErr := c.routeExistingIntentForOwner(intentID, input, claimed.OwnerID)
	// RouteIntent persists business failures on the normal Intent before
	// returning the error. A failure to persist a terminal state leaves the
	// operation uncertain because a Goal, Approval or other effect may already
	// have been created.
	persisted, readErr := c.store.GetIntent(intentID)
	if readErr == nil && persisted != nil && isTerminalIntentStatus(persisted.Status) {
		if completeErr := c.store.CompleteClientIntent(intentID); completeErr == nil {
			finished = true
		}
		return
	}
	reason := "Control could not durably record the intent outcome"
	if routeErr != nil && readErr == nil && persisted != nil && persisted.Status == "pending" {
		reason = "Control returned before the intent outcome was durably recorded"
	}
	_ = c.store.MarkClientIntentUncertain(intentID, reason)
	finished = true
}

func isTerminalIntentStatus(status string) bool {
	switch status {
	case "resolved", "needs_input", "failed":
		return true
	default:
		return false
	}
}
