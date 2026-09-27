package control

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// ClientGoalResult is a bounded result projection for a Goal created by this
// owner's encrypted Client Intent. It does not expose Worker prompts, local
// paths, artifact contents, or another owner's Goal by a guessed ID.
type ClientGoalResult struct {
	IntentID           string                      `json:"intent_id"`
	IntentStatus       string                      `json:"intent_status"`
	GoalID             string                      `json:"goal_id,omitempty"`
	GoalStatus         string                      `json:"goal_status,omitempty"`
	Outcome            string                      `json:"outcome,omitempty"`
	Summary            string                      `json:"summary,omitempty"`
	Workers            []ClientGoalWorkerResult    `json:"workers"`
	Artifacts          []ClientGoalArtifactSummary `json:"artifacts"`
	WorkersTruncated   bool                        `json:"workers_truncated"`
	ArtifactsTruncated bool                        `json:"artifacts_truncated"`
}

type ClientGoalWorkerResult struct {
	WorkerID string `json:"worker_id"`
	Status   string `json:"status"`
	Attempt  int    `json:"attempt"`
	Summary  string `json:"summary,omitempty"`
}

type ClientGoalArtifactSummary struct {
	ArtifactID string `json:"artifact_id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Digest     string `json:"digest,omitempty"`
	Status     string `json:"status"`
}

func (c *Control) ClientGoalResultForIntent(ownerID, intentID string) (*ClientGoalResult, error) {
	progress, err := c.ClientIntentStatus(ownerID, intentID)
	if err != nil {
		return nil, err
	}
	result := &ClientGoalResult{
		IntentID: progress.Intent.ID, IntentStatus: progress.Intent.Status,
		Workers: []ClientGoalWorkerResult{}, Artifacts: []ClientGoalArtifactSummary{},
	}
	if progress.Intent.Status != "resolved" {
		return result, nil
	}
	var association struct {
		GoalID string `json:"goal_id"`
	}
	if err := json.Unmarshal(progress.Intent.Result, &association); err != nil {
		return nil, err
	}
	if association.GoalID == "" {
		return result, nil
	}
	goal, err := c.store.GetGoal(association.GoalID)
	if err != nil {
		return nil, err
	}
	if goal == nil || goal.OwnerID == "" || goal.OwnerID != strings.TrimSpace(ownerID) {
		return nil, store.ErrClientIntentNotFound
	}
	result.GoalID = goal.ID
	result.GoalStatus = goal.Status
	result.Outcome = boundedClientResultText(goal.Outcome, 4096)
	result.Summary = boundedClientResultText(goal.Summary, 8192)
	workers, err := c.store.ListWorkersForGoal(goal.ID)
	if err != nil {
		return nil, err
	}
	for index, worker := range workers {
		if index == 8 {
			break
		}
		result.Workers = append(result.Workers, ClientGoalWorkerResult{
			WorkerID: worker.ID, Status: worker.Status, Attempt: worker.Attempt,
			Summary: boundedClientResultText(worker.Summary, 4096),
		})
	}
	result.WorkersTruncated = len(workers) > 8
	artifacts, err := c.store.ListArtifacts(goal.ID)
	if err != nil {
		return nil, err
	}
	for index, artifact := range artifacts {
		if index == 16 {
			break
		}
		if artifact.GoalID != goal.ID {
			return nil, errors.New("artifact Goal association changed")
		}
		result.Artifacts = append(result.Artifacts, ClientGoalArtifactSummary{
			ArtifactID: artifact.ID, Name: boundedClientResultText(artifact.Name, 256),
			Kind: artifact.Kind, Digest: artifact.Digest, Status: artifact.Status,
		})
	}
	result.ArtifactsTruncated = len(artifacts) > 16
	return result, nil
}

func boundedClientResultText(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	return strings.ToValidUTF8(value[:maxBytes], "")
}
