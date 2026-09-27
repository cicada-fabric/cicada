package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/store"
)

// IntentInput is the language-neutral boundary for the Client's natural input.
// Goal carries optional execution details when the input becomes a Goal.
type IntentInput struct {
	Text        string    `json:"text"`
	Kind        string    `json:"kind,omitempty"`
	TargetID    string    `json:"target_id,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	RevisitWhen string    `json:"revisit_when,omitempty"`
	Attachments []string  `json:"attachments,omitempty"`
	Goal        GoalInput `json:"goal,omitempty"`
}

func (c *Control) Intents(status string) ([]store.Intent, error) {
	return c.store.ListIntents(strings.TrimSpace(status))
}

func (c *Control) Intent(id string) (*store.Intent, error) {
	return c.store.GetIntent(strings.TrimSpace(id))
}

func (c *Control) RouteIntent(input IntentInput) (*store.Intent, error) {
	input, requested, err := normalizeIntentInput(input)
	if err != nil {
		return nil, err
	}
	intent, err := c.store.CreateIntent(input.Text, requested, input.TargetID, input.Attachments)
	if err != nil {
		return nil, err
	}
	return c.routeExistingIntent(intent.ID, input)
}

// AcceptClientIntent persists an asynchronous Client request before the
// transport acknowledges it. Repeated request IDs with the same full input
// return the original Intent; a changed body under the same ID is rejected.
// This method deliberately does not start work. The HTTP boundary should first
// persist its sealed response packet, then call DispatchClientIntentAsync.
func (c *Control) AcceptClientIntent(clientRequestID string, input IntentInput) (*store.Intent, error) {
	return c.acceptClientIntent("", clientRequestID, input)
}

// AcceptClientIntentForOwner is called from an authenticated encrypted
// Client session. The owner value is supplied by the session verifier, not
// the Client intent JSON.
func (c *Control) AcceptClientIntentForOwner(ownerID, clientRequestID string, input IntentInput) (*store.Intent, error) {
	ownerID = strings.TrimSpace(ownerID)
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.acceptClientIntent(ownerID, clientRequestID, input)
}

func (c *Control) acceptClientIntent(ownerID, clientRequestID string, input IntentInput) (*store.Intent, error) {
	clientRequestID = strings.TrimSpace(clientRequestID)
	if clientRequestID == "" || len(clientRequestID) > 256 {
		return nil, errors.New("client_request_id is required and must be at most 256 characters")
	}
	input, requested, err := normalizeIntentInput(input)
	if err != nil {
		return nil, err
	}
	input.Kind = requested
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode accepted Client intent: %w", err)
	}
	var intent *store.Intent
	if ownerID == "" {
		intent, _, err = c.store.AcceptClientIntent(clientRequestID, input.Text, requested,
			input.TargetID, input.Attachments, encoded)
	} else {
		intent, _, err = c.store.AcceptClientIntentForOwner(ownerID, clientRequestID, input.Text, requested,
			input.TargetID, input.Attachments, encoded)
	}
	if err != nil {
		return nil, err
	}
	return intent, nil
}

func normalizeIntentInput(input IntentInput) (IntentInput, string, error) {
	input.Text = strings.TrimSpace(input.Text)
	if input.Text == "" {
		return input, "", errors.New("intent text is required")
	}
	if utf8.RuneCountInString(input.Text) > 16000 {
		return input, "", errors.New("intent text exceeds 16000 characters")
	}
	requested := strings.ToLower(strings.TrimSpace(input.Kind))
	if requested == "" {
		requested = "auto"
	}
	input.Kind = requested
	return input, requested, nil
}

func (c *Control) routeExistingIntent(intentID string, input IntentInput) (*store.Intent, error) {
	return c.routeExistingIntentForOwner(intentID, input, "")
}

func (c *Control) routeExistingIntentForOwner(intentID string, input IntentInput, ownerID string) (*store.Intent, error) {
	requested := input.Kind
	if err := c.prepareIntentAttachments(&input); err != nil {
		failed, updateErr := c.store.ResolveIntent(intentID, "", "failed", map[string]any{}, "", err.Error())
		if updateErr != nil {
			return nil, fmt.Errorf("prepare intent attachments: %v; persist failure: %w", err, updateErr)
		}
		return failed, err
	}
	kind, content, valid := classifyIntent(input.Text, requested)
	if !valid {
		return c.needsIntentInput(intentID, "", "Choose one intent kind: goal, idea, research, question, command, or approval.")
	}
	if requested == "auto" && kind == "goal" {
		if plan, planErr := c.planIntent(input.Text); planErr == nil && plan.Confidence >= 0.65 {
			kind, content = plan.Kind, input.Text
		}
	}
	if question := missingIntentInput(kind, input); question != "" {
		return c.needsIntentInput(intentID, kind, question)
	}

	result, dispatchErr := c.dispatchIntent(intentID, kind, content, input, ownerID)
	if dispatchErr != nil {
		failed, updateErr := c.store.ResolveIntent(intentID, kind, "failed", map[string]any{}, "", dispatchErr.Error())
		if updateErr != nil {
			return nil, fmt.Errorf("dispatch intent: %v; persist failure: %w", dispatchErr, updateErr)
		}
		return failed, dispatchErr
	}
	return c.store.ResolveIntent(intentID, kind, "resolved", result, "", "")
}

func (c *Control) needsIntentInput(id, kind, question string) (*store.Intent, error) {
	return c.store.ResolveIntent(id, kind, "needs_input", map[string]any{}, question, "")
}

func (c *Control) dispatchIntent(intentID, kind, text string, input IntentInput, ownerID string) (map[string]any, error) {
	if ownerID != "" {
		if err := c.ValidateClientOwnerScope(ownerID); err != nil {
			return nil, err
		}
	}
	switch kind {
	case "idea":
		idea, err := c.CreateIdea(IdeaInput{
			Title: intentTitle(text), Description: text, Source: "intent:" + intentID,
			RevisitWhen: input.RevisitWhen,
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "idea", "idea_id": idea.ID}, nil
	case "research":
		idea, err := c.CreateIdea(IdeaInput{
			Title: intentTitle(text), Description: text, Source: "intent:" + intentID,
			RevisitWhen: input.RevisitWhen,
		})
		if err != nil {
			return nil, err
		}
		var goal *store.Goal
		if ownerID == "" {
			goal, err = c.ResearchIdea(idea.ID)
		} else {
			goal, err = c.ResearchIdeaForOwner(ownerID, idea.ID)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "research", "idea_id": idea.ID, "goal_id": goal.ID}, nil
	case "question":
		goalInput := input.Goal
		if strings.TrimSpace(goalInput.Objective) == "" {
			goalInput.Objective = "Answer the user's question accurately:\n\n" + text
		}
		if strings.TrimSpace(goalInput.SuccessCriteria) == "" {
			goalInput.SuccessCriteria = "Provide a direct answer and cite or record the evidence used when verification is needed."
		}
		if strings.TrimSpace(goalInput.Constraints) == "" {
			goalInput.Constraints = "Answer and research only. Do not modify projects or external systems."
		}
		return c.createIntentGoal(ownerID, goalInput)
	case "goal":
		goalInput := input.Goal
		if strings.TrimSpace(goalInput.Objective) == "" {
			goalInput.Objective = text
		}
		return c.createIntentGoal(ownerID, goalInput)
	case "command":
		goalID := strings.TrimSpace(input.TargetID)
		if ownerID != "" {
			goal, err := c.store.GetGoal(goalID)
			if err != nil {
				return nil, err
			}
			if goal == nil || goal.OwnerID != ownerID {
				return nil, os.ErrNotExist
			}
		}
		command, err := c.SendCommand(goalID, text)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "command", "command_id": command.ID, "goal_id": command.GoalID}, nil
	case "approval":
		approvalID := strings.TrimSpace(input.TargetID)
		if ownerID != "" {
			approval, err := c.store.GetApproval(approvalID)
			if err != nil {
				return nil, err
			}
			if approval == nil {
				return nil, os.ErrNotExist
			}
			goal, err := c.store.GetGoal(approval.GoalID)
			if err != nil {
				return nil, err
			}
			if goal == nil || goal.OwnerID != ownerID {
				return nil, os.ErrNotExist
			}
		}
		approval, err := c.ResolveApproval(approvalID, strings.TrimSpace(input.Decision))
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "approval", "approval_id": approval.ID, "decision": approval.Decision}, nil
	default:
		return nil, fmt.Errorf("unsupported intent kind: %s", kind)
	}
}

func (c *Control) createIntentGoal(ownerID string, input GoalInput) (map[string]any, error) {
	var goal *store.Goal
	var err error
	if ownerID == "" {
		goal, err = c.CreateGoal(input)
	} else {
		goal, err = c.CreateGoalForOwner(ownerID, input)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": "goal", "goal_id": goal.ID}, nil
}

func missingIntentInput(kind string, input IntentInput) string {
	switch kind {
	case "command":
		if strings.TrimSpace(input.TargetID) == "" {
			return "Which Goal should receive this command? Provide target_id."
		}
	case "approval":
		if strings.ToLower(strings.TrimSpace(input.Kind)) != "approval" {
			return "Approval decisions must explicitly set kind to approval."
		}
		if strings.TrimSpace(input.TargetID) == "" {
			return "Which pending Approval should be resolved? Provide target_id."
		}
		if strings.TrimSpace(input.Decision) == "" {
			return "Should this Approval be approved or denied? Provide decision."
		}
	}
	return ""
}

func classifyIntent(text, requested string) (string, string, bool) {
	if requested != "auto" {
		switch requested {
		case "goal", "idea", "research", "question", "command", "approval":
			return requested, text, true
		default:
			return "", text, false
		}
	}
	prefixes := []struct{ prefix, kind string }{
		{"idea:", "idea"}, {"idea：", "idea"}, {"想法:", "idea"}, {"想法：", "idea"},
		{"research:", "research"}, {"research：", "research"}, {"研究:", "research"}, {"研究：", "research"}, {"调研:", "research"}, {"调研：", "research"},
		{"question:", "question"}, {"question：", "question"}, {"问题:", "question"}, {"问题：", "question"},
		{"goal:", "goal"}, {"goal：", "goal"}, {"目标:", "goal"}, {"目标：", "goal"},
		{"command:", "command"}, {"command：", "command"}, {"指令:", "command"}, {"指令：", "command"},
	}
	lower := strings.ToLower(text)
	for _, candidate := range prefixes {
		if strings.HasPrefix(lower, candidate.prefix) {
			content := strings.TrimSpace(text[len(candidate.prefix):])
			if content == "" {
				content = text
			}
			return candidate.kind, content, true
		}
	}
	if strings.HasSuffix(text, "?") || strings.HasSuffix(text, "？") {
		return "question", text, true
	}
	return "goal", text, true
}

func intentTitle(text string) string {
	text = strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	runes := []rune(text)
	if len(runes) > 80 {
		return string(runes[:80]) + "…"
	}
	return text
}
