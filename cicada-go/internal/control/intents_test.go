package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClassifyIntentConservatively(t *testing.T) {
	tests := []struct {
		text, requested, kind, content string
		valid                          bool
	}{
		{text: "想法：以后比较两种实现", requested: "auto", kind: "idea", content: "以后比较两种实现", valid: true},
		{text: "Research: compare the papers", requested: "auto", kind: "research", content: "compare the papers", valid: true},
		{text: "Which machine is free?", requested: "auto", kind: "question", content: "Which machine is free?", valid: true},
		{text: "ship the verified patch", requested: "auto", kind: "goal", content: "ship the verified patch", valid: true},
		{text: "yes", requested: "approval", kind: "approval", content: "yes", valid: true},
		{text: "anything", requested: "unsupported", content: "anything", valid: false},
	}
	for _, test := range tests {
		kind, content, valid := classifyIntent(test.text, test.requested)
		if kind != test.kind || content != test.content || valid != test.valid {
			t.Fatalf("classify %q: kind=%q content=%q valid=%v", test.text, kind, content, valid)
		}
	}
}

func TestRouteIntentCreatesIdeaWithoutWorker(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	intent, err := controlPlane.RouteIntent(IntentInput{Text: "想法：比较两种缓存策略"})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status != "resolved" || intent.ResolvedKind != "idea" {
		t.Fatalf("unexpected routed intent: %#v", intent)
	}
	result := decodeIntentResult(t, intent.Result)
	idea, err := controlPlane.Idea(result["idea_id"].(string))
	if err != nil || idea == nil || idea.Description != "比较两种缓存策略" || !strings.HasPrefix(idea.Source, "intent:") {
		t.Fatalf("routed idea missing: %#v err=%v", idea, err)
	}
	if goals, err := controlPlane.Goals(); err != nil || len(goals) != 0 {
		t.Fatalf("capturing an idea started execution: %#v err=%v", goals, err)
	}
}

func TestRouteQuestionCreatesReadOnlyGoal(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	intent, err := controlPlane.RouteIntent(IntentInput{Text: "Which implementation has stronger evidence?"})
	if err != nil {
		t.Fatal(err)
	}
	if intent.ResolvedKind != "question" || intent.Status != "resolved" {
		t.Fatalf("unexpected question intent: %#v", intent)
	}
	result := decodeIntentResult(t, intent.Result)
	goal := waitTestGoal(t, controlPlane, result["goal_id"].(string))
	if !strings.Contains(goal.Constraints, "Do not modify") || goal.Status != "completed" {
		t.Fatalf("question goal was not constrained: %#v", goal)
	}
}

func TestRouteIntentRequestsMissingCommandTarget(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	intent, err := controlPlane.RouteIntent(IntentInput{Text: "command: rerun the benchmark"})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status != "needs_input" || intent.ResolvedKind != "command" || !strings.Contains(intent.Question, "target_id") {
		t.Fatalf("missing command target did not request input: %#v", intent)
	}
	stored, err := controlPlane.Intent(intent.ID)
	if err != nil || stored == nil || stored.Status != "needs_input" {
		t.Fatalf("clarification was not durable: %#v err=%v", stored, err)
	}
}

func TestRouteIntentPersistsDispatchFailure(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	intent, err := controlPlane.RouteIntent(IntentInput{
		Text: "rerun the benchmark", Kind: "command", TargetID: "goal_missing",
	})
	if err == nil || intent == nil || intent.Status != "failed" || intent.Error == "" {
		t.Fatalf("dispatch failure was not retained: intent=%#v err=%v", intent, err)
	}
}

func decodeIntentResult(t *testing.T, data json.RawMessage) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
