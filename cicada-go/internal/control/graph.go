package control

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// evaluateParentGoals lets a monitor-only Goal act as a durable coordinator.
// Child Goals keep their own workers and workspaces; the parent only publishes
// a result after every child reaches a terminal state.
func (c *Control) evaluateParentGoals() {
	goals, err := c.store.ListGoals()
	if err != nil {
		return
	}
	for _, parent := range goals {
		if parent.Status != "running" || parent.MonitorID == "" {
			continue
		}
		workers, workerErr := c.store.ListWorkersForGoal(parent.ID)
		if workerErr != nil || len(workers) != 0 {
			continue
		}
		c.completeParentIfReady(&parent)
	}
}

func (c *Control) completeParentIfReady(parent *store.Goal) {
	children, err := c.store.ListChildGoals(parent.ID)
	if err != nil || len(children) == 0 {
		return
	}
	failed := false
	for _, child := range children {
		switch child.Status {
		case "completed", "cancelled":
		case "failed":
			failed = true
		default:
			return
		}
	}
	status := "completed"
	eventType := "ParentGoalCompleted"
	if failed {
		status = "failed"
		eventType = "ParentGoalFailed"
	}
	summary := childSummary(children)
	evidence := childEvidence(children)
	_, _ = c.store.AppendEvent(parent.ID, "", eventType, map[string]any{
		"children": len(children), "status": status,
	})
	if _, err := c.store.UpdateGoalDetails(parent.ID, status, summary, status, summary, evidence); err != nil {
		return
	}
	if failed {
		c.notify(parent.ID, "goal.children_failed", "P0", "Child goal failed", summary)
	} else {
		c.notify(parent.ID, "goal.completed", "P2", "Goal completed", summary)
	}
}

func childSummary(children []store.Goal) string {
	parts := make([]string, 0, len(children))
	for _, child := range children {
		value := strings.TrimSpace(child.Summary)
		if value == "" {
			value = child.Status
		}
		parts = append(parts, child.ID+": "+value)
	}
	return strings.Join(parts, "\n\n")
}

func childEvidence(children []store.Goal) []any {
	evidence := make([]any, 0, len(children))
	for _, child := range children {
		evidence = append(evidence, map[string]any{
			"goal_id": child.ID, "status": child.Status, "summary": child.Summary,
		})
	}
	return evidence
}
