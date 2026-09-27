package control

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	maxPromptMemoryItems = 12
	maxPromptMemoryBytes = 12000
)

func (c *Control) memoryContext(goal store.Goal) string {
	memories := make([]store.Memory, 0, maxPromptMemoryItems)
	seen := map[string]bool{}
	for _, scope := range []struct{ name, namespace string }{
		{name: "personal"}, {name: "project", namespace: goal.ID}, {name: "execution", namespace: goal.ID},
	} {
		items, err := c.store.ListMemories(scope.name, scope.namespace)
		if err != nil {
			continue
		}
		for _, item := range items {
			if seen[item.ID] || strings.TrimSpace(item.Content) == "" {
				continue
			}
			seen[item.ID] = true
			memories = append(memories, item)
			if len(memories) >= maxPromptMemoryItems {
				break
			}
		}
		if len(memories) >= maxPromptMemoryItems {
			break
		}
	}
	if len(memories) == 0 {
		return ""
	}
	var builder strings.Builder
	used := 0
	for _, memory := range memories {
		content := truncatePromptMemory(memory.Content, 1800)
		entry := fmt.Sprintf("- [%s/%s, importance=%d] %s\n", memory.Scope, memory.Namespace, memory.Importance, content)
		if used+len(entry) > maxPromptMemoryBytes {
			break
		}
		builder.WriteString(entry)
		used += len(entry)
	}
	return builder.String()
}

func attachmentContext(goal store.Goal) string {
	attachments, ok := goal.Resources["attachments"]
	if !ok || attachments == nil {
		return ""
	}
	data, err := json.Marshal(attachments)
	if err != nil || string(data) == "null" || string(data) == "[]" {
		return ""
	}
	return string(data)
}

func truncatePromptMemory(content string, limit int) string {
	content = strings.TrimSpace(content)
	if len(content) <= limit {
		return content
	}
	return content[:limit] + "…"
}
