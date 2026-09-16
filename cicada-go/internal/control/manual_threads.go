package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/cicada-ai/cicada/internal/store"
)

type ThreadSessionInput struct {
	ThreadID  string `json:"thread_id"`
	Label     string `json:"label"`
	Workspace string `json:"workspace"`
}

type ThreadQueueInput struct {
	FromThreadID string `json:"from_thread_id"`
	ToThreadID   string `json:"to_thread_id"`
	Message      string `json:"message"`
}

func (c *Control) RegisterThreadSession(input ThreadSessionInput) (*store.ThreadSession, error) {
	threadID := strings.TrimSpace(input.ThreadID)
	if !validThreadID(threadID) {
		return nil, errors.New("thread_id must contain 8-128 letters, numbers, '-' or '_'")
	}
	label := strings.TrimSpace(input.Label)
	if label == "" {
		label = threadID
	}
	if len(label) > 128 {
		return nil, errors.New("thread label is too long")
	}
	workspace := strings.TrimSpace(input.Workspace)
	if workspace != "" {
		var err error
		workspace, err = c.workspacePath(workspace)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(workspace)
		if err != nil {
			return nil, fmt.Errorf("thread workspace: %w", err)
		}
		if !info.IsDir() {
			return nil, errors.New("thread workspace must be a directory")
		}
	}
	return c.store.UpsertThreadSession(threadID, label, workspace, "active")
}

func validThreadID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func (c *Control) ThreadSessions() ([]store.ThreadSession, error) {
	return c.store.ListThreadSessions()
}

func (c *Control) ThreadSession(threadID string) (*store.ThreadSession, error) {
	return c.store.GetThreadSession(strings.TrimSpace(threadID))
}

func (c *Control) ThreadDeliveries(limit int) ([]store.ThreadDelivery, error) {
	return c.store.ListThreadDeliveries(limit)
}

// QueueThreadSessionMessage invokes only the official Codex queue subcommand;
// no shell is involved and the message is retained in a durable audit record.
func (c *Control) QueueThreadSessionMessage(input ThreadQueueInput) (*store.ThreadDelivery, error) {
	fromID := strings.TrimSpace(input.FromThreadID)
	toID := strings.TrimSpace(input.ToThreadID)
	message := strings.TrimSpace(input.Message)
	if !validThreadID(fromID) || !validThreadID(toID) || message == "" {
		return nil, errors.New("valid from_thread_id, to_thread_id, and message are required")
	}
	if fromID == toID {
		return nil, errors.New("thread queue requires two different threads")
	}
	if len(message) > 32*1024 {
		return nil, errors.New("thread message is limited to 32 KiB")
	}
	from, err := c.store.GetThreadSession(fromID)
	if err != nil {
		return nil, err
	}
	to, err := c.store.GetThreadSession(toID)
	if err != nil {
		return nil, err
	}
	if from == nil || to == nil {
		return nil, os.ErrNotExist
	}
	if from.Status != "active" || to.Status != "active" {
		return nil, errors.New("both thread sessions must be active")
	}
	if _, permissionErr := c.CheckPermission("global", "", "thread.queue", toID); permissionErr != nil {
		return nil, permissionErr
	}
	delivery, err := c.store.CreateThreadDelivery(store.ThreadDelivery{
		FromThreadID: fromID, ToThreadID: toID, Message: message,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	binary := strings.TrimSpace(c.config.CodexBinary)
	if binary == "" {
		binary = "codex"
	}
	command := exec.CommandContext(ctx, binary, "queue", "--thread", toID, "--message", message)
	command.Env = append(os.Environ(), "CODEX_HOME="+envOr("CODEX_HOME", "/state"))
	output, commandErr := command.CombinedOutput()
	if commandErr != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		if detail == "" {
			detail = commandErr.Error()
		}
		updated, updateErr := c.store.UpdateThreadDelivery(delivery.ID, "failed", detail)
		if updateErr != nil {
			return nil, updateErr
		}
		return updated, fmt.Errorf("codex queue failed: %s", detail)
	}
	return c.store.UpdateThreadDelivery(delivery.ID, "delivered", "")
}
