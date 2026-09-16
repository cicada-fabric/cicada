// Package harness contains the small process contract shared by optional
// agent harness adapters. Codex keeps its native app-server/thread path in
// Control; these adapters intentionally expose only bounded stdin/stdout
// execution so a vendor CLI can be replaced without changing Goal state.
package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const OutputLimit = 512 * 1024

type spec struct {
	Name       string
	BinaryEnv  string
	DefaultBin string
	ArgsEnv    string
	DefaultArg []string
}

var specs = map[string]spec{
	"claude-code": {Name: "claude-code", BinaryEnv: "CICADA_CLAUDE_CODE_BIN", DefaultBin: "claude", ArgsEnv: "CICADA_CLAUDE_CODE_ARGS_JSON", DefaultArg: []string{"--print", "--output-format", "json"}},
	"opencode":    {Name: "opencode", BinaryEnv: "CICADA_OPENCODE_BIN", DefaultBin: "opencode", ArgsEnv: "CICADA_OPENCODE_ARGS_JSON", DefaultArg: []string{"run", "--format", "json"}},
	"happy-agent": {Name: "happy-agent", BinaryEnv: "CICADA_HAPPY_AGENT_BIN", DefaultBin: "happy", ArgsEnv: "CICADA_HAPPY_AGENT_ARGS_JSON"},
}

// Canonical normalizes the names exposed in Goal and Machine capabilities.
func Canonical(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "claude", "claude-code", "claude_code":
		return "claude-code"
	case "opencode", "open-code", "open_code":
		return "opencode"
	case "happy", "happy-agent", "happy_agent":
		return "happy-agent"
	default:
		return name
	}
}

func IsOptional(name string) bool {
	_, ok := specs[Canonical(name)]
	return ok
}

func Names() []string { return []string{"claude-code", "opencode", "happy-agent"} }

func Binary(name string) string {
	item, ok := specs[Canonical(name)]
	if !ok {
		return ""
	}
	if value := strings.TrimSpace(os.Getenv(item.BinaryEnv)); value != "" {
		return value
	}
	return item.DefaultBin
}

func Available(name string) bool {
	binary := Binary(name)
	if binary == "" {
		return false
	}
	_, err := exec.LookPath(binary)
	return err == nil
}

// Args reads a JSON argv override. It never invokes a shell and rejects empty
// or excessively large values so an environment setting cannot become an
// unbounded process argument surface.
func Args(name string) ([]string, error) {
	item, ok := specs[Canonical(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported optional harness: %s", name)
	}
	value := strings.TrimSpace(os.Getenv(item.ArgsEnv))
	if value == "" {
		return append([]string(nil), item.DefaultArg...), nil
	}
	var args []string
	if err := json.Unmarshal([]byte(value), &args); err != nil {
		return nil, fmt.Errorf("%s must be a JSON string array: %w", item.ArgsEnv, err)
	}
	if len(args) > 64 {
		return nil, errors.New("optional harness argv must contain at most 64 items")
	}
	for _, arg := range args {
		if strings.TrimSpace(arg) == "" || len(arg) > 4096 {
			return nil, errors.New("optional harness argv items must be non-empty strings under 4 KiB")
		}
	}
	return args, nil
}

func Command(ctx context.Context, name, prompt string, environment []string) (*exec.Cmd, error) {
	name = Canonical(name)
	if !IsOptional(name) {
		return nil, fmt.Errorf("unsupported optional harness: %s", name)
	}
	args, err := Args(name)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, Binary(name), args...)
	command.Env = environment
	command.Stdin = strings.NewReader(prompt)
	return command, nil
}

// Result extracts a session identifier from common JSON-lines responses while
// retaining a bounded textual summary for the normal Worker state machine.
func Result(output []byte, fallback string) (summary, sessionID string) {
	text := strings.TrimSpace(string(output))
	for _, line := range strings.Split(text, "\n") {
		var value map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &value) != nil {
			continue
		}
		for _, key := range []string{"thread_id", "session_id", "conversation_id", "id"} {
			if candidate, ok := value[key].(string); ok && strings.TrimSpace(candidate) != "" {
				sessionID = strings.TrimSpace(candidate)
				break
			}
		}
		for _, key := range []string{"summary", "last_message", "message", "text", "content"} {
			if candidate, ok := value[key].(string); ok && strings.TrimSpace(candidate) != "" {
				summary = strings.TrimSpace(candidate)
				break
			}
		}
	}
	if summary == "" {
		summary = strings.TrimSpace(fallback)
	}
	return limit(summary, 16000), sessionID
}

type BoundedOutput struct {
	mu        sync.Mutex
	data      bytes.Buffer
	Limit     int
	Truncated bool
}

func (b *BoundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.Limit
	if limit <= 0 {
		limit = OutputLimit
	}
	remaining := limit - b.data.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.data.Write(p[:remaining])
			b.Truncated = true
		} else {
			_, _ = b.data.Write(p)
		}
	} else {
		b.Truncated = true
	}
	return len(p), nil
}

func (b *BoundedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

func limit(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
