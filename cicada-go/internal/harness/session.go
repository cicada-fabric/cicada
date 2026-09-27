package harness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// SessionContext is the bounded metadata needed to wrap an already-running
// harness session as a Cicada Endpoint. It deliberately contains no prompt,
// conversation history, environment dump, or credential.
type SessionContext struct {
	Harness         string         `json:"harness"`
	NativeSessionID string         `json:"native_session_id"`
	MachineID       string         `json:"machine_id"`
	Workspace       string         `json:"workspace"`
	Owner           string         `json:"owner"`
	Capabilities    map[string]any `json:"capabilities"`
}

// DetectCurrentSession uses harness-provided environment variables. Codex
// exports CODEX_THREAD_ID/CODEX_SESSION_ID inside tool processes, which lets a
// plugin join the exact TUI thread without inspecting its transcript.
func DetectCurrentSession() (SessionContext, error) {
	context := SessionContext{
		Harness:      Canonical(firstEnvironment("CICADA_HARNESS", "CODEX_HARNESS")),
		MachineID:    strings.TrimSpace(os.Getenv("CICADA_MACHINE_ID")),
		Workspace:    strings.TrimSpace(os.Getenv("CICADA_WORKSPACE")),
		Owner:        firstEnvironment("CICADA_OWNER", "USER", "USERNAME"),
		Capabilities: map[string]any{"fabric_tools": true},
	}
	if context.Harness == "" {
		context.Harness = detectHarnessName()
	}
	switch context.Harness {
	case "codex":
		context.NativeSessionID = firstEnvironment("CICADA_NATIVE_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SESSION_ID")
		context.Capabilities["wake"] = "codex_queue"
	case "claude-code":
		context.NativeSessionID = firstEnvironment("CICADA_NATIVE_SESSION_ID", "CLAUDE_SESSION_ID")
		context.Capabilities["wake"] = "poll"
	case "opencode":
		context.NativeSessionID = firstEnvironment("CICADA_NATIVE_SESSION_ID", "OPENCODE_SESSION_ID", "OPENCODE_CONVERSATION_ID")
		context.Capabilities["wake"] = "poll"
	default:
		context.NativeSessionID = firstEnvironment("CICADA_NATIVE_SESSION_ID")
		context.Capabilities["wake"] = "poll"
	}
	if context.NativeSessionID == "" {
		return context, errors.New("could not discover the current native session; set CICADA_NATIVE_SESSION_ID")
	}
	if context.MachineID == "" {
		// Worker installers default to the short hostname as their stable
		// Machine ID. Use the same value in an ordinary TUI so a plugin and the
		// machine agent meet without requiring shell-specific configuration.
		if hostname, err := os.Hostname(); err == nil {
			context.MachineID = strings.TrimSpace(strings.SplitN(hostname, ".", 2)[0])
		}
		if context.MachineID == "" {
			context.MachineID = "worker-local"
		}
	}
	if context.Workspace == "" {
		if workingDirectory, err := os.Getwd(); err == nil {
			context.Workspace = filepath.Clean(workingDirectory)
		}
	}
	return context, nil
}

func detectHarnessName() string {
	if firstEnvironment("CODEX_THREAD_ID", "CODEX_SESSION_ID") != "" || os.Getenv("CODEX_CI") != "" {
		return "codex"
	}
	if os.Getenv("CLAUDE_SESSION_ID") != "" {
		return "claude-code"
	}
	if firstEnvironment("OPENCODE_SESSION_ID", "OPENCODE_CONVERSATION_ID") != "" {
		return "opencode"
	}
	return "codex"
}

func firstEnvironment(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
