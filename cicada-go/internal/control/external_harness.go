package control

import (
	"context"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

func (c *Control) runOptionalHarness(parent context.Context, goal store.Goal, workerID, prompt string) codexResult {
	worker, err := c.store.GetWorker(workerID)
	if err != nil || worker == nil {
		return codexResult{ExitCode: 1, Output: "worker not found"}
	}
	workspace := worker.Workspace
	if workspace == "" {
		workspace = goal.Workspace
	}
	command, err := harness.Command(parent, worker.Harness, prompt, optionalHarnessEnvironment(os.Environ()))
	if err != nil {
		return codexResult{ExitCode: 2, Output: err.Error()}
	}
	command.Dir = workspace
	output := &harness.BoundedOutput{Limit: harness.OutputLimit}
	command.Stdout, command.Stderr = output, output
	waitErr := command.Run()
	summary, sessionID := harness.Result([]byte(output.String()), "")
	if summary == "" {
		summary = readSummary(worker.ResponseFile)
	}
	if summary == "" {
		summary = strings.TrimSpace(output.String())
	}
	if output.Truncated {
		summary += "\n[output truncated at 512 KiB]"
	}
	if err := os.WriteFile(worker.ResponseFile, []byte(summary+"\n"), 0o600); err != nil && waitErr == nil {
		waitErr = err
	}
	if sessionID == "" {
		sessionID = worker.ThreadID
	}
	if waitErr != nil {
		return codexResult{ExitCode: 1, ThreadID: sessionID, Output: tail(summary, 8000), Summary: tail(summary, 16000)}
	}
	if parent.Err() != nil {
		return codexResult{ExitCode: 124, ThreadID: sessionID, Output: tail(summary, 8000), Summary: tail(summary, 16000)}
	}
	return codexResult{ExitCode: 0, ThreadID: sessionID, Output: tail(summary, 8000), Summary: tail(summary, 16000)}
}

func optionalHarnessEnvironment(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "CICADA_API_TOKEN" || name == "CICADA_PEER_RELAY_TOKEN" || name == "CICADA_WEBHOOK_SECRET" || strings.HasPrefix(name, "CICADA_CONNECTOR_SECRET_") || strings.HasSuffix(name, "_BOT_TOKEN") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
