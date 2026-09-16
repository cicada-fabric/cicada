package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/cicada-ai/cicada/internal/store"
)

const shellOutputLimit = 512 * 1024

func shellArgv(value any) ([]string, error) {
	values, ok := value.([]any)
	if !ok {
		if strings, ok := value.([]string); ok {
			values = make([]any, len(strings))
			for index, item := range strings {
				values[index] = item
			}
		} else {
			return nil, errors.New("shell harness requires resources.argv as a string array")
		}
	}
	if len(values) == 0 || len(values) > 128 {
		return nil, errors.New("shell harness argv must contain 1-128 items")
	}
	argv := make([]string, len(values))
	for index, value := range values {
		item, ok := value.(string)
		if !ok || strings.TrimSpace(item) == "" || len(item) > 4096 {
			return nil, errors.New("shell harness argv items must be non-empty strings under 4 KiB")
		}
		argv[index] = item
	}
	return argv, nil
}

func (c *Control) runWorker(parent context.Context, goal store.Goal, workerID, prompt string) codexResult {
	worker, err := c.store.GetWorker(workerID)
	if err != nil || worker == nil {
		return codexResult{ExitCode: 1, Output: "worker not found"}
	}
	if worker.Harness == "shell" {
		return c.runShell(parent, goal, workerID)
	}
	return c.runCodex(parent, goal, workerID, prompt)
}

func (c *Control) runShell(parent context.Context, goal store.Goal, workerID string) codexResult {
	argv, err := shellArgv(goal.Resources["argv"])
	if err != nil {
		return codexResult{ExitCode: 2, Output: err.Error()}
	}
	if _, permissionErr := c.CheckPermission("goal", goal.ID, "shell.execute", argv[0]); permissionErr != nil {
		return codexResult{ExitCode: 126, Output: permissionErr.Error()}
	}
	worker, err := c.store.GetWorker(workerID)
	if err != nil || worker == nil {
		return codexResult{ExitCode: 1, Output: "worker not found"}
	}
	workspace := goal.Workspace
	if worker.Workspace != "" {
		workspace = worker.Workspace
	}
	ctx, cancel := context.WithTimeout(parent, c.config.WorkerTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir = workspace
	command.Env = workerEnvironment(os.Environ())
	output := &boundedOutput{limit: shellOutputLimit}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		return codexResult{ExitCode: 1, Output: err.Error()}
	}
	pid := command.Process.Pid
	_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{PID: &pid})
	waitErr := command.Wait()
	result := strings.TrimSpace(output.String())
	if result == "" {
		result = "Shell command completed without output."
	}
	if output.Truncated() {
		result += "\n[output truncated at 512 KiB]"
	}
	if writeErr := os.WriteFile(worker.ResponseFile, []byte(result), 0o600); writeErr != nil {
		return codexResult{ExitCode: 1, Output: fmt.Sprintf("save shell output: %v", writeErr)}
	}
	exitCode := 0
	if waitErr != nil {
		exitCode = command.ProcessState.ExitCode()
		if exitCode < 0 {
			exitCode = 1
		}
	}
	if ctx.Err() != nil && exitCode == 0 {
		exitCode = 124
	}
	return codexResult{ExitCode: exitCode, Output: result, Summary: result}
}

func workerEnvironment(environment []string) []string {
	blocked := map[string]bool{
		"API_KEY": true, "OPENAI_API_KEY": true, "CICADA_API_TOKEN": true,
		"CICADA_PEER_RELAY_TOKEN": true, "CICADA_WEBHOOK_SECRET": true,
	}
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || blocked[name] {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

type boundedOutput struct {
	mu        sync.Mutex
	data      bytes.Buffer
	limit     int
	truncated bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := output.limit - output.data.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = output.data.Write(data[:remaining])
			output.truncated = true
		} else {
			_, _ = output.data.Write(data)
		}
	} else {
		output.truncated = true
	}
	return len(data), nil
}

func (output *boundedOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.data.String()
}

func (output *boundedOutput) Truncated() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.truncated
}
