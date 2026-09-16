package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	workspaceprep "github.com/cicada-ai/cicada/internal/workspace"
)

func executeMachineJob(parent context.Context, job machineJob) machineJobResult {
	workspace, responseFile, err := machineJobPaths(job)
	if err != nil {
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(parent, machineJobTimeout())
	defer cancel()
	prepared, err := workspaceprep.Prepare(ctx, workspace, job.Resources, machineWorkerEnvironment(os.Environ(), false))
	if err != nil {
		return machineJobResult{Status: "failed", Error: "prepare workspace: " + err.Error()}
	}
	finish := func(result machineJobResult) machineJobResult {
		result.WorkspaceRevision = prepared.Revision
		return result
	}
	switch strings.ToLower(strings.TrimSpace(job.Harness)) {
	case "shell":
		return finish(executeMachineShell(ctx, job, workspace, responseFile))
	case "codex", "":
		return finish(executeMachineCodex(ctx, job, workspace, responseFile))
	default:
		return machineJobResult{Status: "failed", Error: "unsupported harness: " + job.Harness}
	}
}

func machineJobPaths(job machineJob) (string, string, error) {
	if strings.TrimSpace(job.Workspace) == "" {
		return "", "", errors.New("remote job workspace is required")
	}
	workspace, err := workspaceprep.ResolveWithin(envOr("CICADA_WORKSPACE_ROOT", "/workspace"), job.Workspace)
	if err != nil {
		return "", "", err
	}
	responseFile := filepath.Join(workspace, ".cicada-last-message")
	if err := os.Remove(responseFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	return workspace, responseFile, nil
}

func executeMachineShell(ctx context.Context, job machineJob, workspace, responseFile string) machineJobResult {
	argv, err := machineShellArgv(job.Resources["argv"])
	if err != nil {
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
	output := &machineBoundedOutput{limit: 512 * 1024}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir, command.Env = workspace, machineWorkerEnvironment(os.Environ(), false)
	command.Stdout, command.Stderr = output, output
	waitErr := command.Run()
	summary := strings.TrimSpace(output.String())
	if summary == "" {
		summary = "Shell command completed without output."
	}
	if output.truncated {
		summary += "\n[output truncated at 512 KiB]"
	}
	_ = os.WriteFile(responseFile, []byte(summary+"\n"), 0o600)
	if waitErr != nil {
		return machineJobResult{Status: "failed", Summary: summary, Error: waitErr.Error()}
	}
	if ctx.Err() != nil {
		return machineJobResult{Status: "failed", Summary: summary, Error: ctx.Err().Error()}
	}
	return machineJobResult{Status: "completed", Summary: summary}
}

func executeMachineCodex(ctx context.Context, job machineJob, workspace, responseFile string) machineJobResult {
	args := []string{"exec"}
	if job.ThreadID != "" {
		args = append(args, "resume", job.ThreadID, "--skip-git-repo-check")
	} else {
		args = append(args, "--skip-git-repo-check")
	}
	args = append(args, "--model", "gpt-5.5", "--json", "--output-last-message", responseFile, "-")
	command := exec.CommandContext(ctx, envOr("CICADA_CODEX_BIN", "codex"), args...)
	command.Dir = workspace
	command.Env = append(machineWorkerEnvironment(os.Environ(), true), "CODEX_HOME="+envOr("CODEX_HOME", "/state"))
	command.Stdin = strings.NewReader(job.Prompt)
	output := &machineBoundedOutput{limit: 512 * 1024}
	command.Stdout, command.Stderr = output, output
	waitErr := command.Run()
	threadID := job.ThreadID
	for _, line := range strings.Split(output.String(), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &event) == nil && event["type"] == "thread.started" {
			threadID, _ = event["thread_id"].(string)
		}
	}
	summary := readMachineSummary(responseFile)
	if summary == "" {
		summary = strings.TrimSpace(output.String())
	}
	if waitErr != nil {
		return machineJobResult{Status: "failed", Summary: limitText(summary, 16000), ThreadID: threadID, Error: waitErr.Error()}
	}
	if ctx.Err() != nil {
		return machineJobResult{Status: "failed", Summary: limitText(summary, 16000), ThreadID: threadID, Error: ctx.Err().Error()}
	}
	return machineJobResult{Status: "completed", Summary: limitText(summary, 16000), ThreadID: threadID}
}

func readMachineSummary(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
