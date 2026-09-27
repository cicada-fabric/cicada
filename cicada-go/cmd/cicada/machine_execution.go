package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
	workspaceprep "github.com/cicada-ai/cicada/internal/workspace"
)

func executeMachineJob(parent context.Context, job machineJob) machineJobResult {
	return executeMachineJobWithApproval(parent, job, nil)
}

func executeMachineJobWithApproval(parent context.Context, job machineJob, approval *machineApprovalBridge) machineJobResult {
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
	switch harness.Canonical(job.Harness) {
	case "shell":
		return finish(executeMachineShell(ctx, job, workspace, responseFile))
	case "codex", "":
		if approval != nil {
			return finish(executeMachineCodexWithApproval(ctx, job, workspace, responseFile, *approval))
		}
		return finish(executeMachineCodex(ctx, job, workspace, responseFile))
	case "claude-code", "opencode", "happy-agent":
		return finish(executeMachineOptionalHarness(ctx, job, workspace, responseFile))
	default:
		return machineJobResult{Status: "failed", Error: "unsupported harness: " + job.Harness}
	}
}

func executeMachineOptionalHarness(ctx context.Context, job machineJob, workspace, responseFile string) machineJobResult {
	command, err := harness.Command(ctx, job.Harness, job.Prompt, machineWorkerEnvironment(os.Environ(), true))
	if err != nil {
		return machineJobResult{Status: "failed", Error: err.Error()}
	}
	command.Dir = workspace
	output := &harness.BoundedOutput{Limit: harness.OutputLimit}
	command.Stdout, command.Stderr = output, output
	waitErr := command.Run()
	summary, sessionID := harness.Result([]byte(output.String()), "")
	if summary == "" {
		summary = readMachineSummary(responseFile)
	}
	if summary == "" {
		summary = strings.TrimSpace(output.String())
	}
	if output.Truncated {
		summary += "\n[output truncated at 512 KiB]"
	}
	_ = os.WriteFile(responseFile, []byte(summary+"\n"), 0o600)
	if sessionID == "" {
		sessionID = job.ThreadID
	}
	if waitErr != nil {
		return machineJobResult{Status: "failed", Summary: limitText(summary, 16000), ThreadID: sessionID, Error: waitErr.Error()}
	}
	if ctx.Err() != nil {
		return machineJobResult{Status: "failed", Summary: limitText(summary, 16000), ThreadID: sessionID, Error: ctx.Err().Error()}
	}
	return machineJobResult{Status: "completed", Summary: limitText(summary, 16000), ThreadID: sessionID}
}

func machineJobPaths(job machineJob) (string, string, error) {
	root := envOr("CICADA_WORKSPACE_ROOT", "/workspace")
	path := job.Workspace
	if job.WorkspaceID != "" {
		// Hub and Node do not share a filesystem. The authenticated Workspace ID
		// names the Node-local copy; the Hub's absolute path is never executed.
		if job.WorkspaceID == "." || job.WorkspaceID == ".." ||
			filepath.Base(job.WorkspaceID) != job.WorkspaceID ||
			strings.ContainsAny(job.WorkspaceID, `/\\`) {
			return "", "", errors.New("invalid remote workspace ID")
		}
		path = filepath.Join(root, "workspaces", job.WorkspaceID)
	} else if strings.TrimSpace(path) == "" {
		return "", "", errors.New("remote job workspace is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", "", err
	}
	workspace, err := workspaceprep.ResolveWithin(root, path)
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
	args = append(args, "--model", envOr("CICADA_CODEX_MODEL", "gpt-5.6-luna"), "--json", "--output-last-message", responseFile, "-")
	command := exec.CommandContext(ctx, envOr("CICADA_CODEX_BIN", "codex"), args...)
	command.Dir = workspace
	command.Env = append(machineWorkerEnvironment(os.Environ(), true), "CODEX_HOME="+envOr("CODEX_HOME", "/state"))
	command.Stdin = strings.NewReader(job.Prompt)
	output := &machineBoundedOutput{limit: 512 * 1024}
	command.Stdout, command.Stderr = output, output
	waitErr := command.Run()
	threadID := job.ThreadID
	observedThread := false
	for _, line := range strings.Split(output.String(), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &event) == nil && event["type"] == "thread.started" {
			threadID, _ = event["thread_id"].(string)
			observedThread = true
		}
	}
	if job.ThreadID != "" && (!observedThread || threadID != job.ThreadID) {
		return machineJobResult{Status: "failed", ThreadID: job.ThreadID,
			Error: "Codex resumed a different native thread"}
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
