package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeControlURL(t *testing.T) {
	if got, err := normalizeControlURL(" https://control.example/ "); err != nil || got != "https://control.example" {
		t.Fatalf("normalized URL=%q err=%v", got, err)
	}
	for _, raw := range []string{"control.example", "https://user:pass@control.example", "https://control.example/api"} {
		if _, err := normalizeControlURL(raw); err == nil {
			t.Fatalf("unsafe Control URL was accepted: %q", raw)
		}
	}
}

func TestMachineAgentInterval(t *testing.T) {
	t.Setenv("CICADA_MACHINE_HEARTBEAT_SECONDS", "")
	if got := machineAgentInterval(); got != 30*time.Second {
		t.Fatalf("default interval=%s", got)
	}
}

func TestMachineAgentAdvertisesOnlyInstalledHarnesses(t *testing.T) {
	t.Setenv("CICADA_CODEX_BIN", filepath.Join(t.TempDir(), "missing-codex"))
	if harnesses := discoveredMachineHarnesses(); len(harnesses) != 1 || harnesses[0] != "shell" {
		t.Fatalf("uninstalled Codex was advertised: %v", harnesses)
	}
}

func TestRemoteMachineExecutesShellWithoutControlSecrets(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "goals", "remote-shell")
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("API_KEY", "must-not-reach-worker")
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "shell", Workspace: workspace,
		ResponseFile: filepath.Join(workspace, ".cicada-last-message"),
		Resources: map[string]any{"argv": []any{
			"/bin/sh", "-c", `test -z "$API_KEY" && printf REMOTE_SHELL_READY`,
		}},
	})
	if result.Status != "completed" || result.Summary != "REMOTE_SHELL_READY" {
		t.Fatalf("remote shell result=%#v", result)
	}
}

func TestCodexEnvironmentKeepsModelCredentialsButDropsControlToken(t *testing.T) {
	environment := machineWorkerEnvironment([]string{
		"API_KEY=model-key", "OPENAI_API_KEY=openai-key", "CICADA_API_TOKEN=control-token", "PATH=/usr/bin",
	}, true)
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "API_KEY=model-key") || !strings.Contains(joined, "OPENAI_API_KEY=openai-key") {
		t.Fatalf("Codex credentials were removed: %q", joined)
	}
	if strings.Contains(joined, "CICADA_API_TOKEN=") {
		t.Fatalf("Control token reached Codex: %q", joined)
	}
}

func TestRemoteCodexResumeUsesSupportedCLIArguments(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "goal")
	capture := filepath.Join(root, "args")
	fake := filepath.Join(root, "codex")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$CAPTURE_ARGS"
previous=''
for argument in "$@"; do
  if [ "$previous" = '--output-last-message' ]; then printf 'REMOTE_CODEX_READY\n' > "$argument"; fi
  previous="$argument"
done
printf '{"type":"thread.started","thread_id":"thread-new"}\n'
`
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("CICADA_CODEX_BIN", fake)
	t.Setenv("CAPTURE_ARGS", capture)
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "codex", Workspace: workspace, ThreadID: "thread-old", Prompt: "continue",
		ResponseFile: filepath.Join(workspace, ".cicada-last-message"),
	})
	if result.Status != "completed" || result.Summary != "REMOTE_CODEX_READY" || result.ThreadID != "thread-new" {
		t.Fatalf("remote Codex result=%#v", result)
	}
	arguments, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	got := string(arguments)
	if !strings.HasPrefix(got, "exec\nresume\nthread-old\n") || strings.Contains(got, "\n-C\n") || !strings.Contains(got, "\n--model\ngpt-5.5\n") {
		t.Fatalf("unsupported Codex resume arguments:\n%s", got)
	}
}

func TestRemoteMachineRejectsWorkspaceEscape(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_WORKSPACE_ROOT", filepath.Join(root, "allowed"))
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "shell", Workspace: filepath.Join(root, "outside"),
		ResponseFile: filepath.Join(root, "outside", "result"),
		Resources:    map[string]any{"argv": []any{"/bin/true"}},
	})
	if result.Status != "failed" || !strings.Contains(result.Error, "outside") {
		t.Fatalf("workspace escape was not rejected: %#v", result)
	}
}

func TestRemoteMachineRejectsSymlinkWorkspaceEscape(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "escaped")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_WORKSPACE_ROOT", allowed)
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "shell", Workspace: link,
		Resources: map[string]any{"argv": []any{"/bin/true"}},
	})
	if result.Status != "failed" || !strings.Contains(result.Error, "resolves outside") {
		t.Fatalf("workspace symlink escape was not rejected: %#v", result)
	}
}

func TestRemoteMachinePreparesGitWorkspace(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "goal")
	git := filepath.Join(root, "git")
	script := `#!/bin/sh
set -eu
repository=''
previous=''
for argument in "$@"; do
  if [ "$previous" = '-C' ]; then repository="$argument"; fi
  previous="$argument"
done
case " $* " in
  *' init --quiet '*)
    for argument in "$@"; do target="$argument"; done
    mkdir -p "$target/.git"
    ;;
  *' checkout --quiet '*) printf 'REMOTE_WORKSPACE_READY\n' > "$repository/evidence.txt" ;;
  *' rev-parse HEAD '*) printf 'fedcba9876543210\n' ;;
esac
`
	if err := os.WriteFile(git, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("CICADA_GIT_BIN", git)
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "shell", Workspace: workspace,
		Resources: map[string]any{
			"argv": []any{"/bin/cat", "evidence.txt"},
			"workspace_source": map[string]any{
				"url": "https://93.184.216.34/example/repository.git", "revision": "main",
			},
		},
	})
	if result.Status != "completed" || result.Summary != "REMOTE_WORKSPACE_READY" || result.WorkspaceRevision != "fedcba9876543210" {
		t.Fatalf("remote provisioned result=%#v", result)
	}
}
