package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const markerName = ".cicada-workspace-source.json"

type Prepared struct {
	Source   *Source
	Revision string
	Created  bool
}

type sourceMarker struct {
	Source
	ResolvedRevision string `json:"resolved_revision"`
}

// Prepare materializes a declared workspace source without passing Control or
// model credentials to Git. Existing marked workspaces are resumed in place.
func Prepare(parent context.Context, workspacePath string, resources map[string]any, environment []string) (Prepared, error) {
	source, err := SourceFromResources(resources)
	if err != nil || source == nil {
		return Prepared{Source: source}, err
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	if err := validatePublicGitHost(ctx, source.URL); err != nil {
		return Prepared{Source: source}, err
	}
	path, err := filepath.Abs(strings.TrimSpace(workspacePath))
	if err != nil || strings.TrimSpace(workspacePath) == "" {
		return Prepared{Source: source}, errors.New("workspace path is required")
	}
	if marker, markerErr := readMarker(path); markerErr == nil {
		if marker.URL != source.URL || marker.Revision != source.Revision {
			return Prepared{Source: source}, errors.New("workspace source does not match its existing provenance marker")
		}
		revision, revisionErr := gitOutput(ctx, environment, "-C", path, "rev-parse", "HEAD")
		if revisionErr != nil {
			return Prepared{Source: source}, revisionErr
		}
		return Prepared{Source: source, Revision: revision}, nil
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return Prepared{Source: source}, markerErr
	}
	empty, err := directoryEmpty(path)
	if err != nil {
		return Prepared{Source: source}, err
	}
	if !empty {
		return Prepared{Source: source}, errors.New("workspace source requires an empty directory or a matching provenance marker")
	}
	return cloneWorkspace(ctx, path, *source, environment)
}

func cloneWorkspace(ctx context.Context, target string, source Source, environment []string) (Prepared, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return Prepared{Source: &source}, err
	}
	temporary, err := os.MkdirTemp(filepath.Dir(target), ".cicada-git-")
	if err != nil {
		return Prepared{Source: &source}, err
	}
	defer os.RemoveAll(temporary)
	commands := [][]string{
		{"init", "--quiet", temporary},
		{"-C", temporary, "remote", "add", "origin", source.URL},
		{"-C", temporary, "fetch", "--quiet", "--depth=1", "origin", source.Revision},
		{"-C", temporary, "checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, arguments := range commands {
		if _, err := gitOutput(ctx, environment, arguments...); err != nil {
			return Prepared{Source: &source}, err
		}
	}
	revision, err := gitOutput(ctx, environment, "-C", temporary, "rev-parse", "HEAD")
	if err != nil {
		return Prepared{Source: &source}, err
	}
	marker, err := json.Marshal(sourceMarker{Source: source, ResolvedRevision: revision})
	if err != nil {
		return Prepared{Source: &source}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, markerName), marker, 0o600); err != nil {
		return Prepared{Source: &source}, err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Prepared{Source: &source}, fmt.Errorf("replace empty workspace: %w", err)
	}
	if err := os.Rename(temporary, target); err != nil {
		return Prepared{Source: &source}, err
	}
	return Prepared{Source: &source, Revision: revision, Created: true}, nil
}

func gitOutput(ctx context.Context, environment []string, arguments ...string) (string, error) {
	git := os.Getenv("CICADA_GIT_BIN")
	if git == "" {
		git = "git"
	}
	secure := []string{"-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "-c", "http.followRedirects=false", "-c", "core.hooksPath=/dev/null"}
	command := exec.CommandContext(ctx, git, append(secure, arguments...)...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 5 * time.Second
	command.Env = append(gitEnvironment(environment),
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
	)
	output, err := command.CombinedOutput()
	if len(output) > 64*1024 {
		output = output[len(output)-64*1024:]
	}
	if err != nil {
		return "", fmt.Errorf("git workspace command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func gitEnvironment(environment []string) []string {
	blocked := map[string]bool{
		"API_KEY": true, "OPENAI_API_KEY": true, "CICADA_API_TOKEN": true,
		"CICADA_PEER_RELAY_TOKEN": true, "CICADA_WEBHOOK_SECRET": true,
		"GIT_SSL_NO_VERIFY": true, "GIT_SSL_CAFILE": true, "GIT_SSL_CAINFO": true,
	}
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || blocked[name] || strings.HasPrefix(name, "GIT_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func readMarker(path string) (sourceMarker, error) {
	data, err := os.ReadFile(filepath.Join(path, markerName))
	if err != nil {
		return sourceMarker{}, err
	}
	var marker sourceMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return sourceMarker{}, errors.New("decode workspace provenance marker")
	}
	return marker, nil
}

func directoryEmpty(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return false, err
		}
		return true, nil
	}
	return len(entries) == 0, err
}
