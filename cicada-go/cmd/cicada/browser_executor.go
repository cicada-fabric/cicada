package main

import (
	"bytes"
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

	"github.com/cicada-ai/cicada/internal/store"
)

type browserExecutionRequest struct {
	ActionID   string          `json:"action_id"`
	Kind       string          `json:"kind"`
	Method     string          `json:"method"`
	URL        string          `json:"url"`
	Payload    json.RawMessage `json:"payload"`
	ProfileDir string          `json:"profile_dir,omitempty"`
}

func executeBrowserAction(parent context.Context, action *store.ExternalAction, runner string) ([]byte, error) {
	if action == nil || strings.TrimSpace(action.ID) == "" {
		return nil, errors.New("browser action is required")
	}
	runner = strings.TrimSpace(runner)
	if !filepath.IsAbs(runner) {
		return nil, errors.New("browser runner path must be absolute")
	}
	if action.Kind != "browser" && action.Kind != "authenticated_browser" && action.Kind != "form_fill" {
		return nil, fmt.Errorf("unsupported browser action kind: %s", action.Kind)
	}
	profile := strings.TrimSpace(os.Getenv("CICADA_BROWSER_PROFILE_DIR"))
	if action.Kind != "browser" {
		if profile == "" || !filepath.IsAbs(profile) {
			return nil, errors.New("authenticated browser actions require an absolute CICADA_BROWSER_PROFILE_DIR")
		}
		if err := os.MkdirAll(profile, 0o700); err != nil {
			return nil, fmt.Errorf("create browser profile: %w", err)
		}
	}
	home := profile
	cleanup := func() {}
	if home == "" {
		var err error
		home, err = os.MkdirTemp("", "cicada-browser-home-")
		if err != nil {
			return nil, fmt.Errorf("create isolated browser home: %w", err)
		}
		cleanup = func() { _ = os.RemoveAll(home) }
	}
	defer cleanup()
	payload := action.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	requestData, err := json.Marshal(browserExecutionRequest{
		ActionID: action.ID, Kind: action.Kind, Method: action.Method,
		URL: action.URL, Payload: payload, ProfileDir: profile,
	})
	if err != nil {
		return nil, fmt.Errorf("encode browser action: %w", err)
	}
	timeout := browserActionTimeout()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, runner)
	command.Dir = home
	command.Env = browserRunnerEnvironment(home, profile)
	command.Stdin = bytes.NewReader(append(requestData, '\n'))
	stdout := &machineBoundedOutput{limit: 1 << 20}
	stderr := &machineBoundedOutput{limit: 64 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("browser runner timeout after %s", timeout)
		}
		return nil, errors.New("browser runner failed")
	}
	if stdout.truncated {
		return nil, errors.New("browser runner output exceeded 1 MiB")
	}
	result := bytes.TrimSpace([]byte(stdout.String()))
	if len(result) == 0 || !json.Valid(result) {
		return nil, errors.New("browser runner must return one JSON value")
	}
	return result, nil
}

func browserRunnerEnvironment(home, profile string) []string {
	allowed := map[string]bool{
		"PATH": true, "LANG": true, "LC_ALL": true, "LC_CTYPE": true,
		"TZ": true, "DISPLAY": true, "WAYLAND_DISPLAY": true,
		"XDG_RUNTIME_DIR": true, "DBUS_SESSION_BUS_ADDRESS": true,
	}
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if ok && allowed[name] {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "HOME="+home)
	if profile != "" {
		environment = append(environment, "CICADA_BROWSER_PROFILE_DIR="+profile)
	}
	return environment
}

func browserActionTimeout() time.Duration {
	seconds := envInt("CICADA_BROWSER_TIMEOUT_SECONDS", 120)
	if seconds < 1 {
		seconds = 120
	}
	if seconds > 600 {
		seconds = 600
	}
	return time.Duration(seconds) * time.Second
}
