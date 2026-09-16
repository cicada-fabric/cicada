package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestExecuteBrowserActionUsesIsolatedEnvironment(t *testing.T) {
	root := t.TempDir()
	runner := filepath.Join(root, "runner.sh")
	script := "#!/bin/sh\nif [ -n \"$API_KEY\" ] || [ -n \"$CICADA_API_TOKEN\" ]; then exit 3; fi\ninput=$(cat)\nprintf '%s' \"$input\" | grep -q 'example.com/form' || exit 4\nprintf '{\"ok\":true}'\n"
	if err := os.WriteFile(runner, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "profile")
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("API_KEY", "secret")
	t.Setenv("CICADA_API_TOKEN", "token")
	t.Setenv("CICADA_BROWSER_PROFILE_DIR", profile)
	result, err := executeBrowserAction(context.Background(), &store.ExternalAction{
		ID: "action-1", Kind: "authenticated_browser", Method: "POST",
		URL: "https://example.com/form", Payload: json.RawMessage(`{"field":"value"}`),
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(result) || !strings.Contains(string(result), `"ok":true`) {
		t.Fatalf("unexpected runner result: %s", result)
	}
}

func TestExecuteBrowserActionRequiresProfileForSensitiveKinds(t *testing.T) {
	t.Setenv("CICADA_BROWSER_PROFILE_DIR", "")
	_, err := executeBrowserAction(context.Background(), &store.ExternalAction{
		ID: "action-2", Kind: "form_fill", Method: "POST", URL: "https://example.com",
	}, "/bin/true")
	if err == nil || !strings.Contains(err.Error(), "CICADA_BROWSER_PROFILE_DIR") {
		t.Fatalf("missing profile was accepted: %v", err)
	}
}

func TestBrowserActionTimeoutIsBounded(t *testing.T) {
	root := t.TempDir()
	runner := filepath.Join(root, "sleep.sh")
	if err := os.WriteFile(runner, []byte("#!/bin/sh\nsleep 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_BROWSER_TIMEOUT_SECONDS", "1")
	start := time.Now()
	_, err := executeBrowserAction(context.Background(), &store.ExternalAction{
		ID: "action-3", Kind: "browser", Method: "GET", URL: "https://example.com",
	}, runner)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("timeout was not reported: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("runner exceeded bounded timeout: %s", elapsed)
	}
}
