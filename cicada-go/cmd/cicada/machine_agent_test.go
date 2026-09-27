package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
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

func TestMachineAuthReadsTokenFile(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "control.token")
	if err := os.WriteFile(tokenPath, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", tokenPath)
	request, err := http.NewRequest(http.MethodGet, "https://control.example/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	setMachineAuth(request)
	if got := request.Header.Get("Authorization"); got != "Bearer file-token" {
		t.Fatalf("unexpected machine authorization header: %q", got)
	}
}

func TestMachineNodeAuthReadsDedicatedTokenFile(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "node.token")
	if err := os.WriteFile(tokenPath, []byte("cicada_node_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_TOKEN", "")
	t.Setenv("CICADA_NODE_TOKEN_FILE", tokenPath)
	if got := machineNodeToken(); got != "cicada_node_test" {
		t.Fatalf("node token=%q", got)
	}
}

func TestMachineAgentCreatesAndPersistsNodeCredentialLocally(t *testing.T) {
	stateDir := t.TempDir()
	identity, digest, err := loadOrCreateMachineNodeIdentity(stateDir, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if identity.RelayToken == "" || digest != fabric.HashSessionCredential(identity.RelayToken) {
		t.Fatal("locally generated Node credential or digest is invalid")
	}
	tokenPath := machineNodeCredentialPath(stateDir, "node-a")
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("node credential mode=%#o", info.Mode().Perm())
	}
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil || strings.TrimSpace(string(tokenData)) != identity.RelayToken {
		t.Fatalf("local Node credential file mismatch: err=%v", err)
	}
	identityData, err := os.ReadFile(filepath.Join(machineNodeStateDir(stateDir, "node-a"), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(identityData), identity.RelayToken) || strings.Contains(string(identityData), "relay_token") {
		t.Fatal("identity metadata duplicated the bearer credential")
	}
	reloaded, reloadedDigest, err := loadOrCreateMachineNodeIdentity(stateDir, "node-a")
	if err != nil || reloaded.RelayToken != identity.RelayToken || reloadedDigest != digest {
		t.Fatalf("Node identity did not survive restart: identity=%#v digest=%q err=%v", reloaded, reloadedDigest, err)
	}
}

func TestMachineNodeDeviceCodeRequestSendsOnlyDigestWithoutAuth(t *testing.T) {
	digest := fabric.HashSessionCredential("node bearer secret")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v2/nodes/device-code" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "" {
			t.Errorf("unauthenticated enrollment included Authorization: %q", got)
		}
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&fields); err != nil {
			t.Errorf("decode device-code request: %v", err)
		}
		if len(fields) != 3 || string(fields["node_id"]) != `"node-a"` ||
			string(fields["node_name"]) != `"GPU A"` || string(fields["credential_digest"]) != `"`+digest+`"` {
			t.Errorf("device-code request did not contain only the expected identity digest: %#v", fields)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"user_code":"ABCD-EFGH-JKLM","verification_uri":"/client/device"}`))
	}))
	defer server.Close()
	code, err := requestMachineNodeDeviceCode(context.Background(), server.URL, "node-a", "GPU A", digest)
	if err != nil || code.UserCode != "ABCD-EFGH-JKLM" || code.VerificationURI != "/client/device" {
		t.Fatalf("device-code response=%#v err=%v", code, err)
	}
}

func TestAwaitMachineNodeBindingExplainsPendingAndroidClientFlow(t *testing.T) {
	identityToken, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/events"):
			if got := request.Header.Get("Authorization"); got != "CicadaNode "+identityToken {
				t.Errorf("binding probe authorization=%q", got)
			}
			response.WriteHeader(http.StatusUnauthorized)
		case request.Method == http.MethodPost && request.URL.Path == "/v2/nodes/device-code":
			if got := request.Header.Get("Authorization"); got != "" {
				t.Errorf("device-code authorization=%q", got)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"user_code":"ABCD-EFGH-JKLM","verification_uri":"/client/device"}`))
		default:
			t.Errorf("unexpected route: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	var output strings.Builder
	err = awaitMachineNodeBinding(context.Background(), server.URL, "node-a", "GPU A", identityToken, digest, true, &output)
	if err == nil || !strings.Contains(err.Error(), "owner confirmation") {
		t.Fatalf("pending binding error=%v", err)
	}
	printed := output.String()
	for _, want := range []string{"Android Client verification path (Client flow pending)", server.URL + "/client/device", "ABCD-EFGH-JKLM"} {
		if !strings.Contains(printed, want) {
			t.Fatalf("pending binding output missing %q: %s", want, printed)
		}
	}
	if strings.Contains(printed, "Open ") || strings.Contains(printed, identityToken) {
		t.Fatalf("pending binding output falsely claims a working Hub page or leaks token: %s", printed)
	}
}

func TestMachineNodeHeartbeatUsesBoundCredentialAndEmptyBody(t *testing.T) {
	token, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v2/relay/nodes/node-a/heartbeat" {
			t.Errorf("unexpected heartbeat route: %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "CicadaNode "+token {
			t.Errorf("heartbeat authorization=%q", got)
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{}` {
			t.Errorf("heartbeat body=%q, want empty object", body)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := sendMachineNodeHeartbeat(context.Background(), server.URL, "node-a", token); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRelayTransportRequiresTLSOutsideLoopback(t *testing.T) {
	for _, test := range []struct {
		url string
		ok  bool
	}{
		{"https://hub.example", true},
		{"http://localhost:8787", true},
		{"http://127.0.0.1:8787", true},
		{"http://hub.example", false},
	} {
		err := requireSecureNodeEnrollmentTransport(test.url)
		if (err == nil) != test.ok {
			t.Errorf("transport policy for %s: err=%v, accepted=%t", test.url, err, err == nil)
		}
	}
}

func TestNodeRelayBearerRequestsRejectRedirects(t *testing.T) {
	token, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		targetHits++
		if got := request.Header.Get("Authorization"); got != "" {
			t.Errorf("Node bearer crossed redirect: %q", got)
		}
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"/capture", http.StatusFound)
	}))
	defer redirect.Close()
	t.Setenv("CICADA_NODE_TOKEN", "")
	tokenFile := filepath.Join(t.TempDir(), "node.token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_TOKEN_FILE", tokenFile)

	if err := sendMachineNodeHeartbeat(context.Background(), redirect.URL, "node-a", token); err == nil {
		t.Fatal("heartbeat accepted a redirect")
	}
	if _, err := streamMachineRelayEvents(context.Background(), redirect.URL, "node-a", make(chan struct{}, 1)); err == nil {
		t.Fatal("event stream accepted a redirect")
	}
	err = machineAPIJSON(context.Background(), redirect.URL+"/v2/relay/nodes/node-a/claim", http.MethodPost,
		map[string]string{"consumer_id": "node-test"}, nil)
	if err == nil {
		t.Fatal("Node relay claim accepted a redirect")
	}
	if targetHits != 0 {
		t.Fatalf("Node bearer redirect target received %d requests", targetHits)
	}
}

func TestMachineAgentAdvertisesOnlyInstalledHarnesses(t *testing.T) {
	t.Setenv("CICADA_CODEX_BIN", filepath.Join(t.TempDir(), "missing-codex"))
	for _, variable := range []string{"CICADA_CLAUDE_CODE_BIN", "CICADA_OPENCODE_BIN", "CICADA_HAPPY_AGENT_BIN"} {
		t.Setenv(variable, filepath.Join(t.TempDir(), "missing-"+variable))
	}
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
		"API_KEY=model-key", "OPENAI_API_KEY=openai-key", "CICADA_API_TOKEN=control-token",
		"CICADA_API_TOKEN_FILE=/etc/cicada/control.token", "CICADA_NODE_TOKEN=node-token",
		"CICADA_NODE_TOKEN_FILE=/etc/cicada/node.token", "PATH=/usr/bin",
	}, true)
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "API_KEY=model-key") || !strings.Contains(joined, "OPENAI_API_KEY=openai-key") {
		t.Fatalf("Codex credentials were removed: %q", joined)
	}
	if strings.Contains(joined, "CICADA_API_TOKEN=") || strings.Contains(joined, "CICADA_API_TOKEN_FILE=") ||
		strings.Contains(joined, "CICADA_NODE_TOKEN=") || strings.Contains(joined, "CICADA_NODE_TOKEN_FILE=") {
		t.Fatalf("Control or Node token reached Codex: %q", joined)
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

func TestRemoteOptionalHarnessExecutesWithBoundedJSONResult(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "goal")
	fake := filepath.Join(root, "claude")
	script := `#!/bin/sh
cat >/dev/null
printf '%s\n' '{"session_id":"claude-session","message":"OPTIONAL_READY"}'
`
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("CICADA_CLAUDE_CODE_BIN", fake)
	t.Setenv("CICADA_CLAUDE_CODE_ARGS_JSON", `[]`)
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "claude", Workspace: workspace, Prompt: "continue",
		ResponseFile: filepath.Join(workspace, ".cicada-last-message"),
	})
	if result.Status != "completed" || result.Summary != "OPTIONAL_READY" || result.ThreadID != "claude-session" {
		t.Fatalf("remote optional harness result=%#v", result)
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
