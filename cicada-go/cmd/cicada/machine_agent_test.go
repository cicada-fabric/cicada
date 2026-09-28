package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodelock"
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

func TestMachineAgentRejectsDuplicateBeforeCreatingNodeIdentity(t *testing.T) {
	stateDir := t.TempDir()
	const nodeID = "node-duplicate-lock-test"
	held, err := nodelock.AcquireAgent(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	err = runMachineAgent([]string{"--id", nodeID, "--name", nodeID, "--state-dir", stateDir,
		"--control-url", server.URL, "--interval", "1s", "--once"})
	if !errors.Is(err, nodelock.ErrAgentRunning) {
		t.Fatalf("duplicate Agent error=%v, want ErrAgentRunning", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("duplicate Agent made %d Hub requests", requests.Load())
	}
	if _, err := os.Stat(machineNodeStateDir(stateDir, nodeID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("duplicate Agent created its Node subtree before rejecting: %v", err)
	}
}

func TestMachineAgentRefusesPendingRecoveryBeforeIdentityOrNetwork(t *testing.T) {
	stateDir := t.TempDir()
	const nodeID = "node-recovery-lock-test"
	nodeDir := machineNodeStateDir(stateDir, nodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(nodeDir, machineNodeRecoveryPendingFileName)
	if err := os.WriteFile(marker, []byte(`{"version":1,"recovery_status":"pending"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	err := runMachineAgent([]string{"--id", nodeID, "--name", nodeID, "--state-dir", stateDir,
		"--control-url", server.URL, "--interval", "1s", "--once"})
	if err == nil || !strings.Contains(err.Error(), "recovery is pending") {
		t.Fatalf("pending recovery error=%v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("Agent made %d Hub requests before rejecting pending recovery", requests.Load())
	}
	for _, path := range []string{filepath.Join(nodeDir, "identity.json"),
		machineNodeCredentialPath(stateDir, nodeID), machineNodeInboxPath(stateDir, nodeID)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pending recovery startup created %s: %v", path, err)
		}
	}
}

func TestMachineAgentRefusesRestoredNodeWhenInTreeMarkerIsMissing(t *testing.T) {
	root := t.TempDir()
	const nodeID = "node-recovery-registry-test"
	sourceStateDir := filepath.Join(root, "source-state")
	sourceNodeDir := machineNodeStateDir(sourceStateDir, nodeID)
	if err := os.MkdirAll(sourceNodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceNodeDir, "identity.json"), []byte("synthetic Node identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, "backup")
	if _, err := nodebackup.Backup(sourceStateDir, nodeID, backupDir); err != nil {
		t.Fatalf("create Node backup fixture: %v", err)
	}
	stateDir := filepath.Join(root, "restored-state")
	restored, err := nodebackup.Restore(backupDir, stateDir)
	if err != nil {
		t.Fatalf("restore Node backup fixture: %v", err)
	}
	if err := os.Remove(filepath.Join(restored.NodeState, machineNodeRecoveryPendingFileName)); err != nil {
		t.Fatalf("remove in-tree marker to simulate marker loss: %v", err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	err = runMachineAgent([]string{"--id", nodeID, "--name", nodeID, "--state-dir", stateDir,
		"--control-url", server.URL, "--interval", "1s", "--once"})
	if err == nil || !strings.Contains(err.Error(), "recovery is pending") {
		t.Fatalf("restored Agent error=%v, want recovery quarantine", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("restored Agent made %d Hub requests before refusing quarantine", requests.Load())
	}
	for _, path := range []string{machineNodeCredentialPath(stateDir, nodeID), machineNodeInboxPath(stateDir, nodeID)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("quarantined startup created %s: %v", path, err)
		}
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

func TestMachineNodeWorkerAPIRejectsWrongCredentialWithoutGlobalFallback(t *testing.T) {
	t.Setenv("CICADA_API_TOKEN", "legacy-global-token")
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestCount++
		if request.Method != http.MethodGet || request.URL.Path != "/v2/relay/nodes/node-a/jobs" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "CicadaNode wrong-node-token" {
			t.Errorf("wrong credential request authorization=%q", got)
		}
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte("revoked Node credential"))
	}))
	defer server.Close()

	var payload struct {
		Jobs []machineJob `json:"jobs"`
	}
	err := machineNodeAPIJSON(context.Background(), nodeWorkerJobsEndpoint(server.URL, "node-a"),
		http.MethodGet, "wrong-node-token", nil, &payload)
	if !machineAPIHasStatus(err, http.StatusUnauthorized) {
		t.Fatalf("wrong Node credential error=%v", err)
	}
	if requestCount != 1 {
		t.Fatalf("wrong Node credential caused %d requests; it must not retry with the global bearer", requestCount)
	}
}

func TestMachineAgentNodeWorkerNoWorkspaceProtocolSubsetUsesOneCredentialAndFiltersChild(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	const nodeID = "node-worker-a"
	identity, _, err := loadOrCreateMachineNodeIdentity(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	legacyTokenFile := filepath.Join(root, "legacy.token")
	if err := os.WriteFile(legacyTokenFile, []byte("legacy-file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_API_TOKEN", "legacy-global-token")
	t.Setenv("CICADA_API_TOKEN_FILE", legacyTokenFile)
	t.Setenv("CICADA_NODE_TOKEN", "stale-inherited-node-token")
	t.Setenv("CICADA_WORKSPACE_ROOT", filepath.Join(root, "workspaces"))
	t.Setenv("CICADA_CODEX_BIN", filepath.Join(root, "missing-codex"))
	for _, variable := range []string{"CICADA_CLAUDE_CODE_BIN", "CICADA_OPENCODE_BIN", "CICADA_HAPPY_AGENT_BIN"} {
		t.Setenv(variable, filepath.Join(root, "missing-"+variable))
	}

	workspace := filepath.Join(root, "workspaces", "goals", "node-job")
	job := machineJob{
		WorkerID: "worker-a", GoalID: "goal-a", MachineID: nodeID,
		Harness: "shell", Workspace: workspace,
		ResponseFile: filepath.Join(workspace, ".cicada-last-message"),
		Prompt:       "run a bounded shell task", Attempt: 0,
		Resources: map[string]any{"argv": []any{"/bin/sh", "-c",
			`test -z "${CICADA_API_TOKEN:-}" && test -z "${CICADA_API_TOKEN_FILE:-}" && test -z "${CICADA_NODE_TOKEN:-}" && test -z "${CICADA_NODE_TOKEN_FILE:-}" && printf CHILD_CREDENTIALS_FILTERED`}},
	}
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if strings.HasPrefix(request.URL.Path, "/v1/") {
			t.Errorf("Node agent used legacy global-auth route %s", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if got := request.Header.Get("Authorization"); got != "CicadaNode "+identity.RelayToken {
			t.Errorf("Node request %s authorization=%q", request.URL.Path, got)
		}
		switch request.URL.Path {
		case "/v2/relay/nodes/" + nodeID + "/events":
			if request.Method != http.MethodGet {
				t.Errorf("binding probe method=%s", request.Method)
			}
			response.Header().Set("Content-Type", "text/event-stream")
			_, _ = response.Write([]byte("event: ready\ndata: claim\n\n"))
		case "/v2/relay/nodes/" + nodeID + "/heartbeat":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode Node heartbeat: %v", err)
			}
			if len(body) == 0 {
				response.WriteHeader(http.StatusNoContent)
				return
			}
			if body["status"] != "available" {
				t.Errorf("Node availability heartbeat=%#v", body)
			}
			capabilities, _ := body["capabilities"].(map[string]any)
			if capabilities["role"] != "worker" {
				t.Errorf("Node worker capabilities=%#v", capabilities)
			}
			response.WriteHeader(http.StatusNoContent)
		case "/v2/relay/nodes/" + nodeID + "/sealed/claim":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/relay/nodes/" + nodeID + "/group/sealed/claim":
			if request.Method != http.MethodPost {
				t.Errorf("same-Group sealed claim method=%s", request.Method)
			}
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.ConsumerID != machineRelayConsumerID(nodeID) || input.Limit != 50 {
				t.Errorf("same-Group sealed claim=%#v err=%v", input, err)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/relay/nodes/" + nodeID + "/claim":
			if request.Method != http.MethodPost {
				t.Errorf("Relay claim method=%s", request.Method)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/fabric/node/networks/direct/claim":
			if request.Header.Get("Authorization") != "CicadaNode "+identity.RelayToken {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/relay/nodes/" + nodeID + "/jobs":
			if request.Method != http.MethodGet {
				t.Errorf("jobs poll method=%s", request.Method)
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"jobs": []machineJob{job}})
		case "/v2/relay/nodes/" + nodeID + "/jobs/worker-a/claim":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || len(body) != 0 {
				t.Errorf("claim body=%#v err=%v; Node path is the assignment scope", body, err)
			}
			claimed := job
			claimed.Attempt = 1
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(claimed)
		case "/v2/relay/nodes/" + nodeID + "/jobs/worker-a/result":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode Worker result: %v", err)
			}
			if body["attempt"] != float64(1) || body["status"] != "completed" ||
				body["summary"] != "CHILD_CREDENTIALS_FILTERED" {
				t.Errorf("Worker result=%#v", body)
			}
			if _, exists := body["machine_id"]; exists {
				t.Errorf("Worker result supplied its own machine scope: %#v", body)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"worker-a","status":"completed"}`))
		default:
			t.Errorf("unexpected Node API route: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	if err := runMachineAgent([]string{"--id", nodeID, "--name", "Worker A", "--control-url", server.URL,
		"--state-dir", stateDir, "--interval", "1h", "--once"}); err != nil {
		t.Fatalf("run machine agent: %v", err)
	}
	if len(paths) < 6 {
		t.Fatalf("Worker chain made too few Node API requests: %v", paths)
	}
}

func TestMachineAgentStopsWhenBoundNodeCredentialIsRevoked(t *testing.T) {
	stateDir := t.TempDir()
	const nodeID = "node-revoked-a"
	identity, _, err := loadOrCreateMachineNodeIdentity(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_API_TOKEN", "legacy-global-token")
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if got := request.Header.Get("Authorization"); got != "CicadaNode "+identity.RelayToken {
			t.Errorf("Node request authorization=%q", got)
		}
		switch request.URL.Path {
		case "/v2/relay/nodes/" + nodeID + "/events":
			response.Header().Set("Content-Type", "text/event-stream")
			_, _ = response.Write([]byte("event: ready\ndata: claim\n\n"))
		case "/v2/relay/nodes/" + nodeID + "/heartbeat":
			response.WriteHeader(http.StatusNoContent)
		case "/v2/relay/nodes/" + nodeID + "/sealed/claim":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/relay/nodes/" + nodeID + "/group/sealed/claim":
			if request.Method != http.MethodPost {
				t.Errorf("same-Group sealed claim method=%s", request.Method)
			}
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.ConsumerID != machineRelayConsumerID(nodeID) || input.Limit != 50 {
				t.Errorf("same-Group sealed claim=%#v err=%v", input, err)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/relay/nodes/" + nodeID + "/claim":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/fabric/node/networks/direct/claim":
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case "/v2/relay/nodes/" + nodeID + "/jobs":
			response.WriteHeader(http.StatusUnauthorized)
			_, _ = response.Write([]byte("Node credential revoked"))
		default:
			if strings.HasPrefix(request.URL.Path, "/v1/") {
				t.Errorf("revoked Node token fell back to legacy route %s", request.URL.Path)
			}
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	err = runMachineAgent([]string{"--id", nodeID, "--name", "Revoked Node", "--control-url", server.URL,
		"--state-dir", stateDir, "--interval", "1h", "--once"})
	if !machineAPIHasStatus(err, http.StatusUnauthorized) || !strings.Contains(err.Error(), "stopping machine agent") {
		t.Fatalf("revoked Node credential did not stop the agent: %v", err)
	}
	for _, path := range paths {
		if strings.HasPrefix(path, "/v1/") {
			t.Fatalf("revoked Node credential fell back to %s", path)
		}
	}
}

func TestMachineAgentRejectsWorkspaceSnapshotWithoutWorkspaceIdentity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	result := executeMachineJobWithHeartbeats(context.Background(), "https://hub.example", "node-a", "node-token", time.Second, machineJob{
		WorkspaceSnapshotDigest: "snapshot-digest", Workspace: filepath.Join(root, "goal-a"),
	})
	if result.Status != "failed" || !strings.Contains(result.Error, "workspace ID") {
		t.Fatalf("workspace task did not reject absent identity: %#v", result)
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
printf '{"type":"thread.started","thread_id":"thread-old"}\n'
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
	if result.Status != "completed" || result.Summary != "REMOTE_CODEX_READY" || result.ThreadID != "thread-old" {
		t.Fatalf("remote Codex result=%#v", result)
	}
	arguments, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	got := string(arguments)
	if !strings.HasPrefix(got, "exec\nresume\nthread-old\n") || strings.Contains(got, "\n-C\n") || !strings.Contains(got, "\n--model\ngpt-5.6-luna\n") {
		t.Fatalf("unsupported Codex resume arguments:\n%s", got)
	}
}

func TestRemoteCodexResumeRejectsDifferentNativeThread(t *testing.T) {
	root := t.TempDir()
	fake := filepath.Join(root, "codex")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"thread-new\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	t.Setenv("CICADA_CODEX_BIN", fake)
	result := executeMachineJob(context.Background(), machineJob{
		Harness: "codex", Workspace: filepath.Join(root, "goal"), ThreadID: "thread-old", Prompt: "continue",
	})
	if result.Status != "failed" || result.ThreadID != "thread-old" ||
		!strings.Contains(result.Error, "different native thread") {
		t.Fatalf("different native session was treated as a successful resume: %#v", result)
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
func TestMachineJobPathsUseNodeLocalWorkspaceID(t *testing.T) {
	root := t.TempDir()
	nodeRoot := filepath.Join(root, "node-workspaces")
	t.Setenv("CICADA_WORKSPACE_ROOT", nodeRoot)
	job := machineJob{WorkspaceID: "ws-test-123", Workspace: "/hub/private/goals/goal-test"}
	workspace, responseFile, err := machineJobPaths(job)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(nodeRoot, "workspaces", "ws-test-123")
	if workspace != want || responseFile != filepath.Join(want, ".cicada-last-message") {
		t.Fatalf("Node used the Hub filesystem path: workspace=%q response=%q", workspace, responseFile)
	}
	for _, invalid := range []string{"../escape", "/absolute", "nested/child", `nested\child`, ".", ".."} {
		job.WorkspaceID = invalid
		if _, _, err := machineJobPaths(job); err == nil {
			t.Fatalf("accepted unsafe Workspace ID %q", invalid)
		}
	}
}
