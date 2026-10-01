package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
)

func TestFabricOnlyManagementRoutesFailClosed(t *testing.T) {
	handler := server.NewFabricHandler(nil, "test-manager")
	for _, path := range []string{"/v1/machines", "/v1/goals", "/v1/approvals", "/v1/identity"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer test-manager")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: %d", path, response.Code)
		}
	}
}

func TestSessionAndNodeCredentialsCannotApproveAsUser(t *testing.T) {
	handler := server.NewFabricHandler(nil, "test-manager")
	for _, authorization := range []string{"CicadaSession cicada_session_actor", "CicadaNode cicada_node_actor"} {
		request := httptest.NewRequest(http.MethodPost, "/v1/approvals/approval-test", strings.NewReader(`{"decision":"approve","user_approved":true,"role":"monitor"}`))
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("peer credential entered approval handler: %d", response.Code)
		}
	}
}

func TestRelayOnlyAgentDoesNotStartBeforeOwnerBinding(t *testing.T) {
	t.Setenv("CICADA_NODE_TOKEN", "must-not-be-used")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	var calls []string
	var hubIdentity machineNodeControlHubIdentity
	var pairingInput machineNodeControlPairingInput
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubIdentity = machineNodeControlHubIdentity{Version: nodewire.Version, Algorithm: e2ee.Algorithm,
		HubID: "synthetic-hub", KeyID: hubKey.Public().ID, KeyVersion: 1,
		Fingerprint: nodewire.IdentityFingerprint(hubKey.Public()), PublicIdentity: hubKey.Public()}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v2/node/identity":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
				t.Errorf("public Node-Control identity request carried credentials: method=%s auth=%q",
					r.Method, r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(hubIdentity); err != nil {
				t.Errorf("encode synthetic Hub identity: %v", err)
			}
		case "/v2/relay/nodes/test-node/events":
			if r.Method != http.MethodGet || !strings.HasPrefix(r.Header.Get("Authorization"), "CicadaNode ") || r.Header.Get("Authorization") == "CicadaNode must-not-be-used" {
				t.Errorf("agent did not use its locally generated Node credential: %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/v2/nodes/device-code":
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
				t.Errorf("unauthenticated enrollment had Authorization: %q", r.Header.Get("Authorization"))
			}
			if err := json.NewDecoder(r.Body).Decode(&pairingInput); err != nil || pairingInput.NodeID != "test-node" ||
				pairingInput.NodeName != "test-node" || len(pairingInput.CredentialDigest) != 43 ||
				pairingInput.HubID != hubIdentity.HubID || pairingInput.HubKeyVersion != hubIdentity.KeyVersion ||
				pairingInput.HubFingerprint != hubIdentity.Fingerprint || pairingInput.NodeFingerprint == "" ||
				len(pairingInput.ProofPacket) == 0 {
				t.Errorf("invalid proof-bearing Node-Control enrollment request: %+v err=%v", pairingInput, err)
			}
			w.Header().Set("Content-Type", "application/json")
			candidate := machineNodeControlCandidate{RequestID: "synthetic-pairing-request", Version: 1,
				Mode: "INITIAL", HubID: hubIdentity.HubID, NodeID: pairingInput.NodeID, NodeName: pairingInput.NodeName,
				NodeKeyID: pairingInput.NodePublicIdentity.ID, NodeKeyFingerprint: pairingInput.NodeFingerprint,
				HubNodeControlKeyID: hubIdentity.KeyID, HubNodeControlKeyVersion: hubIdentity.KeyVersion,
				HubNodeControlFingerprint: hubIdentity.Fingerprint, NodeKeyEpoch: 1,
				CandidateDigest: strings.Repeat("a", 64), State: "PENDING",
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)}
			if err := json.NewEncoder(w).Encode(machineNodeControlPairingReply{
				UserCode: "ABCD-EFGH-JKLM", VerificationURI: "/client/device", Candidate: candidate,
			}); err != nil {
				t.Errorf("encode synthetic Node-Control candidate: %v", err)
			}
		case "/v2/node/device-code/synthetic-pairing-request/status":
			// runMachineAgent creates a local random Node credential; the environment
			// token must never be used for an authenticated pairing status request.
			if r.Method != http.MethodGet || r.URL.Query().Get("node_id") != "test-node" ||
				!strings.HasPrefix(r.Header.Get("Authorization"), "CicadaNode ") ||
				r.Header.Get("Authorization") == "CicadaNode must-not-be-used" {
				t.Errorf("pairing status did not use the locally generated Node credential: method=%s query=%s auth=%q",
					r.Method, r.URL.RawQuery, r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNotFound) // No Owner has approved this synthetic candidate.
		default:
			t.Errorf("agent used an unexpected API before binding: %s", r.URL.Path)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer remote.Close()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	err = runMachineAgent([]string{"--id", "test-node", "--control-url", remote.URL, "--state-dir", stateDir, "--once", "--relay-only"})
	if err == nil || !strings.Contains(err.Error(), "explicit Owner approval") {
		t.Fatalf("expected to wait for owner binding, got %v", err)
	}
	wantCalls := []string{
		"GET /v2/relay/nodes/test-node/events",
		"GET /v2/node/identity",
		"GET /v2/relay/nodes/test-node/events",
		"POST /v2/nodes/device-code",
		"GET /v2/node/device-code/synthetic-pairing-request/status",
	}
	if len(calls) != len(wantCalls) {
		t.Fatalf("calls=%v", calls)
	}
	for index := range wantCalls {
		if calls[index] != wantCalls[index] {
			t.Fatalf("call %d=%q, want %q (all calls: %v)", index, calls[index], wantCalls[index], calls)
		}
	}
	if pairingInput.NodeID != "test-node" || pairingInput.HubID != hubIdentity.HubID {
		t.Fatalf("pairing did not bind the local Node and public Hub identity: %#v", pairingInput)
	}
}

func TestMachineAgentRejectsRemoteHTTPHubForNodeCredentials(t *testing.T) {
	err := runMachineAgent([]string{"--id", "test-node", "--control-url", "http://hub.example", "--state-dir", t.TempDir(), "--once", "--relay-only"})
	if err == nil || !strings.Contains(err.Error(), "remote Node enrollment requires an HTTPS Hub URL") {
		t.Fatalf("got %v", err)
	}
}

func TestRetiredThreadAndEndpointCLICommandsAreUnavailable(t *testing.T) {
	for _, command := range []string{"thread", "endpoint"} {
		if err := clientCommand([]string{command, "join"}); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("retired %s command remained available: %v", command, err)
		}
	}
}
