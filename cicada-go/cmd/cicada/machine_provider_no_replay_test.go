package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type providerNoReplayFixture struct {
	c      *control.Control
	http   *httptest.Server
	client *machineNodeControlClient
	ctx    context.Context
	token  string
	ledger *nodeinbox.ProviderAdmissionLedger
	root   string
	owner  string
}

func newProviderNoReplayFixture(t *testing.T) providerNoReplayFixture {
	t.Helper()
	root := t.TempDir()
	c, err := control.New(control.Config{StateDir: filepath.Join(root, "hub"),
		WorkspaceRoot: filepath.Join(root, "hub-workspace"), MaxRecoveries: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown(context.Background()) })
	httpServer := httptest.NewServer(server.NewHandler(c))
	t.Cleanup(httpServer.Close)
	s, err := store.New(filepath.Join(root, "hub", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := c.Identity().ID
	if err := s.EnsureLocalOwnerPrincipal(owner); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal(owner, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hub, err := c.NodeControlPublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(owner, "synthetic-no-replay-device", deviceKey.Public(),
		hub.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := s.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: owner,
		OwnerKeyID: ownerKey.Public().ID, DeviceID: "synthetic-no-replay-device",
		DevicePublic: deviceKey.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	const nodeID = "synthetic-no-replay-node"
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID,
		NodeID: nodeID, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(),
		HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	code, err := c.StartNodeControlDeviceBinding(control.NodeControlDeviceCodeInput{NodeID: nodeID,
		NodeName: "Synthetic no-replay fixture", CredentialDigest: digest, RequestNonce: nonce,
		NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()),
		ProofPacket: proof, HubID: hub.HubID, HubPublicIdentity: hub.PublicIdentity,
		HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := c.PreviewNodeControlDeviceCode(owner, device.DeviceID, code.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := c.ConfirmNodeControlDeviceCode(owner, device.DeviceID, code.UserCode,
		candidate.CandidateDigest, candidate.Version)
	if err != nil {
		t.Fatal(err)
	}
	nodeDir := filepath.Join(root, "node")
	identityPath, statePath := machineNodeControlPaths(nodeDir, nodeID)
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o700); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := node.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistNodeSecretFile(identityPath, keyBytes, ".synthetic-key-"); err != nil {
		t.Fatal(err)
	}
	client, err := openMachineNodeControlClient(nodeDir, httpServer.URL, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { machineNodeControlClients.Delete(statePath) })
	client.state.HubID, client.state.HubKeyID = approved.HubID, hub.PublicIdentity.ID
	client.state.HubPublicIdentity, client.state.HubKeyVersion = hub.PublicIdentity, hub.KeyVersion
	client.state.HubFingerprint = nodewire.IdentityFingerprint(hub.PublicIdentity)
	client.state.NodeKeyID, client.state.NodeKeyFingerprint = node.Public().ID, nodewire.IdentityFingerprint(node.Public())
	client.state.NodeKeyVersion = approved.NodeKeyVersion
	client.state.BindingID, client.state.BindingVersion, client.state.NodeKeyEpoch =
		approved.OwnerBindingID, approved.BindingVersion, approved.NodeKeyEpoch
	if err := client.persistLocked(); err != nil {
		t.Fatal(err)
	}
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(nodeDir, "provider.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ledger.Close() })
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: hub.HubID,
		Origin: httpServer.URL, NodeID: nodeID, StateDir: nodeDir, Token: token,
		WriterRoot: nodeDir, WriterScope: "synthetic-account", ProviderAdmissions: ledger})
	if err := sendMachineNodeWorkerHeartbeat(ctx, httpServer.URL, nodeID, token, "available",
		map[string]any{"harnesses": []string{"codex"}}); err != nil {
		t.Fatal(err)
	}
	return providerNoReplayFixture{c, httpServer, client, ctx, token, ledger, root, owner}
}

func (f providerNoReplayFixture) worker(t *testing.T, id string) store.Worker {
	t.Helper()
	workers, err := f.c.Workers()
	if err != nil {
		t.Fatal(err)
	}
	for _, worker := range workers {
		if worker.ID == id {
			return worker
		}
	}
	t.Fatal("synthetic Worker is missing")
	return store.Worker{}
}

func (f providerNoReplayFixture) claim(t *testing.T, name string) machineJob {
	t.Helper()
	goal, err := f.c.CreateGoalForOwner(f.owner, control.GoalInput{Objective: "synthetic no-replay " + name,
		MachineID: f.client.nodeID, Harness: "codex"})
	if err != nil || goal.Worker == nil {
		t.Fatalf("create synthetic remote Worker: %v", err)
	}
	job, err := claimMachineJob(f.ctx, f.http.URL, f.client.nodeID, f.token,
		machineJob{WorkerID: goal.Worker.ID})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestMachineProviderNoReplayAuthenticatedWorkerResult(t *testing.T) {
	f := newProviderNoReplayFixture(t)
	job := f.claim(t, "post-submission")
	var err error
	job, _, err = prepareMachineNodeClaimExecution(f.ctx, f.client, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.beginClaimExecution(job); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(f.root, "synthetic-native-workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(workspace, "synthetic-codex")
	terminal := syntheticFailedTurn("\"rateLimitExceeded\"", "native-thread-a", "native-turn-a")
	script := "#!/bin/sh\nwhile IFS= read -r line; do\ncase \"$line\" in\n" +
		"*'\"method\":\"initialize\"'*) printf '%s\\n' '{\"id\":1,\"result\":{}}' ;;\n" +
		"*'\"method\":\"thread/start\"'*) printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"native-thread-a\"}}}' ;;\n" +
		"*'\"method\":\"turn/start\"'*) printf '%s\\n' '{\"id\":3,\"result\":{\"turn\":{\"id\":\"native-turn-a\",\"items\":[],\"status\":\"inProgress\"}}}' '" + terminal + "' ;;\nesac\ndone\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", binary)
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	result := executeMachineCodexWithApproval(ctx, job, workspace, filepath.Join(workspace, "response"), machineApprovalBridge{})
	if result.executionState() != "INJECTION_UNCERTAIN" || !result.providerRateLimited {
		t.Fatal("actual child failure did not preserve uncertainty")
	}
	if err := recordMachineNodeProviderOutcome(f.ctx, job, result, f.client); err != nil {
		t.Fatal(err)
	}
	if err := reportMachineJob(f.ctx, f.http.URL, f.client.nodeID, f.token, job, result); err != nil {
		t.Fatal(err)
	}
	saved := f.worker(t, job.WorkerID)
	if saved.Status != "failed" || saved.Attempt != job.Attempt {
		t.Fatal("Hub requeued an uncertain native operation")
	}
	if _, err := claimMachineJob(f.ctx, f.http.URL, f.client.nodeID, f.token, job); err == nil {
		t.Fatal("Hub admitted a new attempt for the uncertain operation")
	}
	original, err := f.ledger.InspectProviderAttempt(f.ctx, nodeinbox.ProviderAdmissionRequest{ExecutionID: job.executionID, ProviderID: job.providerID})
	if err != nil || original.State != nodeinbox.ProviderAdmissionInjectionUncertain || original.Retryable {
		t.Fatal("old execution lost its uncertain tombstone")
	}
}

func TestMachineProviderNoReplayPositiveTrackedPrestart(t *testing.T) {
	f := newProviderNoReplayFixture(t)
	job := f.claim(t, "known prestart")
	var err error
	workspace := filepath.Join(f.root, "synthetic-prestart-workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", filepath.Join(workspace, "missing-owned-binary"))
	for attempt := 1; attempt <= 3; attempt++ {
		job, _, err = prepareMachineNodeClaimExecution(f.ctx, f.client, job)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.client.beginClaimExecution(job); err != nil {
			t.Fatal(err)
		}
		result := executeMachineCodexWithApproval(f.ctx, job, workspace, filepath.Join(workspace, "response"), machineApprovalBridge{})
		if result.executionState() != "NOT_STARTED" || !result.providerStartKnown || result.providerStarted {
			t.Fatal("tracked failed Cmd.Start lacks positive pre-start proof")
		}
		if err := recordMachineNodeProviderOutcome(f.ctx, job, result, f.client); err != nil {
			t.Fatal(err)
		}
		if err := reportMachineJob(f.ctx, f.http.URL, f.client.nodeID, f.token, job, result); err != nil {
			t.Fatal(err)
		}
		next, err := claimMachineJob(f.ctx, f.http.URL, f.client.nodeID, f.token, job)
		if attempt == 3 {
			if err == nil || f.worker(t, job.WorkerID).Status != "failed" {
				t.Fatal("pre-start recovery exceeded MaxRecoveries")
			}
		} else {
			if err != nil || next.Attempt != job.Attempt+1 {
				t.Fatalf("known pre-start refusal lost bounded recovery: %v", err)
			}
			job = next
		}
	}
}

func TestMachineProviderNoReplayMissingAndUnknownOutcome(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "unknown"
		if missing {
			name = "legacy-missing"
		}
		t.Run(name, func(t *testing.T) {
			f := newProviderNoReplayFixture(t)
			job := f.claim(t, name)
			var err error
			job, _, err = prepareMachineNodeClaimExecution(f.ctx, f.client, job)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.client.beginClaimExecution(job); err != nil {
				t.Fatal(err)
			}
			result := machineJobResult{Status: "failed", Error: "synthetic untracked harness outcome"}
			if err := recordMachineNodeProviderOutcome(f.ctx, job, result, f.client); err != nil {
				t.Fatal(err)
			}
			payload := machineJobResultPayload(job, result)
			if missing {
				delete(payload, "execution_state")
			}
			if err := machineNodeAPIJSON(f.ctx, nodeWorkerJobEndpoint(f.http.URL, f.client.nodeID, job.WorkerID, "result"),
				http.MethodPost, f.token, payload, nil); err != nil {
				t.Fatal(err)
			}
			if f.worker(t, job.WorkerID).Status != "failed" {
				t.Fatal("unclassified failure was requeued")
			}
			if _, err := claimMachineJob(f.ctx, f.http.URL, f.client.nodeID, f.token, job); err == nil {
				t.Fatal("unclassified failure was reclaimed")
			}
		})
	}
}

func TestMachineProviderExecutionStateDefaultIsNotProof(t *testing.T) {
	for _, item := range []struct {
		name   string
		result machineJobResult
		state  string
	}{
		{"untracked", machineJobResult{Status: "failed"}, "UNKNOWN"},
		{"partial-start", machineJobResult{Status: "failed", providerStarted: true}, "INJECTION_UNCERTAIN"},
		{"stop-unknown", machineJobResult{Status: "failed", providerStartKnown: true, ResourceStopState: "UNVERIFIED"}, "INJECTION_UNCERTAIN"},
		{"tracked-prestart", machineJobResult{Status: "failed", providerStartKnown: true}, "NOT_STARTED"},
		{"verified-business", machineJobResult{Status: "completed", ResourceStopState: "UNVERIFIED"}, "COMPLETED"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if machineJobResultPayload(machineJob{}, item.result)["execution_state"] != item.state {
				t.Fatal("default boolean authorized recovery")
			}
		})
	}
}

// All packets and identities below are synthetic; no untrusted body may mutate
// a Worker simply by naming the positive pre-start state.
func TestMachineProviderNoReplayRejectsForgedState(t *testing.T) {
	f := newProviderNoReplayFixture(t)
	job := f.claim(t, "wire guards")
	for i, item := range []struct {
		name, state, status, thread, stop string
		wrongAttempt, wrongSender         bool
	}{
		{"invalid-enum", "not_started", "failed", "", "", false, false},
		{"state-status", "NOT_STARTED", "completed", "", "", false, false},
		{"completed-failure", "COMPLETED", "failed", "", "", false, false},
		{"state-stop", "NOT_STARTED", "failed", "", "UNVERIFIED", false, false},
		{"foreign-session", "NOT_STARTED", "failed", "foreign-session", "", false, false},
		{"stale-attempt", "NOT_STARTED", "failed", "", "", true, false},
		{"foreign-sender", "NOT_STARTED", "failed", "", "", false, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			attempt := job.Attempt
			if item.wrongAttempt {
				attempt++
			}
			body, _ := json.Marshal(map[string]any{"worker_id": job.WorkerID, "attempt": attempt, "status": item.status,
				"thread_id": item.thread, "execution_state": item.state, "resource_stop_state": item.stop})
			b := f.client.approvedBinding()
			key := f.client.identity
			if item.wrongSender {
				var err error
				key, err = e2ee.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				b.NodeKey = key.Public()
			}
			route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID,
				BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: uint64(100 + i),
				OperationID: "synthetic-invalid-" + item.name, Operation: "node.jobs.result", SenderKeyID: b.NodeKey.ID,
				SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
			packet, err := nodewire.SealRequest(key, b.HubKey, b, route, body)
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v2/node/control/rpc", bytes.NewReader(packet))
			req.Header.Set("Authorization", "CicadaNode "+f.token)
			response, err := f.http.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if item.wrongSender {
				if response.StatusCode != http.StatusForbidden {
					t.Fatal("foreign sender did not fail authentication")
				}
			} else {
				if response.StatusCode != http.StatusOK {
					t.Fatal("valid encrypted request did not reach its outcome guard")
				}
				opened, err := nodewire.OpenResponse(key, b.HubKey, b, data)
				if err != nil {
					t.Fatal(err)
				}
				var reply struct {
					OK        bool
					ErrorCode string `json:"error_code"`
				}
				if err := json.Unmarshal(opened.Plaintext, &reply); err != nil || reply.OK || reply.ErrorCode == "" {
					t.Fatal("invalid outcome was not a signed refusal")
				}
			}
			saved := f.worker(t, job.WorkerID)
			if saved.Status != "running" || saved.Attempt != job.Attempt {
				t.Fatal("forged state changed the matching claim")
			}
		})
	}
}
