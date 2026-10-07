//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// This gate runs the shipped CLI, not a test-executable Agent or echo server.
// The shell driver optionally starts the actual runtime image in the test
// container's network namespace, from this same synthetic fixture request.
func TestPQDistributionActualHubNode(t *testing.T) {
	binary := os.Getenv("PQTLS_TEST_PACKAGE_BINARY")
	if binary == "" {
		t.Skip("optional shipped package was not supplied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	fixture := newMachineSealedReceiveFixtureWithActions(t, false, "ask", []string{"ask", "reply"})
	frontAddress, address := productFreeAddress(t), productFreeAddress(t)
	_, portText, _ := net.SplitHostPort(frontAddress)
	port, _ := strconv.Atoi(portText)
	base := "http://" + frontAddress // Owner-signed isolated logical application origin.
	current := distributionCurrentTLSFixture(t, fixture, address, base)
	t.Log("phase=actual-owner-device-current-TLS-authority-prepared")
	root, hubState := current.root, current.hubState
	diagnosticsDir := filepath.Join(root, "owned-pqtls-diagnostics")
	if err := os.Mkdir(diagnosticsDir, 0700); err != nil {
		t.Fatal("create private diagnostic directory")
	}
	if err := os.Chmod(diagnosticsDir, 0700); err != nil {
		t.Fatal("protect private diagnostic directory")
	}
	mcpDiagnosticPath := filepath.Join(diagnosticsDir, "mcp-client.jsonl")
	t.Setenv("CICADA_PQTLS_DIAGNOSTIC_FILE", mcpDiagnosticPath)
	database := filepath.Join(hubState, "cicada.sqlite3")
	db, err := store.New(database)
	if err != nil {
		t.Fatal("read actual distribution fixture Store")
	}
	defer db.Close()
	hubID := current.hubConfig.Identity.HubID
	hubPath := writeProductPQConfig(t, root, "hub-config", &current.hubConfig)
	var hub *exec.Cmd
	var output distributionOutput
	imageRequest := os.Getenv("PQTLS_TEST_IMAGE_REQUEST")
	if imageRequest != "" {
		request, _ := json.Marshal(map[string]any{"fixture_root": root, "state_dir": hubState, "config": hubPath, "port": port})
		temporary := imageRequest + ".tmp"
		if err := os.WriteFile(temporary, request, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, imageRequest); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(imageRequest) })
		defer func() {
			if err := os.WriteFile(imageRequest+".done", []byte("test body finished\n"), 0600); err != nil {
				t.Error(err)
				return
			}
			for i := 0; i < 150; i++ {
				if _, err := os.Stat(imageRequest + ".stopped"); err == nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Error("runtime image shutdown was not joined before fixture cleanup")
		}()
	} else {
		hub = exec.CommandContext(ctx, binary, "serve", "--fabric-only", "--host", "127.0.0.1", "--port", portText, "--node-pqtls-config", hubPath)
		hub.Env = distributionProcessEnvironment("CICADA_STATE_DIR="+hubState, "CICADA_WORKSPACE_ROOT="+filepath.Join(root, "workspace"))
		hub.Stdout, hub.Stderr = &output, &output
		if err := hub.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = hub.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- hub.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Error("shipped Hub terminal exit", err)
				}
			case <-time.After(12 * time.Second):
				_ = hub.Process.Kill()
				<-done
				t.Error("shipped Hub shutdown timed out")
			}
			t.Logf("shipped Hub transcript_sha256=%x bytes=%d", sha256.Sum256(output.Bytes()), output.Len())
		}()
	}
	ready := false
	for i := 0; i < 200; i++ {
		response, err := (&http.Client{Timeout: 150 * time.Millisecond}).Get(base + "/healthz")
		if err == nil {
			var health map[string]any
			err = json.NewDecoder(response.Body).Decode(&health)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				t.Fatal("shipped Hub health response invalid")
			}
			if expected := os.Getenv("PQTLS_TEST_EXPECTED_SOURCE_FINGERPRINT"); expected != "" && health["source_fingerprint"] != expected {
				t.Fatal("shipped Hub provenance mismatch")
			}
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("shipped Hub startup timeout")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatalf("shipped Hub did not become ready; transcript_sha256=%x bytes=%d", sha256.Sum256(output.Bytes()), output.Len())
	}
	t.Log("phase=actual-distribution-hub-ready")
	observeIdle := os.Getenv("PQTLS_TEST_OBSERVE_IDLE") == "1"
	var idleChildren []*exec.Cmd
	var idleLogs []*distributionOutput
	stopIdle := func() {
		for i, child := range idleChildren {
			_ = child.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Error("idle shipped Node terminal exit", err)
				}
			case <-time.After(6 * time.Second):
				_ = child.Process.Kill()
				<-done
				t.Error("idle shipped Node shutdown timeout")
			}
			t.Logf("idle shipped Node transcript_sha256=%x bytes=%d", sha256.Sum256(idleLogs[i].Bytes()), idleLogs[i].Len())
		}
		idleChildren = nil
	}
	defer stopIdle()
	makeNode := func(nodeID string) {
		f := current.nodes[nodeID]
		path := distributionActiveConfigPath(f)
		args := []string{"machine", "agent", "--id", nodeID, "--control-url", base, "--state-dir", f.StateRoot, "--pqtls-config", path, "--relay-only"}
		child := exec.CommandContext(ctx, binary, args...)
		diagnosticPath := filepath.Join(diagnosticsDir, "node-"+nodeID+".jsonl")
		child.Env = distributionProcessEnvironment("CICADA_HUB_ID="+hubID, "CICADA_PQTLS_DIAGNOSTIC_FILE="+diagnosticPath)
		log := new(distributionOutput)
		child.Stdout, child.Stderr = log, log
		if err := child.Start(); err != nil {
			t.Fatal("start actual shipped Node Agent")
		}
		idleChildren = append(idleChildren, child)
		idleLogs = append(idleLogs, log)

	}
	// Both actual Agent processes run before enqueue; no native/model consumption.
	makeNode(fixture.sourceNodeID)
	makeNode(fixture.targetNodeID)
	// --once returns before the resident Relay SSE worker starts. Both actual
	// Agents must observe ready before safe stop/join releases their locks.
	readyDeadline := time.Now().Add(15 * time.Second)
	for {
		allReady := true
		for _, nodeID := range []string{fixture.sourceNodeID, fixture.targetNodeID} {
			ready, err := distributionNodeRelayReady(filepath.Join(diagnosticsDir, "node-"+nodeID+".jsonl"))
			if err != nil {
				t.Fatal("invalid bounded synthetic Node readiness diagnostic")
			}
			allReady = allReady && ready
		}
		if !time.Now().Before(readyDeadline) {
			t.Fatal("actual Node Relay ready deadline exceeded")
		}
		if ctx.Err() != nil {
			t.Fatal("actual Node Relay ready parent deadline exceeded")
		}
		if allReady {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual Node Relay ready parent deadline exceeded")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if observeIdle {
		time.Sleep(3 * time.Second)
		if imageRequest != "" {
			if err := os.WriteFile(imageRequest+".memory-ready", []byte("two live idle Agents\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		var samples []map[string]any
		for i := 0; i < 4; i++ {
			rows := []map[string]any{}
			for _, child := range idleChildren {
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", child.Process.Pid))
				if err != nil {
					t.Fatal("idle Agent did not remain alive", err)
				}
				row := map[string]any{"pid": child.Process.Pid}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "VmRSS:") {
						row["VmRSS_raw"] = strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:"))
					}
				}
				if row["VmRSS_raw"] == nil {
					t.Fatal("idle process RSS unavailable")
				}
				rows = append(rows, row)
			}
			samples = append(samples, map[string]any{"utc": time.Now().UTC().Format(time.RFC3339Nano), "nodes": rows})
			time.Sleep(time.Second)
		}
		data, _ := json.MarshalIndent(map[string]any{"setup": "two actual relay-only Node Agents, outbound idle heartbeat/SSE; preapproved synthetic fixture; no messages/native/provider/model;3s warmup then4 samples at1s", "samples": samples, "limits": "process VmRSS includes shared pages and Go/CGo; not allocator/production/peak benchmark; do not sum as exclusive memory"}, "", "  ")
		if err := os.WriteFile(filepath.Join(os.Getenv("PQTLS_TEST_ARTIFACT_DIR"), "memory-observation.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	stopIdle() // Always stop and join before enqueueing or parent lock acquisition.
	// Parent checked clients acquire their genuine runtime locks only after
	// the actual Agent processes have exited and released the same singleton.
	t.Log("phase=actual-two-shipped-agents-joined")
	checkedClient := func(nodeID string) context.Context {
		f := current.nodes[nodeID]
		h := machineHubContext{HubID: hubID, Origin: base, NodeID: nodeID, Token: f.Token, StateDir: f.StateRoot, WriterRoot: f.WriterRoot}
		if err := configureMachinePQTransport(&h, distributionActiveConfigPath(f)); err != nil {
			t.Fatal("current-authority checked distribution client")
		}
		t.Cleanup(func() { h.TLSRuntime.Close() })
		return withMachineHubContext(withMachinePQDiagnostic(ctx, "protected-MCP-metadata", "", ""), h)
	}
	ctxA, ctxB := checkedClient(fixture.sourceNodeID), checkedClient(fixture.targetNodeID)
	t.Run("protected-MCP-metadata-over-current-PQTLS", func(t *testing.T) {
		assertPQProtectedMCPMetadata(t, fixture, current, db, base, ctxA)
	})
	input := fabric.NodeSealedLinkAskInput{LinkID: fixture.link.ID, MessageID: fixture.messageID, RequestID: fixture.requestID, IdempotencyKey: "SYNTHETIC-PACKAGED-ASK", DataScope: fixture.dataScope, ExpiresAt: fixture.link.ExpiresAt, Ciphertext: fixture.ciphertext}
	for i := 0; i < 2; i++ {
		askContext := withMachinePQDiagnostic(ctxA, "sealed-ask", fixture.requestID, fixture.messageID)
		if err := machineAPIJSON(askContext, base+"/v2/relay/nodes/"+fixture.sourceNodeID+"/sealed/ask", http.MethodPost, input, nil); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := db.GetRelaySealedV1(fixture.messageID)
	if err != nil || !bytes.Equal(stored.Ciphertext, fixture.ciphertext) {
		t.Fatal("shipped Hub did not persist exact ciphertext")
	}
	t.Run("borrowed-bearer", func(t *testing.T) {
		h, _ := machineHubFrom(ctxA)
		h.Token = fixture.targetToken
		err := sendMachineNodeHeartbeat(withMachineHubContext(ctx, h), base, fixture.targetNodeID, fixture.targetToken)
		if !machineAPIHasStatus(err, http.StatusUnauthorized) {
			t.Fatal("shipped Hub accepted another Node bearer")
		}
	})
	t.Run("strict-frontdoor", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, base+"/v2/relay/nodes/"+fixture.sourceNodeID+"/heartbeat", strings.NewReader(`{}`))
		request.Header.Set("Authorization", "CicadaNode "+fixture.sourceToken)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("ordinary peer bypass")
		}
	})
	t.Run("Client-and-WebCrypto", func(t *testing.T) {
		for _, path := range []string{"/v2/client/capabilities", "/assets/panel.manifest.json", "/assets/wasm_exec.js", "/assets/cicada-webcrypto.wasm"} {
			response, err := http.DefaultClient.Get(base + path)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || len(data) == 0 {
				t.Fatal("packaged Client asset unavailable", path)
			}
			if path == "/assets/panel.manifest.json" {
				if expected := os.Getenv("PQTLS_TEST_WEBCRYPTO_MANIFEST_SHA256"); expected != "" && fmt.Sprintf("%x", sha256.Sum256(data)) != expected {
					t.Fatal("packaged WebCrypto manifest mismatch")
				}
			}
		}
	})
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	if err := machineAPIJSON(ctxB, base+"/v2/relay/nodes/"+fixture.targetNodeID+"/sealed/claim", http.MethodPost, fabric.NodeClaimInput{ConsumerID: "SYNTHETIC-PACKAGED-CONSUMER", Limit: 10}, &claimed); err != nil {
		t.Fatal(err)
	}
	if len(claimed.Deliveries) != 1 || claimed.Deliveries[0].NodeID != fixture.targetNodeID || !bytes.Equal(claimed.Deliveries[0].Ciphertext, fixture.ciphertext) {
		t.Fatal("packaged durable claim mismatch")
	}
	replyMessageID := "msg_pqtls_fixture_reply"
	link, manifest := fixture.link, fixture.manifest
	replyContextData := e2ee.EndpointMessageContext{
		MessageID: replyMessageID, Kind: "REPLY", RequestID: fixture.requestID, ReplyTo: fixture.messageID,
		SenderEndpointID: link.TargetEndpointID, SenderPrincipalID: link.TargetPrincipalID,
		SenderOwnerID: link.TargetOwnerID, SenderGroupID: link.TargetGroupID,
		SenderMembershipRevision: link.ScopeSnapshot.TargetMembershipRevision,
		SenderBindingEpoch:       manifest.Target.BindingEpoch, SenderKeyID: manifest.Target.KeyID,
		ReceiverEndpointID: link.SourceEndpointID, ReceiverPrincipalID: link.SourcePrincipalID,
		ReceiverOwnerID: link.SourceOwnerID, ReceiverGroupID: link.SourceGroupID,
		ReceiverMembershipRevision: link.ScopeSnapshot.SourceMembershipRevision,
		ReceiverBindingEpoch:       manifest.Source.BindingEpoch, ReceiverKeyID: manifest.Source.KeyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
	replyCiphertext, err := e2ee.SealEndpointMessage(fixture.targetKey, manifest.Source.PublicIdentity,
		replyContextData, []byte("synthetic packaged reply"), 1)
	if err != nil {
		t.Fatal("prepare synthetic endpoint-sealed REPLY")
	}
	reply := fabric.NodeSealedLinkReplyInput{RequestID: fixture.requestID, MessageID: replyMessageID,
		IdempotencyKey: "SYNTHETIC-PACKAGED-REPLY", DataScope: fixture.dataScope, Ciphertext: replyCiphertext}
	replyContext := withMachinePQDiagnostic(ctxB, "sealed-reply", reply.RequestID, reply.MessageID)
	if err := machineAPIJSON(replyContext, base+"/v2/relay/nodes/"+fixture.targetNodeID+"/sealed/reply", http.MethodPost, reply, nil); err != nil {
		t.Fatal("actual checked PQTLS sealed REPLY request failed")
	}
	assertMeasuredPQDiagnosticRoutes(t, mcpDiagnosticPath,
		[]string{"fabric-whoami", "fabric-find", "fabric-resolve", "fabric-heartbeat", "fabric-ask", "fabric-reply"}, nil)
	if machinePQDiagnosticFailures.Load() != 0 {
		t.Fatal("opt-in PQTLS diagnostic sink reported an incomplete write")
	}
	for _, nodeID := range []string{fixture.sourceNodeID, fixture.targetNodeID} {
		assertMeasuredPQDiagnosticRoutes(t, filepath.Join(diagnosticsDir, "node-"+nodeID+".jsonl"), []string{"relay-events"}, []string{"ready"})
	}
	binding, err := db.CurrentNodeTransportBinding(fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RevokeNodeDeviceBinding(binding.OwnerID, binding.BindingID, binding.BindingVersion); err != nil {
		t.Fatal(err)
	}
	if err := sendMachineNodeHeartbeat(ctxB, base, fixture.targetNodeID, fixture.targetToken); !machineAPIHasStatus(err, http.StatusUnauthorized) {
		t.Fatal("packaged reused transport ignored Store revocation")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(database, "private message for the original session"); err != nil {
		t.Fatal(err)
	}
	t.Log("phase=actual-pinned-relay-ciphertext-claim-revocation-complete")
}

func distributionProcessEnvironment(values ...string) []string {
	// Shipped processes must work without build loader paths or provider setup.
	var out []string
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if name == "LD_LIBRARY_PATH" || name == "LD_PRELOAD" || strings.HasPrefix(name, "CGO_") || strings.HasPrefix(name, "CICADA_") {
			continue
		}
		out = append(out, value)
	}
	return append(out, append([]string{"OPENSSL_CONF=/dev/null"}, values...)...)
}

type distributionOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (o *distributionOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.Write(p)
}
func (o *distributionOutput) Bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.buffer.Bytes()...)
}
func (o *distributionOutput) Len() int { o.mu.Lock(); defer o.mu.Unlock(); return o.buffer.Len() }

// Only complete bounded synthetic records are read while the Agent is live.
// The existing final oracle still verifies the complete TLS/ready association.
func distributionNodeRelayReady(path string) (bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	closeErr := file.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if len(data) > 1024*1024 {
		return false, fmt.Errorf("bounded readiness diagnostic exceeded")
	}
	observations := make(map[string]bool)
	lines := bytes.Split(data, []byte{'\n'})
	// The last segment is not newline-terminated and may still be being written.
	for _, line := range lines[:len(lines)-1] {
		if len(line) > 16*1024 {
			return false, fmt.Errorf("bounded readiness record exceeded")
		}
		var record machinePQDiagnosticRecord
		if json.Unmarshal(line, &record) != nil || record.SchemaVersion != 1 {
			return false, fmt.Errorf("invalid readiness record")
		}
		if record.Route != "relay-events" || record.ObservationID == "" {
			continue
		}
		if record.Event == "got-conn" {
			observations[record.ObservationID] = true
		}
		if record.Event == "ready" && observations[record.ObservationID] {
			return true, nil
		}
	}
	return false, nil
}
