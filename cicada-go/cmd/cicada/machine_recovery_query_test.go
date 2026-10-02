package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestMachineRecoveryQueryLostResponsePreservesAllSecretState(t *testing.T) {
	var mu sync.Mutex
	var packets [][]byte
	var client *machineNodeControlClient
	var binding nodewire.Binding
	// Populate before serving any requests; the immutable fixture keys are synthetic.
	var reply func([]byte) ([]byte, error)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		packets = append(packets, append([]byte(nil), data...))
		attempt := len(packets)
		mu.Unlock()
		response, err := reply(data)
		if err != nil {
			t.Error(err)
			w.WriteHeader(403)
			return
		}
		if attempt == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
	defer server.Close()
	fixture, _, hub, b := newMachineNodeControlRecoveryFixture(t, server.URL)
	client = fixture
	binding = b
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nodeDir := machineNodeStateDir(client.stateDir, client.nodeID)
	identityBytes, _ := json.Marshal(machineNodeIdentity{Version: machineNodeIdentityVersion, NodeID: client.nodeID})
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), identityBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(machineNodeCredentialPath(client.stateDir, client.nodeID), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: 7, OperationID: "restored-pending-heartbeat", Operation: "node.heartbeat", SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	pending, err := nodewire.SealRequest(client.identity, b.HubKey, b, route, []byte(`{"status":"available"}`))
	if err != nil {
		t.Fatal(err)
	}
	client.state.Sequence = 7
	client.state.PendingOperationID = route.OperationID
	client.state.PendingSequence = 7
	client.state.PendingOperation = route.Operation
	client.state.PendingPacket = pending
	if err := client.persistLocked(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "archive")
	if _, err := nodebackup.Backup(client.stateDir, client.nodeID, backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := nodebackup.RestoreWithWriterRoot(backup, restored, restored); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restored, "synthetic-shared-resource-ledger.json"), []byte(`{"held_generation":9,"outcome":"UNKNOWN"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Arrange all existing advisory files before hashing. The CLI itself must not create them.
	maintenance, err := nodelock.AcquireMaintenanceExclusive(restored, client.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	maintenance.Close()
	writer, err := nodelock.AcquireWriterRootExclusive(restored)
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
	reply = func(packet []byte) ([]byte, error) {
		q, err := nodewire.OpenRecoveryRequest(hub, binding, packet)
		if err != nil {
			return nil, err
		}
		if q.CredentialDigest != digest || q.Origin != server.URL || len(q.Operations) != 1 || q.Operations[0].OperationID != route.OperationID || q.Operations[0].Sequence != 7 || q.Operations[0].RequestDigest != nodewire.RecoveryDigest(pending) {
			t.Error("CLI changed pinned scope")
		}
		status := nodewire.RecoveryStatus{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKey.ID, NodeKeyVersion: b.NodeKeyVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyID: b.HubKey.ID, HubKeyVersion: b.HubKeyVersion, CredentialVersion: 1, AcceptedHighwater: 40, Operations: []nodewire.RecoveryOperationStatus{{RecoveryOperationQuery: q.Operations[0], State: "COMPLETE"}}}
		return nodewire.SealRecoveryResponse(hub, b, q, packet, status)
	}
	before, err := recoveryTreeDigest(restored)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	args := []string{"recovery", "query", "--backup", backup, "--state-dir", restored, "--plan-sha256", nodewire.RecoveryDigest([]byte("synthetic immutable plan"))}
	if err := machineRecoveryCommandOutput(args, &output); err != nil {
		t.Fatal(err)
	}
	after, err := recoveryTreeDigest(restored)
	if err != nil || before != after {
		t.Fatalf("query mutated keys/counters/quarantine/ledger: %v", err)
	}
	mu.Lock()
	same := len(packets) == 2 && bytes.Equal(packets[0], packets[1])
	mu.Unlock()
	if !same {
		t.Fatal("lost response did not retry exact read packet")
	}
	for _, secret := range []string{token, digest, "nonce", "prompt", "result"} {
		if bytes.Contains(output.Bytes(), []byte(secret)) {
			t.Fatalf("CLI output exposed %s", secret)
		}
	}
	var report struct {
		AgentMayStart bool                    `json:"agent_may_start"`
		Status        nodewire.RecoveryStatus `json:"status"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.AgentMayStart || report.Status.AcceptedHighwater != 40 {
		t.Fatalf("unsafe CLI report: %v", err)
	}
	// Loader remains read-only and preserves stale restored floor exactly.
	loaded, _, err := loadMachineRecoveryClient(restored, client.nodeID)
	if err != nil || loaded.state.Sequence != 7 || !bytes.Equal(loaded.state.PendingPacket, pending) {
		t.Fatalf("read-only loader repaired sequence: %v", err)
	}
	// An existing live writer holds recovery; lease expiry is not a stop proof.
	hold, err := nodelock.AcquireWriterRoot(restored)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = machineRecoveryCommandOutput(args, &output)
	hold.Close()
	if err == nil || output.Len() != 0 {
		t.Fatal("live WriterRoot ownership bypassed")
	}
	hold, err = nodelock.AcquireMaintenance(restored, client.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	err = machineRecoveryCommandOutput(args, &output)
	hold.Close()
	if err == nil {
		t.Fatal("live Node writer bypassed")
	}
	markerPath := filepath.Join(machineNodeStateDir(restored, client.nodeID), "recovery-pending.json")
	markerBytes, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	err = machineRecoveryCommandOutput(args, &output)
	if err == nil {
		t.Fatal("missing quarantine proof accepted")
	}
	if _, statErr := os.Stat(markerPath); !os.IsNotExist(statErr) {
		t.Fatal("query fabricated quarantine proof")
	}
	if err = os.WriteFile(markerPath, markerBytes, 0600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	requests := len(packets)
	mu.Unlock()
	if requests != 2 {
		t.Fatal("failed proof/writer checks sent network queries")
	}
	for _, fault := range []struct {
		name, path string
		bad, good  os.FileMode
	}{
		{"private-lock-directory", filepath.Join(restored, "nodes", ".locks"), 0500, 0700},
		{"private-Node-lock", filepath.Join(restored, "nodes", ".locks", "node-"+urlPath(client.nodeID)+".maintenance.lock"), 0400, 0600},
		{"private-WriterRoot-lock", filepath.Join(restored, ".writer-root.maintenance.lock"), 0400, 0600},
		{"setgid-lock-directory", filepath.Join(restored, "nodes", ".locks"), os.ModeSetgid | 0700, 0700},
		{"sticky-lock-directory", filepath.Join(restored, "nodes", ".locks"), os.ModeSticky | 0700, 0700},
		{"setuid-Node-lock", filepath.Join(restored, "nodes", ".locks", "node-"+urlPath(client.nodeID)+".maintenance.lock"), os.ModeSetuid | 0600, 0600},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if err := os.Chmod(fault.path, fault.bad); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(fault.path, fault.good)
			before, err := recoveryTreeDigest(restored)
			if err != nil {
				t.Fatal(err)
			}
			output.Reset()
			err = machineRecoveryCommandOutput(args, &output)
			if err == nil || output.Len() != 0 {
				t.Fatal("noncanonical private lock mode accepted")
			}
			after, err := recoveryTreeDigest(restored)
			if err != nil || before != after {
				t.Fatalf("rejected layout changed shared root/Node bytes or modes: %v", err)
			}
			info, err := os.Lstat(fault.path)
			if err != nil || info.Mode()&^os.ModeDir != fault.bad {
				t.Fatal("rejection repaired a lock mode")
			}
			mu.Lock()
			requests := len(packets)
			mu.Unlock()
			if requests != 2 {
				t.Fatal("invalid lock modes sent a network request")
			}
		})
	}

}
func TestMachineRecoveryQueryRejectsMissingProofUnsafePathsAndScope(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "missing")
	var output bytes.Buffer
	if err := machineRecoveryQueryCommand([]string{"--backup", backup, "--state-dir", dir, "--plan-sha256", nodewire.RecoveryDigest([]byte("plan"))}, &output); err == nil {
		t.Fatal("missing archive accepted")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("missing archive was created")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if recoveryPrivatePath(alias, true) == nil {
		t.Fatal("symlink directory accepted")
	}
	file := filepath.Join(dir, "public-file")
	os.WriteFile(file, []byte("synthetic"), 0644)
	if recoveryPrivatePath(file, false) == nil {
		t.Fatal("public secret file accepted")
	}
	client, ctx, hub, b := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:9")
	q := nodewire.RecoveryRequest{Nonce: make([]byte, 32), Origin: client.base, CredentialDigest: "synthetic", RestoreDigest: nodewire.RecoveryDigest([]byte("restore")), PlanDigest: nodewire.RecoveryDigest([]byte("plan")), Operations: []nodewire.RecoveryOperationQuery{}}
	packet, _ := nodewire.SealRecoveryRequest(client.identity, b, q)
	wrong := withMachineHubContext(context.Background(), machineHubContext{HubID: b.HubID, Origin: "http://other.invalid", NodeID: b.NodeID})
	if _, err := queryMachineRecoveryStatus(wrong, client, "synthetic", q, packet); err == nil {
		t.Fatal("wrong context origin accepted")
	}
	response, _ := nodewire.SealRecoveryResponse(hub, b, q, packet, nodewire.RecoveryStatus{})
	if _, err := nodewire.OpenRecoveryResponse(client.identity, b, q, packet, response); err == nil {
		t.Fatal("missing current response coordinates accepted")
	}
	_ = ctx
}

func TestMachineRecoveryQueryResponseFaultsNeverWrite(t *testing.T) {
	for _, mode := range []string{"forged", "oversize", "redirect", "deny"} {
		t.Run(mode, func(t *testing.T) {
			var requests int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				switch mode {
				case "oversize":
					w.Write(bytes.Repeat([]byte("x"), nodewire.MaxRecoveryPacketBytes+1))
				case "redirect":
					w.Header().Set("Location", "http://other.invalid/v2/node/control/rpc")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "deny":
					w.WriteHeader(http.StatusForbidden)
				default:
					w.Write([]byte(`{"route":{},"envelope":{}}`))
				}
			}))
			defer server.Close()
			client, ctx, _, b := newMachineNodeControlRecoveryFixture(t, server.URL)
			before, _ := recoveryTreeDigest(client.stateDir)
			q := nodewire.RecoveryRequest{Nonce: make([]byte, 32), Origin: server.URL, CredentialDigest: "synthetic", RestoreDigest: nodewire.RecoveryDigest([]byte("restore")), PlanDigest: nodewire.RecoveryDigest([]byte("plan")), Operations: []nodewire.RecoveryOperationQuery{}}
			packet, err := nodewire.SealRecoveryRequest(client.identity, b, q)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := queryMachineRecoveryStatus(ctx, client, "synthetic", q, packet); err == nil {
				t.Fatal("fault accepted")
			}
			after, _ := recoveryTreeDigest(client.stateDir)
			if before != after || requests != 1 {
				t.Fatalf("fault mutated/retried/redirected: %d", requests)
			}
		})
	}
}

func TestMachineTLSRecoveryQueryRejectsClosedAndForeignMaintenanceScope(t *testing.T) {
	root, writer := t.TempDir(), t.TempDir()
	if os.Chmod(root, 0700) != nil || os.Chmod(writer, 0700) != nil {
		t.Fatal("private scopes")
	}
	node, err := nodelock.AcquireMaintenanceExclusive(root, "synthetic-node")
	if err != nil {
		t.Fatal(err)
	}
	node.Close()
	wr, err := nodelock.AcquireWriterRootExclusive(writer)
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	cap, err := nodetransport.AcquireTLSMaintenanceRead(root, writer, "synthetic-hub", "synthetic-node")
	if err != nil {
		t.Fatal(err)
	}
	defer cap.Close()
	hub := machineHubContext{StateDir: root, WriterRoot: writer, HubID: "foreign-hub", NodeID: "synthetic-node", Origin: "https://hub.synthetic.invalid"}
	before, err := recoveryTreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = machineTLSRecoveryQuery(context.Background(), cap, &hub, "", nil, "", nodewire.RecoveryRequest{}, nil); !errors.Is(err, nodetransport.ErrTLSInstall) {
		t.Fatal("foreign maintenance scope accepted", err)
	}
	hub.HubID = "synthetic-hub"
	copyBeforeClose := *cap
	cap.Close()
	if _, err = machineTLSRecoveryQuery(context.Background(), &copyBeforeClose, &hub, "", nil, "", nodewire.RecoveryRequest{}, nil); !errors.Is(err, nodetransport.ErrTLSRuntimeClosed) {
		t.Fatal("closed maintenance copy accepted", err)
	}
	after, err := recoveryTreeDigest(root)
	if err != nil || before != after || hub.TLSRuntime != nil || hub.NodeTransport != nil {
		t.Fatal("denied recovery mutated/published")
	}
}
