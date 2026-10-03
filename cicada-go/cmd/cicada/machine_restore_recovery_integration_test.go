package main

// This opt-in disposable fixture is compiled only into a test binary. No fault
// endpoint, key initializer or database corruption control enters cicada.
import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

const restoreFixtureNode = "synthetic-restore-node"

type restoreFixtureCoordinates struct {
	Owner   string `json:"owner"`
	Binding string `json:"binding"`
	Version int64  `json:"version"`
}

func restoreFixtureControl(t *testing.T, hub string) *control.Control {
	t.Helper()
	c, err := control.New(control.Config{StateDir: hub, WorkspaceRoot: filepath.Join(hub, "workspace"), APIToken: "synthetic-only-restore-management"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return c
}

func restoreFixtureInit(t *testing.T, hub, source, origin string) {
	t.Helper()
	for _, path := range []string{hub, source} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := restoreFixtureControl(t, hub)
	s, err := store.New(filepath.Join(hub, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := c.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureLocalOwnerPrincipal(owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal(owner, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	h, err := c.NodeControlPublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(owner, "synthetic-restore-device", deviceKey.Public(), h.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := s.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: owner, OwnerKeyID: ownerKey.Public().ID, DeviceID: "synthetic-restore-device", DevicePublic: deviceKey.Public(), OwnerDeviceGrant: grant})
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
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: h.HubID, NodeID: restoreFixtureNode, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: h.PublicIdentity, HubKeyVersion: h.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, h.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	code, err := c.StartNodeControlDeviceBinding(control.NodeControlDeviceCodeInput{NodeID: restoreFixtureNode, NodeName: "SYNTHETIC disposable restore", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: h.HubID, HubPublicIdentity: h.PublicIdentity, HubKeyVersion: h.KeyVersion, HubFingerprint: h.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := c.PreviewNodeControlDeviceCode(owner, device.DeviceID, code.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := c.ConfirmNodeControlDeviceCode(owner, device.DeviceID, code.UserCode, candidate.CandidateDigest, candidate.Version)
	if err != nil {
		t.Fatal(err)
	}
	b := nodewire.Binding{HubID: approved.HubID, NodeID: approved.NodeID, BindingID: approved.OwnerBindingID, BindingVersion: approved.BindingVersion, NodeKeyEpoch: approved.NodeKeyEpoch, NodeKeyVersion: approved.NodeKeyVersion, HubKeyVersion: approved.HubKeyVersion, NodeKey: node.Public(), HubKey: h.PublicIdentity}
	identityPath, statePath := machineNodeControlPaths(source, restoreFixtureNode)
	if err := os.MkdirAll(filepath.Dir(identityPath), 0700); err != nil {
		t.Fatal(err)
	}
	key, err := node.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := openMachineNodeControlClient(source, origin, restoreFixtureNode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { machineNodeControlClients.Delete(statePath) })
	client.state.HubID, client.state.HubKeyID, client.state.HubFingerprint = b.HubID, b.HubKey.ID, nodewire.IdentityFingerprint(b.HubKey)
	client.state.HubKeyVersion, client.state.HubPublicIdentity = b.HubKeyVersion, b.HubKey
	client.state.NodeKeyID, client.state.NodeKeyFingerprint = b.NodeKey.ID, nodewire.IdentityFingerprint(b.NodeKey)
	client.state.NodeKeyVersion, client.state.NodeKeyEpoch = b.NodeKeyVersion, b.NodeKeyEpoch
	client.state.BindingID, client.state.BindingVersion = b.BindingID, b.BindingVersion
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: 7, OperationID: "synthetic-restored-status", Operation: "node.binding.status", SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	pending, err := nodewire.SealRequest(node, b.HubKey, b, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	// Seed receipts by sending real encrypted packets through the production
	// HTTP handler; the fixture never mocks the recovery Store callback.
	tcp := httptest.NewServer(server.NewHandler(c))
	defer tcp.Close()
	post := func(packet []byte) {
		req, err := http.NewRequest(http.MethodPost, tcp.URL+"/v2/node/control/rpc", bytes.NewReader(packet))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "CicadaNode "+token)
		resp, err := tcp.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("fixture receipt HTTP %d", resp.StatusCode)
		}
	}
	post(pending)
	route.Sequence, route.OperationID = 40, "synthetic-forward-status"
	forward, err := nodewire.SealRequest(node, b.HubKey, b, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	post(forward)
	client.state.Sequence, client.state.PendingSequence = 7, 7
	client.state.PendingOperationID, client.state.PendingOperation, client.state.PendingPacket = "synthetic-restored-status", "node.binding.status", pending
	if err := client.persistLocked(); err != nil {
		t.Fatal(err)
	}
	identity, _ := json.Marshal(machineNodeIdentity{Version: machineNodeIdentityVersion, NodeID: restoreFixtureNode})
	if err := os.WriteFile(filepath.Join(filepath.Dir(identityPath), "identity.json"), identity, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(machineNodeCredentialPath(source, restoreFixtureNode), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	cryptoState, err := nodekeys.OpenCryptoState(filepath.Dir(identityPath))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cryptoState.TrustOwnerApprovalKeyLocal(owner, ownerKey.Public().ID, ownerKey.Public(), fingerprint); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if _, err := cryptoState.ReserveOutboundSequence(context.Background(), "synthetic-endpoint", "synthetic-key"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cryptoState.AcceptInbound(context.Background(), "synthetic-endpoint", "synthetic-peer", "synthetic-replay-message", 11, []byte(`{"synthetic":"opaque"}`)); err != nil {
		t.Fatal(err)
	}
	if err := cryptoState.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := nodekeys.LoadOrCreate(filepath.Dir(identityPath), "synthetic-endpoint"); err != nil {
		t.Fatal(err)
	}
	publicBytes, _ := json.Marshal(ownerKey.Public())
	if err := os.WriteFile(filepath.Join(source, "synthetic-owner-public.json"), publicBytes, 0600); err != nil {
		t.Fatal(err)
	}
	trustArgs, _ := json.Marshal([]string{"--owner-id", owner, "--public", "/node/source/synthetic-owner-public.json", "--expect-key-id", ownerKey.Public().ID, "--expect-fingerprint", fingerprint})
	if err := os.WriteFile(filepath.Join(source, "synthetic-trust-args.json"), trustArgs, 0600); err != nil {
		t.Fatal(err)
	}
	revokeArgs, _ := json.Marshal([]string{"--owner-id", owner, "--key-id", ownerKey.Public().ID, "--expected-version", "1"})
	if err := os.WriteFile(filepath.Join(source, "synthetic-revoke-args.json"), revokeArgs, 0600); err != nil {
		t.Fatal(err)
	}
	inboxPath := filepath.Join(filepath.Dir(identityPath), "inbox.sqlite")
	inbox, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := inbox.Save(context.Background(), nodeinbox.Message{MessageID: "synthetic-uncertain", Digest: "synthetic-digest", EndpointID: "synthetic-endpoint", SessionID: "synthetic-session", BindingEpoch: 1, Payload: []byte("SYNTHETIC PRIVATE PAYLOAD DO NOT LOG")}); err != nil {
		t.Fatal(err)
	}
	claim, err := inbox.Claim(context.Background(), "synthetic-consumer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	inbox.Close()
	inbox, err = nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	inbox.Close() // production restart marks INJECTION_UNCERTAIN
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(source, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AdmitProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{ExecutionID: "synthetic-provider-attempt", ProviderID: "synthetic-no-provider", AdmissionIntent: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	ledger.Close()
	history, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(source, "node-native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := history.CheckAndRecordNativeContext(context.Background(), nodeinbox.NativeContextScopeInput{AccountID: "synthetic-account", Harness: "codex", NativeSessionID: "synthetic-session", HubID: b.HubID, GroupID: "synthetic-group", ContextPolicy: nodeinbox.NativeContextPolicyGroupScoped, EndpointID: "synthetic-endpoint", BindingID: "synthetic-native-binding", BindingEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	history.Close()
	writer, err := nodelock.AcquireNativeWriter(context.Background(), source, "synthetic-account", "codex", "synthetic-session")
	if err != nil {
		t.Fatal(err)
	}
	op := nodelock.NativeOperation{HubID: b.HubID, NodeID: restoreFixtureNode, EndpointID: "synthetic-endpoint", BindingID: "synthetic-native-binding", BindingEpoch: 1, MessageID: "synthetic-native-uncertain", Digest: strings.Repeat("b", 64), AttemptID: "synthetic-native-attempt"}
	if _, err := writer.BeginNativeOperation(op); err != nil {
		t.Fatal(err)
	}
	writer.Close() // durable unresolved operation; no actual Runtime invoked
	resources, err := nodelock.OpenResourceExecutionManager(source)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := resources.Begin(nodelock.ResourceExecutionRequest{ResourceID: "gpu/0", LeaseID: "synthetic-resource-lease", FencingEpoch: 3, ExecutionID: "synthetic-resource-attempt"})
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Quarantine(); err != nil {
		t.Fatal(err)
	}
	coordinates, _ := json.Marshal(restoreFixtureCoordinates{owner, b.BindingID, int64(b.BindingVersion)})
	if err := os.WriteFile(filepath.Join(hub, "synthetic-coordinates.json"), coordinates, 0600); err != nil {
		t.Fatal(err)
	}
}

func restoreFixtureFault(t *testing.T, hub, fault string) {
	t.Helper()
	s, err := store.New(filepath.Join(hub, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data, err := os.ReadFile(filepath.Join(hub, "synthetic-coordinates.json"))
	if err != nil {
		t.Fatal(err)
	}
	var coord restoreFixtureCoordinates
	if err := json.Unmarshal(data, &coord); err != nil {
		t.Fatal(err)
	}
	if fault == "revoked" {
		if _, err := s.RevokeNodeDeviceBinding(coord.Owner, coord.Binding, coord.Version); err != nil {
			t.Fatal(err)
		}
		return
	}
	db, err := sql.Open("sqlite", filepath.Join(hub, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var query string
	var trigger string
	switch fault {
	case "missing-receipt":
		query = `DELETE FROM node_control_rpc_inbox_v1 WHERE sequence=7`
	case "uncertain":
		query = `UPDATE node_control_rpc_inbox_v1 SET state='UNCERTAIN' WHERE sequence=7`
	case "highwater-rollback":
		query = `UPDATE node_control_rpc_sequences_v1 SET last_sequence=3`
	case "digest-mismatch":
		trigger = "node_control_rpc_request_immutable_v1"
		query = `UPDATE node_control_rpc_inbox_v1 SET request_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE sequence=7`
	case "stale-epoch":
		trigger = "node_control_key_binding_immutable_v1"
		query = `UPDATE node_control_key_bindings_v1 SET node_key_epoch=node_key_epoch+1`
	default:
		t.Fatal("unknown synthetic fault")
	}
	var triggerSQL string
	if trigger != "" {
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, trigger).Scan(&triggerSQL); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("DROP TRIGGER " + trigger); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.Exec(triggerSQL); err != nil {
				t.Error(err)
			}
		}()
	}
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func TestMachineRestoreRecoveryDisposableFixture(t *testing.T) {
	mode := os.Getenv("CICADA_SYNTHETIC_RESTORE_MODE")
	if mode == "" {
		t.Skip("opt-in disposable fixture, run the production CLI Docker driver")
	}
	hub, source, origin := os.Getenv("CICADA_SYNTHETIC_HUB"), os.Getenv("CICADA_SYNTHETIC_NODE"), os.Getenv("CICADA_SYNTHETIC_ORIGIN")
	if hub == "" || source == "" || origin == "" {
		t.Fatal("explicit synthetic paths and origin required")
	}
	switch mode {
	case "init":
		restoreFixtureInit(t, hub, source, origin)
	case "fault":
		restoreFixtureFault(t, hub, os.Getenv("CICADA_SYNTHETIC_FAULT"))
	case "serve":
		c := restoreFixtureControl(t, hub)
		t.Fatal(http.ListenAndServe(":8787", server.NewHandler(c)))
	default:
		t.Fatal("unknown fixture mode")
	}
}

func TestMachineRestoreRecoveryProductionHandler(t *testing.T) {
	for _, fault := range []string{"complete", "missing-receipt", "uncertain", "stale-epoch", "highwater-rollback", "digest-mismatch", "revoked"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			hub, source := filepath.Join(root, "hub"), filepath.Join(root, "source")
			// The saved logical origin must equal the final production handler.
			var handler http.Handler
			tcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
			defer tcp.Close()
			restoreFixtureInit(t, hub, source, tcp.URL)
			if fault != "complete" {
				restoreFixtureFault(t, hub, fault)
			}
			c := restoreFixtureControl(t, hub)
			handler = server.NewHandler(c)
			archive, restored := filepath.Join(root, "archive"), filepath.Join(root, "restored")
			var output bytes.Buffer
			if err := machineBackupCommandOutput([]string{"backup", "--id", restoreFixtureNode, "--state-dir", source, "--output", archive}, &output); err != nil {
				t.Fatal(err)
			}
			if err := machineBackupCommandOutput([]string{"restore", "--backup", archive, "--state-dir", restored}, &output); err != nil {
				t.Fatal(err)
			}
			before, err := recoveryTreeDigest(restored)
			if err != nil {
				t.Fatal(err)
			}
			output.Reset()
			err = machineRecoveryQueryCommand([]string{"--backup", archive, "--state-dir", restored, "--plan-sha256", nodewire.RecoveryDigest([]byte("synthetic immutable plan"))}, &output)
			allowed := fault == "complete" || fault == "missing-receipt" || fault == "uncertain"
			if allowed != (err == nil) {
				t.Fatalf("query allow=%t err=%v", allowed, err)
			}
			after, e := recoveryTreeDigest(restored)
			if e != nil || before != after {
				t.Fatal("query changed restored bytes or modes")
			}
			if allowed {
				var report struct {
					AgentMayStart bool                    `json:"agent_may_start"`
					Status        nodewire.RecoveryStatus `json:"status"`
				}
				if err := json.Unmarshal(output.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				want := map[string]string{"complete": "COMPLETE", "missing-receipt": "NOT_RECORDED", "uncertain": "UNCERTAIN"}[fault]
				if report.AgentMayStart || report.Status.AcceptedHighwater != 40 || len(report.Status.Operations) != 1 || report.Status.Operations[0].State != want {
					t.Fatal("unsafe bounded status")
				}
			} else if output.Len() != 0 {
				t.Fatal("denial exposed status")
			}
			proof, err := nodebackup.InspectWithWriterRoot(archive, restored, restored)
			if err != nil || proof.AgentMayStart || proof.RelayInbox.DeliveriesByState["INJECTION_UNCERTAIN"] != 1 || proof.CryptoState.HighestLocalSequence != 9 || proof.CryptoState.ReplayRecords != 1 {
				t.Fatalf("lost replay/uncertain state: %v", err)
			}
		})
	}
}
