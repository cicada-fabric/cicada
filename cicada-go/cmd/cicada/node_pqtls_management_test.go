//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func productNodeFingerprint(identity e2ee.PublicIdentity) string {
	return nodewire.IdentityFingerprint(identity)
}
func productNodePairingProof(nodeKey *e2ee.Identity, hub control.NodeControlHubIdentity, nodeID, digest string, nonce []byte) ([]byte, error) {
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID, NodeID: nodeID, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: nodeKey.Public(), HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion})
	if err != nil {
		return nil, err
	}
	return e2ee.Seal(nodeKey, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
}

func TestProductNodePQManagedOriginPreservesKeysAndEncryptedRPC(t *testing.T) {
	if os.Getenv("PQTLS_PRODUCT_MANAGED_AGENT_CHILD") == "1" {
		if err := runMachineAgent([]string{"--id", os.Getenv("PQTLS_CHILD_NODE_ID"), "--control-url", os.Getenv("PQTLS_CHILD_ORIGIN"), "--state-dir", os.Getenv("PQTLS_CHILD_NODE_STATE"), "--pqtls-config", os.Getenv("PQTLS_CHILD_CONFIG"), "--once"}); err != nil {
			t.Fatal("separate managed Node PQ Agent failed")
		}
		return
	}
	root, pins := productPQFixtures(t)
	hubState := filepath.Join(root, "hub-state")
	c, err := control.New(control.Config{StateDir: hubState, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-management-only"})
	if err != nil {
		t.Fatal(err)
	}
	// No planner/scheduler is started and no Worker job/native provider exists.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	db, err := store.New(filepath.Join(hubState, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ownerID := c.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerApproval, err := db.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubIdentity, err := c.NodeControlPublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "synthetic-pq-owner-device", deviceKey.Public(), hubIdentity.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: ownerID, OwnerKeyID: ownerApproval.KeyID, DeviceID: "synthetic-pq-owner-device", DevicePublic: deviceKey.Public(), OwnerDeviceGrant: grant}); err != nil {
		t.Fatal(err)
	}
	const nodeID = "synthetic-managed-pq-node"
	nodeKey, err := e2ee.NewIdentity()
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
	proof, err := productNodePairingProof(nodeKey, hubIdentity, nodeID, digest, nonce)
	if err != nil {
		t.Fatal(err)
	}
	code, err := c.StartNodeControlDeviceBinding(control.NodeControlDeviceCodeInput{NodeID: nodeID, NodeName: "synthetic PQ managed Node", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: nodeKey.Public(), NodeFingerprint: productNodeFingerprint(nodeKey.Public()), ProofPacket: proof, HubID: hubIdentity.HubID, HubPublicIdentity: hubIdentity.PublicIdentity, HubKeyVersion: hubIdentity.KeyVersion, HubFingerprint: hubIdentity.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := c.PreviewNodeControlDeviceCode(ownerID, "synthetic-pq-owner-device", code.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := c.ConfirmNodeControlDeviceCode(ownerID, "synthetic-pq-owner-device", code.UserCode, preview.CandidateDigest, preview.Version)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := db.CurrentNodeTransportBinding(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	address, frontAddress := productFreeAddress(t), productFreeAddress(t)
	logicalOrigin, pqOrigin := "http://"+frontAddress, "https://"+address
	hubTLS := nodetransport.Identity{Kind: "hub", HubID: hubIdentity.HubID, DNSName: "hub.synthetic.invalid"}
	nodeTLS := nodetransport.Identity{Kind: "node", HubID: hubIdentity.HubID, NodeID: nodeID, TLSEpoch: 17, DNSName: "node-a.synthetic.invalid"}
	hubCfg := &nodetransport.Config{Version: 1, Role: "hub", Listen: address, CertificateFile: filepath.Join(root, "hub.pem"), PrivateKeyFile: filepath.Join(root, "hub.key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: hubTLS, Peers: []nodetransport.Approval{{Identity: nodeTLS, PinKind: "certificate-sha256", PinSHA256: pins["node-a"], OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, CredentialVersion: binding.CredentialVersion}}}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var pqRPC atomic.Int64
	var ordinaryRPC atomic.Int64
	inner := server.NewHandler(c)
	front := newControlHTTPServer("", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/node/control/rpc" {
			if _, err := pqtls.StateFromContext(r.Context()); err != nil {
				ordinaryRPC.Add(1)
			} else {
				pqRPC.Add(1)
			}
		}
		inner.ServeHTTP(w, r)
	}))
	front.Addr = frontAddress
	done := make(chan error, 1)
	go func() { done <- serveProductHTTP(ctx, front, c.Fabric(), hubCfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(12 * time.Second):
			t.Error("managed PQ Hub did not stop")
		}
	})
	for i := 0; i < 100; i++ {
		r, err := (&http.Client{Timeout: 100 * time.Millisecond}).Get(logicalOrigin + "/healthz")
		if err == nil {
			r.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	nodeState, err := os.MkdirTemp(root, "managed-node-state-")
	if err != nil {
		t.Fatal(err)
	}
	identityPath, statePath := machineNodeControlPaths(nodeState, nodeID)
	if err := persistMachineNodeIdentity(filepath.Join(machineNodeStateDir(nodeState, nodeID), "identity.json"), machineNodeCredentialPath(nodeState, nodeID), &machineNodeIdentity{Version: 1, NodeID: nodeID, RelayToken: token}); err != nil {
		t.Fatal(err)
	}
	identityData, err := nodeKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistNodeSecretFile(identityPath, identityData, ".synthetic-existing-node-key-"); err != nil {
		t.Fatal(err)
	}
	client, err := openMachineNodeControlClient(nodeState, logicalOrigin, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { machineNodeControlClients.Delete(statePath) })
	client.mu.Lock()
	client.state.HubID, client.state.HubKeyID = hubIdentity.HubID, hubIdentity.KeyID
	client.state.HubFingerprint, client.state.HubKeyVersion, client.state.HubPublicIdentity = hubIdentity.Fingerprint, hubIdentity.KeyVersion, hubIdentity.PublicIdentity
	client.state.NodeKeyID, client.state.NodeKeyFingerprint, client.state.NodeKeyVersion = nodeKey.Public().ID, productNodeFingerprint(nodeKey.Public()), approved.NodeKeyVersion
	client.state.BindingID, client.state.BindingVersion, client.state.NodeKeyEpoch = approved.OwnerBindingID, approved.BindingVersion, approved.NodeKeyEpoch
	client.state.ApprovedRequestID, client.state.ApprovedRequestVersion, client.state.ApprovedCandidateDigest = preview.RequestID, preview.Version, preview.CandidateDigest
	if err := client.persistLocked(); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.mu.Unlock()
	beforeState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeKey, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeCfg := &nodetransport.Config{Version: 1, Role: "node", Origin: pqOrigin, ApplicationOrigin: logicalOrigin, CertificateFile: filepath.Join(root, "node-a.pem"), PrivateKeyFile: filepath.Join(root, "node-a.key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: nodeTLS, Peers: []nodetransport.Approval{{Identity: hubTLS, PinKind: "certificate-sha256", PinSHA256: pins["hub"]}}}
	configPath := writeProductPQConfig(t, root, "managed-node-config", nodeCfg)
	hub := machineHubContext{HubID: hubIdentity.HubID, Origin: logicalOrigin, NodeID: nodeID, StateDir: nodeState, Token: token, WriterRoot: nodeState, WriterScope: machineNativeWriterScope()}
	if err := configureMachinePQTransport(&hub, configPath); err != nil {
		t.Fatal(err)
	}
	defer hub.NodeTransport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
	afterState, _ := os.ReadFile(statePath)
	afterKey, _ := os.ReadFile(identityPath)
	if !bytes.Equal(beforeState, afterState) || !bytes.Equal(beforeKey, afterKey) {
		t.Fatal("transport activation rewrote persisted Node-Control origin/key/counter")
	}
	agentCtx := withMachineHubContext(ctx, hub)
	var status machineNodeControlBindingStatus
	if err := client.call(agentCtx, token, "node.binding.status", map[string]any{}, &status); err != nil || status.NodeID != nodeID {
		t.Fatal("actual encrypted Node-Control RPC over mapped PQ failed")
	}
	if client.state.HubOrigin != logicalOrigin || client.state.Sequence != 1 {
		t.Fatal("RPC did not preserve logical origin and advance existing replay state")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithTimeout(ctx, 15*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, executable, "-test.run=^TestProductNodePQManagedOriginPreservesKeysAndEncryptedRPC$", "-test.v")
	child.Env = append(os.Environ(), "PQTLS_PRODUCT_MANAGED_AGENT_CHILD=1", "PQTLS_CHILD_NODE_ID="+nodeID, "PQTLS_CHILD_ORIGIN="+logicalOrigin, "PQTLS_CHILD_NODE_STATE="+nodeState, "PQTLS_CHILD_CONFIG="+configPath, "CICADA_HUB_ID="+hubIdentity.HubID)
	output, err := child.CombinedOutput()
	if err != nil {
		if len(output) < 64<<10 {
			os.WriteFile(filepath.Join(os.Getenv("PQTLS_TEST_ARTIFACT_DIR"), "managed-agent-child-failure.log"), output, 0600)
		}
		t.Fatal("separate production managed Node PQ process failed")
	}
	t.Logf("separate managed Node Agent process exit=0 transcript_sha256=%x bytes=%d", sha256.Sum256(output), len(output))
	finalKey, _ := os.ReadFile(identityPath)
	if !bytes.Equal(beforeKey, finalKey) {
		t.Fatal("managed Node replaced application identity")
	}
	finalStateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var finalState machineNodeControlState
	if json.Unmarshal(finalStateBytes, &finalState) != nil || finalState.HubOrigin != logicalOrigin || finalState.Sequence < 3 {
		t.Fatal("managed Agent did not preserve origin and continue replay state")
	}
	if pqRPC.Load() < 3 || ordinaryRPC.Load() != 0 {
		t.Fatal("managed Node RPC did not exclusively reach PQ Router")
	}
	t.Log("existing Node-Control identity/state preserved at activation; original logical HubOrigin retained; replay advanced through real encrypted RPC and separate managed Agent process; no job/provider/model started")
}
