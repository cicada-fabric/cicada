package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestNodeRecoveryHTTPCurrentProofReadOnlyAndStaleAdmission(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "hub")
	c, err := control.New(control.Config{StateDir: state, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-recovery-management"})
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
	server := httptest.NewServer(NewHandler(c))
	defer server.Close()
	s, err := store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := c.Identity().ID
	ownerKey, _ := e2ee.NewIdentity()
	deviceKey, _ := e2ee.NewIdentity()
	if err := s.EnsureLocalOwnerPrincipal(owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal(owner, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hub, err := c.NodeControlPublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(owner, "synthetic-recovery-device", deviceKey.Public(), hub.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := s.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: owner, OwnerKeyID: ownerKey.Public().ID, DeviceID: "synthetic-recovery-device", DevicePublic: deviceKey.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	node, _ := e2ee.NewIdentity()
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID, NodeID: "synthetic-recovery-node", RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	code, err := c.StartNodeControlDeviceBinding(control.NodeControlDeviceCodeInput{NodeID: "synthetic-recovery-node", NodeName: "Synthetic recovery fixture", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: hub.HubID, HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint})
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
	b := nodewire.Binding{HubID: approved.HubID, NodeID: approved.NodeID, BindingID: approved.OwnerBindingID, BindingVersion: approved.BindingVersion, NodeKeyEpoch: approved.NodeKeyEpoch, NodeKeyVersion: approved.NodeKeyVersion, HubKeyVersion: approved.HubKeyVersion, NodeKey: node.Public(), HubKey: hub.PublicIdentity}
	post := func(packet []byte, bearer string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/v2/node/control/rpc", bytes.NewReader(packet))
		req.Header.Set("Authorization", "CicadaNode "+bearer)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, data
	}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: 40, OperationID: "accepted-status", Operation: "node.binding.status", SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	normal, err := nodewire.SealRequest(node, b.HubKey, b, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post(normal, token); code != http.StatusOK {
		t.Fatalf("normal status code %d", code)
	}
	q := nodewire.RecoveryRequest{Nonce: nonce, Origin: server.URL, CredentialDigest: digest, RestoreDigest: nodewire.RecoveryDigest([]byte("synthetic restore")), PlanDigest: nodewire.RecoveryDigest([]byte("synthetic immutable plan")), Operations: []nodewire.RecoveryOperationQuery{{OperationID: route.OperationID, Sequence: 40, RequestDigest: nodewire.RecoveryDigest(normal)}, {OperationID: "unknown-claim", Sequence: 1, RequestDigest: nodewire.RecoveryDigest([]byte("synthetic unknown claim"))}}}
	packet, err := nodewire.SealRecoveryRequest(node, b, q)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		code, response := post(packet, token)
		if code != http.StatusOK {
			t.Fatalf("read query code %d", code)
		}
		status, err := nodewire.OpenRecoveryResponse(node, b, q, packet, response)
		if err != nil || status.AcceptedHighwater != 40 || status.Operations[0].State != "COMPLETE" || status.Operations[1].State != "NOT_RECORDED" {
			t.Fatalf("query response: %+v %v", status, err)
		}
		raw, _ := json.Marshal(status)
		for _, secret := range []string{token, digest, "result", "prompt", "response_packet"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("status leaked %s", secret)
			}
		}
	}
	route.Sequence = 1
	route.OperationID = "stale-mutate"
	route.Operation = "node.heartbeat"
	stale, err := nodewire.SealRequest(node, b.HubKey, b, route, []byte(`{"status":"available"}`))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post(stale, token); code != http.StatusConflict {
		t.Fatalf("ordinary stale RPC admitted: %d", code)
	}
	wrongToken, _, _ := fabric.NewNodeCredential()
	if code, _ := post(packet, wrongToken); code != http.StatusForbidden {
		t.Fatalf("copied packet with wrong bearer: %d", code)
	}
	forged, _ := e2ee.NewIdentity()
	wrong := b
	wrong.NodeKey = forged.Public()
	forgedPacket, _ := nodewire.SealRecoveryRequest(forged, wrong, q)
	if code, _ := post(forgedPacket, token); code != http.StatusForbidden {
		t.Fatalf("copied bearer without approved private key: %d", code)
	}
	changed := q
	changed.Operations = append([]nodewire.RecoveryOperationQuery(nil), q.Operations...)
	changed.Operations[0].RequestDigest = nodewire.RecoveryDigest([]byte("changed"))
	bad, _ := nodewire.SealRecoveryRequest(node, b, changed)
	if code, _ := post(bad, token); code != http.StatusForbidden {
		t.Fatalf("conflicting operation digest: %d", code)
	}
	// Reading unknown claim metadata must not create jobs, heartbeat, or inbox admissions.
	db, err := sql.Open("sqlite", filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM node_control_rpc_inbox_v1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("query/business path wrote inbox: %d %v", count, err)
	}
	if _, err := s.RevokeNodeDeviceBinding(owner, b.BindingID, int64(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if code, _ := post(packet, token); code != http.StatusForbidden {
		t.Fatalf("revoked binding queried: %d", code)
	}
}
