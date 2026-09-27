package control

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func newNodeBindingControl(t *testing.T) (*Control, string, *e2ee.Identity) {
	t.Helper()
	root := t.TempDir()
	c, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown Control: %v", err)
		}
	})
	ownerIdentity := c.identity
	ownerID := ownerIdentity.Public().ID
	if _, err := c.store.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		Name: "owner", Status: store.PrincipalStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := c.store.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := c.ClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, "android", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterClientDevice(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: "android",
		DevicePublic: device.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	return c, ownerID, device
}

func TestNodeDeviceCodeOwnerConfirmationActivatesLocallyHeldBearerAndSupportsRevocation(t *testing.T) {
	c, ownerID, device := newNodeBindingControl(t)
	nodeToken, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := c.StartNodeDeviceBinding("node-device-1", "GPU node", credentialDigest)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.UserCode == "" || challenge.VerificationURI != NodeDeviceVerificationURI ||
		strings.HasPrefix(challenge.VerificationURI, "http") {
		t.Fatalf("unexpected untrusted pairing response: %+v", challenge)
	}
	if _, err := c.Fabric().AuthenticateNode(nodeToken); !errors.Is(err, fabricpkg.ErrUnauthenticated) {
		t.Fatalf("Node bearer became active before Client approval: %v", err)
	}
	preview, err := c.PreviewNodeDeviceCode(ownerID, "android", challenge.UserCode)
	if err != nil || preview.NodeID != "node-device-1" || preview.NodeName != "GPU node" ||
		preview.NodeCredentialDigest != "" || preview.CodeDigest != "" {
		t.Fatalf("owner preview returned wrong or secret Node details: %#v err=%v", preview, err)
	}
	if _, err := c.ConfirmNodeDeviceCode(ownerID, "forged-device", challenge.UserCode); !errors.Is(err, store.ErrNodeDeviceBindingUnauthorized) {
		t.Fatalf("unregistered Client device confirmed Node: %v", err)
	}
	if _, err := c.ConfirmNodeDeviceCode("another-owner", device.Public().ID, challenge.UserCode); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("another owner confirmed Node: %v", err)
	}
	binding, err := c.ConfirmNodeDeviceCode(ownerID, "android", challenge.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if binding.OwnerID != ownerID || binding.NodeID != "node-device-1" || binding.HubID == "" ||
		binding.ClientDeviceID != "android" || binding.State != "ACTIVE" {
		t.Fatalf("confirmation did not return owner-scoped state: %+v", binding)
	}
	if authenticatedNode, err := c.Fabric().AuthenticateNode(nodeToken); err != nil || authenticatedNode != "node-device-1" {
		t.Fatalf("owner-confirmed local Node bearer was not activated: node=%q err=%v", authenticatedNode, err)
	}
	beforeHeartbeat, err := c.BuildClientStatusSnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	var pendingVisible bool
	for _, node := range beforeHeartbeat.Nodes {
		if node.NodeID == "node-device-1" {
			pendingVisible = node.Verified && node.Connectivity.Known &&
				node.Connectivity.State == ClientNodeOffline && node.Connectivity.ObservedAt == ""
		}
	}
	if !pendingVisible {
		t.Fatal("confirmed-but-disconnected Node did not appear offline with no heartbeat timestamp")
	}
	if err := c.Fabric().RecordBoundNodeMachineHeartbeat(nodeToken, "available", map[string]any{
		"harnesses": []string{"codex"},
	}); err != nil {
		t.Fatalf("bound Node machine heartbeat failed: %v", err)
	}
	afterHeartbeat, err := c.BuildClientStatusSnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	var connected bool
	for _, node := range afterHeartbeat.Nodes {
		if node.NodeID == "node-device-1" {
			connected = node.Verified && node.Connectivity.Known && node.Connectivity.State == ClientNodeConnected
		}
	}
	if !connected {
		t.Fatal("bound Node heartbeat did not update verified Client connectivity")
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), nodeToken) || strings.Contains(string(encoded), credentialDigest) {
		t.Fatalf("owner binding response leaked Node credential material: %s", encoded)
	}
	bindings, err := c.NodeDeviceBindings(ownerID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != binding.ID {
		t.Fatalf("owner could not list its Node binding: %#v err=%v", bindings, err)
	}
	revoked, err := c.RevokeNodeDeviceBinding(ownerID, binding.ID, binding.Version)
	if err != nil || revoked.State != "REVOKED" {
		t.Fatalf("revoke owner Node binding: %#v err=%v", revoked, err)
	}
	if _, err := c.Fabric().AuthenticateNode(nodeToken); !errors.Is(err, fabricpkg.ErrUnauthenticated) {
		t.Fatalf("revoked Node bearer remained usable: %v", err)
	}
	if err := c.Fabric().HeartbeatNode(nodeToken); !errors.Is(err, fabricpkg.ErrUnauthenticated) {
		t.Fatalf("revoked Node heartbeat remained usable: %v", err)
	}
	revokedSnapshot, err := c.BuildClientStatusSnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range revokedSnapshot.Nodes {
		if node.NodeID == "node-device-1" && (node.Verified || node.Connectivity.Known) {
			t.Fatalf("revoked Node remained verified or connected in Client status: %+v", node)
		}
	}
}

func TestStartNodeDeviceBindingReturnsOnlyCodeAndRelativeVerificationURI(t *testing.T) {
	c, _, _ := newNodeBindingControl(t)
	_, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := c.StartNodeDeviceBinding("node-display", "node", digest)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(serialized, &response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 2 || response["user_code"] == nil || response["verification_uri"] == nil {
		t.Fatalf("unauthenticated Node response contains extra fields: %s", serialized)
	}
	if _, err := c.StartNodeDeviceBinding("node-display", "node retry", digest); !errors.Is(err, store.ErrNodeDeviceBindingRateLimited) {
		t.Fatalf("rapid same-Node code reissue was not rate limited: %v", err)
	}
	if _, err := c.PreviewNodeDeviceCode(c.Identity().ID, "android", challenge.UserCode); err != nil {
		t.Fatalf("rate-limited reissue invalidated the existing code: %v", err)
	}
}
