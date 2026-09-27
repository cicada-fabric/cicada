package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type groupKeyHTTPTestClient struct {
	serverURL string
	http      *http.Client
	ownerID   string
	deviceID  string
	device    *e2ee.Identity
	hubID     string
	hubPublic e2ee.PublicIdentity
	sequence  uint64
}

func (client *groupKeyHTTPTestClient) call(t *testing.T, operation string, input any) (bool, json.RawMessage) {
	t.Helper()
	plaintext, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	client.sequence++
	binding := clientwire.Binding{HubID: client.hubID, OwnerID: client.ownerID,
		DeviceID: client.deviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: client.sequence,
		OperationID: fmt.Sprintf("group-key-http-%s-%d", client.deviceID, client.sequence),
		Operation:   operation, SenderKeyID: client.device.Public().ID,
		SenderKeyVersion: 1, ReceiverKeyID: client.hubPublic.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(client.device, client.hubPublic, binding, route, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	status, responseBody := clientNodeChainHTTP(t, client.http, client.serverURL, http.MethodPost,
		"/v2/client/rpc", packet, "")
	if status != http.StatusOK {
		t.Fatalf("encrypted HTTP operation %s failed: status=%d body=%s", operation, status, responseBody)
	}
	opened, err := clientwire.OpenResponse(client.device, client.hubPublic, binding, responseBody)
	if err != nil {
		t.Fatalf("decrypt encrypted HTTP operation %s: %v", operation, err)
	}
	var outcome struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(opened.Plaintext, &outcome); err != nil {
		t.Fatalf("decode encrypted HTTP operation %s: %v", operation, err)
	}
	return outcome.OK, outcome.Result
}

// TestClientGroupEndpointKeyGrantEncryptedHTTPLifecycle exercises the encrypted
// Client RPCs over an HTTP server. Its Node, SessionBinding, and Endpoint
// records are synthetic Store fixtures; it does not invoke Node or Codex.
func TestClientGroupEndpointKeyGrantEncryptedHTTPLifecycle(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	manager, err := control.New(control.Config{StateDir: stateDir,
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-manager-token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Shutdown(ctx); err != nil {
			t.Errorf("shutdown test Control: %v", err)
		}
	})

	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "synthetic-group-key-http"})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(NewHandler(manager))
	t.Cleanup(httpServer.Close)
	httpClient := httpServer.Client()
	identityStatus, identityBody := clientNodeChainHTTP(t, httpClient, httpServer.URL,
		http.MethodGet, "/v2/client/identity", nil, "")
	if identityStatus != http.StatusOK {
		t.Fatalf("read Hub identity: status=%d body=%s", identityStatus, identityBody)
	}
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityBody, &hub); err != nil || hub.HubID == "" {
		t.Fatalf("decode Hub identity: err=%v body=%s", err, identityBody)
	}

	ownerID := manager.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	guestID := "synthetic-foreign-group-key-owner"
	guestKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	guestDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	const (
		deviceID      = "synthetic-group-key-http-device"
		guestDeviceID = "synthetic-foreign-group-key-device"
		principalID   = "synthetic-group-key-http-principal"
		nodeID        = "synthetic-group-key-http-node"
		endpointID    = "synthetic-group-key-http-endpoint"
	)
	database, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	databaseClosed := false
	t.Cleanup(func() {
		if !databaseClosed {
			if err := database.Close(); err != nil {
				t.Errorf("close test Store: %v", err)
			}
		}
	})
	closeDatabase := func() {
		t.Helper()
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		databaseClosed = true
	}
	if _, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePrincipal(store.Principal{ID: principalID,
		Kind: store.PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: ownerID,
		Name: "Synthetic Group key HTTP Endpoint", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateMembership(store.Membership{PrincipalID: principalID,
		GroupID: group.ID, Role: "member"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePrincipal(store.Principal{ID: guestID,
		Kind: store.PrincipalKindHuman, OwnerID: guestID, TrustDomainID: guestID,
		Name: guestID, Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterOwnerApprovalKeyLocal(guestID, guestKey.Public()); err != nil {
		t.Fatal(err)
	}
	endpoint, err := database.UpsertEndpoint(store.Endpoint{ID: endpointID, Name: endpointID,
		Harness: "codex", NativeSessionID: "synthetic-native-group-key-http",
		MachineID: nodeID, Owner: ownerID, Status: "online"})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := database.CreateSessionBinding(store.SessionBinding{EndpointID: endpoint.ID,
		PrincipalID: principalID, GroupID: group.ID, NativeSessionID: endpoint.NativeSessionID,
		NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	leaseExpiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	leased, err := database.AcquireSessionBindingLease(binding.ID, "synthetic-group-key-http-lease",
		binding.Epoch, leaseExpiry)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := candidate.SignEndpointKeyAttestation(endpointID, principalID,
		nodeID, leased.ID, leased.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterEndpointKeyCandidate(endpointID, principalID,
		leased.ID, leased.Epoch, attestation); err != nil {
		t.Fatal(err)
	}
	enrollSyntheticGroupKeyHTTPDevice(t, httpClient, httpServer.URL, ownerID,
		ownerKey, ownerDevice, deviceID, hub.HubID)
	enrollSyntheticGroupKeyHTTPDevice(t, httpClient, httpServer.URL, guestID,
		guestKey, guestDevice, guestDeviceID, hub.HubID)
	credentialDigest := sha256.Sum256([]byte("synthetic-node-credential"))
	codeDigest := sha256.Sum256([]byte("synthetic-node-device-code"))
	if _, err := database.CreatePendingNodeDeviceBinding(nodeID, nodeID,
		base64.RawURLEncoding.EncodeToString(credentialDigest[:]), hex.EncodeToString(codeDigest[:]),
		time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConfirmPendingNodeDeviceBinding(ownerID, deviceID,
		hex.EncodeToString(codeDigest[:])); err != nil {
		t.Fatal(err)
	}
	closeDatabase()
	ownerClient := &groupKeyHTTPTestClient{serverURL: httpServer.URL, http: httpClient,
		ownerID: ownerID, deviceID: deviceID, device: ownerDevice,
		hubID: hub.HubID, hubPublic: hub.ControlPublicIdentity}
	guestClient := &groupKeyHTTPTestClient{serverURL: httpServer.URL, http: httpClient,
		ownerID: guestID, deviceID: guestDeviceID, device: guestDevice,
		hubID: hub.HubID, hubPublic: hub.ControlPublicIdentity}

	issuedAt := time.Now().UTC().Add(-time.Second)
	firstExpiresAt := time.Now().UTC().Add(time.Hour)
	manifest, ok := requestGroupEndpointKeyManifest(t, ownerClient, group.ID,
		endpointID, ownerKey.Public().ID, issuedAt, firstExpiresAt)
	if !ok {
		t.Fatal("owner's encrypted HTTP manifest request was rejected")
	}
	firstProof, err := signGroupEndpointKeyManifest(ownerKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	var tampered e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(firstProof, &tampered); err != nil || len(tampered.Signature) == 0 {
		t.Fatalf("decode synthetic Group proof before tampering: err=%v", err)
	}
	tampered.Signature[0] ^= 1
	tamperedProof, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := ownerClient.call(t, "group.key_grant", groupEndpointKeyGrantInput(
		group.ID, endpointID, ownerKey.Public().ID, tamperedProof)); ok {
		t.Fatal("Hub accepted a byte-tampered Group Endpoint owner proof over HTTP")
	}
	if ok, _ := guestClient.call(t, "group.key_grant", groupEndpointKeyGrantInput(
		group.ID, endpointID, ownerKey.Public().ID, firstProof)); ok {
		t.Fatal("Hub accepted another owner's Group Endpoint proof from a foreign encrypted session")
	}
	if ok, _ := guestClient.call(t, "group.key_status", map[string]string{
		"group_id": group.ID, "endpoint_id": endpointID,
	}); ok {
		t.Fatal("foreign owner read the Group Endpoint key status over HTTP")
	}
	if ok, result := ownerClient.call(t, "group.key_grant", groupEndpointKeyGrantInput(
		group.ID, endpointID, ownerKey.Public().ID, firstProof)); !ok {
		t.Fatalf("Hub rejected the valid owner proof over HTTP: %s", result)
	}
	if got := groupEndpointKeyHTTPStatus(t, ownerClient, group.ID, endpointID); got != store.GroupEndpointKeyGrantCurrent {
		t.Fatalf("newly accepted Group Endpoint grant status=%q, want CURRENT", got)
	}

	shortIssuedAt := time.Now().UTC().Add(-time.Second)
	shortExpiresAt := time.Now().UTC().Add(5 * time.Second)
	shortManifest, ok := requestGroupEndpointKeyManifest(t, ownerClient, group.ID,
		endpointID, ownerKey.Public().ID, shortIssuedAt, shortExpiresAt)
	if !ok {
		t.Fatal("owner's encrypted HTTP short-lived manifest request was rejected")
	}
	shortProof, err := signGroupEndpointKeyManifest(ownerKey, shortManifest)
	if err != nil {
		t.Fatal(err)
	}
	if ok, result := ownerClient.call(t, "group.key_grant", groupEndpointKeyGrantInput(
		group.ID, endpointID, ownerKey.Public().ID, shortProof)); !ok {
		t.Fatalf("Hub rejected the short-lived valid owner proof over HTTP: %s", result)
	}
	if got := groupEndpointKeyHTTPStatus(t, ownerClient, group.ID, endpointID); got != store.GroupEndpointKeyGrantCurrent {
		t.Fatalf("short-lived Group Endpoint grant status=%q before expiry, want CURRENT", got)
	}
	if expiresAt, err := time.Parse(time.RFC3339Nano, shortManifest.ExpiresAt); err != nil {
		t.Fatal(err)
	} else if wait := time.Until(expiresAt) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	if got := groupEndpointKeyHTTPStatus(t, ownerClient, group.ID, endpointID); got != store.GroupEndpointKeyGrantExpired {
		t.Fatalf("expired Group Endpoint proof status=%q, want PROOF_EXPIRED", got)
	}

	currentIssuedAt := time.Now().UTC().Add(-time.Second)
	currentExpiresAt := time.Now().UTC().Add(time.Hour)
	currentManifest, ok := requestGroupEndpointKeyManifest(t, ownerClient, group.ID,
		endpointID, ownerKey.Public().ID, currentIssuedAt, currentExpiresAt)
	if !ok {
		t.Fatal("owner's encrypted HTTP current manifest request was rejected")
	}
	currentProof, err := signGroupEndpointKeyManifest(ownerKey, currentManifest)
	if err != nil {
		t.Fatal(err)
	}
	if ok, result := ownerClient.call(t, "group.key_grant", groupEndpointKeyGrantInput(
		group.ID, endpointID, ownerKey.Public().ID, currentProof)); !ok {
		t.Fatalf("Hub rejected the renewed valid owner proof over HTTP: %s", result)
	}
	if got := groupEndpointKeyHTTPStatus(t, ownerClient, group.ID, endpointID); got != store.GroupEndpointKeyGrantCurrent {
		t.Fatalf("renewed Group Endpoint grant status=%q before membership change, want CURRENT", got)
	}

	staleDB, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	membership, err := staleDB.GetMembershipByPrincipalGroup(principalID, group.ID)
	if err != nil {
		_ = staleDB.Close()
		t.Fatal(err)
	}
	if _, err := staleDB.RevokeMembership(membership.ID, "synthetic Group key HTTP staleness check"); err != nil {
		_ = staleDB.Close()
		t.Fatal(err)
	}
	if err := staleDB.Close(); err != nil {
		t.Fatal(err)
	}
	if got := groupEndpointKeyHTTPStatus(t, ownerClient, group.ID, endpointID); got != store.GroupEndpointKeyGrantStale {
		t.Fatalf("revoked-membership Group Endpoint grant status=%q, want STALE", got)
	}
}

func enrollSyntheticGroupKeyHTTPDevice(t *testing.T, client *http.Client, baseURL, ownerID string,
	ownerKey, deviceKey *e2ee.Identity, deviceID, hubID string) {
	t.Helper()
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, deviceKey.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"owner_id": ownerID,
		"owner_key_id": ownerKey.Public().ID, "device_id": deviceID,
		"device_public_identity": deviceKey.Public(), "owner_device_grant": grant})
	if err != nil {
		t.Fatal(err)
	}
	status, responseBody := clientNodeChainHTTP(t, client, baseURL, http.MethodPost,
		"/v2/client/devices/enroll", body, "")
	if status != http.StatusCreated {
		t.Fatalf("enroll synthetic Client device %q: status=%d body=%s", deviceID, status, responseBody)
	}
}

func requestGroupEndpointKeyManifest(t *testing.T, client *groupKeyHTTPTestClient,
	groupID, endpointID, ownerKeyID string, issuedAt, expiresAt time.Time) (store.GroupEndpointKeyGrantManifest, bool) {
	t.Helper()
	body := map[string]string{"group_id": groupID, "endpoint_id": endpointID,
		"owner_key_id": ownerKeyID, "issued_at": issuedAt.UTC().Format(time.RFC3339Nano),
		"expires_at": expiresAt.UTC().Format(time.RFC3339Nano)}
	ok, result := client.call(t, "group.key_manifest", body)
	if !ok {
		return store.GroupEndpointKeyGrantManifest{}, false
	}
	var manifest store.GroupEndpointKeyGrantManifest
	if err := json.Unmarshal(result, &manifest); err != nil || manifest.Digest == "" ||
		manifest.OwnerID != client.ownerID || manifest.GroupID != groupID || manifest.EndpointID != endpointID {
		t.Fatalf("decode encrypted Group Endpoint key manifest: manifest=%#v err=%v", manifest, err)
	}
	if len(manifest.CandidateAttestation) == 0 {
		t.Fatal("encrypted manifest omitted synthetic Endpoint attestation bytes")
	}
	return manifest, true
}

func signGroupEndpointKeyManifest(ownerKey *e2ee.Identity,
	manifest store.GroupEndpointKeyGrantManifest) ([]byte, error) {
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return ownerKey.SignOwnerLinkKeyGrant(manifest.OwnerID, store.GroupEndpointKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
}

func groupEndpointKeyGrantInput(groupID, endpointID, ownerKeyID string, proof []byte) map[string]any {
	return map[string]any{"group_id": groupID, "endpoint_id": endpointID,
		"owner_key_id": ownerKeyID, "signed_proof": proof}
}

func groupEndpointKeyHTTPStatus(t *testing.T, client *groupKeyHTTPTestClient,
	groupID, endpointID string) string {
	t.Helper()
	ok, result := client.call(t, "group.key_status", map[string]string{
		"group_id": groupID, "endpoint_id": endpointID,
	})
	if !ok {
		t.Fatalf("encrypted HTTP Group Endpoint key status query was rejected: %s", result)
	}
	var status struct {
		CurrentStatus string `json:"current_status"`
	}
	if err := json.Unmarshal(result, &status); err != nil {
		t.Fatalf("decode encrypted HTTP Group Endpoint key status: %v", err)
	}
	return status.CurrentStatus
}
