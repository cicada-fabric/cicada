package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type encryptedGroupKeyClient struct {
	handler   http.Handler
	ownerID   string
	deviceID  string
	device    *e2ee.Identity
	hubID     string
	hubPublic e2ee.PublicIdentity
	sequence  uint64
}

func (client *encryptedGroupKeyClient) call(t *testing.T, operation string, body any) (bool, json.RawMessage) {
	t.Helper()
	plain, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	client.sequence++
	binding := clientwire.Binding{HubID: client.hubID, OwnerID: client.ownerID,
		DeviceID: client.deviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: client.sequence,
		OperationID: fmt.Sprintf("group-key-rpc-%s-%d", client.deviceID, client.sequence),
		Operation:   operation, SenderKeyID: client.device.Public().ID,
		SenderKeyVersion: 1, ReceiverKeyID: client.hubPublic.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(client.device, client.hubPublic, binding, route, plain)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet))
	client.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("encrypted operation %s transport failed: %d %s", operation, response.Code, response.Body.String())
	}
	opened, err := clientwire.OpenResponse(client.device, client.hubPublic, binding, response.Body.Bytes())
	if err != nil {
		t.Fatalf("decrypt %s response: %v", operation, err)
	}
	var outcome struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(opened.Plaintext, &outcome); err != nil {
		t.Fatalf("decode %s response: %v", operation, err)
	}
	return outcome.OK, outcome.Result
}

func TestClientGroupEndpointKeyGrantOperationsRequireEncryptedOwnerScope(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "manager-bearer"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)

	ownerID := manager.Identity().ID
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "group-key-rpc"})
	if err != nil {
		t.Fatal(err)
	}
	unjoinedGroup, err := manager.CreateGroup(control.GroupCreateInput{Name: "group-key-rpc-unjoined"})
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "group-key-phone"
	endpointID, principalID, nodeID := "endpoint-group-key-rpc", "principal-group-key-rpc", "node-group-key-rpc"
	database, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePrincipal(store.Principal{ID: principalID, Kind: store.PrincipalKindAgent,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: "Group key RPC Endpoint", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateMembership(store.Membership{PrincipalID: principalID, GroupID: group.ID, Role: "member"}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := database.UpsertEndpoint(store.Endpoint{ID: endpointID, Name: endpointID,
		Harness: "codex", NativeSessionID: "native-group-key-rpc", MachineID: nodeID,
		Owner: ownerID, Status: "online"})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := database.CreateSessionBinding(store.SessionBinding{EndpointID: endpoint.ID,
		PrincipalID: principalID, GroupID: group.ID, NativeSessionID: endpoint.NativeSessionID,
		NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	leased, err := database.AcquireSessionBindingLease(binding.ID, "lease-group-key-rpc", binding.Epoch,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
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
	unjoinedEndpointID, unjoinedPrincipalID := "endpoint-group-key-rpc-unjoined", "principal-group-key-rpc-unjoined"
	if _, err := database.CreatePrincipal(store.Principal{ID: unjoinedPrincipalID, Kind: store.PrincipalKindAgent,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: "Unjoined Group key RPC Endpoint", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateMembership(store.Membership{PrincipalID: unjoinedPrincipalID,
		GroupID: unjoinedGroup.ID, Role: "member"}); err != nil {
		t.Fatal(err)
	}
	unjoinedEndpoint, err := database.UpsertEndpoint(store.Endpoint{ID: unjoinedEndpointID,
		Name: unjoinedEndpointID, Harness: "codex", NativeSessionID: "native-group-key-rpc-unjoined",
		MachineID: nodeID, Owner: ownerID, Status: "online"})
	if err != nil {
		t.Fatal(err)
	}
	unjoinedBinding, err := database.CreateSessionBinding(store.SessionBinding{EndpointID: unjoinedEndpoint.ID,
		PrincipalID: unjoinedPrincipalID, GroupID: unjoinedGroup.ID,
		NativeSessionID: unjoinedEndpoint.NativeSessionID, NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AcquireSessionBindingLease(unjoinedBinding.ID, "lease-group-key-rpc-unjoined",
		unjoinedBinding.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	identityResponse := httptest.NewRecorder()
	handler.ServeHTTP(identityResponse, httptest.NewRequest(http.MethodGet, "/v2/client/identity", nil))
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityResponse.Body.Bytes(), &hub); err != nil || hub.HubID == "" {
		t.Fatalf("read Hub identity: %v", err)
	}
	if err := enrollGroupKeyClient(t, handler, ownerID, ownerKey, ownerDevice, deviceID, hub.HubID); err != nil {
		t.Fatal(err)
	}
	credentialDigest := sha256.Sum256([]byte("node-group-key-rpc-credential"))
	codeDigest := sha256.Sum256([]byte("node-group-key-rpc-code"))
	if _, err := database.CreatePendingNodeDeviceBinding(nodeID, nodeID,
		base64.RawURLEncoding.EncodeToString(credentialDigest[:]), hex.EncodeToString(codeDigest[:]),
		time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, hex.EncodeToString(codeDigest[:])); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	ownerClient := &encryptedGroupKeyClient{handler: handler, ownerID: ownerID, deviceID: deviceID,
		device: ownerDevice, hubID: hub.HubID, hubPublic: hub.ControlPublicIdentity}
	capabilityResponse := httptest.NewRecorder()
	handler.ServeHTTP(capabilityResponse, httptest.NewRequest(http.MethodGet, "/v2/client/capabilities", nil))
	if !bytes.Contains(capabilityResponse.Body.Bytes(), []byte(`"group_endpoint_key_grants":true`)) {
		t.Fatalf("Group Endpoint key grant capability is missing: %s", capabilityResponse.Body.String())
	}

	issuedAt := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	manifestInput := map[string]string{"group_id": group.ID, "endpoint_id": endpointID,
		"owner_key_id": ownerKey.Public().ID, "issued_at": issuedAt, "expires_at": expiresAt}
	manifestOK, manifestBody := ownerClient.call(t, "group.key_manifest", manifestInput)
	if !manifestOK {
		t.Fatalf("owner Group Endpoint key manifest was rejected: %s", manifestBody)
	}
	var manifest store.GroupEndpointKeyGrantManifest
	if err := json.Unmarshal(manifestBody, &manifest); err != nil || manifest.Digest == "" ||
		manifest.OwnerID != ownerID || manifest.GroupID != group.ID || manifest.EndpointID != endpointID {
		t.Fatalf("manifest omitted the trusted owner scope: manifest=%#v err=%v", manifest, err)
	}
	attestationDigest := sha256.Sum256(manifest.CandidateAttestation)
	if len(manifest.CandidateAttestation) == 0 || hex.EncodeToString(attestationDigest[:]) != manifest.CandidateProofDigest {
		t.Fatalf("encrypted manifest omitted or mismatched candidate attestation: bytes=%d proof_digest=%q",
			len(manifest.CandidateAttestation), manifest.CandidateProofDigest)
	}
	issued, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	linkProof, err := ownerKey.SignOwnerLinkKeyGrant(ownerID, "link-cross-protocol",
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	linkProofOK, _ := ownerClient.call(t, "group.key_grant", map[string]any{
		"group_id": group.ID, "endpoint_id": endpointID, "owner_key_id": ownerKey.Public().ID,
		"signed_proof": linkProof,
	})
	if linkProofOK {
		t.Fatal("ordinary Link proof was accepted as Group Endpoint key consent")
	}

	groupProof, err := ownerKey.SignOwnerLinkKeyGrant(ownerID, store.GroupEndpointKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	grantOK, grantBody := ownerClient.call(t, "group.key_grant", map[string]any{
		"group_id": group.ID, "endpoint_id": endpointID, "owner_key_id": ownerKey.Public().ID,
		"signed_proof": groupProof,
	})
	if !grantOK {
		t.Fatalf("owner Group Endpoint key proof was rejected: %s", grantBody)
	}
	var accepted store.OwnerGroupEndpointKeyGrant
	if err := json.Unmarshal(grantBody, &accepted); err != nil ||
		accepted.CurrentStatus != store.GroupEndpointKeyGrantCurrent || accepted.Manifest.Digest != manifest.Digest {
		t.Fatalf("unexpected accepted grant: grant=%#v err=%v", accepted, err)
	}
	statusOK, statusBody := ownerClient.call(t, "group.key_status", map[string]string{
		"group_id": group.ID, "endpoint_id": endpointID,
	})
	if !statusOK || !bytes.Contains(statusBody, []byte(`"current_status":"CURRENT"`)) {
		t.Fatalf("owner could not read current grant status: ok=%t status=%s", statusOK, statusBody)
	}
	unjoinedOK, _ := ownerClient.call(t, "group.key_manifest", map[string]string{
		"group_id": group.ID, "endpoint_id": unjoinedEndpointID, "owner_key_id": ownerKey.Public().ID,
		"issued_at": issuedAt, "expires_at": expiresAt,
	})
	if unjoinedOK {
		t.Fatal("owner received a key manifest for an Endpoint not joined to the requested Group")
	}
	staleDB, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	endpointMembership, err := staleDB.GetMembershipByPrincipalGroup(principalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleDB.RevokeMembership(endpointMembership.ID, "test key grant staleness"); err != nil {
		t.Fatal(err)
	}
	if err := staleDB.Close(); err != nil {
		t.Fatal(err)
	}
	staleOK, staleBody := ownerClient.call(t, "group.key_status", map[string]string{
		"group_id": group.ID, "endpoint_id": endpointID,
	})
	if !staleOK || !bytes.Contains(staleBody, []byte(`"current_status":"STALE"`)) {
		t.Fatalf("membership change did not stale accepted Group key grant: ok=%t status=%s", staleOK, staleBody)
	}

	guestID := "external-group-key-owner"
	guestKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	guestDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	guestDB, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guestDB.CreatePrincipal(store.Principal{ID: guestID, Kind: store.PrincipalKindHuman,
		OwnerID: guestID, TrustDomainID: guestID, Name: guestID, Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := guestDB.RegisterOwnerApprovalKeyLocal(guestID, guestKey.Public()); err != nil {
		t.Fatal(err)
	}
	if err := guestDB.Close(); err != nil {
		t.Fatal(err)
	}
	guestDeviceID := "external-group-key-phone"
	if err := enrollGroupKeyClient(t, handler, guestID, guestKey, guestDevice, guestDeviceID, hub.HubID); err != nil {
		t.Fatal(err)
	}
	guestClient := &encryptedGroupKeyClient{handler: handler, ownerID: guestID, deviceID: guestDeviceID,
		device: guestDevice, hubID: hub.HubID, hubPublic: hub.ControlPublicIdentity}
	guestCapabilitiesOK, guestCapabilitiesBody := guestClient.call(t, "session.capabilities", map[string]any{})
	if !guestCapabilitiesOK || !bytes.Contains(guestCapabilitiesBody, []byte(`group.key_manifest`)) {
		t.Fatalf("external owner was not offered Group key RPC: ok=%t capabilities=%s", guestCapabilitiesOK, guestCapabilitiesBody)
	}
	foreignManifestOK, _ := guestClient.call(t, "group.key_manifest", map[string]string{
		"group_id": group.ID, "endpoint_id": endpointID, "owner_key_id": guestKey.Public().ID,
		"issued_at": issuedAt, "expires_at": expiresAt,
	})
	if foreignManifestOK {
		t.Fatal("external owner read another owner's Group Endpoint manifest")
	}
	foreignStatusOK, _ := guestClient.call(t, "group.key_status", map[string]string{
		"group_id": group.ID, "endpoint_id": endpointID,
	})
	if foreignStatusOK {
		t.Fatal("external owner read another owner's Group Endpoint grant status")
	}
	spoofedOwnerStatusOK, _ := guestClient.call(t, "group.key_status", map[string]string{
		"owner_id": ownerID, "group_id": group.ID, "endpoint_id": endpointID,
	})
	if spoofedOwnerStatusOK {
		t.Fatal("external owner used a self-reported owner_id to read another owner's grant")
	}

	plainRequest := httptest.NewRequest(http.MethodPost, "/v2/client/rpc",
		bytes.NewReader([]byte(`{"operation":"group.key_grant","group_id":"`+group.ID+`"}`)))
	plainRequest.Header.Set("Authorization", "Bearer manager-bearer")
	plainResponse := httptest.NewRecorder()
	handler.ServeHTTP(plainResponse, plainRequest)
	if plainResponse.Code == http.StatusOK {
		t.Fatal("plaintext manager-bearer request reached Group Endpoint key grant RPC")
	}
}

func enrollGroupKeyClient(t *testing.T, handler http.Handler, ownerID string, ownerKey, deviceKey *e2ee.Identity,
	deviceID, hubID string) error {
	t.Helper()
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, deviceKey.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"owner_id": ownerID,
		"owner_key_id": ownerKey.Public().ID, "device_id": deviceID,
		"device_public_identity": deviceKey.Public(), "owner_device_grant": grant})
	if err != nil {
		return err
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(body)))
	if response.Code != http.StatusCreated {
		return errors.New(response.Body.String())
	}
	return nil
}
