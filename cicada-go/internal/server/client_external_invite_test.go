package server

import (
	"bytes"
	"context"
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
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestEncryptedExternalThreadInvitationUsesTwoOwnerSessionsAndStaysNonRoutable(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"),
		WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "legacy-manager"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	database, err := store.New(filepath.Join(root, "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	managerOwnerID := manager.Identity().ID
	guestOwnerID := "guest-invite-owner"
	if _, err := database.CreatePrincipal(store.Principal{ID: guestOwnerID, Kind: store.PrincipalKindHuman,
		OwnerID: guestOwnerID, TrustDomainID: guestOwnerID, Name: "Guest", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	managerGroup, err := manager.CreateGroup(control.GroupCreateInput{Name: "Alice's group"})
	if err != nil {
		t.Fatal(err)
	}
	guestGroup, err := database.CreateGroup(store.Group{Name: "Bob's group", OwnerPrincipalID: guestOwnerID,
		TrustDomainID: guestOwnerID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := manager.Fabric().Join(fabric.JoinInput{GroupID: managerGroup.ID,
		EndpointName: "Alice agent", Harness: "codex", NativeSessionID: "alice-native-invite",
		NodeID: "alice-node", Workspace: "/work/alice"})
	if err != nil {
		t.Fatal(err)
	}
	guestFabric, err := fabric.NewService(database, guestOwnerID, guestOwnerID)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := guestFabric.Join(fabric.JoinInput{GroupID: guestGroup.ID,
		EndpointName: "Bob agent", Harness: "codex", NativeSessionID: "bob-native-invite",
		NodeID: "bob-node", Workspace: "/work/bob"})
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := manager.ClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	hubPublic := manager.ClientControlPublicIdentity()
	handler := NewHandler(manager)
	type enrolled struct {
		ownerID  string
		deviceID string
		key      *e2ee.Identity
		seq      uint64
	}
	enroll := func(ownerID, deviceID string) *enrolled {
		t.Helper()
		ownerKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
			t.Fatal(err)
		}
		device, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), hubID,
			e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
			"device_id": deviceID, "device_public_identity": device.Public(), "owner_device_grant": grant})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v2/client/devices/enroll", bytes.NewReader(body)))
		if response.Code != http.StatusCreated {
			t.Fatalf("enroll %s: %d %s", ownerID, response.Code, response.Body.String())
		}
		return &enrolled{ownerID: ownerID, deviceID: deviceID, key: device}
	}
	managerClient := enroll(managerOwnerID, "alice-phone")
	guestClient := enroll(guestOwnerID, "bob-phone")
	call := func(client *enrolled, operation string, input any) (bool, json.RawMessage) {
		t.Helper()
		client.seq++
		binding := clientwire.Binding{HubID: hubID, OwnerID: client.ownerID, DeviceID: client.deviceID,
			SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: hubID, OwnerID: client.ownerID, DeviceID: client.deviceID, SessionEpoch: 1,
			Sequence: client.seq, OperationID: fmt.Sprintf("invite-%s-%d", client.deviceID, client.seq),
			Operation: operation, SenderKeyID: client.key.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: hubPublic.ID, ReceiverKeyVersion: 1}
		plaintext, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := clientwire.SealRequest(client.key, hubPublic, binding, route, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v2/client/rpc", bytes.NewReader(packet)))
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s transport: %d %s", client.ownerID, operation, response.Code, response.Body.String())
		}
		opened, err := clientwire.OpenResponse(client.key, hubPublic, binding, response.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(opened.Plaintext, &result); err != nil {
			t.Fatal(err)
		}
		return result.OK, result.Result
	}
	create := map[string]any{"source_endpoint_id": alice.Endpoint.ID, "source_group_id": managerGroup.ID,
		"hub_id": hubID, "actions": []string{"ask", "reply"},
		"data_scopes": []string{"benchmark.public_result"},
		"expires_at":  time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano)}
	if ok, _ := call(guestClient, "link.invite_create", create); ok {
		t.Fatal("guest owner proposed from another owner's Endpoint")
	}
	ok, createdRaw := call(managerClient, "link.invite_create", create)
	var created store.ExternalThreadInviteCreated
	if !ok || json.Unmarshal(createdRaw, &created) != nil || created.Token == "" || created.HubID != hubID {
		t.Fatalf("encrypted invite create failed: ok=%t result=%s", ok, createdRaw)
	}
	if ok, _ := call(guestClient, "link.invite_preview", map[string]string{"token": "invalid"}); ok {
		t.Fatal("guessed invite token was accepted")
	}
	ok, preview := call(guestClient, "link.invite_preview", map[string]string{"token": created.Token})
	if !ok || !bytes.Contains(preview, []byte("alice-agent")) ||
		bytes.Contains(preview, []byte(alice.Endpoint.ID)) || bytes.Contains(preview, []byte(managerGroup.ID)) {
		t.Fatalf("external preview disclosed private IDs or failed: ok=%t result=%s", ok, preview)
	}
	accept := map[string]string{"token": created.Token, "target_endpoint_id": bob.Endpoint.ID,
		"target_group_id": guestGroup.ID}
	if ok, _ := call(managerClient, "link.invite_accept", accept); ok {
		t.Fatal("source owner accepted its own external invitation")
	}
	ok, acceptedRaw := call(guestClient, "link.invite_accept", accept)
	var accepted store.ExternalThreadInviteAcceptance
	if !ok || json.Unmarshal(acceptedRaw, &accepted) != nil ||
		accepted.LinkID == "" || accepted.State != store.CommunicationLinkProposed {
		t.Fatalf("second owner acceptance failed: ok=%t result=%s", ok, acceptedRaw)
	}
	if ok, _ := call(guestClient, "link.invite_accept", accept); ok {
		t.Fatal("one-time external invitation was consumed twice")
	}
	if ok, _ := call(managerClient, "link.invite_preview", map[string]string{"token": created.Token}); ok {
		t.Fatal("consumed token remained previewable")
	}
	for _, client := range []*enrolled{managerClient, guestClient} {
		ok, pageRaw := call(client, "link.list", map[string]any{"limit": 10})
		var page control.ClientCommunicationLinksPage
		if !ok || json.Unmarshal(pageRaw, &page) != nil || len(page.Links) != 1 ||
			page.Links[0].Link.LinkID != accepted.LinkID || page.HasMore {
			t.Fatalf("owner did not recover accepted Link: owner=%s ok=%t page=%s", client.ownerID, ok, pageRaw)
		}
		wantSide := "SOURCE"
		if client == guestClient {
			wantSide = "TARGET"
		}
		if page.Links[0].MySide != wantSide {
			t.Fatalf("Link owner side mismatch: got=%s want=%s", page.Links[0].MySide, wantSide)
		}
	}
	if ok, _ := call(guestClient, "link.list", map[string]any{"cursor": "invalid"}); ok {
		t.Fatal("invalid Link page cursor was accepted")
	}
	link, err := database.GetCommunicationLinkForOwner(accepted.LinkID, managerOwnerID)
	if err != nil || link.State != store.CommunicationLinkProposed ||
		link.SourceOwnerID != managerOwnerID || link.TargetOwnerID != guestOwnerID ||
		link.SourceEndpointID != alice.Endpoint.ID || link.TargetEndpointID != bob.Endpoint.ID {
		t.Fatalf("cross-owner proposal was not bounded: link=%#v err=%v", link, err)
	}
	actor, err := manager.Fabric().Authenticate(alice.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Fabric().Ask(actor, fabric.AskInput{Target: bob.Endpoint.ID,
		Question: "What is the current result?"}); !errors.Is(err, fabric.ErrCrossGroupDirectDenied) {
		t.Fatalf("unactivated cross-user Link became a peer route: %v", err)
	}
	if ok, result := call(guestClient, "topology.apply", map[string]any{
		"kind": "link.revoke", "revoke_link": map[string]any{
			"link_id": accepted.LinkID, "expected_link_version": accepted.Version,
		}}); !ok || !bytes.Contains(result, []byte(`"state":"REVOKED"`)) {
		t.Fatalf("target owner could not revoke accepted proposal: ok=%t result=%s", ok, result)
	}
}
