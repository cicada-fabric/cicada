package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

type groupDirectoryHTTPFixture struct {
	*reviewPolicyHTTPFixture
	manager   *control.Control
	group     *store.Group
	member    *store.Membership
	endpoints []*store.Endpoint
	tokens    []string
}

func newGroupDirectoryHTTPFixture(t *testing.T) *groupDirectoryHTTPFixture {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	path := filepath.Join(state, "cicada.sqlite3")
	manager, err := control.New(control.Config{StateDir: state, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-directory-manager"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	database, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	hub := httptest.NewServer(NewHandler(manager))
	t.Cleanup(hub.Close)
	hubID, err := database.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	rpc := &reviewPolicyHTTPFixture{server: hub, store: database, hubKey: manager.ClientControlPublicIdentity()}
	for _, owner := range []string{manager.Identity().ID, "synthetic-directory-foreign"} {
		if err := database.EnsureLocalOwnerPrincipal(owner); err != nil {
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
		if _, err := database.RegisterOwnerApprovalKeyLocal(owner, ownerKey.Public()); err != nil {
			t.Fatal(err)
		}
		deviceID := "synthetic-directory-phone-" + owner
		grant, err := ownerKey.SignOwnerDeviceGrant(owner, deviceID, deviceKey.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{"owner_id": owner, "owner_key_id": ownerKey.Public().ID, "device_id": deviceID, "device_public_identity": deviceKey.Public(), "owner_device_grant": grant})
		if err != nil {
			t.Fatal(err)
		}
		response, err := hub.Client().Post(hub.URL+"/v2/client/devices/enroll", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatal("synthetic Owner device enrollment failed")
		}
		a := &reviewPolicyHTTPActor{ownerID: owner, deviceID: deviceID, ownerKey: ownerKey, deviceKey: deviceKey, binding: clientwire.Binding{HubID: hubID, OwnerID: owner, DeviceID: deviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}}
		if owner == manager.Identity().ID {
			rpc.source = a
		} else {
			rpc.foreign = a
		}
	}
	network, err := database.CreateNetwork(store.Network{ID: "synthetic-directory-network", HubID: hubID, OwnerID: rpc.source.ownerID, Name: "Synthetic directory Network"})
	if err != nil {
		t.Fatal(err)
	}
	// Group creation uses the actual encrypted Owner entry, not a fixture grant.
	reply := rpc.call(t, rpc.source, "topology.apply", map[string]any{"kind": "group.create", "create_group": map[string]any{"group": map[string]any{"network_id": network.ID, "name": "Synthetic directory Group"}}})
	var created control.ClientTopologyChangeResult
	if !reply.OK || json.Unmarshal(reply.Result, &created) != nil || created.Group == nil {
		t.Fatalf("encrypted Group creation: %s", reply.Result)
	}
	group, err := database.GetGroup(created.Group.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := database.CreatePrincipal(store.Principal{ID: "synthetic-directory-principal", Kind: store.PrincipalKindAgent, OwnerID: rpc.source.ownerID, TrustDomainID: rpc.source.ownerID, Name: "Synthetic Monitor", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	member, err := database.CreateMembership(store.Membership{PrincipalID: principal.ID, GroupID: group.ID, Role: "monitor", Roles: []string{"monitor"}, Grants: []string{"task.read", "artifact.share"}, Status: store.MembershipStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := raw.Exec(`INSERT INTO network_memberships_v2(id,network_id,principal_id,grants_json,status,revision,created_at,updated_at) VALUES(?,?,?,'[]','active',1,?,?)`, "synthetic-directory-network-member", network.ID, principal.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	f := &groupDirectoryHTTPFixture{reviewPolicyHTTPFixture: rpc, manager: manager, group: group, member: member}
	for _, id := range []string{"synthetic-directory-endpoint-a", "synthetic-directory-endpoint-b"} {
		token, digest, err := fabric.NewSessionCredential()
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := database.UpsertEndpointV2(store.Endpoint{ID: id, Name: id, Harness: "codex", NativeSessionID: "synthetic-native-" + id, MachineID: "synthetic-directory-node", Owner: rpc.source.ownerID, Status: "online", PrincipalID: principal.ID, GroupID: group.ID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := database.CreateSessionBinding(store.SessionBinding{EndpointID: id, PrincipalID: principal.ID, GroupID: group.ID, NativeSessionID: endpoint.NativeSessionID, NodeID: endpoint.MachineID, CredentialHash: digest})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.AcquireSessionBindingLease(binding.ID, "synthetic-lease-"+id, binding.Epoch, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO endpoint_network_memberships_v2(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at) VALUES(?,?,'active',1,?,0,?,?)`, network.ID, id, id, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		f.endpoints = append(f.endpoints, endpoint)
		f.tokens = append(f.tokens, token)
	}
	if err := database.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	return f
}

func directoryPermissionAction(group, member string, enabled bool, version int64) map[string]any {
	return map[string]any{"kind": "membership.set_directory_permission", "set_directory_permission": map[string]any{"group_id": group, "membership_id": member, "enabled": enabled, "expected_membership_version": version}}
}
func (f *groupDirectoryHTTPFixture) directory(t *testing.T, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.server.URL+"/v2/fabric/members", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "CicadaSession "+token)
	req.Header.Set("Cicada-Group-Scope", f.group.ID)
	response, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}
func (f *groupDirectoryHTTPFixture) snapshotMember(t *testing.T) control.ClientTopologyMember {
	t.Helper()
	reply := f.call(t, f.source, "topology.snapshot", map[string]any{})
	var snapshot control.ClientTopologySnapshot
	if !reply.OK || json.Unmarshal(reply.Result, &snapshot) != nil {
		t.Fatal("encrypted snapshot failed")
	}
	for _, m := range snapshot.Memberships {
		if m.MembershipID == f.member.ID {
			return m
		}
	}
	t.Fatal("Owner snapshot omitted Membership")
	return control.ClientTopologyMember{}
}

func TestClientGroupDirectoryPermissionEncryptedHTTPEnableRetryDisable(t *testing.T) {
	f := newGroupDirectoryHTTPFixture(t)
	before := f.snapshotMember(t)
	if before.DirectoryPermissionEnabled {
		t.Fatal("role granted Directory before consent")
	}
	for _, token := range f.tokens {
		if code, _ := f.directory(t, token); code != http.StatusForbidden {
			t.Fatalf("initial Directory HTTP%d", code)
		}
	}
	packet := f.seal(t, f.source, "topology.apply", directoryPermissionAction(f.group.ID, f.member.ID, true, before.Version))
	code, response, reply := f.post(t, f.source, packet)
	if code != http.StatusOK || !reply.OK {
		t.Fatal("encrypted Directory grant rejected")
	}
	code, retried, _ := f.post(t, f.source, packet)
	if code != http.StatusOK || !bytes.Equal(response, retried) {
		t.Fatal("exact packet retry did not reuse cached response")
	}
	enabled := f.snapshotMember(t)
	if !enabled.DirectoryPermissionEnabled || enabled.Version != before.Version+1 {
		t.Fatal("grant/retry changed version incorrectly")
	}
	for i, token := range f.tokens {
		code, body := f.directory(t, token)
		if code != http.StatusOK || !bytes.Contains(body, []byte(f.endpoints[1-i].ID)) || bytes.Contains(body, []byte(f.endpoints[1-i].NativeSessionID)) {
			t.Fatalf("Principal-wide Directory privacy HTTP%d", code)
		}
		actor, err := f.manager.Fabric().AuthenticateForGroup(token, f.group.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range []string{"message.ask", "message.send", "message.broadcast", "space.read", "group.manage"} {
			if err := f.manager.Fabric().Authorize(actor, action); err == nil {
				t.Fatalf("Directory granted unrelated %s", action)
			}
		}
	}
	if f.call(t, f.source, "topology.apply", directoryPermissionAction(f.group.ID, f.member.ID, false, before.Version)).OK {
		t.Fatal("stale snapshot applied")
	}
	if !f.call(t, f.source, "topology.apply", directoryPermissionAction(f.group.ID, f.member.ID, false, enabled.Version)).OK {
		t.Fatal("encrypted Directory revoke rejected")
	}
	disabled := f.snapshotMember(t)
	if disabled.DirectoryPermissionEnabled || disabled.Version != before.Version+2 {
		t.Fatal("revoke projection/version wrong")
	}
	for _, token := range f.tokens {
		if code, _ := f.directory(t, token); code != http.StatusForbidden {
			t.Fatalf("retained native session reads after revoke HTTP%d", code)
		}
	}
	after, err := f.store.GetMembership(f.member.ID)
	if err != nil || !reflect.DeepEqual(after.Roles, f.member.Roles) || !reflect.DeepEqual(after.Grants, f.member.Grants) {
		t.Fatal("permission cycle changed roles/other grants")
	}
}

func TestClientGroupDirectoryPermissionEncryptedHTTPRejectsForgedPayloads(t *testing.T) {
	f := newGroupDirectoryHTTPFixture(t)
	cases := []struct {
		name   string
		actor  *reviewPolicyHTTPActor
		mutate func(map[string]any)
	}{
		{"foreign_Owner", f.foreign, func(map[string]any) {}},
		{"missing_flag", f.source, func(a map[string]any) { delete(a["set_directory_permission"].(map[string]any), "enabled") }},
		{"null_flag", f.source, func(a map[string]any) { a["set_directory_permission"].(map[string]any)["enabled"] = nil }},
		{"multiple_payloads", f.source, func(a map[string]any) { a["bind_role"] = map[string]any{} }},
		{"mismatched_kind", f.source, func(a map[string]any) { a["kind"] = "membership.bind_role" }},
		{"forged_Owner", f.source, func(a map[string]any) { a["owner_id"] = f.foreign.ownerID }},
		{"model_approval", f.source, func(a map[string]any) { a["set_directory_permission"].(map[string]any)["user_approved"] = true }},
		{"forged_scope", f.source, func(a map[string]any) { a["set_directory_permission"].(map[string]any)["group_id"] = "forged-group" }},
		{"missing_CAS", f.source, func(a map[string]any) {
			delete(a["set_directory_permission"].(map[string]any), "expected_membership_version")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := directoryPermissionAction(f.group.ID, f.member.ID, true, f.member.Version)
			tc.mutate(action)
			if f.call(t, tc.actor, "topology.apply", action).OK {
				t.Fatal("forged payload accepted")
			}
			after, err := f.store.GetMembership(f.member.ID)
			if err != nil || !reflect.DeepEqual(after, f.member) {
				t.Fatal("rejected action mutated Membership")
			}
		})
	}
	packet := f.seal(t, f.source, "topology.apply", directoryPermissionAction(f.group.ID, f.member.ID, true, f.member.Version))
	device, err := f.store.GetClientDevice(f.source.ownerID, f.source.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeClientDevice(f.source.ownerID, f.source.deviceID, device.Version); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.post(t, f.source, packet); code != http.StatusForbidden {
		t.Fatalf("revoked device HTTP%d", code)
	}
}
