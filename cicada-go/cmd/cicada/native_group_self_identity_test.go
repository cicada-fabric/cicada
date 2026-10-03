package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

// Real MCP -> owner-only Unix Join bridge -> HTTP -> Store, using the reviewed
// Network/native adapter fixture. Session records are synthetic, not a native run.
func TestNativeGroupJoinAndSelfCandidateWithoutDirectoryGrant(t *testing.T) {
	for _, role := range []string{"member", "monitor"} {
		t.Run(role, func(t *testing.T) {
			f := newNativeNetworkBindingFixture(t)
			if _, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID}); err != nil {
				t.Fatal(err)
			}
			networkState := f.state(t)
			group, err := f.persistence.CreateClientTopologyGroupAtomic(store.Group{
				NetworkID: f.networkID, OwnerPrincipalID: f.ownerID, TrustDomainID: f.ownerID,
				Name: "Synthetic explicitly admitted Group", State: store.GroupStateActive,
				ContextPolicy: "group_scoped", IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated"},
				"", f.clientRequest(t, "topology.apply"))
			if err != nil {
				t.Fatal(err)
			}
			preview, err := f.persistence.PreviewClientTopologyEndpointAdmissionForClientRequest(
				f.clientRequest(t, store.ClientTopologyEndpointAdmissionPreviewOperation), f.ownerID,
				f.networkID, group.ID, networkState.EndpointID)
			if err != nil {
				t.Fatal(err)
			}
			member, _, err := f.persistence.AdmitClientTopologyEndpointForClientRequest(f.clientRequest(t, "topology.apply"), f.ownerID,
				store.ClientTopologyEndpointAdmissionInput{NetworkID: f.networkID, GroupID: group.ID,
					EndpointID: networkState.EndpointID, ExpectedEndpointMigrationState: preview.EndpointMigrationState,
					ExpectedNetworkVersion: preview.NetworkVersion, ExpectedGroupVersion: preview.GroupVersion,
					ExpectedNetworkMembership: preview.NetworkMembershipRevision, ExpectedEndpointNetwork: preview.EndpointNetworkRevision,
					NetworkAccessBindingID: preview.NetworkAccessBindingID, NetworkAccessEpoch: preview.NetworkAccessEpoch,
					NativeBindingID: preview.NativeBindingID, NativeBindingEpoch: preview.NativeBindingEpoch})
			if err != nil {
				t.Fatal(err)
			}
			if len(member.Grants) != 0 || member.Role != "member" {
				t.Fatal("admission added permissions")
			}
			if role == "monitor" {
				member, err = f.persistence.UpdateMembershipAuthorization(member.ID, []string{"monitor"},
					[]string{"federation.represent", "task.read", "task.verify", "artifact.share"}, map[string]any{}, member.Version)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.mcp.callTool("cicada_join", map[string]any{"group_id": group.ID})
			if err != nil {
				t.Fatalf("Join blocked own key publication without directory grant: %v", err)
			}
			joined, ok := result.(mcpPublicJoinResult)
			if !ok || joined.Endpoint.ID != networkState.EndpointID || joined.Endpoint.NativeSessionID != f.nativeID ||
				joined.BindingID == "" || joined.BindingEpoch == 0 || joined.NativeContextScope == nil || !joined.NativeContextScope.Accepted {
				t.Fatal("Group Join replaced or failed to activate the original native identity")
			}
			candidate, err := f.persistence.GetEndpointKeyCandidate(joined.Endpoint.ID)
			if err != nil || candidate.BindingID != joined.BindingID || candidate.BindingEpoch != joined.BindingEpoch ||
				candidate.State != store.EndpointKeyCandidateStateCandidate {
				t.Fatalf("Join failed own public candidate publication: %v", err)
			}
			if _, err := f.mcp.callTool("cicada_whoami", nil); err != nil {
				t.Fatalf("MCP own identity blocked: %v", err)
			}
			if _, err := f.mcp.callTool("cicada_publish_endpoint_key_candidate", nil); err != nil {
				t.Fatalf("explicit MCP own candidate publication blocked: %v", err)
			}
			afterCandidate, err := f.persistence.GetEndpointKeyCandidate(joined.Endpoint.ID)
			if err != nil || afterCandidate.KeyID != candidate.KeyID || afterCandidate.Version != candidate.Version {
				t.Fatal("repeat self publication changed identity/version")
			}
			if _, err := f.mcp.callTool("cicada_members", nil); err == nil {
				t.Fatal("zero directory grant allowed peer enumeration")
			}
			if _, err := f.mcp.callTool("cicada_find", map[string]any{"query": joined.Endpoint.ID}); err == nil {
				t.Fatal("Directory alias path bypassed grant check even for self")
			}
			after, err := f.persistence.GetMembership(member.ID)
			if err != nil || after.Role != member.Role || after.Version != member.Version || after.Revision != member.Revision ||
				len(after.Grants) != len(member.Grants) {
				t.Fatal("Join/self operations expanded membership")
			}
			for _, grant := range after.Grants {
				if grant == "directory.read" {
					t.Fatal("Join implicitly granted directory access")
				}
			}
			var grants, endpoints int
			if err := f.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE endpoint_id=?`, joined.Endpoint.ID).Scan(&grants); err != nil || grants != 0 {
				t.Fatal("candidate publication created Owner key consent")
			}
			if err := f.db.QueryRow(`SELECT count(*) FROM fabric_endpoints WHERE native_session_id=?`, f.nativeID).Scan(&endpoints); err != nil || endpoints != 1 {
				t.Fatal("Join created another native Endpoint")
			}
			if native := f.binding(t, joined.Endpoint.ID); native.ID != preview.NativeBindingID || native.Epoch != preview.NativeBindingEpoch {
				t.Fatal("Group Join changed independent Network native binding")
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			f.mcp.sessionMu.RLock()
			sessionToken := f.mcp.sessionToken
			f.mcp.sessionMu.RUnlock()
			if sessionToken == "" || bytes.Contains(encoded, []byte(sessionToken)) || bytes.Contains(encoded, []byte(f.join.OwnerJoinProof)) {
				t.Fatal("MCP result leaked credentials")
			}
			actor, err := f.service.AuthenticateForGroup(sessionToken, group.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, grant := range []string{"message.send", "message.ask", "message.receive", "space.read"} {
				if err := f.service.Authorize(actor, grant); err == nil {
					t.Fatalf("Join enabled traffic/history grant %s", grant)
				}
			}
			if candidate.PrincipalID != actor.PrincipalID || actor.EndpointID != networkState.EndpointID {
				t.Fatal("self key identity was not session-derived")
			}
		})
	}
}
