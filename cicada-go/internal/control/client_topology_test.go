package control

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func createClientTopologyEndpoint(t *testing.T, c *Control, groupID, principalID, endpointID, nodeID string, alsoJoin ...string) (*store.Principal, *store.Endpoint, *store.SessionBinding) {
	t.Helper()
	ownerID := c.Identity().ID
	principal, err := c.store.CreatePrincipal(store.Principal{
		ID: principalID, Kind: store.PrincipalKindAgent, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: principalID, DisplayName: "Display " + principalID,
		Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateMembership(store.Membership{
		PrincipalID: principal.ID, GroupID: groupID, Role: "member",
		Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"},
		Status: store.MembershipStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	for _, joinedGroup := range alsoJoin {
		if _, err := c.store.CreateMembership(store.Membership{
			PrincipalID: principal.ID, GroupID: joinedGroup, Role: "member",
			Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"},
			Status: store.MembershipStatusActive,
		}); err != nil {
			t.Fatal(err)
		}
	}
	endpoint, err := c.store.UpsertEndpoint(store.Endpoint{
		ID: endpointID, Name: endpointID, Harness: "codex", NativeSessionID: "native-" + endpointID,
		MachineID: nodeID, Status: "online", Capabilities: map[string]any{"secret": "do-not-project"},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.store.CreateSessionBinding(store.SessionBinding{
		ID: "binding-" + endpointID, EndpointID: endpoint.ID, PrincipalID: principal.ID,
		GroupID: groupID, NativeSessionID: endpoint.NativeSessionID, NodeID: nodeID,
		Status: store.SessionBindingStatusActive, CredentialHash: "binding-secret-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, joinedGroup := range alsoJoin {
		if _, err := c.store.JoinEndpointGroup(endpoint.ID, joinedGroup); err != nil {
			t.Fatal(err)
		}
	}
	return principal, endpoint, binding
}

func TestClientTopologySnapshotScopesMetadataAndOmitsSecrets(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	root, err := c.CreateGroup(GroupCreateInput{Name: "root"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := c.CreateGroup(GroupCreateInput{Name: "child"})
	if err != nil {
		t.Fatal(err)
	}
	child, err = c.SetGroupParent(child.ID, root.ID, child.Version)
	if err != nil {
		t.Fatal(err)
	}
	_, endpoint, _ := createClientTopologyEndpoint(t, c, root.ID, "topology-local", "topology-endpoint", "node-local", child.ID)
	foreignGroup, err := c.store.CreateGroup(store.Group{
		ID: "group-foreign-topology", OwnerPrincipalID: "owner-foreign", TrustDomainID: "owner-foreign",
		Name: "foreign", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignPrincipal, err := c.store.CreatePrincipal(store.Principal{
		ID: "principal-foreign-topology", Kind: store.PrincipalKindAgent,
		OwnerID: "owner-foreign", TrustDomainID: "owner-foreign", Name: "foreign",
		Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateMembership(store.Membership{PrincipalID: foreignPrincipal.ID, GroupID: root.ID, Role: "member", Status: store.MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.BuildClientTopologySnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OwnerPrincipalID != ownerID || len(snapshot.Groups) != 2 || len(snapshot.Endpoints) != 1 {
		t.Fatalf("owner snapshot scope is wrong: %#v", snapshot)
	}
	var projectedChild *ClientTopologyGroup
	for i := range snapshot.Groups {
		if snapshot.Groups[i].GroupID == child.ID {
			projectedChild = &snapshot.Groups[i]
			break
		}
	}
	if projectedChild == nil || projectedChild.ParentGroupID != root.ID {
		t.Fatalf("nested group parent was not projected: %#v", projectedChild)
	}
	if snapshot.Endpoints[0].EndpointID != endpoint.ID || snapshot.Endpoints[0].BindingEpoch == 0 || len(snapshot.Endpoints[0].GroupIDs) != 2 {
		t.Fatalf("endpoint membership/binding metadata is incomplete: %#v", snapshot.Endpoints[0])
	}
	for _, membership := range snapshot.Memberships {
		if membership.PrincipalID == foreignPrincipal.ID {
			t.Fatal("foreign principal appeared in owner topology")
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"do-not-project", "binding-secret-hash", "credential_hash", "capabilities"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("topology snapshot exposed %q: %s", secret, encoded)
		}
	}
	if _, err := c.BuildClientTopologySnapshot("forged-owner"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forged owner snapshot err=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange("forged-owner", ClientTopologyAction{
		Kind: ClientTopologyCreateGroup, CreateGroup: &ClientTopologyCreateGroupAction{Group: GroupCreateInput{Name: "forged"}},
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forged owner mutation err=%v", err)
	}
	if _, err := c.store.GetGroup(foreignGroup.ID); err != nil {
		t.Fatal(err)
	}
}

func TestApplyClientTopologyGroupParentAndExplicitRoleCAS(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	root, err := c.CreateGroup(GroupCreateInput{Name: "root"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:        ClientTopologyCreateGroup,
		CreateGroup: &ClientTopologyCreateGroupAction{Group: GroupCreateInput{Name: "nested"}, ParentGroupID: root.ID},
	})
	if err != nil || created.Group == nil || created.Group.ParentGroupID != root.ID {
		t.Fatalf("nested group creation result=%#v err=%v", created, err)
	}
	member, err := c.AddGroupMember(created.Group.GroupID, GroupMemberInput{Name: "candidate"})
	if err != nil {
		t.Fatal(err)
	}
	if member.Role != "member" || containsGrant(member.Grants, "resource.execute") {
		t.Fatalf("membership join granted an execution role: %#v", member)
	}
	bound, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyBindRole,
		BindRole: &ClientTopologyBindRoleAction{GroupID: created.Group.GroupID, MembershipID: member.ID,
			Role: "worker", ExpectedMembershipVersion: member.Version},
	})
	if err != nil || bound.Membership == nil || bound.Membership.Role != "worker" {
		t.Fatalf("worker role binding=%#v err=%v", bound, err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyBindRole,
		BindRole: &ClientTopologyBindRoleAction{GroupID: created.Group.GroupID, MembershipID: member.ID,
			Role: "monitor", ExpectedMembershipVersion: member.Version},
	}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale role update err=%v", err)
	}
	demoted, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyBindRole,
		BindRole: &ClientTopologyBindRoleAction{GroupID: created.Group.GroupID, MembershipID: member.ID,
			Role: "member", ExpectedMembershipVersion: bound.Membership.Version},
	})
	if err != nil || demoted.Membership == nil || demoted.Membership.Role != "member" {
		t.Fatalf("role revocation/demotion=%#v err=%v", demoted, err)
	}
	if containsGrant(demoted.Membership.Roles, "worker") {
		t.Fatalf("worker role remained after demotion: %#v", demoted.Membership)
	}
	storedDemotion, err := c.store.GetMembership(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if containsGrant(storedDemotion.Grants, "resource.execute") || containsGrant(storedDemotion.Grants, "federation.produce") {
		t.Fatalf("worker grants remained after demotion: %#v", storedDemotion.Grants)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:      ClientTopologySetParent,
		SetParent: &ClientTopologySetParentAction{GroupID: created.Group.GroupID, ParentGroupID: "", ExpectedGroupVersion: root.Version},
	}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale parent change err=%v", err)
	}
	foreignGroup, err := c.store.CreateGroup(store.Group{ID: "group-foreign-parent", OwnerPrincipalID: "foreign", TrustDomainID: "foreign", Name: "foreign", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:      ClientTopologySetParent,
		SetParent: &ClientTopologySetParentAction{GroupID: root.ID, ParentGroupID: foreignGroup.ID, ExpectedGroupVersion: root.Version},
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-owner parent change err=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:     ClientTopologyBindRole,
		BindRole: &ClientTopologyBindRoleAction{GroupID: root.ID, MembershipID: member.ID, Role: "monitor", ExpectedMembershipVersion: demoted.Membership.Version},
	}); !errors.Is(err, store.ErrMembershipNotFound) {
		t.Fatalf("cross-group membership role binding err=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:        ClientTopologyCreateGroup,
		CreateGroup: &ClientTopologyCreateGroupAction{Group: GroupCreateInput{Name: "must-not-create"}, ParentGroupID: foreignGroup.ID},
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("foreign parent group creation err=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:        ClientTopologyCreateGroup,
		CreateGroup: &ClientTopologyCreateGroupAction{Group: GroupCreateInput{Name: "extra"}},
		SetParent:   &ClientTopologySetParentAction{GroupID: root.ID, ExpectedGroupVersion: root.Version},
	}); err == nil {
		t.Fatal("ambiguous action union was accepted")
	}
}

func TestClientTopologyNestedCreateDoesNotLeaveRootAfterParentGrantRevocation(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	parent, err := c.CreateGroup(GroupCreateInput{Name: "nested-parent"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := c.store.ListGroups(store.GroupFilter{Owner: ownerID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.RevokeMembershipForPrincipalGroup(ownerID, parent.ID, "synthetic revoke"); err != nil {
		t.Fatal(err)
	}
	result, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyCreateGroup,
		CreateGroup: &ClientTopologyCreateGroupAction{
			Group: GroupCreateInput{Name: "must-not-survive"}, ParentGroupID: parent.ID,
		},
	})
	if !errors.Is(err, store.ErrNetworkPermission) || result != nil {
		t.Fatalf("revoked parent accepted nested Group: %+v, %v", result, err)
	}
	after, err := c.store.ListGroups(store.GroupFilter{Owner: ownerID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed nested create left %d extra Groups", len(after)-len(before))
	}
	for _, group := range after {
		if group.Name == "must-not-survive" {
			t.Fatal("failed nested create left a root Group")
		}
	}
}

func TestApplyClientTopologyJoinLeaveIsOwnerScopedAndFenced(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	groupA, err := c.CreateGroup(GroupCreateInput{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := c.CreateGroup(GroupCreateInput{Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	groupC, err := c.CreateGroup(GroupCreateInput{Name: "c"})
	if err != nil {
		t.Fatal(err)
	}
	_, endpoint, binding := createClientTopologyEndpoint(t, c, groupA.ID, "topology-joiner", "topology-join-endpoint", "node", groupB.ID)
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyJoinGroup, JoinGroup: &ClientTopologyJoinGroupAction{EndpointID: endpoint.ID, GroupID: groupB.ID},
	}); err != nil {
		t.Fatal(err)
	}
	joined, err := c.store.GetEndpointGroupMembership(endpoint.ID, groupB.ID)
	if err != nil || joined.Status != store.MembershipStatusActive {
		t.Fatalf("explicit second Group membership=%#v err=%v", joined, err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyJoinGroup, JoinGroup: &ClientTopologyJoinGroupAction{EndpointID: endpoint.ID, GroupID: groupC.ID},
	}); !errors.Is(err, store.ErrMembershipNotActive) {
		t.Fatalf("endpoint crossed into a group without Principal membership: %v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyLeaveGroup,
		LeaveGroup: &ClientTopologyLeaveGroupAction{EndpointID: endpoint.ID, GroupID: groupB.ID,
			BindingID: binding.ID, ExpectedBindingEpoch: binding.Epoch + 1},
	}); !errors.Is(err, store.ErrSessionBindingStaleEpoch) {
		t.Fatalf("stale leave epoch err=%v", err)
	}
	left, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyLeaveGroup,
		LeaveGroup: &ClientTopologyLeaveGroupAction{EndpointID: endpoint.ID, GroupID: groupB.ID,
			BindingID: binding.ID, ExpectedBindingEpoch: binding.Epoch},
	})
	if err != nil || left.RemainingGroupID != groupA.ID {
		t.Fatalf("leave second group result=%#v err=%v", left, err)
	}
	if ok, err := c.store.IsEndpointGroupActive(endpoint.ID, groupB.ID); err != nil || ok {
		t.Fatalf("left Group remains active: active=%v err=%v", ok, err)
	}
	if ok, err := c.store.IsEndpointGroupActive(endpoint.ID, groupA.ID); err != nil || !ok {
		t.Fatalf("remaining Group was lost: active=%v err=%v", ok, err)
	}
	foreignPrincipal, err := c.store.CreatePrincipal(store.Principal{ID: "foreign-topology-endpoint", Kind: store.PrincipalKindAgent, OwnerID: "foreign-owner", Name: "foreign", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateMembership(store.Membership{PrincipalID: foreignPrincipal.ID, GroupID: groupA.ID, Role: "member", Status: store.MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	foreignEndpoint, err := c.store.UpsertEndpoint(store.Endpoint{ID: "ep-foreign-topology", Name: "foreign", Harness: "codex", NativeSessionID: "native-foreign", MachineID: "node"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateSessionBinding(store.SessionBinding{ID: "binding-foreign-topology", EndpointID: foreignEndpoint.ID,
		PrincipalID: foreignPrincipal.ID, GroupID: groupA.ID, NativeSessionID: foreignEndpoint.NativeSessionID, NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyJoinGroup, JoinGroup: &ClientTopologyJoinGroupAction{EndpointID: foreignEndpoint.ID, GroupID: groupA.ID},
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("foreign Endpoint join err=%v", err)
	}
}

func TestApplyClientTopologyLinkProposalAndRevocationFailClosed(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	groupA, err := c.CreateGroup(GroupCreateInput{Name: "link-a"})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := c.CreateGroup(GroupCreateInput{Name: "link-b"})
	if err != nil {
		t.Fatal(err)
	}
	_, source, _ := createClientTopologyEndpoint(t, c, groupA.ID, "link-source", "ep-link-source", "node-a")
	_, target, _ := createClientTopologyEndpoint(t, c, groupB.ID, "link-target", "ep-link-target", "node-b")
	proposal := CommunicationLinkProposalInput{
		SourceEndpointID: source.ID, SourceGroupID: groupA.ID, TargetEndpointID: target.ID, TargetGroupID: groupB.ID,
		Direction: "forward", Actions: []string{"ask", "reply"}, DataScopes: []string{"benchmark.public"},
		TransportHubID: "hub-local", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}
	created, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyProposeLink, ProposeLink: &ClientTopologyProposeLinkAction{Proposal: proposal},
	})
	if err != nil || created.Link == nil || created.Link.State != store.CommunicationLinkProposed {
		t.Fatalf("link proposal=%#v err=%v", created, err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:       ClientTopologyRevokeLink,
		RevokeLink: &ClientTopologyRevokeLinkAction{LinkID: created.Link.LinkID, ExpectedLinkVersion: created.Link.Version + 1},
	}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale link revoke err=%v", err)
	}
	revoked, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:       ClientTopologyRevokeLink,
		RevokeLink: &ClientTopologyRevokeLinkAction{LinkID: created.Link.LinkID, ExpectedLinkVersion: created.Link.Version, Reason: "user revoked"},
	})
	if err != nil || revoked.Link == nil || revoked.Link.State != store.CommunicationLinkRevoked {
		t.Fatalf("link revoke=%#v err=%v", revoked, err)
	}
	foreignOwner := "foreign-owner"
	foreignGroup, err := c.store.CreateGroup(store.Group{ID: "group-link-foreign", OwnerPrincipalID: foreignOwner, TrustDomainID: foreignOwner, Name: "foreign", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind: ClientTopologyProposeLink,
		ProposeLink: &ClientTopologyProposeLinkAction{Proposal: CommunicationLinkProposalInput{
			SourceEndpointID: source.ID, SourceGroupID: groupA.ID, TargetEndpointID: target.ID, TargetGroupID: foreignGroup.ID,
			Direction: "forward", Actions: []string{"ask"}, DataScopes: []string{"benchmark.public"},
			TransportHubID: "hub-local", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		}},
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-owner link proposal err=%v", err)
	}
	snapshot, err := c.BuildClientTopologySnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range snapshot.Links {
		if link.LinkID == created.Link.LinkID && link.State != store.CommunicationLinkRevoked {
			t.Fatalf("revoked link state was not reflected: %#v", link)
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "contract_digest") || strings.Contains(string(encoded), "source_owner_id") {
		t.Fatalf("topology exposed internal link fields: %s", encoded)
	}
}

func TestClientTopologyParentCycleRejected(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	parent, err := c.CreateGroup(GroupCreateInput{Name: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := c.CreateGroup(GroupCreateInput{Name: "child"})
	if err != nil {
		t.Fatal(err)
	}
	linked, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:      ClientTopologySetParent,
		SetParent: &ClientTopologySetParentAction{GroupID: child.ID, ParentGroupID: parent.ID, ExpectedGroupVersion: child.Version},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:      ClientTopologySetParent,
		SetParent: &ClientTopologySetParentAction{GroupID: parent.ID, ParentGroupID: child.ID, ExpectedGroupVersion: parent.Version},
	}); !errors.Is(err, store.ErrGroupHierarchyCycle) {
		t.Fatalf("cycle was accepted: %v", err)
	}
	if linked.Group.ParentGroupID != parent.ID {
		t.Fatalf("parent assignment not reflected: %#v", linked.Group)
	}
}

func TestClientTopologyMissingIDsFailClosed(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "known"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:      ClientTopologySetParent,
		SetParent: &ClientTopologySetParentAction{GroupID: "missing-group", ExpectedGroupVersion: 1},
	}); !errors.Is(err, store.ErrGroupNotFound) {
		t.Fatalf("missing Group error=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:      ClientTopologyJoinGroup,
		JoinGroup: &ClientTopologyJoinGroupAction{EndpointID: "missing-endpoint", GroupID: group.ID},
	}); !errors.Is(err, store.ErrEndpointNotFound) {
		t.Fatalf("missing Endpoint error=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:     ClientTopologyBindRole,
		BindRole: &ClientTopologyBindRoleAction{GroupID: group.ID, MembershipID: "missing-membership", Role: "worker", ExpectedMembershipVersion: 1},
	}); !errors.Is(err, store.ErrMembershipNotFound) {
		t.Fatalf("missing Membership error=%v", err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID, ClientTopologyAction{
		Kind:       ClientTopologyRevokeLink,
		RevokeLink: &ClientTopologyRevokeLinkAction{LinkID: "missing-link", ExpectedLinkVersion: 1},
	}); !errors.Is(err, store.ErrCommunicationLinkNotFound) {
		t.Fatalf("missing link error=%v", err)
	}
}
