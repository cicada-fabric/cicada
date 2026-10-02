package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
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

func TestClientTopologySnapshotProjectsCurrentGroupContextPolicies(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	ordinary, err := c.CreateGroup(GroupCreateInput{
		Name: "ordinary context", ContextPolicy: "group_scoped",
	})
	if err != nil {
		t.Fatal(err)
	}
	dedicated, err := c.CreateGroup(GroupCreateInput{
		Name: "dedicated context", ContextPolicy: store.DedicatedThreadContextPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.BuildClientTopologySnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	policies := make(map[string]string, len(snapshot.Groups))
	for _, group := range snapshot.Groups {
		policies[group.GroupID] = group.ContextPolicy
	}
	if policies[ordinary.ID] != "group_scoped" || policies[dedicated.ID] != store.DedicatedThreadContextPolicy {
		t.Fatalf("topology snapshot omitted or changed Group context policy: groups=%#v", snapshot.Groups)
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

// These are synthetic, disposable identities. The fixture uses real Owner
// enrollment, Network consent and ClientWire authentication; it never starts
// Control workers or invokes a model/runtime.
type clientTopologyMutationFixture struct {
	c            *Control
	owner        *e2ee.Identity
	device       *e2ee.Identity
	ownerKey     *store.OwnerApprovalKey
	registered   *store.ClientDevice
	hubID        string
	groups       [2]*store.Group
	endpoints    [2]*store.Endpoint
	bindings     [2]*store.SessionBinding
	sourceMember *store.Membership
	sequence     uint64
}

func newClientTopologyMutationFixture(t *testing.T) *clientTopologyMutationFixture {
	t.Helper()
	f := &clientTopologyMutationFixture{c: newClientStatusControl(t, time.Minute)}
	ownerID := f.c.Identity().ID
	if err := f.c.store.EnsureLocalOwnerPrincipal(ownerID); err != nil {
		t.Fatal(err)
	}
	var err error
	f.owner, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.device, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.ownerKey, err = f.c.store.RegisterOwnerApprovalKeyLocal(ownerID, f.owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	f.hubID, err = f.c.ClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	grant, err := f.owner.SignOwnerDeviceGrant(ownerID, "synthetic-canvas-device", f.device.Public(),
		f.hubID, e2ee.OwnerDevicePurposeControl, at.Add(-time.Minute), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.registered, err = f.c.RegisterClientDevice(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: f.ownerKey.KeyID, DeviceID: "synthetic-canvas-device",
		DevicePublic: f.device.Public(), OwnerDeviceGrant: grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.c.store.CreateNetwork(store.Network{ID: "synthetic-canvas-network",
		HubID: f.hubID, Name: "Synthetic Canvas Network", OwnerID: ownerID, State: store.NetworkStateActive})
	if err != nil {
		t.Fatal(err)
	}
	for i, label := range []string{"source", "target"} {
		f.groups[i], err = f.c.store.CreateGroup(store.Group{ID: "synthetic-canvas-group-" + label,
			NetworkID: network.ID, OwnerPrincipalID: ownerID, TrustDomainID: ownerID,
			Name: "Synthetic " + label, State: store.GroupStateActive, ContextPolicy: "group_scoped"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.c.store.CreateMembership(store.Membership{PrincipalID: ownerID, GroupID: f.groups[i].ID,
			Role: "owner", Roles: []string{"owner"}, Grants: []string{"group.manage", "membership.manage"},
			Status: store.MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	const nodeID = "synthetic-canvas-node"
	nodeDigestBytes := sha256.Sum256([]byte("synthetic-canvas-node-credential"))
	nodeDigest := base64.RawURLEncoding.EncodeToString(nodeDigestBytes[:])
	codeDigest := store.NetworkInvitationDigest("synthetic-canvas-node-code")
	if _, err := f.c.store.CreatePendingNodeDeviceBinding(nodeID, "Synthetic Canvas Node", nodeDigest,
		codeDigest, at.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.store.ConfirmPendingNodeDeviceBinding(ownerID, f.registered.DeviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	for i, label := range []string{"source", "target"} {
		invitation := "synthetic-canvas-network-invitation-" + label + "-aaaaaaaaaaaaaaaa"
		nativeID := "synthetic-canvas-native-" + label
		grants := []string{"directory.discover", "directory.publish"}
		expiry := at.Add(time.Hour).Format(time.RFC3339Nano)
		if err := f.c.store.IssueNetworkInvitation(network.ID, ownerID, ownerID, invitation, expiry, grants); err != nil {
			t.Fatal(err)
		}
		proof, err := f.owner.SignOwnerNetworkJoinGrant(ownerID, f.hubID, network.ID, nodeID,
			nativeID, store.NetworkInvitationDigest(invitation), f.ownerKey.KeyID, grants, true,
			at.Add(-time.Minute), at.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var claims e2ee.OwnerNetworkJoinGrant
		if err := json.Unmarshal(proof, &claims); err != nil {
			t.Fatal(err)
		}
		joined, err := f.c.store.AcceptNetworkJoin(store.AcceptNetworkJoinInput{
			NetworkID: network.ID, OwnerID: ownerID, TrustDomainID: ownerID, NodeID: nodeID,
			NativeSessionID: nativeID, Harness: "codex", EndpointName: "Synthetic " + label,
			InvitationToken: invitation, ProofNonce: claims.Nonce,
			ProofDigest: store.NetworkInvitationDigest(string(proof)), ProofExpiresAt: claims.ExpiresAt,
			OwnerKeyID: f.ownerKey.KeyID, OwnerJoinProof: string(proof), NodeCredentialHash: nodeDigest,
			Grants: grants, Discoverable: true, CredentialHash: store.NetworkInvitationDigest("synthetic-access-" + label),
			LeaseOwner: "synthetic-canvas-lease-" + label, LeaseExpiresAt: expiry,
		})
		if err != nil {
			t.Fatal(err)
		}
		member, err := f.c.store.CreateMembership(store.Membership{
			PrincipalID: joined.PrincipalID, GroupID: f.groups[i].ID, Role: "member", Roles: []string{"member"},
			Grants: []string{"message.send", "message.receive"}, Status: store.MembershipStatusActive,
		})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.sourceMember = member
		}
		f.bindings[i], err = f.c.store.CreateSessionBinding(store.SessionBinding{
			ID: "synthetic-canvas-binding-" + label, EndpointID: joined.EndpointID, PrincipalID: joined.PrincipalID,
			GroupID: f.groups[i].ID, NativeSessionID: nativeID, NodeID: nodeID, Status: store.SessionBindingStatusActive,
			CredentialHash: store.NetworkInvitationDigest("synthetic-canvas-session-" + label),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.endpoints[i], err = f.c.store.GetEndpointWithIdentity(joined.EndpointID)
		if err != nil {
			t.Fatal(err)
		}
	}
	// The Join action references an already authorized Membership, but its
	// Endpoint has not yet joined the target Group.
	if _, err := f.c.store.CreateMembership(store.Membership{PrincipalID: f.endpoints[0].PrincipalID,
		GroupID: f.groups[1].ID, Role: "member", Roles: []string{"member"},
		Grants: []string{"message.send", "message.receive"}, Status: store.MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *clientTopologyMutationFixture) accept(t *testing.T, action ClientTopologyAction) *store.ClientRequest {
	return f.acceptOperation(t, action, "topology.apply")
}

func (f *clientTopologyMutationFixture) acceptOperation(t *testing.T, action ClientTopologyAction, operation string) *store.ClientRequest {
	t.Helper()
	f.sequence++
	body, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	binding := clientwire.Binding{HubID: f.hubID, OwnerID: f.registered.OwnerID, DeviceID: f.registered.DeviceID,
		SessionEpoch: f.registered.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: f.registered.KeyVersion}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: f.sequence, OperationID: store.NewID("synthetic_canvas"),
		Operation: operation, SenderKeyID: f.device.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion,
		ReceiverKeyID: f.c.ClientControlPublicIdentity().ID, ReceiverKeyVersion: binding.HubKeyVersion}
	packet, err := clientwire.SealRequest(f.device, f.c.ClientControlPublicIdentity(), binding, route, body)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := f.c.OpenClientControlPacket(f.device.Public(), binding, packet)
	if err != nil || !reflect.DeepEqual(opened.Plaintext, body) {
		t.Fatalf("synthetic ClientWire request was not authenticated: %v", err)
	}
	digest := sha256.Sum256(packet)
	accepted, err := f.c.AcceptClientControlRequest(store.AcceptClientRequestInput{
		OwnerID: binding.OwnerID, DeviceID: binding.DeviceID, SessionEpoch: opened.Route.SessionEpoch,
		Sequence: opened.Route.Sequence, OperationID: opened.Route.OperationID,
		RouteOperation: opened.Route.Operation, CiphertextDigest: hex.EncodeToString(digest[:]),
	})
	if err != nil || accepted == nil || accepted.Outcome != store.ClientRequestOutcomeNew ||
		accepted.Request == nil || accepted.Request.Status != store.ClientRequestProcessing {
		t.Fatalf("synthetic current Client request was not accepted as NEW: %v", err)
	}
	return accepted.Request
}

type clientTopologyMutationSnapshot struct {
	Groups      []store.Group
	Memberships []store.Membership
	Endpoints   []store.Endpoint
	Bindings    []store.SessionBinding
	Joins       [][]store.EndpointGroupMembership
	Links       []store.CommunicationLink
}

func (f *clientTopologyMutationFixture) snapshot(t *testing.T) clientTopologyMutationSnapshot {
	t.Helper()
	var snapshot clientTopologyMutationSnapshot
	for i, group := range f.groups {
		current, err := f.c.store.GetGroup(group.ID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Groups = append(snapshot.Groups, *current)
		members, err := f.c.store.ListMemberships(store.MembershipFilter{GroupID: group.ID, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Memberships = append(snapshot.Memberships, members...)
		endpoint, err := f.c.store.GetEndpointWithIdentity(f.endpoints[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Endpoints = append(snapshot.Endpoints, *endpoint)
		binding, err := f.c.store.GetActiveSessionBinding(endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Bindings = append(snapshot.Bindings, *binding)
		joins, err := f.c.store.ListEndpointGroupMemberships(endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Joins = append(snapshot.Joins, joins)
	}
	var err error
	snapshot.Links, err = f.c.store.ListCommunicationLinksForOwner(f.registered.OwnerID, 100)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *clientTopologyMutationFixture) action(kind ClientTopologyActionKind) ClientTopologyAction {
	switch kind {
	case ClientTopologySetParent:
		return ClientTopologyAction{Kind: kind, SetParent: &ClientTopologySetParentAction{
			GroupID: f.groups[0].ID, ParentGroupID: f.groups[1].ID, ExpectedGroupVersion: f.groups[0].Version}}
	case ClientTopologyJoinGroup:
		return ClientTopologyAction{Kind: kind, JoinGroup: &ClientTopologyJoinGroupAction{
			EndpointID: f.endpoints[0].ID, GroupID: f.groups[1].ID}}
	case ClientTopologyBindRole:
		return ClientTopologyAction{Kind: kind, BindRole: &ClientTopologyBindRoleAction{
			GroupID: f.groups[0].ID, MembershipID: f.sourceMember.ID, Role: "monitor",
			ExpectedMembershipVersion: f.sourceMember.Version}}
	case ClientTopologySetBroadcastPermission:
		enabled := true
		return ClientTopologyAction{Kind: kind, SetBroadcastPermission: &ClientTopologySetBroadcastPermissionAction{
			GroupID: f.groups[0].ID, MembershipID: f.sourceMember.ID, Enabled: &enabled,
			ExpectedMembershipVersion: f.sourceMember.Version}}
	case ClientTopologyProposeLink:
		return ClientTopologyAction{Kind: kind, ProposeLink: &ClientTopologyProposeLinkAction{
			Proposal: CommunicationLinkProposalInput{SourceEndpointID: f.endpoints[0].ID, SourceGroupID: f.groups[0].ID,
				TargetEndpointID: f.endpoints[1].ID, TargetGroupID: f.groups[1].ID, Direction: "forward",
				Actions: []string{"send"}, DataScopes: []string{"thread.message"},
				ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}}}
	default:
		panic("unsupported synthetic Canvas mutation")
	}
}

func TestClientTopologyAcceptedRequestRevocationFencesCanvasMutations(t *testing.T) {
	for _, kind := range []ClientTopologyActionKind{ClientTopologySetParent, ClientTopologyJoinGroup,
		ClientTopologyBindRole, ClientTopologySetBroadcastPermission, ClientTopologyProposeLink} {
		for _, revocation := range []string{"revoked_device", "advanced_epoch", "revoked_owner_key"} {
			t.Run(string(kind)+"/"+revocation, func(t *testing.T) {
				f := newClientTopologyMutationFixture(t)
				action := f.action(kind)
				accepted := f.accept(t, action)
				var err error
				switch revocation {
				case "revoked_device":
					_, err = f.c.store.RevokeClientDevice(f.registered.OwnerID, f.registered.DeviceID, f.registered.Version)
				case "advanced_epoch":
					_, err = f.c.store.AdvanceClientDeviceSessionEpoch(f.registered.OwnerID, f.registered.DeviceID, f.registered.SessionEpoch)
				case "revoked_owner_key":
					_, err = f.c.store.RevokeOwnerApprovalKeyLocal(f.registered.OwnerID, f.ownerKey.KeyID, f.ownerKey.Version)
				}
				if err != nil {
					t.Fatalf("synthetic current-authority change failed: %v", err)
				}
				before := f.snapshot(t)
				result, err := f.c.ApplyClientTopologyChangeForClientRequest(f.registered.OwnerID, accepted.ID, action)
				if err == nil || result != nil {
					t.Errorf("accepted request retained Canvas mutation authority after %s (error=%v)", revocation, err)
				}
				after := f.snapshot(t)
				if !reflect.DeepEqual(before, after) {
					t.Error("rejected Canvas mutation changed persisted topology, authorization, joins, bindings or versions")
				}
			})
		}
	}
}

func TestClientTopologyCurrentAcceptedRequestAppliesCanvasMutations(t *testing.T) {
	f := newClientTopologyMutationFixture(t)
	var err error
	f.sourceMember, err = f.c.store.UpdateMembershipAuthorization(f.sourceMember.ID, f.sourceMember.Roles,
		append(f.sourceMember.Grants, "task.claim"), map[string]any{"task.claim": true, "synthetic.other": true}, f.sourceMember.Version)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []ClientTopologyActionKind{ClientTopologySetParent, ClientTopologyJoinGroup,
		ClientTopologyBindRole, ClientTopologySetBroadcastPermission, ClientTopologyProposeLink} {
		t.Run(string(kind), func(t *testing.T) {
			action := f.action(kind)
			accepted := f.accept(t, action)
			before := f.snapshot(t)
			result, err := f.c.ApplyClientTopologyChangeForClientRequest(f.registered.OwnerID, accepted.ID, action)
			if err != nil || result == nil || !result.Changed {
				t.Fatalf("current accepted Canvas request rejected: %v", err)
			}
			after := f.snapshot(t)
			if reflect.DeepEqual(before, after) {
				t.Fatal("accepted Canvas operation did not persist its mutation")
			}
			switch kind {
			case ClientTopologySetParent:
				current, err := f.c.store.GetGroup(f.groups[0].ID)
				if err != nil || current.ParentGroupID != f.groups[1].ID || current.Version != f.groups[0].Version+1 {
					t.Fatalf("current parent placement/CAS failed: %v", err)
				}
				f.groups[0] = current
			case ClientTopologyJoinGroup:
				if result.EndpointGroup == nil || result.EndpointGroup.GroupID != f.groups[1].ID || result.EndpointGroup.Status != store.MembershipStatusActive ||
					!reflect.DeepEqual(before.Bindings, after.Bindings) || !reflect.DeepEqual(before.Endpoints, after.Endpoints) {
					t.Fatal("second join changed the native binding or stable Endpoint")
				}
			case ClientTopologyBindRole, ClientTopologySetBroadcastPermission:
				current, err := f.c.store.GetMembership(f.sourceMember.ID)
				if err != nil || current.Version != f.sourceMember.Version+1 || current.Revision != f.sourceMember.Revision+1 ||
					current.Role != "monitor" || current.Authorization["synthetic.other"] != true {
					t.Fatalf("role/broadcast CAS changed unrelated scope: %v", err)
				}
				if kind == ClientTopologyBindRole {
					if slices.Contains(current.Grants, "message.broadcast") || slices.Contains(current.Grants, "task.claim") || current.Authorization["task.claim"] != nil ||
						!slices.Contains(current.Grants, "federation.represent") || !slices.Contains(current.Grants, "message.send") {
						t.Fatal("monitor role changed unrelated grants or granted broadcast authority")
					}
				} else if !slices.Contains(current.Grants, "message.broadcast") || !reflect.DeepEqual(current.Roles, f.sourceMember.Roles) ||
					!reflect.DeepEqual(current.Authorization, f.sourceMember.Authorization) {
					t.Fatal("explicit broadcast permission changed roles or other authorization")
				}
				f.sourceMember = current
			case ClientTopologyProposeLink:
				if result.Link == nil || result.Link.State != store.CommunicationLinkProposed || len(after.Links) != len(before.Links)+1 ||
					after.Links[len(after.Links)-1].Version != 1 {
					t.Fatal("accepted link proposal acquired active routing authority")
				}
			}
		})
	}
}

func TestClientTopologyAcceptedRequestRequiresApplyPurpose(t *testing.T) {
	f := newClientTopologyMutationFixture(t)
	for _, kind := range []ClientTopologyActionKind{ClientTopologySetParent, ClientTopologyJoinGroup,
		ClientTopologyBindRole, ClientTopologySetBroadcastPermission, ClientTopologyProposeLink} {
		t.Run(string(kind), func(t *testing.T) {
			action := f.action(kind)
			wrongPurpose := f.acceptOperation(t, action, "topology.snapshot")
			before := f.snapshot(t)
			for _, requestID := range []string{"", "synthetic-forged-request", wrongPurpose.ID} {
				result, err := f.c.ApplyClientTopologyChangeForClientRequest(f.registered.OwnerID, requestID, action)
				if err == nil || result != nil {
					t.Error("missing, forged or read-purpose request authorized a Canvas write")
				}
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("request-purpose refusal changed persisted business state")
			}
		})
	}
}

func TestClientTopologyAcceptedRequestNetworkAndNodeFences(t *testing.T) {
	for _, scope := range []string{"revoked_network_membership", "revoked_node_binding"} {
		t.Run(scope, func(t *testing.T) {
			f := newClientTopologyMutationFixture(t)
			kinds := []ClientTopologyActionKind{ClientTopologyJoinGroup, ClientTopologyProposeLink}
			requests := make([]*store.ClientRequest, len(kinds))
			for i, kind := range kinds {
				requests[i] = f.accept(t, f.action(kind))
			}
			if scope == "revoked_network_membership" {
				member, err := f.c.store.GetNetworkMembership(f.groups[0].NetworkID, f.endpoints[0].PrincipalID)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.c.store.RevokeNetworkMembership(member.NetworkID, member.PrincipalID, member.Revision); err != nil {
					t.Fatal(err)
				}
			} else {
				bindings, err := f.c.store.ListNodeDeviceBindings(f.registered.OwnerID)
				if err != nil || len(bindings) != 1 {
					t.Fatalf("synthetic current Node binding absent: %v", err)
				}
				if _, err := f.c.store.RevokeNodeDeviceBinding(f.registered.OwnerID, bindings[0].ID, bindings[0].Version); err != nil {
					t.Fatal(err)
				}
			}
			for i, kind := range kinds {
				t.Run(string(kind), func(t *testing.T) {
					before := f.snapshot(t)
					result, err := f.c.ApplyClientTopologyChangeForClientRequest(f.registered.OwnerID, requests[i].ID, f.action(kind))
					if err == nil || result != nil {
						t.Fatal("accepted request bypassed current Network/Node scope")
					}
					if !reflect.DeepEqual(before, f.snapshot(t)) {
						t.Fatal("Network/Node refusal retained a tentative join or link proposal")
					}
				})
			}
		})
	}
}
