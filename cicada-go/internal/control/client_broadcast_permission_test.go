package control

import (
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func boolPointer(value bool) *bool { return &value }

func topologyBroadcastAction(groupID, membershipID string, enabled *bool, version int64) ClientTopologyAction {
	return ClientTopologyAction{Kind: ClientTopologySetBroadcastPermission,
		SetBroadcastPermission: &ClientTopologySetBroadcastPermissionAction{
			GroupID: groupID, MembershipID: membershipID, Enabled: enabled,
			ExpectedMembershipVersion: version}}
}

func topologyBroadcastFlag(t *testing.T, c *Control, ownerID, membershipID string) bool {
	t.Helper()
	snapshot, err := c.BuildClientTopologySnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range snapshot.Memberships {
		if member.MembershipID == membershipID {
			return member.BroadcastPermissionEnabled
		}
	}
	t.Fatal("membership missing from owner topology snapshot")
	return false
}

func TestClientBroadcastPermissionCASAndLostResponseReconciliation(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "broadcast permission synthetic group"})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, _ := createClientTopologyEndpoint(t, c, group.ID,
		"pr_broadcast_permission_synthetic", "ep_broadcast_permission_synthetic", "node_broadcast_permission_synthetic")
	membership, err := c.store.GetMembershipByPrincipalGroup(principal.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	membership, err = c.store.UpdateMembershipAuthorization(membership.ID,
		[]string{"monitor"}, append([]string(nil), membership.Grants...),
		map[string]any{"unrelated.policy": true}, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	if topologyBroadcastFlag(t, c, ownerID, membership.ID) {
		t.Fatal("ungranted broadcast flag was enabled")
	}
	originalVersion := membership.Version
	// The caller can lose this response and read the authoritative snapshot.
	if _, err := c.ApplyClientTopologyChange(ownerID,
		topologyBroadcastAction(group.ID, membership.ID, boolPointer(true), originalVersion)); err != nil {
		t.Fatal(err)
	}
	if !topologyBroadcastFlag(t, c, ownerID, membership.ID) {
		t.Fatal("lost enable response could not be reconciled")
	}
	enabled, err := c.store.GetMembership(membership.ID)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.Version != originalVersion+1 || enabled.Revision != membership.Revision+1 ||
		!containsGrant(enabled.Grants, "message.broadcast") || !containsGrant(enabled.Grants, "message.receive") ||
		!containsGrant(enabled.Roles, "monitor") || enabled.Authorization["unrelated.policy"] != true {
		t.Fatalf("enable changed unrelated role/grants or missed CAS revision: %+v", enabled)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID,
		topologyBroadcastAction(group.ID, membership.ID, boolPointer(false), originalVersion)); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatal("stale version changed permission", err)
	}
	// Simulate an older explicit authorization override; disable must clear
	// both representations because Guard accepts either one.
	authorization := map[string]any{"unrelated.policy": true, "message.broadcast": true}
	withOverride, err := c.store.UpdateMembershipAuthorization(enabled.ID, enabled.Roles,
		enabled.Grants, authorization, enabled.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID,
		topologyBroadcastAction(group.ID, membership.ID, boolPointer(false), withOverride.Version)); err != nil {
		t.Fatal(err)
	}
	if topologyBroadcastFlag(t, c, ownerID, membership.ID) {
		t.Fatal("lost disable response could not be reconciled")
	}
	disabled, err := c.store.GetMembership(membership.ID)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Version != withOverride.Version+1 || disabled.Revision != withOverride.Revision+1 ||
		containsGrant(disabled.Grants, "message.broadcast") || disabled.Authorization["message.broadcast"] != nil ||
		!containsGrant(disabled.Grants, "message.receive") || !containsGrant(disabled.Roles, "monitor") ||
		disabled.Authorization["unrelated.policy"] != true {
		t.Fatalf("disable retained broadcast authority or changed unrelated values: %+v", disabled)
	}
}

func TestClientBroadcastPermissionRejectsMissingForeignAndRevokedScope(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "synthetic owned group"})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := c.CreateGroup(GroupCreateInput{Name: "synthetic other group"})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, _ := createClientTopologyEndpoint(t, c, group.ID,
		"pr_broadcast_denial_synthetic", "ep_broadcast_denial_synthetic", "node_broadcast_denial_synthetic")
	membership, err := c.store.GetMembershipByPrincipalGroup(principal.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string]struct {
		owner  string
		action ClientTopologyAction
	}{
		"missing enabled": {ownerID, topologyBroadcastAction(group.ID, membership.ID, nil, membership.Version)},
		"stale version":   {ownerID, topologyBroadcastAction(group.ID, membership.ID, boolPointer(true), membership.Version-1)},
		"wrong group":     {ownerID, topologyBroadcastAction(otherGroup.ID, membership.ID, boolPointer(true), membership.Version)},
		"foreign caller":  {"foreign_owner_synthetic", topologyBroadcastAction(group.ID, membership.ID, boolPointer(true), membership.Version)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.ApplyClientTopologyChange(attempt.owner, attempt.action); err == nil {
				t.Fatal("unauthorized broadcast grant accepted")
			}
		})
	}
	foreign, err := c.store.CreatePrincipal(store.Principal{ID: "pr_foreign_broadcast_synthetic",
		Kind: store.PrincipalKindAgent, OwnerID: "foreign_owner_synthetic",
		TrustDomainID: "foreign_owner_synthetic", Name: "foreign", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	foreignMember, err := c.store.CreateMembership(store.Membership{PrincipalID: foreign.ID,
		GroupID: group.ID, Role: "member", Status: store.MembershipStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID,
		topologyBroadcastAction(group.ID, foreignMember.ID, boolPointer(true), foreignMember.Version)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("foreign-owned member granted broadcast", err)
	}
	if _, err := c.store.RevokeMembershipForPrincipalGroup(principal.ID, group.ID, "synthetic revocation"); err != nil {
		t.Fatal(err)
	}
	revoked, err := c.store.GetMembership(membership.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID,
		topologyBroadcastAction(group.ID, revoked.ID, boolPointer(true), revoked.Version)); err == nil {
		t.Fatal("revoked member granted broadcast")
	}
	if topologyBroadcastFlag(t, c, ownerID, membership.ID) {
		t.Fatal("denied attempts changed snapshot authority")
	}
}

func TestClientBroadcastPermissionRejectsInactiveOwnedGroup(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "synthetic paused broadcast group"})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, _ := createClientTopologyEndpoint(t, c, group.ID,
		"pr_broadcast_paused_synthetic", "ep_broadcast_paused_synthetic", "node_broadcast_paused_synthetic")
	membership, err := c.store.GetMembershipByPrincipalGroup(principal.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	group.State = store.GroupStatePaused
	group.Revision++
	if _, err := c.store.UpsertGroup(*group); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyClientTopologyChange(ownerID,
		topologyBroadcastAction(group.ID, membership.ID, boolPointer(true), membership.Version)); err == nil {
		t.Fatal("inactive owned Group granted broadcast permission")
	}
	current, err := c.store.GetMembership(membership.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != membership.Version || current.Revision != membership.Revision ||
		containsGrant(current.Grants, "message.broadcast") || topologyBroadcastFlag(t, c, ownerID, membership.ID) {
		t.Fatal("denied inactive Group action mutated Membership")
	}
}
