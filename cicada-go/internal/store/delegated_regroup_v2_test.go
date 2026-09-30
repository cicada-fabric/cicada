package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestDelegatedRegroupExactOwnerConsentCASAndAudit(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	m, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"monitor"},
		m.Grants, m.Authorization, m.Version); err != nil {
		t.Fatal(err)
	}
	actor := f.actor(t, f.sealed.source)
	group, err := f.sealed.store.GetGroup(f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	input := RegroupProposalInput{OperationID: "synthetic_regroup_one", NetworkID: f.networkID,
		SourceGroupID: group.ID, TargetGroupID: group.ID, Action: RegroupCreateChild,
		NewGroupName: "synthetic empty child", ExpectedSourceVersion: group.Version,
		ExpectedTargetVersion: group.Version}
	proposal, err := f.sealed.store.ProposeRegroup(actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.HubID == "" || proposal.OwnerID != f.sealed.ownerID || proposal.State != "PROPOSED" {
		t.Fatalf("proposal scope: %+v", proposal)
	}
	repeated, err := f.sealed.store.ProposeRegroup(actor, input)
	if err != nil || repeated.ProposalID != proposal.ProposalID {
		t.Fatalf("proposal retry: %+v, %v", repeated, err)
	}
	modified := input
	modified.NewGroupName = "synthetic different child"
	if _, err := f.sealed.store.ProposeRegroup(actor, modified); !errors.Is(err, ErrRegroupConflict) {
		t.Fatalf("operation ID accepted different proposal: %v", err)
	}
	hidden := input
	hidden.OperationID = "synthetic_hidden_target"
	hidden.TargetGroupID = "grp_synthetic_hidden_target"
	if _, err := f.sealed.store.ProposeRegroup(actor, hidden); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("hidden target leaked existence/version: %v", err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.sealed.owner.SignOwnerDeviceGrant(f.sealed.ownerID, "synthetic_regroup_device",
		device.Public(), proposal.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: f.sealed.ownerID, OwnerKeyID: f.sealed.ownerKeyID,
		DeviceID: "synthetic_regroup_device", DevicePublic: device.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	accept := func(sequence uint64, route string) string {
		t.Helper()
		digest := sha256.Sum256([]byte(NewID("synthetic_ciphertext")))
		a, err := f.sealed.store.AcceptClientRequest(AcceptClientRequestInput{
			OwnerID: f.sealed.ownerID, DeviceID: registered.DeviceID,
			SessionEpoch: registered.SessionEpoch, Sequence: sequence,
			OperationID: NewID("synthetic_operation"), RouteOperation: route,
			CiphertextDigest: hex.EncodeToString(digest[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		return a.Request.ID
	}
	wrongPurpose := accept(1, "status.snapshot")
	if _, err := f.sealed.store.GetRegroupProposalForClientRequest(wrongPurpose,
		f.sealed.ownerID, proposal.ProposalID); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("status request authorized proposal review: %v", err)
	}
	if _, err := f.sealed.store.IssueRegroupDelegationForClientRequest(wrongPurpose,
		f.sealed.ownerID, proposal.ProposalID, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), 1); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("status request authorized delegation: %v", err)
	}
	issueRequest := accept(2, "topology.delegation_issue")
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := f.sealed.store.IssueRegroupDelegationForClientRequest(issueRequest,
		"owner_synthetic_other", proposal.ProposalID, expires, 1); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("forged Owner request authorized delegation: %v", err)
	}
	delegation, err := f.sealed.store.IssueRegroupDelegationForClientRequest(issueRequest,
		f.sealed.ownerID, proposal.ProposalID, expires, 1)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.sealed.store.IssueRegroupDelegationForClientRequest(issueRequest,
		f.sealed.ownerID, proposal.ProposalID, expires, 1)
	if err != nil || retry.DelegationID != delegation.DelegationID {
		t.Fatalf("lost issue response retry: %+v, %v", retry, err)
	}
	if _, err := f.sealed.store.RevokeRegroupDelegationForClientRequest(wrongPurpose,
		f.sealed.ownerID, delegation.DelegationID, delegation.Version); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("status request authorized delegation revoke: %v", err)
	}
	forged := actor
	forged.Scope.BindingEpoch++
	if _, err := f.sealed.store.ApplyDelegatedRegroup(forged, proposal.ProposalID,
		delegation.DelegationID); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("forged native binding epoch applied regroup: %v", err)
	}
	result, err := f.sealed.store.ApplyDelegatedRegroup(actor, proposal.ProposalID, delegation.DelegationID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Group.ParentGroupID != group.ID || result.Group.NetworkID != f.networkID || result.Group.OwnerPrincipalID != f.sealed.ownerID {
		t.Fatalf("wrong scoped child: %+v", result.Group)
	}
	var members, readers int
	if err := f.sealed.store.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE group_id=?`,
		result.Group.ID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.db.QueryRow(`SELECT COUNT(*) FROM group_space_audience_v2 WHERE group_id=?`,
		result.Group.ID).Scan(&readers); err != nil {
		t.Fatal(err)
	}
	if members != 1 || readers != 0 {
		t.Fatalf("delegated child inherited readers: memberships=%d audience=%d", members, readers)
	}
	prior, err := f.sealed.store.ApplyDelegatedRegroup(actor, proposal.ProposalID, delegation.DelegationID)
	if err != nil || prior.AuditID != result.AuditID || prior.Group.ID != result.Group.ID {
		t.Fatalf("lost apply response replayed topology: %+v, %v", prior, err)
	}
	var audits int
	if err := f.sealed.store.db.QueryRow(`SELECT COUNT(*) FROM regroup_audit_v2 WHERE proposal_id=?`,
		proposal.ProposalID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit count=%d err=%v", audits, err)
	}
	updated, err := f.sealed.store.GetGroup(group.ID)
	if err != nil || updated.Version <= group.Version {
		t.Fatalf("parent topology version was not advanced: %+v, %v", updated, err)
	}
	stale := input
	stale.OperationID = "synthetic_stale_topology"
	if _, err := f.sealed.store.ProposeRegroup(actor, stale); !errors.Is(err, ErrRegroupConflict) {
		t.Fatalf("stale topology version accepted: %v", err)
	}
	m, err = f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"worker"},
		m.Grants, m.Authorization, m.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.ApplyDelegatedRegroup(f.actor(t, f.sealed.source), proposal.ProposalID,
		delegation.DelegationID); !errors.Is(err, ErrRegroupDenied) {
		t.Fatalf("role-revoked Monitor read audit through apply retry: %v", err)
	}
}

func TestDelegatedSetParentKeepsReadersSeparateAndFencesOldKeyConsent(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	source, err := f.sealed.store.GetGroup(f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	target, err := f.sealed.store.UpsertGroup(Group{NetworkID: f.networkID,
		OwnerPrincipalID: source.OwnerPrincipalID, TrustDomainID: source.TrustDomainID,
		Name: "synthetic parent", ContextPolicy: "group_scoped", IsolationProfile: "trusted_host",
		ExternalMode: source.ExternalMode})
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"monitor"},
		m.Grants, m.Authorization, m.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.UpsertMembership(Membership{PrincipalID: f.sealed.source.principal,
		GroupID: target.ID, Role: "monitor", Roles: []string{"monitor"}, Status: MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.JoinEndpointGroup(f.sealed.source.id, target.ID); err != nil {
		t.Fatal(err)
	}
	actor := f.actor(t, f.sealed.source)
	proposal, err := f.sealed.store.ProposeRegroup(actor, RegroupProposalInput{
		OperationID: "synthetic_set_parent", NetworkID: f.networkID,
		SourceGroupID: source.ID, TargetGroupID: target.ID, Action: RegroupSetParent,
		ExpectedSourceVersion: source.Version, ExpectedTargetVersion: target.Version})
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.sealed.owner.SignOwnerDeviceGrant(f.sealed.ownerID, "synthetic_parent_device",
		device.Public(), proposal.HubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: f.sealed.ownerID, OwnerKeyID: f.sealed.ownerKeyID,
		DeviceID: "synthetic_parent_device", DevicePublic: device.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic_set_parent_owner_request"))
	accepted, err := f.sealed.store.AcceptClientRequest(AcceptClientRequestInput{
		OwnerID: f.sealed.ownerID, DeviceID: registered.DeviceID,
		SessionEpoch: registered.SessionEpoch, Sequence: 1,
		OperationID: "synthetic_parent_issue", RouteOperation: "topology.delegation_issue",
		CiphertextDigest: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := f.sealed.store.IssueRegroupDelegationForClientRequest(accepted.Request.ID,
		f.sealed.ownerID, proposal.ProposalID, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), 1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.sealed.store.ApplyDelegatedRegroup(actor, proposal.ProposalID, delegation.DelegationID)
	if err != nil || result.Group.ParentGroupID != target.ID || result.Group.ID != source.ID ||
		result.Group.Revision <= source.Revision {
		t.Fatalf("set parent did not atomically change scoped source: %+v, %v", result, err)
	}
	var audience int
	if err := f.sealed.store.db.QueryRow(`SELECT COUNT(*) FROM group_space_audience_v2 WHERE group_id=?`,
		target.ID).Scan(&audience); err != nil || audience != 0 {
		t.Fatalf("parent relationship leaked readers: audience=%d err=%v", audience, err)
	}
	if _, err := f.sealed.store.PrepareGroupSpaceWrite(f.actor(t, f.sealed.source),
		GroupSpacePrepareInput{GroupID: source.ID, OperationID: "synthetic_after_parent", Kind: GroupSpaceKindJournal}); !errors.Is(err, ErrGroupSpaceNotReady) {
		t.Fatalf("old Group key consent remained current after topology revision: %v", err)
	}
}
