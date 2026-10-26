package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestEndpointGroupsNetworkBusinessCeilingCoversBilateralActions(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	m := f.join.Member
	actions := []string{"directory.discover", "direct.send", "direct.receive", "task.offer.publish", "task.offer.list", "broadcast.publish", "network.admin.invite"}
	raw, err := json.Marshal(actions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.db.db.Exec(`UPDATE network_memberships_v2 SET grants_json=? WHERE network_id=? AND principal_id=?`, string(raw), f.domain.Policy.NetworkID, m.PrincipalID); err != nil {
		t.Fatal(err)
	}
	check := func(managed bool) {
		t.Helper()
		tx, err := f.f.db.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, action := range actions {
			err = networkDirectMembershipAllowsTx(tx, f.domain.Policy.NetworkID, m.EndpointID, m.PrincipalID, action, f.at)
			if managed && !errors.Is(err, ErrNetworkPermission) || !managed && err != nil {
				t.Fatalf("bilateral current Endpoint action %s managed=%v: %v", action, managed, err)
			}
		}
	}
	nm, err := f.f.db.GetNetworkMembership(f.domain.Policy.NetworkID, m.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	scope := NetworkAccessScope{NetworkID: nm.NetworkID, PrincipalID: m.PrincipalID, EndpointID: m.EndpointID, AccessSessionID: m.NetworkAccessBindingID, AccessEpoch: m.NetworkAccessEpoch, LeaseOwner: m.LeaseOwner, MembershipID: nm.ID, MembershipRevision: nm.Revision, EndpointMembershipRevision: int64(m.EndpointNetworkRevision)}
	check(false)
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if err := f.f.db.IssueNetworkInvitationScoped(scope, "synthetic-target-owner", "synthetic-network-before-registration-invitation", expires, []string{"directory.discover"}); err != nil {
		t.Fatal("independently enrolled Endpoint invitation positive", err)
	}
	f.describe(t, f.at)
	check(true)
	if err := f.f.db.IssueNetworkInvitationScoped(scope, "synthetic-target-owner", "synthetic-network-after-registration-invitation", expires, []string{"directory.discover"}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("invitation transaction borrowed wider Principal grants", err)
	}
	// Neither expired registration liveness nor a retained broad Principal row
	// makes the original Endpoint a legacy Network business actor again.
	if _, err = f.f.db.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, f.at.Add(-time.Hour).Format(time.RFC3339Nano), m.BindingID); err != nil {
		t.Fatal(err)
	}
	check(true)
}

// The Principal deliberately has wider actual stored rights before the Node
// completes the exact original key. Current per-Endpoint authority must still
// cap both Fabric-facing and transactional guards at the five reviewed rights.
func TestEndpointGroupsActualSourceCapsWidePrincipalAtBothGuards(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	f.describe(t, f.at)
	group := f.create(t, f.at.Add(time.Second))
	rights := append(e2ee.EndpointGroupRights(), "*", "task.create", "message.broadcast", "group.manage")
	member, err := f.f.db.CreateMembership(Membership{PrincipalID: f.join.Member.PrincipalID, GroupID: group, Role: "member", Grants: rights, Status: MembershipStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	before := *member
	review := f.add(t, group, f.at.Add(3*time.Second))
	ch, _, _ := f.prepare(t, review, f.at.Add(5*time.Second))
	in, seal := f.completeInput(t, review, *ch.Challenge, f.at.Add(6*time.Second))
	var key wire.EndpointGroupsNodeKeyResult
	f.result(t, in, seal, &key)
	anchor := key.Registration
	member, err = f.f.db.GetMembership(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if member.Revision != before.Revision || !reflect.DeepEqual(member.Grants, before.Grants) {
		t.Fatal("activation changed the shared Principal's existing grants")
	}
	scope := NativeActorScope{PrincipalID: anchor.Registration.PrincipalID, EndpointID: anchor.Registration.EndpointID, GroupID: group, NetworkID: anchor.NetworkID, MembershipID: member.ID, MembershipRevision: member.Revision, BindingID: anchor.BindingID, BindingEpoch: anchor.BindingEpoch, LeaseOwner: anchor.LeaseOwner}
	at := f.at.Add(7 * time.Second)
	for _, action := range append([]string{""}, e2ee.EndpointGroupRights()...) {
		managed, err := f.f.db.AuthorizeEndpointGroupSource(scope, action, at)
		if !managed || err != nil {
			t.Fatalf("actual source positive %s: managed=%v err=%v", action, managed, err)
		}
		tx, err := f.f.db.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		err = guardNativeActorTx(tx, scope, action, at)
		tx.Rollback()
		if err != nil {
			t.Fatalf("transactional positive %s: %v", action, err)
		}
	}
	for _, action := range []string{"*", "task.create", "task.claim", "task.submit", "artifact.read", "space.read", "link.send", "message.broadcast", "group.manage", "membership.manage", "network.directory.read", "lease.acquire"} {
		managed, err := f.f.db.AuthorizeEndpointGroupSource(scope, action, at)
		if !managed || !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("wide Principal escaped source cap %s: %v", action, err)
		}
		tx, err := f.f.db.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		err = guardNativeActorTx(tx, scope, action, at)
		tx.Rollback()
		if !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("transactional source cap %s: %v", action, err)
		}
	}
	if err := f.f.db.LeaveEndpointAllGroups(scope.EndpointID, scope.BindingID, scope.BindingEpoch, "synthetic legacy global Leave"); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("legacy global Leave escaped source cap", err)
	}
	if _, err := f.f.db.LeaveEndpointGroup(scope.EndpointID, scope.GroupID, scope.BindingID, scope.BindingEpoch, "synthetic legacy Group Leave"); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("legacy Group Leave escaped exact Owner review", err)
	}
	// A new Owner removal changes no key or identity and is effective immediately
	// against cached actor coordinates and every named action.
	rq, rp, rr := endpointGroupsOwnerTestPrepareBusiness(t, f.f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, NodeID: anchor.Registration.NodeID, NetworkID: anchor.NetworkID, GroupID: group, EndpointID: anchor.Registration.EndpointID}, at.Add(time.Second))
	endpointGroupsOwnerTestApplyBusiness(t, f.f, rq, rp, rr, at.Add(2*time.Second), &key.OwnerControl)
	if managed, err := f.f.db.AuthorizeEndpointGroupSource(scope, "message.send", at.Add(3*time.Second)); !managed || !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("cached actor survived exact Owner removal", err)
	}
}

// Advance the production Store's injected clock; this is not a 24-hour wall
// Runtime gate. The old unbounded default chain stays cryptographically valid
// while the completed finite Owner head prevents every default fallback.
func TestEndpointGroupsActualFiniteExpiryPersistsAcrossRenewRestartAndOldProof(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	initial := f.describe(t, f.at)
	if len(initial.Authorities) != 1 || initial.Authorities[0].Relation.Source != "DEFAULT_POLICY" {
		t.Fatal("fixture lacks actual active default source")
	}
	group := f.domain.Policy.GroupID
	pq, pi, review := endpointGroupsOwnerTestPrepareBusiness(t, f.f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, NodeID: f.domain.Policy.Node.NodeID, NetworkID: f.domain.Policy.NetworkID, GroupID: group, EndpointID: f.join.Member.EndpointID, Duration: "1d"}, f.at.Add(time.Second))
	endpointGroupsOwnerTestApplyBusiness(t, f.f, pq, pi, review, f.at.Add(2*time.Second), nil)
	pending := f.describe(t, f.at.Add(3*time.Second))
	if len(pending.Authorities) != 1 || pending.Authorities[0].Relation.Source != "DEFAULT_POLICY" {
		t.Fatal("pending manual displaced untouched default")
	}
	ready, _, _ := f.prepare(t, review, f.at.Add(4*time.Second))
	complete, seal := f.completeInput(t, review, *ready.Challenge, f.at.Add(5*time.Second))
	var key wire.EndpointGroupsNodeKeyResult
	receipt := f.result(t, complete, seal, &key)
	end, err := time.Parse(time.RFC3339Nano, review.Policy.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	renew := wire.EndpointGroupsNodeRenew{EndpointID: key.Registration.Registration.EndpointID, RegistrationDigest: key.Registration.RegistrationDigest, ExpectedBindingID: key.Registration.BindingID, ExpectedBindingEpoch: key.Registration.BindingEpoch}
	ri, rs := f.input(t, wire.OperationEndpointGroupsNodeRenew, renew, end.Add(-time.Second))
	var renewed wire.EndpointGroupsNodeRenewResult
	f.result(t, ri, rs, &renewed)
	before := f.describe(t, end.Add(-time.Nanosecond))
	if len(before.Authorities) != 1 || before.Authorities[0].Relation.Source != "OWNER_EXPLICIT" {
		t.Fatal("finite authority failed before exact expiry")
	}
	endpoint, err := f.f.db.GetEndpointV2(key.Registration.Registration.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := f.f.db.FilterEndpointGroupDirectory(group, []Endpoint{*endpoint}, end.Add(-time.Nanosecond))
	if err != nil || len(listed) != 1 {
		t.Fatal("current target lost directory visibility", err)
	}
	atBoundary := f.describe(t, end)
	if len(atBoundary.Authorities) != 0 {
		t.Fatal("source survived its exact expiry")
	}
	listed, err = f.f.db.FilterEndpointGroupDirectory(group, []Endpoint{*endpoint}, end)
	if err != nil || len(listed) != 0 {
		t.Fatal("expired target retained directory visibility", err)
	}
	for _, card := range atBoundary.Relations {
		if card.GroupID == group && (card.OwnerControl.Mode != "OWNER" || card.OwnerControl.DenyReason != "EXPIRED" || card.DecisionRevision != key.OwnerControl.Revision+1) {
			t.Fatal("expiry did not persist exact Owner deny")
		}
	}
	var path string
	if err = f.f.db.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	f.f.db = restarted
	if retry, err := restarted.ProcessHubEndpointGroupsNode(complete, seal); err != nil || !reflect.DeepEqual(receipt, retry) {
		t.Fatal("expiry altered immutable historical completion", err)
	}
	ri, rs = f.input(t, wire.OperationEndpointGroupsNodeRenew, renew, end.Add(7*time.Minute))
	f.result(t, ri, rs, &renewed)
	after := f.describe(t, end.Add(7*time.Minute+time.Second))
	if len(after.Authorities) != 0 || after.Registration.State != "REGISTERED" {
		t.Fatal("renew/restart revived default or lost original registration")
	}
	// A new request with the old exact signed key proof must not re-complete.
	oldBody := complete.Body.(wire.EndpointGroupsNodeKeyComplete)
	late, lateSeal := f.input(t, wire.OperationEndpointGroupsNodeKeyComplete, oldBody, end.Add(7*time.Minute+2*time.Second))
	packet, err := restarted.ProcessHubEndpointGroupsNode(late, lateSeal)
	if err != nil {
		t.Fatal(err)
	}
	if code := f.open(t, late, packet, nil); code != "TARGET_NOT_AUTHORIZED" {
		t.Fatal("old proof revived expired source", code)
	}
	tx, err := restarted.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	p, err := readLocalDomain(tx, f.domain.Policy.PolicyID)
	tx.Rollback()
	if err != nil || p.state != wire.LocalDomainActive {
		t.Fatal("test accidentally revoked original default", err)
	}
}
