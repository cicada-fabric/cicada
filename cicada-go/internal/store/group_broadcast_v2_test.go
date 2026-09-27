package store

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type sameGroupBroadcastV2Fixture struct {
	sealed       *sameGroupSealedV1Fixture
	sessionToken string
}

func sameGroupBroadcastV2CredentialDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func newSameGroupBroadcastV2Fixture(t *testing.T) *sameGroupBroadcastV2Fixture {
	t.Helper()
	sealed := newSameGroupSealedV1Fixture(t)
	for _, endpoint := range []sameGroupSealedV1EndpointFixture{
		sealed.source, sealed.target, sealed.sameNode,
	} {
		membership, err := sealed.store.GetMembershipByPrincipalGroup(endpoint.principal, sealed.groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := []string{"message.receive"}
		if endpoint.id == sealed.source.id {
			grants = append(grants, "message.send", "message.broadcast")
		}
		if _, err := sealed.store.UpdateMembershipAuthorization(membership.ID,
			membership.Roles, grants, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
	}
	for _, endpoint := range []sameGroupSealedV1EndpointFixture{
		sealed.source, sealed.target, sealed.sameNode,
	} {
		sealed.grant(t, endpoint.id)
	}

	sessionToken := "session_broadcast_source"
	if _, err := sealed.store.db.Exec(`UPDATE session_bindings SET credential_hash=? WHERE id=?`,
		sameGroupBroadcastV2CredentialDigest(sessionToken), sealed.source.binding.ID); err != nil {
		t.Fatal(err)
	}
	return &sameGroupBroadcastV2Fixture{sealed: sealed, sessionToken: sessionToken}
}

func (f *sameGroupBroadcastV2Fixture) input(broadcastID string) SameGroupBroadcastV2SnapshotInput {
	return SameGroupBroadcastV2SnapshotInput{
		NodeCredentialDigest:    f.sealed.sourceNode.nodeCredential,
		SessionCredentialDigest: sameGroupBroadcastV2CredentialDigest(f.sessionToken),
		GroupID:                 f.sealed.groupID, BroadcastID: broadcastID,
	}
}

func (f *sameGroupBroadcastV2Fixture) snapshot(t *testing.T,
	broadcastID string) *SameGroupBroadcastV2Snapshot {
	t.Helper()
	snapshot, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input(broadcastID))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func createSameGroupBroadcastV2Endpoint(t *testing.T, f *sameGroupSealedV1Fixture,
	endpointID, nodeID, groupID string, withKey bool) sameGroupSealedV1EndpointFixture {
	t.Helper()
	principalID := "pr_" + endpointID
	principal, err := f.store.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
		OwnerID: f.ownerID, TrustDomainID: f.ownerID, Name: endpointID,
		Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateMembership(Membership{PrincipalID: principal.ID,
		GroupID: groupID, Role: "member", Grants: []string{"message.receive"}}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.store.UpsertEndpointV2(Endpoint{ID: endpointID, Name: endpointID,
		Harness: "codex", NativeSessionID: "native_" + endpointID,
		MachineID: nodeID, Owner: f.ownerID, Status: "online",
		PrincipalID: principal.ID, GroupID: groupID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
		PrincipalID: principal.ID, GroupID: groupID,
		NativeSessionID: endpoint.NativeSessionID, NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = f.store.AcquireSessionBindingLease(binding.ID, "lease_"+endpointID,
		binding.Epoch, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	result := sameGroupSealedV1EndpointFixture{id: endpointID, nodeID: nodeID,
		principal: principal.ID, binding: binding}
	if !withKey {
		return result
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(endpointID, principal.ID,
		nodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RegisterEndpointKeyCandidate(endpointID, principal.ID,
		binding.ID, binding.Epoch, proof); err != nil {
		t.Fatal(err)
	}
	result.identity = identity
	return result
}

func TestSameGroupBroadcastV2CapturesExactImmutableSnapshot(t *testing.T) {
	f := newSameGroupBroadcastV2Fixture(t)
	otherGroup, err := f.sealed.store.CreateGroup(Group{ID: "grp_broadcast_other",
		OwnerPrincipalID: f.sealed.ownerID, TrustDomainID: f.sealed.ownerID,
		Name: "other", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.CreateMembership(Membership{PrincipalID: f.sealed.target.principal,
		GroupID: otherGroup.ID, Role: "member", Grants: []string{"message.receive"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.JoinEndpointGroup(f.sealed.target.id, otherGroup.ID); err != nil {
		t.Fatal(err)
	}
	child, err := f.sealed.store.CreateGroup(Group{ID: "grp_broadcast_child",
		OwnerPrincipalID: f.sealed.ownerID, TrustDomainID: f.sealed.ownerID,
		Name: "child", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	child, err = f.sealed.store.SetGroupParent(child.ID, f.sealed.groupID, child.Version)
	if err != nil {
		t.Fatal(err)
	}
	childEndpoint := createSameGroupBroadcastV2Endpoint(t, f.sealed,
		"ep_broadcast_child", "node_broadcast_child", child.ID, false)

	// Repeating a Group join is idempotent and does not create a duplicate recipient.
	if _, err := f.sealed.store.JoinEndpointGroup(f.sealed.target.id, f.sealed.groupID); err != nil {
		t.Fatal(err)
	}
	snapshot := f.snapshot(t, "bc_snapshot_exact")
	if snapshot.GroupRevision <= 0 || snapshot.Source.EndpointID != f.sealed.source.id ||
		snapshot.Source.NativeSessionID != f.sealed.source.binding.NativeSessionID {
		t.Fatalf("snapshot omitted its exact source identity/binding: %#v", snapshot.Source)
	}
	if len(snapshot.Recipients) != 2 || snapshot.Recipients[0].EndpointID != f.sealed.sameNode.id ||
		snapshot.Recipients[1].EndpointID != f.sealed.target.id {
		t.Fatalf("snapshot is not sorted, unique, or exact-Group scoped: %#v", snapshot.Recipients)
	}
	for _, recipient := range snapshot.Recipients {
		if recipient.EndpointID == f.sealed.source.id || recipient.EndpointID == childEndpoint.id ||
			recipient.NativeSessionID != "" || recipient.PublicKey.ID != recipient.KeyID ||
			recipient.BindingVersion <= 0 || recipient.KeyVersion <= 0 || recipient.KeyProofDigest == "" {
			t.Fatalf("recipient snapshot leaked or omitted pinned key/binding data: %#v", recipient)
		}
	}
	if snapshot.SnapshotDigest == "" || snapshot.Recipients[0].PublicKey.ID != f.sealed.sameNode.identity.Public().ID {
		t.Fatalf("snapshot did not preserve the pinned public key/digest: %#v", snapshot)
	}

	before := *snapshot
	before.Recipients = append([]SameGroupBroadcastV2Endpoint(nil), snapshot.Recipients...)
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input(snapshot.BroadcastID)); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot(t, snapshot.BroadcastID)
	if !reflect.DeepEqual(&before, after) {
		t.Fatalf("same-id retry changed the immutable snapshot:\nbefore=%#v\nafter=%#v", before, after)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE group_broadcast_v2_snapshots SET captured_at='changed' WHERE broadcast_id=?`,
		snapshot.BroadcastID); err == nil {
		t.Fatal("database allowed a durable snapshot update")
	}
	if _, err := f.sealed.store.db.Exec(`DELETE FROM group_broadcast_v2_snapshot_recipients WHERE broadcast_id=?`,
		snapshot.BroadcastID); err == nil {
		t.Fatal("database allowed durable recipient deletion")
	}
}

func TestSameGroupBroadcastV2RejectsForgedUnjoinedAndUnauthorizedSources(t *testing.T) {
	t.Run("forged Node", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		input := f.input("bc_forged_node")
		input.NodeCredentialDigest = sameGroupBroadcastV2CredentialDigest("not a Node credential")
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(input); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("forged Node credential was accepted: %v", err)
		}
	})
	t.Run("Node does not own source binding", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		input := f.input("bc_wrong_node")
		input.NodeCredentialDigest = f.sealed.targetNode.nodeCredential
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(input); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("different Node credential impersonated the source: %v", err)
		}
	})
	t.Run("unjoined Session", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		input := f.input("bc_unjoined_session")
		input.SessionCredentialDigest = sameGroupBroadcastV2CredentialDigest("not a joined Session")
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(input); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("unjoined Session was accepted: %v", err)
		}
	})
	t.Run("different Group", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		input := f.input("bc_wrong_group")
		input.GroupID = "grp_not_joined"
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(input); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("source broadcast across Groups was accepted: %v", err)
		}
	})
	t.Run("missing broadcast grant", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		membership, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, f.sealed.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.UpdateMembershipAuthorization(membership.ID,
			membership.Roles, []string{"message.receive"}, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_no_broadcast_grant")); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("source without message.broadcast was accepted: %v", err)
		}
	})
	t.Run("missing send grant", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		membership, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, f.sealed.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.UpdateMembershipAuthorization(membership.ID,
			membership.Roles, []string{"message.receive", "message.broadcast"},
			membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_no_send_grant")); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("source without message.send was accepted: %v", err)
		}
	})
	t.Run("revoked source binding", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		if _, err := f.sealed.store.RevokeSessionBinding(f.sealed.source.binding.ID,
			f.sealed.source.binding.Epoch, "test revoke"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_stale_source")); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("stale source binding was accepted: %v", err)
		}
	})
	t.Run("revoked Group", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		if _, err := f.sealed.store.db.Exec(`UPDATE groups SET state='ARCHIVED', revision=revision+1 WHERE id=?`,
			f.sealed.groupID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_archived_group")); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
			t.Fatalf("archived Group was accepted: %v", err)
		}
	})
}

func TestSameGroupBroadcastV2RejectsOperationIDReuseAcrossSources(t *testing.T) {
	f := newSameGroupBroadcastV2Fixture(t)
	const broadcastID = "bc_id_conflict"
	f.snapshot(t, broadcastID)

	membership, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.target.principal, f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.UpdateMembershipAuthorization(membership.ID,
		membership.Roles, []string{"message.receive", "message.send", "message.broadcast"},
		membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
	f.sealed.grant(t, f.sealed.target.id)
	targetSessionToken := "session_broadcast_target"
	if _, err := f.sealed.store.db.Exec(`UPDATE session_bindings SET credential_hash=? WHERE id=?`,
		sameGroupBroadcastV2CredentialDigest(targetSessionToken), f.sealed.target.binding.ID); err != nil {
		t.Fatal(err)
	}
	input := SameGroupBroadcastV2SnapshotInput{
		NodeCredentialDigest:    f.sealed.targetNode.nodeCredential,
		SessionCredentialDigest: sameGroupBroadcastV2CredentialDigest(targetSessionToken),
		GroupID:                 f.sealed.groupID, BroadcastID: broadcastID,
	}
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(input); !errors.Is(err, ErrSameGroupBroadcastV2Conflict) {
		t.Fatalf("another Endpoint reused an existing broadcast ID: %v", err)
	}
}

func TestSameGroupBroadcastV2SnapshotInsertRollsBackAtomically(t *testing.T) {
	f := newSameGroupBroadcastV2Fixture(t)
	if _, err := f.sealed.store.db.Exec(`CREATE TRIGGER broadcast_test_abort_second_recipient
BEFORE INSERT ON group_broadcast_v2_snapshot_recipients
WHEN NEW.ordinal=1 BEGIN SELECT RAISE(ABORT, 'simulated recipient insert interruption'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_insert_interrupted")); err == nil {
		t.Fatal("simulated recipient persistence interruption did not fail")
	}
	var parents, recipients int
	if err := f.sealed.store.db.QueryRow(`SELECT count(*) FROM group_broadcast_v2_snapshots WHERE broadcast_id=?`,
		"bc_insert_interrupted").Scan(&parents); err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.db.QueryRow(`SELECT count(*) FROM group_broadcast_v2_snapshot_recipients WHERE broadcast_id=?`,
		"bc_insert_interrupted").Scan(&recipients); err != nil {
		t.Fatal(err)
	}
	if parents != 0 || recipients != 0 {
		t.Fatalf("partial broadcast snapshot survived failed transaction: parent=%d recipients=%d", parents, recipients)
	}
}

func TestSameGroupBroadcastV2RecipientPermissionOwnerAndFanoutBound(t *testing.T) {
	t.Run("receive right filters exact member", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		membership, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.target.principal, f.sealed.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.UpdateMembershipAuthorization(membership.ID,
			membership.Roles, nil, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
		snapshot := f.snapshot(t, "bc_receive_right")
		if len(snapshot.Recipients) != 1 || snapshot.Recipients[0].EndpointID != f.sealed.sameNode.id {
			t.Fatalf("Endpoint without message.receive was included: %#v", snapshot.Recipients)
		}
	})
	t.Run("foreign owner fails closed", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		foreignOwner := "owner_broadcast_foreign"
		if _, err := f.sealed.store.CreatePrincipal(Principal{ID: foreignOwner,
			Kind: PrincipalKindHuman, OwnerID: foreignOwner, TrustDomainID: foreignOwner,
			Name: foreignOwner}); err != nil {
			t.Fatal(err)
		}
		foreign, err := f.sealed.store.CreatePrincipal(Principal{ID: "pr_broadcast_foreign",
			Kind: PrincipalKindAgent, OwnerID: foreignOwner, TrustDomainID: foreignOwner,
			Name: "foreign", Status: PrincipalStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CreateMembership(Membership{PrincipalID: foreign.ID,
			GroupID: f.sealed.groupID, Role: "member", Grants: []string{"message.receive"}}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := f.sealed.store.UpsertEndpointV2(Endpoint{ID: "ep_broadcast_foreign",
			Name: "foreign", Harness: "codex", NativeSessionID: "native_broadcast_foreign",
			MachineID: "node_broadcast_foreign", Owner: foreignOwner, Status: "online",
			PrincipalID: foreign.ID, GroupID: f.sealed.groupID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := f.sealed.store.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
			PrincipalID: foreign.ID, GroupID: f.sealed.groupID,
			NativeSessionID: endpoint.NativeSessionID, NodeID: "node_broadcast_foreign"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.AcquireSessionBindingLease(binding.ID,
			"lease_broadcast_foreign", binding.Epoch,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_foreign_owner")); !errors.Is(err, ErrSameGroupBroadcastV2NotReady) {
			t.Fatalf("unsupported cross-owner recipient was silently omitted or leaked: %v", err)
		}
	})
	t.Run("cap rejects before partial snapshot", func(t *testing.T) {
		f := newSameGroupBroadcastV2Fixture(t)
		for i := 0; i < SameGroupBroadcastV2MaxRecipients-1; i++ {
			createSameGroupBroadcastV2Endpoint(t, f.sealed,
				fmt.Sprintf("ep_broadcast_cap_%02d", i), "node_broadcast_cap", f.sealed.groupID, false)
		}
		if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_fanout_cap")); !errors.Is(err, ErrSameGroupBroadcastV2RecipientLimit) {
			t.Fatalf("oversized Group fanout was not rejected: %v", err)
		}
		var count int
		if err := f.sealed.store.db.QueryRow(`SELECT count(*) FROM group_broadcast_v2_snapshots WHERE broadcast_id=?`,
			"bc_fanout_cap").Scan(&count); err != nil || count != 0 {
			t.Fatalf("rejected fanout left a partial durable snapshot: count=%d err=%v", count, err)
		}
	})
}

func TestSameGroupBroadcastV2RetrySurvivesMembershipChangesAndRestart(t *testing.T) {
	f := newSameGroupBroadcastV2Fixture(t)
	original := f.snapshot(t, "bc_retry_stable")
	joined := createSameGroupBroadcastV2Endpoint(t, f.sealed,
		"ep_broadcast_later_join", f.sealed.target.nodeID, f.sealed.groupID, true)
	f.sealed.grant(t, joined.id)
	if _, err := f.sealed.store.RevokeMembershipForPrincipalGroup(f.sealed.target.principal,
		f.sealed.groupID, "recipient revoked after snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	f.sealed.store = reopened

	retried := f.snapshot(t, original.BroadcastID)
	if !reflect.DeepEqual(original, retried) {
		t.Fatalf("crash/retry or later membership change expanded the stored snapshot:\noriginal=%#v\nretried=%#v", original, retried)
	}
	fresh := f.snapshot(t, "bc_after_revocation")
	if len(fresh.Recipients) != 2 || fresh.Recipients[0].EndpointID != joined.id ||
		fresh.Recipients[1].EndpointID != f.sealed.sameNode.id {
		t.Fatalf("fresh snapshot did not use current receive-authorized membership: %#v", fresh.Recipients)
	}
}
