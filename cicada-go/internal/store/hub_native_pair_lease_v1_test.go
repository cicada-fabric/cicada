package store

import (
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairLeaseFixture(t *testing.T, both bool) (*nativePairStoreFixture, wire.NativePairBootstrapChallenge, *HubNativePairZeroJoin) {
	t.Helper()
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, seal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, seal); err != nil {
		t.Fatal(err)
	}
	// Synthetic Store setup for lease tests only. The separate HTTP tests cover
	// authenticated Node describe/Join, original routes and durable receipts.
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, err := readNativePair(tx, ch.Bootstrap.PairID)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := nativePairZeroJoinTx(tx, p, wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision,
		PairID: p.id, Slot: "A", ExpectedGeneration: 1, Runtime: "codex",
		NativeSessionID: "synthetic-heartbeat-original-session", Workspace: "/synthetic/heartbeat", EndpointName: "Synthetic heartbeat"},
		"synthetic-heartbeat-original-credential", f.at)
	if err != nil {
		t.Fatal(err)
	}
	if both {
		p, err = readNativePair(tx, ch.Bootstrap.PairID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = nativePairZeroJoinTx(tx, p, wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision,
			PairID: p.id, Slot: "B", ExpectedGeneration: 1, Runtime: "codex",
			NativeSessionID: "synthetic-heartbeat-original-other-session", Workspace: "/synthetic/heartbeat-other", EndpointName: "Synthetic heartbeat other"},
			"synthetic-heartbeat-original-other-credential", f.at); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return f, ch, joined
}

func TestHubNativePairHeartbeatPreservesIdentityBeyondJoinDeadline(t *testing.T) {
	f, ch, joined := nativePairLeaseFixture(t, true)
	basis := joined.Binding
	var accessID, initialCredential, initialLeaseOwner string
	var initialEpoch uint64
	if err := f.f.db.db.QueryRow(`SELECT id,credential_hash,epoch,lease_owner FROM network_access_sessions_v2 WHERE endpoint_id=?`,
		joined.Endpoint.ID).Scan(&accessID, &initialCredential, &initialEpoch, &initialLeaseOwner); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{4 * time.Minute, 8 * time.Minute, 12 * time.Minute} {
		at := f.at.Add(elapsed)
		updated, err := f.f.db.renewSessionBindingLease(basis.ID, basis.LeaseOwner, basis.Epoch,
			appNodeStamp(at.Add(5*time.Minute)), func() time.Time { return at })
		if err != nil {
			t.Fatal(err)
		}
		var credential, leaseOwner, expiry string
		var epoch uint64
		if err = f.f.db.db.QueryRow(`SELECT credential_hash,epoch,lease_owner,lease_expires_at FROM network_access_sessions_v2 WHERE id=?`,
			accessID).Scan(&credential, &epoch, &leaseOwner, &expiry); err != nil {
			t.Fatal(err)
		}
		if updated.ID != basis.ID || updated.Epoch != basis.Epoch || updated.NativeSessionID != basis.NativeSessionID ||
			updated.CredentialHash != basis.CredentialHash || updated.LeaseOwner != basis.LeaseOwner ||
			credential != initialCredential || epoch != initialEpoch || leaseOwner != initialLeaseOwner || expiry != updated.LeaseExpiresAt {
			t.Fatal("heartbeat rotated identity or left directory access behind")
		}
	}
	// Both slots were accepted in time. Their heartbeats survive JoinUntil without
	// executing another Join, changing a SID or rotating network access epoch.
	joinEnd, _ := time.Parse(time.RFC3339Nano, ch.Bootstrap.JoinUntil)
	if !f.at.Add(12 * time.Minute).After(joinEnd) {
		t.Fatal("test did not cross the signed Join deadline")
	}
	before := f.at.Add(13 * time.Minute)
	updated, err := f.f.db.renewSessionBindingLease(basis.ID, basis.LeaseOwner, basis.Epoch,
		appNodeStamp(before.Add(2*time.Hour)), func() time.Time { return before })
	if err != nil || updated.LeaseExpiresAt != ch.Bootstrap.PeerExpiresAt {
		t.Fatal("heartbeat did not cap both leases at Owner ceiling", err)
	}
	end, _ := time.Parse(time.RFC3339Nano, ch.Bootstrap.PeerExpiresAt)
	if _, err = f.f.db.renewSessionBindingLease(basis.ID, basis.LeaseOwner, basis.Epoch,
		appNodeStamp(end.Add(time.Minute)), func() time.Time { return end }); err == nil {
		t.Fatal("expired authority was resurrected")
	}
}

func TestHubNativePairHeartbeatRejectsLostAuthorityAtomically(t *testing.T) {
	cases := map[string]func(*nativePairStoreFixture, wire.NativePairBootstrapChallenge, *HubNativePairZeroJoin, time.Time) error{
		"expired_access": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, j *HubNativePairZeroJoin, at time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=? WHERE endpoint_id=?`, appNodeStamp(at), j.Endpoint.ID)
			return err
		},
		"expired_native": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, j *HubNativePairZeroJoin, at time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, appNodeStamp(at), j.Binding.ID)
			return err
		},
		"changed_access_epoch": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, j *HubNativePairZeroJoin, _ time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE network_access_sessions_v2 SET epoch=epoch+1 WHERE endpoint_id=?`, j.Endpoint.ID)
			return err
		},
		"changed_access_lease_owner": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, j *HubNativePairZeroJoin, _ time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE network_access_sessions_v2 SET lease_owner='synthetic-other-owner' WHERE endpoint_id=?`, j.Endpoint.ID)
			return err
		},
		"revoked_pair": func(f *nativePairStoreFixture, ch wire.NativePairBootstrapChallenge, _ *HubNativePairZeroJoin, _ time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE hub_native_pairs_v1 SET state='REVOKED',control_revision=control_revision+1 WHERE pair_id=?`, ch.Bootstrap.PairID)
			return err
		},
		"revoked_owner_key": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, _ *HubNativePairZeroJoin, _ time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED' WHERE owner_id=? AND key_id=?`, f.scope.Actor.OwnerID, f.scope.Actor.OwnerPublic.ID)
			return err
		},
		"revoked_node_binding": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, _ *HubNativePairZeroJoin, _ time.Time) error {
			_, err := f.f.db.db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED' WHERE node_id=?`, f.scope.Node.NodeID)
			return err
		},
		"native_write_rollback": func(f *nativePairStoreFixture, _ wire.NativePairBootstrapChallenge, _ *HubNativePairZeroJoin, _ time.Time) error {
			_, err := f.f.db.db.Exec(`CREATE TRIGGER synthetic_heartbeat_abort BEFORE UPDATE ON session_bindings WHEN NEW.version!=OLD.version BEGIN SELECT RAISE(ABORT,'synthetic heartbeat failure'); END`)
			return err
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			f, ch, joined := nativePairLeaseFixture(t, true)
			at := f.at.Add(4 * time.Minute)
			if err := alter(f, ch, joined, at); err != nil {
				t.Fatal(err)
			}
			var beforeAccess, beforeNative string
			if f.f.db.db.QueryRow(`SELECT lease_expires_at FROM network_access_sessions_v2 WHERE endpoint_id=?`, joined.Endpoint.ID).Scan(&beforeAccess) != nil ||
				f.f.db.db.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=?`, joined.Binding.ID).Scan(&beforeNative) != nil {
				t.Fatal("missing synthetic original lease")
			}
			if _, err := f.f.db.renewSessionBindingLease(joined.Binding.ID, joined.Binding.LeaseOwner, joined.Binding.Epoch,
				appNodeStamp(at.Add(5*time.Minute)), func() time.Time { return at }); err == nil {
				t.Fatal("invalid authority renewed")
			}
			var afterAccess, afterNative string
			if f.f.db.db.QueryRow(`SELECT lease_expires_at FROM network_access_sessions_v2 WHERE endpoint_id=?`, joined.Endpoint.ID).Scan(&afterAccess) != nil ||
				f.f.db.db.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=?`, joined.Binding.ID).Scan(&afterNative) != nil ||
				beforeAccess != afterAccess || beforeNative != afterNative {
				t.Fatal("failed heartbeat partially renewed a lease")
			}
		})
	}
}

func TestHubNativePairHeartbeatIncompleteJoinCannotCrossDeadline(t *testing.T) {
	f, ch, joined := nativePairLeaseFixture(t, false)
	b := joined.Binding
	for _, elapsed := range []time.Duration{4 * time.Minute, 8 * time.Minute} {
		at := f.at.Add(elapsed)
		if _, err := f.f.db.renewSessionBindingLease(b.ID, b.LeaseOwner, b.Epoch,
			appNodeStamp(at.Add(5*time.Minute)), func() time.Time { return at }); err != nil {
			t.Fatal(err)
		}
	}
	end, err := time.Parse(time.RFC3339Nano, ch.Bootstrap.JoinUntil)
	if err != nil {
		t.Fatal(err)
	}
	var beforeNative, beforeAccess string
	if f.f.db.db.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=?`, b.ID).Scan(&beforeNative) != nil ||
		f.f.db.db.QueryRow(`SELECT lease_expires_at FROM network_access_sessions_v2 WHERE endpoint_id=?`, b.EndpointID).Scan(&beforeAccess) != nil {
		t.Fatal("missing original lease")
	}
	for _, value := range []string{beforeNative, beforeAccess} {
		lease, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || !lease.After(end) {
			t.Fatal("ordinary lease expiry would mask the Join deadline guard")
		}
	}
	if _, err = f.f.db.renewSessionBindingLease(b.ID, b.LeaseOwner, b.Epoch,
		appNodeStamp(end.Add(5*time.Minute)), func() time.Time { return end }); err == nil {
		t.Fatal("incomplete pair renewed past its Join deadline")
	}
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	scope := NativeActorScope{PrincipalID: b.PrincipalID, EndpointID: b.EndpointID, GroupID: b.GroupID,
		NetworkID: ch.Bootstrap.NetworkID, BindingID: b.ID, BindingEpoch: b.Epoch, LeaseOwner: b.LeaseOwner}
	if err = tx.QueryRow(`SELECT id,revision FROM memberships WHERE principal_id=? AND group_id=?`,
		b.PrincipalID, b.GroupID).Scan(&scope.MembershipID, &scope.MembershipRevision); err != nil {
		t.Fatal(err)
	}
	if guardNativeSelfTx(tx, scope, end.Add(-time.Nanosecond)) != nil || guardNativeSelfTx(tx, scope, end) == nil {
		t.Fatal("self authority ignored the derived incomplete-Join deadline")
	}
	var afterNative, afterAccess string
	if tx.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=?`, b.ID).Scan(&afterNative) != nil ||
		tx.QueryRow(`SELECT lease_expires_at FROM network_access_sessions_v2 WHERE endpoint_id=?`, b.EndpointID).Scan(&afterAccess) != nil ||
		beforeNative != afterNative || beforeAccess != afterAccess {
		t.Fatal("rejected incomplete-Join heartbeat changed a lease")
	}
}
