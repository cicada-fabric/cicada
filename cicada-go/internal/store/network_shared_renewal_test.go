package store

import (
	"errors"
	"testing"
	"time"
)

func TestNetworkIndependentRenewalDoesNotAcquireNewGrants(t *testing.T) {
	f := newDirectoryOnlyNetworkFixture(t)
	s := f.publisher.scope
	var before string
	if err := f.s.db.QueryRow(`SELECT grants_json FROM network_memberships_v2 WHERE id=?`, s.MembershipID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	renewed, err := f.s.RenewNetworkAccess(RenewNetworkAccessInput{NetworkID: s.NetworkID, EndpointID: s.EndpointID, OwnerID: "owner_a", NodeID: "node_directory_only", Harness: "codex", NativeSessionID: "native_directory_only", NodeCredentialHash: f.credential, CredentialHash: "synthetic-renewed-access", LeaseOwner: "synthetic-renewed-lease", LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)})
	if err != nil || renewed.AccessSessionID != s.AccessSessionID || renewed.AccessSessionEpoch != s.AccessEpoch+1 {
		t.Fatal("independent renewal refused", err)
	}
	var after string
	if err := f.s.db.QueryRow(`SELECT grants_json FROM network_memberships_v2 WHERE id=?`, s.MembershipID).Scan(&after); err != nil || before != after {
		t.Fatal("renewal changed grants", err)
	}
}

func assertSharedNetworkRenewalRejected(t *testing.T, s *Store, access, binding string) {
	t.Helper()
	var network, endpoint, principal, node, native, credential, token, owner, lease string
	var epoch uint64
	if err := s.db.QueryRow(`SELECT network_id,endpoint_id,principal_id,node_id,native_session_id,credential_hash,epoch,lease_owner FROM network_access_sessions_v2 WHERE id=?`, access).Scan(&network, &endpoint, &principal, &node, &native, &token, &epoch, &lease); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT owner FROM fabric_endpoints WHERE id=?`, endpoint).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE node_id=?`, node).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	_, err := s.RenewNetworkAccess(RenewNetworkAccessInput{NetworkID: network, EndpointID: endpoint, OwnerID: owner, NodeID: node, Harness: "codex", NativeSessionID: native, NodeCredentialHash: credential, CredentialHash: "synthetic-forbidden-rotation", LeaseOwner: "synthetic-forbidden-lease", LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)})
	if !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("shared access renewed", err)
	}
	var afterToken, afterLease string
	var afterEpoch uint64
	if err := s.db.QueryRow(`SELECT credential_hash,epoch,lease_owner FROM network_access_sessions_v2 WHERE id=?`, access).Scan(&afterToken, &afterEpoch, &afterLease); err != nil || token != afterToken || epoch != afterEpoch || lease != afterLease {
		t.Fatal("rejected renewal changed shared identity", err)
	}
	// The Pair fixture signs its admission a few seconds ahead. This is an
	// explicit synthetic verification instant, not elapsed wall-clock expiry.
	at := time.Now().UTC().Add(time.Minute)
	if _, err := s.renewSessionBindingLease(binding, lease, 1, at.Add(time.Minute).Format(time.RFC3339Nano), func() time.Time { return at }); err != nil {
		t.Fatal("original heartbeat broke after selection/renewal refusal", err)
	}
	// Historical access ownership remains a fence even after its carrier's
	// credential or lease no longer matches a current Group binding.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := rejectLocalDomainNetworkRenewalTx(tx, access); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("historical shared access fence absent", err)
	}
}

func TestNetworkPairSharedRenewalCannotRotateOriginalHeartbeat(t *testing.T) {
	f, _, joined := nativePairLeaseFixture(t, true)
	var access string
	if err := f.f.db.db.QueryRow(`SELECT network_access_binding_id FROM hub_native_pair_slots_v1 WHERE binding_id=?`, joined.Binding.ID).Scan(&access); err != nil {
		t.Fatal(err)
	}
	assertSharedNetworkRenewalRejected(t, f.f.db, access, joined.Binding.ID)
}

func TestNetworkLocalDomainSharedRenewalCannotRotateOriginalHeartbeat(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	joined, _ := f.join(t, d, "synthetic-network-picker-domain")
	assertSharedNetworkRenewalRejected(t, f.f.f.db, joined.Member.NetworkAccessBindingID, joined.Member.BindingID)
}
