package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type communicationLinkGrantFixture struct {
	store            *Store
	path             string
	link             *CommunicationLink
	sourceKey        *e2ee.Identity
	targetKey        *e2ee.Identity
	sourceKeyID      string
	targetKeyID      string
	sourceBindingID  string
	sourceLeaseOwner string
}

func newCommunicationLinkGrantFixture(t *testing.T) *communicationLinkGrantFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "link-grants.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	owner, err := s.CreatePrincipal(Principal{ID: "owner_a", Kind: PrincipalKindHuman,
		OwnerID: "owner_a", TrustDomainID: "owner_a", Name: "owner_a"})
	if err != nil {
		t.Fatal(err)
	}
	createEndpoint := func(endpointID, groupID, nodeID string) string {
		t.Helper()
		if _, err := s.CreateGroup(Group{ID: groupID, Name: groupID,
			OwnerPrincipalID: owner.ID, TrustDomainID: "owner_a", State: GroupStateActive}); err != nil {
			t.Fatal(err)
		}
		principal, err := s.CreatePrincipal(Principal{ID: "pr_" + endpointID,
			Kind: PrincipalKindAgent, OwnerID: "owner_a", TrustDomainID: "owner_a", Name: endpointID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
			Role: "member", Grants: []string{"message.ask"}}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.UpsertEndpoint(Endpoint{ID: endpointID, Name: endpointID,
			Harness: "codex", NativeSessionID: "native_" + endpointID,
			MachineID: nodeID, Status: "online"})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := s.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
			PrincipalID: principal.ID, GroupID: groupID,
			NativeSessionID: endpoint.NativeSessionID, NodeID: nodeID})
		if err != nil {
			t.Fatal(err)
		}
		leaseOwner := "lease_" + endpointID
		if _, err := s.AcquireSessionBindingLease(binding.ID, leaseOwner, binding.Epoch,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		return binding.ID
	}
	sourceBindingID := createEndpoint("ep_source", "group_source", "node_source")
	createEndpoint("ep_target", "group_target", "node_target")

	sourceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sourceRecord, err := s.RegisterOwnerApprovalKeyLocal("owner_a", sourceKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	targetRecord, err := s.RegisterOwnerApprovalKeyLocal("owner_a", targetKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	link, err := s.ProposeCommunicationLink(CommunicationLinkProposal{
		SourceEndpointID: "ep_source", SourceGroupID: "group_source",
		TargetEndpointID: "ep_target", TargetGroupID: "group_target",
		ActorOwnerID: "owner_a", Direction: "bidirectional",
		Actions: []string{"ask", "reply"}, DataScopes: []string{"benchmark.public_result"},
		TransportHubID: hubID, ExpiresAt: expiresAt.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &communicationLinkGrantFixture{
		store: s, path: path, link: link, sourceKey: sourceKey, targetKey: targetKey,
		sourceKeyID: sourceRecord.KeyID, targetKeyID: targetRecord.KeyID,
		sourceBindingID: sourceBindingID, sourceLeaseOwner: "lease_ep_source",
	}
}

func signCommunicationLinkGrant(t *testing.T, identity *e2ee.Identity, link *CommunicationLink,
	side e2ee.OwnerLinkGrantSide, issuedAt, expiresAt time.Time,
) []byte {
	t.Helper()
	proof, err := identity.SignOwnerLinkGrant("owner_a", link.ID, link.ContractDigest,
		uint64(link.Version), side, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestCommunicationLinkOwnerGrantsAreSeparateDurableAndIdempotent(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	now := time.Now().UTC()
	grantExpiry := now.Add(time.Hour)
	issuedAt := now.Add(-time.Minute)
	sourceProof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
		e2ee.OwnerLinkGrantSideSource, issuedAt, grantExpiry)
	targetProof := signCommunicationLinkGrant(t, f.targetKey, f.link,
		e2ee.OwnerLinkGrantSideTarget, issuedAt, grantExpiry)

	initial, err := f.store.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(initial) != 2 || initial[0].CurrentStatus != CommunicationLinkGrantMissing ||
		initial[1].CurrentStatus != CommunicationLinkGrantMissing {
		t.Fatalf("initial grant statuses = %#v err=%v", initial, err)
	}

	first, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof)
	if err != nil || !first.Accepted || first.Side != CommunicationLinkGrantSource ||
		first.CurrentStatus != CommunicationLinkGrantAccepted {
		t.Fatalf("record source grant = %#v err=%v", first, err)
	}
	retried, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof)
	if err != nil || retried.AcceptedAt != first.AcceptedAt || retried.CurrentStatus != first.CurrentStatus {
		t.Fatalf("exact retry was not idempotent: first=%#v retry=%#v err=%v", first, retried, err)
	}
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantTarget, f.targetKeyID, targetProof); err != nil {
		t.Fatalf("record target grant: %v", err)
	}

	otherSourceProof := signCommunicationLinkGrant(t, f.targetKey, f.link,
		e2ee.OwnerLinkGrantSideSource, issuedAt, grantExpiry)
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.targetKeyID, otherSourceProof); !errors.Is(err, ErrCommunicationLinkGrantConflict) {
		t.Fatalf("different source grant replaced accepted proof: %v", err)
	}
	link, err := f.store.GetCommunicationLinkForOwner(f.link.ID, "owner_a")
	if err != nil || link.State != CommunicationLinkProposed || link.Version != 1 {
		t.Fatalf("owner grants changed link state: link=%#v err=%v", link, err)
	}
	statuses, err := f.store.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 {
		t.Fatalf("read bilateral grants = %#v err=%v", statuses, err)
	}
	for i, side := range []string{CommunicationLinkGrantSource, CommunicationLinkGrantTarget} {
		if statuses[i].Side != side || !statuses[i].Accepted ||
			statuses[i].CurrentStatus != CommunicationLinkGrantAccepted {
			t.Fatalf("grant side %s was merged or not current: %#v", side, statuses[i])
		}
	}
	if _, err := f.store.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "stranger"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("third party read owner grant statuses: %v", err)
	}

	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	statuses, err = restarted.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || !statuses[0].Accepted || !statuses[1].Accepted {
		t.Fatalf("grant states did not survive restart: %#v err=%v", statuses, err)
	}
	if _, err := restarted.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof); err != nil {
		t.Fatalf("retry after restart was not idempotent: %v", err)
	}
}

func TestCommunicationLinkOwnerGrantRejectsInvalidProofAndStaleAuthority(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, f *communicationLinkGrantFixture) error
		want error
	}{
		{
			name: "unregistered signing key",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				untrusted, err := e2ee.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				proof := signCommunicationLinkGrant(t, untrusted, f.link,
					e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				_, err = f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, untrusted.Public().ID, proof)
				return err
			},
			want: ErrOwnerApprovalKeyNotFound,
		},
		{
			name: "wrong side",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideTarget, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				_, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
		},
		{
			name: "expired proof",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				now := time.Now().UTC()
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideSource, now.Add(-2*time.Minute), now.Add(-time.Minute))
				_, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
		},
		{
			name: "grant expires after link",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				linkExpiry, err := time.Parse(time.RFC3339, f.link.ExpiresAt)
				if err != nil {
					t.Fatal(err)
				}
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), linkExpiry.Add(time.Minute))
				_, err = f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
		},
		{
			name: "revoked owner key",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				if _, err := f.store.RevokeOwnerApprovalKeyLocal("owner_a", f.sourceKeyID, 1); err != nil {
					t.Fatal(err)
				}
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				_, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
			want: ErrOwnerApprovalKeyConflict,
		},
		{
			name: "stale membership revision",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				if _, err := f.store.db.Exec(`UPDATE memberships SET revision = revision + 1
WHERE principal_id = ? AND group_id = ?`, "pr_ep_source", "group_source"); err != nil {
					t.Fatal(err)
				}
				_, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
			want: ErrCommunicationLinkScope,
		},
		{
			name: "expired link",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				if _, err := f.store.db.Exec(`UPDATE communication_links_v2 SET expires_at = ? WHERE id = ?`,
					time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), f.link.ID); err != nil {
					t.Fatal(err)
				}
				_, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
			want: ErrCommunicationLinkScope,
		},
		{
			name: "revoked link",
			run: func(t *testing.T, f *communicationLinkGrantFixture) error {
				if _, err := f.store.RevokeCommunicationLink(f.link.ID, "owner_a", f.link.Version, "test"); err != nil {
					t.Fatal(err)
				}
				proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
					e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				_, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
					CommunicationLinkGrantSource, f.sourceKeyID, proof)
				return err
			},
			want: ErrCommunicationLinkNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newCommunicationLinkGrantFixture(t)
			err := test.run(t, f)
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("got error %v; want errors.Is(_, %v)", err, test.want)
			}
			if test.want == nil && err == nil {
				t.Fatal("invalid owner grant was accepted")
			}
		})
	}
}

func TestCommunicationLinkOwnerGrantStatusRechecksKeyAndLink(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	now := time.Now().UTC()
	proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
		e2ee.OwnerLinkGrantSideSource, now.Add(-time.Minute), now.Add(time.Hour))
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeOwnerApprovalKeyLocal("owner_a", f.sourceKeyID, 1); err != nil {
		t.Fatal(err)
	}
	statuses, err := f.store.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || !statuses[0].Accepted ||
		statuses[0].CurrentStatus != CommunicationLinkGrantKeyRevoked || statuses[1].Accepted {
		t.Fatalf("status read did not recheck key state: %#v err=%v", statuses, err)
	}
	if _, err := f.store.RevokeCommunicationLink(f.link.ID, "owner_a", f.link.Version, "test revoke"); err != nil {
		t.Fatal(err)
	}
	statuses, err = f.store.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || statuses[0].CurrentStatus != CommunicationLinkGrantLinkRevoked {
		t.Fatalf("status read did not recheck link state: %#v err=%v", statuses, err)
	}
}

func TestCommunicationLinkOwnerGrantStatusFencesBindingEpochChange(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	now := time.Now().UTC()
	proof := signCommunicationLinkGrant(t, f.sourceKey, f.link,
		e2ee.OwnerLinkGrantSideSource, now.Add(-time.Minute), now.Add(time.Hour))
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(f.link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, proof); err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetSessionBinding(f.sourceBindingID)
	if err != nil {
		t.Fatal(err)
	}
	released, err := f.store.ReleaseSessionBindingLease(binding.ID, f.sourceLeaseOwner, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcquireSessionBindingLease(released.ID, "lease_ep_source_new", released.Epoch,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	statuses, err := f.store.GetCommunicationLinkOwnerGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || !statuses[0].Accepted ||
		statuses[0].CurrentStatus != CommunicationLinkGrantScopeStale {
		t.Fatalf("grant remained current after binding epoch changed: %#v err=%v", statuses, err)
	}
}

func TestCommunicationLinkGrantAcceptsEndpointJoinedToSecondGroup(t *testing.T) {
	f := newCommunicationLinkGrantFixture(t)
	joinSecondGroup := func(endpointID, principalID, groupID string) {
		t.Helper()
		if _, err := f.store.CreateGroup(Group{ID: groupID, Name: groupID,
			OwnerPrincipalID: "owner_a", TrustDomainID: "owner_a", State: GroupStateActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.CreateMembership(Membership{PrincipalID: principalID,
			GroupID: groupID, Role: "member", Grants: []string{"message.ask"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JoinEndpointGroup(endpointID, groupID); err != nil {
			t.Fatal(err)
		}
	}
	joinSecondGroup("ep_source", "pr_ep_source", "group_source_second")
	joinSecondGroup("ep_target", "pr_ep_target", "group_target_second")
	link, err := f.store.ProposeCommunicationLink(CommunicationLinkProposal{
		SourceEndpointID: "ep_source", SourceGroupID: "group_source_second",
		TargetEndpointID: "ep_target", TargetGroupID: "group_target_second",
		ActorOwnerID: "owner_a", Direction: "bidirectional",
		Actions: []string{"ask", "reply"}, DataScopes: []string{"benchmark.public_result"},
		TransportHubID: "hub_shared", ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.link = link
	now := time.Now().UTC()
	sourceProof := signCommunicationLinkGrant(t, f.sourceKey, link,
		e2ee.OwnerLinkGrantSideSource, now.Add(-time.Minute), now.Add(30*time.Minute))
	targetProof := signCommunicationLinkGrant(t, f.targetKey, link,
		e2ee.OwnerLinkGrantSideTarget, now.Add(-time.Minute), now.Add(30*time.Minute))
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(link.ID,
		CommunicationLinkGrantSource, f.sourceKeyID, sourceProof); err != nil {
		t.Fatalf("source grant for second Group join: %v", err)
	}
	if _, err := f.store.RecordCommunicationLinkOwnerGrant(link.ID,
		CommunicationLinkGrantTarget, f.targetKeyID, targetProof); err != nil {
		t.Fatalf("target grant for second Group join: %v", err)
	}
	statuses, err := f.store.GetCommunicationLinkOwnerGrantStatuses(link.ID, "owner_a")
	if err != nil || len(statuses) != 2 || statuses[0].CurrentStatus != CommunicationLinkGrantAccepted ||
		statuses[1].CurrentStatus != CommunicationLinkGrantAccepted {
		t.Fatalf("second Group grants = %#v err=%v", statuses, err)
	}
}

func TestCommunicationLinkGrantMigrationRollsBackAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("interrupt communication link grant migration")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.collaboration.link_owner_grants" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("migration interruption = %v", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var tableCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master
WHERE type = 'table' AND name = 'communication_link_grants_v2'`).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 0 {
		t.Fatal("interrupted migration left a partial grant table")
	}
	var state string
	var attempts int
	if err := check.QueryRow(`SELECT state, attempts FROM schema_migrations_v2 WHERE version = 16`).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != v2MigrationFailed || attempts != 1 {
		t.Fatalf("interrupted migration ledger = %q attempts=%d", state, attempts)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(16)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("grant migration did not resume: %#v err=%v", entry, err)
	}
	if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master
WHERE type = 'table' AND name = 'communication_link_grants_v2'`).Scan(&tableCount); err != nil || tableCount != 1 {
		t.Fatalf("grant table missing after retry: count=%d err=%v", tableCount, err)
	}
}
