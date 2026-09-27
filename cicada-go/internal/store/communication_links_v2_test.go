package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCommunicationLinkProposalRejectsForeignOwnerAndNeverBecomesActive(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "links.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	makeEndpoint := func(ownerID, groupID, endpointID, nodeID string) {
		t.Helper()
		owner, err := s.GetPrincipal(ownerID)
		if errors.Is(err, ErrPrincipalNotFound) {
			owner, err = s.CreatePrincipal(Principal{ID: ownerID, Kind: PrincipalKindHuman,
				OwnerID: ownerID, TrustDomainID: ownerID, Name: ownerID})
		}
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.CreateGroup(Group{ID: groupID, Name: groupID,
			OwnerPrincipalID: owner.ID, TrustDomainID: ownerID, State: GroupStateActive})
		if err != nil {
			t.Fatal(err)
		}
		principal, err := s.CreatePrincipal(Principal{ID: "pr_" + endpointID,
			Kind: PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: ownerID, Name: endpointID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
			Role: "member", Grants: []string{"directory.read", "message.ask"}}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.UpsertEndpoint(Endpoint{ID: endpointID, Name: endpointID,
			Harness: "codex", NativeSessionID: "native_" + endpointID,
			MachineID: nodeID, Status: "online"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
			PrincipalID: principal.ID, GroupID: groupID,
			NativeSessionID: endpoint.NativeSessionID, NodeID: nodeID}); err != nil {
			t.Fatal(err)
		}
	}
	makeEndpoint("owner_a", "group_a", "ep_a", "node_a")
	makeEndpoint("owner_a", "group_b", "ep_b", "node_b")
	makeEndpoint("owner_b", "group_external", "ep_external", "node_external")
	proposal := CommunicationLinkProposal{SourceEndpointID: "ep_a", SourceGroupID: "group_a",
		TargetEndpointID: "ep_b", TargetGroupID: "group_b", ActorOwnerID: "owner_a",
		Direction: "forward", Actions: []string{"ask", "reply"},
		DataScopes: []string{"benchmark.public_result"}, TransportHubID: "hub_shared",
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}
	if _, err := s.ProposeCommunicationLink(CommunicationLinkProposal{
		SourceEndpointID: proposal.SourceEndpointID, SourceGroupID: proposal.SourceGroupID,
		TargetEndpointID: proposal.TargetEndpointID, TargetGroupID: proposal.TargetGroupID,
		ActorOwnerID: "owner_b", Direction: proposal.Direction, Actions: proposal.Actions,
		DataScopes: proposal.DataScopes, TransportHubID: proposal.TransportHubID,
		ExpiresAt: proposal.ExpiresAt}); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("target owner impersonated source proposer: %v", err)
	}
	crossOwner := proposal
	crossOwner.TargetEndpointID = "ep_external"
	crossOwner.TargetGroupID = "group_external"
	if _, err := s.ProposeCommunicationLink(crossOwner); !errors.Is(err, ErrCommunicationLinkScope) {
		t.Fatalf("uninvited foreign Endpoint proposal = %v", err)
	}
	missingHub := proposal
	missingHub.TransportHubID = ""
	if _, err := s.ProposeCommunicationLink(missingHub); err == nil {
		t.Fatal("cross-node proposal did not require selected Hub")
	}
	// A fractional-second future effective_at must not compare as earlier
	// than a whole-second RFC3339 timestamp.
	checkAt := time.Now().UTC().Truncate(time.Second)
	future := checkAt.Add(500 * time.Millisecond).Format(time.RFC3339Nano)
	if _, err := s.db.Exec(`UPDATE memberships SET effective_at = ? WHERE principal_id = ? AND group_id = ?`,
		future, "pr_ep_b", "group_b"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, scopeErr := readLinkEndpointScope(tx, "ep_b", "group_b", checkAt)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(scopeErr, ErrCommunicationLinkScope) {
		t.Fatalf("fractional-second future membership became proposal scope: %v", scopeErr)
	}
	if _, err := s.db.Exec(`UPDATE memberships SET effective_at = ? WHERE principal_id = ? AND group_id = ?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "pr_ep_b", "group_b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE memberships SET expires_at = ? WHERE principal_id = ? AND group_id = ?`,
		future, "pr_ep_b", "group_b"); err != nil {
		t.Fatal(err)
	}
	tx, err = s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, scopeErr = readLinkEndpointScope(tx, "ep_b", "group_b", checkAt)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if scopeErr != nil {
		t.Fatalf("fractional-second unexpired membership was rejected: %v", scopeErr)
	}
	if _, err := s.db.Exec(`UPDATE memberships SET expires_at = '' WHERE principal_id = ? AND group_id = ?`,
		"pr_ep_b", "group_b"); err != nil {
		t.Fatal(err)
	}
	link, err := s.ProposeCommunicationLink(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if link.State != CommunicationLinkProposed || link.SourceOwnerID != "owner_a" ||
		link.TargetOwnerID != "owner_a" || link.ContractDigest == "" || link.Version != 1 ||
		link.ScopeSnapshot.SourceMembershipRevision < 1 || link.ScopeSnapshot.TargetJoinRevision < 1 ||
		link.ScopeSnapshot.SourceGroupVersion < 1 {
		t.Fatalf("incorrect persisted proposal: %#v", link)
	}
	second, err := s.ProposeCommunicationLink(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == link.ID || second.ContractDigest == link.ContractDigest {
		t.Fatalf("distinct proposals must have distinct contract identities: first=%s second=%s", link.ID, second.ID)
	}
	if _, err := s.GetCommunicationLinkForOwner(link.ID, "stranger"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("third party could inspect link: %v", err)
	}
	if _, err := s.GetCommunicationLinkForOwner(link.ID, "owner_b"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("unrelated owner could inspect proposal: %v", err)
	}
	if links, err := s.ListCommunicationLinksForOwner("stranger", 100); err != nil || len(links) != 0 {
		t.Fatalf("third party enumerated links: %#v err=%v", links, err)
	}
	if _, err := s.RevokeCommunicationLink(link.ID, "stranger", 1, "bad"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("third party revoked link: %v", err)
	}
	revoked, err := s.RevokeCommunicationLink(link.ID, "owner_a", 1, "changed scope")
	if err != nil || revoked.State != CommunicationLinkRevoked || revoked.Version != 2 ||
		revoked.RevokedByOwnerID != "owner_a" {
		t.Fatalf("owner revocation failed: %#v err=%v", revoked, err)
	}
	if _, err := s.RevokeCommunicationLink(link.ID, "owner_a", 1, "stale"); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale owner update = %v", err)
	}
}

func TestCommunicationLinkMigrationRollsBackWithoutTouchingLegacyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("stop after link proposal DDL")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.collaboration.link_proposals" && phase == "after_apply" {
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
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'communication_links_v2'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("interrupted link migration left partial table")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(13)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("resumed migration ledger = %#v err=%v", entry, err)
	}
}
