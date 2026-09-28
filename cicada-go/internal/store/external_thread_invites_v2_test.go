package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type externalThreadInviteTestEndpoint struct {
	ownerID    string
	groupID    string
	endpointID string
	bindingID  string
}

type externalThreadInviteTestFixture struct {
	store  *Store
	hubID  string
	source externalThreadInviteTestEndpoint
	target externalThreadInviteTestEndpoint
}

func newExternalThreadInviteTestFixture(t *testing.T) *externalThreadInviteTestFixture {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "external-thread-invites.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	makeEndpoint := func(ownerID, groupID, endpointID, nodeID string) externalThreadInviteTestEndpoint {
		t.Helper()
		owner, err := s.CreatePrincipal(Principal{ID: ownerID, Kind: PrincipalKindHuman,
			OwnerID: ownerID, TrustDomainID: ownerID, Name: ownerID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateGroup(Group{ID: groupID, Name: "Group " + ownerID,
			OwnerPrincipalID: owner.ID, TrustDomainID: ownerID, State: GroupStateActive}); err != nil {
			t.Fatal(err)
		}
		principal, err := s.CreatePrincipal(Principal{ID: "pr_" + endpointID,
			Kind: PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: ownerID, Name: endpointID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
			Role: "member", Grants: []string{"message.ask"}}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.UpsertEndpoint(Endpoint{ID: endpointID, Name: "Thread " + endpointID,
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
		if _, err := s.AcquireSessionBindingLease(binding.ID, "lease_"+endpointID, binding.Epoch,
			time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		return externalThreadInviteTestEndpoint{ownerID: ownerID, groupID: groupID,
			endpointID: endpointID, bindingID: binding.ID}
	}

	source := makeEndpoint("owner_source", "group_source", "ep_source", "node_source")
	target := makeEndpoint("owner_target", "group_target", "ep_target", "node_target")
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	return &externalThreadInviteTestFixture{store: s, hubID: hubID, source: source, target: target}
}

func (f *externalThreadInviteTestFixture) createInvite(t *testing.T) *ExternalThreadInviteCreated {
	t.Helper()
	invite, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: f.source.ownerID, SourceEndpointID: f.source.endpointID,
		SourceGroupID: f.source.groupID, HubID: f.hubID,
		Actions: []string{"reply", "ask"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	return invite
}

func TestExternalThreadInviteAcceptsOnceCreatesNonRoutableProposedLink(t *testing.T) {
	f := newExternalThreadInviteTestFixture(t)
	invite := f.createInvite(t)
	if invite.InviteID == "" || len(invite.Token) != 43 || invite.HubID != f.hubID {
		t.Fatalf("invalid one-time invite response: %#v", invite)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(invite.Token)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("invite token is not 256-bit base64url: len=%d err=%v", len(decoded), err)
	}
	digest := sha256.Sum256([]byte(invite.Token))
	var storedDigest string
	if err := f.store.db.QueryRow(`SELECT token_digest FROM external_thread_invites_v2 WHERE invite_id = ?`, invite.InviteID).Scan(&storedDigest); err != nil {
		t.Fatal(err)
	}
	if storedDigest != hex.EncodeToString(digest[:]) || storedDigest == invite.Token {
		t.Fatalf("database did not store only the token digest: %q", storedDigest)
	}
	var tokenColumns int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM pragma_table_info('external_thread_invites_v2') WHERE name = 'token'`).Scan(&tokenColumns); err != nil {
		t.Fatal(err)
	}
	if tokenColumns != 0 {
		t.Fatal("invite table contains a raw token column")
	}

	preview, err := f.store.PreviewExternalThreadInvite(invite.Token)
	if err != nil {
		t.Fatal(err)
	}
	if preview.SourceEndpointLabel != "Thread ep_source" || preview.SourceGroupLabel != "Group owner_source" ||
		preview.HubID != f.hubID || preview.Direction != "forward" || len(preview.Actions) != 2 ||
		preview.Actions[0] != "ask" || preview.Actions[1] != "reply" ||
		len(preview.DataScopes) != 1 || preview.DataScopes[0] != "thread.message" {
		t.Fatalf("preview did not preserve the invite's minimal card and terms: %#v", preview)
	}

	// Multiple pending invites are allowed; the partial unique Link index only
	// applies after one is consumed.
	secondInvite, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: f.source.ownerID, SourceEndpointID: f.source.endpointID,
		SourceGroupID: f.source.groupID, HubID: f.hubID,
		DataScopes: []string{"thread.message"},
		ExpiresAt:  time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultPreview, err := f.store.PreviewExternalThreadInvite(secondInvite.Token)
	if err != nil || len(defaultPreview.Actions) != 2 || defaultPreview.Actions[0] != "ask" || defaultPreview.Actions[1] != "reply" {
		t.Fatalf("omitted invite actions did not default to ask+reply: %#v err=%v", defaultPreview, err)
	}
	accepted, err := f.store.AcceptExternalThreadInvite(invite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State != CommunicationLinkProposed || accepted.Version != 1 || accepted.LinkID == "" ||
		accepted.ExpiresAt != invite.ExpiresAt {
		t.Fatalf("acceptance did not create a non-active Link proposal: %#v", accepted)
	}
	link, err := f.store.GetCommunicationLinkForOwner(accepted.LinkID, f.target.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if link.State != CommunicationLinkProposed || link.SourceOwnerID != f.source.ownerID ||
		link.TargetOwnerID != f.target.ownerID || link.TransportHubID != f.hubID ||
		link.Direction != "forward" || len(link.Actions) != 2 || link.Actions[0] != "ask" ||
		link.Actions[1] != "reply" || len(link.DataScopes) != 1 || link.DataScopes[0] != "thread.message" {
		t.Fatalf("accepted Link differs from the invited contract or became active: %#v", link)
	}
	if _, err := f.store.GetCommunicationLinkForOwner(link.ID, "stranger"); !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatalf("unrelated owner read accepted Link: %v", err)
	}
	if sourceVisible, err := f.store.GetCommunicationLinkForOwner(link.ID, f.source.ownerID); err != nil || sourceVisible.ID != link.ID {
		t.Fatalf("source owner could not read accepted proposal: %#v err=%v", sourceVisible, err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(invite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("consumed invite was replayed: %v", err)
	}
	if _, err := f.store.PreviewExternalThreadInvite(invite.Token); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("consumed invite still previews: %v", err)
	}
	if _, err := f.store.PreviewExternalThreadInvite(secondInvite.Token); err != nil {
		t.Fatalf("independent pending invite was affected by first acceptance: %v", err)
	}
}

func TestExternalThreadInviteSameNodeProposalDoesNotSelectRelayHub(t *testing.T) {
	f := newExternalThreadInviteTestFixture(t)
	invite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE fabric_endpoints SET machine_id = ? WHERE id = ?`,
		"node_source", f.target.endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE session_bindings SET node_id = ? WHERE id = ?`,
		"node_source", f.target.bindingID); err != nil {
		t.Fatal(err)
	}
	accepted, err := f.store.AcceptExternalThreadInvite(invite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	link, err := f.store.GetCommunicationLinkForOwner(accepted.LinkID, f.target.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if link.SourceNodeID != link.TargetNodeID || link.TransportHubID != "" || link.State != CommunicationLinkProposed {
		t.Fatalf("same-Node invite selected a relay or activated its Link: %#v", link)
	}
}

func TestExternalThreadInviteRejectsGuessesOwnersExpiryRevocationAndHubMismatch(t *testing.T) {
	f := newExternalThreadInviteTestFixture(t)
	validHub := f.hubID
	if _, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: f.source.ownerID, SourceEndpointID: "guessed_endpoint", SourceGroupID: f.source.groupID,
		HubID: f.hubID, Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano),
	}); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("guessed source Endpoint was accepted: %v", err)
	}
	if _, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: "wrong_owner", SourceEndpointID: f.source.endpointID, SourceGroupID: f.source.groupID,
		HubID: f.hubID, Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano),
	}); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("wrong source owner created invite: %v", err)
	}
	if _, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: f.source.ownerID, SourceEndpointID: f.source.endpointID, SourceGroupID: f.source.groupID,
		HubID: "different_hub", Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano),
	}); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("mismatched Hub was accepted at creation: %v", err)
	}
	if _, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: f.source.ownerID, SourceEndpointID: f.source.endpointID, SourceGroupID: f.source.groupID,
		HubID: f.hubID, Actions: []string{"reply"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano),
	}); err == nil {
		t.Fatal("reply-only invite was accepted")
	}

	guessedTargetInvite := f.createInvite(t)
	if _, err := f.store.AcceptExternalThreadInvite(guessedTargetInvite.Token, f.target.ownerID,
		"guessed_endpoint", f.target.groupID); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("guessed target Endpoint was accepted: %v", err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(guessedTargetInvite.Token, "wrong_owner",
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("wrong authenticated target owner was accepted: %v", err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(guessedTargetInvite.Token, f.source.ownerID,
		f.source.endpointID, f.source.groupID); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("same owner accepted their own invite: %v", err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(guessedTargetInvite.Token, f.target.ownerID,
		f.target.endpointID, "guessed_group"); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("guessed target Group was accepted: %v", err)
	}
	if links, err := f.store.ListCommunicationLinksForOwner(f.source.ownerID, 100); err != nil || len(links) != 0 {
		t.Fatalf("failed guesses created a Link: %#v err=%v", links, err)
	}

	expiredInvite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE external_thread_invites_v2 SET expires_at = ? WHERE invite_id = ?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), expiredInvite.InviteID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PreviewExternalThreadInvite(expiredInvite.Token); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("expired invite preview = %v", err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(expiredInvite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("expired invite acceptance = %v", err)
	}

	revokedSourceInvite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE session_bindings SET status = ? WHERE id = ?`,
		SessionBindingStatusRevoked, f.source.bindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PreviewExternalThreadInvite(revokedSourceInvite.Token); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("revoked source binding still previews: %v", err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(revokedSourceInvite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("revoked source binding still accepts: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE session_bindings SET status = ? WHERE id = ?`,
		SessionBindingStatusLeased, f.source.bindingID); err != nil {
		t.Fatal(err)
	}

	revokedOwnerInvite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE principals SET status = ? WHERE id = ?`,
		PrincipalStatusRevoked, f.source.ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PreviewExternalThreadInvite(revokedOwnerInvite.Token); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("revoked source owner still previews invite: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE principals SET status = ? WHERE id = ?`,
		PrincipalStatusActive, f.source.ownerID); err != nil {
		t.Fatal(err)
	}

	revokedTargetInvite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE memberships SET status = 'revoked' WHERE principal_id = ? AND group_id = ?`,
		"pr_"+f.target.endpointID, f.target.groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(revokedTargetInvite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("revoked target membership accepted: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE memberships SET status = ? WHERE principal_id = ? AND group_id = ?`,
		MembershipStatusActive, "pr_"+f.target.endpointID, f.target.groupID); err != nil {
		t.Fatal(err)
	}

	revokedTargetOwnerInvite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE principals SET status = ? WHERE id = ?`,
		PrincipalStatusRevoked, f.target.ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(revokedTargetOwnerInvite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("revoked target owner accepted invite: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE principals SET status = ? WHERE id = ?`,
		PrincipalStatusActive, f.target.ownerID); err != nil {
		t.Fatal(err)
	}

	foreignGroupInvite := f.createInvite(t)
	if _, err := f.store.db.Exec(`UPDATE groups SET owner_principal_id = ?, trust_domain_id = ? WHERE id = ?`,
		f.source.ownerID, f.source.ownerID, f.target.groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(foreignGroupInvite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteScope) {
		t.Fatalf("target accepted Endpoint in a foreign-owned Group: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE groups SET owner_principal_id = ?, trust_domain_id = ? WHERE id = ?`,
		f.target.ownerID, f.target.ownerID, f.target.groupID); err != nil {
		t.Fatal(err)
	}

	rotatedHub := validHub + "_rotated"
	if _, err := f.store.db.Exec(`UPDATE client_device_hub_config_v2 SET hub_id = ? WHERE id = 1`, rotatedHub); err != nil {
		t.Fatal(err)
	}
	changedHubInvite := f.createInviteAfterHubChange(t, rotatedHub)
	if _, err := f.store.PreviewExternalThreadInvite(changedHubInvite.Token); err != nil {
		t.Fatalf("new invite for current Hub failed after rotation: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE client_device_hub_config_v2 SET hub_id = ? WHERE id = 1`, validHub); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PreviewExternalThreadInvite(changedHubInvite.Token); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("invite remained valid after Hub mismatch: %v", err)
	}
	if _, err := f.store.AcceptExternalThreadInvite(changedHubInvite.Token, f.target.ownerID,
		f.target.endpointID, f.target.groupID); !errors.Is(err, ErrExternalThreadInviteUnavailable) {
		t.Fatalf("invite was accepted after Hub mismatch: %v", err)
	}
}

func (f *externalThreadInviteTestFixture) createInviteAfterHubChange(t *testing.T, hubID string) *ExternalThreadInviteCreated {
	t.Helper()
	invite, err := f.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: f.source.ownerID, SourceEndpointID: f.source.endpointID,
		SourceGroupID: f.source.groupID, HubID: hubID,
		Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	return invite
}

func TestExternalThreadInviteMigrationRollsBackAndPreservesLegacyRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("stop after external Thread invite DDL")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.collaboration.external_thread_invites" && phase == "after_apply" {
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
	var inviteTableCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='external_thread_invites_v2'`).Scan(&inviteTableCount); err != nil {
		t.Fatal(err)
	}
	if inviteTableCount != 0 {
		t.Fatal("failed v26 migration left a partial invite table")
	}
	var state string
	var attempts int
	if err := check.QueryRow(`SELECT state, attempts FROM schema_migrations_v2 WHERE version = 26`).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != v2MigrationFailed || attempts != 1 {
		t.Fatalf("failed v26 migration was not recorded: state=%q attempts=%d", state, attempts)
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
	assertV2Ledger(t, reopened, map[int]string{
		1: v2MigrationApplied, 2: v2MigrationApplied, 3: v2MigrationApplied,
		4: v2MigrationApplied, 5: v2MigrationApplied, 6: v2MigrationApplied,
		7: v2MigrationApplied, 8: v2MigrationApplied, 9: v2MigrationApplied,
		10: v2MigrationApplied, 11: v2MigrationApplied, 12: v2MigrationApplied,
		13: v2MigrationApplied, 14: v2MigrationApplied, 15: v2MigrationApplied,
		16: v2MigrationApplied, 17: v2MigrationApplied, 18: v2MigrationApplied,
		19: v2MigrationApplied, 20: v2MigrationApplied, 21: v2MigrationApplied,
		22: v2MigrationApplied, 23: v2MigrationApplied, 24: v2MigrationApplied,
		25: v2MigrationApplied, 26: v2MigrationApplied, 27: v2MigrationApplied,
		28: v2MigrationApplied, 29: v2MigrationApplied, 30: v2MigrationApplied,
		31: v2MigrationApplied, 32: v2MigrationApplied, 33: v2MigrationApplied,
		34: v2MigrationApplied, 35: v2MigrationApplied, 36: v2MigrationApplied,
	})
	var legacyRows int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM fabric_messages WHERE id = 'fabric_message_legacy'`).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 1 {
		t.Fatalf("legacy Fabric message row was not preserved after v26 retry: %d", legacyRows)
	}
}
