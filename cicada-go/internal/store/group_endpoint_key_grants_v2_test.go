package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type groupEndpointKeyGrantFixture struct {
	store              *Store
	ownerID            string
	groupID            string
	endpointID         string
	bindingID          string
	leaseOwner         string
	nodeBindingID      string
	nodeBindingVersion int64
	ownerIdentity      *e2ee.Identity
	ownerKeyID         string
	candidate          *e2ee.Identity
	otherEndpointID    string
}

func newGroupEndpointKeyGrantFixture(t *testing.T) *groupEndpointKeyGrantFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "group-endpoint-key-grants.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ownerID, groupID := "owner_key_grant", "grp_shared_key_grant"
	ownerPrincipal, err := s.CreatePrincipal(Principal{ID: ownerID, Kind: PrincipalKindHuman,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(Group{ID: groupID, OwnerPrincipalID: ownerPrincipal.ID,
		TrustDomainID: ownerID, Name: groupID, State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	createEndpoint := func(endpointID, nodeID string) (*SessionBinding, *e2ee.Identity) {
		t.Helper()
		principalID := "pr_" + endpointID
		principal, err := s.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
			OwnerID: ownerID, TrustDomainID: ownerID, Name: endpointID, Status: PrincipalStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
			Role: "member"}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.UpsertEndpoint(Endpoint{ID: endpointID, Name: endpointID,
			Harness: "codex", NativeSessionID: "native_" + endpointID, MachineID: nodeID,
			Owner: ownerID, Status: "online"})
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
		leased, err := s.AcquireSessionBindingLease(binding.ID, leaseOwner, binding.Epoch,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := candidate.SignEndpointKeyAttestation(endpoint.ID, principal.ID,
			nodeID, leased.ID, leased.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RegisterEndpointKeyCandidate(endpoint.ID, principal.ID,
			leased.ID, leased.Epoch, attestation); err != nil {
			t.Fatal(err)
		}
		return leased, candidate
	}
	remoteBinding, remoteCandidate := createEndpoint("ep_remote_key_grant", "node_remote")
	_, _ = createEndpoint("ep_local_key_grant", "node_local")

	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	deviceIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, "device_group_key_grant",
		deviceIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: "device_group_key_grant",
		DevicePublic: deviceIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	})
	if err != nil {
		t.Fatal(err)
	}
	bindNode := func(nodeID string) *NodeDeviceBinding {
		t.Helper()
		credentialDigest := nodeBindingTestCredentialDigest("credential-" + nodeID)
		codeDigest := nodeBindingTestCodeDigest("code-" + nodeID)
		if _, err := s.CreatePendingNodeDeviceBinding(nodeID, nodeID, credentialDigest,
			codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		binding, err := s.ConfirmPendingNodeDeviceBinding(ownerID, device.DeviceID, codeDigest)
		if err != nil {
			t.Fatal(err)
		}
		return binding
	}
	remoteNodeBinding := bindNode("node_remote")
	_ = bindNode("node_local")
	return &groupEndpointKeyGrantFixture{
		store: s, ownerID: ownerID, groupID: groupID, endpointID: "ep_remote_key_grant",
		bindingID: remoteBinding.ID, leaseOwner: "lease_ep_remote_key_grant",
		nodeBindingID: remoteNodeBinding.ID, nodeBindingVersion: remoteNodeBinding.Version,
		ownerIdentity: ownerIdentity, ownerKeyID: ownerKey.KeyID, candidate: remoteCandidate,
		otherEndpointID: "ep_local_key_grant",
	}
}

func (f *groupEndpointKeyGrantFixture) preview(t *testing.T) *GroupEndpointKeyGrantManifest {
	t.Helper()
	issuedAt := time.Now().UTC().Add(-time.Second)
	expiresAt := time.Now().UTC().Add(time.Hour)
	manifest, err := f.store.PreviewGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func (f *groupEndpointKeyGrantFixture) sign(t *testing.T, signer *e2ee.Identity,
	manifest *GroupEndpointKeyGrantManifest) []byte {
	t.Helper()
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signer.SignOwnerLinkKeyGrant(manifest.OwnerID, GroupEndpointKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestGroupEndpointKeyGrantAcceptsCurrentOwnerSignatureIdempotently(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	manifest := f.preview(t)
	if manifest.Operation != GroupEndpointKeyGrantOperation || manifest.HubID == "" ||
		manifest.OwnerID != f.ownerID || manifest.GroupID != f.groupID ||
		manifest.EndpointID != f.endpointID || manifest.NodeID != "node_remote" ||
		manifest.BindingID != f.bindingID || manifest.BindingEpoch == 0 ||
		manifest.MembershipRevision <= 0 || manifest.EndpointJoinRevision <= 0 ||
		manifest.CandidateVersion <= 0 || manifest.CandidateKeyID != f.candidate.Public().ID ||
		manifest.CandidateFingerprint == "" || manifest.CandidateProofDigest == "" ||
		manifest.OwnerKeyID != f.ownerKeyID || manifest.ExpiresAt == "" {
		t.Fatalf("manifest does not cover the expected current public scope: %#v", manifest)
	}
	if manifest.CandidatePublicIdentity.ID != f.candidate.Public().ID ||
		manifest.CandidateBindingDigest == manifest.Digest {
		t.Fatalf("manifest omitted candidate public material or distinct binding digest: %#v", manifest)
	}
	attestationDigest := sha256.Sum256(manifest.CandidateAttestation)
	if len(manifest.CandidateAttestation) == 0 ||
		hex.EncodeToString(attestationDigest[:]) != manifest.CandidateProofDigest {
		t.Fatal("manifest does not expose the candidate proof bound by its digest")
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(manifest.CandidateAttestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID,
		manifest.BindingID, manifest.BindingEpoch)
	if err != nil || verified.ID != manifest.CandidatePublicIdentity.ID ||
		!bytes.Equal(verified.KEMPublic, manifest.CandidatePublicIdentity.KEMPublic) ||
		!bytes.Equal(verified.SigningPublic, manifest.CandidatePublicIdentity.SigningPublic) {
		t.Fatalf("manifest Endpoint attestation cannot be verified independently: identity=%#v err=%v", verified, err)
	}
	otherEndpoint, err := f.store.GetEndpointV2(f.otherEndpointID)
	if err != nil || otherEndpoint == nil || otherEndpoint.MachineID == manifest.NodeID {
		t.Fatalf("fixture did not include a second Endpoint on a different Node: endpoint=%#v err=%v", otherEndpoint, err)
	}
	proof := f.sign(t, f.ownerIdentity, manifest)
	first, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, proof)
	if err != nil || first.CurrentStatus != GroupEndpointKeyGrantCurrent ||
		first.Manifest.Digest != manifest.Digest {
		t.Fatalf("valid Group key grant was rejected: grant=%#v err=%v", first, err)
	}
	retry, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, proof)
	if err != nil || retry.ID != first.ID || retry.AcceptedAt != first.AcceptedAt {
		t.Fatalf("exact grant retry was not idempotent: first=%#v retry=%#v err=%v", first, retry, err)
	}
	current, err := f.store.VerifyCurrentGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
	if err != nil || current.CurrentStatus != GroupEndpointKeyGrantCurrent ||
		current.Manifest.Digest != manifest.Digest || current.Manifest.CandidatePublicIdentity.ID != f.candidate.Public().ID {
		t.Fatalf("current grant verification failed: grant=%#v err=%v", current, err)
	}

	// A proof made for an ordinary Link ID cannot cross this operation boundary.
	issuedAt, _ := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	linkProof, err := f.ownerIdentity.SignOwnerLinkKeyGrant(f.ownerID, "link_ordinary",
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, linkProof); err == nil {
		t.Fatal("ordinary Link key grant proof crossed into the Group-key operation")
	}
}

func TestGroupEndpointKeyGrantRejectsAnotherOwnersSignature(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	manifest := f.preview(t)
	otherOwnerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forged := f.sign(t, otherOwnerKey, manifest)
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, forged); err == nil {
		t.Fatal("signature from another owner's key was accepted")
	}
	if _, err := f.store.AcceptGroupEndpointKeyGrant("owner_other", f.groupID,
		f.endpointID, f.ownerKeyID, f.sign(t, f.ownerIdentity, manifest)); err == nil {
		t.Fatal("caller-selected other owner gained authority over the Endpoint")
	}
}

func TestGroupEndpointKeyGrantBecomesStaleAfterCandidateChange(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	manifest := f.preview(t)
	proof := f.sign(t, f.ownerIdentity, manifest)
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_key_candidates_v2 SET version = version + 1 WHERE endpoint_id = ?`, f.endpointID); err != nil {
		t.Fatal(err)
	}
	grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
	if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
		t.Fatalf("candidate version change did not stale grant: grant=%#v err=%v", grant, err)
	}
	if _, err := f.store.VerifyCurrentGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID); !errors.Is(err, ErrGroupEndpointKeyGrantStale) {
		t.Fatalf("stale candidate grant verified as current: %v", err)
	}
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, proof); err == nil {
		t.Fatal("old signature was accepted after the candidate version changed")
	}
}

func TestGroupEndpointKeyGrantBecomesStaleAfterBindingEpochChanges(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	manifest := f.preview(t)
	proof := f.sign(t, f.ownerIdentity, manifest)
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ReleaseSessionBindingLease(f.bindingID, f.leaseOwner, manifest.BindingEpoch); err != nil {
		t.Fatal(err)
	}
	grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
	if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
		t.Fatalf("binding epoch change did not stale grant: grant=%#v err=%v", grant, err)
	}
}

func TestGroupEndpointKeyGrantBecomesStaleAfterNodeOwnerBindingRevocation(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	manifest := f.preview(t)
	proof := f.sign(t, f.ownerIdentity, manifest)
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeNodeDeviceBinding(f.ownerID, f.nodeBindingID,
		f.nodeBindingVersion); err != nil {
		t.Fatal(err)
	}
	grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
	if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
		t.Fatalf("revoked Node owner binding did not stale grant: grant=%#v err=%v", grant, err)
	}
}

func TestGroupEndpointKeyGrantBindsMembershipAndEndpointJoinRevisions(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		query string
	}{
		{name: "membership", query: `UPDATE memberships SET revision = revision + 1 WHERE principal_id = 'pr_ep_remote_key_grant' AND group_id = 'grp_shared_key_grant'`},
		{name: "Endpoint join", query: `UPDATE endpoint_group_memberships SET revision = revision + 1 WHERE endpoint_id = 'ep_remote_key_grant' AND group_id = 'grp_shared_key_grant'`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			f := newGroupEndpointKeyGrantFixture(t)
			manifest := f.preview(t)
			proof := f.sign(t, f.ownerIdentity, manifest)
			if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
				f.endpointID, f.ownerKeyID, proof); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.Exec(testCase.query); err != nil {
				t.Fatal(err)
			}
			grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
			if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
				t.Fatalf("%s revision change did not stale grant: grant=%#v err=%v", testCase.name, grant, err)
			}
		})
	}
}

func TestGroupEndpointKeyGrantGroupAndOwnerKeyRevocation(t *testing.T) {
	t.Run("membership revocation", func(t *testing.T) {
		f := newGroupEndpointKeyGrantFixture(t)
		manifest := f.preview(t)
		proof := f.sign(t, f.ownerIdentity, manifest)
		if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
			f.endpointID, f.ownerKeyID, proof); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RevokeMembershipForPrincipalGroup(
			"pr_ep_remote_key_grant", f.groupID, "grant scope revoked"); err != nil {
			t.Fatal(err)
		}
		grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
		if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
			t.Fatalf("membership revocation did not stale grant: grant=%#v err=%v", grant, err)
		}
	})
	t.Run("Group revocation", func(t *testing.T) {
		f := newGroupEndpointKeyGrantFixture(t)
		manifest := f.preview(t)
		proof := f.sign(t, f.ownerIdentity, manifest)
		if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
			f.endpointID, f.ownerKeyID, proof); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.db.Exec(`UPDATE groups SET state = 'ARCHIVED', revision = revision + 1 WHERE id = ?`, f.groupID); err != nil {
			t.Fatal(err)
		}
		grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
		if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
			t.Fatalf("Group revocation did not stale grant: grant=%#v err=%v", grant, err)
		}
	})
	t.Run("owner key revocation", func(t *testing.T) {
		f := newGroupEndpointKeyGrantFixture(t)
		manifest := f.preview(t)
		proof := f.sign(t, f.ownerIdentity, manifest)
		if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
			f.endpointID, f.ownerKeyID, proof); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RevokeOwnerApprovalKeyLocal(f.ownerID, f.ownerKeyID, 1); err != nil {
			t.Fatal(err)
		}
		grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
		if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantRevoked {
			t.Fatalf("owner key revocation did not fence grant: grant=%#v err=%v", grant, err)
		}
		if _, err := f.store.VerifyCurrentGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID); !errors.Is(err, ErrGroupEndpointKeyGrantStale) {
			t.Fatalf("revoked owner key still verified: %v", err)
		}
	})
}

func TestGroupEndpointKeyGrantV27MigrationPreservesV26RowsAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("interrupt v27 Group key grant migration")
	if _, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.collaboration.group_endpoint_key_grants" && phase == "before_apply" {
			return injected
		}
		return nil
	}); !errors.Is(err, injected) {
		t.Fatalf("expected injected v27 migration failure, got %v", err)
	}

	// This is now a v26 database: preserve its invite row while v27 is retried.
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Use a fixed valid digest shape; this is only public migration fixture data.
	digest := hex.EncodeToString(make([]byte, sha256.Size))
	_, err = check.Exec(`INSERT INTO external_thread_invites_v2
(invite_id, token_digest, source_endpoint_id, source_group_id, source_owner_id,
 source_principal_id, source_node_id, source_membership_revision, source_join_revision,
 source_group_version, hub_id, direction, actions_json, data_scopes_json, expires_at,
 state, created_at)
VALUES ('invite_v26_preserved', ?, 'ep_old', 'grp_old', 'owner_old', 'pr_old',
 'node_old', 3, 4, 5, 'hub_old', 'forward', '["ask"]', '["public.result"]',
 '2099-01-01T00:00:00Z', 'PENDING', '2026-01-01T00:00:00Z')`, digest)
	if err != nil {
		t.Fatal(err)
	}
	var newTableCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'group_endpoint_key_grants_v2'`).Scan(&newTableCount); err != nil {
		t.Fatal(err)
	}
	if newTableCount != 0 {
		t.Fatalf("failed v27 migration left its new table behind: %d", newTableCount)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var storedDigest, storedEndpoint string
	if err := reopened.db.QueryRow(`SELECT token_digest, source_endpoint_id FROM external_thread_invites_v2
WHERE invite_id = 'invite_v26_preserved'`).Scan(&storedDigest, &storedEndpoint); err != nil {
		t.Fatal(err)
	}
	if storedDigest != digest || storedEndpoint != "ep_old" {
		t.Fatalf("v27 changed v26 public invite data: digest=%q endpoint=%q", storedDigest, storedEndpoint)
	}
	var grantRows int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2`).Scan(&grantRows); err != nil {
		t.Fatal(err)
	}
	if grantRows != 0 {
		t.Fatalf("v26 data was incorrectly backfilled as owner-approved trust: %d", grantRows)
	}
	entry, err := reopened.readV2Migration(27)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v27 migration did not retry cleanly: entry=%#v err=%v", entry, err)
	}
}
