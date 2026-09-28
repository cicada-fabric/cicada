package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkMigrationInspectionIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inspection.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.DryRunNetworkMigration()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectNetworkMigrationReadOnly(path)
	if err != nil || inspected.Phase != before.Phase || inspected.UnmappedCount != before.UnmappedCount {
		t.Fatalf("read-only inventory mismatch: %#v %v", inspected, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatalf("inspection mutated source database: %v", err)
	}
	if _, err := InspectNetworkMigrationReadOnly(filepath.Join(t.TempDir(), "missing.sqlite3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing DB was initialized by inventory: %v", err)
	}
}

func TestNetworkSignedJoinIsIndependentOfGroupAndRevocable(t *testing.T) {
	s, owner, _, device := newClientDeviceFixture(t)
	if _, err := s.db.Exec(`UPDATE principals SET trust_domain_id='domain' WHERE id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	const nodeToken = "synthetic-network-node-credential"
	credentialDigest := nodeBindingTestCredentialDigest(nodeToken)
	codeDigest := nodeBindingTestCodeDigest("network-test-code")
	request, err := s.CreatePendingNodeDeviceBinding("network-node", "Network Node", credentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	network, err := s.CreateNetwork(Network{ID: "network-a", HubID: request.HubID, Name: "A", OwnerID: "owner_a"})
	if err != nil {
		t.Fatal(err)
	}
	const invitation = "synthetic-invitation-aaaaaaaaaaaaaaaaaaaaaaaa"
	grants := []string{"directory.discover", "directory.publish"}
	if err := s.IssueNetworkInvitation(network.ID, "owner_a", "owner_a", invitation, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Add(-time.Minute)
	proof, err := owner.SignOwnerNetworkJoinGrant("owner_a", request.HubID, network.ID, "network-node", "synthetic-native-session", NetworkInvitationDigest(invitation), owner.Public().ID, grants, true, issued, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var nonce, expiry string
	{
		var grant struct {
			Nonce     string `json:"nonce"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(proof, &grant); err != nil {
			t.Fatal(err)
		}
		nonce, expiry = grant.Nonce, grant.ExpiresAt
	}
	join := AcceptNetworkJoinInput{NetworkID: network.ID, OwnerID: "owner_a", TrustDomainID: "domain", NodeID: "network-node", NativeSessionID: "synthetic-native-session", Harness: "codex", EndpointName: "agent", InvitationToken: invitation, ProofNonce: nonce, ProofDigest: NetworkInvitationDigest(string(proof)), ProofExpiresAt: expiry, OwnerKeyID: owner.Public().ID, OwnerJoinProof: string(proof), NodeCredentialHash: credentialDigest, Grants: grants, Discoverable: true, CredentialHash: "synthetic-access-digest", LeaseOwner: "synthetic-lease", LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	accepted, err := s.AcceptNetworkJoin(join)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := s.GetEndpointV2(accepted.EndpointID)
	if err != nil || endpoint.GroupID != "" || endpoint.PrincipalID != accepted.PrincipalID {
		t.Fatalf("network join changed Group identity: %#v %v", endpoint, err)
	}
	entries, err := s.ListNetworkDirectory(NetworkAccessScope{
		NetworkID: network.ID, PrincipalID: accepted.PrincipalID,
		EndpointID: accepted.EndpointID, AccessSessionID: accepted.AccessSessionID,
		AccessEpoch: accepted.AccessSessionEpoch, LeaseOwner: join.LeaseOwner,
		MembershipID: accepted.MembershipID, MembershipRevision: accepted.MembershipRevision,
		EndpointMembershipRevision: accepted.EndpointRevision,
	}, 10)
	if err != nil || len(entries) != 1 || entries[0].EndpointID != accepted.EndpointID {
		t.Fatalf("directory=%#v err=%v", entries, err)
	}
	join.CredentialHash = "synthetic-access-digest-retry"
	retried, err := s.AcceptNetworkJoin(join)
	if err != nil || retried.EndpointID != accepted.EndpointID || retried.AccessSessionEpoch != accepted.AccessSessionEpoch+1 {
		t.Fatalf("retry=%#v err=%v", retried, err)
	}
	if err := s.RevokeNetworkMembership(network.ID, accepted.PrincipalID, retried.MembershipRevision); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.NetworkAllows(network.ID, accepted.PrincipalID, accepted.EndpointID, "directory.discover"); err != nil || allowed {
		t.Fatalf("revoked member allowed=%v err=%v", allowed, err)
	}
	if _, err := s.RenewNetworkAccess(RenewNetworkAccessInput{NetworkID: network.ID, EndpointID: accepted.EndpointID, OwnerID: "owner_a", NodeID: "network-node", Harness: "codex", NativeSessionID: "synthetic-native-session", NodeCredentialHash: credentialDigest, CredentialHash: "synthetic-new-digest", LeaseOwner: "synthetic-new-lease", LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked renewal: %v", err)
	}
	join.CredentialHash = "synthetic-old-proof-replay"
	if _, err := s.AcceptNetworkJoin(join); !errors.Is(err, ErrNetworkConsent) {
		t.Fatalf("consumed proof revived revoked member: %v", err)
	}
	const nextInvitation = "synthetic-invitation-bbbbbbbbbbbbbbbbbbbbbbbb"
	if err := s.IssueNetworkInvitation(network.ID, "owner_a", "owner_a", nextInvitation, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	nextProof, err := owner.SignOwnerNetworkJoinGrant("owner_a", request.HubID, network.ID, "network-node", "synthetic-native-session", NetworkInvitationDigest(nextInvitation), owner.Public().ID, grants, true, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var nextGrant struct {
		Nonce     string `json:"nonce"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(nextProof, &nextGrant); err != nil {
		t.Fatal(err)
	}
	join.InvitationToken = nextInvitation
	join.OwnerJoinProof = string(nextProof)
	join.ProofNonce = nextGrant.Nonce
	join.ProofDigest = NetworkInvitationDigest(string(nextProof))
	join.ProofExpiresAt = nextGrant.ExpiresAt
	join.CredentialHash = "synthetic-rejoined-digest"
	rejoined, err := s.AcceptNetworkJoin(join)
	if err != nil || rejoined.EndpointID != accepted.EndpointID || rejoined.PrincipalID != accepted.PrincipalID || rejoined.MembershipRevision <= retried.MembershipRevision || rejoined.EndpointRevision <= retried.EndpointRevision {
		t.Fatalf("fresh consent failed to restore original identity: %#v %v", rejoined, err)
	}
}

func TestNetworkMigrationMappingIsVersionedAndOneWay(t *testing.T) {
	s, err := New(t.TempDir() + "/state.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner, err := s.CreatePrincipal(Principal{ID: "synthetic-owner", Kind: PrincipalKindHuman, OwnerID: "synthetic-owner", TrustDomainID: "synthetic-domain", Name: "owner", Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	networkA, err := s.CreateNetwork(Network{ID: "net-a", HubID: hubID, Name: "A", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	networkB, err := s.CreateNetwork(Network{ID: "net-b", HubID: hubID, Name: "B", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(Group{ID: "synthetic-group", OwnerPrincipalID: owner.ID, TrustDomainID: "synthetic-domain", Name: "private", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateNetworkMode(); !errors.Is(err, ErrNetworkMigration) {
		t.Fatalf("unreviewed group activated: %v", err)
	}
	if _, err := s.PrepareGroupNetworkMapping(group.ID, networkA.ID, "synthetic decision", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveGroupNetworkMapping(group.ID, networkB.ID, group.Version); !errors.Is(err, ErrNetworkConflict) {
		t.Fatalf("wrong mapping accepted: %v", err)
	}
	if err := s.ApproveGroupNetworkMapping(group.ID, networkA.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareGroupNetworkMapping(group.ID, networkB.ID, "remap", group.Version+1); !errors.Is(err, ErrNetworkConflict) {
		t.Fatalf("approved map changed: %v", err)
	}
	if err := s.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	if err := s.NetworkGuardGroup("unknown", "unknown", group.ID, networkB.ID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("forged Network accepted: %v", err)
	}
	if err := s.NetworkGuardGroup("unknown", "unknown", group.ID, ""); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old unscoped access accepted: %v", err)
	}
}
