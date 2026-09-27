package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type localDeliveryAuthorizationFixture struct {
	store         *Store
	group         *Group
	nodeID        string
	nodeDigest    string
	sessionToken  string
	sessionDigest string
	source        *Endpoint
	sourceBinding *SessionBinding
	target        *Endpoint
	targetBinding *SessionBinding
}

func newLocalDeliveryAuthorizationFixture(t *testing.T) *localDeliveryAuthorizationFixture {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "local-delivery.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreatePrincipal(Principal{
		ID: "owner_local", Kind: PrincipalKindHuman, OwnerID: "owner_local",
		TrustDomainID: "domain_local", Name: "local owner", Status: PrincipalStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(Group{
		ID: "group_local", Name: "local group", OwnerPrincipalID: "owner_local",
		TrustDomainID: "domain_local", State: GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(Group{
		ID: "group_other", Name: "other group", OwnerPrincipalID: "owner_local",
		TrustDomainID: "domain_local", State: GroupStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	nodeDigest := localDeliveryDigest("node local credential")
	if err := bindLocalDeliveryNode(s, "node_local", nodeDigest); err != nil {
		t.Fatal(err)
	}
	sourceToken := "cicada_session_source_local"
	source, sourceBinding := addLocalDeliveryEndpoint(t, s, group.ID, "ep_source", "source", "node_local",
		[]string{"message.send", "message.ask", "message.reply"}, sourceToken)
	target, targetBinding := addLocalDeliveryEndpoint(t, s, group.ID, "ep_target", "target", "node_local",
		[]string{"message.receive"}, "cicada_session_target_local")
	return &localDeliveryAuthorizationFixture{
		store: s, group: group, nodeID: "node_local", nodeDigest: nodeDigest,
		sessionToken: sourceToken, sessionDigest: localDeliveryDigest(sourceToken),
		source: source, sourceBinding: sourceBinding, target: target, targetBinding: targetBinding,
	}
}

func bindLocalDeliveryNode(s *Store, nodeID, credentialDigest string) error {
	owner, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal("owner_local", owner.Public())
	if err != nil {
		return err
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		return err
	}
	deviceID := "device_" + nodeID
	nowTime := time.Now().UTC()
	grant, err := owner.SignOwnerDeviceGrant("owner_local", deviceID, device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, nowTime.Add(-time.Minute), nowTime.Add(time.Hour))
	if err != nil {
		return err
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_local", OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		return err
	}
	codeSum := sha256.Sum256([]byte("pairing code " + nodeID))
	code := hex.EncodeToString(codeSum[:])
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, nodeID, credentialDigest,
		code, nowTime.Add(10*time.Minute)); err != nil {
		return err
	}
	_, err = s.ConfirmPendingNodeDeviceBinding("owner_local", deviceID, code)
	return err
}

func addLocalDeliveryEndpoint(t *testing.T, s *Store, groupID, endpointID, name, nodeID string,
	grants []string, token string) (*Endpoint, *SessionBinding) {
	t.Helper()
	principal, err := s.CreatePrincipal(Principal{
		ID: "pr_" + endpointID, Kind: PrincipalKindAgent, OwnerID: "owner_local",
		TrustDomainID: "domain_local", Name: endpointID, Status: PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMembership(Membership{
		PrincipalID: principal.ID, GroupID: groupID, Role: "member", Grants: grants,
		Status: MembershipStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := s.UpsertEndpoint(Endpoint{
		ID: endpointID, Name: name, Role: "thread", Harness: "codex",
		NativeSessionID: "native_" + endpointID, MachineID: nodeID,
		Owner: "owner_local", Status: "online",
	})
	if err != nil {
		t.Fatal(err)
	}
	leaseOwner := "lease_" + endpointID
	binding, err := s.CreateSessionBinding(SessionBinding{
		EndpointID: endpoint.ID, PrincipalID: principal.ID, GroupID: groupID,
		NativeSessionID: endpoint.NativeSessionID, NodeID: nodeID, Epoch: 1,
		LeaseOwner: leaseOwner, LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		Status: SessionBindingStatusLeased, CredentialHash: localDeliveryDigest(token),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(endpoint.ID, principal.ID, nodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterEndpointKeyCandidate(endpoint.ID, principal.ID, binding.ID, binding.Epoch, proof); err != nil {
		t.Fatal(err)
	}
	endpoint, err = s.GetEndpointV2(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint, binding
}

func localDeliveryDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *localDeliveryAuthorizationFixture) authorize(target, groupID, action string) (*LocalDeliveryAuthorization, error) {
	return f.store.AuthorizeLocalDeliveryForNodeCredential(f.nodeDigest, f.sessionDigest,
		LocalDeliveryAuthorizationInput{GroupID: groupID, Target: target, Action: action})
}

func TestLocalDeliveryAuthorizationReturnsCurrentSameNodeRouteAndRevalidates(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	authorized, err := f.authorize("target", f.group.ID, "message.ask")
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Action != "message.ask" || authorized.AuthorizationRevision == "" || authorized.AuthorizedAt == "" ||
		authorized.ValidUntil == "" || authorized.Source.EndpointID != f.source.ID ||
		authorized.Source.OwnerID != "owner_local" || authorized.Source.NativeSessionID != "" ||
		authorized.Target.EndpointID != f.target.ID || authorized.Target.NativeSessionID != f.target.NativeSessionID ||
		authorized.Source.GroupJoinRevision <= 0 || authorized.Target.GroupJoinRevision <= 0 ||
		authorized.Source.MembershipRevision <= 0 || authorized.Target.MembershipRevision <= 0 ||
		authorized.Source.BindingID != f.sourceBinding.ID || authorized.Target.BindingID != f.targetBinding.ID ||
		authorized.Source.BindingEpoch != f.sourceBinding.Epoch || authorized.Target.BindingEpoch != f.targetBinding.Epoch ||
		authorized.SourceKey.KeyID == "" || len(authorized.SourceKey.Proof) == 0 ||
		authorized.TargetKey.KeyID == "" || len(authorized.TargetKey.Proof) == 0 {
		t.Fatalf("incomplete bounded authorization snapshot: %#v", authorized)
	}

	revalidated, err := f.store.RevalidateLocalDeliveryForNodeCredential(f.nodeDigest,
		LocalDeliveryRevalidationInput{
			GroupID: f.group.ID, SourceEndpointID: f.source.ID,
			SourceBindingID: f.sourceBinding.ID, SourceBindingEpoch: f.sourceBinding.Epoch,
			TargetEndpointID: f.target.ID, Action: "message.ask",
		})
	if err != nil || revalidated.Target.NativeSessionID != f.target.NativeSessionID {
		t.Fatalf("Node could not revalidate exact persisted route: %#v err=%v", revalidated, err)
	}
	if _, err := f.store.RevalidateLocalDeliveryForNodeCredential(f.nodeDigest,
		LocalDeliveryRevalidationInput{
			GroupID: f.group.ID, SourceEndpointID: f.source.ID,
			SourceBindingID: f.sourceBinding.ID, SourceBindingEpoch: f.sourceBinding.Epoch + 1,
			TargetEndpointID: f.target.ID, Action: "message.ask",
		}); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
		t.Fatalf("forged source binding epoch revalidated: %v", err)
	}
}

func TestLocalDeliveryAuthorizationRevisionSurvivesLeaseRenewalButFencesNewEpoch(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	first, err := f.authorize(f.target.ID, f.group.ID, "message.ask")
	if err != nil {
		t.Fatal(err)
	}
	newExpiry := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339Nano)
	if _, err := f.store.RenewSessionBindingLease(f.sourceBinding.ID, f.sourceBinding.LeaseOwner,
		f.sourceBinding.Epoch, newExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RenewSessionBindingLease(f.targetBinding.ID, f.targetBinding.LeaseOwner,
		f.targetBinding.Epoch, newExpiry); err != nil {
		t.Fatal(err)
	}
	second, err := f.authorize(f.target.ID, f.group.ID, "message.ask")
	if err != nil || second.AuthorizationRevision != first.AuthorizationRevision {
		t.Fatalf("lease renewal changed the stable local route revision: first=%#v second=%#v err=%v", first, second, err)
	}
	input := LocalDeliveryRevalidationInput{
		GroupID: f.group.ID, SourceEndpointID: f.source.ID, SourceBindingID: f.sourceBinding.ID,
		SourceBindingEpoch: f.sourceBinding.Epoch, TargetEndpointID: f.target.ID, Action: "message.ask",
	}
	if _, err := f.store.RevalidateLocalDeliveryForNodeCredential(f.nodeDigest, input); err != nil {
		t.Fatalf("lease-renewed route did not revalidate: %v", err)
	}
	released, err := f.store.ReleaseSessionBindingLease(f.sourceBinding.ID, f.sourceBinding.LeaseOwner, f.sourceBinding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if released.Epoch == f.sourceBinding.Epoch {
		t.Fatal("lease release did not advance its fencing epoch")
	}
	if _, err := f.store.AcquireSessionBindingLease(f.sourceBinding.ID, f.sourceBinding.LeaseOwner,
		released.Epoch, newExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevalidateLocalDeliveryForNodeCredential(f.nodeDigest, input); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
		t.Fatalf("old route epoch survived rebind: %v", err)
	}
}

func TestLocalDeliveryAuthorizationFailsClosedForGroupOwnerMembershipAndBindingChanges(t *testing.T) {
	t.Run("wrong group", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.authorize(f.target.ID, "group_other", "message.ask"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("source authorized outside joined Group: %v", err)
		}
	})
	t.Run("unjoined target", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.db.Exec(`UPDATE endpoint_group_memberships SET status='revoked', revision=revision+1 WHERE endpoint_id=? AND group_id=?`, f.target.ID, f.group.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authorize(f.target.ID, f.group.ID, "message.ask"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("unjoined target was routed: %v", err)
		}
	})
	t.Run("revoked source membership", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.RevokeMembershipForPrincipalGroup(f.source.PrincipalID, f.group.ID, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authorize(f.target.ID, f.group.ID, "message.ask"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("revoked source membership remained authorized: %v", err)
		}
	})
	t.Run("revoked target membership", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.RevokeMembershipForPrincipalGroup(f.target.PrincipalID, f.group.ID, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authorize(f.target.ID, f.group.ID, "message.ask"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("revoked target membership remained routable: %v", err)
		}
	})
	t.Run("stale source binding", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.RevokeSessionBinding(f.sourceBinding.ID, f.sourceBinding.Epoch, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authorize(f.target.ID, f.group.ID, "message.ask"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("stale source binding remained authorized: %v", err)
		}
	})
	t.Run("wrong Node credential", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		otherDigest := localDeliveryDigest("node other credential")
		if err := bindLocalDeliveryNode(f.store, "node_other", otherDigest); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeLocalDeliveryForNodeCredential(otherDigest, f.sessionDigest,
			LocalDeliveryAuthorizationInput{GroupID: f.group.ID, Target: f.target.ID, Action: "message.ask"}); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("wrong Node credential authorized source binding: %v", err)
		}
	})
	t.Run("same Node different owner", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreatePrincipal(Principal{
			ID: "foreign_owner", Kind: PrincipalKindHuman, OwnerID: "foreign_owner",
			Name: "foreign owner", Status: PrincipalStatusActive,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.CreatePrincipal(Principal{
			ID: "pr_foreign_target", Kind: PrincipalKindAgent, OwnerID: "foreign_owner",
			Name: "foreign target", Status: PrincipalStatusActive,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.CreateMembership(Membership{PrincipalID: "pr_foreign_target", GroupID: f.group.ID,
			Role: "member", Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := f.store.UpsertEndpoint(Endpoint{
			ID: "ep_foreign_target", Name: "foreign", Harness: "codex", NativeSessionID: "native_foreign",
			MachineID: f.nodeID, Owner: "foreign_owner", Status: "online",
		})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := f.store.CreateSessionBinding(SessionBinding{
			EndpointID: endpoint.ID, PrincipalID: "pr_foreign_target", GroupID: f.group.ID,
			NativeSessionID: endpoint.NativeSessionID, NodeID: f.nodeID, Status: SessionBindingStatusLeased,
			LeaseOwner: "lease_foreign", LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			CredentialHash: localDeliveryDigest("foreign session token"),
		})
		if err != nil {
			t.Fatal(err)
		}
		identity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := identity.SignEndpointKeyAttestation(endpoint.ID, "pr_foreign_target", f.nodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RegisterEndpointKeyCandidate(endpoint.ID, "pr_foreign_target", binding.ID, binding.Epoch, proof); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authorize(endpoint.ID, f.group.ID, "message.ask"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
			t.Fatalf("same-Node cross-owner route was allowed: %v", err)
		}
	})
}

func TestLocalDeliveryAuthorizationRejectsAmbiguousAliasesAndChangedCandidates(t *testing.T) {
	t.Run("ambiguous alias", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		addLocalDeliveryEndpoint(t, f.store, f.group.ID, "ep_target2", "target", f.nodeID,
			[]string{"message.receive"}, "cicada_session_target2")
		if _, err := f.authorize("target", f.group.ID, "message.send"); !errors.Is(err, ErrLocalDeliveryAmbiguousTarget) {
			t.Fatalf("ambiguous alias was guessed: %v", err)
		}
	})
	t.Run("candidate binding substitution", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.db.Exec(`UPDATE endpoint_key_candidates_v2 SET binding_epoch=binding_epoch+1 WHERE endpoint_id=?`, f.target.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authorize(f.target.ID, f.group.ID, "message.ask"); !errors.Is(err, ErrLocalDeliveryTargetKeyUnavailable) {
			t.Fatalf("candidate from a stale binding remained current: %v", err)
		}
	})
}

func TestLocalDeliveryAuthorizationSignalsOnlyUniqueAuthorizedRemoteTargets(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	remote, _ := addLocalDeliveryEndpoint(t, f.store, f.group.ID, "ep_remote", "remote", "node_remote",
		[]string{"message.receive"}, "cicada_session_remote")
	if _, err := f.authorize(remote.ID, f.group.ID, "message.send"); !errors.Is(err, ErrLocalDeliveryNotLocal) {
		t.Fatalf("unique authorized remote target was not distinguished: %v", err)
	}
	if _, err := f.authorize("missing", f.group.ID, "message.send"); !errors.Is(err, ErrLocalDeliveryNotAuthorized) {
		t.Fatalf("invisible target returned remote fallback signal: %v", err)
	}
}
