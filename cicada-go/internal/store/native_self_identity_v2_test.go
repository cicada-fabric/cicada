package store

import (
	"errors"
	"testing"
	"time"
)

func nativeSelfCandidateScope(t *testing.T, f *endpointKeyCandidateFixture) NativeActorScope {
	t.Helper()
	member, err := f.store.GetMembershipByPrincipalGroup("pr_candidate", "grp_candidate")
	if err != nil {
		t.Fatal(err)
	}
	return NativeActorScope{PrincipalID: member.PrincipalID, EndpointID: f.binding.EndpointID,
		GroupID: member.GroupID, MembershipID: member.ID, MembershipRevision: member.Revision,
		BindingID: f.binding.ID, BindingEpoch: f.binding.Epoch, LeaseOwner: f.binding.LeaseOwner}
}

func assertNativeSelfDenied(t *testing.T, f *endpointKeyCandidateFixture, scope NativeActorScope, proof []byte) {
	t.Helper()
	for name, call := range map[string]func() error{
		"identity":        func() error { _, _, err := f.store.GetNativeSelfForActor(scope); return err },
		"candidate read":  func() error { _, err := f.store.GetOwnEndpointKeyCandidateForActor(scope); return err },
		"candidate write": func() error { _, err := f.store.RegisterEndpointKeyCandidateForActor(scope, proof); return err },
	} {
		if err := call(); !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("%s accepted invalid self scope: %v", name, err)
		}
	}
}

func TestNativeSelfRequiresExactCurrentScopeAndPublicProof(t *testing.T) {
	f := newEndpointKeyCandidateFixture(t)
	scope := nativeSelfCandidateScope(t, f)
	proof := f.attestation(t, f.identity, scope.BindingID, scope.BindingEpoch)
	for name, alter := range map[string]func(*NativeActorScope){
		"endpoint":    func(s *NativeActorScope) { s.EndpointID = "ep_other" },
		"principal":   func(s *NativeActorScope) { s.PrincipalID = "pr_other" },
		"group":       func(s *NativeActorScope) { s.GroupID = "grp_other" },
		"membership":  func(s *NativeActorScope) { s.MembershipID = "member_other" },
		"revision":    func(s *NativeActorScope) { s.MembershipRevision++ },
		"epoch":       func(s *NativeActorScope) { s.BindingEpoch++ },
		"binding":     func(s *NativeActorScope) { s.BindingID = "bind_other" },
		"lease owner": func(s *NativeActorScope) { s.LeaseOwner = "lease_other" },
		"network":     func(s *NativeActorScope) { s.NetworkID = "network_other" },
	} {
		t.Run(name, func(t *testing.T) {
			forged := scope
			alter(&forged)
			assertNativeSelfDenied(t, f, forged, proof)
		})
	}
	wrongProof, err := f.identity.SignEndpointKeyAttestation("ep_other", scope.PrincipalID,
		"node_candidate", scope.BindingID, scope.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RegisterEndpointKeyCandidateForActor(scope, wrongProof); err == nil {
		t.Fatal("accepted proof for another Endpoint")
	}
	corrupt := append([]byte(nil), proof...)
	corrupt[len(corrupt)/2] ^= 1
	if _, err := f.store.RegisterEndpointKeyCandidateForActor(scope, corrupt); err == nil {
		t.Fatal("accepted altered self proof")
	}
	if _, err := f.store.GetOwnEndpointKeyCandidateForActor(scope); !errors.Is(err, ErrEndpointKeyNotFound) {
		t.Fatalf("refused proofs created a candidate: %v", err)
	}
	endpoint, binding, err := f.store.GetNativeSelfForActor(scope)
	if err != nil || endpoint.ID != scope.EndpointID || endpoint.PrincipalID != scope.PrincipalID ||
		binding.ID != scope.BindingID || binding.NativeSessionID != "native-candidate" {
		t.Fatalf("current zero-grant self read failed: %v", err)
	}
	first, err := f.store.RegisterEndpointKeyCandidateForActor(scope, proof)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := f.store.RegisterEndpointKeyCandidateForActor(scope, proof)
	if err != nil || first.Version != repeated.Version || first.State != EndpointKeyCandidateStateCandidate {
		t.Fatalf("same candidate was not idempotent: %v", err)
	}
	member, err := f.store.GetMembership(scope.MembershipID)
	if err != nil || len(member.Grants) != 0 || member.Revision != scope.MembershipRevision {
		t.Fatal("self operations expanded membership authority")
	}
	updated, err := f.store.UpdateMembershipAuthorization(member.ID, member.Roles,
		member.Grants, member.Authorization, member.Version)
	if err != nil {
		t.Fatal(err)
	}
	assertNativeSelfDenied(t, f, scope, proof)
	scope.MembershipRevision = updated.Revision
	if _, err := f.store.GetOwnEndpointKeyCandidateForActor(scope); err != nil {
		t.Fatalf("current revised self could not read its candidate: %v", err)
	}
}

func TestNativeSelfRevokedSelectedGroupCannotBorrowAnotherGroupAcrossStores(t *testing.T) {
	f := newEndpointKeyCandidateFixture(t)
	scope := nativeSelfCandidateScope(t, f)
	proof := f.attestation(t, f.identity, scope.BindingID, scope.BindingEpoch)
	if _, err := f.store.RegisterEndpointKeyCandidateForActor(scope, proof); err != nil {
		t.Fatal(err)
	}
	otherGroup, err := f.store.CreateGroup(Group{ID: "grp_other_active", OwnerPrincipalID: "pr_candidate",
		Name: "synthetic second Group", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	otherMember, err := f.store.CreateMembership(Membership{PrincipalID: scope.PrincipalID,
		GroupID: otherGroup.ID, Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.JoinEndpointGroup(scope.EndpointID, otherGroup.ID); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := f.store.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.RevokeMembership(scope.MembershipID, "synthetic selected Group revoke"); err != nil {
		t.Fatal(err)
	}
	assertNativeSelfDenied(t, f, scope, proof)
	currentBinding, err := f.store.GetSessionBinding(scope.BindingID)
	if err != nil || currentBinding.Epoch != scope.BindingEpoch || currentBinding.Status != SessionBindingStatusLeased {
		t.Fatal("selected Group revoke unexpectedly fenced the other Group's binding")
	}
	scope.GroupID, scope.MembershipID, scope.MembershipRevision = otherGroup.ID, otherMember.ID, otherMember.Revision
	if _, err := f.store.GetOwnEndpointKeyCandidateForActor(scope); err != nil {
		t.Fatalf("independently active zero-grant Group lost own candidate read: %v", err)
	}
}

func TestNativeSelfRejectsExpiredOrUnusablePersistedAuthority(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	for name, mutation := range map[string]struct {
		query string
		value any
	}{
		"expired membership": {`UPDATE memberships SET expires_at=?`, past},
		"future membership":  {`UPDATE memberships SET effective_at=?`, future},
		"expired lease":      {`UPDATE session_bindings SET lease_expires_at=?`, past},
		"native mismatch":    {`UPDATE session_bindings SET native_session_id=?`, "native-other"},
		"node mismatch":      {`UPDATE session_bindings SET node_id=?`, "node-other"},
		"inactive Group":     {`UPDATE groups SET state=?`, GroupStateArchived},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEndpointKeyCandidateFixture(t)
			scope := nativeSelfCandidateScope(t, f)
			proof := f.attestation(t, f.identity, scope.BindingID, scope.BindingEpoch)
			if _, err := f.store.RegisterEndpointKeyCandidateForActor(scope, proof); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.Exec(mutation.query, mutation.value); err != nil {
				t.Fatal(err)
			}
			assertNativeSelfDenied(t, f, scope, proof)
		})
	}
}
