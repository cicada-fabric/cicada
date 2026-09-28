package store

import (
	"errors"
	"testing"
	"time"
)

func TestNetworkArtifactMutationsRejectStaleNativeActorAcrossStores(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.store.CreateNetwork(Network{ID: "net_artifact_mutation", HubID: hubID,
		OwnerID: f.ownerID, Name: "Synthetic artifact mutation"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.store.GetGroup(f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.store.GetEndpointV2(f.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), network.ID,
		endpoint.PrincipalID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'artifact actor',0,?,?)`, network.ID, endpoint.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	membership, err = f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles,
		[]string{"artifact.publish", "artifact.share"}, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetSessionBinding(f.bindingID)
	if err != nil {
		t.Fatal(err)
	}
	scope := NativeActorScope{PrincipalID: endpoint.PrincipalID, EndpointID: endpoint.ID,
		GroupID: group.ID, NetworkID: network.ID, MembershipID: membership.ID,
		MembershipRevision: membership.Revision, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
	goal, err := f.store.CreateGoal("goal_artifact_mutation", "synthetic artifact", "", "", 50,
		endpoint.MachineID, "monitor_artifact_mutation", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE goals SET owner_id=? WHERE id=?`, f.ownerID, goal.ID); err != nil {
		t.Fatal(err)
	}
	worker, err := f.store.CreateWorkerAtHarness("worker_artifact_mutation", goal.ID,
		endpoint.MachineID, endpoint.Harness, "response.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE workers SET thread_id=? WHERE id=?`, endpoint.NativeSessionID, worker.ID); err != nil {
		t.Fatal(err)
	}
	legacy, err := f.store.CreateArtifact(Artifact{ID: "synthetic-artifact-mutation", GoalID: goal.ID,
		WorkerID: worker.ID, Name: "evidence",
		Path: "evidence.txt", Kind: "evidence", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	input := ArtifactRefV2Input{ArtifactID: legacy.ID, GroupID: group.ID,
		ProducerPrincipalID: scope.PrincipalID, ProducerEndpointID: scope.EndpointID,
		Scopes: []string{ArtifactRefV2ScopeMetadata}}
	otherGoal, err := f.store.CreateGoal("goal_other_artifact", "other owner", "", "", 50,
		endpoint.MachineID, "monitor_other_artifact", "")
	if err != nil {
		t.Fatal(err)
	}
	otherWorker, err := f.store.CreateWorkerAtHarness("worker_other_artifact", otherGoal.ID,
		endpoint.MachineID, endpoint.Harness, "other-response.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE goals SET owner_id='other_owner' WHERE id=?`, otherGoal.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE workers SET thread_id=? WHERE id=?`, endpoint.NativeSessionID, otherWorker.ID); err != nil {
		t.Fatal(err)
	}
	foreign, err := f.store.CreateArtifact(Artifact{ID: "foreign-owner-artifact", GoalID: otherGoal.ID,
		WorkerID: otherWorker.ID, Name: "foreign evidence", Path: "foreign.txt", Kind: "evidence",
		Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	if err != nil {
		t.Fatal(err)
	}
	foreignInput := input
	foreignInput.ArtifactID = foreign.ID
	if _, err := f.store.CreateArtifactRefV2ForActor(scope, foreignInput); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("current actor published another owner's legacy Artifact: %v", err)
	}
	unmapped, err := f.store.CreateArtifact(Artifact{ID: "unmapped-legacy-artifact", Name: "unmapped",
		Path: "unmapped.txt", Kind: "evidence",
		Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
	if err != nil {
		t.Fatal(err)
	}
	unmappedInput := input
	unmappedInput.ArtifactID = unmapped.ID
	if _, err := f.store.CreateArtifactRefV2ForActor(scope, unmappedInput); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("current actor published unmapped legacy Artifact: %v", err)
	}
	var foreignRefs int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM artifact_v2_refs WHERE artifact_id=?`, foreign.ID).Scan(&foreignRefs); err != nil || foreignRefs != 0 {
		t.Fatalf("foreign Artifact acquired scoped ref: count=%d err=%v", foreignRefs, err)
	}
	ref, err := f.store.CreateArtifactRefV2ForActor(scope, input)
	if err != nil {
		t.Fatalf("current scoped publish: %v", err)
	}
	grantInput := ArtifactRefV2GrantInput{ArtifactRefID: ref.ID, GrantorPrincipalID: scope.PrincipalID,
		GranteePrincipalID: scope.PrincipalID, Scopes: []string{ArtifactRefV2ScopeMetadata}}
	grant, err := f.store.CreateArtifactRefV2GrantForActor(scope, grantInput)
	if err != nil {
		t.Fatalf("current scoped grant: %v", err)
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
	if err := other.LeaveEndpointNetwork(network.ID, endpoint.ID, 1); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"publish":      func() error { _, err := f.store.CreateArtifactRefV2ForActor(scope, input); return err },
		"grant":        func() error { _, err := f.store.CreateArtifactRefV2GrantForActor(scope, grantInput); return err },
		"revoke grant": func() error { _, err := f.store.RevokeArtifactRefV2GrantForActor(scope, grant.ID, "stale"); return err },
		"revoke ref":   func() error { _, err := f.store.RevokeArtifactRefV2ForActor(scope, ref.ID, "stale"); return err },
	} {
		if err := run(); !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("stale actor %s: %v", name, err)
		}
	}
	currentRef, err := f.store.GetArtifactRefV2(ref.ID)
	if err != nil || currentRef.Status != ArtifactRefV2StatusAvailable {
		t.Fatalf("revoked actor mutated ref: %#v %v", currentRef, err)
	}
	currentGrant, err := f.store.GetArtifactRefV2Grant(grant.ID)
	if err != nil || currentGrant.Status != "active" {
		t.Fatalf("revoked actor mutated grant: %#v %v", currentGrant, err)
	}
}
