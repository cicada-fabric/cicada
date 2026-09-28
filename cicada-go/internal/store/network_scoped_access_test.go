package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A second Store represents an operator or another Hub request that commits
// revocation between actor authentication and a scoped directory read.
func TestNetworkDirectoryScopedReadRechecksAcrossStoreHandles(t *testing.T) {
	for _, operation := range []string{"membership revoke", "endpoint leave"} {
		t.Run(operation, func(t *testing.T) {
			s, owner, _, device := newClientDeviceFixture(t)
			if _, err := s.db.Exec(`UPDATE principals SET trust_domain_id='scope-domain' WHERE id='owner_a'`); err != nil {
				t.Fatal(err)
			}
			const nodeToken = "synthetic-scoped-directory-node"
			credentialDigest := nodeBindingTestCredentialDigest(nodeToken)
			codeDigest := nodeBindingTestCodeDigest("scoped-directory-code")
			bindingRequest, err := s.CreatePendingNodeDeviceBinding("node-scoped-directory",
				"synthetic directory Node", credentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); err != nil {
				t.Fatal(err)
			}
			network, err := s.CreateNetwork(Network{ID: "net-scoped-directory", HubID: bindingRequest.HubID,
				Name: "synthetic directory", OwnerID: "owner_a"})
			if err != nil {
				t.Fatal(err)
			}
			const invitation = "synthetic-scoped-directory-invitation-0001"
			grants := []string{"directory.discover", "directory.publish"}
			if err := s.IssueNetworkInvitation(network.ID, "owner_a", "owner_a", invitation,
				time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
				t.Fatal(err)
			}
			proof, err := owner.SignOwnerNetworkJoinGrant("owner_a", bindingRequest.HubID,
				network.ID, "node-scoped-directory", "native-scoped-directory",
				NetworkInvitationDigest(invitation), owner.Public().ID, grants, true,
				time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			var signed struct {
				Nonce     string `json:"nonce"`
				ExpiresAt string `json:"expires_at"`
			}
			if err := json.Unmarshal(proof, &signed); err != nil {
				t.Fatal(err)
			}
			join, err := s.AcceptNetworkJoin(AcceptNetworkJoinInput{NetworkID: network.ID,
				OwnerID: "owner_a", TrustDomainID: "scope-domain", NodeID: "node-scoped-directory",
				NativeSessionID: "native-scoped-directory", Harness: "codex", EndpointName: "directory-target",
				InvitationToken: invitation, ProofNonce: signed.Nonce,
				ProofDigest: NetworkInvitationDigest(string(proof)), ProofExpiresAt: signed.ExpiresAt,
				OwnerKeyID: owner.Public().ID, OwnerJoinProof: string(proof),
				NodeCredentialHash: credentialDigest, Grants: grants, Discoverable: true,
				CredentialHash: "synthetic-scoped-access", LeaseOwner: "scoped-lease",
				LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)})
			if err != nil {
				t.Fatal(err)
			}
			scope := NetworkAccessScope{NetworkID: network.ID, PrincipalID: join.PrincipalID,
				EndpointID: join.EndpointID, AccessSessionID: join.AccessSessionID,
				AccessEpoch: join.AccessSessionEpoch, LeaseOwner: "scoped-lease",
				MembershipID: join.MembershipID, MembershipRevision: join.MembershipRevision,
				EndpointMembershipRevision: join.EndpointRevision}
			if cards, err := s.ListNetworkDirectory(scope, 10); err != nil || len(cards) != 1 {
				t.Fatalf("current scoped directory: cards=%#v err=%v", cards, err)
			}
			if cards, err := s.ResolveNetworkDirectory(scope, "directory-target"); err != nil || len(cards) != 1 {
				t.Fatalf("current scoped resolve: cards=%#v err=%v", cards, err)
			}
			var seq int
			var dbName, dbPath string
			if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &dbName, &dbPath); err != nil || dbPath == "" {
				t.Fatal("could not locate disposable fixture database")
			}
			other, err := New(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if operation == "membership revoke" {
				err = other.RevokeNetworkMembership(network.ID, join.PrincipalID, join.MembershipRevision)
			} else {
				err = other.LeaveEndpointNetwork(network.ID, join.EndpointID, join.EndpointRevision)
			}
			if err != nil {
				t.Fatal(err)
			}
			if cards, err := s.ListNetworkDirectory(scope, 10); !errors.Is(err, ErrNetworkPermission) || len(cards) != 0 {
				t.Fatalf("stale directory read after %s: cards=%#v err=%v", operation, cards, err)
			}
			if cards, err := s.ResolveNetworkDirectory(scope, "directory-target"); !errors.Is(err, ErrNetworkPermission) || len(cards) != 0 {
				t.Fatalf("stale resolve after %s: cards=%#v err=%v", operation, cards, err)
			}
		})
	}
}

func TestNetworkScopedTaskAndRequestReadsFenceOldEnrollment(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	if err := f.store.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.GetMembershipByPrincipalGroup(f.source.principal, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles,
		[]string{"task.read", "task.claim", "task.submit", "task.verify"},
		membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
	actor := func() NativeActorScope {
		t.Helper()
		member, err := f.store.GetMembershipByPrincipalGroup(f.source.principal, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		return NativeActorScope{PrincipalID: f.source.principal, EndpointID: f.source.id,
			GroupID: f.groupID, NetworkID: networkID, MembershipID: member.ID,
			MembershipRevision: member.Revision, BindingID: f.source.binding.ID,
			BindingEpoch: f.source.binding.Epoch, LeaseOwner: f.source.binding.LeaseOwner}
	}
	oldActor := actor()
	task, err := f.store.CreateSharedTask(SharedTask{GroupID: f.groupID,
		Objective: "synthetic scoped task", AcceptanceCriteria: "current actor only"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(id string) *FabricRequest {
		t.Helper()
		created, err := f.store.CreateFabricRequest(FabricRequest{RequestID: id,
			MessageID: "msg_" + id, SenderEndpointID: f.source.id,
			SenderPrincipalID: f.source.principal, SenderGroupID: f.groupID,
			SenderBindingID: f.source.binding.ID, SenderBindingEpoch: f.source.binding.Epoch,
			ReceiverEndpointID: f.target.id, ReceiverPrincipalID: f.target.principal,
			ReceiverGroupID: f.groupID, ReceiverBindingID: f.target.binding.ID,
			ReceiverBindingEpoch: f.target.binding.Epoch, AuthorizationRef: oldActor.MembershipID,
			Body: "synthetic request", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	oldRequest := request("rq_scoped_old")
	if got, err := f.store.GetSharedTaskForActor(oldActor, task.ID, "task.read"); err != nil || got.ID != task.ID {
		t.Fatalf("current Task read: task=%#v err=%v", got, err)
	}
	if got, err := f.store.GetRelayFabricRequestForActor(oldRequest.RequestID, oldActor); err != nil || got.RequestID != oldRequest.RequestID {
		t.Fatalf("current Request read: request=%#v err=%v", got, err)
	}
	other, err := New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	member, err := other.GetNetworkMembership(networkID, f.source.principal)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.RevokeNetworkMembership(networkID, f.source.principal, member.Revision); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.GetSharedTaskForActor(oldActor, task.ID, "task.read"); !errors.Is(err, ErrNetworkPermission) || got != nil {
		t.Fatalf("revoked actor read Task: task=%#v err=%v", got, err)
	}
	if got, err := f.store.GetRelayFabricRequestForActor(oldRequest.RequestID, oldActor); !errors.Is(err, ErrNetworkPermission) || got != nil {
		t.Fatalf("revoked actor read Request: request=%#v err=%v", got, err)
	}
	if got, err := f.store.RequestFabricRequestCancellationForActor(oldRequest.RequestID,
		"revoked actor", oldActor); !errors.Is(err, ErrNetworkPermission) || got != nil {
		t.Fatalf("revoked actor cancelled Request: request=%#v err=%v", got, err)
	}
	// Synthetic fresh consent restores this source only. The target's current
	// enrollment never changed; old request snapshots must still stay stale.
	stamp := now()
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND principal_id=?`, stamp, networkID, f.source.principal); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND endpoint_id=?`, stamp, networkID, f.source.id); err != nil {
		t.Fatal(err)
	}
	newActor := actor()
	if newActor.MembershipRevision <= oldActor.MembershipRevision {
		t.Fatal("new authorization did not advance the Group membership revision")
	}
	if got, err := f.store.GetSharedTaskForActor(oldActor, task.ID, "task.read"); !errors.Is(err, ErrNetworkPermission) || got != nil {
		t.Fatalf("old actor read Task after rejoin: task=%#v err=%v", got, err)
	}
	if got, err := f.store.GetSharedTaskForActor(newActor, task.ID, "task.read"); err != nil || got.ID != task.ID {
		t.Fatalf("new actor lost current Task read: task=%#v err=%v", got, err)
	}
	if got, err := f.store.GetRelayFabricRequestForActor(oldRequest.RequestID, newActor); !errors.Is(err, ErrNetworkPermission) || got != nil {
		t.Fatalf("new actor revived old Request: request=%#v err=%v", got, err)
	}
	newRequest := request("rq_scoped_new")
	if got, err := f.store.GetRelayFabricRequestForActor(newRequest.RequestID, newActor); err != nil || got.RequestID != newRequest.RequestID {
		t.Fatalf("new actor lost current Request read: request=%#v err=%v", got, err)
	}
	if got, err := f.store.RequestFabricRequestCancellationForActor(newRequest.RequestID,
		"current actor", newActor); err != nil || got.State != FabricRequestCancelRequested {
		t.Fatalf("current actor could not cancel current Request: request=%#v err=%v", got, err)
	}
}
