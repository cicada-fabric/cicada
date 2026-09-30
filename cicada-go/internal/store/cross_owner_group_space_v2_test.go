package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// The two synthetic Endpoint owners start in separate Groups. SQL enrollment
// below stands in for already verified Network Owner Join; the actual tested
// v40 admission, Endpoint consent, key proofs and Board Guard are live Store
// APIs with accepted, route-bound encrypted Client requests.
func TestCrossOwnerGroupAdmissionJoinAndDualKeyBoard(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, false)
	s := f.base.store
	group, err := s.GetGroup(f.base.source.groupID)
	if err != nil {
		t.Fatal(err)
	}
	network, err := s.CreateNetwork(Network{HubID: f.base.hubID, OwnerID: f.base.source.ownerID, Name: "synthetic shared Network"})
	if err != nil {
		t.Fatal(err)
	}
	for _, groupID := range []string{f.base.source.groupID, f.base.target.groupID} {
		if _, err := s.db.Exec(`UPDATE groups SET context_policy='group_scoped' WHERE id=?`, groupID); err != nil {
			t.Fatal(err)
		}
		g, err := s.GetGroup(groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.PrepareGroupNetworkMapping(groupID, network.ID, "synthetic reviewed mapping", g.Version); err != nil {
			t.Fatal(err)
		}
		if err := s.ApproveGroupNetworkMapping(groupID, network.ID, g.Version); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	for _, endpointID := range []string{f.base.source.endpointID, f.base.target.endpointID} {
		ep, err := s.GetEndpointV2(endpointID)
		if err != nil {
			t.Fatal(err)
		}
		owner := f.base.source.ownerID
		if endpointID == f.base.target.endpointID {
			owner = f.base.target.ownerID
		}
		if _, err := s.db.Exec(`UPDATE fabric_endpoints SET owner=? WHERE id=?`, owner, endpointID); err != nil {
			t.Fatal(err)
		}
		stamp := now()
		if _, err := s.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("nm"), network.ID, ep.PrincipalID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,?,0,?,?)`, network.ID, endpointID, endpointID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetEndpointGroupMembership(endpointID, ep.GroupID); errors.Is(err, ErrEndpointGroupNotFound) {
			if _, err := s.JoinEndpointGroup(endpointID, ep.GroupID); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	sourceEndpoint, err := s.GetEndpointV2(f.base.source.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	sourceMembership, err := s.GetMembershipByPrincipalGroup(sourceEndpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateMembershipAuthorization(sourceMembership.ID, sourceMembership.Roles,
		[]string{"space.read", "space.write", "space.moderate"}, sourceMembership.Authorization, sourceMembership.Version); err != nil {
		t.Fatal(err)
	}
	group, err = s.GetGroup(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	grantV1, err := s.PreviewGroupEndpointKeyGrant(f.base.source.ownerID, group.ID, sourceEndpoint.ID,
		f.sourceOwner.ownerKeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuedV1, err := time.Parse(time.RFC3339Nano, grantV1.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresV1, err := time.Parse(time.RFC3339Nano, grantV1.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proofV1, err := f.sourceOwner.identity.SignOwnerLinkKeyGrant(f.base.source.ownerID,
		GroupEndpointKeyGrantOperation, grantV1.Digest, grantV1.CandidateBindingDigest,
		uint64(grantV1.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedV1, expiresV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptGroupEndpointKeyGrant(f.base.source.ownerID, group.ID, sourceEndpoint.ID,
		f.sourceOwner.ownerKeyID, proofV1); err != nil {
		t.Fatal(err)
	}

	sequence := map[string]uint64{}
	accept := func(owner, device, route string) string {
		t.Helper()
		sequence[owner]++
		registered, err := s.GetClientDevice(owner, device)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(NewID("synthetic_cipher")))
		request, err := s.AcceptClientRequest(AcceptClientRequestInput{OwnerID: owner, DeviceID: device,
			SessionEpoch: registered.SessionEpoch, Sequence: sequence[owner], OperationID: NewID("synthetic_op"),
			RouteOperation: route, CiphertextDigest: hex.EncodeToString(digest[:])})
		if err != nil {
			t.Fatal(err)
		}
		return request.Request.ID
	}
	admitRequest := accept(f.base.source.ownerID, f.sourceOwner.clientDeviceID, CrossOwnerMemberAdmitOperation)
	if _, err := s.AdmitCrossOwnerGroupMemberForClientRequest(admitRequest, f.base.source.ownerID, group.ID,
		f.base.target.endpointID, []string{"space.write"}, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), group.Revision, 0); !errors.Is(err, ErrCrossOwnerGroupDenied) {
		t.Fatalf("write without read was accepted: %v", err)
	}
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	admission, err := s.AdmitCrossOwnerGroupMemberForClientRequest(admitRequest, f.base.source.ownerID, group.ID,
		f.base.target.endpointID, []string{"space.read"}, expires, group.Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	targetBinding, err := s.GetSessionBindingForEndpoint(f.base.target.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	joinRequest := accept(f.base.target.ownerID, f.targetOwner.clientDeviceID, CrossOwnerEndpointJoinOperation)
	consent, err := s.ConsentCrossOwnerGroupJoinForClientRequest(joinRequest, f.base.target.ownerID,
		admission.ID, targetBinding.ID, targetBinding.Epoch, true)
	if err != nil || consent.State != "ACTIVE" {
		t.Fatalf("Endpoint Owner join consent: %+v %v", consent, err)
	}
	if err := s.CheckCrossOwnerGroupJoin(f.base.target.ownerID, f.base.target.endpointID, group.ID,
		targetBinding.NodeID, targetBinding.ID, targetBinding.Epoch); err != nil {
		t.Fatal(err)
	}
	rotated, err := s.RotateAndJoinEndpointGroupCrossOwner(f.base.target.ownerID, f.base.target.endpointID, group.ID,
		targetBinding.NodeID, targetBinding.ID, targetBinding.Epoch, NewID("credential"), targetBinding.LeaseOwner,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil || rotated.Epoch != targetBinding.Epoch+1 {
		t.Fatalf("atomic cross Owner join: %+v %v", rotated, err)
	}
	if err := s.CheckCrossOwnerGroupJoin(f.base.target.ownerID, f.base.target.endpointID, group.ID,
		targetBinding.NodeID, targetBinding.ID, rotated.Epoch); err != nil {
		t.Fatalf("lost response retry precheck: %v", err)
	}
	previousEpoch := rotated.Epoch
	rotated, err = s.RotateAndJoinEndpointGroupCrossOwner(f.base.target.ownerID, f.base.target.endpointID,
		group.ID, targetBinding.NodeID, targetBinding.ID, previousEpoch, NewID("retry_credential"),
		targetBinding.LeaseOwner, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil || rotated.Epoch != previousEpoch+1 {
		t.Fatalf("lost Join response retry: %+v %v", rotated, err)
	}
	// A credential rotation invalidates the old Endpoint key candidate. The
	// owner-bound Node republishes the same synthetic key for its new epoch.
	attestation, err := f.targetEndpointKey.SignEndpointKeyAttestation(f.base.target.endpointID,
		rotated.PrincipalID, rotated.NodeID, rotated.ID, rotated.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterEndpointKeyCandidate(f.base.target.endpointID, rotated.PrincipalID,
		rotated.ID, rotated.Epoch, attestation); err != nil {
		t.Fatal(err)
	}
	previewRequest := accept(f.base.target.ownerID, f.targetOwner.clientDeviceID, "space.key_manifest_v2")
	manifest, err := s.PreviewCrossOwnerGroupKeyManifestForClientRequest(previewRequest, f.base.target.ownerID,
		group.ID, f.base.target.endpointID)
	if err != nil || !manifest.CrossOwnerContextShared || manifest.HistoryIncluded || manifest.Digest == "" {
		t.Fatalf("manifest: %+v %v", manifest, err)
	}
	if _, err := s.groupSpaceTestProbe(group.ID, f.base.target.endpointID); !errors.Is(err, ErrGroupSpaceNotReady) {
		t.Fatalf("one-sided/unsigned reader ready: %v", err)
	}
	for index, item := range []struct {
		owner, device, key, route, side string
		signer                          *e2ee.Identity
		wire                            e2ee.OwnerLinkGrantSide
	}{
		{f.base.target.ownerID, f.targetOwner.clientDeviceID, f.targetOwner.ownerKeyID, CrossOwnerKeyConsentRoute, CrossOwnerKeySideEndpoint, f.targetOwner.identity, e2ee.OwnerLinkGrantSideSource},
		{f.base.source.ownerID, f.sourceOwner.clientDeviceID, f.sourceOwner.ownerKeyID, CrossOwnerKeyAdmissionRoute, CrossOwnerKeySideGroup, f.sourceOwner.identity, e2ee.OwnerLinkGrantSideTarget},
	} {
		proof, err := item.signer.SignOwnerLinkKeyGrant(item.owner, CrossOwnerGroupKeyOperation, manifest.Digest,
			manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), item.wire,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(30*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		request := accept(item.owner, item.device, item.route)
		if _, err := s.AcceptCrossOwnerGroupKeyProofForClientRequest(request, item.owner, group.ID,
			f.base.target.endpointID, item.key, item.side, proof); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if _, err := s.groupSpaceTestProbe(group.ID, f.base.target.endpointID); !errors.Is(err, ErrGroupSpaceNotReady) {
				t.Fatalf("one Owner proof enabled foreign reader: %v", err)
			}
		}
	}
	evidence, err := s.groupSpaceTestProbe(group.ID, f.base.target.endpointID)
	if err != nil || evidence.EvidenceProtocol != "cross-owner-group-key-v2" || evidence.CrossOwnerKeyStatus == nil ||
		!evidence.CrossOwnerKeyStatus.Current {
		t.Fatalf("dual proof evidence: %+v %v", evidence, err)
	}
	sourceBinding, err := s.GetSessionBindingForEndpoint(sourceEndpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	sourceMember, err := s.GetMembershipByPrincipalGroup(sourceEndpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	producer := GroupSpaceActor{Scope: NativeActorScope{PrincipalID: sourceEndpoint.PrincipalID, EndpointID: sourceEndpoint.ID,
		GroupID: group.ID, NetworkID: network.ID, MembershipID: sourceMember.ID, MembershipRevision: sourceMember.Revision,
		BindingID: sourceBinding.ID, BindingEpoch: sourceBinding.Epoch, LeaseOwner: sourceBinding.LeaseOwner},
		NodeCredentialDigest: f.sourceOwner.nodeCredential}
	targetEndpoint, err := s.GetEndpointV2(f.base.target.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	reader := GroupSpaceActor{Scope: NativeActorScope{PrincipalID: targetEndpoint.PrincipalID, EndpointID: targetEndpoint.ID,
		GroupID: group.ID, NetworkID: network.ID, MembershipID: admission.MembershipID, MembershipRevision: admission.MembershipRevision,
		BindingID: rotated.ID, BindingEpoch: rotated.Epoch, LeaseOwner: rotated.LeaseOwner},
		NodeCredentialDigest: f.targetOwner.nodeCredential}
	snapshot, err := s.PrepareGroupSpaceWrite(producer, GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "synthetic_cross_owner_board", Kind: GroupSpaceKindJournal})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Readers) != 2 {
		t.Fatalf("cross Owner reader snapshot count=%d", len(snapshot.Readers))
	}
	body := []byte("synthetic new shared Group context")
	inner, err := e2ee.SignGroupSpaceBody(f.sourceEndpointKey, GroupSpaceReaderContext(*snapshot, snapshot.Readers[0]), body)
	if err != nil {
		t.Fatal(err)
	}
	commitInput := GroupSpaceCommitInput{ReservationID: snapshot.ReservationID}
	for i, recipient := range snapshot.Readers {
		wire, err := e2ee.SealGroupSpaceReader(f.sourceEndpointKey, recipient.PublicIdentity,
			GroupSpaceReaderContext(*snapshot, recipient), inner, uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		commitInput.ReaderCiphertexts = append(commitInput.ReaderCiphertexts, GroupSpaceReaderCiphertext{
			EndpointID: recipient.EndpointID, KeyID: recipient.KeyID, Wire: wire})
	}
	record, err := s.CommitGroupSpaceWrite(producer, commitInput)
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.GetGroupSpace(reader, GroupSpaceGetInput{GroupID: group.ID, RecordID: record.Snapshot.RecordID})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _, err := e2ee.OpenGroupSpaceReader(f.targetEndpointKey, read.Snapshot.Producer.PublicIdentity,
		read.Snapshot.Producer.PublicIdentity, GroupSpaceReaderContext(read.Snapshot, read.Snapshot.Readers[0]),
		read.ReaderCiphertext.Wire)
	if err != nil || string(plaintext) != string(body) {
		t.Fatalf("cross Owner sealed board read: %q %v", plaintext, err)
	}
	// Corrupt one retained Owner signature. Metadata alone must never satisfy
	// dual proof Guard, even though the other side remains current.
	if _, err := s.db.Exec(`UPDATE cross_owner_group_key_proofs_v2 SET proof=x'00'
WHERE group_id=? AND endpoint_id=? AND signer_side='GROUP'`, group.ID, targetEndpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareGroupSpaceWrite(producer, GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "synthetic_after_proof_change", Kind: GroupSpaceKindJournal}); !errors.Is(err, ErrGroupSpaceNotReady) {
		t.Fatalf("changed foreign proof remained valid: %v", err)
	}
	if _, err := s.GetGroupSpace(reader, GroupSpaceGetInput{GroupID: group.ID, RecordID: record.Snapshot.RecordID}); !errors.Is(err, ErrGroupSpaceDenied) {
		t.Fatalf("changed Owner proof still allowed connected read: %v", err)
	}
	if _, err := s.LeaveEndpointGroup(targetEndpoint.ID, group.ID, rotated.ID, rotated.Epoch, "synthetic explicit leave"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCrossOwnerGroupJoin(f.base.target.ownerID, targetEndpoint.ID, group.ID,
		rotated.NodeID, rotated.ID, rotated.Epoch); !errors.Is(err, ErrCrossOwnerGroupDenied) {
		t.Fatalf("old consent restored an explicitly left Group: %v", err)
	}
	wrongRevokeRequest := accept(f.base.source.ownerID, f.sourceOwner.clientDeviceID, "status.snapshot")
	if _, err := s.RevokeCrossOwnerGroupAdmissionForClientRequest(wrongRevokeRequest,
		f.base.source.ownerID, admission.ID, admission.MembershipRevision); !errors.Is(err, ErrCrossOwnerGroupDenied) {
		t.Fatalf("status request revoked foreign Member: %v", err)
	}
	revokeRequest := accept(f.base.source.ownerID, f.sourceOwner.clientDeviceID, CrossOwnerMemberRevokeOperation)
	revoked, err := s.RevokeCrossOwnerGroupAdmissionForClientRequest(revokeRequest,
		f.base.source.ownerID, admission.ID, admission.MembershipRevision)
	if err != nil || revoked.State != "REVOKED" {
		t.Fatalf("Owner foreign Member revoke: %+v %v", revoked, err)
	}
	retried, err := s.RevokeCrossOwnerGroupAdmissionForClientRequest(revokeRequest,
		f.base.source.ownerID, admission.ID, admission.MembershipRevision)
	if err != nil || retried.ID != revoked.ID || retried.State != "REVOKED" {
		t.Fatalf("lost revoke response retry: %+v %v", retried, err)
	}
	if _, err := s.GetGroupSpace(reader, GroupSpaceGetInput{GroupID: group.ID, RecordID: record.Snapshot.RecordID}); err == nil {
		t.Fatal("revoked foreign member still read sealed board")
	}
	if _, err := s.groupSpaceTestProbe(group.ID, f.base.target.endpointID); !errors.Is(err, ErrGroupSpaceNotReady) && !errors.Is(err, ErrGroupSpaceDenied) {
		t.Fatalf("revoked foreign reader remained available: %v", err)
	}
	memberAfterRevoke, err := s.GetMembership(admission.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	if memberAfterRevoke.Revision <= admission.MembershipRevision {
		t.Fatal("revoke did not fence Membership revision")
	}
	readmitRequest := accept(f.base.source.ownerID, f.sourceOwner.clientDeviceID, CrossOwnerMemberAdmitOperation)
	readmitted, err := s.AdmitCrossOwnerGroupMemberForClientRequest(readmitRequest, f.base.source.ownerID,
		group.ID, targetEndpoint.ID, []string{"space.read"}, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		group.Revision, memberAfterRevoke.Revision)
	if err != nil || readmitted.ID == admission.ID || readmitted.MembershipRevision != memberAfterRevoke.Revision+1 {
		t.Fatalf("fresh CAS readmission: %+v %v", readmitted, err)
	}
	if err := s.CheckCrossOwnerGroupJoin(f.base.target.ownerID, targetEndpoint.ID, group.ID,
		rotated.NodeID, rotated.ID, rotated.Epoch); !errors.Is(err, ErrCrossOwnerGroupDenied) {
		t.Fatalf("old Join consent revived after fresh admission: %v", err)
	}
}

func (s *Store) groupSpaceTestProbe(groupID, endpointID string) (GroupSpaceEndpointEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return GroupSpaceEndpointEvidence{}, err
	}
	defer tx.Rollback()
	return groupSpaceEndpointEvidenceTx(tx, groupID, endpointID, time.Now().UTC())
}
