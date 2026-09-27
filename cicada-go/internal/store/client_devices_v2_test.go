package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func newClientDeviceFixture(t *testing.T) (*Store, *e2ee.Identity, *e2ee.Identity, *ClientDevice) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrincipal(Principal{
		ID: "owner_a", Kind: PrincipalKindHuman, OwnerID: "owner_a",
		Name: "owner_a", Status: PrincipalStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal("owner_a", owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil || hubID == "" {
		t.Fatalf("load stable Hub ID: %q %v", hubID, err)
	}
	now := time.Now().UTC()
	grant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: ownerKey.KeyID, DeviceID: "phone_a",
		DevicePublic: device.Public(), OwnerDeviceGrant: grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, owner, device, registered
}

func TestClientDeviceRegistrationRequiresLocalOwnerGrantAndStableHub(t *testing.T) {
	s, owner, device, registered := newClientDeviceFixture(t)
	if registered.State != ClientDeviceActive || registered.Version != 1 ||
		registered.SessionEpoch != 1 || registered.KeyVersion != 1 || registered.KeyFingerprint == "" {
		t.Fatalf("unexpected registered Client device: %+v", registered)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}

	newDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	unregisteredOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := unregisteredOwner.SignOwnerDeviceGrant("owner_a", "phone_b", newDevice.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: unregisteredOwner.Public().ID, DeviceID: "phone_b",
		DevicePublic: newDevice.Public(), OwnerDeviceGrant: newGrant,
	}); !errors.Is(err, ErrOwnerApprovalKeyNotFound) {
		t.Fatalf("unregistered owner key authorized a device: %v", err)
	}

	wrongHubGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_c", newDevice.Public(), "packet_hub_id",
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: owner.Public().ID, DeviceID: "phone_c",
		DevicePublic: newDevice.Public(), OwnerDeviceGrant: wrongHubGrant,
	}); err == nil {
		t.Fatal("grant using a packet-selected Hub ID was accepted")
	}

	ownerKey, err := s.GetOwnerApprovalKey("owner_a", owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeOwnerApprovalKeyLocal("owner_a", ownerKey.KeyID, ownerKey.Version); err != nil {
		t.Fatal(err)
	}
	postRevokeGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_d", newDevice.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: owner.Public().ID, DeviceID: "phone_d",
		DevicePublic: newDevice.Public(), OwnerDeviceGrant: postRevokeGrant,
	}); !errors.Is(err, ErrOwnerApprovalKeyConflict) {
		t.Fatalf("revoked owner approval key authorized a device: %v", err)
	}

	replacement, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherOwnerKey, err := s.RegisterOwnerApprovalKeyLocal("owner_a", otherOwner.Public())
	if err != nil {
		t.Fatal(err)
	}
	replacementGrant, err := otherOwner.SignOwnerDeviceGrant("owner_a", "phone_a", replacement.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: otherOwnerKey.KeyID, DeviceID: "phone_a",
		DevicePublic: replacement.Public(), OwnerDeviceGrant: replacementGrant,
	}); !errors.Is(err, ErrClientDeviceConflict) {
		t.Fatalf("same owner/device ID rebound to another public key: %v", err)
	}
	revokedDeviceDigest := sha256.Sum256([]byte("request after owner trust revocation"))
	if _, err := s.AcceptClientRequest(AcceptClientRequestInput{OwnerID: "owner_a", DeviceID: "phone_a",
		SessionEpoch: 1, Sequence: 1, OperationID: "op_after_owner_revoke",
		CiphertextDigest: hex.EncodeToString(revokedDeviceDigest[:])}); !errors.Is(err, ErrClientDeviceRevoked) {
		t.Fatalf("device authorized by revoked owner key accepted a request: %v", err)
	}
	if registered.KeyID != device.Public().ID {
		t.Fatal("fixture device key changed unexpectedly")
	}
}

func TestClientRequestAcceptanceIsAtomicIdempotentAndCachesSealedResponse(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	digestA := sha256.Sum256([]byte("verified request ciphertext A"))
	digestB := sha256.Sum256([]byte("different ciphertext"))
	input := AcceptClientRequestInput{OwnerID: "owner_a", DeviceID: "phone_a",
		SessionEpoch: 1, Sequence: 1, OperationID: "op_1", CiphertextDigest: hex.EncodeToString(digestA[:])}
	first, err := s.AcceptClientRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != ClientRequestOutcomeNew || first.Request.Status != ClientRequestProcessing || first.Request.ResponsePacket != nil {
		t.Fatalf("first acceptance should be new PROCESSING: %+v", first)
	}
	duplicate, err := s.AcceptClientRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Outcome != ClientRequestOutcomeExactRetry || duplicate.Request.ID != first.Request.ID ||
		duplicate.Request.Status != ClientRequestProcessing {
		t.Fatalf("in-flight retry changed the executing request: first=%+v duplicate=%+v", first, duplicate)
	}
	if _, err := s.AcceptClientRequest(AcceptClientRequestInput{OwnerID: input.OwnerID, DeviceID: input.DeviceID,
		SessionEpoch: 1, Sequence: 1, OperationID: "op_1", CiphertextDigest: hex.EncodeToString(digestB[:])}); !errors.Is(err, ErrClientRequestConflict) {
		t.Fatalf("same sequence with a different ciphertext was accepted: %v", err)
	}
	if completed, err := s.CompleteClientRequestWithSealedResponse(input.OwnerID, input.DeviceID, input.OperationID, []byte("opaque sealed response")); err != nil || completed.Status != ClientRequestCompleted {
		t.Fatalf("in-flight request could not complete after a concurrent retry: result=%+v err=%v", completed, err)
	}

	nextDigest := sha256.Sum256([]byte("verified request ciphertext B"))
	next := AcceptClientRequestInput{OwnerID: input.OwnerID, DeviceID: input.DeviceID,
		SessionEpoch: 1, Sequence: 2, OperationID: "op_2", CiphertextDigest: hex.EncodeToString(nextDigest[:])}
	accepted, err := s.AcceptClientRequest(next)
	if err != nil || accepted.Outcome != ClientRequestOutcomeNew {
		t.Fatalf("next request was not accepted: result=%+v err=%v", accepted, err)
	}
	sealed := []byte(`{"ciphertext":"opaque"}`)
	completed, err := s.CompleteClientRequestWithSealedResponse(next.OwnerID, next.DeviceID, next.OperationID, sealed)
	if err != nil || completed.Status != ClientRequestCompleted || !bytes.Equal(completed.ResponsePacket, sealed) {
		t.Fatalf("sealed response was not persisted with completion: result=%+v err=%v", completed, err)
	}
	retry, err := s.AcceptClientRequest(next)
	if err != nil || retry.Outcome != ClientRequestOutcomeExactRetry || retry.Request.ID != accepted.Request.ID ||
		retry.Request.Status != ClientRequestCompleted || !bytes.Equal(retry.Request.ResponsePacket, sealed) {
		t.Fatalf("completed exact retry did not return cached response: result=%+v err=%v", retry, err)
	}
	if _, err := s.CompleteClientRequestWithSealedResponse(next.OwnerID, next.DeviceID, next.OperationID, []byte("different sealed response")); !errors.Is(err, ErrClientRequestStateConflict) {
		t.Fatalf("completed response packet was replaceable: %v", err)
	}
	if _, err := s.AcceptClientRequest(AcceptClientRequestInput{OwnerID: next.OwnerID, DeviceID: next.DeviceID,
		SessionEpoch: 1, Sequence: 3, OperationID: next.OperationID, CiphertextDigest: hex.EncodeToString(nextDigest[:])}); !errors.Is(err, ErrClientRequestConflict) {
		t.Fatalf("operation ID was reused at a new sequence: %v", err)
	}
	thirdDigest := sha256.Sum256([]byte("verified request ciphertext C"))
	third := AcceptClientRequestInput{OwnerID: next.OwnerID, DeviceID: next.DeviceID,
		SessionEpoch: 1, Sequence: 3, OperationID: "op_3", CiphertextDigest: hex.EncodeToString(thirdDigest[:])}
	if _, err := s.AcceptClientRequest(third); err != nil {
		t.Fatal(err)
	}
	failed, err := s.UpdateClientRequestStatus(third.OwnerID, third.DeviceID, third.OperationID, ClientRequestFailed)
	if err != nil || failed.Status != ClientRequestFailed {
		t.Fatalf("request failure state did not persist: request=%+v err=%v", failed, err)
	}
	failedRetry, err := s.AcceptClientRequest(third)
	if err != nil || failedRetry.Outcome != ClientRequestOutcomeExactRetry || failedRetry.Request.Status != ClientRequestFailed {
		t.Fatalf("failed request retry lost durable outcome: result=%+v err=%v", failedRetry, err)
	}
	if _, err := s.UpdateClientRequestStatus(third.OwnerID, third.DeviceID, third.OperationID, ClientRequestUncertain); !errors.Is(err, ErrClientRequestStateConflict) {
		t.Fatalf("terminal request status was changed: %v", err)
	}
	if responseSeq, err := s.AllocateClientResponseSequence("owner_a", "phone_a", 1); err != nil || responseSeq != 1 {
		t.Fatalf("first durable response sequence: got %d err=%v", responseSeq, err)
	}
	if responseSeq, err := s.AllocateClientResponseSequence("owner_a", "phone_a", 1); err != nil || responseSeq != 2 {
		t.Fatalf("second durable response sequence: got %d err=%v", responseSeq, err)
	}
	rotated, err := s.AdvanceClientDeviceSessionEpoch("owner_a", "phone_a", 1)
	if err != nil || rotated.SessionEpoch != 2 || rotated.NextResponseSeq != 1 || rotated.LastRequestSeq != 0 {
		t.Fatalf("session epoch did not rotate atomically: device=%+v err=%v", rotated, err)
	}
	if _, err := s.AcceptClientRequest(input); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("old session epoch request was accepted: %v", err)
	}
	if responseSeq, err := s.AllocateClientResponseSequence("owner_a", "phone_a", 2); err != nil || responseSeq != 1 {
		t.Fatalf("response sequence did not reset under new epoch: got %d err=%v", responseSeq, err)
	}
	if _, err := s.RevokeClientDevice("owner_a", "phone_a", device.Version); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale device revoke version was accepted: %v", err)
	}
	if _, err := s.RevokeClientDevice("owner_a", "phone_a", rotated.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptClientRequest(AcceptClientRequestInput{OwnerID: "owner_a", DeviceID: "phone_a",
		SessionEpoch: 2, Sequence: 1, OperationID: "op_after_revoke", CiphertextDigest: hex.EncodeToString(digestA[:])}); !errors.Is(err, ErrClientDeviceRevoked) {
		t.Fatalf("revoked device accepted a request: %v", err)
	}
	if _, err := s.AllocateClientResponseSequence("owner_a", "phone_a", 2); !errors.Is(err, ErrClientDeviceRevoked) {
		t.Fatalf("revoked device allocated a Hub response sequence: %v", err)
	}
}

func TestClientRequestProcessingBecomesUncertainAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal("owner_a", owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{OwnerID: "owner_a",
		OwnerKeyID: ownerKey.KeyID, DeviceID: "phone_a", DevicePublic: device.Public(), OwnerDeviceGrant: grant}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("request ciphertext"))
	input := AcceptClientRequestInput{OwnerID: "owner_a", DeviceID: "phone_a", SessionEpoch: 1,
		Sequence: 1, OperationID: "op_restart", CiphertextDigest: hex.EncodeToString(digest[:])}
	first, err := s.AcceptClientRequest(input)
	if err != nil || first.Outcome != ClientRequestOutcomeNew {
		t.Fatalf("initial request acceptance failed: result=%+v err=%v", first, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	fenced, err := restarted.MarkInterruptedClientRequestsUncertain()
	if err != nil || fenced != 1 {
		t.Fatalf("startup did not fence interrupted processing request: count=%d err=%v", fenced, err)
	}
	retry, err := restarted.AcceptClientRequest(input)
	if err != nil || retry.Outcome != ClientRequestOutcomeExactRetry || retry.Request.ID != first.Request.ID ||
		retry.Request.Status != ClientRequestUncertain {
		t.Fatalf("restart allowed a duplicate dispatch or lost recovery state: result=%+v err=%v", retry, err)
	}
	status, err := restarted.GetClientRequestByOperationID("owner_a", "phone_a", "op_restart")
	if err != nil || status.Status != ClientRequestUncertain {
		t.Fatalf("uncertain request is not queryable by operation ID: result=%+v err=%v", status, err)
	}
}
