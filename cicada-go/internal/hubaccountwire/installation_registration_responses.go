package hubaccountwire

import (
	"encoding/base64"
	"encoding/json"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const installationResponseAAD = "cicada/installation-registration/response-aad/v1\x00"

func installationResponseSizeForPlain(p InstallationResponsePacket, trusted HubIdentity, plaintextBytes int) (int, error) {
	n, err := e2ee.InstallationSealedEnvelopeSize(trusted.Public, plaintextBytes)
	if err != nil {
		return 0, ErrInvalid
	}
	b, err := json.Marshal(installationResponseHeader(p))
	if err != nil {
		return 0, ErrInvalid
	}
	return len(b) - len("null") + 2 + base64.StdEncoding.EncodedLen(n), nil
}

// InstallationResponsePlaintextBudget lets H2 encode each row once, accumulate
// JSON bytes/commas and reserve bounded cursor bytes, then perform PQ Seal once.
// page_size is a count ceiling, not a promise that all rows fit this byte cap.
func InstallationResponsePlaintextBudget(trusted HubIdentity, original []byte) (int, error) {
	var request InstallationPacket
	if installationCanonical(original, &request, MaxInstallationReconcilePacketBytes) != nil || validateInstallationHeader(request, trusted) != nil {
		return 0, ErrInvalid
	}
	p := InstallationResponsePacket{Format: InstallationPacketFormat, Version: 1, Operation: request.Operation, RequestID: installationRequestID(request), RequestPacketDigest: e2ee.InstallationPacketDigest(original), ReceiverKeyID: request.SenderPublic.ID}
	limit := installationResponseLimit(request.Operation)
	lo, hi := 0, limit
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		n, err := installationResponseSizeForPlain(p, trusted, mid)
		if err != nil {
			return 0, err
		}
		if n <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo, nil
}

func InstallationResponseEncodedSize(trusted HubIdentity, original []byte, body any) (int, error) {
	var request InstallationPacket
	if installationCanonical(original, &request, MaxInstallationReconcilePacketBytes) != nil || validateInstallationHeader(request, trusted) != nil {
		return 0, ErrInvalid
	}
	p := InstallationResponsePacket{Format: InstallationPacketFormat, Version: 1, Operation: request.Operation, RequestID: installationRequestID(request), RequestPacketDigest: e2ee.InstallationPacketDigest(original), ReceiverKeyID: request.SenderPublic.ID}
	if validateInstallationResponse(body, p) != nil {
		return 0, ErrInvalid
	}
	b, err := json.Marshal(body)
	if err != nil {
		return 0, ErrInvalid
	}
	return installationResponseSizeForPlain(p, trusted, len(b))
}

func installationResponseHeader(p InstallationResponsePacket) InstallationResponsePacket {
	p.Packet = nil
	return p
}

func installationResponseLimit(operation string) int {
	if operation == OperationInstallationReconcile {
		return MaxInstallationReconcilePacketBytes
	}
	return MaxInstallationReceiptBytes
}

func installationResponseAADBytes(p InstallationResponsePacket, trusted HubIdentity) ([]byte, error) {
	fp, err := HubFingerprint(trusted)
	if err != nil {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(struct {
		Header         InstallationResponsePacket `json:"header"`
		HubFingerprint string                     `json:"hub_fingerprint"`
	}{installationResponseHeader(p), fp})
	if err != nil {
		return nil, ErrInvalid
	}
	return append([]byte(installationResponseAAD), b...), nil
}

func validateInstallationResponse(body any, p InstallationResponsePacket) error {
	valid := false
	match := func(id, digest string) bool { return id == p.RequestID && digest == p.RequestPacketDigest }
	switch v := installationBodyValue(body).(type) {
	case InstallationStartResult:
		valid = p.Operation == OperationInstallationStart && v.Format == InstallationFormat && match(v.RequestID, v.RequestPacketDigest) && v.State == InstallationPending && isHex(v.AttemptID, RequestIDBytes) && isHex(v.CandidateDigest, 32) && validateCanonicalTime(v.ExpiresAt) == nil && len(v.Selector) <= 32 &&
			v.AdmissionChallenge.Header.Nonce == nil && v.SubjectChallenge.Header.Nonce == nil && len(v.AdmissionChallenge.Packet) > 0 && len(v.SubjectChallenge.Packet) > 0
	case e2ee.InstallationPossession:
		valid = p.Operation == OperationInstallationProve && isHex(v.CandidateDigest, 32) && isHex(v.ChallengeID, RequestIDBytes) && isHex(v.StartPacketDigest, 32) && v.ProveRequestID == p.RequestID && validateCanonicalTime(v.VerifiedAt) == nil
	case InstallationOwnerChallenge:
		valid = p.Operation == OperationOwnerInstallationPrepare && v.Format == InstallationFormat && match(v.RequestID, v.RequestPacketDigest) && e2ee.ValidateInstallationApproval(v.Approval, v.Candidate) == nil
	case InstallationAccessChallenge:
		valid = p.Operation == OperationOwnerAppAccessPrepare && v.Format == InstallationFormat && match(v.RequestID, v.RequestPacketDigest)
	case InstallationAccessResult:
		valid = (p.Operation == OperationOwnerAppAccessComplete || p.Operation == OperationOwnerAppAccessRevoke) && v.Format == InstallationFormat && v.Operation == p.Operation && match(v.RequestID, v.RequestPacketDigest) && validateCanonicalTime(v.ObservedAt) == nil &&
			(v.Outcome == InstallationCompleted || v.Outcome == InstallationRejectedFenced) && (v.Outcome == InstallationCompleted) == (v.ErrorCode == "") && len(v.ErrorCode) <= 64
	case InstallationResult:
		valid = validateInstallationResult(v, p)
	case InstallationApproved:
		valid = (p.Operation == OperationOwnerInstallationComplete || p.Operation == OperationInstallationPoll) && validateInstallationResult(v.Result, p) && v.Result.AttemptState == InstallationOwnerApproved && len(v.OwnerProof) > 0 && len(v.OwnerProof) <= e2ee.MaxInstallationProofBytes && len(v.TrustCapsule) > 0 && len(v.TrustCapsule) <= MaxInstallationPacketBytes
	case InstallationConnectionsSnapshot:
		valid = p.Operation == OperationOwnerConnectionsRead && v.Format == InstallationFormat && match(v.RequestID, v.RequestPacketDigest) && installationPositive(v.SnapshotRevision) && (v.OwnParent == nil || ValidateInstallationParent(*v.OwnParent) == nil) &&
			len(v.Parents)+len(v.Nodes)+len(v.Pairs) <= MaxInstallationPageSize && len(v.Grants) <= MaxInstallationEffectiveGrants && len(v.NextCursor) <= 512 && validateCanonicalTime(v.ObservedAt) == nil
	case InstallationReconciled:
		valid = p.Operation == OperationInstallationReconcile && v.Format == InstallationFormat && match(v.RequestID, v.RequestPacketDigest) && InstallationHTTPPath(v.OriginalOperation) != "" && v.OriginalOperation != OperationInstallationReconcile && isHex(v.OriginalRequestID, RequestIDBytes) && isHex(v.OriginalPacketDigest, 32) && validateCanonicalTime(v.ObservedAt) == nil
		if valid {
			valid = (v.State == InstallationCompleted || v.State == InstallationRejectedFenced) && len(v.ReceiptPacket) > 0 && len(v.ReceiptPacket) <= MaxInstallationReceiptBytes || v.State == InstallationReadExpired && InstallationIsRead(v.OriginalOperation) && len(v.ReceiptPacket) == 0
		}
	}
	if !valid {
		return ErrInvalid
	}
	return nil
}

func validateInstallationResult(v InstallationResult, p InstallationResponsePacket) bool {
	if v.Format != InstallationFormat || v.Operation != p.Operation || v.RequestID != p.RequestID || v.RequestPacketDigest != p.RequestPacketDigest || !installationPositive(v.Revision) || validateCanonicalTime(v.ObservedAt) != nil || len(v.ErrorCode) > 64 || len(v.Grants) > MaxInstallationEffectiveGrants {
		return false
	}
	switch v.AttemptState {
	case InstallationPending, InstallationOwnerApproved, InstallationRegistered, InstallationExpired, InstallationRevoked, InstallationRejectedFenced:
	default:
		return false
	}
	if v.Outcome != InstallationCompleted && v.Outcome != InstallationRejectedFenced && !(InstallationIsRead(p.Operation) && v.Outcome == InstallationReadExpired) {
		return false
	}
	if v.Outcome == InstallationRejectedFenced && InstallationIsRead(p.Operation) {
		return false
	}
	if (v.Outcome == InstallationCompleted) != (v.ErrorCode == "") {
		return false
	}
	if v.Parent != nil && ValidateInstallationParent(*v.Parent) != nil {
		return false
	}
	if v.AttemptState == InstallationRegistered && (v.Parent == nil || v.Parent.State != InstallationRegistered || v.Subject == nil || v.Subject.State != InstallationRegistered) {
		return false
	}
	return true
}

func SealInstallationResponse(hub *e2ee.Identity, trusted HubIdentity, original []byte, body any) ([]byte, error) {
	var request InstallationPacket
	if hub == nil || !reflect.DeepEqual(hub.Public(), trusted.Public) || installationCanonical(original, &request, MaxInstallationReconcilePacketBytes) != nil || validateInstallationHeader(request, trusted) != nil {
		return nil, ErrInvalid
	}
	p := InstallationResponsePacket{Format: InstallationPacketFormat, Version: 1, Operation: request.Operation, RequestID: installationRequestID(request), RequestPacketDigest: e2ee.InstallationPacketDigest(original), ReceiverKeyID: request.SenderPublic.ID}
	if validateInstallationResponse(body, p) != nil {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(body)
	if err != nil || len(b) > installationResponseLimit(p.Operation) {
		return nil, ErrInvalid
	}
	defer clear(b)
	aad, err := installationResponseAADBytes(p, trusted)
	if err != nil {
		return nil, err
	}
	p.Packet, err = e2ee.Seal(hub, request.SenderPublic, b, aad, 1)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > installationResponseLimit(p.Operation) {
		return nil, ErrInvalid
	}
	return raw, nil
}

func OpenInstallationResponse(recipient *e2ee.Identity, trusted HubIdentity, original, raw []byte, out any) error {
	var request InstallationPacket
	var response InstallationResponsePacket
	if recipient == nil || installationCanonical(original, &request, MaxInstallationReconcilePacketBytes) != nil || validateInstallationHeader(request, trusted) != nil ||
		!reflect.DeepEqual(recipient.Public(), request.SenderPublic) || installationCanonical(raw, &response, installationResponseLimit(request.Operation)) != nil || response.Format != InstallationPacketFormat || response.Version != 1 ||
		response.Operation != request.Operation || response.RequestID != installationRequestID(request) || response.RequestPacketDigest != e2ee.InstallationPacketDigest(original) || response.ReceiverKeyID != recipient.Public().ID || len(response.Packet) == 0 {
		return ErrInvalid
	}
	aad, err := installationResponseAADBytes(response, trusted)
	if err != nil {
		return err
	}
	plain, seq, err := e2ee.Open(recipient, trusted.Public, response.Packet, aad)
	if err != nil || seq != 1 {
		clear(plain)
		return ErrInvalid
	}
	defer clear(plain)
	if installationCanonical(plain, out, installationResponseLimit(request.Operation)) != nil || validateInstallationResponse(out, response) != nil {
		return ErrInvalid
	}
	return nil
}
