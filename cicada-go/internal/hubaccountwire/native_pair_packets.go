package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func nativePairOperation(op string) bool { return NativePairHTTPPath(op) != "" }

func nativePairRequestParts(body any) (op, format string, c NativePairRequestContext, token, proof []byte) {
	switch v := dereference(body).(type) {
	case NativePairBootstrapPrepare:
		return OperationNativePairBootstrapPrepare, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case NativePairBootstrapComplete:
		return OperationNativePairBootstrapComplete, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case NativePairConsentPrepare:
		return OperationNativePairConsentPrepare, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case NativePairConsentComplete:
		return OperationNativePairConsentComplete, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case NativePairSlotReject:
		return OperationNativePairSlotReject, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case NativePairRevoke:
		return OperationNativePairRevoke, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case NativePairStatusRequest:
		return OperationNativePairStatus, v.Format, v.Context, v.SessionToken, nil
	case NativePairReconcileRequest:
		return OperationNativePairReconcile, v.Format, v.Context, nil, nil
	}
	return
}

func nativePairMetadata(body any) (operation, id, owner, device string, epoch uint64, err error) {
	op, _, c, _, _ := nativePairRequestParts(body)
	if op == "" {
		return "", "", "", "", 0, ErrInvalid
	}
	return op, c.RequestID, c.OwnerID, c.DeviceID, HandshakeEpoch, nil
}

func nativePairContextScope(c NativePairRequestContext, s e2ee.OwnerAppNodeScope) bool {
	return c.Origin == s.Origin && c.HubID == s.HubID && c.AccountID == s.AccountID && c.OwnerID == s.OwnerID && c.DeviceID == s.DeviceID &&
		c.AccountSessionID == s.AccountSessionID && c.AccountEpoch == s.AccountEpoch && c.DeviceEpoch == s.DeviceEpoch && c.ClientSessionEpoch == s.ClientSessionEpoch
}

func validateNativePairRequest(body any, hub HubIdentity, now time.Time) error {
	op, format, c, token, raw := nativePairRequestParts(body)
	if op == "" || format != NativePairFormat || c.HubID != hub.HubID || validateOrigin(c.Origin) != nil || !validID(c.AccountID) || !validID(c.OwnerID) ||
		!validDeviceID(c.DeviceID) || !nativePairToken(c.AccountSessionID) || !nativePairPositive(c.AccountEpoch) || !nativePairPositive(c.DeviceEpoch) || !nativePairPositive(c.ClientSessionEpoch) ||
		!isHex(c.RequestID, RequestIDBytes) || len(c.ClientNonce) != NonceBytes || validateRecent(c.IssuedAt, now, MaxSessionRequestLifetime) != nil {
		return ErrInvalid
	}
	if purpose := NativePairOwnerPurpose(op); purpose != "" {
		var p e2ee.OwnerNativePairProof
		if len(token) != MaxSessionTokenBytes || decodeCanonical(raw, e2ee.MaxOwnerNativePairProofBytes, &p) != nil ||
			!nativePairContextScope(c, p.Claims.Scope.Actor) || p.Claims.RequestID != c.RequestID || p.Claims.Nonce != hex.EncodeToString(c.ClientNonce) || p.Claims.IssuedAt != c.IssuedAt {
			return ErrInvalid
		}
		if _, err := e2ee.VerifyOwnerNativePair(p.Claims.Scope.Actor.OwnerPublic, raw, purpose, now); err != nil {
			return ErrInvalid
		}
		if purpose == e2ee.OwnerNativePairBootstrapPreview {
			if ValidateNativePairBootstrapPreviewScope(p.Claims.Scope, hub) != nil {
				return ErrInvalid
			}
		} else if ValidateNativePairScope(p.Claims.Scope, hub) != nil {
			return ErrInvalid
		}
		if purpose == e2ee.OwnerNativePairRevoke && ValidateNativePairRevokeTarget(p.Claims) != nil {
			return ErrInvalid
		}

	}
	switch v := dereference(body).(type) {
	case NativePairConsentComplete:
		var g e2ee.OwnerLinkKeyGrant
		if decodeCanonical(v.GroupKeyProof, 16*1024, &g) != nil || g.OwnerID != c.OwnerID || g.LinkID != "group-endpoint-key-grant:v1" || g.Side != e2ee.OwnerLinkGrantSideSource {
			return ErrInvalid
		}
	case NativePairStatusRequest:
		if !isHex(v.PairID, RequestIDBytes) || len(token) != 0 && len(token) != MaxSessionTokenBytes {
			return ErrInvalid
		}
	case NativePairReconcileRequest:
		p, err := nativePairOriginal(v.OriginalPacket)
		if err != nil || (!isHex(v.PairID, RequestIDBytes) && !(v.PairID == "" && p.Packet.Route.Operation == OperationNativePairBootstrapPrepare)) || p.Packet.Route.HubID != c.HubID || p.Packet.Route.OwnerID != c.OwnerID || p.Packet.Route.DeviceID != c.DeviceID {
			return ErrInvalid
		}
	}
	return nil
}

func nativePairOriginal(raw []byte) (Packet, error) {
	if len(raw) == 0 || len(raw) > MaxNativePairOriginalBytes {
		return Packet{}, ErrInvalid
	}
	p, err := DecodePacket(raw)
	if err != nil || p.Packet.Route.Direction != clientwire.DirectionRequest || !nativePairOperation(p.Packet.Route.Operation) || p.Packet.Route.Operation == OperationNativePairReconcile {
		return Packet{}, ErrInvalid
	}
	return p, nil
}

func validateNativePairDevice(body any, device e2ee.PublicIdentity) error {
	op, _, _, _, raw := nativePairRequestParts(body)
	if NativePairOwnerPurpose(op) != "" {
		var p e2ee.OwnerNativePairProof
		if decodeCanonical(raw, e2ee.MaxOwnerNativePairProofBytes, &p) != nil || !reflect.DeepEqual(p.Claims.Scope.Actor.DevicePublic, device) {
			return ErrInvalid
		}
	} else if v, ok := dereference(body).(NativePairReconcileRequest); ok {
		p, err := nativePairOriginal(v.OriginalPacket)
		if err != nil || !reflect.DeepEqual(p.SenderPublicIdentity, device) {
			return ErrInvalid
		}
	} else if op != OperationNativePairStatus {
		return ErrInvalid
	}
	return nil
}

func nativePairStateKnown(s NativePairState) bool {
	switch s {
	case NativePairPrepared, NativePairWaitingJoin, NativePairWaitingConsent, NativePairActive, NativePairExpired, NativePairRevoked:
		return true
	}
	return false
}

func nativePairSlotStateKnown(s NativePairSlotState) bool {
	switch s {
	case NativePairSlotReserved, NativePairSlotJoinedZero, NativePairSlotCandidateReady, NativePairSlotConsentRecorded, NativePairSlotActive, NativePairSlotRejected:
		return true
	}
	return false
}

func validateNativePairResponse(body any, r clientwire.Route) error {
	if !nativePairOperation(r.Operation) {
		return ErrInvalid
	}
	switch v := dereference(body).(type) {
	case NativePairRejectionFence:
		if !nativePairKnownMutation(r.Operation) || v.Operation != r.Operation || v.Format != NativePairFormat || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) || !isHex(v.PairID, RequestIDBytes) || v.State != "REJECTED_FENCED" || !v.NoEffect || !nativePairToken(v.ErrorCode) || len(v.ErrorCode) > 64 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	case NativePairBootstrapFence:
		if r.Operation != OperationNativePairBootstrapPrepare || v.Operation != r.Operation || v.Format != NativePairFormat || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) || v.State != "REJECTED_FENCED" || !v.NoEffect || !nativePairToken(v.ErrorCode) || len(v.ErrorCode) > 64 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	case NativePairBootstrapChallenge:
		if r.Operation != OperationNativePairBootstrapPrepare || v.Format != NativePairFormat || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) ||
			v.Scope.Actor.HubID != r.HubID || v.Scope.Actor.OwnerID != r.OwnerID || v.Scope.Actor.DeviceID != r.DeviceID || v.Scope.Actor.DevicePublic.ID != r.SenderKeyID ||
			v.Bootstrap.PrepareRequestID != r.OperationID || v.Bootstrap.PreparePacketDigest != v.RequestPacketDigest || validateCanonicalTime(v.ProofExpiresAt) != nil || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	case NativePairPlanChallenge:
		s := v.Plan.Scope.Actor
		if r.Operation != OperationNativePairConsentPrepare || v.Format != NativePairFormat || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) ||
			s.HubID != r.HubID || s.OwnerID != r.OwnerID || s.DeviceID != r.DeviceID || s.DevicePublic.ID != r.SenderKeyID || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	case NativePairResult:
		if r.Operation == OperationNativePairReconcile || v.Format != NativePairFormat || v.Operation != r.Operation || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) ||
			validateCanonicalTime(v.ObservedAt) != nil || !nativePairPositive(v.ControlRevision) || !isHex(v.PairID, RequestIDBytes) || !nativePairStateKnown(v.State) ||
			!nativePairSlotStateKnown(v.SlotAState) || !nativePairSlotStateKnown(v.SlotBState) || validateCanonicalTime(v.PeerExpiresAt) != nil {
			return ErrInvalid
		}
		if v.Outcome != "COMPLETED" && v.Outcome != "REJECTED_FENCED" && !(r.Operation == OperationNativePairStatus && v.Outcome == "READ_EXPIRED") {
			return ErrInvalid
		}
		if (v.Outcome == "COMPLETED") != (v.ErrorCode == "") || len(v.ErrorCode) > 64 || v.Budget.RootAsksUsed > 4 || v.Budget.RepliesUsed > 4 || v.Budget.MessagesUsed > 8 || v.Budget.CiphertextBytesUsed > 1024*1024 {
			return ErrInvalid
		}
	case NativePairReconciled:
		if r.Operation != OperationNativePairReconcile || v.Format != NativePairFormat || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) || (!isHex(v.PairID, RequestIDBytes) && !(v.PairID == "" && v.OriginalOperation == OperationNativePairBootstrapPrepare && v.State == "REJECTED_FENCED")) ||
			!nativePairOperation(v.OriginalOperation) || v.OriginalOperation == OperationNativePairReconcile || !isHex(v.OriginalRequestID, RequestIDBytes) || !isHex(v.OriginalPacketDigest, 32) ||
			(v.State != "COMPLETED" && v.State != "REJECTED_FENCED" && !(v.OriginalOperation == OperationNativePairStatus && v.State == "READ_EXPIRED")) || len(v.ReceiptPacket) > MaxNativePairReceiptBytes ||
			((v.State == "COMPLETED" || v.State == "REJECTED_FENCED") != (len(v.ReceiptPacket) > 0)) || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > maxBodyForOperation(r.Operation) {
		return ErrInvalid
	}
	return nil
}

func nativePairKnownMutation(op string) bool {
	switch op {
	case OperationNativePairBootstrapComplete, OperationNativePairSlotReject, OperationNativePairConsentPrepare, OperationNativePairConsentComplete, OperationNativePairRevoke:
		return true
	}
	return false
}

func nativePairClaimsPairID(c e2ee.OwnerNativePairClaims) string {
	switch c.Purpose {
	case e2ee.OwnerNativePairBootstrapCommit:
		if c.Bootstrap != nil {
			return c.Bootstrap.PairID
		}
	case e2ee.OwnerNativePairConsentPreview, e2ee.OwnerNativePairSlotConsent:
		if c.Consent != nil {
			return c.Consent.PairID
		}
	case e2ee.OwnerNativePairSlotReject:
		if c.Reject != nil {
			return c.Reject.PairID
		}
	case e2ee.OwnerNativePairRevoke:
		if c.Revoke != nil {
			return c.Revoke.PairID
		}
	}
	return ""
}

// Call after opening this fence against the original pinned Hub request route.
// Original DTO and ciphertext are the exact pair retained in the local outbox.
func ValidateNativePairRejectionTarget(v NativePairRejectionFence, originalBody any, original []byte) error {
	op, _, ctx, _, rawProof := nativePairRequestParts(originalBody)
	p, err := nativePairOriginal(original)
	if err != nil || !nativePairKnownMutation(op) || p.Packet.Route.Operation != op || p.Packet.Route.OperationID != ctx.RequestID || p.Packet.Route.OwnerID != ctx.OwnerID || p.Packet.Route.DeviceID != ctx.DeviceID || p.Packet.Route.HubID != ctx.HubID || p.Packet.Route.SessionEpoch != HandshakeEpoch || validateNativePairResponse(v, p.Packet.Route) != nil || v.RequestPacketDigest != NativePairPacketDigest(original) || validateNativePairDevice(originalBody, p.SenderPublicIdentity) != nil {
		return ErrInvalid
	}
	var proof e2ee.OwnerNativePairProof
	if decodeCanonical(rawProof, e2ee.MaxOwnerNativePairProofBytes, &proof) != nil {
		return ErrInvalid
	}
	c, err := e2ee.VerifyOwnerNativePair(proof.Claims.Scope.Actor.OwnerPublic, rawProof, NativePairOwnerPurpose(op), time.Time{})
	if err != nil || !nativePairContextScope(ctx, c.Scope.Actor) || c.RequestID != ctx.RequestID || c.Nonce != hex.EncodeToString(ctx.ClientNonce) || c.IssuedAt != ctx.IssuedAt || nativePairClaimsPairID(c) != v.PairID {
		return ErrInvalid
	}
	return nil
}

// Recovery always binds the exact original. This validates a diagnostic target,
// not current authority or whether a server has durably fenced it.
func ValidateNativePairReconcileTarget(v NativePairReconciled, pairID string, original []byte) error {
	p, err := nativePairOriginal(original)
	unknownPrepare := pairID == "" && p.Packet.Route.Operation == OperationNativePairBootstrapPrepare
	if err != nil || (!unknownPrepare && v.PairID != pairID) || (unknownPrepare && !isHex(v.PairID, RequestIDBytes) && !(v.PairID == "" && v.State == "REJECTED_FENCED")) || v.OriginalOperation != p.Packet.Route.Operation || v.OriginalRequestID != p.Packet.Route.OperationID || v.OriginalPacketDigest != NativePairPacketDigest(original) {
		return ErrInvalid
	}
	return nil
}

func NativePairPacketDigest(raw []byte) string {
	h := sha256.Sum256(append([]byte("cicada/native-pair/packet/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

// Large diagnostic frames use an explicit new-operation decoder. The legacy
// DecodePacket bound is unchanged and this entry rejects every legacy operation.
func DecodeNativePairPacket(raw []byte) (Packet, error) {
	p, err := decodePacketWithLimit(raw, MaxNativePairReconcilePacketBytes)
	if err != nil || !nativePairOperation(p.Packet.Route.Operation) {
		return Packet{}, ErrInvalid
	}
	return p, nil
}

func decodePacketForOperation(raw []byte, expected string) (Packet, error) {
	if ownerEndpointGroupsOperation(expected) {
		return DecodeOwnerEndpointGroupsPacket(raw)
	}
	if localDomainOperation(expected) {
		return DecodeLocalDomainPacket(raw)
	}
	if nativePairOperation(expected) {
		return DecodeNativePairPacket(raw)
	}
	return DecodePacket(raw)
}

func outerLimitForRoute(r clientwire.Route) int {
	if appNodeScopedOperation(r.Operation) {
		return appNodeScopedOuterLimit(r.Operation)
	}

	if ownerEndpointGroupsOperation(r.Operation) {
		if r.Operation == OperationOwnerEndpointGroupsReconcile {
			return MaxOwnerEndpointGroupsReconcilePacketBytes
		}
		if r.Direction == clientwire.DirectionRequest {
			return MaxOwnerEndpointGroupsOriginalBytes
		}
		return MaxOwnerEndpointGroupsPacketBytes
	}
	if localDomainOperation(r.Operation) {
		if r.Operation == OperationLocalDomainReconcile {
			return MaxLocalDomainReconcilePacketBytes
		}
		if r.Direction == clientwire.DirectionRequest {
			return MaxLocalDomainOriginalBytes
		}
		return MaxLocalDomainPacketBytes
	}
	if !nativePairOperation(r.Operation) {
		return appNodeOuterLimit(r.Operation)
	}
	if r.Operation == OperationNativePairReconcile {
		return MaxNativePairReconcilePacketBytes
	}
	if r.Direction == clientwire.DirectionRequest {
		return MaxNativePairOriginalBytes
	}
	return MaxNativePairPacketBytes
}
