package hubaccountwire

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func appNodeScopedOperation(op string) bool { return AppNodeScopedHTTPPath(op) != "" }

func appNodeScopedOuterLimit(op string) int {
	if appNodeScopedOperation(op) && op != OperationAppNodeScopedReconcile {
		return MaxAppNodeScopedMutationPacketBytes
	}
	return MaxPacketBytes
}

func appNodeScopedMetadata(body any) (operation, id, owner, device string, epoch uint64, err error) {
	var c AppNodeRequestContext
	switch v := dereference(body).(type) {
	case AppNodeScopedPrepare:
		operation, c = OperationAppNodeScopedPrepare, v.Context
	case AppNodeScopedComplete:
		operation, c = OperationAppNodeScopedComplete, v.Context
	case AppNodeScopedStatus:
		operation, c = OperationAppNodeScopedStatus, v.Context
	case AppNodeScopedCancel:
		operation, c = OperationAppNodeScopedCancel, v.Context
	case AppNodeScopedReconcile:
		operation, c = OperationAppNodeScopedReconcile, v.Context
	default:
		return "", "", "", "", 0, ErrInvalid
	}
	return operation, c.RequestID, c.OwnerID, c.DeviceID, HandshakeEpoch, nil
}

func validateAppNodeScopedRequest(body any, hub HubIdentity, now time.Time) error {
	var ctx AppNodeRequestContext
	switch v := dereference(body).(type) {
	case AppNodeScopedPrepare:
		ctx = v.Context
		var intent e2ee.OwnerAppNodeScopedPreview
		if v.Format != AppNodeScopedPrepareFormat || len(v.SessionToken) != MaxSessionTokenBytes || decodeCanonical(v.OwnerIntent, MaxAppNodeScopedProofBytes, &intent) != nil ||
			ValidateAppNodeScopedPreviewClaims(intent.Claims, hub, now) != nil || !appNodeScopedContextScope(ctx, intent.Claims.Scope) || intent.Claims.RequestID != ctx.RequestID || intent.Claims.Nonce != hex.EncodeToString(ctx.ClientNonce) || intent.Claims.IssuedAt != ctx.IssuedAt {
			return ErrInvalid
		}
		if _, err := e2ee.VerifyOwnerAppNodeScopedPreview(intent.Claims.Scope.OwnerPublic, v.OwnerIntent, now); err != nil {
			return ErrInvalid
		}
		switch v.Target.Kind {
		case AppNodeScopedTargetInitial:
			digest, err := AppNodeCodeDigest(ctx.HubID, v.Target.Code)
			normalized, normalizeErr := NormalizeAppNodeCode(v.Target.Code)
			if err != nil || normalizeErr != nil || normalized != v.Target.Code || v.Target.PreviousGrantID != "" || intent.Claims.Purpose != e2ee.OwnerAppNodeScopedPreviewPurpose || intent.Claims.CodeDigest != digest {
				return ErrInvalid
			}
		case AppNodeScopedTargetPrevious:
			if v.Target.Code != "" || intent.Claims.Purpose != e2ee.OwnerAppNodeScopedStatusPreviewPurpose || v.Target.PreviousGrantID != intent.Claims.PreviousGrantID {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case AppNodeScopedComplete:
		ctx = v.Context
		var proof e2ee.OwnerAppNodeScopedGrant
		if v.Format != AppNodeScopedCompleteFormat || len(v.SessionToken) != MaxSessionTokenBytes || decodeCanonical(v.OwnerGrant, MaxAppNodeScopedProofBytes, &proof) != nil || ValidateAppNodeScopedGrantClaims(proof.Claims, hub, now) != nil || !appNodeScopedContextScope(ctx, proof.Claims.Scope) {
			return ErrInvalid
		}
		if _, err := e2ee.VerifyOwnerAppNodeScopedGrant(proof.Claims.Scope.OwnerPublic, v.OwnerGrant, now); err != nil {
			return ErrInvalid
		}
	case AppNodeScopedStatus:
		ctx = v.Context
		if !appNodeScopedStatusTargetValid(v.Target, v.SessionToken, v.GrantID) || v.Format != AppNodeScopedStatusFormat || (v.GrantID != "" && !isHex(v.GrantID, RequestIDBytes)) || (len(v.SessionToken) != 0 && len(v.SessionToken) != MaxSessionTokenBytes) {
			return ErrInvalid
		}
	case AppNodeScopedCancel:
		ctx = v.Context
		if !appNodeScopedNodeID(v.AuthorityNodeID) || v.Format != AppNodeScopedCancelFormat || len(v.SessionToken) != MaxSessionTokenBytes || !isHex(v.GrantID, RequestIDBytes) || v.ExpectedHeadVersion > math.MaxInt64 {
			return ErrInvalid
		}
	case AppNodeScopedReconcile:
		ctx = v.Context
		if !appNodeScopedNodeID(v.AuthorityNodeID) || v.Format != AppNodeScopedReconcileFormat || (v.GrantID != "" && !isHex(v.GrantID, RequestIDBytes)) {
			return ErrInvalid
		}
		r, _, err := appNodeScopedOriginalRoute(v.OriginalKind, v.OriginalPacket)
		if err != nil || r.HubID != ctx.HubID || r.OwnerID != ctx.OwnerID || r.DeviceID != ctx.DeviceID {
			return ErrInvalid
		}
		if v.OriginalKind == AppNodeScopedOriginalClient {
			grant, _, err := ParseAppNodeScopedBusinessOperationID(r.OperationID)
			if err != nil || grant != v.GrantID {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	if !appNodeContextValid(ctx, hub, now) {
		return ErrInvalid
	}
	return nil
}

func appNodeScopedOriginalRoute(kind string, original []byte) (clientwire.Route, *e2ee.PublicIdentity, error) {
	if len(original) == 0 || len(original) > MaxAppNodeScopedOriginalBytes {
		return clientwire.Route{}, nil, ErrInvalid
	}
	var r clientwire.Route
	var pub *e2ee.PublicIdentity
	switch kind {
	case AppNodeScopedOriginalAuthority:
		p, err := DecodePacket(original)
		if err != nil {
			return r, nil, ErrInvalid
		}
		r = p.Packet.Route
		pub = &p.SenderPublicIdentity
	case AppNodeScopedOriginalClient:
		var p clientwire.Packet
		if decodeCanonical(original, MaxAppNodeScopedOriginalBytes, &p) != nil || len(p.Envelope) == 0 {
			return r, nil, ErrInvalid
		}
		r = p.Route
		if _, _, err := ParseAppNodeScopedBusinessOperationID(r.OperationID); err != nil {
			return r, nil, ErrInvalid
		}
	default:
		return r, nil, ErrInvalid
	}
	if r.Direction != clientwire.DirectionRequest || !AppNodeScopedReconcileOriginalAllowed(kind, r.Operation) {
		return r, nil, ErrInvalid
	}
	return r, pub, nil
}

func validateAppNodeScopedDevice(body any, device e2ee.PublicIdentity) error {
	switch v := dereference(body).(type) {
	case AppNodeScopedPrepare:
		var p e2ee.OwnerAppNodeScopedPreview
		if decodeCanonical(v.OwnerIntent, MaxAppNodeScopedProofBytes, &p) != nil || !reflect.DeepEqual(p.Claims.Scope.DevicePublic, device) {
			return ErrInvalid
		}
	case AppNodeScopedComplete:
		var p e2ee.OwnerAppNodeScopedGrant
		if decodeCanonical(v.OwnerGrant, MaxAppNodeScopedProofBytes, &p) != nil || !reflect.DeepEqual(p.Claims.Scope.DevicePublic, device) {
			return ErrInvalid
		}
	case AppNodeScopedReconcile:
		r, pub, err := appNodeScopedOriginalRoute(v.OriginalKind, v.OriginalPacket)
		if err != nil || r.SenderKeyID != device.ID || (pub != nil && !reflect.DeepEqual(*pub, device)) {
			return ErrInvalid
		}
	case AppNodeScopedStatus, AppNodeScopedCancel:
	default:
		return ErrInvalid
	}
	return nil
}

func validateAppNodeScopedResponse(body any, r clientwire.Route) error {
	if !appNodeScopedOperation(r.Operation) {
		return ErrInvalid
	}
	switch v := dereference(body).(type) {
	case AppNodeScopedChallenge:
		s := v.Claims.Scope
		if r.Operation != OperationAppNodeScopedPrepare || v.Format != AppNodeScopedChallengeFormat || v.RequestID != r.OperationID || s.HubID != r.HubID || s.OwnerID != r.OwnerID || s.DeviceID != r.DeviceID || s.DevicePublic.ID != r.SenderKeyID || !isHex(v.RequestPacketDigest, 32) || v.Claims.PreparePacketDigest != v.RequestPacketDigest || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	case AppNodeScopedResult:
		a := v.Authority
		s := a.Scope
		if s.Version != AppNodeScopedScopeVersion || !appNodeScopedNodeID(s.AuthorityNodeID) || r.Operation == OperationAppNodeScopedReconcile || v.Format != AppNodeScopedResultFormat || v.Operation != r.Operation || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) || s.HubID != r.HubID || s.OwnerID != r.OwnerID || s.DeviceID != r.DeviceID || s.DevicePublic.ID != r.SenderKeyID || !validID(s.AccountID) || validateOrigin(s.Origin) != nil || e2ee.ValidatePublicIdentity(s.OwnerPublic) != nil || e2ee.ValidatePublicIdentity(s.DevicePublic) != nil || s.AccountEpoch == 0 || s.DeviceEpoch == 0 || a.CurrentHeadVersion > math.MaxInt64 || a.RemainingConfirmations > 1 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		if v.State != AppNodeScopedCompleted && v.State != AppNodeScopedRejectedFenced && !(r.Operation == OperationAppNodeScopedStatus && v.State == AppNodeScopedReadExpired) {
			return ErrInvalid
		}
		if (v.State == AppNodeScopedCompleted && v.ErrorCode != "") || (v.State == AppNodeScopedRejectedFenced && !appNodeScopedErrorKnown(v.ErrorCode)) || (v.State == AppNodeScopedReadExpired && v.ErrorCode != AppNodeScopedReadExpired) {
			return ErrInvalid
		}
		if v.State == AppNodeScopedReadExpired && (v.Node != nil || len(a.AllowedOperations) != 0 || a.RemainingConfirmations != 0) {
			return ErrInvalid
		}
		if a.RootState != RootActiveState && a.RootState != RootUnavailableState {
			return ErrInvalid
		}
		if a.Counters.SessionEpoch != s.ClientSessionEpoch || a.Counters.SessionEpoch == 0 || a.Counters.LastRequestSequence > math.MaxInt64 || a.Counters.NextResponseSequence == 0 || a.Counters.NextResponseSequence > math.MaxInt64 {
			return ErrInvalid
		}
		if a.Profile == AppNodeScopedProfileStatus && (a.RemainingConfirmations != 0 || len(a.AllowedOperations) > 0) {
			return ErrInvalid
		}
		if a.GrantID != "" && !isHex(a.GrantID, RequestIDBytes) {
			return ErrInvalid
		}
		if a.LeaseExpiresAt != "" && validateCanonicalTime(a.LeaseExpiresAt) != nil {
			return ErrInvalid
		}
		if len(a.AllowedOperations) > 0 && !reflect.DeepEqual(a.AllowedOperations, AppNodeScopedAllowedOperations()) {
			return ErrInvalid
		}
		switch a.State {
		case AppNodeScopedAbsent, AppNodeScopedPrepared, AppNodeScopedActive, AppNodeScopedExpired, AppNodeScopedCancelled, AppNodeScopedRevoked, AppNodeScopedSessionEnded:
		default:
			return ErrInvalid
		}
		if (a.State != AppNodeScopedActive || a.LoginRequired) && (len(a.AllowedOperations) > 0 || v.Node != nil) {
			return ErrInvalid
		}
		if v.Node != nil && (v.Node.NodeID != s.AuthorityNodeID || r.Operation != OperationAppNodeScopedStatus || validateAppNodeObservation(*v.Node) != nil) {
			return ErrInvalid
		}
	case AppNodeScopedReconciled:
		if !appNodeScopedNodeID(v.AuthorityNodeID) || r.Operation != OperationAppNodeScopedReconcile || v.Format != AppNodeScopedReconciledFormat || v.RequestID != r.OperationID || v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || validateOrigin(v.Origin) != nil || !validID(v.AccountID) || !isHex(v.RequestPacketDigest, 32) || !isHex(v.OriginalPacketDigest, 32) || !AppNodeScopedReconcileOriginalAllowed(v.OriginalKind, v.OriginalOperation) || len(v.ReceiptPacket) > MaxAppNodeScopedReceiptBytes || v.AccountEpoch == 0 || v.DeviceEpoch == 0 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		if v.OriginalKind == AppNodeScopedOriginalClient {
			id, _, err := ParseAppNodeScopedBusinessOperationID(v.OriginalRequestID)
			if err != nil || id != v.GrantID {
				return ErrInvalid
			}
		} else if !isHex(v.OriginalRequestID, RequestIDBytes) {
			return ErrInvalid
		}
		if v.State != AppNodeScopedCompleted && v.State != AppNodeScopedRejectedFenced && !(v.State == AppNodeScopedReadExpired && v.OriginalOperation == OperationAppNodeScopedStatus) {
			return ErrInvalid
		}
		if (v.State == AppNodeScopedCompleted || v.State == AppNodeScopedRejectedFenced) != (len(v.ReceiptPacket) > 0) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > MaxAppNodeScopedBodyBytes {
		return ErrInvalid
	}
	return nil
}

func ValidateAppNodeScopedReconcileTarget(result AppNodeScopedReconciled, nodeID, kind string, original []byte) error {
	r, _, err := appNodeScopedOriginalRoute(kind, original)
	if err != nil || !appNodeScopedNodeID(nodeID) || result.AuthorityNodeID != nodeID || result.OriginalKind != kind || result.OriginalOperation != r.Operation || result.OriginalRequestID != r.OperationID || result.OriginalPacketDigest != AppNodeScopedPacketDigest(original) || result.HubID != r.HubID || result.OwnerID != r.OwnerID || result.DeviceID != r.DeviceID {
		return ErrInvalid
	}
	return nil
}

func appNodeScopedErrorKnown(code string) bool {
	switch code {
	case "INVALID_REQUEST", "SESSION_REQUIRED", "ROOT_UNAVAILABLE", "DEVICE_UNAVAILABLE", "SCOPE_MISMATCH", "CANDIDATE_UNAVAILABLE", "CANDIDATE_CHANGED", "AUTHORITY_CONFLICT", "PROOF_EXPIRED", "AUTHORITY_EXPIRED", "AUTHORITY_REVOKED", "CONFIRMATION_USED", "REPLAY_CONFLICT", "COUNTER_CONFLICT", "DIAGNOSTICS_FULL":
		return true
	}
	return false
}

// A live snapshot is a complete, pinned current actor/lease observation. A
// diagnostic result remains recoverable with partial session information but
// can never carry a Node observation or a new business-operation capability.
func validateOpenedAppNodeScopedResult(v AppNodeScopedResult, hub HubIdentity) error {
	a := v.Authority
	fp, err := HubFingerprint(hub)
	if err != nil || a.Scope.HubFingerprint != fp || a.Scope.HubID != hub.HubID {
		return ErrInvalid
	}
	if v.State != AppNodeScopedCompleted || a.State != AppNodeScopedActive || a.LoginRequired {
		if v.Node != nil || len(a.AllowedOperations) > 0 {
			return ErrInvalid
		}
		return nil
	}
	if ValidateAppNodeScopedScope(a.Scope, hub) != nil || a.RootState != RootActiveState || !isHex(a.GrantID, RequestIDBytes) || a.LatestGrantID != a.GrantID || a.CurrentHeadVersion == 0 || a.CurrentHeadVersion != a.Scope.HeadVersion {
		return ErrInvalid
	}
	observed, err := parseCanonicalUTC(v.ObservedAt)
	if err != nil {
		return ErrInvalid
	}
	for _, end := range []string{a.LeaseExpiresAt, a.Scope.AccountSessionExpiresAt} {
		deadline, e := parseCanonicalUTC(end)
		if e != nil || !observed.Before(deadline) {
			return ErrInvalid
		}
	}
	switch a.Profile {
	case AppNodeScopedProfileInitial:
		if a.RemainingConfirmations == 1 {
			if !reflect.DeepEqual(a.AllowedOperations, AppNodeScopedAllowedOperations()) {
				return ErrInvalid
			}
		} else if len(a.AllowedOperations) != 0 {
			return ErrInvalid
		}
	case AppNodeScopedProfileStatus:
		if a.RemainingConfirmations != 0 || len(a.AllowedOperations) != 0 || !isHex(a.ConfirmationProvenanceID, RequestIDBytes) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if v.Node != nil && v.Node.ObservedAt != v.ObservedAt {
		return ErrInvalid
	}
	return nil
}
