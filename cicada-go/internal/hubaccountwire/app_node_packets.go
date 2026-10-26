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

func appNodeOperation(op string) bool { return AppNodeHTTPPath(op) != "" }

func innerLimitForOperation(op string) int {
	if op == OperationOwnerEndpointGroupsReconcile {
		return MaxOwnerEndpointGroupsReconcilePacketBytes
	}
	if ownerEndpointGroupsOperation(op) {
		return MaxOwnerEndpointGroupsPacketBytes
	}
	if op == OperationLocalDomainReconcile {
		return MaxLocalDomainReconcileInnerPacketBytes
	}
	if localDomainOperation(op) {
		return MaxLocalDomainInnerPacketBytes
	}
	if op == OperationNativePairReconcile {
		return MaxNativePairReconcileInnerPacketBytes
	}
	if nativePairOperation(op) {
		return MaxNativePairInnerPacketBytes
	}
	if appNodeOperation(op) {
		return MaxAppNodeInnerPacketBytes
	}
	return MaxInnerPacketBytes
}

func appNodeOuterLimit(op string) int {
	if appNodeOperation(op) && op != OperationAppNodeReconcile {
		return MaxAppNodeMutationPacketBytes
	}
	return MaxPacketBytes
}

func appNodeMetadata(body any) (operation, id, owner, device string, epoch uint64, err error) {
	var c AppNodeRequestContext
	switch v := dereference(body).(type) {
	case AppNodePrepare:
		operation, c = OperationAppNodePrepare, v.Context
	case AppNodeComplete:
		operation, c = OperationAppNodeComplete, v.Context
	case AppNodeStatusRequest:
		operation, c = OperationAppNodeStatus, v.Context
	case AppNodeCancel:
		operation, c = OperationAppNodeCancel, v.Context
	case AppNodeReconcileRequest:
		operation, c = OperationAppNodeReconcile, v.Context
	default:
		return "", "", "", "", 0, ErrInvalid
	}
	return operation, c.RequestID, c.OwnerID, c.DeviceID, HandshakeEpoch, nil
}

func appNodeContextValid(c AppNodeRequestContext, hub HubIdentity, now time.Time) bool {
	return c.HubID == hub.HubID && validateOrigin(c.Origin) == nil && validID(c.AccountID) && validID(c.OwnerID) && validDeviceID(c.DeviceID) &&
		c.AccountEpoch > 0 && c.AccountEpoch <= math.MaxInt64 && c.DeviceEpoch > 0 && c.DeviceEpoch <= math.MaxInt64 && isHex(c.RequestID, RequestIDBytes) && len(c.ClientNonce) == NonceBytes && validateRecent(c.IssuedAt, now, MaxSessionRequestLifetime) == nil
}

func validateAppNodeRequest(body any, hub HubIdentity, now time.Time) error {
	var ctx AppNodeRequestContext
	switch v := dereference(body).(type) {
	case AppNodePrepare:
		ctx = v.Context
		var intent e2ee.OwnerAppNodePreview
		if v.Format != AppNodePrepareFormat || len(v.SessionToken) != MaxSessionTokenBytes || decodeCanonical(v.OwnerIntent, MaxAppNodeProofBytes, &intent) != nil ||
			ValidateAppNodePreviewClaims(intent.Claims, hub, now) != nil || !appNodeContextScope(ctx, intent.Claims.Scope) || intent.Claims.RequestID != ctx.RequestID || intent.Claims.Nonce != hex.EncodeToString(ctx.ClientNonce) || intent.Claims.IssuedAt != ctx.IssuedAt {
			return ErrInvalid
		}
		if _, err := e2ee.VerifyOwnerAppNodePreview(intent.Claims.Scope.OwnerPublic, v.OwnerIntent, now); err != nil {
			return ErrInvalid
		}
		switch v.Target.Kind {
		case AppNodeTargetInitial:
			digest, err := AppNodeCodeDigest(ctx.HubID, v.Target.Code)
			normalized, normalizeErr := NormalizeAppNodeCode(v.Target.Code)
			if err != nil || normalizeErr != nil || normalized != v.Target.Code || v.Target.PreviousGrantID != "" || intent.Claims.Purpose != e2ee.OwnerAppNodePreviewPurpose || intent.Claims.CodeDigest != digest {
				return ErrInvalid
			}
		case AppNodeTargetPrevious:
			if v.Target.Code != "" || intent.Claims.Purpose != e2ee.OwnerAppNodeStatusPreviewPurpose || v.Target.PreviousGrantID != intent.Claims.PreviousGrantID {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case AppNodeComplete:
		ctx = v.Context
		var proof e2ee.OwnerAppNodeGrant
		if v.Format != AppNodeCompleteFormat || len(v.SessionToken) != MaxSessionTokenBytes || decodeCanonical(v.OwnerGrant, MaxAppNodeProofBytes, &proof) != nil || ValidateAppNodeGrantClaims(proof.Claims, hub, now) != nil || !appNodeContextScope(ctx, proof.Claims.Scope) {
			return ErrInvalid
		}
		if _, err := e2ee.VerifyOwnerAppNodeGrant(proof.Claims.Scope.OwnerPublic, v.OwnerGrant, now); err != nil {
			return ErrInvalid
		}
	case AppNodeStatusRequest:
		ctx = v.Context
		if v.Format != AppNodeStatusFormat || (v.GrantID != "" && !isHex(v.GrantID, RequestIDBytes)) || (len(v.SessionToken) != 0 && len(v.SessionToken) != MaxSessionTokenBytes) {
			return ErrInvalid
		}
	case AppNodeCancel:
		ctx = v.Context
		if v.Format != AppNodeCancelFormat || len(v.SessionToken) != MaxSessionTokenBytes || !isHex(v.GrantID, RequestIDBytes) || v.ExpectedHeadVersion > math.MaxInt64 {
			return ErrInvalid
		}
	case AppNodeReconcileRequest:
		ctx = v.Context
		if v.Format != AppNodeReconcileFormat || (v.GrantID != "" && !isHex(v.GrantID, RequestIDBytes)) {
			return ErrInvalid
		}
		r, _, err := appNodeOriginalRoute(v.OriginalKind, v.OriginalPacket)
		if err != nil || r.HubID != ctx.HubID || r.OwnerID != ctx.OwnerID || r.DeviceID != ctx.DeviceID {
			return ErrInvalid
		}
		if v.OriginalKind == AppNodeOriginalClient {
			grant, _, err := ParseAppNodeBusinessOperationID(r.OperationID)
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

func appNodeOriginalRoute(kind string, original []byte) (clientwire.Route, *e2ee.PublicIdentity, error) {
	if len(original) == 0 || len(original) > MaxAppNodeOriginalBytes {
		return clientwire.Route{}, nil, ErrInvalid
	}
	var r clientwire.Route
	var pub *e2ee.PublicIdentity
	switch kind {
	case AppNodeOriginalAuthority:
		p, err := DecodePacket(original)
		if err != nil {
			return r, nil, ErrInvalid
		}
		r = p.Packet.Route
		pub = &p.SenderPublicIdentity
	case AppNodeOriginalClient:
		var p clientwire.Packet
		if decodeCanonical(original, MaxAppNodeOriginalBytes, &p) != nil || len(p.Envelope) == 0 {
			return r, nil, ErrInvalid
		}
		r = p.Route
		if _, _, err := ParseAppNodeBusinessOperationID(r.OperationID); err != nil {
			return r, nil, ErrInvalid
		}
	default:
		return r, nil, ErrInvalid
	}
	if r.Direction != clientwire.DirectionRequest || !AppNodeReconcileOriginalAllowed(kind, r.Operation) {
		return r, nil, ErrInvalid
	}
	return r, pub, nil
}

func validateAppNodeDevice(body any, device e2ee.PublicIdentity) error {
	switch v := dereference(body).(type) {
	case AppNodePrepare:
		var p e2ee.OwnerAppNodePreview
		if decodeCanonical(v.OwnerIntent, MaxAppNodeProofBytes, &p) != nil || !reflect.DeepEqual(p.Claims.Scope.DevicePublic, device) {
			return ErrInvalid
		}
	case AppNodeComplete:
		var p e2ee.OwnerAppNodeGrant
		if decodeCanonical(v.OwnerGrant, MaxAppNodeProofBytes, &p) != nil || !reflect.DeepEqual(p.Claims.Scope.DevicePublic, device) {
			return ErrInvalid
		}
	case AppNodeReconcileRequest:
		r, pub, err := appNodeOriginalRoute(v.OriginalKind, v.OriginalPacket)
		if err != nil || r.SenderKeyID != device.ID || (pub != nil && !reflect.DeepEqual(*pub, device)) {
			return ErrInvalid
		}
	case AppNodeStatusRequest, AppNodeCancel:
	default:
		return ErrInvalid
	}
	return nil
}

func validateAppNodeResponse(body any, r clientwire.Route) error {
	if !appNodeOperation(r.Operation) {
		return ErrInvalid
	}
	switch v := dereference(body).(type) {
	case AppNodeChallenge:
		s := v.Claims.Scope
		if r.Operation != OperationAppNodePrepare || v.Format != AppNodeChallengeFormat || v.RequestID != r.OperationID || s.HubID != r.HubID || s.OwnerID != r.OwnerID || s.DeviceID != r.DeviceID || s.DevicePublic.ID != r.SenderKeyID || !isHex(v.RequestPacketDigest, 32) || v.Claims.PreparePacketDigest != v.RequestPacketDigest || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
	case AppNodeResult:
		a := v.Authority
		s := a.Scope
		if r.Operation == OperationAppNodeReconcile || v.Format != AppNodeResultFormat || v.Operation != r.Operation || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) || s.HubID != r.HubID || s.OwnerID != r.OwnerID || s.DeviceID != r.DeviceID || s.DevicePublic.ID != r.SenderKeyID || !validID(s.AccountID) || validateOrigin(s.Origin) != nil || e2ee.ValidatePublicIdentity(s.OwnerPublic) != nil || e2ee.ValidatePublicIdentity(s.DevicePublic) != nil || s.AccountEpoch == 0 || s.DeviceEpoch == 0 || a.CurrentHeadVersion > math.MaxInt64 || a.RemainingConfirmations > 1 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		if v.State != AppNodeCompleted && v.State != AppNodeRejectedFenced && !(r.Operation == OperationAppNodeStatus && v.State == AppNodeReadExpired) {
			return ErrInvalid
		}
		if (v.State == AppNodeCompleted && v.ErrorCode != "") || (v.State == AppNodeRejectedFenced && !appNodeErrorKnown(v.ErrorCode)) || (v.State == AppNodeReadExpired && v.ErrorCode != AppNodeReadExpired) {
			return ErrInvalid
		}
		if v.State == AppNodeReadExpired && (v.Node != nil || len(a.AllowedOperations) != 0 || a.RemainingConfirmations != 0) {
			return ErrInvalid
		}
		if a.RootState != RootActiveState && a.RootState != RootUnavailableState {
			return ErrInvalid
		}
		if a.Counters.SessionEpoch != s.ClientSessionEpoch || a.Counters.SessionEpoch == 0 || a.Counters.LastRequestSequence > math.MaxInt64 || a.Counters.NextResponseSequence == 0 || a.Counters.NextResponseSequence > math.MaxInt64 {
			return ErrInvalid
		}
		if a.Profile == AppNodeProfileStatus && (a.RemainingConfirmations != 0 || len(a.AllowedOperations) > 0) {
			return ErrInvalid
		}
		if a.GrantID != "" && !isHex(a.GrantID, RequestIDBytes) {
			return ErrInvalid
		}
		if a.LeaseExpiresAt != "" && validateCanonicalTime(a.LeaseExpiresAt) != nil {
			return ErrInvalid
		}
		if len(a.AllowedOperations) > 0 && !reflect.DeepEqual(a.AllowedOperations, AppNodeAllowedOperations()) {
			return ErrInvalid
		}
		switch a.State {
		case AppNodeAbsent, AppNodePrepared, AppNodeActive, AppNodeExpired, AppNodeCancelled, AppNodeRevoked, AppNodeSessionEnded:
		default:
			return ErrInvalid
		}
		if (a.State != AppNodeActive || a.LoginRequired) && (len(a.AllowedOperations) > 0 || v.Node != nil) {
			return ErrInvalid
		}
		if v.Node != nil && (r.Operation != OperationAppNodeStatus || validateAppNodeObservation(*v.Node) != nil) {
			return ErrInvalid
		}
	case AppNodeReconcileResult:
		if r.Operation != OperationAppNodeReconcile || v.Format != AppNodeReconciledFormat || v.RequestID != r.OperationID || v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || validateOrigin(v.Origin) != nil || !validID(v.AccountID) || !isHex(v.RequestPacketDigest, 32) || !isHex(v.OriginalPacketDigest, 32) || !AppNodeReconcileOriginalAllowed(v.OriginalKind, v.OriginalOperation) || len(v.ReceiptPacket) > MaxAppNodeReceiptBytes || v.AccountEpoch == 0 || v.DeviceEpoch == 0 || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		if v.OriginalKind == AppNodeOriginalClient {
			id, _, err := ParseAppNodeBusinessOperationID(v.OriginalRequestID)
			if err != nil || id != v.GrantID {
				return ErrInvalid
			}
		} else if !isHex(v.OriginalRequestID, RequestIDBytes) {
			return ErrInvalid
		}
		if v.State != AppNodeCompleted && v.State != AppNodeRejectedFenced && !(v.State == AppNodeReadExpired && v.OriginalOperation == OperationAppNodeStatus) {
			return ErrInvalid
		}
		if (v.State == AppNodeCompleted || v.State == AppNodeRejectedFenced) != (len(v.ReceiptPacket) > 0) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > MaxAppNodeBodyBytes {
		return ErrInvalid
	}
	return nil
}

func validateAppNodeObservation(n AppNodeObservation) error {
	if !validID(n.NodeID) || n.NodeID == "control-local" || n.NodeID == "worker-local" || !validID(n.BindingID) || n.BindingVersion == 0 || n.CredentialVersion == 0 || n.NodeKeyEpoch == 0 || !validID(n.NodeKeyID) || !isHex(n.NodeKeyFingerprint, 32) || n.Source != "store.machines.last_seen" || validateCanonicalTime(n.ObservedAt) != nil {
		return ErrInvalid
	}
	if n.BindingState != "ACTIVE" && n.BindingState != "REVOKED" {
		return ErrInvalid
	}
	if n.LastHeartbeatAt != "" && validateCanonicalTime(n.LastHeartbeatAt) != nil {
		return ErrInvalid
	}
	switch n.Connectivity {
	case "UNKNOWN":
		if n.Known || !n.Stale || n.FreshUntil != "" {
			return ErrInvalid
		}
	case "CONNECTED", "STALE":
		last, err := parseCanonicalUTC(n.LastHeartbeatAt)
		if err != nil {
			return ErrInvalid
		}
		fresh, err := parseCanonicalUTC(n.FreshUntil)
		if err != nil || !fresh.Equal(last.Add(AppNodeObservationStaleAfter)) || !n.Known {
			return ErrInvalid
		}
		observed, _ := parseCanonicalUTC(n.ObservedAt)
		if last.After(observed) || (n.Connectivity == "CONNECTED" && (n.BindingState != "ACTIVE" || !n.Authorized || n.Stale || !observed.Before(fresh))) {
			return ErrInvalid
		}
		if n.Connectivity == "STALE" && (!n.Stale || observed.Before(fresh)) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateAppNodeReconcileTarget(result AppNodeReconcileResult, kind string, original []byte) error {
	r, _, err := appNodeOriginalRoute(kind, original)
	if err != nil || result.OriginalKind != kind || result.OriginalOperation != r.Operation || result.OriginalRequestID != r.OperationID || result.OriginalPacketDigest != AppNodePacketDigest(original) || result.HubID != r.HubID || result.OwnerID != r.OwnerID || result.DeviceID != r.DeviceID {
		return ErrInvalid
	}
	return nil
}

func appNodeErrorKnown(code string) bool {
	switch code {
	case "INVALID_REQUEST", "SESSION_REQUIRED", "ROOT_UNAVAILABLE", "DEVICE_UNAVAILABLE", "SCOPE_MISMATCH", "CANDIDATE_UNAVAILABLE", "CANDIDATE_CHANGED", "AUTHORITY_CONFLICT", "PROOF_EXPIRED", "AUTHORITY_EXPIRED", "AUTHORITY_REVOKED", "CONFIRMATION_USED", "REPLAY_CONFLICT", "COUNTER_CONFLICT", "DIAGNOSTICS_FULL":
		return true
	}
	return false
}

// A live snapshot is a complete, pinned current actor/lease observation. A
// diagnostic result remains recoverable with partial session information but
// can never carry a Node observation or a new business-operation capability.
func validateOpenedAppNodeResult(v AppNodeResult, hub HubIdentity) error {
	a := v.Authority
	fp, err := HubFingerprint(hub)
	if err != nil || a.Scope.HubFingerprint != fp || a.Scope.HubID != hub.HubID {
		return ErrInvalid
	}
	if v.State != AppNodeCompleted || a.State != AppNodeActive || a.LoginRequired {
		if v.Node != nil || len(a.AllowedOperations) > 0 {
			return ErrInvalid
		}
		return nil
	}
	if ValidateAppNodeScope(a.Scope, hub) != nil || a.RootState != RootActiveState || !isHex(a.GrantID, RequestIDBytes) || a.LatestGrantID != a.GrantID || a.CurrentHeadVersion == 0 || a.CurrentHeadVersion != a.Scope.HeadVersion {
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
	case AppNodeProfileInitial:
		if a.RemainingConfirmations == 1 {
			if !reflect.DeepEqual(a.AllowedOperations, AppNodeAllowedOperations()) {
				return ErrInvalid
			}
		} else if len(a.AllowedOperations) != 0 {
			return ErrInvalid
		}
	case AppNodeProfileStatus:
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
