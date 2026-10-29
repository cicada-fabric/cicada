package hubaccountwire

import (
	"encoding/hex"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func appNodeScopedContextScope(c AppNodeRequestContext, s e2ee.OwnerAppNodeScopedScope) bool {
	return c.Origin == s.Origin && c.HubID == s.HubID && c.AccountID == s.AccountID && c.OwnerID == s.OwnerID && c.DeviceID == s.DeviceID && c.AccountEpoch == s.AccountEpoch && c.DeviceEpoch == s.DeviceEpoch
}

func NewAppNodeScopedPrepare(s AppNodeSession, scope e2ee.OwnerAppNodeScopedScope, target AppNodeScopedPrepareTarget, owner *e2ee.Identity, now time.Time) (AppNodeScopedPrepare, error) {
	ctx, err := s.context(now, true)
	if err != nil || ValidateAppNodeScopedScope(scope, s.Hub) != nil || !appNodeScopedContextScope(ctx, scope) || owner == nil || !reflect.DeepEqual(owner.Public(), scope.OwnerPublic) {
		return AppNodeScopedPrepare{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return AppNodeScopedPrepare{}, err
	}
	end := now.Add(MaxAppNodeScopedIntentLifetime)
	sessionEnd, _ := parseCanonicalUTC(scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	intent := e2ee.OwnerAppNodeScopedPreviewClaims{Scope: scope, GrantID: id, RequestID: ctx.RequestID, Nonce: hex.EncodeToString(ctx.ClientNonce), IssuedAt: ctx.IssuedAt, ExpiresAt: formatUTC(end)}
	switch target.Kind {
	case AppNodeScopedTargetInitial:
		if target.PreviousGrantID != "" {
			return AppNodeScopedPrepare{}, ErrInvalid
		}
		code, err := NormalizeAppNodeCode(target.Code)
		if err != nil {
			return AppNodeScopedPrepare{}, err
		}
		target.Code = code
		intent.Purpose = e2ee.OwnerAppNodeScopedPreviewPurpose
		intent.CodeDigest, err = AppNodeCodeDigest(s.Hub.HubID, code)
		if err != nil {
			return AppNodeScopedPrepare{}, err
		}
	case AppNodeScopedTargetPrevious:
		if target.Code != "" || !isHex(target.PreviousGrantID, RequestIDBytes) {
			return AppNodeScopedPrepare{}, ErrInvalid
		}
		intent.Purpose, intent.PreviousGrantID = e2ee.OwnerAppNodeScopedStatusPreviewPurpose, target.PreviousGrantID
	default:
		return AppNodeScopedPrepare{}, ErrInvalid
	}
	if ValidateAppNodeScopedPreviewClaims(intent, s.Hub, now) != nil {
		return AppNodeScopedPrepare{}, ErrInvalid
	}
	proof, err := e2ee.SignOwnerAppNodeScopedPreview(owner, intent)
	if err != nil {
		return AppNodeScopedPrepare{}, err
	}
	return AppNodeScopedPrepare{Format: AppNodeScopedPrepareFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), Target: target, OwnerIntent: proof}, nil
}

func NewAppNodeScopedComplete(s AppNodeSession, prepare AppNodeScopedPrepare, originalPrepare []byte, ch AppNodeScopedChallenge, owner *e2ee.Identity, now time.Time) (AppNodeScopedComplete, error) {
	ctx, err := s.context(now, true)
	if err != nil || owner == nil || validateAppNodeScopedRequest(prepare, s.Hub, time.Time{}) != nil {
		return AppNodeScopedComplete{}, ErrInvalid
	}
	intent, err := e2ee.VerifyOwnerAppNodeScopedPreview(owner.Public(), prepare.OwnerIntent, time.Time{})
	if err != nil || ValidateAppNodeScopedPreparedResponse(ch, intent, prepare.OwnerIntent, originalPrepare, s.Hub, now) != nil || !appNodeScopedContextScope(ctx, ch.Claims.Scope) || !reflect.DeepEqual(s.Token, prepare.SessionToken) {
		return AppNodeScopedComplete{}, ErrInvalid
	}
	proof, err := e2ee.SignOwnerAppNodeScopedGrant(owner, ch.Claims)
	if err != nil {
		return AppNodeScopedComplete{}, err
	}
	return AppNodeScopedComplete{Format: AppNodeScopedCompleteFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), OwnerGrant: proof}, nil
}

func NewAppNodeScopedStatus(s AppNodeSession, target AppNodeScopedStatusTarget, grantID string, now time.Time) (AppNodeScopedStatus, error) {
	ctx, err := s.context(now, false)
	if err != nil || !appNodeScopedStatusTargetValid(target, s.Token, grantID) {
		return AppNodeScopedStatus{}, ErrInvalid
	}
	return AppNodeScopedStatus{Target: target, Format: AppNodeScopedStatusFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), GrantID: grantID}, nil
}

func NewAppNodeScopedCancel(s AppNodeSession, nodeID, grantID string, expectedHead uint64, now time.Time) (AppNodeScopedCancel, error) {
	ctx, err := s.context(now, true)
	if err != nil || !appNodeScopedNodeID(nodeID) || !isHex(grantID, RequestIDBytes) || expectedHead > math.MaxInt64 {
		return AppNodeScopedCancel{}, ErrInvalid
	}
	return AppNodeScopedCancel{AuthorityNodeID: nodeID, Format: AppNodeScopedCancelFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), GrantID: grantID, ExpectedHeadVersion: expectedHead}, nil
}

func NewAppNodeScopedReconcile(s AppNodeSession, nodeID, kind, grantID string, original []byte, now time.Time) (AppNodeScopedReconcile, error) {
	ctx, err := s.context(now, false)
	if err != nil {
		return AppNodeScopedReconcile{}, err
	}
	r := AppNodeScopedReconcile{AuthorityNodeID: nodeID, Format: AppNodeScopedReconcileFormat, Context: ctx, GrantID: grantID, OriginalKind: kind, OriginalPacket: append([]byte(nil), original...)}
	if validateAppNodeScopedRequest(r, s.Hub, now) != nil {
		return AppNodeScopedReconcile{}, ErrInvalid
	}
	return r, nil
}

func DecodeAppNodeScopedCapabilities(raw []byte) (AppNodeScopedCapabilities, error) {
	var c AppNodeScopedCapabilities
	expected := []string{OperationAppNodeScopedPrepare, OperationAppNodeScopedComplete, OperationAppNodeScopedStatus, OperationAppNodeScopedCancel, OperationAppNodeScopedReconcile}
	if decodeCanonical(raw, MaxAppNodeScopedCapabilitiesBytes, &c) != nil || c.Format != AppNodeScopedCapabilitiesFormat || c.ContractRevision != AppNodeScopedContractRevision || c.ScopeKind != AppNodeScopedScopeKind || c.ScopeVersion != AppNodeScopedScopeVersion || c.ServeMode != "--hub-nodes-only" || !c.Available ||
		!reflect.DeepEqual(c.HTTPOperations, expected) || !reflect.DeepEqual(c.Profiles, []string{AppNodeScopedProfileInitial, AppNodeScopedProfileStatus}) || c.RuntimeLeaseSeconds != uint64(AppNodeScopedLeaseLifetime/time.Second) || c.MaxOriginalBytes != MaxAppNodeScopedOriginalBytes ||
		(c.TransportPolicy != AppNodeScopedTransportHTTPS && c.TransportPolicy != AppNodeScopedTransportLoopbackTest) {
		return AppNodeScopedCapabilities{}, ErrInvalid
	}
	return c, nil
}
