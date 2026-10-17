package hubaccountwire

import (
	"encoding/hex"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// AppNodeSession is local constructor input, not a new wire/session or actor.
// Its Hub and scope come from the trusted profile and current account flow.
type AppNodeSession struct {
	Hub                                  HubIdentity
	Origin, AccountID, OwnerID, DeviceID string
	AccountEpoch, DeviceEpoch            uint64
	Token                                []byte
}

func (s AppNodeSession) context(now time.Time, requireToken bool) (AppNodeRequestContext, error) {
	if validateHubIdentity(s.Hub) != nil || validateOrigin(s.Origin) != nil || !validID(s.AccountID) || !validID(s.OwnerID) || !validDeviceID(s.DeviceID) ||
		s.AccountEpoch == 0 || s.DeviceEpoch == 0 || s.AccountEpoch > math.MaxInt64 || s.DeviceEpoch > math.MaxInt64 || now.IsZero() ||
		(requireToken && len(s.Token) != MaxSessionTokenBytes) || (!requireToken && len(s.Token) != 0 && len(s.Token) != MaxSessionTokenBytes) {
		return AppNodeRequestContext{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return AppNodeRequestContext{}, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return AppNodeRequestContext{}, err
	}
	return AppNodeRequestContext{Origin: s.Origin, HubID: s.Hub.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, RequestID: id, ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}

func appNodeContextScope(c AppNodeRequestContext, s e2ee.OwnerAppNodeScope) bool {
	return c.Origin == s.Origin && c.HubID == s.HubID && c.AccountID == s.AccountID && c.OwnerID == s.OwnerID && c.DeviceID == s.DeviceID && c.AccountEpoch == s.AccountEpoch && c.DeviceEpoch == s.DeviceEpoch
}

func NewAppNodePrepare(s AppNodeSession, scope e2ee.OwnerAppNodeScope, target AppNodePrepareTarget, owner *e2ee.Identity, now time.Time) (AppNodePrepare, error) {
	ctx, err := s.context(now, true)
	if err != nil || ValidateAppNodeScope(scope, s.Hub) != nil || !appNodeContextScope(ctx, scope) || owner == nil || !reflect.DeepEqual(owner.Public(), scope.OwnerPublic) {
		return AppNodePrepare{}, ErrInvalid
	}
	id, err := NewRequestID()
	if err != nil {
		return AppNodePrepare{}, err
	}
	end := now.Add(MaxAppNodeIntentLifetime)
	sessionEnd, _ := parseCanonicalUTC(scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	intent := e2ee.OwnerAppNodePreviewClaims{Scope: scope, GrantID: id, RequestID: ctx.RequestID, Nonce: hex.EncodeToString(ctx.ClientNonce), IssuedAt: ctx.IssuedAt, ExpiresAt: formatUTC(end)}
	switch target.Kind {
	case AppNodeTargetInitial:
		if target.PreviousGrantID != "" {
			return AppNodePrepare{}, ErrInvalid
		}
		code, err := NormalizeAppNodeCode(target.Code)
		if err != nil {
			return AppNodePrepare{}, err
		}
		target.Code = code
		intent.Purpose = e2ee.OwnerAppNodePreviewPurpose
		intent.CodeDigest, err = AppNodeCodeDigest(s.Hub.HubID, code)
		if err != nil {
			return AppNodePrepare{}, err
		}
	case AppNodeTargetPrevious:
		if target.Code != "" || !isHex(target.PreviousGrantID, RequestIDBytes) {
			return AppNodePrepare{}, ErrInvalid
		}
		intent.Purpose, intent.PreviousGrantID = e2ee.OwnerAppNodeStatusPreviewPurpose, target.PreviousGrantID
	default:
		return AppNodePrepare{}, ErrInvalid
	}
	if ValidateAppNodePreviewClaims(intent, s.Hub, now) != nil {
		return AppNodePrepare{}, ErrInvalid
	}
	proof, err := e2ee.SignOwnerAppNodePreview(owner, intent)
	if err != nil {
		return AppNodePrepare{}, err
	}
	return AppNodePrepare{Format: AppNodePrepareFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), Target: target, OwnerIntent: proof}, nil
}

func NewAppNodeComplete(s AppNodeSession, prepare AppNodePrepare, originalPrepare []byte, ch AppNodeChallenge, owner *e2ee.Identity, now time.Time) (AppNodeComplete, error) {
	ctx, err := s.context(now, true)
	if err != nil || owner == nil || validateAppNodeRequest(prepare, s.Hub, time.Time{}) != nil {
		return AppNodeComplete{}, ErrInvalid
	}
	intent, err := e2ee.VerifyOwnerAppNodePreview(owner.Public(), prepare.OwnerIntent, time.Time{})
	if err != nil || ValidateAppNodePreparedResponse(ch, intent, prepare.OwnerIntent, originalPrepare, s.Hub, now) != nil || !appNodeContextScope(ctx, ch.Claims.Scope) || !reflect.DeepEqual(s.Token, prepare.SessionToken) {
		return AppNodeComplete{}, ErrInvalid
	}
	proof, err := e2ee.SignOwnerAppNodeGrant(owner, ch.Claims)
	if err != nil {
		return AppNodeComplete{}, err
	}
	return AppNodeComplete{Format: AppNodeCompleteFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), OwnerGrant: proof}, nil
}

func NewAppNodeStatus(s AppNodeSession, grantID string, now time.Time) (AppNodeStatusRequest, error) {
	ctx, err := s.context(now, false)
	if err != nil || (grantID != "" && !isHex(grantID, RequestIDBytes)) {
		return AppNodeStatusRequest{}, ErrInvalid
	}
	return AppNodeStatusRequest{Format: AppNodeStatusFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), GrantID: grantID}, nil
}

func NewAppNodeCancel(s AppNodeSession, grantID string, expectedHead uint64, now time.Time) (AppNodeCancel, error) {
	ctx, err := s.context(now, true)
	if err != nil || !isHex(grantID, RequestIDBytes) || expectedHead > math.MaxInt64 {
		return AppNodeCancel{}, ErrInvalid
	}
	return AppNodeCancel{Format: AppNodeCancelFormat, Context: ctx, SessionToken: append([]byte(nil), s.Token...), GrantID: grantID, ExpectedHeadVersion: expectedHead}, nil
}

func NewAppNodeReconcile(s AppNodeSession, kind, grantID string, original []byte, now time.Time) (AppNodeReconcileRequest, error) {
	ctx, err := s.context(now, false)
	if err != nil {
		return AppNodeReconcileRequest{}, err
	}
	r := AppNodeReconcileRequest{Format: AppNodeReconcileFormat, Context: ctx, GrantID: grantID, OriginalKind: kind, OriginalPacket: append([]byte(nil), original...)}
	if validateAppNodeRequest(r, s.Hub, now) != nil {
		return AppNodeReconcileRequest{}, ErrInvalid
	}
	return r, nil
}

func DecodeAppNodeCapabilities(raw []byte) (AppNodeCapabilities, error) {
	var c AppNodeCapabilities
	expected := []string{OperationAppNodePrepare, OperationAppNodeComplete, OperationAppNodeStatus, OperationAppNodeCancel, OperationAppNodeReconcile}
	if decodeCanonical(raw, MaxAppNodeCapabilitiesBytes, &c) != nil || c.Format != AppNodeCapabilitiesFormat || c.ContractRevision != AppNodeContractRevision || c.ServeMode != "--hub-nodes-only" || !c.Available ||
		!reflect.DeepEqual(c.HTTPOperations, expected) || !reflect.DeepEqual(c.Profiles, []string{AppNodeProfileInitial, AppNodeProfileStatus}) || c.RuntimeLeaseSeconds != uint64(AppNodeLeaseLifetime/time.Second) || c.MaxOriginalBytes != MaxAppNodeOriginalBytes ||
		(c.TransportPolicy != AppNodeTransportHTTPS && c.TransportPolicy != AppNodeTransportLoopbackTest) {
		return AppNodeCapabilities{}, ErrInvalid
	}
	return c, nil
}
