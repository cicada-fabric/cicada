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

func threadCollaborationOwnerOperation(op string) bool { return ThreadCollaborationHTTPPath(op) != "" }
func ThreadCollaborationOwnerPurpose(op string) string {
	switch op {
	case OperationThreadCollaborationOwnerRead:
		return "owner-thread-collaboration-read:v1"
	case OperationThreadCollaborationOwnerPrepare:
		return "owner-thread-collaboration-prepare:v1"
	case OperationThreadCollaborationOwnerApply:
		return "owner-thread-collaboration-apply:v1"
	case OperationThreadCollaborationOwnerStatus:
		return "owner-thread-collaboration-status:v1"
	case OperationThreadCollaborationOwnerReconcile:
		return "owner-thread-collaboration-reconcile:v1"
	}
	return ""
}

// Reuses the existing Owner/device/account-session scope and signing service.
// The new exact purposes never validate as an old endpoint-groups operation.
func threadCollaborationOwnerParts(q any) (op, format string, c AppNodeRequestContext, token, proof []byte, body any) {
	switch v := dereference(q).(type) {
	case ThreadCollaborationOwnerReadRequest:
		return OperationThreadCollaborationOwnerRead, v.Format, v.Context, v.SessionToken, v.OwnerProof, v.Body
	case ThreadCollaborationOwnerPrepareRequest:
		return OperationThreadCollaborationOwnerPrepare, v.Format, v.Context, v.SessionToken, v.OwnerProof, v.Body
	case ThreadCollaborationOwnerApplyRequest:
		return OperationThreadCollaborationOwnerApply, v.Format, v.Context, v.SessionToken, v.OwnerProof, v.Body
	case ThreadCollaborationOwnerStatusRequest:
		return OperationThreadCollaborationOwnerStatus, v.Format, v.Context, v.SessionToken, v.OwnerProof, v.Body
	case ThreadCollaborationOwnerReconcileRequest:
		return OperationThreadCollaborationOwnerReconcile, v.Format, v.Context, v.SessionToken, v.OwnerProof, v.Body
	}
	return
}
func threadCollaborationOwnerMetadata(q any) (op, id, owner, device string, epoch uint64, err error) {
	op, _, c, _, _, _ := threadCollaborationOwnerParts(q)
	if op == "" {
		return "", "", "", "", 0, ErrInvalid
	}
	return op, c.RequestID, c.OwnerID, c.DeviceID, HandshakeEpoch, nil
}
func ThreadCollaborationOwnerRequestBodyDigest(body any) (string, error) {
	switch v := dereference(body).(type) {
	case ThreadCollaborationOwnerReadBody:
		if ValidateThreadCollaborationOwnerReadBody(v) != nil {
			return "", ErrInvalid
		}
	case ThreadCollaborationOwnerPrepareBody:
		if ValidateThreadCollaborationOwnerPrepareBody(v) != nil {
			return "", ErrInvalid
		}
	case ThreadCollaborationOwnerApplyBody:
		if !isHex(v.ReviewID, 16) || !isHex(v.ReviewDigest, 32) {
			return "", ErrInvalid
		}
	case ThreadCollaborationOwnerStatusBody:
		if !isHex(v.OperationID, 16) || !isHex(v.OriginalPacketDigest, 32) {
			return "", ErrInvalid
		}
	case ThreadCollaborationOwnerReconcileBody:
		p, err := DecodeThreadCollaborationOwnerPacket(v.OriginalPacket)
		if err != nil || len(v.OriginalPacket) > MaxThreadCollaborationOriginalBytes || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.Operation == OperationThreadCollaborationOwnerReconcile {
			return "", ErrInvalid
		}
	default:
		return "", ErrInvalid
	}
	return ownerEndpointGroupsDigest("cicada/thread-collaboration/owner-request-body/v1\x00", dereference(body))
}
func ThreadCollaborationOwnerPacketDigest(raw []byte) string {
	// Keep packets distinct from all previous Owner request families.
	digest := sha256.Sum256(append([]byte("cicada/thread-collaboration/owner-packet/v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}
func ValidateThreadCollaborationOwnerRequest(q any, hub HubIdentity, now time.Time) error {
	op, format, c, token, raw, body := threadCollaborationOwnerParts(q)
	digest, err := ThreadCollaborationOwnerRequestBodyDigest(body)
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if err != nil || !threadCollaborationOwnerOperation(op) || format != ThreadCollaborationOwnerFormat || !appNodeContextValid(c, hub, now) || len(token) != MaxSessionTokenBytes || decodeCanonical(raw, e2ee.MaxEndpointGroupProofBytes, &proof) != nil || ValidateAppNodeScope(proof.Claims.Scope, hub) != nil || !appNodeContextScope(c, proof.Claims.Scope) || proof.Claims.RequestID != c.RequestID || proof.Claims.Nonce != hex.EncodeToString(c.ClientNonce) || proof.Claims.IssuedAt != c.IssuedAt || proof.Claims.BodyDigest != digest {
		return ErrInvalid
	}
	if _, err := e2ee.VerifyOwnerEndpointGroupsRequest(proof.Claims.Scope.OwnerPublic, raw, ThreadCollaborationOwnerPurpose(op), now); err != nil {
		return ErrInvalid
	}
	if b, ok := body.(ThreadCollaborationOwnerReconcileBody); ok {
		p, err := DecodeThreadCollaborationOwnerPacket(b.OriginalPacket)
		if err != nil || p.Packet.Route.HubID != c.HubID || p.Packet.Route.OwnerID != c.OwnerID || p.Packet.Route.DeviceID != c.DeviceID || !reflect.DeepEqual(p.SenderPublicIdentity, proof.Claims.Scope.DevicePublic) {
			return ErrInvalid
		}
	}
	return nil
}
func newThreadCollaborationOwnerRequest(s AppNodeSession, scope e2ee.OwnerAppNodeScope, op string, body any, owner *e2ee.Identity, now time.Time) (AppNodeRequestContext, []byte, []byte, error) {
	c, err := s.context(now, true)
	digest, de := ThreadCollaborationOwnerRequestBodyDigest(body)
	if err != nil || de != nil || ValidateAppNodeScope(scope, s.Hub) != nil || !appNodeContextScope(c, scope) || !threadCollaborationOwnerOperation(op) {
		return AppNodeRequestContext{}, nil, nil, ErrInvalid
	}
	end := now.Add(e2ee.EndpointGroupsRequestLifetime)
	sessionEnd, _ := parseCanonicalUTC(scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	claims := e2ee.OwnerEndpointGroupsRequestClaims{Version: 1, Purpose: ThreadCollaborationOwnerPurpose(op), Scope: scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: formatUTC(end), BodyDigest: digest}
	if e2ee.ValidateOwnerEndpointGroupsRequest(claims, now) != nil {
		return AppNodeRequestContext{}, nil, nil, ErrInvalid
	}
	proof, err := e2ee.SignOwnerEndpointGroupsRequest(owner, claims)
	if err != nil {
		return AppNodeRequestContext{}, nil, nil, err
	}
	return c, append([]byte(nil), s.Token...), proof, nil
}
func NewThreadCollaborationOwnerRead(s AppNodeSession, scope e2ee.OwnerAppNodeScope, body ThreadCollaborationOwnerReadBody, owner *e2ee.Identity, now time.Time) (ThreadCollaborationOwnerReadRequest, error) {
	if body.View == "THREADS" && body.Limit == 0 {
		body.Limit = MaxThreadCollaborationPageRows
	}
	c, t, p, e := newThreadCollaborationOwnerRequest(s, scope, OperationThreadCollaborationOwnerRead, body, owner, now)
	return ThreadCollaborationOwnerReadRequest{ThreadCollaborationOwnerFormat, c, t, p, body}, e
}
func NewThreadCollaborationOwnerPrepare(s AppNodeSession, scope e2ee.OwnerAppNodeScope, body ThreadCollaborationOwnerPrepareBody, owner *e2ee.Identity, now time.Time) (ThreadCollaborationOwnerPrepareRequest, error) {
	c, t, p, e := newThreadCollaborationOwnerRequest(s, scope, OperationThreadCollaborationOwnerPrepare, body, owner, now)
	return ThreadCollaborationOwnerPrepareRequest{ThreadCollaborationOwnerFormat, c, t, p, body}, e
}
func ValidateThreadCollaborationOwnerReview(q ThreadCollaborationOwnerPrepareRequest, original []byte, r ThreadCollaborationOwnerReview, hub HubIdentity, now time.Time) error {
	_, err := ThreadCollaborationOwnerReviewDigest(r)
	p, pe := DecodeThreadCollaborationOwnerPacket(original)
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if ValidateThreadCollaborationOwnerRequest(q, hub, time.Time{}) != nil || err != nil || pe != nil || now.IsZero() || r.HubID != hub.HubID || r.OwnerID != q.Context.OwnerID || r.DeviceID != q.Context.DeviceID || r.PrepareRequestID != q.Context.RequestID || r.PreparePacketDigest != ThreadCollaborationOwnerPacketDigest(original) || !reflect.DeepEqual(r.Prepared, q.Body) || p.Packet.Route.Operation != OperationThreadCollaborationOwnerPrepare || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.OperationID != q.Context.RequestID || p.Packet.Route.HubID != hub.HubID || p.Packet.Route.OwnerID != q.Context.OwnerID || p.Packet.Route.DeviceID != q.Context.DeviceID || decodeCanonical(q.OwnerProof, e2ee.MaxEndpointGroupProofBytes, &proof) != nil || !reflect.DeepEqual(p.SenderPublicIdentity, proof.Claims.Scope.DevicePublic) {
		return ErrInvalid
	}
	observed, _ := parseCanonicalUTC(r.ObservedAt)
	end, _ := parseCanonicalUTC(r.ExpiresAt)
	issued, _ := parseCanonicalUTC(q.Context.IssuedAt)
	proofEnd, _ := parseCanonicalUTC(proof.Claims.ExpiresAt)
	if observed.Before(issued.Add(-30*time.Second)) || observed.After(now.Add(30*time.Second)) || !now.Before(end) || end.After(proofEnd) {
		return ErrInvalid
	}
	return nil
}
func NewThreadCollaborationOwnerApply(s AppNodeSession, scope e2ee.OwnerAppNodeScope, prepare ThreadCollaborationOwnerPrepareRequest, original []byte, review ThreadCollaborationOwnerReview, owner *e2ee.Identity, now time.Time) (ThreadCollaborationOwnerApplyRequest, error) {
	if ValidateThreadCollaborationOwnerReview(prepare, original, review, s.Hub, now) != nil || review.OwnerID != s.OwnerID || review.DeviceID != s.DeviceID {
		return ThreadCollaborationOwnerApplyRequest{}, ErrInvalid
	}
	d, err := ThreadCollaborationOwnerReviewDigest(review)
	if err != nil {
		return ThreadCollaborationOwnerApplyRequest{}, err
	}
	b := ThreadCollaborationOwnerApplyBody{review.ReviewID, d}
	c, t, p, e := newThreadCollaborationOwnerRequest(s, scope, OperationThreadCollaborationOwnerApply, b, owner, now)
	return ThreadCollaborationOwnerApplyRequest{ThreadCollaborationOwnerFormat, c, t, p, b}, e
}
func NewThreadCollaborationOwnerStatus(s AppNodeSession, scope e2ee.OwnerAppNodeScope, original []byte, owner *e2ee.Identity, now time.Time) (ThreadCollaborationOwnerStatusRequest, error) {
	p, err := DecodeThreadCollaborationOwnerPacket(original)
	if err != nil || p.Packet.Route.Operation != OperationThreadCollaborationOwnerApply || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.HubID != s.Hub.HubID || p.Packet.Route.OwnerID != s.OwnerID || p.Packet.Route.DeviceID != s.DeviceID || !reflect.DeepEqual(p.SenderPublicIdentity, scope.DevicePublic) {
		return ThreadCollaborationOwnerStatusRequest{}, ErrInvalid
	}
	b := ThreadCollaborationOwnerStatusBody{p.Packet.Route.OperationID, ThreadCollaborationOwnerPacketDigest(original)}
	c, t, pr, e := newThreadCollaborationOwnerRequest(s, scope, OperationThreadCollaborationOwnerStatus, b, owner, now)
	return ThreadCollaborationOwnerStatusRequest{ThreadCollaborationOwnerFormat, c, t, pr, b}, e
}
func NewThreadCollaborationOwnerReconcile(s AppNodeSession, scope e2ee.OwnerAppNodeScope, original []byte, owner *e2ee.Identity, now time.Time) (ThreadCollaborationOwnerReconcileRequest, error) {
	b := ThreadCollaborationOwnerReconcileBody{append([]byte(nil), original...)}
	c, t, p, e := newThreadCollaborationOwnerRequest(s, scope, OperationThreadCollaborationOwnerReconcile, b, owner, now)
	q := ThreadCollaborationOwnerReconcileRequest{ThreadCollaborationOwnerFormat, c, t, p, b}
	if e != nil || ValidateThreadCollaborationOwnerRequest(q, s.Hub, now) != nil {
		return ThreadCollaborationOwnerReconcileRequest{}, ErrInvalid
	}
	return q, nil
}
func DecodeThreadCollaborationOwnerPacket(raw []byte) (Packet, error) {
	p, err := decodePacketWithLimit(raw, MaxThreadCollaborationReconcilePacketBytes)
	if err != nil || !threadCollaborationOwnerOperation(p.Packet.Route.Operation) {
		return Packet{}, ErrInvalid
	}
	return p, nil
}
func DecodeThreadCollaborationOwnerRequest(op string, raw []byte, hub HubIdentity, now time.Time) (any, error) {
	var q any
	switch op {
	case OperationThreadCollaborationOwnerRead:
		q = &ThreadCollaborationOwnerReadRequest{}
	case OperationThreadCollaborationOwnerPrepare:
		q = &ThreadCollaborationOwnerPrepareRequest{}
	case OperationThreadCollaborationOwnerApply:
		q = &ThreadCollaborationOwnerApplyRequest{}
	case OperationThreadCollaborationOwnerStatus:
		q = &ThreadCollaborationOwnerStatusRequest{}
	case OperationThreadCollaborationOwnerReconcile:
		q = &ThreadCollaborationOwnerReconcileRequest{}
	default:
		return nil, ErrInvalid
	}
	if decodeCanonical(raw, maxBodyForOperation(op), q) != nil || ValidateThreadCollaborationOwnerRequest(q, hub, now) != nil {
		return nil, ErrInvalid
	}
	return dereference(q), nil
}
func OpenThreadCollaborationOwnerResponse(device *e2ee.Identity, hub HubIdentity, original, response []byte, out *ThreadCollaborationOwnerResult) error {
	p, err := DecodeThreadCollaborationOwnerPacket(original)
	if err != nil {
		return ErrInvalid
	}
	return openClientResponsePacket(device, hub, p, original, response, out)
}

func validateThreadCollaborationOwnerResponse(body any, r clientwire.Route) error {
	v, ok := dereference(body).(ThreadCollaborationOwnerResult)
	if !ok || v.Format != ThreadCollaborationOwnerResultFormat || v.ContractRevision != ThreadCollaborationContractRevision || v.RequestID != r.OperationID || v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || !isHex(v.RequestPacketDigest, 32) || !isHex(v.OperationID, 16) || !isHex(v.OriginalPacketDigest, 32) {
		return ErrInvalid
	}
	if _, err := parseCanonicalUTC(v.ObservedAt); err != nil {
		return ErrInvalid
	}
	effects := 0
	if v.Thread != nil {
		effects++
		if ValidateThreadScopeView(*v.Thread) != nil || v.Thread.HubID != "" && v.Thread.HubID != r.HubID {
			return ErrInvalid
		}
	}
	if v.Policy != nil {
		effects++
		if ValidateGroupCoordinationPolicy(*v.Policy) != nil || v.Policy.HubID != r.HubID {
			return ErrInvalid
		}
	}
	if v.Lock != nil {
		effects++
		if ValidateGroupLockReceipt(*v.Lock) != nil || v.Lock.Scope.HubID != r.HubID {
			return ErrInvalid
		}
	}
	if v.Read != nil {
		effects++
		if validateThreadCollaborationOwnerReadResult(*v.Read) != nil || v.Read.HubID != r.HubID {
			return ErrInvalid
		}
	}
	if v.Review != nil {
		effects++
		if v.Review.HubID != r.HubID || v.Review.OwnerID != r.OwnerID || v.Review.DeviceID != r.DeviceID {
			return ErrInvalid
		}
		if _, err := ThreadCollaborationOwnerReviewDigest(*v.Review); err != nil {
			return ErrInvalid
		}
	}
	switch v.State {
	case "COMPLETED":
		if effects != 1 || v.ErrorCode != "" || len(v.ReceiptPacket) != 0 {
			return ErrInvalid
		}
		switch r.Operation {
		case OperationThreadCollaborationOwnerRead:
			if v.Read == nil {
				return ErrInvalid
			}
		case OperationThreadCollaborationOwnerPrepare:
			if v.Review == nil {
				return ErrInvalid
			}
		case OperationThreadCollaborationOwnerApply:
			if v.Read != nil || v.Review != nil {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case "ORIGINAL_RECEIPT":
		p, err := DecodeThreadCollaborationOwnerPacket(v.ReceiptPacket)
		if effects != 0 || v.ErrorCode != "" || err != nil || p.Packet.Route.Direction != clientwire.DirectionResponse || p.Packet.Route.OperationID != v.OperationID || p.Packet.Route.HubID != r.HubID || p.Packet.Route.OwnerID != r.OwnerID || p.Packet.Route.DeviceID != r.DeviceID || (r.Operation != OperationThreadCollaborationOwnerStatus && r.Operation != OperationThreadCollaborationOwnerReconcile) {
			return ErrInvalid
		}
	case "REJECTED", "ORIGINAL_NOT_APPLIED", "ORIGINAL_OUTCOME_UNCERTAIN":
		if effects != 0 || len(v.ReceiptPacket) != 0 || v.ErrorCode == "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Verify the completed historical effect against the exact approved review.
// Status/reconcile return the retained response; open it with the original Apply
// before using this helper. A later current view is a separate observation.
func VerifyThreadCollaborationOwnerOperation(review ThreadCollaborationOwnerReview, apply ThreadCollaborationOwnerApplyRequest, original []byte, result ThreadCollaborationOwnerResult, hub HubIdentity) error {
	d, err := ThreadCollaborationOwnerReviewDigest(review)
	if err != nil || VerifyThreadCollaborationOwnerResult(apply, original, result, hub) != nil || result.State != "COMPLETED" || apply.Body.ReviewID != review.ReviewID || apply.Body.ReviewDigest != d || review.HubID != apply.Context.HubID || review.OwnerID != apply.Context.OwnerID || review.DeviceID != apply.Context.DeviceID {
		return ErrInvalid
	}
	b := review.Prepared
	switch b.Action {
	case ThreadCollaborationSetClassification:
		want, got := b.Role, result.Thread
		if got == nil || got.NetworkID != want.NetworkID || got.NodeID != want.NodeID || got.EndpointID != want.EndpointID || got.Source != want.Source || got.RegistrationDigest != want.RegistrationDigest || got.Classification != want.Classification || got.ClassificationRevision != want.ExpectedClassificationRevision+1 || got.RelationsRevision != want.ExpectedRelationsRevision {
			return ErrInvalid
		}
	case ThreadCollaborationCreateGroupWithPolicy, ThreadCollaborationEnableGroupPolicy, ThreadCollaborationRevokeGroupPolicy:
		want, got := b.Policy, result.Policy
		state := "ENABLED"
		if b.Action == ThreadCollaborationRevokeGroupPolicy {
			state = "REVOKED"
		}
		if got == nil || got.NetworkID != want.NetworkID || got.GroupID != review.TargetGroupID || got.State != state || got.Revision != want.ExpectedPolicyRevision+1 || got.OwnerConsentDigest != result.OriginalPacketDigest {
			return ErrInvalid
		}
	case ThreadCollaborationClearOneSlot:
		want, got := b.Clear, result.Lock
		if got == nil || got.Scope != want.Scope || got.Slot != want.Slot || got.Generation != want.Generation || got.AppliedVersion != want.ExpectedVersion+1 || got.Outcome != "OWNER_CLEARED" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validateThreadCollaborationOwnerReadResult(v ThreadCollaborationOwnerReadResult) error {
	if !validID(v.HubID) || !validID(v.NetworkID) || len(v.Threads) > MaxThreadCollaborationPageRows || !ownerEndpointGroupsCursor(v.NextCursor) {
		return ErrInvalid
	}
	if _, err := parseCanonicalUTC(v.ObservedAt); err != nil {
		return ErrInvalid
	}
	switch v.View {
	case "THREADS", "THREAD_SCOPE":
		if v.Group != nil || v.GroupPolicy != nil || v.GroupSlots != nil || v.View == "THREAD_SCOPE" && (len(v.Threads) != 1 || v.NextCursor != "") {
			return ErrInvalid
		}
		for _, t := range v.Threads {
			if ValidateThreadScopeView(t) != nil || t.HubID != "" && t.HubID != v.HubID || t.NetworkID != "" && t.NetworkID != v.NetworkID {
				return ErrInvalid
			}
		}
	case "GROUP_LOCKS":
		if v.Group == nil || !validID(v.Group.GroupID) || v.Group.NetworkID != v.NetworkID || !ownerEndpointGroupsName(v.Group.Name) || !threadCollaborationRevision(v.Group.GroupVersion) || len(v.Threads) != 0 || v.NextCursor != "" || (v.GroupPolicy == nil) != (v.GroupSlots == nil) {
			return ErrInvalid
		}
		if v.GroupPolicy != nil {
			p, s := v.GroupPolicy, v.GroupSlots
			if ValidateGroupCoordinationPolicy(*p) != nil || ValidateGroupSlotView(*s) != nil || p.HubID != v.HubID || p.NetworkID != v.NetworkID || p.GroupID != v.Group.GroupID || s.Scope != (GroupLockScope{p.HubID, p.NetworkID, p.GroupID}) || s.ObservedAt != v.ObservedAt || s.PolicyRevision != p.Revision || s.PolicyState != p.State {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxThreadCollaborationPageBytes {
		return ErrInvalid
	}
	return nil
}

// Must follow successful OpenThreadCollaborationOwnerResponse. This adds typed
// original-body/receipt correlation; it is not a substitute for PQC opening.
func VerifyThreadCollaborationOwnerResult(q any, original []byte, result ThreadCollaborationOwnerResult, hub HubIdentity) error {
	if ValidateThreadCollaborationOwnerRequest(q, hub, time.Time{}) != nil {
		return ErrInvalid
	}
	op, _, c, _, _, b := threadCollaborationOwnerParts(q)
	p, err := DecodeThreadCollaborationOwnerPacket(original)
	if err != nil || p.Packet.Route.Operation != op || p.Packet.Route.OperationID != c.RequestID || result.RequestPacketDigest != ThreadCollaborationOwnerPacketDigest(original) || validateThreadCollaborationOwnerResponse(result, p.Packet.Route) != nil {
		return ErrInvalid
	}
	wantID, wantDigest := c.RequestID, ThreadCollaborationOwnerPacketDigest(original)
	switch body := b.(type) {
	case ThreadCollaborationOwnerStatusBody:
		wantID, wantDigest = body.OperationID, body.OriginalPacketDigest
	case ThreadCollaborationOwnerReconcileBody:
		p, e := DecodeThreadCollaborationOwnerPacket(body.OriginalPacket)
		if e != nil {
			return ErrInvalid
		}
		wantID, wantDigest = p.Packet.Route.OperationID, ThreadCollaborationOwnerPacketDigest(body.OriginalPacket)
	case ThreadCollaborationOwnerReadBody:
		if result.Read != nil && (result.Read.HubID != c.HubID || result.Read.NetworkID != body.NetworkID || result.Read.View != body.View || result.Read.Group != nil && result.Read.Group.GroupID != body.GroupID || result.Read.GroupSlots != nil && result.Read.GroupSlots.Scope.GroupID != body.GroupID) {
			return ErrInvalid
		}
		if result.Read != nil && body.View == "THREAD_SCOPE" && (result.Read.Threads[0].NodeID != body.NodeID || result.Read.Threads[0].EndpointID != body.EndpointID && result.Read.Threads[0].State != "NETWORK_CONFLICT") {
			return ErrInvalid
		}
	case ThreadCollaborationOwnerPrepareBody:
		if result.Review != nil && (result.Review.HubID != c.HubID || result.Review.OwnerID != c.OwnerID || result.Review.DeviceID != c.DeviceID || result.Review.PrepareRequestID != c.RequestID || result.Review.PreparePacketDigest != wantDigest || !reflect.DeepEqual(result.Review.Prepared, body)) {
			return ErrInvalid
		}
	}
	if result.OperationID != wantID || result.OriginalPacketDigest != wantDigest {
		return ErrInvalid
	}
	return nil
}
