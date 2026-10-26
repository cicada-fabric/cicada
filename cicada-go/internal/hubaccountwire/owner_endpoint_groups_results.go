package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func endpointGroupsContains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func endpointGroupsError(code string) bool {
	if code == OwnerEndpointGroupsOriginalNotAdmitted {
		return true
	}
	return code == "" || endpointGroupsContains([]string{"UNSUPPORTED_PROFILE", "OWNER_AUTHORITY_REQUIRED", "TARGET_NOT_AUTHORIZED", "REVIEW_EXPIRED", "CAS_CONFLICT", "KEY_NOT_READY", "OWNER_READD_REQUIRED", "ORIGINAL_PACKET_CONFLICT", "OUTCOME_UNCERTAIN", "GROUP_RELATION_LIMIT", "SHARED_MEMBERSHIP_CONFLICT", "CURSOR_STALE", "MANUAL_SOURCE_ALREADY_ACTIVE", "RELATION_PENDING"}, code)
}

func endpointGroupsActions(actions []string) bool {
	if !sort.StringsAreSorted(actions) {
		return false
	}
	for i, a := range actions {
		if !endpointGroupsContains([]string{OwnerEndpointGroupsCreateGroup, OwnerEndpointGroupsAddEndpoint, OwnerEndpointGroupsRemoveEndpoint}, a) || i > 0 && actions[i-1] == a {
			return false
		}
	}
	return true
}

func endpointGroupsState(state string) bool {
	return endpointGroupsContains([]string{"NONE", "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}, state)
}
func endpointGroupsKeyState(state string) bool {
	return endpointGroupsContains([]string{"NOT_READY", "PENDING", "CURRENT", "STALE", "REVOKED", "EXPIRED"}, state)
}
func endpointGroupsSource(source string) bool {
	return source == "DEFAULT_POLICY" || source == "OWNER_EXPLICIT"
}

func endpointGroupsSourceRef(r EndpointGroupSourceReference) bool {
	return endpointGroupsSource(r.Source) && validID(r.AuthorityID) && nativePairPositive(r.AuthorityEpoch) && nativePairPositive(r.ContributionRevision)
}

func endpointGroupsRelationCard(c OwnerEndpointGroupsRelationCard) bool {
	if !validID(c.GroupID) || !ownerEndpointGroupsName(c.GroupName) || !validID(c.NetworkID) || !endpointGroupsState(c.State) || c.RelationRevision >= 1<<63 || c.State != "NONE" && c.RelationRevision == 0 ||
		e2ee.ValidateEndpointGroupOwnerControl(c.OwnerControl) != nil || c.DecisionRevision != c.OwnerControl.Revision || c.ManualDeny != (c.OwnerControl.DenyReason != "NONE") ||
		len(c.Contributions) > 2 || !endpointGroupsKeyState(c.KeyState) || !endpointGroupsActions(c.AllowedActions) || len(c.UnavailableReason) > 128 ||
		c.ExpiresAt != "" && validateCanonicalTime(c.ExpiresAt) != nil {
		return false
	}
	effective := 0
	for i, s := range c.Contributions {
		ref := EndpointGroupSourceReference{s.Source, s.AuthorityID, s.AuthorityEpoch, s.ContributionRevision}
		if !endpointGroupsSourceRef(ref) || !endpointGroupsContains([]string{"PENDING_KEY", "ACTIVE", "REVOKED", "EXPIRED"}, s.State) || !endpointGroupsKeyState(s.KeyState) || len(s.UnavailableReason) > 128 ||
			s.ExpiresAt != "" && validateCanonicalTime(s.ExpiresAt) != nil || i > 0 && c.Contributions[i-1].Source >= s.Source {
			return false
		}
		if !s.Effective {
			continue
		}
		effective++
		if c.State != "ACTIVE" || s.State != "ACTIVE" || s.KeyState != "CURRENT" || c.KeyState != "CURRENT" || c.SelectedSource == nil || *c.SelectedSource != ref || c.ExpiresAt != s.ExpiresAt || c.ManualDeny {
			return false
		}
		if c.OwnerControl.Mode == "OWNER" {
			if s.Source != "OWNER_EXPLICIT" || s.AuthorityID != c.OwnerControl.PolicyID || s.AuthorityEpoch != c.OwnerControl.PolicyEpoch {
				return false
			}
		} else if s.Source != "DEFAULT_POLICY" {
			return false
		}
	}
	if c.State == "ACTIVE" {
		return effective == 1
	}
	if effective != 0 || c.SelectedSource != nil {
		return false
	}
	if c.OwnerControl.DenyReason == "REMOVED" && c.State != "REMOVED" || c.OwnerControl.DenyReason == "EXPIRED" && c.State != "EXPIRED" {
		return false
	}
	return true
}

func endpointGroupsGroupCard(c OwnerEndpointGroupsGroupCard) bool {
	return validID(c.GroupID) && ownerEndpointGroupsName(c.Name) && validID(c.NetworkID) && nativePairPositive(c.GroupVersion) && c.ContextPolicy == "group_scoped" && endpointGroupsActions(c.AllowedActions) && len(c.UnavailableReason) <= 128
}

func ownerEndpointGroupsEffect(o OwnerEndpointGroupsOperation) bool {
	e := o.Effect
	if e == nil || e.GroupID != o.Target.GroupID {
		return false
	}
	switch o.Action {
	case OwnerEndpointGroupsCreateGroup:
		return e.Created != nil && *e.Created && reflect.DeepEqual(*e, OwnerEndpointGroupsEffect{GroupID: e.GroupID, Created: e.Created})
	case OwnerEndpointGroupsAddEndpoint:
		if e.EndpointID != o.Target.EndpointID || e.RelationRevision == nil || !nativePairPositive(*e.RelationRevision) || e.DecisionRevision == nil || e.OwnerControl == nil ||
			e2ee.ValidateEndpointGroupOwnerControl(*e.OwnerControl) != nil || *e.DecisionRevision != e.OwnerControl.Revision || !isHex(e.PolicyID, 16) || !nativePairPositive(e.PolicyEpoch) || !nativePairPositive(e.ContributionRevision) ||
			e.ContributionState != "PENDING_KEY" || !endpointGroupsContains([]string{"PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}, e.EffectiveRelationState) {
			return false
		}
		if e.OwnerControl.DenyReason == "REMOVED" && e.EffectiveRelationState != "REMOVED" || e.OwnerControl.DenyReason == "EXPIRED" && e.EffectiveRelationState != "EXPIRED" ||
			e.EffectiveRelationState == "ACTIVE" && (e.OwnerControl.Mode != "DEFAULT" || e.OwnerControl.DenyReason != "NONE") {
			return false
		}
		return reflect.DeepEqual(*e, OwnerEndpointGroupsEffect{GroupID: e.GroupID, EndpointID: e.EndpointID, RelationRevision: e.RelationRevision, DecisionRevision: e.DecisionRevision, PolicyID: e.PolicyID, PolicyEpoch: e.PolicyEpoch, ContributionRevision: e.ContributionRevision, ContributionState: e.ContributionState, EffectiveRelationState: e.EffectiveRelationState, OwnerControl: e.OwnerControl})
	case OwnerEndpointGroupsRemoveEndpoint:
		if e.EndpointID != o.Target.EndpointID || e.RelationRevision == nil || !nativePairPositive(*e.RelationRevision) || e.DecisionRevision == nil || e.OwnerControl == nil ||
			e2ee.ValidateEndpointGroupOwnerControl(*e.OwnerControl) != nil || e.OwnerControl.Mode != "OWNER" || e.OwnerControl.DenyReason != "REMOVED" || *e.DecisionRevision != e.OwnerControl.Revision ||
			e.ManualDeny == nil || !*e.ManualDeny || e.RelationState != "REMOVED" || e.WithdrawnContributions == nil || *e.WithdrawnContributions == nil || len(*e.WithdrawnContributions) > 2 {
			return false
		}
		for i, s := range *e.WithdrawnContributions {
			if !endpointGroupsSourceRef(s) || i > 0 && (*e.WithdrawnContributions)[i-1].Source >= s.Source {
				return false
			}
		}
		return reflect.DeepEqual(*e, OwnerEndpointGroupsEffect{GroupID: e.GroupID, EndpointID: e.EndpointID, RelationRevision: e.RelationRevision, DecisionRevision: e.DecisionRevision, WithdrawnContributions: e.WithdrawnContributions, ManualDeny: e.ManualDeny, RelationState: e.RelationState, OwnerControl: e.OwnerControl})
	}
	return false
}

func ownerEndpointGroupsOperationShape(o OwnerEndpointGroupsOperation) bool {
	if !isHex(o.OperationID, 16) || !isHex(o.OriginalPacketDigest, 32) || !isHex(o.ReviewID, 16) || !ownerEndpointGroupsTargetValid(o.Target, o.Action) || validateCanonicalTime(o.CommittedAt) != nil || !endpointGroupsError(o.ErrorCode) {
		return false
	}
	if o.State == "REJECTED_FENCED" {
		return o.Effect == nil && o.ErrorCode != "" && o.ErrorCode != "OUTCOME_UNCERTAIN"
	}
	return o.State == "COMPLETED" && o.ErrorCode == "" && ownerEndpointGroupsEffect(o)
}

func validateOwnerEndpointGroupsResponse(body any, route clientwire.Route) error {
	r, ok := dereference(body).(OwnerEndpointGroupsResult)
	if !ok || !ownerEndpointGroupsOperation(route.Operation) || r.Format != OwnerEndpointGroupsResultFormat || r.ContractRevision != OwnerEndpointGroupsContractRevision ||
		r.RequestID != route.OperationID || r.HubID != route.HubID || r.OwnerID != route.OwnerID || r.DeviceID != route.DeviceID || !isHex(r.RequestPacketDigest, 32) ||
		!endpointGroupsContains([]string{"PREPARED", "COMPLETED", "REJECTED_FENCED", "READ_EXPIRED"}, r.State) || !endpointGroupsError(r.ErrorCode) || validateCanonicalTime(r.CapturedAt) != nil ||
		r.Freshness != "SNAPSHOT_ONLY" || !ownerEndpointGroupsCursor(r.NextCursor) || len(r.Threads)+len(r.Groups)+len(r.Relations) > 64 || len(r.ReceiptPacket) > MaxOwnerEndpointGroupsPacketBytes {
		return ErrInvalid
	}
	if r.ErrorCode == "OUTCOME_UNCERTAIN" && r.Operation != nil {
		return ErrInvalid
	}
	if route.Operation == OperationOwnerEndpointGroupsApply && (len(r.ReceiptPacket) != 0 || r.State == "COMPLETED" && r.ErrorCode == "" && r.Operation == nil) {
		return ErrInvalid
	}
	if route.Operation == OperationOwnerEndpointGroupsApply && r.Operation == nil {
		if r.State != "REJECTED_FENCED" || r.ErrorCode != OwnerEndpointGroupsOriginalNotAdmitted || !ownerEndpointGroupsTargetlessFence(r) {
			return ErrInvalid
		}
	}
	if route.Operation == OperationOwnerEndpointGroupsPrepare && r.State == "PREPARED" && r.ErrorCode == "" && r.Review == nil {
		return ErrInvalid
	}
	if r.State == "REJECTED_FENCED" && (r.ErrorCode == "" || r.ErrorCode == "OUTCOME_UNCERTAIN") {
		return ErrInvalid
	}
	if r.Review != nil && (route.Operation != OperationOwnerEndpointGroupsPrepare || ownerEndpointGroupsReviewShape(*r.Review) != nil) {
		return ErrInvalid
	}
	if r.Operation != nil && (!ownerEndpointGroupsOperationShape(*r.Operation) || r.Operation.Target.OwnerID != r.OwnerID || r.Operation.Target.HubID != r.HubID) {
		return ErrInvalid
	}
	if r.Operation == nil && (r.CurrentRelation != nil || r.CurrentGroup != nil) {
		return ErrInvalid
	}
	if r.NodeID != "" && !validID(r.NodeID) {
		return ErrInvalid
	}
	if route.Operation != OperationOwnerEndpointGroupsRead && (len(r.Threads) != 0 || len(r.Groups) != 0 || len(r.Relations) != 0 || r.ScopeActions != nil || r.RelationPage != nil || r.NextCursor != "") {
		return ErrInvalid
	}
	if r.Operation != nil {
		target := r.Operation.Target
		if r.NodeID != target.NodeID || r.CurrentRelation != nil && (r.CurrentRelation.GroupID != target.GroupID || r.CurrentRelation.NetworkID != target.NetworkID) ||
			r.CurrentGroup != nil && (r.CurrentGroup.GroupID != target.GroupID || r.CurrentGroup.NetworkID != target.NetworkID) {
			return ErrInvalid
		}
	}
	for i, t := range r.Threads {
		if !validID(t.EndpointID) || !validID(t.PrincipalID) || !validID(t.NodeID) || !validID(t.NetworkID) || !ownerEndpointGroupsText(t.Name, 256) || t.Harness != "codex" || !endpointGroupsContains([]string{"offline", "left", "LEASE_RECENT", "UNKNOWN"}, t.Presence) ||
			t.Workspace == "" || len(t.Workspace) > 1024 || !isHex(t.RegistrationDigest, 32) || !nativePairPositive(t.RegistrationRevision) || t.RelationsRevision >= 1<<63 || len(t.Relations) > 8 ||
			!ownerEndpointGroupsCursor(t.RelationsNextCursor) || t.RelationsComplete != (t.RelationsNextCursor == "") || !reflect.DeepEqual(t.RelationStates, []string{"NONE", "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}) || i > 0 && r.Threads[i-1].EndpointID >= t.EndpointID {
			return ErrInvalid
		}
		for j, c := range t.Relations {
			if !endpointGroupsRelationCard(c) || c.NetworkID != t.NetworkID || j > 0 && t.Relations[j-1].GroupID >= c.GroupID {
				return ErrInvalid
			}
		}
	}
	for i, g := range r.Groups {
		if !endpointGroupsGroupCard(g) || i > 0 && r.Groups[i-1].GroupID >= g.GroupID {
			return ErrInvalid
		}
	}
	for i, c := range r.Relations {
		if !endpointGroupsRelationCard(c) || i > 0 && r.Relations[i-1].GroupID >= c.GroupID {
			return ErrInvalid
		}
	}
	if r.ScopeActions != nil && (!validID(r.ScopeActions.NodeID) || !validID(r.ScopeActions.NetworkID) || !endpointGroupsActions(r.ScopeActions.AllowedActions) || len(r.ScopeActions.UnavailableReason) > 128) {
		return ErrInvalid
	}
	if r.RelationPage != nil && (!validID(r.RelationPage.EndpointID) || !validID(r.RelationPage.NetworkID) || r.RelationPage.RelationsRevision >= 1<<63 || !reflect.DeepEqual(r.RelationPage.States, []string{"NONE", "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}) || !ownerEndpointGroupsCursor(r.RelationPage.NextCursor) || r.RelationPage.Complete != (r.RelationPage.NextCursor == "")) {
		return ErrInvalid
	}
	if r.CurrentRelation != nil && !endpointGroupsRelationCard(*r.CurrentRelation) || r.CurrentGroup != nil && !endpointGroupsGroupCard(*r.CurrentGroup) {
		return ErrInvalid
	}
	if route.Operation == OperationOwnerEndpointGroupsRead {
		raw, err := json.Marshal(r)
		if err != nil || len(raw) > MaxOwnerEndpointGroupsPageBytes || r.State == "COMPLETED" && r.ErrorCode == "" && r.ScopeActions == nil {
			return ErrInvalid
		}
	}
	return nil
}

func ownerEndpointGroupsTargetlessFence(r OwnerEndpointGroupsResult) bool {
	return r.NodeID == "" && r.Operation == nil && r.Review == nil && len(r.Threads) == 0 && len(r.Groups) == 0 && len(r.Relations) == 0 && r.ScopeActions == nil && r.RelationPage == nil && r.NextCursor == "" && r.CurrentRelation == nil && r.CurrentGroup == nil && len(r.ReceiptPacket) == 0
}

// Call only after opening the nested ORIGINAL apply response with its retained
// original ciphertext. A wrapper error, missing row or timeout is never a fence.
func VerifyOwnerEndpointGroupsOriginalFence(q OwnerEndpointGroupsApplyRequest, original []byte, r OwnerEndpointGroupsResult, hub HubIdentity) error {
	if VerifyOwnerEndpointGroupsResult(q, original, r, hub) != nil || r.State != "REJECTED_FENCED" || r.ErrorCode != OwnerEndpointGroupsOriginalNotAdmitted || !ownerEndpointGroupsTargetlessFence(r) {
		return ErrInvalid
	}
	return nil
}

// This is historical receipt verification. It never redispatches the original
// request or turns a pending/absent operation into success.
func VerifyOwnerEndpointGroupsResult(request any, original []byte, result OwnerEndpointGroupsResult, hub HubIdentity) error {
	op, _, c, _, proofRaw, body := ownerEndpointGroupsParts(request)
	if ValidateOwnerEndpointGroupsRequest(request, hub, time.Time{}) != nil || validateOwnerEndpointGroupsResponse(result, clientwire.Route{Operation: op, OperationID: c.RequestID, HubID: c.HubID, OwnerID: c.OwnerID, DeviceID: c.DeviceID}) != nil || result.RequestPacketDigest != OwnerEndpointGroupsPacketDigest(original) {
		return ErrInvalid
	}
	packet, err := DecodeOwnerEndpointGroupsPacket(original)
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if err != nil || packet.Packet.Route.Direction != clientwire.DirectionRequest || packet.Packet.Route.Operation != op || packet.Packet.Route.OperationID != c.RequestID ||
		packet.Packet.Route.HubID != c.HubID || packet.Packet.Route.OwnerID != c.OwnerID || packet.Packet.Route.DeviceID != c.DeviceID || decodeCanonical(proofRaw, e2ee.MaxEndpointGroupProofBytes, &proof) != nil || !reflect.DeepEqual(packet.SenderPublicIdentity, proof.Claims.Scope.DevicePublic) {
		return ErrInvalid
	}
	if len(result.ReceiptPacket) != 0 {
		if op != OperationOwnerEndpointGroupsStatus && op != OperationOwnerEndpointGroupsReconcile {
			return ErrInvalid
		}
		receipt, err := DecodeOwnerEndpointGroupsPacket(result.ReceiptPacket)
		if err != nil || receipt.Packet.Route.Direction != clientwire.DirectionResponse || receipt.Packet.Route.HubID != c.HubID || receipt.Packet.Route.OwnerID != c.OwnerID || receipt.Packet.Route.DeviceID != c.DeviceID || !reflect.DeepEqual(receipt.SenderPublicIdentity, hub.Public) {
			return ErrInvalid
		}
		if b, ok := body.(OwnerEndpointGroupsStatusBody); ok && (receipt.Packet.Route.Operation != OperationOwnerEndpointGroupsApply || receipt.Packet.Route.OperationID != b.OperationID) {
			return ErrInvalid
		}
		if b, ok := body.(OwnerEndpointGroupsReconcileBody); ok {
			originalPacket, err := DecodeOwnerEndpointGroupsPacket(b.OriginalPacket)
			if err != nil || receipt.Packet.Route != responseRoute(originalPacket.Packet.Route) {
				return ErrInvalid
			}
		}
	}
	if b, ok := body.(OwnerEndpointGroupsReadBody); ok {
		if result.NodeID != b.NodeID || result.ScopeActions != nil && (result.ScopeActions.NodeID != b.NodeID || result.ScopeActions.NetworkID != b.NetworkID) {
			return ErrInvalid
		}
		for _, t := range result.Threads {
			if t.NodeID != b.NodeID || t.NetworkID != b.NetworkID || b.EndpointID != "" && t.EndpointID != b.EndpointID {
				return ErrInvalid
			}
		}
		for _, g := range result.Groups {
			if g.NetworkID != b.NetworkID {
				return ErrInvalid
			}
		}
		for _, r := range result.Relations {
			if r.NetworkID != b.NetworkID {
				return ErrInvalid
			}
		}
		if result.State == "COMPLETED" && result.ErrorCode == "" {
			switch b.View {
			case "THREADS":
				if len(result.Groups)+len(result.Relations) != 0 || result.RelationPage != nil {
					return ErrInvalid
				}
			case "CANDIDATE_GROUPS":
				if len(result.Threads)+len(result.Relations) != 0 || result.RelationPage != nil {
					return ErrInvalid
				}
			case "RELATIONS":
				if len(result.Threads)+len(result.Groups) != 0 || result.RelationPage == nil || result.RelationPage.EndpointID != b.EndpointID || result.RelationPage.NetworkID != b.NetworkID || result.RelationPage.NextCursor != result.NextCursor {
					return ErrInvalid
				}
			}
		}
	}
	if b, ok := body.(OwnerEndpointGroupsStatusBody); ok && result.Operation != nil && (result.Operation.OperationID != b.OperationID || result.Operation.OriginalPacketDigest != b.OriginalPacketDigest) {
		return ErrInvalid
	}
	if b, ok := body.(OwnerEndpointGroupsApplyBody); ok && result.Operation != nil && (result.Operation.OperationID != c.RequestID || result.Operation.OriginalPacketDigest != OwnerEndpointGroupsPacketDigest(original) || result.Operation.ReviewID != b.ReviewID) {
		return ErrInvalid
	}
	if b, ok := body.(OwnerEndpointGroupsReconcileBody); ok && result.Operation != nil {
		p, err := DecodeOwnerEndpointGroupsPacket(b.OriginalPacket)
		if err != nil || p.Packet.Route.Operation != OperationOwnerEndpointGroupsApply || result.Operation.OperationID != p.Packet.Route.OperationID || result.Operation.OriginalPacketDigest != OwnerEndpointGroupsPacketDigest(b.OriginalPacket) {
			return ErrInvalid
		}
	}
	return nil
}

// Verify an apply receipt against the locally retained, previously approved
// review as well as the exact apply ciphertext. Use alongside Result verification.
// REMOVE requires expectedHead from an authenticated relation card for the same
// target and decision revision, retained with the pending operation. Other
// actions may pass nil. It cannot be reconstructed from a new current snapshot.
func VerifyOwnerEndpointGroupsOperation(review OwnerEndpointGroupsReview, originalApply []byte, o OwnerEndpointGroupsOperation, expectedHead *e2ee.EndpointGroupOwnerControl) error {
	p, err := DecodeOwnerEndpointGroupsPacket(originalApply)
	if err != nil || ownerEndpointGroupsReviewShape(review) != nil || p.Packet.Route.Operation != OperationOwnerEndpointGroupsApply || p.Packet.Route.Direction != clientwire.DirectionRequest ||
		!ownerEndpointGroupsOperationShape(o) || o.OperationID != p.Packet.Route.OperationID || o.OriginalPacketDigest != OwnerEndpointGroupsPacketDigest(originalApply) || o.ReviewID != review.ReviewID ||
		o.Action != review.Action || !reflect.DeepEqual(o.Target, review.Target) || p.Packet.Route.HubID != review.Target.HubID || p.Packet.Route.OwnerID != review.Target.OwnerID {
		return ErrInvalid
	}
	if o.State == "COMPLETED" && o.Action == OwnerEndpointGroupsAddEndpoint {
		if review.Policy == nil || o.Effect.PolicyID != review.Policy.PolicyID || o.Effect.PolicyEpoch != review.Policy.Epoch || o.Effect.DecisionRevision == nil || *o.Effect.DecisionRevision != review.Expected.DecisionRevision ||
			!reflect.DeepEqual(o.Effect.OwnerControl, review.Projection.ExpectedOwnerControl) {
			return ErrInvalid
		}
	}
	if o.State == "COMPLETED" && (o.Action == OwnerEndpointGroupsAddEndpoint || o.Action == OwnerEndpointGroupsRemoveEndpoint) {
		if o.Effect.RelationRevision == nil || *o.Effect.RelationRevision != review.Expected.RelationRevision+1 {
			return ErrInvalid
		}
		if o.Action == OwnerEndpointGroupsRemoveEndpoint && (o.Effect.DecisionRevision == nil || *o.Effect.DecisionRevision != review.Expected.DecisionRevision+1) {
			return ErrInvalid
		}
	}
	if o.Action == OwnerEndpointGroupsRemoveEndpoint {
		if expectedHead == nil || e2ee.ValidateEndpointGroupOwnerControl(*expectedHead) != nil || expectedHead.Revision != review.Expected.DecisionRevision {
			return ErrInvalid
		}
		if o.State == "COMPLETED" {
			projected := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: expectedHead.Revision + 1, DenyReason: "REMOVED", PolicyID: expectedHead.PolicyID, PolicyEpoch: expectedHead.PolicyEpoch}
			if o.Effect.OwnerControl == nil || *o.Effect.OwnerControl != projected {
				return ErrInvalid
			}
		}
	}
	return nil
}
