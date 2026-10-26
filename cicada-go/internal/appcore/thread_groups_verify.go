package appcore

import (
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) validateThreadGroupTarget(r *threadGroupRecord, request any) error {
	switch q := request.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		if q.Body.NodeID != r.NodeID || q.Body.NetworkID != r.NetworkID {
			return wire.ErrInvalid
		}
	case wire.OwnerEndpointGroupsPrepareRequest:
		if q.Body.NodeID != r.NodeID || q.Body.NetworkID != r.NetworkID || r.Binding == nil || r.Binding.NodeID != r.NodeID {
			return wire.ErrInvalid
		}
		if q.Body.Action != wire.OwnerEndpointGroupsCreateGroup {
			if r.Thread == nil || r.Thread.EndpointID != q.Body.EndpointID || r.Thread.NodeID != r.NodeID || r.Thread.NetworkID != r.NetworkID {
				return wire.ErrInvalid
			}
			if q.Body.Action == wire.OwnerEndpointGroupsAddEndpoint && (r.Group == nil || r.Group.GroupID != q.Body.GroupID || r.Group.NetworkID != r.NetworkID) {
				return wire.ErrInvalid
			}
			if q.Body.Action == wire.OwnerEndpointGroupsRemoveEndpoint && (r.Relation == nil || r.Relation.GroupID != q.Body.GroupID || r.Relation.NetworkID != r.NetworkID || r.ExpectedHead == nil || !reflect.DeepEqual(*r.ExpectedHead, r.Relation.OwnerControl)) {
				return wire.ErrInvalid
			}
		}
	case wire.OwnerEndpointGroupsApplyRequest:
		if r.Review == nil || q.Body.ReviewID != r.Review.ReviewID || q.Body.ReviewDigest != r.Review.ReviewDigest || q.Body.PreparePacketDigest != r.Review.RequestPacketDigest || c.verifyThreadGroupReviewTarget(r, *r.Review) != nil || !threadGroupReviewCASMatches(r, *r.Review) {
			return wire.ErrInvalid
		}
		if r.Review.Action == wire.OwnerEndpointGroupsAddEndpoint {
			policy, err := e2ee.VerifyOwnerEndpointGroupPolicy(c.owner.Public(), q.Body.PolicyProof, time.Time{})
			if err != nil || r.Review.Policy == nil || !reflect.DeepEqual(policy, *r.Review.Policy) {
				return wire.ErrInvalid
			}
		}
	}
	return nil
}

func (c *nativeController) verifyThreadGroupReviewTarget(r *threadGroupRecord, review wire.OwnerEndpointGroupsReview) error {
	t := review.Target
	if t.NodeID != r.NodeID || t.NetworkID != r.NetworkID || t.OwnerID != c.state.OwnerID || t.HubID != c.hub.HubID || r.Binding == nil || r.Binding.NodeID != r.NodeID {
		return wire.ErrInvalid
	}
	if review.Action == wire.OwnerEndpointGroupsCreateGroup {
		return nil
	}
	if r.LocalUserScope == "" || t.LocalUserScope != r.LocalUserScope {
		return wire.ErrInvalid
	}
	if r.Thread == nil || t.EndpointID != r.Thread.EndpointID || t.PrincipalID != r.Thread.PrincipalID || t.RegistrationDigest != r.Thread.RegistrationDigest {
		return wire.ErrInvalid
	}
	if review.Action == wire.OwnerEndpointGroupsAddEndpoint {
		if r.Group == nil || t.GroupID != r.Group.GroupID || review.Policy == nil || !reflect.DeepEqual(review.Policy.Node, *r.Binding) {
			return wire.ErrInvalid
		}
	} else if r.Relation == nil || r.ExpectedHead == nil || t.GroupID != r.Relation.GroupID {
		return wire.ErrInvalid
	}
	return nil
}

func threadGroupReviewCASMatches(r *threadGroupRecord, review wire.OwnerEndpointGroupsReview) bool {
	if review.Action == wire.OwnerEndpointGroupsCreateGroup {
		return true
	}
	if r.Thread == nil || review.Expected.RegistrationRevision != r.Thread.RegistrationRevision {
		return false
	}
	if review.Action == wire.OwnerEndpointGroupsAddEndpoint {
		return r.Group != nil && review.Expected.GroupVersion == r.Group.GroupVersion
	}
	return r.Relation != nil && review.Expected.DecisionRevision == r.Relation.DecisionRevision && review.Expected.RelationRevision == r.Relation.RelationRevision
}

func (c *nativeController) verifyThreadGroupResultTarget(record *threadGroupRecord, result *wire.OwnerEndpointGroupsResult, original *threadGroupRecord) error {
	if result.NodeID != record.NodeID {
		if result.NodeID == "" && c.verifiedThreadGroupOriginalFence(record, result) {
			return nil
		}
		if result.NodeID == "" && original != nil && record.Route.Operation == wire.OperationOwnerEndpointGroupsReconcile &&
			len(result.ReceiptPacket) != 0 && result.Operation == nil && result.Review == nil && result.CurrentRelation == nil && result.CurrentGroup == nil &&
			len(result.Threads)+len(result.Groups)+len(result.Relations) == 0 && result.ScopeActions == nil && result.RelationPage == nil && result.NextCursor == "" {
			// A wrapper cannot assert that an unseen apply had no effect. Open
			// and verify that exact original receipt independently first.
			nested, err := c.openThreadGroupResult(original, result.ReceiptPacket, nil)
			if err == nil && c.verifiedThreadGroupOriginalFence(original, nested) {
				return nil
			}
		}
		return wire.ErrInvalid
	}
	anchor := record
	if original != nil {
		anchor = original
	}
	if result.Review != nil {
		q, err := c.threadGroupDTO(record, nil)
		prepare, ok := q.(wire.OwnerEndpointGroupsPrepareRequest)
		if err != nil || !ok || wire.ValidateOwnerEndpointGroupsReview(prepare, record.Packet, *result.Review, c.hub, parseExpiry(result.Review.ObservedAt)) != nil || c.verifyThreadGroupReviewTarget(record, *result.Review) != nil {
			return wire.ErrInvalid
		}
	}
	if result.Operation != nil {
		if anchor.Review == nil || wire.VerifyOwnerEndpointGroupsOperation(*anchor.Review, anchor.Packet, *result.Operation, anchor.ExpectedHead) != nil {
			return wire.ErrInvalid
		}
	}
	if result.CurrentRelation != nil {
		if anchor.Review == nil || anchor.Review.Action == wire.OwnerEndpointGroupsCreateGroup || result.CurrentRelation.GroupID != anchor.Review.Target.GroupID || result.CurrentRelation.NetworkID != anchor.NetworkID {
			return wire.ErrInvalid
		}
	}
	if result.CurrentGroup != nil {
		if anchor.Review == nil || result.CurrentGroup.GroupID != anchor.Review.Target.GroupID || result.CurrentGroup.NetworkID != anchor.NetworkID {
			return wire.ErrInvalid
		}
	}
	return nil
}

func (c *nativeController) verifiedThreadGroupOriginalFence(record *threadGroupRecord, result *wire.OwnerEndpointGroupsResult) bool {
	if record == nil || result == nil || record.Route.Operation != wire.OperationOwnerEndpointGroupsApply {
		return false
	}
	request, err := c.threadGroupDTO(record, nil)
	apply, ok := request.(wire.OwnerEndpointGroupsApplyRequest)
	return err == nil && ok && wire.VerifyOwnerEndpointGroupsOriginalFence(apply, record.Packet, *result, c.hub) == nil
}
