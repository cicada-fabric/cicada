package appcore

import (
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) persistPairState() error {
	state := c.pair
	// Fresh admission is process-local. Restarted metadata cannot reactivate
	// buttons merely because an old receipt was successfully authenticated.
	state.View.Current, state.View.AdministrativePermission, state.View.Pending = false, false, false
	return c.persistPairRecord(pairStateRecord, state)
}

func (c *nativeController) pairReviewReceipt(live bool) (pairReceipt, error) {
	var empty pairReceipt
	if c.pairReview == nil {
		return empty, ErrInvalidAction
	}
	r := c.pairReview
	v, err := c.openPairReceipt(&r.Original, r.Response.Packet, nil)
	if err != nil {
		return empty, err
	}
	now := c.cfg.Now().UTC()
	if v.Bootstrap != nil {
		var q wire.NativePairBootstrapPrepare
		if decodeStateJSON(r.Original.DTO, &q) != nil {
			return empty, wire.ErrInvalid
		}
		if !live {
			now = parseExpiry(v.Bootstrap.Bootstrap.PreparedAt)
		}
		if wire.ValidateNativePairBootstrapTarget(q, r.Original.Packet, *v.Bootstrap, c.hub, now) != nil {
			return empty, wire.ErrInvalid
		}
	} else if v.Plan != nil {
		var q wire.NativePairConsentPrepare
		if decodeStateJSON(r.Original.DTO, &q) != nil {
			return empty, wire.ErrInvalid
		}
		if !live {
			now = parseExpiry(v.Plan.Plan.PreparedAt)
		}
		if wire.ValidateNativePairPlanTarget(q, r.Original.Packet, *v.Plan, c.pair.BootstrapProof, c.hub, now) != nil {
			return empty, wire.ErrInvalid
		}
	} else {
		return empty, ErrInvalidAction
	}
	return v, nil
}

func pairSlotView(slot *wire.NativePairSlot, state wire.NativePairSlotState, peer *wire.NativePairSlot) PairSlotSnapshot {
	v := PairSlotSnapshot{State: string(state), ConsentRecorded: state == wire.NativePairSlotConsentRecorded || state == wire.NativePairSlotActive}
	if slot != nil {
		v.Slot, v.Generation, v.NativeSessionID, v.CandidateFingerprint = slot.Slot, slot.Generation, slot.NativeSessionID, slot.CandidateFingerprint
		v.CandidateKeyID, v.CandidateVersion = slot.CandidatePublic.ID, slot.CandidateVersion
		v.EndpointID, v.PrincipalID, v.AttemptID = slot.EndpointID, slot.PrincipalID, slot.AttemptID
		v.BindingID, v.BindingEpoch = slot.BindingID, slot.BindingEpoch
		v.NetworkBindingID, v.NetworkEpoch = slot.NetworkAccessBindingID, slot.NetworkAccessEpoch
		v.NetworkMembership, v.EndpointNetwork = slot.NetworkMembershipRevision, slot.EndpointNetworkRevision
		v.MembershipRevision, v.EndpointJoinRevision = slot.MembershipRevision, slot.EndpointJoinRevision
		v.LeaseOwner, v.LeaseCeiling = slot.LeaseOwner, slot.LeaseCeiling
		v.TargetDigest, _ = wire.NativePairSlotDigest(*slot)
	}
	if peer != nil {
		v.PeerNativeSessionID = peer.NativeSessionID
	}
	return v
}

func (c *nativeController) applyPairReceipt(receipt pairReceipt, fresh bool) error {
	r := c.pairOriginal
	if r == nil {
		return ErrInvalidAction
	}
	if c.pair.Format == "" {
		c.pair = c.newPairState()
	}
	if c.pair.LastAppliedDigest == r.Digest {
		return c.finishPairOriginal()
	}
	// A rejection settles only the exact operation, never current authority.
	if receipt.Fence != nil || receipt.Rejection != nil {
		c.pairError = "APP_PAIR_REQUEST_FENCED"
		c.pair.View.Current, c.pair.View.AdministrativePermission = false, false
		c.pair.View.StateReviewID = ""
		return c.finishPairOriginal()
	}
	current := fresh && c.pairAccountReady()
	switch {
	case receipt.Bootstrap != nil:
		if err := c.preservePairReview(); err != nil {
			return err
		}
		if _, err := c.pairReviewReceipt(false); err != nil {
			return err
		}
		ch := receipt.Bootstrap
		if c.pair.View.PairID != ch.Bootstrap.PairID {
			clear(c.pair.BootstrapProof)
			c.pair.BootstrapProof = nil
		}
		c.pair.View = PairSetupSnapshot{PairID: ch.Bootstrap.PairID, NodeID: ch.Scope.Node.NodeID, Label: ch.Bootstrap.GroupLabel,
			State: string(wire.NativePairPrepared), ReviewID: wire.NativePairPacketDigest(c.pairReview.Response.Packet),
			ReviewExpiresAt: ch.ProofExpiresAt, JoinUntil: ch.Bootstrap.JoinUntil, PeerExpiresAt: ch.Bootstrap.PeerExpiresAt, ObservedAt: ch.ObservedAt}
		_, liveErr := c.pairReviewReceipt(true)
		c.pair.View.Current = current && c.freshObservation(ch.ObservedAt)
		c.pair.View.AdministrativePermission = c.pair.View.Current && liveErr == nil && c.pairScopeCurrent(ch.Scope)
	case receipt.Plan != nil:
		if err := c.preservePairReview(); err != nil {
			return err
		}
		if _, err := c.pairReviewReceipt(false); err != nil {
			return err
		}
		p := receipt.Plan.Plan
		previous, samePlan := c.pair.View.Slots, c.pair.View.ReviewID == p.Digest
		c.pair.View.ReviewID, c.pair.View.ReviewExpiresAt = p.Digest, p.ExpiresAt
		c.pair.View.Slots = [2]PairSlotSnapshot{pairSlotView(&p.SlotA, wire.NativePairSlotCandidateReady, &p.SlotB), pairSlotView(&p.SlotB, wire.NativePairSlotCandidateReady, &p.SlotA)}
		if samePlan {
			for i := range c.pair.View.Slots {
				if previous[i].TargetDigest == c.pair.View.Slots[i].TargetDigest && previous[i].ConsentRecorded {
					c.pair.View.Slots[i].ConsentRecorded = true
					c.pair.View.Slots[i].State = string(wire.NativePairSlotConsentRecorded)
				}
			}
		}
		c.pair.View.State, c.pair.View.PeerExpiresAt = string(wire.NativePairWaitingConsent), p.PeerExpiresAt
		c.pair.View.ControlRevision, c.pair.View.ObservedAt = p.ExpectedRevision, receipt.Plan.ObservedAt
		_, liveErr := c.pairReviewReceipt(true)
		c.pair.View.Current = current && c.freshObservation(receipt.Plan.ObservedAt)
		c.pair.View.AdministrativePermission = c.pair.View.Current && liveErr == nil && c.pairScopeCurrent(p.Scope)
	case receipt.Result != nil:
		result := receipt.Result
		if result.Outcome == "READ_EXPIRED" {
			if r.Route.Operation != wire.OperationNativePairStatus {
				return wire.ErrInvalid
			}
			c.pair.View.Current, c.pair.View.AdministrativePermission = false, false
			c.pair.View.StateReviewID = ""
			return c.finishPairOriginal()
		}
		if result.ControlRevision < c.pair.View.ControlRevision {
			c.pair.View.Current, c.pair.View.AdministrativePermission = false, false
			c.pair.View.StateReviewID = ""
			return c.finishPairOriginal()
		}
		if result.State == wire.NativePairActive && (result.SlotA == nil || result.SlotB == nil ||
			result.SlotAState != wire.NativePairSlotActive || result.SlotBState != wire.NativePairSlotActive ||
			result.SlotA.NativeSessionID == result.SlotB.NativeSessionID) {
			return wire.ErrInvalid
		}
		if err := validatePairResultSlots(*result, r.Target.Scope); err != nil {
			return err
		}
		if r.Route.Operation == wire.OperationNativePairBootstrapComplete {
			var q wire.NativePairBootstrapComplete
			if decodeStateJSON(r.DTO, &q) != nil || result.State != wire.NativePairWaitingJoin ||
				result.SlotAState != wire.NativePairSlotReserved || result.SlotBState != wire.NativePairSlotReserved {
				return wire.ErrInvalid
			}
			proof, err := e2ee.VerifyOwnerNativePair(r.Target.Scope.Actor.OwnerPublic, q.OwnerProof, e2ee.OwnerNativePairBootstrapCommit, time.Time{})
			if err != nil || result.PairID != proof.Bootstrap.PairID || result.PeerExpiresAt != proof.Bootstrap.PeerExpiresAt {
				return wire.ErrInvalid
			}
			c.pair.BootstrapProof = append([]byte(nil), q.OwnerProof...)
		}
		if r.Route.Operation == wire.OperationNativePairConsentComplete {
			review, err := c.pairReviewReceipt(false)
			if err != nil || review.Plan == nil || !pairResultMatchesConsentPlan(*result, review.Plan.Plan) ||
				result.PeerExpiresAt != review.Plan.Plan.PeerExpiresAt || (result.State != wire.NativePairWaitingConsent && result.State != wire.NativePairActive) ||
				result.State == wire.NativePairActive && (result.SlotAState != wire.NativePairSlotActive || result.SlotBState != wire.NativePairSlotActive) {
				return wire.ErrInvalid
			}
		}
		if r.Route.Operation == wire.OperationNativePairRevoke && result.State != wire.NativePairRevoked {
			return wire.ErrInvalid
		}
		if c.pair.View.NodeID != "" {
			for _, s := range []*wire.NativePairSlot{result.SlotA, result.SlotB} {
				if s != nil && s.NativeSessionID != "" && s.NodeID != c.pair.View.NodeID {
					return wire.ErrInvalid
				}
			}
		}
		c.pair.View.PairID, c.pair.View.State, c.pair.View.ControlRevision = result.PairID, string(result.State), result.ControlRevision
		c.pair.View.PeerExpiresAt, c.pair.View.ObservedAt = result.PeerExpiresAt, result.ObservedAt
		c.pair.View.Slots = [2]PairSlotSnapshot{pairSlotView(result.SlotA, result.SlotAState, result.SlotB), pairSlotView(result.SlotB, result.SlotBState, result.SlotA)}
		c.pair.View.Current = current && c.freshObservation(result.ObservedAt)
		c.pair.View.AdministrativePermission = c.pair.View.Current && result.AdministrativePermission
		c.pairCurrent = result
		if c.pair.View.Current {
			c.pair.View.StateReviewID = wire.NativePairPacketDigest(c.pairOriginalResponse.Packet)
		}
		if c.pairReview != nil && c.pairReview.Original.Route.Operation == wire.OperationNativePairConsentPrepare {
			review, err := c.pairReviewReceipt(false)
			if err != nil || review.Plan == nil || result.State != wire.NativePairWaitingConsent || result.SlotA == nil || result.SlotB == nil ||
				!reflect.DeepEqual(*result.SlotA, review.Plan.Plan.SlotA) || !reflect.DeepEqual(*result.SlotB, review.Plan.Plan.SlotB) {
				if err := c.clearPairReview(); err != nil {
					return err
				}
			}
		} else if result.State != wire.NativePairPrepared {
			if err := c.clearPairReview(); err != nil {
				return err
			}
		}
	default:
		return wire.ErrInvalid
	}
	c.pairError = ""
	return c.finishPairOriginal()
}

func (c *nativeController) clearPairReview() error {
	if c.pairReview != nil {
		if err := c.persistPairRecord(pairReviewRecordIndex, nil); err != nil {
			return err
		}
		clear(c.pairReview.Original.Packet)
		clear(c.pairReview.Original.DTO)
		clear(c.pairReview.Response.Packet)
		c.pairReview = nil
	}
	c.pair.View.ReviewID, c.pair.View.ReviewExpiresAt = "", ""
	return nil
}

func (c *nativeController) finishPairOriginal() error {
	if c.pairOriginal == nil {
		return ErrInvalidAction
	}
	c.pair.LastAppliedDigest = c.pairOriginal.Digest
	if err := c.persistPairState(); err != nil {
		return err
	}
	copy := *c.pairOriginal
	copy.Applied = true
	if err := c.persistPairRecord(pairOriginalRecord, copy); err != nil {
		return err
	}
	c.pairOriginal.Applied = true
	if c.pairRecoveryResponse != nil {
		if err := c.persistPairRecord(pairRecoveryResponseRecord, nil); err != nil {
			return err
		}
		clear(c.pairRecoveryResponse.Packet)
		c.pairRecoveryResponse = nil
	}
	if c.pairRecovery != nil {
		if err := c.persistPairRecord(pairRecoveryRecord, nil); err != nil {
			return err
		}
		clear(c.pairRecovery.Packet)
		c.pairRecovery = nil
	}
	c.publish()
	return nil
}

func pairResultMatchesConsentPlan(result wire.NativePairResult, plan wire.NativePairConsentPlan) bool {
	if result.SlotA == nil || result.SlotB == nil {
		return false
	}
	a, b := plan.SlotA, plan.SlotB
	if result.State == wire.NativePairActive {
		a.MembershipRevision, b.MembershipRevision = plan.ProjectedSlotAMembership, plan.ProjectedSlotBMembership
	}
	return reflect.DeepEqual(*result.SlotA, a) && reflect.DeepEqual(*result.SlotB, b)
}
