package appcore

import (
	"errors"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Values here are transient verified plaintext. Only encrypted raw replies and
// bounded state/review metadata are retained in the vault.
type pairReceipt struct {
	Bootstrap *wire.NativePairBootstrapChallenge
	Fence     *wire.NativePairBootstrapFence
	Rejection *wire.NativePairRejectionFence
	Plan      *wire.NativePairPlanChallenge
	Result    *wire.NativePairResult
	Recovery  *wire.NativePairReconciled
	Nested    *pairReceipt
}

func (v pairReceipt) pairID() string {
	switch {
	case v.Bootstrap != nil:
		return v.Bootstrap.Bootstrap.PairID
	case v.Plan != nil:
		return v.Plan.Plan.PairID
	case v.Rejection != nil:
		return v.Rejection.PairID
	case v.Result != nil:
		return v.Result.PairID
	case v.Recovery != nil:
		return v.Recovery.PairID
	}
	return ""
}

func (c *nativeController) openPairReceipt(request *pairRequestRecord, raw []byte, original *pairRequestRecord) (pairReceipt, error) {
	var v pairReceipt
	if c.device == nil || request == nil || len(raw) == 0 {
		return v, ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return v, err
	}
	open := func(out any) error { return wire.OpenClientResponse(device, c.hub, request.Packet, raw, out) }
	openRejection := func() (*wire.NativePairRejectionFence, error) {
		var fence wire.NativePairRejectionFence
		body, err := pairMutationDTO(request)
		if err != nil || request.Target.PairID == "" || open(&fence) != nil ||
			wire.ValidateNativePairRejectionTarget(fence, body, request.Packet) != nil {
			return nil, wire.ErrInvalid
		}
		return &fence, nil
	}
	var digest string
	switch request.Route.Operation {
	case wire.OperationNativePairBootstrapPrepare:
		var challenge wire.NativePairBootstrapChallenge
		if open(&challenge) == nil {
			v.Bootstrap, digest = &challenge, challenge.RequestPacketDigest
		} else {
			var fence wire.NativePairBootstrapFence
			if open(&fence) != nil {
				return v, wire.ErrInvalid
			}
			v.Fence, digest = &fence, fence.RequestPacketDigest
		}
	case wire.OperationNativePairConsentPrepare:
		var plan wire.NativePairPlanChallenge
		if open(&plan) == nil {
			v.Plan, digest = &plan, plan.RequestPacketDigest
		} else {
			// Only the dedicated authenticated no-effect fence may replace a
			// plan; it must bind this original typed Owner proof and packet.
			fence, err := openRejection()
			if err != nil {
				return v, wire.ErrInvalid
			}
			v.Rejection, digest = fence, fence.RequestPacketDigest
		}
	case wire.OperationNativePairReconcile:
		if original == nil {
			return v, ErrInvalidAction
		}
		var result wire.NativePairReconciled
		if open(&result) != nil || wire.ValidateNativePairReconcileTarget(result, original.Target.PairID, original.Packet) != nil {
			return v, wire.ErrInvalid
		}
		v.Recovery, digest = &result, result.RequestPacketDigest
		if len(result.ReceiptPacket) != 0 {
			nested, err := c.openPairReceipt(original, result.ReceiptPacket, nil)
			if err != nil || nested.pairID() != result.PairID {
				return v, wire.ErrInvalid
			}
			fenced := nested.Fence != nil || nested.Rejection != nil
			if (result.State == "REJECTED_FENCED") != fenced {
				return v, wire.ErrInvalid
			}
			v.Nested = &nested
		}
	default:
		if wire.NativePairHTTPPath(request.Route.Operation) == "" {
			return v, ErrInvalidAction
		}
		var result wire.NativePairResult
		if open(&result) == nil {
			if result.Outcome == "REJECTED_FENCED" {
				return v, wire.ErrInvalid
			}
			v.Result, digest = &result, result.RequestPacketDigest
		} else {
			fence, err := openRejection()
			if err != nil {
				return v, err
			}
			v.Rejection, digest = fence, fence.RequestPacketDigest
		}
	}
	if digest != request.Digest {
		return pairReceipt{}, errors.New("native pair receipt does not match its original request")
	}
	if request.Target.PairID != "" && v.pairID() != request.Target.PairID {
		return pairReceipt{}, errors.New("native pair receipt identifies another pair")
	}
	return v, nil
}

func pairMutationDTO(r *pairRequestRecord) (any, error) {
	var body any
	switch r.Route.Operation {
	case wire.OperationNativePairBootstrapComplete:
		body = new(wire.NativePairBootstrapComplete)
	case wire.OperationNativePairConsentPrepare:
		body = new(wire.NativePairConsentPrepare)
	case wire.OperationNativePairConsentComplete:
		body = new(wire.NativePairConsentComplete)
	case wire.OperationNativePairSlotReject:
		body = new(wire.NativePairSlotReject)
	case wire.OperationNativePairRevoke:
		body = new(wire.NativePairRevoke)
	default:
		return nil, wire.ErrInvalid
	}
	if decodeStateJSON(r.DTO, body) != nil {
		return nil, wire.ErrInvalid
	}
	return body, nil
}

func (c *nativeController) storePairResponse(index int, request *pairRequestRecord, raw []byte, original *pairRequestRecord) (pairReceipt, error) {
	var empty pairReceipt
	recovery := index == pairRecoveryResponseRecord
	if index != pairOriginalResponseRecord && !recovery {
		return empty, ErrInvalidAction
	}
	if err := c.validatePairRequest(request, original); err != nil {
		return empty, err
	}
	record := pairResponseRecord{Format: "cicada.native-pair.response.v1", Target: request.Target,
		RequestRoute: request.Route, RequestDigest: request.Digest, Packet: raw}
	if err := validatePairResponseLink(&record, request, recovery); err != nil {
		return empty, err
	}
	receipt, err := c.openPairReceipt(request, raw, original)
	if err != nil {
		return empty, err
	}
	if err := c.persistPairRecord(index, record); err != nil {
		return empty, err
	}
	record.Packet = append([]byte(nil), raw...)
	if recovery {
		c.pairRecoveryResponse = &record
	} else {
		c.pairOriginalResponse = &record
	}
	// Returning verified plaintext only after CAS succeeds prevents memory-only
	// continuation. Applying the business outcome is a separate idempotent step.
	return receipt, nil
}
