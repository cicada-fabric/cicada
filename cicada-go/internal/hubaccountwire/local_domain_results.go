package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

// ValidateLocalDomainResultTarget follows authenticated envelope opening. It
// binds an Owner result to the exact local selector and independently pinned
// Owner key, including each row of a recovered Node policy-history page.
func ValidateLocalDomainResultTarget(request any, original []byte, result LocalDomainResult, hub HubIdentity) error {
	op, _, ctx, _, raw := localDomainParts(request)
	var proof e2ee.OwnerLocalDomainRequestProof
	if validateLocalDomainRequest(request, hub, time.Time{}) != nil || op == OperationLocalDomainReconcile ||
		decodeCanonical(raw, e2ee.MaxLocalDomainProofBytes, &proof) != nil || result.Operation != op || result.RequestID != ctx.RequestID || result.RequestPacketDigest != LocalDomainPacketDigest(original) ||
		validateLocalDomainResponse(result, clientwire.Route{Operation: op, OperationID: ctx.RequestID, HubID: ctx.HubID, OwnerID: ctx.OwnerID, DeviceID: ctx.DeviceID}) != nil {
		return ErrInvalid
	}
	if op == OperationLocalDomainPrepare && (result.State != AppNodeRejectedFenced || !result.NoEffect || result.PolicyID != "" || result.PolicyEpoch != 0 || result.Description != nil || result.NodeID != "" || len(result.Policies) != 0) {
		return ErrInvalid
	}
	if result.State != AppNodeCompleted {
		return nil
	}
	c := proof.Claims
	check := func(d LocalDomainDescription) bool {
		return ValidateLocalDomainDescription(d, hub, time.Time{}) == nil && d.Policy.OwnerID == c.Scope.OwnerID && reflect.DeepEqual(d.Policy.OwnerPublic, c.Scope.OwnerPublic)
	}
	if c.NodeID != "" {
		if result.NodeID != c.NodeID {
			return ErrInvalid
		}
		for _, d := range result.Policies {
			if !check(d) || d.Policy.PolicyID <= c.Cursor {
				return ErrInvalid
			}
		}
		return nil
	}
	if result.Description == nil || result.PolicyID != c.PolicyID || !check(*result.Description) {
		return ErrInvalid
	}
	if op != OperationLocalDomainStatus {
		digest, err := e2ee.LocalDomainPolicyDigest(result.Description.Policy)
		if err != nil || digest != c.PolicyDigest || result.PolicyEpoch != c.PolicyEpoch {
			return ErrInvalid
		}
		if (op == OperationLocalDomainActivate && result.Description.State != LocalDomainActive) || (op == OperationLocalDomainRevoke && result.Description.State != LocalDomainRevoked && result.Description.State != LocalDomainExpired) {
			return ErrInvalid
		}
	}
	return nil
}

// BuildLocalDomainStatusPage enforces both the row ceiling and canonical byte
// budget. The Store supplies sorted candidates beginning after the requested
// cursor. A first row that cannot fit is an error, never silently skipped.
func BuildLocalDomainStatusPage(base LocalDomainResult, candidates []LocalDomainDescription, more bool) (LocalDomainResult, error) {
	return buildLocalDomainStatusPage(base, candidates, more, MaxLocalDomainPageBytes)
}

func buildLocalDomainStatusPage(base LocalDomainResult, candidates []LocalDomainDescription, more bool, budget int) (LocalDomainResult, error) {
	if base.Operation != OperationLocalDomainStatus || base.State != AppNodeCompleted || !validID(base.NodeID) || base.Description != nil || len(base.Policies) != 0 || base.NextCursor != "" || len(candidates) > 65 || (more && len(candidates) == 0) || budget <= 0 || budget > MaxLocalDomainPageBytes {
		return LocalDomainResult{}, ErrInvalid
	}
	result := base
	for i, d := range candidates {
		if len(result.Policies) > 0 && result.Policies[len(result.Policies)-1].Policy.PolicyID >= d.Policy.PolicyID {
			return LocalDomainResult{}, ErrInvalid
		}
		if localDomainDescriptionShape(d) != nil || d.Policy.Node.NodeID != base.NodeID || d.Policy.HubID != base.HubID || d.Policy.OwnerID != base.OwnerID {
			return LocalDomainResult{}, ErrInvalid
		}
		if len(result.Policies) == 64 {
			result.NextCursor = result.Policies[len(result.Policies)-1].Policy.PolicyID
			break
		}
		previous := len(result.Policies)
		result.Policies = append(result.Policies, d)
		if more || i+1 < len(candidates) {
			result.NextCursor = d.Policy.PolicyID
		} else {
			result.NextCursor = ""
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return LocalDomainResult{}, ErrInvalid
		}
		if len(raw) > budget {
			result.Policies = result.Policies[:previous]
			if previous == 0 {
				return LocalDomainResult{}, ErrInvalid
			}
			result.NextCursor = result.Policies[previous-1].Policy.PolicyID
			break
		}
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > budget || validateLocalDomainResponse(result, clientwire.Route{Operation: base.Operation, OperationID: base.RequestID, HubID: base.HubID, OwnerID: base.OwnerID, DeviceID: base.DeviceID}) != nil {
		return LocalDomainResult{}, ErrInvalid
	}
	return result, nil
}
