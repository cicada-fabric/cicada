package appcore

import (
	"encoding/hex"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The local target and typed proof must describe the same request. Packet and
// DTO are sealed together in beginPairOriginal; neither is rewritten on retry.
func validatePairDTO(r *pairRequestRecord) error {
	var context wire.NativePairRequestContext
	var proof []byte
	if r.Route.Operation == wire.OperationNativePairStatus {
		var q wire.NativePairStatusRequest
		if decodeStateJSON(r.DTO, &q) != nil || q.PairID != r.Target.PairID || q.Format != wire.NativePairFormat {
			return wire.ErrInvalid
		}
		context = q.Context
	} else if r.Route.Operation == wire.OperationNativePairConsentComplete {
		var q wire.NativePairConsentComplete
		if decodeStateJSON(r.DTO, &q) != nil || q.Format != wire.NativePairFormat {
			return wire.ErrInvalid
		}
		context, proof = q.Context, q.OwnerProof
	} else {
		// These dedicated wire DTOs have the same fields; the route fixes the
		// expected proof purpose, so a proof cannot cross operation kinds.
		var q wire.NativePairBootstrapPrepare
		if wire.NativePairOwnerPurpose(r.Route.Operation) == "" || decodeStateJSON(r.DTO, &q) != nil || q.Format != wire.NativePairFormat {
			return wire.ErrInvalid
		}
		context, proof = q.Context, q.OwnerProof
	}
	a := r.Target.Scope.Actor
	if context.RequestID != r.Route.OperationID || context.Origin != a.Origin || context.HubID != a.HubID ||
		context.AccountID != a.AccountID || context.OwnerID != a.OwnerID || context.DeviceID != a.DeviceID || context.AccountSessionID != a.AccountSessionID ||
		context.AccountEpoch != a.AccountEpoch || context.DeviceEpoch != a.DeviceEpoch || context.ClientSessionEpoch != a.ClientSessionEpoch {
		return wire.ErrInvalid
	}
	if len(proof) != 0 {
		claims, err := e2ee.VerifyOwnerNativePair(a.OwnerPublic, proof, wire.NativePairOwnerPurpose(r.Route.Operation), time.Time{})
		if err != nil || !reflect.DeepEqual(claims.Scope, r.Target.Scope) || claims.RequestID != context.RequestID ||
			claims.Nonce != hex.EncodeToString(context.ClientNonce) || claims.IssuedAt != context.IssuedAt {
			return wire.ErrInvalid
		}
		id := ""
		switch {
		case claims.Bootstrap != nil:
			id = claims.Bootstrap.PairID
		case claims.Consent != nil:
			id = claims.Consent.PairID
		case claims.Reject != nil:
			id = claims.Reject.PairID
		case claims.Revoke != nil:
			id = claims.Revoke.PairID
		}
		if id != r.Target.PairID {
			return wire.ErrInvalid
		}
	} else if r.Route.Operation != wire.OperationNativePairStatus {
		return wire.ErrInvalid
	}
	return nil
}
