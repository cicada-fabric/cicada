package appcore

import (
	"context"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) sendNewPair(ctx context.Context, scope e2ee.OwnerNativePairScope, id string, body any) error {
	if !c.pairAvailable || c.hasPairPending() || c.hasNodePending() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return ErrInvalidAction
	}
	if err := c.beginPairOriginal(scope, id, body); err != nil {
		if c.storageFault {
			return c.failPairStorage(err)
		}
		return c.failPair("APP_PAIR_REQUEST_INVALID", err)
	}
	c.publish()
	return c.sendPairOriginal(ctx, true)
}

func (c *nativeController) sendPairOriginal(ctx context.Context, fresh bool) error {
	if c.pairOriginal == nil || c.pairOriginal.Applied {
		return ErrInvalidAction
	}
	var receipt pairReceipt
	var err error
	if c.pairOriginalResponse != nil {
		receipt, err = c.openPairReceipt(c.pairOriginal, c.pairOriginalResponse.Packet, nil)
		fresh = false
	} else {
		raw, callErr := c.postPairPacket(ctx, c.pairOriginal)
		if callErr != nil {
			return c.failPair("APP_PAIR_REQUEST_UNKNOWN", callErr)
		}
		defer clear(raw)
		receipt, err = c.storePairResponse(pairOriginalResponseRecord, c.pairOriginal, raw, nil)
	}
	if err == nil {
		err = c.applyPairReceipt(receipt, fresh && ctx.Err() == nil)
	}
	if err != nil {
		if c.storageFault {
			return c.failPairStorage(err)
		}
		return c.failPair("APP_PAIR_RESPONSE_INVALID", err)
	}
	return nil
}

func (c *nativeController) recoverPair(ctx context.Context) error {
	if c.vault == nil || c.device == nil || !c.connected || !c.hasPairPending() {
		return ErrInvalidAction
	}
	c.pair.View.Current, c.pair.View.AdministrativePermission = false, false
	if c.pairOriginal != nil && c.pairOriginal.Applied {
		if err := c.finishPairOriginal(); err != nil {
			return c.failPairStorage(err)
		}
		return nil
	}
	if c.pairRecovery == nil {
		if c.pairOriginalResponse != nil {
			return c.sendPairOriginal(ctx, false)
		}
		if err := c.discoverPairAvailability(ctx); err != nil {
			return c.failPair("APP_PAIR_UNAVAILABLE", err)
		}
		// Exact historical retry first. An unsigned HTTP failure never
		// authorizes replacement or clearing the business original.
		if err := c.sendPairOriginal(ctx, false); err == nil {
			return nil
		}
		if c.storageFault || ctx.Err() != nil {
			return c.failPair("APP_PAIR_REQUEST_UNKNOWN", ctx.Err())
		}
		if err := c.beginPairRecovery(); err != nil {
			if c.storageFault {
				return c.failPairStorage(err)
			}
			return c.failPair("APP_PAIR_RECOVERY_INVALID", err)
		}
	}
	if c.pairRecoveryResponse == nil {
		// Renew only an expired detached diagnostic query. Its business
		// original, target and signature remain byte-for-byte unchanged.
		if !c.cfg.Now().UTC().Before(parseExpiry(c.pairRecovery.CreatedAt).Add(wire.MaxSessionRequestLifetime)) {
			if err := c.beginPairRecovery(); err != nil {
				if c.storageFault {
					return c.failPairStorage(err)
				}
				return c.failPair("APP_PAIR_RECOVERY_INVALID", err)
			}
		}
		if !c.pairAvailable {
			if err := c.discoverPairAvailability(ctx); err != nil {
				return c.failPair("APP_PAIR_UNAVAILABLE", err)
			}
		}
		raw, err := c.postPairPacket(ctx, c.pairRecovery)
		if err != nil {
			return c.failPair("APP_PAIR_REQUEST_UNKNOWN", err)
		}
		defer clear(raw)
		if _, err := c.storePairResponse(pairRecoveryResponseRecord, c.pairRecovery, raw, c.pairOriginal); err != nil {
			if c.storageFault {
				return c.failPairStorage(err)
			}
			return c.failPair("APP_PAIR_RESPONSE_INVALID", err)
		}
	}
	v, err := c.openPairReceipt(c.pairRecovery, c.pairRecoveryResponse.Packet, c.pairOriginal)
	if err != nil || v.Recovery == nil {
		return c.failPair("APP_PAIR_RECOVERY_INVALID", err)
	}
	if v.Nested != nil {
		if _, err := c.storePairResponse(pairOriginalResponseRecord, c.pairOriginal, v.Recovery.ReceiptPacket, nil); err != nil {
			if c.storageFault {
				return c.failPairStorage(err)
			}
			return c.failPair("APP_PAIR_RECOVERY_INVALID", err)
		}
		if err := c.applyPairReceipt(*v.Nested, false); err != nil {
			if c.storageFault {
				return c.failPairStorage(err)
			}
			return c.failPair("APP_PAIR_RESPONSE_INVALID", err)
		}
		return nil
	}
	if v.Recovery.State != "READ_EXPIRED" || c.pairOriginal.Route.Operation != wire.OperationNativePairStatus {
		return c.failPair("APP_PAIR_RECOVERY_UNRESOLVED", wire.ErrInvalid)
	}
	if err := c.finishPairOriginal(); err != nil {
		return c.failPairStorage(err)
	}
	return nil
}
