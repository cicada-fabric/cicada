package appcore

import (
	"context"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) recoverOperation(ctx context.Context) error {
	if c.state.Recovery != nil && c.state.Recovery.Operation == wire.OperationActivationStatus {
		return c.refreshActivation(ctx)
	}
	if c.state.Pending == nil || (len(c.state.Pending.Response) != 0 && c.state.Recovery == nil) {
		return ErrInvalidAction
	}
	if c.state.Recovery == nil {
		// An exact replay always precedes any reconciliation. A timeout or
		// unsigned HTTP rejection remains an observation, never a decision.
		if err := c.retry(ctx); err == nil {
			return c.afterRecovery(ctx)
		}
		if c.storageFault || ctx.Err() != nil {
			return errors.New("ACCOUNT_RESPONSE_UNKNOWN")
		}
	}
	op := c.state.Pending.Operation
	if op == wire.OperationActivationPrepare || op == wire.OperationActivationComplete {
		return c.refreshActivation(ctx)
	}
	if !wire.AccountReconcileOperationAllowed(op) {
		return errors.New("ACCOUNT_RESPONSE_UNKNOWN")
	}
	if err := c.queryRecovery(ctx, wire.OperationAccountReconcile, func() (any, error) {
		return wire.NewAccountReconcileRequest(c.hub, c.connection.Origin, c.connection.AccountID,
			c.connection.OwnerID, c.state.DeviceID, c.state.Pending.Request, c.cfg.Now().UTC())
	}); err != nil {
		return err
	}
	return c.afterRecovery(ctx)
}

func (c *nativeController) afterRecovery(ctx context.Context) error {
	if c.state.Pending != nil && len(c.state.Pending.Response) == 0 {
		return nil
	}
	if c.session != nil && c.sessionNeedsCheck {
		if err := c.inspectSession(ctx); err != nil {
			return err
		}
	}
	if c.state.Enrollment != nil && c.state.Enrollment.Target != nil && c.canBeginOperation() {
		return c.refreshActivation(ctx)
	}
	return nil
}

func (c *nativeController) refreshActivation(ctx context.Context) error {
	e := c.state.Enrollment
	if e == nil || e.Target == nil || c.device == nil {
		return ErrInvalidAction
	}
	if c.state.Pending != nil && len(c.state.Pending.Response) == 0 &&
		c.state.Pending.Operation != wire.OperationActivationPrepare && c.state.Pending.Operation != wire.OperationActivationComplete {
		return ErrInvalidAction
	}
	return c.queryRecovery(ctx, wire.OperationActivationStatus, func() (any, error) {
		packet, err := wire.DecodePacket(e.Target.Request)
		if err != nil {
			return nil, err
		}
		return wire.NewActivationStatusRequest(c.hub, c.connection.Origin, c.connection.AccountID,
			c.connection.OwnerID, e.Material.ActivationID, c.state.DeviceID, e.Target.Operation,
			packet.Packet.Route.OperationID, wire.ActivationPacketDigest(e.Target.Request), c.cfg.Now().UTC())
	})
}

func (c *nativeController) queryRecovery(ctx context.Context, operation string, build func() (any, error)) error {
	if c.state.Recovery != nil {
		old := c.state.Recovery
		if old.Operation == wire.OperationActivationStatus {
			// Exact retries recover history even when the cached observation
			// is only milliseconds old. Only a new query can confirm access.
			c.activationStatusRequestID = ""
			c.authorizationChecked = false
		}
		if len(old.Response) != 0 {
			if err := c.applyRecovery(); err != nil {
				return c.failStorage("APP_RECOVERY_RECEIPT_INVALID", err)
			}
		} else {
			err := c.sendRecovery(ctx)
			if err != nil && (c.cfg.Now().UTC().Sub(parseExpiry(old.CreatedAt)) < 60*time.Second || c.storageFault || ctx.Err() != nil) {
				return err
			}
			if err != nil {
				// Expiry permits a new recovery observation, never replacement of
				// its business target. Retain bounded digests of expired queries.
				c.state.RecoveryHistory = append(c.state.RecoveryHistory, recoveryDigest{Operation: old.Operation,
					Digest: wire.ActivationPacketDigest(old.Request), CreatedAt: old.CreatedAt})
				if len(c.state.RecoveryHistory) > 8 {
					c.state.RecoveryHistory = c.state.RecoveryHistory[1:]
				}
				c.state.Recovery = nil
			}
		}
		if operation == wire.OperationAccountReconcile && (c.state.Pending == nil || len(c.state.Pending.Response) != 0) {
			return nil
		}
		if operation == wire.OperationActivationStatus && c.authorizationChecked {
			return nil
		}
	}
	body, err := build()
	if err != nil {
		return c.fail(PhaseUnavailable, "APP_RECOVERY_REQUEST_INVALID", err)
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	packet, err := wire.SealClientRequest(device, c.hub, body)
	if err != nil {
		return c.fail(PhaseUnavailable, "APP_RECOVERY_REQUEST_INVALID", err)
	}
	c.state.Recovery = &pendingOperation{Operation: operation, Request: packet, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	// The business receipt remains in Pending/Target. Keep the previous
	// completed recovery query as a bounded digest when publishing its successor.
	if prior := c.state.LastRecovery; prior != nil {
		c.state.RecoveryHistory = append(c.state.RecoveryHistory, recoveryDigest{Operation: prior.Operation, Digest: wire.ActivationPacketDigest(prior.Request), CreatedAt: prior.CreatedAt})
		if len(c.state.RecoveryHistory) > 8 {
			c.state.RecoveryHistory = c.state.RecoveryHistory[1:]
		}
		c.state.LastRecovery = nil
	}
	if operation == wire.OperationActivationStatus {
		decoded, _ := wire.DecodePacket(packet)
		c.activationStatusRequestID = decoded.Packet.Route.OperationID
		c.authorizationChecked = false
	}
	if err := c.persistState(); err != nil {
		return c.failStorage("APP_RECOVERY_COMMIT_FAILED", err)
	}
	c.publish()
	return c.sendRecovery(ctx)
}

func (c *nativeController) sendRecovery(ctx context.Context) error {
	r := c.state.Recovery
	if r == nil {
		return ErrInvalidAction
	}
	response, _, err := postAccountPacket(ctx, c.cfg.HTTP, c.connection.Origin, c.connection.Origin, r.Operation, r.Request)
	if err != nil {
		return c.fail(PhaseUnavailable, "APP_RECOVERY_RESPONSE_UNKNOWN", err)
	}
	defer clear(response)
	value, err := c.openPendingResponse(r.Operation, r.Request, response)
	if err != nil || c.validateRecoveryTarget(value) != nil {
		return c.fail(PhaseUnavailable, "APP_RECOVERY_RESPONSE_INVALID", err)
	}
	r.Response = append([]byte(nil), response...)
	if err := c.persistState(); err != nil {
		return c.failStorage("APP_RECOVERY_COMMIT_FAILED", err)
	}
	if err := c.applyRecovery(); err != nil {
		return c.failStorage("APP_RECOVERY_RECEIPT_INVALID", err)
	}
	return nil
}

func (c *nativeController) validateRecoveryTarget(value any) error {
	switch result := value.(type) {
	case *wire.AccountReconcileResult:
		if c.state.Pending == nil || wire.ValidateAccountReconcileTarget(*result, c.state.Pending.Request) != nil ||
			result.AccountID != c.connection.AccountID || result.Origin != c.connection.Origin {
			return ErrInvalidAction
		}
	case *wire.ActivationResult:
		if c.state.Enrollment == nil || c.state.Enrollment.Target == nil ||
			wire.ValidateActivationStatusTarget(*result, c.state.Enrollment.Target.Request) != nil ||
			result.AccountID != c.connection.AccountID || result.Origin != c.connection.Origin ||
			result.ActivationID != c.state.Enrollment.Material.ActivationID {
			return ErrInvalidAction
		}
	default:
		return ErrInvalidAction
	}
	return nil
}

func (c *nativeController) applyRecovery() error {
	r := c.state.Recovery
	if r == nil || len(r.Response) == 0 {
		return ErrInvalidAction
	}
	value, err := c.openPendingResponse(r.Operation, r.Request, r.Response)
	if err != nil || c.validateRecoveryTarget(value) != nil {
		return errors.New("recovery target mismatch")
	}
	var state string
	var receipt []byte
	switch result := value.(type) {
	case *wire.AccountReconcileResult:
		state, receipt = result.State, result.ReceiptPacket
		c.observeEpochs(result.AccountEpoch, result.DeviceEpoch)
	case *wire.ActivationResult:
		state, receipt = result.TargetState, result.ReceiptPacket
	}
	if state == wire.ActivationCompleted {
		target := c.state.Pending
		if r.Operation == wire.OperationActivationStatus {
			target = c.state.Enrollment.Target
		}
		if target == nil || len(receipt) == 0 {
			return errors.New("accepted original receipt missing")
		}
		opened, err := c.openPendingResponse(target.Operation, target.Request, receipt)
		if err != nil {
			return errors.New("original receipt rejected")
		}
		// Both the authenticated recovery response and its original receipt
		// are committed before any restored session or proof is published.
		target.Response = append([]byte(nil), receipt...)
		if c.state.Pending != nil && wire.ActivationPacketDigest(c.state.Pending.Request) == wire.ActivationPacketDigest(target.Request) {
			c.state.Pending = target
			if err := c.persistState(); err != nil {
				return err
			}
			c.suppressPublish = true
			err := c.applyResponse(target.Operation, opened, target.Request, target.Response)
			c.suppressPublish = false
			if err != nil {
				return err
			}
		}
	} else if state == wire.ActivationRejected || state == wire.ActivationCancelled {
		// This transition requires a signed, target-bound durable tombstone.
		if r.Operation == wire.OperationAccountReconcile {
			keepChallenge := c.state.Pending != nil && c.state.Pending.Operation == wire.OperationLoginComplete &&
				c.state.LoginChallenge != nil && c.cfg.Now().UTC().Before(parseExpiry(c.state.LoginChallenge.ExpiresAt)) &&
				c.state.LoginChallenge.AccountEpoch == c.state.ObservedAccountEpoch && c.state.LoginChallenge.DeviceEpoch == c.state.ObservedDeviceEpoch
			if err := c.clearPersistedSession(); err != nil {
				return err
			}
			c.clearSession()
			if !keepChallenge {
				c.state.LoginChallenge = nil
			}
			c.state.AccountState = AccountStateLoginRequired
		}
		if c.state.Pending != nil && (r.Operation == wire.OperationAccountReconcile ||
			wire.ActivationPacketDigest(c.state.Pending.Request) == wire.ActivationPacketDigest(c.state.Enrollment.Target.Request)) {
			c.state.Pending = nil
		}
	} // ABSENT and other observations leave the original packet uncertain.
	if result, ok := value.(*wire.ActivationResult); ok {
		if err := c.applyActivationResult(result); err != nil {
			return err
		}
	}
	if c.session != nil && (c.session.AccountEpoch < c.state.ObservedAccountEpoch || c.session.DeviceEpoch < c.state.ObservedDeviceEpoch) {
		if err := c.clearPersistedSession(); err != nil {
			return err
		}
		c.clearSession()
		c.state.AccountState, c.state.RootState = AccountStateLoginRequired, RootStateUnknown
		c.authorizationChecked = false
	}
	c.state.LastRecovery, c.state.Recovery = r, nil
	if err := c.persistState(); err != nil {
		return err
	}
	c.snapshotMu.Lock()
	c.snapshot.ErrorCode = ""
	if state == wire.ActivationRejected || state == wire.ActivationCancelled {
		c.snapshot.ErrorCode = "ACCOUNT_REQUEST_REJECTED"
	}
	c.snapshotMu.Unlock()
	c.publish()
	return nil
}
