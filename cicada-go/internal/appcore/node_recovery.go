package appcore

import (
	"context"
	"errors"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) recoverNode(ctx context.Context) error {
	if c.hasOwnerEndpointPending() {
		return c.recoverOwnerEndpoints(ctx)
	}
	if c.device == nil || c.vault == nil || !c.connected || !c.hasNodePending() {
		return ErrInvalidAction
	}
	if !c.nodeAvailable {
		if err := c.discoverNodeAvailability(ctx); err != nil {
			return c.failNode("APP_NODE_UNAVAILABLE", err)
		}
	}
	c.nodeChecked, c.nodeContextChecked, c.nodeReadRequestID = false, false, ""
	if c.nodeRecovery == nil {
		if !c.node.Pending.unresolved() {
			return ErrInvalidAction
		}
		// Retry exactly the saved packet first, including a historical status.
		// An unsigned response never gives permission to replace its target.
		if err := c.sendNodePending(ctx, false); err == nil {
			return c.afterNodeRecovery(ctx)
		}
		if c.storageFault || ctx.Err() != nil {
			return errors.New("Node request remains unconfirmed")
		}
		p := c.node.Pending
		request, err := wire.NewAppNodeReconcile(c.nodeSession(), p.Kind, p.GrantID, p.Request, c.cfg.Now().UTC())
		if err != nil {
			return c.failNode("APP_NODE_RECOVERY_INVALID", err)
		}
		device, err := c.device.E2EE()
		if err != nil {
			return err
		}
		raw, err := wire.SealClientRequest(device, c.hub, request)
		if err != nil {
			return c.failNode("APP_NODE_RECOVERY_INVALID", err)
		}
		c.nodeRecovery = &nodeOperation{Kind: wire.AppNodeOriginalAuthority, Operation: wire.OperationAppNodeReconcile, GrantID: p.GrantID,
			Request: raw, CreatedAt: request.Context.IssuedAt}
		if err := c.persistNodeRecovery(); err != nil {
			return c.failStorage("APP_NODE_COMMIT_FAILED", err)
		}
		c.publish()
	}
	if len(c.nodeRecovery.Response) == 0 {
		raw, err := c.postNodePacket(ctx, c.nodeRecovery)
		if err != nil {
			return c.failNode("APP_NODE_REQUEST_UNKNOWN", err)
		}
		defer clear(raw)
		if _, err := c.openNodeReconciliation(raw); err != nil {
			return c.failNode("APP_NODE_RESPONSE_INVALID", err)
		}
		c.nodeRecovery.Response = append([]byte(nil), raw...)
		if err := c.persistNodeRecovery(); err != nil {
			return c.failStorage("APP_NODE_COMMIT_FAILED", err)
		}
	}
	if err := c.applyNodeReconciliation(); err != nil {
		return c.failNode("APP_NODE_RECOVERY_UNRESOLVED", err)
	}
	return c.afterNodeRecovery(ctx)
}

func (c *nativeController) openNodeReconciliation(raw []byte) (*wire.AppNodeReconcileResult, error) {
	if c.nodeRecovery == nil || c.node.Pending == nil {
		return nil, ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	var result wire.AppNodeReconcileResult
	p := c.node.Pending
	if wire.OpenClientResponse(device, c.hub, c.nodeRecovery.Request, raw, &result) != nil ||
		wire.ValidateAppNodeReconcileTarget(result, p.Kind, p.Request) != nil || result.Origin != c.connection.Origin ||
		result.HubID != c.connection.HubID || result.AccountID != c.connection.AccountID || result.OwnerID != c.connection.OwnerID || result.DeviceID != c.state.DeviceID || result.GrantID != p.GrantID {
		return nil, wire.ErrInvalid
	}
	return &result, nil
}

func (c *nativeController) applyNodeReconciliation() error {
	r, err := c.openNodeReconciliation(c.nodeRecovery.Response)
	if err != nil {
		return err
	}
	p := c.node.Pending
	switch r.State {
	case wire.AppNodeCompleted:
		if len(r.ReceiptPacket) == 0 || c.verifyNodeResponse(p, r.ReceiptPacket) != nil {
			return wire.ErrInvalid
		}
		p.Response = append([]byte(nil), r.ReceiptPacket...)
		if err := c.persistNode(); err != nil {
			return err
		}
		if err := c.applyNodeResponse(p, false); err != nil {
			return err
		}
	case wire.AppNodeRejectedFenced:
		// In particular, a Client fence supplies its original route's sealed
		// rejection. Only that receipt can advance the exact reserved counters.
		if len(r.ReceiptPacket) == 0 || c.verifyNodeResponse(p, r.ReceiptPacket) != nil {
			return wire.ErrInvalid
		}
		p.Response = append([]byte(nil), r.ReceiptPacket...)
		if err := c.persistNode(); err != nil {
			return err
		}
		if err := c.applyNodeResponse(p, false); err != nil {
			return err
		}
		p.Settlement = wire.AppNodeRejectedFenced
	case wire.AppNodeReadExpired:
		if p.Kind != wire.AppNodeOriginalAuthority || p.Operation != wire.OperationAppNodeStatus {
			return wire.ErrInvalid
		}
		p.Settlement = wire.AppNodeReadExpired
		p.Applied = true
	default:
		return errors.New("Node outcome has no authenticated receipt or fence")
	}
	if r.CurrentHeadVersion > c.node.HighestHead {
		c.node.HighestHead = r.CurrentHeadVersion
	}
	if err := c.observeNodeEpochs(r.AccountEpoch, r.DeviceEpoch); err != nil {
		return err
	}
	copy := *r
	copy.ReceiptPacket = nil
	c.node.Diagnostics = &copy
	c.node.LastSettlementDigest, c.node.LastSettlement = r.OriginalPacketDigest, r.State
	c.nodeChecked, c.nodeContextChecked, c.nodeReadRequestID = false, false, ""
	if err := c.persistNode(); err != nil {
		return err
	}
	c.nodeRecovery = nil
	if err := c.persistNodeRecovery(); err != nil {
		return err
	}
	c.nodeError = ""
	c.publish()
	return nil
}

func (c *nativeController) afterNodeRecovery(ctx context.Context) error {
	if c.hasNodePending() || !c.nodeAccountReady() || !c.canBeginOperation() {
		c.publish()
		return nil
	}
	if err := c.refreshNodeContext(ctx); err != nil {
		return err
	}
	if c.node.Grant != nil || (c.node.Proposal != nil && c.node.Proposal.Challenge != nil) {
		return c.refreshNode(ctx)
	}
	c.publish()
	return nil
}
