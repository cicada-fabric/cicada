package appcore

import (
	"bytes"
	"context"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) recoverScopedNode(ctx context.Context) error {
	if err := c.ensureScopedNodesLoaded(); err != nil {
		return err
	}
	p := c.scoped.original
	if p == nil || !c.nodeAccountReady() || c.hasNodePending() || c.hasPairPending() || c.hasLocalDomainPending() || c.hasThreadGroupPending() || c.state.Recovery != nil || !canBeginOperation(c.state.Pending) {
		return ErrInvalidAction
	}
	if p.Applied || len(p.Response) != 0 {
		if !p.Applied {
			if err := c.sendScopedPending(ctx, false); err != nil {
				return err
			}
		}
		if c.scoped.recovery != nil {
			if err := c.persistScopedFrame(scopedRecoverySlot, nil); err != nil {
				return err
			}
			c.scoped.recovery = nil
		}
		c.publish()
		return c.completeScopedAction(ctx)
	}
	if !c.scoped.available {
		if err := c.discoverScopedNodes(ctx); err != nil {
			return c.scopedRecoveryFailure()
		}
	}
	if c.scoped.recovery == nil {
		r, err := c.makeScopedRecovery(p)
		if err != nil {
			return err
		}
		if err := c.scopedBudget(p); err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_STORAGE_FULL")
		}
		if err := c.persistScopedFrame(scopedRecoverySlot, r); err != nil {
			return err
		}
		c.scoped.recovery = r
	}
	r := c.scoped.recovery
	if r.NodeID != p.NodeID || r.PairTrust != p.PairTrust || !r.Recovery {
		return wire.ErrInvalid
	}
	if len(r.Response) == 0 {
		if err := c.scopedBudget(p); err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_STORAGE_FULL")
		}
		raw, err := c.postScopedOriginal(ctx, r)
		if err != nil {
			return c.scopedRecoveryFailure()
		}
		defer clear(raw)
		if _, _, err := c.openScopedRecovery(r, p, raw); err != nil {
			return c.scopedRecoveryFailure()
		}
		copy := *r
		copy.Response = bytes.Clone(raw)
		if err := c.persistScopedFrame(scopedRecoverySlot, &copy); err != nil {
			return err
		}
		c.scoped.recovery = &copy
		r = &copy
	}
	receipt, terminal, err := c.openScopedRecovery(r, p, r.Response)
	if err != nil {
		return c.scopedRecoveryFailure()
	}
	if len(receipt) != 0 {
		if err := c.checkScopedResponse(p, receipt); err != nil {
			return c.scopedRecoveryFailure()
		}
		copy := *p
		copy.Response = bytes.Clone(receipt)
		if err := c.persistScopedFrame(scopedOriginalSlot, &copy); err != nil {
			return err
		}
		c.scoped.original = &copy
		if err := c.sendScopedPending(ctx, false); err != nil {
			return err
		}
	} else if terminal {
		copy := *p
		copy.Applied = true
		if err := c.persistScopedFrame(scopedOriginalSlot, &copy); err != nil {
			return err
		}
		c.scoped.original = &copy
		if f := c.scoped.flow; f != nil && p.PairTrust {
			f.Stage = wire.NodePairTrustScopedFenced
			f.LastError = "APP_NODE_PAIRING_UNKNOWN"
			if err := c.persistScopedFlow(); err != nil {
				return err
			}
		}
	} else {
		return c.scopedRecoveryFailure()
	}
	if err := c.persistScopedFrame(scopedRecoverySlot, nil); err != nil {
		return err
	}
	c.scoped.recovery = nil
	c.publish()
	return c.completeScopedAction(ctx)
}

func (c *nativeController) completeScopedAction(ctx context.Context) error {
	f := c.scoped.flow
	if f != nil && f.Stage == wire.NodePairTrustScopedACKed && !c.scopedPending() {
		n := c.scopedNode(f.NodeID)
		if n == nil || !n.CountersCommitted || n.Trust == nil || c.verifyStoredScopedTrust(n) != nil {
			return wire.ErrInvalid
		}
		// Exact successful receipts now live in the independent Node record.
		// Only settled shared work is retired; all CAS generations remain.
		c.scoped.flow = nil
		if err := c.persistScopedFlow(); err != nil {
			c.scoped.flow = f
			return err
		}
		if err := c.persistScopedFrame(scopedOriginalSlot, nil); err != nil {
			return err
		}
		if p := c.scoped.original; p != nil {
			clear(p.Body)
			clear(p.Packet)
			clear(p.Response)
		}
		c.scoped.original = nil
		clearScopedFlowSecrets(f)
	}
	if !c.scopedBusy() {
		c.initializeScopedNode(ctx)
		c.initializeLocalCollaboration(ctx)
		c.initializeThreadGroups(ctx)
	}
	c.publish()
	return nil
}

// Return receipt bytes only after authenticating both layers and matching the
// retained sender/Node/attempt/operation/digest. A raw HTTP error never reaches
// this settlement path. Empty terminal authority results are read expiry only.
func (c *nativeController) openScopedRecovery(r, p *scopedOriginal, raw []byte) ([]byte, bool, error) {
	device, err := c.device.E2EE()
	if err != nil {
		return nil, false, err
	}
	if p.PairTrust {
		body, err := c.scopedBody(r, p)
		if err != nil {
			return nil, false, err
		}
		q, ok := body.(*wire.NodePairTrustScopedReconcile)
		if !ok {
			return nil, false, wire.ErrInvalid
		}
		outer, err := wire.OpenNodePairTrustScopedResponse(device, c.hub, r.Packet, raw, q)
		if err != nil {
			return nil, false, err
		}
		if outer.State == wire.NodePairTrustScopedFenced && outer.ErrorCode == "FENCED" && outer.OriginalPacketDigest == "" && len(outer.OriginalReceipt) == 0 {
			return nil, true, nil
		}
		originalBody, err := c.scopedBody(p, nil)
		if err != nil {
			return nil, false, err
		}
		_, receipt, err := wire.OpenNodePairTrustScopedRecoveredResponse(device, c.hub, r.Packet, raw, *q, originalBody)
		return receipt, false, err
	}
	o, err := wire.OpenAppNodeScopedResponse(device, c.hub, r.Packet, raw)
	if err != nil || o.Reconciled == nil {
		return nil, false, wire.ErrInvalid
	}
	q := o.Reconciled
	if wire.ValidateAppNodeScopedReconcileTarget(*q, p.NodeID, wire.AppNodeScopedOriginalAuthority, p.Packet) != nil {
		return nil, false, wire.ErrInvalid
	}
	if len(q.ReceiptPacket) != 0 {
		return q.ReceiptPacket, false, nil
	}
	if q.State == wire.AppNodeScopedReadExpired && p.Operation == wire.OperationAppNodeScopedStatus {
		return nil, true, nil
	}
	return nil, false, wire.ErrInvalid
}
