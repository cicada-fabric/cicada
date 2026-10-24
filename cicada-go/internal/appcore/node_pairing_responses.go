package appcore

import (
	"bytes"
	"context"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) applyNodePairTrustResponse(fresh bool) error {
	t := c.node.PairTrust
	p := t.Pending
	if p == nil || p.Applied || len(p.Response) == 0 {
		return ErrInvalidAction
	}
	r, err := c.openNodePairTrustResponse(p, p.Response)
	if err != nil {
		return err
	}
	if r.ErrorCode != "" {
		if r.ErrorCode == "FENCED" && r.State == wire.NodePairTrustFenced {
			t.FencedOperation, t.FencedRequestDigest = p.Operation, wire.NodePairTrustPacketDigest(p.Request)
			p.Applied = true
			t.LastError = "APP_NODE_PAIRING_UNKNOWN"
			return c.persistNode()
		}
		if !pairTrustDefiniteRejection(r) {
			// A signed uncertainty is still uncertainty. Keep exact request,
			// consent, S and reserved confirmation; never start a new packet.
			p.Response = nil
			if err := c.persistNode(); err != nil {
				return err
			}
			return wire.ErrInvalid
		}
		t.Stage, t.LastError = r.State, "APP_NODE_PAIRING_REFUSED"
		p.Applied = true
		return c.persistNode()
	}
	switch p.Operation {
	case wire.OperationOwnerNodePairTrustLookup:
		t.Context, t.OOB = r.Context, r.OOBCommitment
		// A historical lookup can restore exact state, never fresh approval.
		at := c.cfg.Now().UTC()
		if !fresh {
			at = parseExpiry(r.Context.IssuedAt)
		}
		if err := c.matchNodePairTrust(at); err != nil {
			return err
		}
	case wire.OperationOwnerNodePairTrustPrepare:
		if r.Approval == nil || !reflect.DeepEqual(r.Approval.Scope, t.Scope) {
			return wire.ErrInvalid
		}
		t.Approval = r.Approval
	case wire.OperationOwnerNodePairTrustComplete:
		t.Stage = wire.NodePairTrustOwnerApproved
	case wire.OperationOwnerNodePairTrustStatus, wire.OperationOwnerNodePairTrustCancel:
		if r.State == wire.NodePairTrustACKed {
			if t.Approval == nil || r.Binding == nil || wire.ValidateNodePairTrustAccepted(*t.Context, *t.Approval, *r.Binding) != nil {
				return wire.ErrInvalid
			}
			if t.Context.Mode == wire.NodePairTrustInitial {
				confirmation := t.Confirmation
				if confirmation == nil || confirmation.GrantClaims == nil {
					return wire.ErrInvalid
				}
				device, err := c.device.E2EE()
				if err != nil {
					return err
				}
				reply, err := wire.OpenAppNodeConfirmationResponse(device, c.hub, *confirmation.GrantClaims, confirmation.Request, r.ConfirmationResponse, confirmation.ExpectedResponseSequence)
				if err != nil || !reply.OK || reply.Binding == nil || !reflect.DeepEqual(*reply.Binding, *r.Binding) {
					return wire.ErrInvalid
				}
				if len(confirmation.Response) != 0 && !bytes.Equal(confirmation.Response, r.ConfirmationResponse) {
					return wire.ErrInvalid
				}
				confirmation.Response = bytes.Clone(r.ConfirmationResponse)
				// Keep the authenticated exact receipt durable before original counters
				// or the immutable binding can advance, including after a process crash.
				if err := c.persistNode(); err != nil {
					return err
				}
				if !confirmation.Applied {
					if err := c.applyNodeConfirmation(confirmation); err != nil {
						return err
					}
				}
			}
			t.Stage = wire.NodePairTrustACKed
		} else if p.Operation == wire.OperationOwnerNodePairTrustStatus && r.State == wire.NodePairTrustPending && t.Stage == "REVIEW" {
			// Keep the original historical review, including when applying a
			// durable response after restart. Only fresh scope/deadline checks
			// can make this review available for a later explicit approval.
			t.Stage = "REVIEW"
		} else {
			t.Stage = r.State
		}
	default:
		return wire.ErrInvalid
	}
	p.Applied = true
	t.LastError = ""
	// An ACK is a durable binding fact. Fresh liveness/business permission must
	// still come from the existing separate authenticated Node status projection.
	c.nodeChecked = false
	return c.persistNode()
}
func (c *nativeController) recoverNodePairing(ctx context.Context) error {
	t := c.node.PairTrust
	if t == nil || c.device == nil || c.vault == nil || !c.connected {
		return ErrInvalidAction
	}
	c.pairTrustWorking = true
	defer func() { c.pairTrustWorking = false }()
	if c.hasNodePending() {
		if sameNodePairConfirmation(c.node.Pending, t.Confirmation) {
			// JSON restoration does not preserve aliases. Reconcile the exact
			// reserved original, never send it as an ordinary mutation.
			t.Confirmation = c.node.Pending
			if err := c.recoverReservedNodeConfirmation(ctx); err != nil {
				return err
			}
		} else if err := c.recoverNode(ctx); err != nil {
			return err
		}
	}

	if t.Recovery == nil && t.Pending != nil && !t.Pending.Applied {
		// Retry original bytes before creating a separate observation. Cached
		// results restore history; they never mint current permission or new S/X.
		if err := c.sendNodePairTrustPending(ctx, false); err != nil {
			if c.storageFault || ctx.Err() != nil {
				return err
			}
			if err := c.newNodePairTrustRecovery(); err != nil {
				return err
			}
		}
	}
	if t.Recovery != nil {
		if len(t.Recovery.Response) == 0 {
			body, err := c.nodePairTrustBody(t.Recovery)
			if err != nil {
				return err
			}
			issued := parseExpiry(body.(*wire.NodePairTrustReconcile).IssuedAt)
			if !c.cfg.Now().UTC().Before(issued.Add(time.Minute)) {
				// This is an expired observation, not the original mutation.
				// A fresh query observes the same immutable target. Any durable
				// old response is always opened first, regardless of age.
				if err := c.newNodePairTrustRecovery(); err != nil {
					return err
				}
			}
		}
		p := t.Recovery
		if len(p.Response) == 0 {
			raw, err := c.postNodePairTrust(ctx, p)
			if err != nil {
				return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
			}
			if _, err := c.openNodePairTrustResponse(p, raw); err != nil {
				clear(raw)
				return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
			}
			p.Response = raw
			if err := c.persistNodePairRecovery(); err != nil {
				return c.failStorage("APP_NODE_COMMIT_FAILED", err)
			}
		}
		body, err := c.nodePairTrustBody(p)
		if err != nil {
			return err
		}
		device, err := c.device.E2EE()
		if err != nil {
			return err
		}
		outer, err := c.openNodePairTrustResponse(p, p.Response)
		if err != nil {
			return err
		}
		if outer.ErrorCode == "FENCED" {
			// This exact packet had no effect. The attempt may still be RESERVED,
			// OWNER_APPROVED or ACKED: observe it before retrying or ending it.
			t.FencedOperation = t.Pending.Operation
			t.FencedRequestDigest = wire.NodePairTrustPacketDigest(t.Pending.Request)
			t.Pending.Applied = true
			t.LastError = "APP_NODE_PAIRING_UNKNOWN"
			if err := c.persistNode(); err != nil {
				return err
			}
		} else {
			oldBody, err := c.nodePairTrustBody(t.Pending)
			if err != nil {
				return err
			}
			_, raw, err := wire.OpenNodePairTrustRecoveredResponse(device, c.hub, p.Request, p.Response, *body.(*wire.NodePairTrustReconcile), oldBody)
			if err != nil {
				return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
			}
			t.Pending.Response = bytes.Clone(raw)
			if err := c.persistNode(); err != nil {
				return c.failStorage("APP_NODE_COMMIT_FAILED", err)
			}
			if !t.Pending.Applied {
				if err := c.applyNodePairTrustResponse(false); err != nil {
					if !c.storageFault && len(t.Pending.Response) == 0 {
						// An authenticated outer response can recover an uncertain
						// original error. That query has completed, but its target
						// stays pending; do not pin recovery to that error forever.
						t.Recovery = nil
						if saved := c.persistNodePairRecovery(); saved != nil {
							return saved
						}
					}
					return err
				}
			}
		}
		t.Recovery = nil
		if err := c.persistNodePairRecovery(); err != nil {
			return c.failStorage("APP_NODE_COMMIT_FAILED", err)
		}
	}
	if c.nodePairTrustPending() {
		c.publish()
		return nil
	}
	if t.FencedOperation != "" {
		if !c.nodeAccountReady() {
			c.publish()
			return nil
		}
		return c.observeFencedNodePairing(ctx)
	}
	if pairTrustTerminal(t.Stage) && t.Confirmation != nil && !t.Confirmation.Applied {
		if err := c.recoverReservedNodeConfirmation(ctx); err != nil {
			return err
		}
	}
	if !c.nodeAccountReady() {
		c.publish()
		return nil
	}
	if c.nodePairTrustNeedsCleanup() {
		return c.finishTerminalNodePairing(ctx)
	}
	if t.Stage == "LOOKUP" || t.Stage == "APPROVING" {
		return c.refreshNodePairing(ctx)
	}
	if t.Stage == wire.NodePairTrustOwnerApproved {
		return c.refreshNodePairing(ctx)
	}
	c.publish()
	return nil
}
func pairTrustTerminal(stage string) bool {
	return stage == wire.NodePairTrustExpired || stage == wire.NodePairTrustCancelled || stage == wire.NodePairTrustRevoked || stage == wire.NodePairTrustFenced
}

func pairTrustDefiniteRejection(r wire.NodePairTrustResult) bool {
	return r.ErrorCode == r.State && pairTrustTerminal(r.State)
}
func sameNodePairConfirmation(a, b *nodeOperation) bool {
	return a != nil && b != nil && a.Kind == b.Kind && a.Operation == b.Operation && a.GrantID == b.GrantID && a.ExpectedResponseSequence == b.ExpectedResponseSequence && bytes.Equal(a.Request, b.Request) && reflect.DeepEqual(a.GrantClaims, b.GrantClaims)
}

func (c *nativeController) recoverReservedNodeConfirmation(ctx context.Context) error {
	t := c.node.PairTrust
	if t == nil || t.Confirmation == nil {
		return ErrInvalidAction
	}
	p := t.Confirmation
	if p.Applied {
		return nil
	}
	if !pairTrustTerminal(t.Stage) && len(p.Response) == 0 {
		return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
	}
	if c.nodeRecovery == nil {
		request, err := wire.NewAppNodeReconcile(c.nodeSession(), p.Kind, p.GrantID, p.Request, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		device, err := c.device.E2EE()
		if err != nil {
			return err
		}
		raw, err := wire.SealClientRequest(device, c.hub, request)
		if err != nil {
			return err
		}
		c.node.Pending = p
		if err := c.persistNode(); err != nil {
			return err
		}
		c.nodeRecovery = &nodeOperation{Kind: wire.AppNodeOriginalAuthority, Operation: wire.OperationAppNodeReconcile, GrantID: p.GrantID, Request: raw, CreatedAt: request.Context.IssuedAt}
		if err := c.persistNodeRecovery(); err != nil {
			return err
		}
	}
	if err := c.recoverNode(ctx); err != nil {
		return err
	}
	// afterNodeRecovery may already have installed a later status request in
	// node.Pending. Retain this original object, not that replacement pointer.
	t.Confirmation = p
	return c.persistNode()
}

// A new outer query never dispatches or replaces the original target. Retain
// its exact bytes/digest and consent; only observation ID/nonce/time may change.
func (c *nativeController) newNodePairTrustRecovery() error {
	t := c.node.PairTrust
	if t == nil || t.Pending == nil || t.Pending.Applied || c.nodeRecovery != nil {
		return ErrInvalidAction
	}
	q := wire.NodePairTrustReconcile{Format: wire.NodePairTrustFormat, OriginalPacket: t.Pending.Request,
		OriginalPacketDigest: wire.NodePairTrustPacketDigest(t.Pending.Request), IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return err
	}
	raw, err := wire.SealNodePairTrustRequest(device, c.hub, wire.NodePairTrustPacket{Operation: wire.OperationNodePairTrustReconcile, RequestID: id, AttemptID: t.Code.AttemptID}, q, c.cfg.Now().UTC())
	if err != nil {
		return c.failNodePairing("APP_NODE_PAIRING_UNKNOWN")
	}
	body, digest, err := compactNodePairRecoveryBody(q)
	if err != nil {
		return err
	}
	previous := t.Recovery
	t.Recovery = &nodePairTrustOperation{Operation: wire.OperationNodePairTrustReconcile, Body: body, BodyDigest: digest, Request: raw}
	if !c.nodePairTrustFits(t.Recovery) {
		t.Recovery = previous
		clear(body)
		clear(raw)
		return c.failNodePairing("APP_NODE_PAIRING_STORAGE_FULL")
	}
	if err := c.persistNodePairRecovery(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	return nil
}
