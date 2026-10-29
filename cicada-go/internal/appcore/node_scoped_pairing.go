package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/cicada-ai/cicada/internal/clientwire"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"reflect"
	"time"
)

func (c *nativeController) matchScopedCode(at time.Time) error {
	f := c.scoped.flow
	if f == nil || f.Context == nil {
		return wire.ErrInvalid
	}
	descriptor, err := c.nodePairTrustDescriptor()
	if err != nil {
		return err
	}
	oob, err := wire.MatchNodePairTrustScopedCode(f.Code, *f.Context, c.hub, c.state.Transport.Descriptor.Claims.NodeControl, c.connection.Origin, wire.NodePairTrustScopedDescriptorDigest(descriptor), at)
	if err != nil || f.OOB != "" && f.OOB != oob {
		return wire.ErrInvalid
	}
	f.OOB = oob
	return nil
}

func (c *nativeController) applyScopedPairResult(p *scopedOriginal, r wire.NodePairTrustScopedResult, fresh bool) error {
	f := c.scoped.flow
	if f == nil || f.NodeID != p.NodeID || f.Code.AttemptID != p.AttemptID {
		return wire.ErrInvalid
	}
	if r.ErrorCode != "" {
		// Only an authenticated exact result settles a refusal. An uncertain
		// result is kept as the same original and never becomes a fresh write.
		if r.State != wire.NodePairTrustScopedFenced && r.State != wire.NodePairTrustScopedExpired && r.State != wire.NodePairTrustScopedCancelled && r.State != wire.NodePairTrustScopedRevoked {
			return c.scopedFailure("APP_NODE_PAIRING_UNKNOWN")
		}
		f.Stage, f.LastError = r.State, "APP_NODE_PAIRING_REFUSED"
		c.scoped.errorCode = f.LastError
		return c.persistScopedFlow()
	}
	switch p.Operation {
	case wire.OperationOwnerNodePairTrustScopedLookup:
		if r.Context == nil || r.Context.AuthorityNodeID != f.NodeID {
			return wire.ErrInvalid
		}
		f.Context = r.Context
		f.OOB = r.OOBCommitment
		at := c.cfg.Now().UTC()
		if !fresh {
			at = parseExpiry(r.Context.IssuedAt)
		}
		if err := c.matchScopedCode(at); err != nil {
			return err
		}
	case wire.OperationOwnerNodePairTrustScopedPrepare:
		if r.Approval == nil || !reflect.DeepEqual(r.Approval.Scope, f.Scope) {
			return wire.ErrInvalid
		}
		f.Approval = r.Approval
	case wire.OperationOwnerNodePairTrustScopedComplete:
		f.Stage = wire.NodePairTrustScopedOwnerApproved
	case wire.OperationOwnerNodePairTrustScopedStatus, wire.OperationOwnerNodePairTrustScopedCancel:
		if r.State == wire.NodePairTrustScopedACKed {
			if f.Approval == nil || r.Binding == nil || wire.ValidateNodePairTrustScopedAccepted(*f.Context, *f.Approval, *r.Binding) != nil {
				return wire.ErrInvalid
			}
			if err := c.acceptScopedACK(p, r); err != nil {
				return err
			}
			f.Stage = wire.NodePairTrustScopedACKed
		} else {
			f.Stage = r.State
			if p.Operation == wire.OperationOwnerNodePairTrustScopedCancel && r.State == wire.NodePairTrustScopedCancelled {
				f.CancelRequested = true
			}
		}
	default:
		return wire.ErrInvalid
	}
	return c.persistScopedFlow()
}

func cloneScopedOriginal(p *scopedOriginal) *scopedOriginal {
	if p == nil {
		return nil
	}
	q := *p
	q.Body = bytes.Clone(p.Body)
	q.Packet = bytes.Clone(p.Packet)
	q.Response = bytes.Clone(p.Response)
	return &q
}

func (c *nativeController) acceptScopedACK(p *scopedOriginal, r wire.NodePairTrustScopedResult) error {
	f := c.scoped.flow
	n := c.newScopedNode(f.NodeID)
	if n.Binding != nil && !reflect.DeepEqual(n.Binding, r.Binding) {
		return wire.ErrInvalid
	}
	if f.Context.Mode == wire.NodePairTrustScopedInitial {
		if f.Confirmation == nil || len(r.ConfirmationResponse) == 0 {
			return wire.ErrInvalid
		}
		device, err := c.device.E2EE()
		if err != nil {
			return err
		}
		reply, err := wire.OpenAppNodeScopedConfirmationResponse(device, c.hub, f.Confirmation.Grant, f.Confirmation.Request, r.ConfirmationResponse, f.Confirmation.ExpectedResponseSequence)
		if err != nil || !reply.OK || reply.Binding == nil || !reflect.DeepEqual(reply.Binding, r.Binding) {
			return wire.ErrInvalid
		}
		copy := *f.Confirmation
		copy.Request = bytes.Clone(f.Confirmation.Request)
		copy.Response = bytes.Clone(r.ConfirmationResponse)
		if n.Confirmation != nil && !equalScopedConfirmation(n.Confirmation, &copy) {
			return wire.ErrInvalid
		}
		n.Confirmation = &copy
	}
	// A historical ACK may restore this App's own previously approved attempt.
	// It cannot create first trust from an expired, newly arriving code/proof.
	approved := parseExpiry(f.ApprovedAt)
	if approved.IsZero() || len(f.OwnerProof) == 0 || c.matchScopedCode(approved) != nil || wire.ValidateNodePairTrustScopedApproval(*f.Approval, *f.Context, f.OOB, approved) != nil {
		return c.scopedFailure("APP_NODE_PAIRING_EXPIRED")
	}
	descriptor, err := c.nodePairTrustDescriptor()
	if err != nil {
		return err
	}
	code := f.Code
	code.OOBSecret = bytes.Clone(code.OOBSecret)
	n.Binding = r.Binding
	n.Trust = &scopedAcceptedTrust{Code: code, Context: *f.Context, Approval: *f.Approval, OOB: f.OOB, AcceptedAt: f.ApprovedAt, Original: cloneScopedOriginal(p), TrustedNodeControl: c.state.Transport.Descriptor.Claims.NodeControl, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(descriptor)}
	if err := c.persistScopedNode(n); err != nil {
		return err
	}
	if err := c.commitScopedCounters(n); err != nil {
		return err
	}
	return c.registerScopedSelection(n)
}

func (c *nativeController) verifyStoredScopedTrust(n *scopedNodeRecord) error {
	t := n.Trust
	if t == nil || t.Original == nil || n.Binding == nil || t.Context.AuthorityNodeID != n.NodeID || t.Approval.Scope.AuthorityNodeID != n.NodeID || n.Binding.NodeID != n.NodeID {
		return wire.ErrInvalid
	}
	at := parseExpiry(t.AcceptedAt)
	if at.IsZero() {
		return wire.ErrInvalid
	}
	oob, err := wire.MatchNodePairTrustScopedCode(t.Code, t.Context, c.hub, t.TrustedNodeControl, c.connection.Origin, t.DescriptorDigest, at)
	if err != nil || oob != t.OOB || wire.ValidateNodePairTrustScopedApproval(t.Approval, t.Context, t.OOB, at) != nil {
		return wire.ErrInvalid
	}
	if err := c.validateScopedOriginal(t.Original); err != nil {
		return err
	}
	body, err := c.scopedBody(t.Original, nil)
	if err != nil {
		return err
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	r, err := wire.OpenNodePairTrustScopedResponse(device, c.hub, t.Original.Packet, t.Original.Response, body)
	if err != nil || r.State != wire.NodePairTrustScopedACKed || r.Binding == nil || !reflect.DeepEqual(r.Binding, n.Binding) || wire.ValidateNodePairTrustScopedAccepted(t.Context, t.Approval, *n.Binding) != nil {
		return wire.ErrInvalid
	}
	if q := n.Confirmation; q != nil {
		reply, err := wire.OpenAppNodeScopedConfirmationResponse(device, c.hub, q.Grant, q.Request, q.Response, q.ExpectedResponseSequence)
		if err != nil || !reply.OK || !reflect.DeepEqual(reply.Binding, n.Binding) {
			return wire.ErrInvalid
		}
	} else if t.Context.Mode == wire.NodePairTrustScopedInitial {
		return wire.ErrInvalid
	}
	return nil
}

func (c *nativeController) observesReservedScopedConfirmation(got wire.AppNodeClientCounters) bool {
	f := c.scoped.flow
	if f == nil || f.Confirmation == nil || len(f.Confirmation.Response) != 0 {
		return false
	}
	var packet clientwire.Packet
	if json.Unmarshal(f.Confirmation.Request, &packet) != nil {
		return false
	}
	s := c.node.Client
	return got.SessionEpoch == s.Epoch && packet.Route.SessionEpoch == s.Epoch && packet.Route.Sequence == s.NextRequest && got.LastRequestSequence == s.NextRequest && got.NextResponseSequence == s.NextResponse+1
}

func (c *nativeController) commitScopedCounters(n *scopedNodeRecord) error {
	if n.CountersCommitted {
		return nil
	}
	if q := n.Confirmation; q != nil {
		var packet clientwire.Packet
		if json.Unmarshal(q.Request, &packet) != nil || !c.node.Client.Initialized || packet.Route.SessionEpoch != c.node.Client.Epoch {
			return wire.ErrInvalid
		}
		s := c.node.Client
		apply := s.NextRequest == packet.Route.Sequence && s.NextResponse == q.ExpectedResponseSequence
		already := s.NextRequest == packet.Route.Sequence+1 && s.NextResponse == q.ExpectedResponseSequence+1
		if !apply && !already {
			return wire.ErrInvalid
		}
		if apply {
			c.node.Client.NextRequest++
			c.node.Client.NextResponse++
			if err := c.persistNode(); err != nil {
				return err
			}
		}
	}
	n.CountersCommitted = true
	return c.persistScopedNode(n)
}

func (c *nativeController) refreshScopedPairing(ctx context.Context) error {
	f := c.scoped.flow
	if f == nil || c.scopedPending() || !c.nodeAccountReady() {
		return ErrInvalidAction
	}
	if !c.scoped.available {
		if err := c.discoverScopedNodes(ctx); err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_UNAVAILABLE")
		}
	}
	if !c.scopedScopeSessionMatches(f.Scope) {
		if err := c.refreshScopedContext(ctx, f.NodeID); err != nil {
			return err
		}
	}
	if f.Context == nil {
		q := wire.NodePairTrustScopedOwnerLookup{Format: wire.NodePairTrustScopedFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: f.Scope, Selector: f.Code.Selector, ContextDigest: f.Code.ContextDigest, IssuedAt: c.scopedNow()}
		if err := c.sendScopedNew(ctx, q, f.NodeID, true); err != nil {
			return err
		}
	}
	if f.Stage == "LOOKUP" || f.Stage == "APPROVING" {
		return c.continueScopedPairing(ctx)
	}
	if f.Stage == "REVIEW" {
		if err := c.matchScopedCode(c.cfg.Now().UTC()); err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_EXPIRED")
		}
		c.publish()
		return nil
	}
	q := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: f.Scope, Context: *f.Context, OOBCommitment: f.OOB, IssuedAt: c.scopedNow()}
	if err := c.sendScopedNew(ctx, q, f.NodeID, true); err != nil {
		return err
	}
	if f.CancelRequested {
		return c.finishScopedCancellation(ctx)
	}
	return nil
}

func (c *nativeController) cancelScopedPairing(ctx context.Context, review string) error {
	f := c.scoped.flow
	if f == nil || f.Context == nil || review == "" || review != c.scopedReviewID() || c.scopedPending() || !c.nodeAccountReady() {
		return ErrInvalidAction
	}
	if !c.scopedScopeSessionMatches(f.Scope) {
		if err := c.refreshScopedContext(ctx, f.NodeID); err != nil {
			return err
		}
	}
	q := &wire.NodePairTrustScopedOwnerCancel{Format: wire.NodePairTrustScopedFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: f.Scope, Context: *f.Context, OOBCommitment: f.OOB, IssuedAt: c.scopedNow()}
	f.CancelRequested = true
	if err := c.persistScopedFlow(); err != nil {
		return err
	}
	if err := c.sendScopedNew(ctx, q, f.NodeID, true); err != nil {
		return err
	}
	return c.finishScopedCancellation(ctx)
}

func (c *nativeController) finishScopedCancellation(ctx context.Context) error {
	f := c.scoped.flow
	if f == nil || !f.CancelRequested || c.scopedPending() {
		return ErrInvalidAction
	}
	if f.Stage == wire.NodePairTrustScopedACKed {
		return nil
	}
	if f.Stage != wire.NodePairTrustScopedCancelled && f.Stage != wire.NodePairTrustScopedExpired && f.Stage != wire.NodePairTrustScopedRevoked && f.Stage != wire.NodePairTrustScopedFenced {
		return c.scopedFailure("APP_NODE_PAIRING_UNKNOWN")
	}
	if f.Challenge != nil {
		n := c.scopedNode(f.NodeID)
		if n == nil {
			return wire.ErrInvalid
		}
		head := f.Challenge.Claims.ExpectedHeadVersion
		if n.Grant != nil && n.Grant.Claims.GrantID == f.Challenge.Claims.GrantID {
			head = n.Grant.Claims.Scope.HeadVersion
		}
		q, err := wire.NewAppNodeScopedCancel(c.nodeSession(), f.NodeID, f.Challenge.Claims.GrantID, head, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		if err := c.sendScopedNew(ctx, q, f.NodeID, false); err != nil {
			return err
		}
		if n.Current == nil || (n.Current.Authority.State != wire.AppNodeScopedCancelled && n.Current.Authority.State != wire.AppNodeScopedExpired && n.Current.Authority.State != wire.AppNodeScopedSessionEnded && n.Current.Authority.State != wire.AppNodeScopedRevoked) {
			return c.scopedFailure("APP_NODE_PAIRING_UNKNOWN")
		}
	}
	f.CleanupComplete = true
	if err := c.persistScopedFlow(); err != nil {
		return err
	}
	c.publish()
	return nil
}

func (c *nativeController) scopedRecordConfirmed(id string) bool {
	n := c.scopedNode(id)
	return n != nil && n.Binding != nil && n.Trust != nil && n.CountersCommitted && c.verifyStoredScopedTrust(n) == nil
}

func (c *nativeController) scopedRecoveryFailure() error {
	return c.scopedFailure("APP_NODE_PAIRING_UNKNOWN")
}
