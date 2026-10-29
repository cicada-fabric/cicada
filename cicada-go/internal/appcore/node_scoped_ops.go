package appcore

import (
	"bytes"
	"context"
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func (c *nativeController) scopedOperationAllowed(node string) bool {
	for id, n := range c.scoped.nodes {
		if n.ReadProposal != nil && id != node {
			return false
		}
	}
	f := c.scoped.flow
	flowAllowed := f == nil || f.Stage == wire.NodePairTrustScopedACKed || f.CleanupComplete || f.NodeID == node
	return flowAllowed && c.nodeAccountReady() && !c.storageFault && !c.hasNodePending() && !c.hasPairPending() && !c.hasLocalDomainPending() && !c.hasThreadGroupPending() && !c.nodePairTrustBusy() && c.node.Proposal == nil && len(c.node.OwnerDirectoryUnknown) == 0 && canBeginOperation(c.state.Pending) && c.state.Recovery == nil && !c.scopedPending()
}

func (c *nativeController) reviewScopedNodePairing(ctx context.Context, text string) error {
	if err := c.ensureScopedNodesLoaded(); err != nil {
		return err
	}
	if c.targetSelectionLocked() || c.scopedBusy() {
		return ErrInvalidAction
	}
	code, err := wire.DecodeNodePairTrustScopedCode(text, c.cfg.Now().UTC())
	if err != nil {
		return c.scopedFailure("APP_NODE_PAIRING_CODE_INVALID")
	}
	if code.HubID != c.hub.HubID || code.Origin != c.connection.Origin || code.HubFingerprint != c.connection.HubFingerprint || c.state.Transport == nil || code.NodeControlFingerprint != nodewire.IdentityFingerprint(c.state.Transport.Descriptor.Claims.NodeControl) {
		clear(code.OOBSecret)
		return c.scopedFailure("APP_NODE_PAIRING_TRUST_MISMATCH")
	}
	known := c.localTargets()
	if len(known.Nodes) >= maxLocalNodes && !slices.ContainsFunc(known.Nodes, func(n savedNodeReference) bool { return n.NodeID == code.AuthorityNodeID }) {
		clear(code.OOBSecret)
		return c.scopedFailure("APP_NODE_PAIRING_STORAGE_FULL")
	}
	// No new flow, original or secret POST exists until both exact capabilities
	// are available under the independently pinned connection.
	if err := c.discoverScopedNodes(ctx); err != nil {
		clear(code.OOBSecret)
		return c.scopedFailure("APP_NODE_PAIRING_UNAVAILABLE")
	}
	c.scoped.flow = &scopedPairFlow{Format: scopedStateFormat, Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, NodeID: code.AuthorityNodeID, Code: code, Stage: "LOOKUP"}
	c.scoped.adding = false
	if err := c.persistScopedFlow(); err != nil {
		return err
	}
	if err := c.refreshScopedContext(ctx, code.AuthorityNodeID); err != nil {
		return err
	}
	f := c.scoped.flow
	q := wire.NodePairTrustScopedOwnerLookup{Format: wire.NodePairTrustScopedFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: f.Scope, Selector: code.Selector, ContextDigest: code.ContextDigest, IssuedAt: c.scopedNow()}
	if err := c.sendScopedNew(ctx, q, f.NodeID, true); err != nil {
		return err
	}
	return c.continueScopedPairing(ctx)
}

func (c *nativeController) scopedNow() string { return c.cfg.Now().UTC().Format(time.RFC3339Nano) }

func (c *nativeController) scopedFailure(code string) error {
	c.scoped.errorCode = code
	if f := c.scoped.flow; f != nil {
		f.LastError = code
	}
	return c.fail(PhaseUnavailable, code, wire.ErrInvalid)
}

func (c *nativeController) refreshScopedContext(ctx context.Context, node string) error {
	q, err := wire.NewAppNodeScopedStatus(c.nodeSession(), wire.AppNodeScopedStatusTarget{NodeID: node}, "", c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendScopedNew(ctx, q, node, false)
}

func (c *nativeController) sendScopedNew(ctx context.Context, body any, node string, pair bool) error {
	if !c.scoped.available || !c.scopedOperationAllowed(node) && !c.scopedOwnerRecoveryContextRead(body, node) {
		return ErrInvalidAction
	}
	p, err := c.newScopedOriginal(body, node, pair)
	if err != nil {
		return err
	}
	if err := c.scopedBudget(p); err != nil {
		clear(p.Packet)
		clear(p.Body)
		return c.scopedFailure("APP_NODE_PAIRING_STORAGE_FULL")
	}
	if err := c.persistScopedFrame(scopedRecoverySlot, nil); err != nil {
		return err
	}
	if err := c.persistScopedFrame(scopedOriginalSlot, p); err != nil {
		return err
	}
	c.scoped.original, c.scoped.recovery = p, nil
	if q, ok := body.(wire.AppNodeScopedPrepare); ok {
		if q.Target.Kind == wire.AppNodeScopedTargetPrevious {
			n := c.scopedNode(node)
			if n == nil {
				return wire.ErrInvalid
			}
			n.ReadProposal = &scopedReadProposal{Prepare: q, Packet: bytes.Clone(p.Packet)}
			if err := c.persistScopedNode(n); err != nil {
				return err
			}
		} else {
			if c.scoped.flow == nil || c.scoped.flow.NodeID != node {
				return wire.ErrInvalid
			}
			c.scoped.flow.Prepare = &q
			c.scoped.flow.PreparePacket = bytes.Clone(p.Packet)
			if err := c.persistScopedFlow(); err != nil {
				return err
			}
		}
	}
	c.publish()
	return c.sendScopedPending(ctx, true)
}

// An original Owner operation may need a fresh account-session leaf after
// restart/login before its read-only reconciliation can be signed. This one
// exact-target status read uses its own persisted original; it cannot prepare a
// grant, select another Node or bypass any other family's unknown operation.
func (c *nativeController) scopedOwnerRecoveryContextRead(body any, node string) bool {
	n := c.selectedScopedNode()
	if n == nil || n.NodeID != node || c.selectedNodeBinding() == nil {
		return false
	}
	q, ok := body.(wire.AppNodeScopedStatus)
	if !ok || q.GrantID != "" || q.Target.NodeID != node || q.Target.CandidateCode != "" || !c.nodeAccountReady() || !bytes.Equal(q.SessionToken, c.session.SessionToken) ||
		c.scopedBusy() || c.hasNodePending() || c.node.Proposal != nil || c.hasPairPending() || c.nodePairTrustBusy() || len(c.node.OwnerDirectoryUnknown) != 0 || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return false
	}
	group, domain := c.hasThreadGroupPending(), c.hasLocalDomainPending()
	if group == domain {
		return false
	}
	return group && c.threadGroups.original.NodeID == node || domain && c.localDomain.original.NodeID == node
}

func (c *nativeController) sendScopedPending(ctx context.Context, fresh bool) error {
	p := c.scoped.original
	if p == nil || p.Applied {
		return ErrInvalidAction
	}
	if len(p.Response) == 0 {
		if err := c.scopedBudget(p); err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_STORAGE_FULL")
		}
		raw, err := c.postScopedOriginal(ctx, p)
		if err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_UNKNOWN")
		}
		defer clear(raw)
		if err := c.checkScopedResponse(p, raw); err != nil {
			return c.scopedFailure("APP_NODE_PAIRING_UNKNOWN")
		}
		copy := *p
		copy.Response = bytes.Clone(raw)
		if err := c.persistScopedFrame(scopedOriginalSlot, &copy); err != nil {
			return err
		}
		c.scoped.original = &copy
		p = &copy
	}
	c.scoped.errorCode = ""
	if f := c.scoped.flow; f != nil {
		f.LastError = ""
	}
	if err := c.applyScopedResponse(p, fresh); err != nil {
		return err
	}
	copy := *p
	copy.Applied = true
	if err := c.persistScopedFrame(scopedOriginalSlot, &copy); err != nil {
		return err
	}
	c.scoped.original = &copy
	c.publish()
	if c.scoped.errorCode != "" {
		return c.scopedFailure(c.scoped.errorCode)
	}
	return nil
}

func (c *nativeController) checkScopedResponse(p *scopedOriginal, raw []byte) error {
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	if p.PairTrust {
		body, err := c.scopedBody(p, nil)
		if err != nil {
			return err
		}
		_, err = wire.OpenNodePairTrustScopedResponse(device, c.hub, p.Packet, raw, body)
		return err
	}
	opened, err := wire.OpenAppNodeScopedResponse(device, c.hub, p.Packet, raw)
	if err != nil {
		return err
	}
	if opened.Challenge != nil && (!c.scopedScopeMatches(opened.Challenge.Claims.Scope, false) || opened.Challenge.Claims.Scope.AuthorityNodeID != p.NodeID) {
		return wire.ErrInvalid
	}
	if r := opened.Result; r != nil && (!c.scopedScopeMatches(r.Authority.Scope, false) || r.Authority.Scope.AuthorityNodeID != p.NodeID) {
		return wire.ErrInvalid
	}
	return nil
}

func (c *nativeController) applyScopedResponse(p *scopedOriginal, fresh bool) error {
	if err := c.checkScopedResponse(p, p.Response); err != nil {
		return err
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	if p.PairTrust {
		body, err := c.scopedBody(p, nil)
		if err != nil {
			return err
		}
		r, err := wire.OpenNodePairTrustScopedResponse(device, c.hub, p.Packet, p.Response, body)
		if err != nil {
			return err
		}
		return c.applyScopedPairResult(p, r, fresh)
	}
	o, err := wire.OpenAppNodeScopedResponse(device, c.hub, p.Packet, p.Response)
	if err != nil {
		return err
	}
	n := c.newScopedNode(p.NodeID)
	if o.Challenge != nil {
		body, err := c.scopedBody(p, nil)
		if err != nil {
			return err
		}
		prepare := body.(*wire.AppNodeScopedPrepare)
		intent, err := e2ee.VerifyOwnerAppNodeScopedPreview(c.owner.Public(), prepare.OwnerIntent, time.Time{})
		if err != nil || wire.ValidateAppNodeScopedPreparedResponse(*o.Challenge, intent, prepare.OwnerIntent, p.Packet, c.hub, time.Time{}) != nil {
			return wire.ErrInvalid
		}
		if prepare.Target.Kind == wire.AppNodeScopedTargetPrevious {
			if o.Challenge.Claims.Profile != wire.AppNodeScopedProfileStatus || n.Binding == nil || !reflect.DeepEqual(o.Challenge.Claims.Binding, n.Binding) {
				return wire.ErrInvalid
			}
			n.ReadProposal = &scopedReadProposal{Prepare: *prepare, Packet: bytes.Clone(p.Packet), Challenge: o.Challenge}
			return c.persistScopedNode(n)
		}
		f := c.scoped.flow
		if f == nil || f.NodeID != p.NodeID || f.Prepare == nil || !bytes.Equal(f.PreparePacket, p.Packet) {
			return wire.ErrInvalid
		}
		if f.Context != nil && f.Context.Mode == wire.NodePairTrustScopedInitial && !reflect.DeepEqual(o.Challenge.Claims.Candidate, f.Context.Candidate) {
			return wire.ErrInvalid
		}
		f.Challenge = o.Challenge
		if err := c.persistScopedFlow(); err != nil {
			return err
		}
		return nil
	}
	r := o.Result
	if r == nil {
		return wire.ErrInvalid
	}
	if r.Authority.CurrentHeadVersion < n.HighestHead {
		if fresh {
			return wire.ErrInvalid
		}
		// A verified old original can settle without replacing a newer local
		// authority observation or its immutable provenance.
		return nil
	}
	if !fresh {
		delete(c.scoped.fresh, p.NodeID)
		delete(c.scoped.fresh, p.NodeID+"/grant")
	}
	if fresh {
		if !c.scopedSessionLeafMatches(r.Authority.Scope) {
			return wire.ErrInvalid
		}
		if p.Operation == wire.OperationAppNodeScopedStatus {
			body, err := c.scopedBody(p, nil)
			if err != nil {
				return err
			}
			if !bytes.Equal(body.(*wire.AppNodeScopedStatus).SessionToken, c.session.SessionToken) {
				return wire.ErrInvalid
			}
		} else if !c.scopedScopeSessionMatches(r.Authority.Scope) {
			return wire.ErrInvalid
		}
		if err := c.acceptGlobalNodeCounters(r.Authority.Counters, true); err != nil {
			return err
		}
		if err := c.persistNode(); err != nil {
			return err
		}
	}
	n.HighestHead = max(n.HighestHead, r.Authority.CurrentHeadVersion)
	if n.Grant != nil && (n.HighestHead != n.Grant.Claims.Scope.HeadVersion || r.Authority.LatestGrantID != n.Grant.Claims.GrantID) {
		delete(c.scoped.fresh, p.NodeID+"/grant")
	}
	if r.State == wire.AppNodeScopedCompleted {
		if n.ProvenanceID != "" && n.ProvenanceID != r.Authority.ConfirmationProvenanceID {
			return wire.ErrInvalid
		}
		n.LatestGrantID, n.ProvenanceID = r.Authority.LatestGrantID, r.Authority.ConfirmationProvenanceID
		if p.Operation == wire.OperationAppNodeScopedStatus {
			body, err := c.scopedBody(p, nil)
			if err != nil {
				return err
			}
			q := body.(*wire.AppNodeScopedStatus)
			if q.GrantID == "" {
				n.Context = r
				if fresh {
					c.scoped.fresh[p.NodeID] = sessionTokenDigest(c.session.SessionToken)
				}
			} else {
				n.Current = r
				if fresh {
					c.scoped.fresh[p.NodeID+"/grant"] = sessionTokenDigest(c.session.SessionToken)
				}
			}
		}
		if p.Operation == wire.OperationAppNodeScopedComplete {
			var challenge *wire.AppNodeScopedChallenge
			if n.ReadProposal != nil {
				challenge = n.ReadProposal.Challenge
			} else if f := c.scoped.flow; f != nil && f.NodeID == p.NodeID {
				challenge = f.Challenge
			}
			if challenge == nil || wire.ValidateAppNodeScopedLiveResult(*r, challenge.Claims, c.hub, parseExpiry(r.ObservedAt)) != nil {
				return wire.ErrInvalid
			}
			n.Grant = challenge
			n.Current = r
			n.ReadProposal = nil
			if fresh && wire.ValidateAppNodeScopedLiveResult(*r, n.Grant.Claims, c.hub, c.cfg.Now().UTC()) == nil {
				c.scoped.fresh[p.NodeID+"/grant"] = sessionTokenDigest(c.session.SessionToken)
			}
		}
		if p.Operation == wire.OperationAppNodeScopedCancel {
			n.SelfCancelledGrantID = p.GrantID
			n.Current = r
			n.ReadProposal = nil
		}
	} else {
		c.scoped.errorCode = "APP_NODE_PAIRING_REFUSED"
		if f := c.scoped.flow; f != nil && f.NodeID == p.NodeID {
			f.LastError = c.scoped.errorCode
			if err := c.persistScopedFlow(); err != nil {
				return err
			}
		}
	}
	if r.Authority.RootState != wire.RootActiveState {
		c.state.RootState = RootStateUnavailable
		c.authorizationChecked = false
		if err := c.persistState(); err != nil {
			return err
		}
	}
	if err := c.persistScopedNode(n); err != nil {
		return err
	}
	if f := c.scoped.flow; f != nil && f.NodeID == p.NodeID && n.Context != nil && c.scopedScopeMatches(n.Context.Authority.Scope, true) {
		f.Scope = n.Context.Authority.Scope
		return c.persistScopedFlow()
	}
	return nil
}

func (c *nativeController) scopedScopeSessionMatches(s e2ee.OwnerAppNodeScopedScope) bool {
	if !c.scopedSessionLeafMatches(s) {
		return false
	}
	if n := c.scopedNode(s.AuthorityNodeID); n != nil && n.Context != nil && c.scoped.fresh[s.AuthorityNodeID] == sessionTokenDigest(c.session.SessionToken) {
		return n.Context.Authority.Scope.AccountSessionID == s.AccountSessionID
	}
	if c.nodeContextChecked && c.node.Context != nil && c.node.Context.Authority.Scope.AccountSessionExpiresAt == c.session.ExpiresAt {
		return s.AccountSessionID == c.node.Context.Authority.Scope.AccountSessionID
	}
	return false
}

func (c *nativeController) scopedSessionLeafMatches(s e2ee.OwnerAppNodeScopedScope) bool {
	return c.scopedScopeMatches(s, false) && c.nodeAccountReady() && s.AccountSessionExpiresAt == c.session.ExpiresAt && s.AccountEpoch == c.session.AccountEpoch && s.DeviceEpoch == c.session.DeviceEpoch
}

func (c *nativeController) scopedReviewID() string {
	f := c.scoped.flow
	if f == nil || f.Context == nil {
		return ""
	}
	scope := f.Scope
	if f.Challenge != nil {
		scope = f.Challenge.Claims.Scope
	}
	return localCollaborationReviewID(struct {
		Context   wire.NodePairTrustScopedContext
		Scope     e2ee.OwnerAppNodeScopedScope
		OOB       string
		Challenge *wire.AppNodeScopedChallenge
	}{*f.Context, scope, f.OOB, f.Challenge})
}

func (c *nativeController) continueScopedPairing(ctx context.Context) error {
	f := c.scoped.flow
	if f == nil || f.Context == nil || c.scopedPending() || !c.nodeAccountReady() {
		return ErrInvalidAction
	}
	if err := c.matchScopedCode(c.cfg.Now().UTC()); err != nil {
		return c.scopedFailure("APP_NODE_PAIRING_EXPIRED")
	}
	if f.Stage == "LOOKUP" {
		if f.Context.Mode == wire.NodePairTrustScopedInitial && f.Challenge == nil {
			n := c.scopedNode(f.NodeID)
			if c.nodeConfirmation != nil && c.nodeConfirmation.Binding.NodeID == f.NodeID || n != nil && (n.Binding != nil || n.ProvenanceID != "") {
				return c.scopedFailure("APP_NODE_PAIRING_TRUST_MISMATCH")
			}
			if n == nil || n.Context == nil || !c.scopedScopeMatches(n.Context.Authority.Scope, true) {
				return ErrInvalidAction
			}
			if n.Context.Authority.State != wire.AppNodeScopedAbsent && n.Context.Authority.State != wire.AppNodeScopedExpired && !(n.Context.Authority.State == wire.AppNodeScopedCancelled && n.SelfCancelledGrantID == n.Context.Authority.LatestGrantID) {
				return c.scopedFailure("APP_NODE_PAIRING_REFUSED")
			}
			owner, err := c.owner.E2EE()
			if err != nil {
				return err
			}
			q, err := wire.NewAppNodeScopedPrepare(c.nodeSession(), n.Context.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.Code.Selector}, owner, c.cfg.Now().UTC())
			if err != nil {
				return err
			}
			if err := c.sendScopedNew(ctx, q, f.NodeID, false); err != nil {
				return err
			}
		}
		f.Stage = "REVIEW"
		f.ReviewID = ""
		if err := c.persistScopedFlow(); err != nil {
			return err
		}
		c.publish()
		return nil
	}
	if f.Stage != "APPROVING" {
		return nil
	}
	if f.ReviewID == "" || f.ReviewID != c.scopedReviewID() {
		return ErrInvalidAction
	}
	if f.Challenge != nil && !c.scopedScopeSessionMatches(f.Challenge.Claims.Scope) {
		return c.scopedFailure("APP_NODE_PAIRING_EXPIRED")
	}
	if f.Context.Mode == wire.NodePairTrustScopedInitial {
		if f.Challenge == nil || f.Prepare == nil {
			return wire.ErrInvalid
		}
		n := c.scopedNode(f.NodeID)
		if n == nil || n.Grant == nil || n.Grant.Claims.GrantID != f.Challenge.Claims.GrantID {
			owner, err := c.owner.E2EE()
			if err != nil {
				return err
			}
			q, err := wire.NewAppNodeScopedComplete(c.nodeSession(), *f.Prepare, f.PreparePacket, *f.Challenge, owner, c.cfg.Now().UTC())
			if err != nil {
				return err
			}
			f.GrantProof = bytes.Clone(q.OwnerGrant)
			if err := c.persistScopedFlow(); err != nil {
				return err
			}
			if err := c.sendScopedNew(ctx, q, f.NodeID, false); err != nil {
				return err
			}
			n = c.scopedNode(f.NodeID)
		}
		if n == nil || n.Grant == nil {
			return c.scopedFailure("APP_NODE_PAIRING_REFUSED")
		}
		q, err := wire.NewAppNodeScopedStatus(c.nodeSession(), wire.AppNodeScopedStatusTarget{NodeID: f.NodeID}, n.Grant.Claims.GrantID, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		if err := c.sendScopedNew(ctx, q, f.NodeID, false); err != nil {
			return err
		}
		if n.Current == nil || wire.ValidateAppNodeScopedLiveResult(*n.Current, n.Grant.Claims, c.hub, c.cfg.Now().UTC()) != nil || n.Current.Authority.RemainingConfirmations != 1 {
			return c.scopedFailure("APP_NODE_PAIRING_EXPIRED")
		}
		f.Scope = n.Grant.Claims.Scope
		if f.Confirmation == nil {
			if !c.node.Client.Initialized || c.node.Client.NextRequest >= math.MaxInt64 || c.node.Client.NextResponse >= math.MaxInt64 {
				return wire.ErrInvalid
			}
			device, err := c.device.E2EE()
			if err != nil {
				return err
			}
			raw, err := wire.SealAppNodeScopedConfirmation(device, c.hub, n.Grant.Claims, f.Code.Selector, c.node.Client.NextRequest, c.cfg.Now().UTC())
			if err != nil {
				return err
			}
			f.Confirmation = &scopedConfirmation{Grant: n.Grant.Claims, Request: raw, ExpectedResponseSequence: c.node.Client.NextResponse}
			if err := c.persistScopedFlow(); err != nil {
				return err
			}
		}
	}
	if f.Approval == nil {
		q := wire.NodePairTrustScopedOwnerPrepare{Format: wire.NodePairTrustScopedFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: f.Scope, Context: *f.Context, OOBCommitment: f.OOB, GrantProof: f.GrantProof, IssuedAt: c.scopedNow()}
		if f.Confirmation != nil {
			q.ConfirmationPacket = f.Confirmation.Request
		}
		if err := c.sendScopedNew(ctx, q, f.NodeID, true); err != nil {
			return err
		}
	}
	if f.Approval == nil || wire.ValidateNodePairTrustScopedApproval(*f.Approval, *f.Context, f.OOB, c.cfg.Now().UTC()) != nil {
		return c.scopedFailure("APP_NODE_PAIRING_EXPIRED")
	}
	if len(f.OwnerProof) == 0 {
		owner, err := c.owner.E2EE()
		if err != nil {
			return err
		}
		x, err := wire.NewNonce()
		if err != nil {
			return err
		}
		defer clear(x)
		f.OwnerProof, f.Capsule, err = wire.SealNodePairTrustScopedApproval(owner, *f.Context, f.OOB, *f.Approval, f.Code.OOBSecret, x, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		f.ApprovedAt = c.scopedNow()
		if err := c.persistScopedFlow(); err != nil {
			return err
		}
	}
	q := wire.NodePairTrustScopedOwnerComplete{Format: wire.NodePairTrustScopedFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: f.Scope, Context: *f.Context, OOBCommitment: f.OOB, OwnerProof: f.OwnerProof, TrustCapsule: f.Capsule, IssuedAt: c.scopedNow()}
	return c.sendScopedNew(ctx, q, f.NodeID, true)
}

func (c *nativeController) approveScopedPairing(ctx context.Context, review string, consent bool) error {
	f := c.scoped.flow
	if f == nil || f.Stage != "REVIEW" || !consent || review == "" || review != c.scopedReviewID() || c.scopedPending() {
		return ErrInvalidAction
	}
	f.ReviewID, f.Stage = review, "APPROVING"
	if err := c.persistScopedFlow(); err != nil {
		return err
	}
	return c.continueScopedPairing(ctx)
}
