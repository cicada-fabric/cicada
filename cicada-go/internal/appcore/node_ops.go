package appcore

import (
	"context"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) initializeNode(ctx context.Context) {
	if c.nodePairTrustBusy() && !c.pairTrustWorking {
		return
	}
	if !c.nodeAccountReady() || !c.canBeginOperation() || c.hasNodePending() {
		return
	}
	if !c.nodeDiscoveryTried {
		if err := c.discoverNodeAvailability(ctx); err != nil {
			c.publish()
			return
		}
	}
	if !c.nodeAvailable || c.nodeContextChecked {
		if c.nodeAccountReady() && !c.pairTrustDiscovery && c.state.Transport != nil {
			_ = c.discoverNodePairTrust(ctx)
		}
		return
	}
	if c.nodeVer == 0 {
		c.node = c.newNodeState()
	}
	if err := c.refreshNodeContext(ctx); err != nil {
		c.publish()
		return
	}
	if c.node.Grant != nil {
		_ = c.refreshNode(ctx)
	}
	if !c.pairTrustDiscovery && c.state.Transport != nil {
		_ = c.discoverNodePairTrust(ctx)
	}
	c.publish()
}

func (c *nativeController) refreshNodeContext(ctx context.Context) error {
	if !c.nodeAccountReady() || c.hasNodePending() || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	request, err := wire.NewAppNodeStatus(c.nodeSession(), "", c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendNewNodeAuthority(ctx, wire.OperationAppNodeStatus, "", request)
}

func (c *nativeController) previewNode(ctx context.Context, code string, previous bool) error {
	if !c.nodeAccountReady() || c.hasNodePending() || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	if !previous {
		var err error
		code, err = wire.NormalizeAppNodeCode(code)
		if err != nil {
			return c.failNode("APP_NODE_CODE_INVALID", err)
		}
	}
	if err := c.discoverNodeAvailability(ctx); err != nil {
		return c.failNode("APP_NODE_UNAVAILABLE", err)
	}
	if c.nodeVer == 0 {
		c.node = c.newNodeState()
	}
	if c.node.Proposal != nil {
		return ErrInvalidAction
	}
	if err := c.refreshNodeContext(ctx); err != nil {
		return err
	}
	if !previous && !c.nodeCanStartInitial() {
		return ErrInvalidAction
	}
	target := wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: code}
	if previous {
		if !c.nodeCanReauthorizeStatus() {
			return ErrInvalidAction
		}
		target = wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetPrevious, PreviousGrantID: c.node.LatestGrantID}
	}
	if c.node.Context == nil || !c.nodeContextChecked {
		return ErrInvalidAction
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewAppNodePrepare(c.nodeSession(), c.node.Context.Authority.Scope, target, owner, c.cfg.Now().UTC())
	if err != nil {
		return c.failNode("APP_NODE_CODE_INVALID", err)
	}
	intent, err := e2ee.VerifyOwnerAppNodePreview(c.owner.Public(), request.OwnerIntent, time.Time{})
	if err != nil {
		return err
	}
	// The signed intent is a preview only. Permission needs a separate, exact
	// native consent gesture after the authenticated challenge is displayed.
	c.node.Proposal = &nodeProposal{Prepare: request}
	return c.sendNewNodeAuthority(ctx, wire.OperationAppNodePrepare, intent.GrantID, request)
}

func (c *nativeController) approveNode(ctx context.Context, action Action) error {
	p := c.node.Proposal
	if p == nil || p.Challenge == nil || !c.nodeProposalReviewable() || !action.ConfirmNodeIdentity || !action.ConfirmNodeAccess ||
		action.NodeReviewID != wire.AppNodeClaimsDigest(p.Challenge.Claims) {
		return ErrInvalidAction
	}
	claims := p.Challenge.Claims
	if claims.Profile == wire.AppNodeProfileStatus && !c.nodeExistingTargetMatches(claims) {
		return ErrInvalidAction
	}
	if c.node.Grant == nil || c.node.Grant.Claims.GrantID != claims.GrantID {
		owner, err := c.owner.E2EE()
		if err != nil {
			return err
		}
		request, err := wire.NewAppNodeComplete(c.nodeSession(), p.Prepare, p.PreparePacket, *p.Challenge, owner, c.cfg.Now().UTC())
		if err != nil {
			return c.failNode("APP_NODE_CANDIDATE_EXPIRED", err)
		}
		if err := c.sendNewNodeAuthority(ctx, wire.OperationAppNodeComplete, claims.GrantID, request); err != nil {
			return err
		}
	}
	if c.node.Grant == nil || c.node.Grant.Claims.GrantID != claims.GrantID {
		return nil
	}
	if err := c.refreshNode(ctx); err != nil {
		return err
	}
	if claims.Profile == wire.AppNodeProfileStatus {
		return nil
	}
	if !c.nodeGrantLive() || c.node.Current.Authority.RemainingConfirmations != 1 {
		return nil
	}
	if err := c.confirmNode(ctx); err != nil {
		return err
	}
	return c.refreshNode(ctx)
}

func (c *nativeController) refreshNode(ctx context.Context) error {
	if c.hasNodePending() || !c.canBeginOperation() || c.device == nil {
		return ErrInvalidAction
	}
	if !c.nodeAvailable {
		if err := c.discoverNodeAvailability(ctx); err != nil {
			return c.failNode("APP_NODE_UNAVAILABLE", err)
		}
	}
	grantID := ""
	if c.node.Grant != nil {
		grantID = c.node.Grant.Claims.GrantID
	}
	if p := c.node.Proposal; p != nil && p.Challenge != nil && (c.node.Grant == nil || p.Challenge.Claims.GrantID != c.node.Grant.Claims.GrantID) {
		grantID = p.Challenge.Claims.GrantID
	}
	if grantID == "" {
		return c.refreshNodeContext(ctx)
	}
	request, err := wire.NewAppNodeStatus(c.nodeSession(), grantID, c.cfg.Now().UTC())
	if err != nil {
		return c.failNode("APP_NODE_REQUEST_INVALID", err)
	}
	return c.sendNewNodeAuthority(ctx, wire.OperationAppNodeStatus, grantID, request)
}

func (c *nativeController) cancelNodeAccess(ctx context.Context, reviewID string) error {
	if !c.nodeAccountReady() || c.hasNodePending() || !c.canBeginOperation() || !c.nodeAvailable {
		return ErrInvalidAction
	}
	var grant string
	var head uint64
	var expectedReview string
	if p := c.node.Proposal; p != nil && p.Challenge != nil && (c.node.Grant == nil || c.node.Grant.Claims.GrantID != p.Challenge.Claims.GrantID) {
		grant, head = p.Challenge.Claims.GrantID, p.Challenge.Claims.ExpectedHeadVersion
		expectedReview = wire.AppNodeClaimsDigest(p.Challenge.Claims)
	} else if c.nodeGrantLive() {
		grant, head = c.node.Grant.Claims.GrantID, c.node.Grant.Claims.Scope.HeadVersion
		expectedReview = wire.AppNodeClaimsDigest(c.node.Grant.Claims)
	} else {
		return ErrInvalidAction
	}
	if reviewID == "" || reviewID != expectedReview {
		return ErrInvalidAction
	}
	request, err := wire.NewAppNodeCancel(c.nodeSession(), grant, head, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendNewNodeAuthority(ctx, wire.OperationAppNodeCancel, grant, request)
}

func nodeActionKind(kind ActionKind) bool {
	return kind == ActionPreviewNode || kind == ActionApproveNode || kind == ActionRefreshNode || kind == ActionRecoverNode || kind == ActionReauthorizeNodeStatus || kind == ActionCancelNodeAccess
}

func (c *nativeController) sendNewNodeAuthority(ctx context.Context, operation, grantID string, body any) error {
	if !c.nodeAvailable || c.hasNodePending() || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	raw, err := wire.SealClientRequest(device, c.hub, body)
	if err != nil || len(raw) > wire.MaxAppNodeOriginalBytes {
		clear(raw)
		return c.failNode("APP_NODE_REQUEST_INVALID", wire.ErrInvalid)
	}
	p := &nodeOperation{Kind: wire.AppNodeOriginalAuthority, Operation: operation, GrantID: grantID, Request: raw, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if operation == wire.OperationAppNodePrepare {
		if c.node.Proposal == nil {
			return ErrInvalidAction
		}
		c.node.Proposal.PreparePacket = append([]byte(nil), raw...)
	}
	c.node.Pending = p
	c.nodeChecked = false
	c.nodeReadRequestID = ""
	if operation == wire.OperationAppNodeStatus {
		packet, err := wire.DecodePacket(raw)
		if err != nil {
			return err
		}
		c.nodeReadRequestID = packet.Packet.Route.OperationID
		if grantID == "" {
			c.nodeContextChecked = false
		}
	}
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	c.publish()
	return c.sendNodePending(ctx, true)
}

func (c *nativeController) sendNodePending(ctx context.Context, fresh bool) error {
	p := c.node.Pending
	if !p.unresolved() {
		return ErrInvalidAction
	}
	if !fresh && p.Operation != wire.OperationOwnerEndpointRead {
		c.nodeChecked, c.nodeReadRequestID = false, ""
	}
	if len(p.Response) != 0 {
		if err := c.applyNodeResponse(p, false); err != nil {
			return c.failNodePending(p, "APP_NODE_RESPONSE_INVALID", err)
		}
		c.publish()
		return nil
	}
	raw, err := c.postNodePacket(ctx, p)
	if err != nil {
		return c.failNodePending(p, "APP_NODE_REQUEST_UNKNOWN", err)
	}
	defer clear(raw)
	if err := c.verifyNodeResponse(p, raw); err != nil {
		return c.failNodePending(p, "APP_NODE_RESPONSE_INVALID", err)
	}
	p.Response = append([]byte(nil), raw...)
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	if ctx.Err() != nil {
		if err := c.applyNodeResponse(p, false); err != nil {
			return c.failNodePending(p, "APP_NODE_RESPONSE_INVALID", err)
		}
		c.publish()
		return ctx.Err()
	}
	if err := c.applyNodeResponse(p, fresh); err != nil {
		return c.failNodePending(p, "APP_NODE_RESPONSE_INVALID", err)
	}
	c.publish()
	return nil
}

func (c *nativeController) failNodePending(p *nodeOperation, code string, err error) error {
	if p != nil && p.Operation == wire.OperationOwnerEndpointRead {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_REQUEST_UNKNOWN", err)
	}
	return c.failNode(code, err)
}

func (c *nativeController) failNode(code string, err error) error {
	c.nodeError, c.nodeChecked = code, false
	c.publish()
	return err
}

func (c *nativeController) nodeExistingTargetMatches(g e2ee.OwnerAppNodeGrantClaims) bool {
	return g.Profile == wire.AppNodeProfileStatus && g.Candidate == nil && g.Binding != nil && c.nodeConfirmation != nil &&
		c.node.ProvenanceID != "" && g.ConfirmationProvenanceID == c.node.ProvenanceID && g.PreviousGrantID == c.node.LatestGrantID &&
		reflect.DeepEqual(*g.Binding, c.nodeConfirmation.Binding)
}

func (c *nativeController) acceptNodeCounters(result wire.AppNodeResult, fresh bool) error {
	got := result.Authority.Counters
	if !fresh {
		return nil
	}
	if got.SessionEpoch == 0 || got.LastRequestSequence >= math.MaxInt64 || got.NextResponseSequence == 0 {
		return wire.ErrInvalid
	}
	if !c.node.Client.Initialized {
		if c.node.Pending != nil && c.node.Pending.Kind == wire.AppNodeOriginalClient {
			return wire.ErrInvalid
		}
		c.node.Client = nodeClientState{Initialized: true, Epoch: got.SessionEpoch, NextRequest: got.LastRequestSequence + 1, NextResponse: got.NextResponseSequence}
		return nil
	}
	if c.observesReservedNodeConfirmation(got) {
		// A status counter is not the exact original receipt. Preserve the
		// reserved local slot until the independently opened ACK response.
		return nil
	}
	if got.SessionEpoch != c.node.Client.Epoch || got.LastRequestSequence+1 != c.node.Client.NextRequest || got.NextResponseSequence != c.node.Client.NextResponse {
		return errors.New("authenticated Client counters conflict with saved conversation")
	}
	return nil
}
