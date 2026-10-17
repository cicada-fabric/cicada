package appcore

import (
	"context"
	"math"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) confirmNode(ctx context.Context) error {
	g, p := c.node.Grant, c.node.Proposal
	if !c.nodeGrantLive() || g == nil || g.Claims.Profile != wire.AppNodeProfileInitial || g.Claims.Candidate == nil || p == nil || p.Challenge == nil ||
		p.Challenge.Claims.GrantID != g.Claims.GrantID || c.node.Current.Authority.RemainingConfirmations != 1 ||
		!c.node.Client.Initialized || c.node.Client.Epoch != g.Claims.Scope.ClientSessionEpoch || c.node.Client.NextRequest >= math.MaxInt64 ||
		c.node.Client.NextResponse >= math.MaxInt64 || !c.cfg.Now().UTC().Before(parseExpiry(g.Claims.Candidate.ExpiresAt)) {
		return ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	raw, err := wire.SealAppNodeConfirmation(device, c.hub, g.Claims, p.Prepare.Target.Code, c.node.Client.NextRequest, c.cfg.Now().UTC())
	if err != nil || len(raw) > wire.MaxAppNodeMutationPacketBytes {
		clear(raw)
		return wire.ErrInvalid
	}
	claims := g.Claims
	c.node.Pending = &nodeOperation{Kind: wire.AppNodeOriginalClient, Operation: "nodes.confirm", GrantID: claims.GrantID, GrantClaims: &claims,
		Request: raw, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano), ExpectedResponseSequence: c.node.Client.NextResponse}
	c.nodeChecked, c.nodeReadRequestID = false, ""
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	c.publish()
	return c.sendNodePending(ctx, true)
}
