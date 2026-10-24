package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func (c *nativeController) reviewNodePairing(ctx context.Context, text string) error {
	if !c.nodeAccountReady() || c.nodePairTrustBusy() || c.hasNodePending() || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	code, err := wire.DecodeNodePairTrustCode(text, c.cfg.Now().UTC())
	if err != nil {
		return c.failNodePairing("APP_NODE_PAIRING_CODE_INVALID")
	}
	descriptor, err := c.nodePairTrustDescriptor()
	if err != nil || code.Origin != c.connection.Origin || code.HubID != c.hub.HubID || code.HubFingerprint != c.connection.HubFingerprint || code.NodeControlFingerprint != nodewire.IdentityFingerprint(c.state.Transport.Descriptor.Claims.NodeControl) {
		clear(code.OOBSecret)
		return c.failNodePairing("APP_NODE_PAIRING_TRUST_MISMATCH")
	}
	_ = descriptor // Exact descriptor digest is checked against authenticated Context.
	if err := c.discoverNodePairTrust(ctx); err != nil {
		clear(code.OOBSecret)
		return c.failNodePairing("APP_NODE_PAIRING_UNAVAILABLE")
	}
	c.pairTrustWorking = true
	defer func() { c.pairTrustWorking = false }()
	if err := c.refreshNodePairingContext(ctx); err != nil {
		clear(code.OOBSecret)
		return err
	}
	if c.node.Context == nil || !c.nodeContextChecked {
		clear(code.OOBSecret)
		return ErrInvalidAction
	}
	c.node.PairTrust = &nodePairTrustState{Code: code, Scope: c.node.Context.Authority.Scope, Stage: "LOOKUP"}
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	t := c.node.PairTrust
	lookup := wire.NodePairTrustOwnerLookup{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: t.Scope, Selector: code.Selector, ContextDigest: code.ContextDigest, IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if err := c.newNodePairTrustOperation(ctx, wire.OperationOwnerNodePairTrustLookup, lookup); err != nil {
		return err
	}
	return c.continueNodePairing(ctx)
}
func (c *nativeController) nodePairingReviewID() string {
	t := c.node.PairTrust
	if t == nil || t.Context == nil {
		return ""
	}
	original := ""
	if p := c.node.Proposal; p != nil && p.Challenge != nil {
		original = wire.AppNodeClaimsDigest(p.Challenge.Claims)
	}
	raw, _ := json.Marshal([]any{t.Code.ContextDigest, t.OOB, t.Scope, original})
	digest := sha256.Sum256(append([]byte("cicada/app/node-pairing-review/v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}
func (c *nativeController) approveNodePairing(ctx context.Context, review string, confirm bool) error {
	t := c.node.PairTrust
	if !confirm || !c.nodeAccountReady() || !c.canBeginOperation() || t == nil || t.Stage != "REVIEW" || review == "" || review != c.nodePairingReviewID() || c.matchNodePairTrust(c.cfg.Now().UTC()) != nil || c.nodePairTrustPending() || c.hasNodePending() {
		return ErrInvalidAction
	}
	if t.Context.Mode == wire.NodePairTrustInitial && !c.nodeProposalReviewable() {
		return ErrInvalidAction
	}
	t.ConsentReviewID, t.Stage = review, "APPROVING"
	if err := c.persistNode(); err != nil {
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	return c.continueNodePairing(ctx)
}
func (c *nativeController) continueNodePairing(ctx context.Context) error {
	t := c.node.PairTrust
	if t == nil || t.Context == nil || !c.nodeAccountReady() || !c.canBeginOperation() || c.nodePairTrustPending() || c.hasNodePending() {
		return ErrInvalidAction
	}
	c.pairTrustWorking = true
	defer func() { c.pairTrustWorking = false }()
	if c.matchNodePairTrust(c.cfg.Now().UTC()) != nil {
		return c.failNodePairing("APP_NODE_PAIRING_EXPIRED")
	}
	if t.Stage == "LOOKUP" {
		if t.Context.Mode == wire.NodePairTrustInitial {
			if c.node.Proposal == nil {
				if err := c.previewNode(ctx, t.Code.Selector, false); err != nil {
					return err
				}
			}
			if c.node.Proposal == nil || c.node.Proposal.Challenge == nil || !reflect.DeepEqual(c.node.Proposal.Challenge.Claims.Candidate, t.Context.Candidate) {
				return c.failNodePairing("APP_NODE_PAIRING_TRUST_MISMATCH")
			}
			t.Scope = c.node.Proposal.Challenge.Claims.Scope
		} else if t.Context.Binding.OwnerID != c.connection.OwnerID || t.Context.Binding.OwnerKeyID != c.owner.Public().ID {
			return c.failNodePairing("APP_NODE_PAIRING_TRUST_MISMATCH")
		}
		t.Stage = "REVIEW"
		if err := c.persistNode(); err != nil {
			return c.failStorage("APP_NODE_COMMIT_FAILED", err)
		}
		c.publish()
		return nil
	}
	if t.Stage != "APPROVING" {
		c.publish()
		return nil
	}
	if t.ConsentReviewID == "" || t.ConsentReviewID != c.nodePairingReviewID() {
		return c.failNodePairing("APP_NODE_PAIRING_TRUST_MISMATCH")
	}
	if t.Context.Mode == wire.NodePairTrustInitial {
		p := c.node.Proposal
		if p == nil || p.Challenge == nil || !reflect.DeepEqual(p.Challenge.Claims.Candidate, t.Context.Candidate) {
			return wire.ErrInvalid
		}
		if c.node.Grant == nil || c.node.Grant.Claims.GrantID != p.Challenge.Claims.GrantID {
			if !c.nodeProposalReviewable() {
				return c.failNodePairing("APP_NODE_PAIRING_EXPIRED")
			}
			owner, err := c.owner.E2EE()
			if err != nil {
				return err
			}
			request, err := wire.NewAppNodeComplete(c.nodeSession(), p.Prepare, p.PreparePacket, *p.Challenge, owner, c.cfg.Now().UTC())
			if err != nil {
				return err
			}
			t.GrantProof = bytes.Clone(request.OwnerGrant)
			// The grant proof and prior consent are saved with the old complete packet.
			if err := c.sendNewNodeAuthority(ctx, wire.OperationAppNodeComplete, p.Challenge.Claims.GrantID, request); err != nil {
				return err
			}
		}
		if err := c.refreshNode(ctx); err != nil {
			return err
		}
		if !c.nodeGrantLive() || c.node.Current.Authority.RemainingConfirmations != 1 {
			return c.failNodePairing("APP_NODE_PAIRING_EXPIRED")
		}
		t.Scope = c.node.Grant.Claims.Scope
		if t.Confirmation == nil {
			if !c.node.Client.Initialized || c.node.Client.NextRequest >= math.MaxInt64 || c.node.Client.NextResponse >= math.MaxInt64 {
				return wire.ErrInvalid
			}
			device, err := c.device.E2EE()
			if err != nil {
				return err
			}
			raw, err := wire.SealAppNodeConfirmation(device, c.hub, c.node.Grant.Claims, t.Code.Selector, c.node.Client.NextRequest, c.cfg.Now().UTC())
			if err != nil {
				return err
			}
			claims := c.node.Grant.Claims
			t.Confirmation = &nodeOperation{Kind: wire.AppNodeOriginalClient, Operation: "nodes.confirm", GrantID: claims.GrantID, GrantClaims: &claims, Request: raw, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano), ExpectedResponseSequence: c.node.Client.NextResponse}
			if err := c.persistNode(); err != nil {
				return c.failStorage("APP_NODE_COMMIT_FAILED", err)
			}
		}
	}
	if t.Approval == nil {
		prepare := wire.NodePairTrustOwnerPrepare{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: t.Scope, Context: *t.Context, OOBCommitment: t.OOB, GrantProof: t.GrantProof, IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
		if t.Confirmation != nil {
			prepare.ConfirmationPacket = t.Confirmation.Request
		}
		if err := c.newNodePairTrustOperation(ctx, wire.OperationOwnerNodePairTrustPrepare, prepare); err != nil {
			return err
		}
	}
	if t.Approval == nil || wire.ValidateNodePairTrustApproval(*t.Approval, *t.Context, t.OOB, c.cfg.Now().UTC()) != nil {
		return c.failNodePairing("APP_NODE_PAIRING_EXPIRED")
	}
	if len(t.OwnerProof) == 0 {
		owner, err := c.owner.E2EE()
		if err != nil {
			return err
		}
		x, err := wire.NewNonce()
		if err != nil {
			return err
		}
		defer clear(x)
		proof, capsule, err := wire.SealNodePairTrustApproval(owner, *t.Context, t.OOB, *t.Approval, t.Code.OOBSecret, x, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		t.OwnerProof, t.Capsule = proof, capsule
	}
	complete := wire.NodePairTrustOwnerComplete{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: t.Scope, Context: *t.Context, OOBCommitment: t.OOB, OwnerProof: t.OwnerProof, TrustCapsule: t.Capsule, IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	return c.newNodePairTrustOperation(ctx, wire.OperationOwnerNodePairTrustComplete, complete)
}
func (c *nativeController) refreshNodePairing(ctx context.Context) error {
	t := c.node.PairTrust
	if t == nil || t.Context == nil || !c.nodeAccountReady() || c.nodePairTrustPending() || c.hasNodePending() {
		return ErrInvalidAction
	}
	if t.FencedOperation != "" {
		return c.observeFencedNodePairing(ctx)
	}
	if (t.Stage == "LOOKUP" || t.Stage == "APPROVING") && c.nodePairTrustMayContinue() {
		return c.continueNodePairing(ctx)
	}
	if err := c.observeNodePairing(ctx); err != nil {
		return err
	}
	return c.finishTerminalNodePairing(ctx)
}

func (c *nativeController) nodePairTrustMayContinue() bool {
	t := c.node.PairTrust
	if t == nil || t.Context == nil {
		return false
	}
	end := earlierNodeDeadline(t.Context.ExpiresAt, t.Scope.AccountSessionExpiresAt)
	if t.Approval != nil {
		end = earlierNodeDeadline(end, t.Approval.AcceptBefore)
	}
	return c.cfg.Now().UTC().Before(parseExpiry(end))
}

func (c *nativeController) observeNodePairing(ctx context.Context) error {
	t := c.node.PairTrust
	scope, err := c.nodePairingObservationScope(ctx)
	if err != nil {
		return err
	}
	status := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: scope, Context: *t.Context, OOBCommitment: t.OOB, IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	return c.newNodePairTrustOperation(ctx, wire.OperationOwnerNodePairTrustStatus, status)
}
func (c *nativeController) cancelNodePairing(ctx context.Context, review string) error {
	t := c.node.PairTrust
	if t == nil || t.Context == nil || review == "" || review != c.nodePairingReviewID() || !c.nodeAccountReady() || c.nodePairTrustPending() {
		return ErrInvalidAction
	}
	scope, err := c.nodePairingObservationScope(ctx)
	if err != nil {
		return err
	}
	status := wire.NodePairTrustOwnerStatus{Format: wire.NodePairTrustFormat, SessionToken: bytes.Clone(c.session.SessionToken), Scope: scope, Context: *t.Context, OOBCommitment: t.OOB, IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if err := c.newNodePairTrustOperation(ctx, wire.OperationOwnerNodePairTrustCancel, status); err != nil {
		return err
	}
	return c.finishTerminalNodePairing(ctx)
}

func (c *nativeController) refreshNodePairingContext(ctx context.Context) error {
	if !c.nodeAvailable {
		if err := c.discoverNodeAvailability(ctx); err != nil {
			return c.failNodePairing("APP_NODE_PAIRING_UNAVAILABLE")
		}
	}
	return c.refreshNodeContext(ctx)
}

func (c *nativeController) nodePairingObservationScope(ctx context.Context) (e2ee.OwnerAppNodeScope, error) {
	if err := c.refreshNodePairingContext(ctx); err != nil {
		return e2ee.OwnerAppNodeScope{}, err
	}
	r := c.node.Context
	if r == nil || r.RequestID != c.nodeReadRequestID || !c.freshObservation(r.ObservedAt) || r.State != wire.AppNodeCompleted || r.ErrorCode != "" || r.Authority.LoginRequired || !c.nodeScopeIdentityMatches(r.Authority.Scope) || c.session == nil || r.Authority.Scope.AccountEpoch != c.session.AccountEpoch || r.Authority.Scope.DeviceEpoch != c.session.DeviceEpoch {
		return e2ee.OwnerAppNodeScope{}, ErrInvalidAction
	}
	// This authenticated scope permits only the closed observation/cancel DTO.
	// It never changes the original approval or reconciles old counters by fiat.
	return r.Authority.Scope, nil
}
