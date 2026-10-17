package appcore

import (
	"context"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// NodeStatusTarget is a public, non-secret expected scope for one automatic
// selected-Node read. It is neither a grant nor a substitute for the core guard.
type NodeStatusTarget struct {
	Origin, HubID, AccountID, OwnerID, DeviceID string
	BindingID, NodeID, ReviewID                 string
	BindingVersion                              uint64
}

// AutomaticNodeStatusTarget is a display-only eligibility check. Dispatch must
// recheck the exact target and current authority under the controller lock.
func AutomaticNodeStatusTarget(s Snapshot, now time.Time) (NodeStatusTarget, bool) {
	n := s.Node
	if !s.Hub.Verified || s.Account.RootState != RootStateActive ||
		(s.Account.State != AccountStateSessionActive && s.Account.State != AccountStateOwnerReady) ||
		!now.Before(parseExpiry(s.Account.SessionExpiresAt)) || s.ErrorCode != "" || n.ErrorCode != "" ||
		!n.Available || n.Binding == nil || !n.Binding.Authorized || n.Binding.ID == "" || n.Binding.NodeID == "" || n.Binding.Version == 0 ||
		n.Access.State != wire.AppNodeActive || !n.Access.Confirmed || n.Access.ReviewID == "" || !now.Before(parseExpiry(n.Access.ExpiresAt)) ||
		n.Candidate != nil || n.Pending {
		return NodeStatusTarget{}, false
	}
	refresh := false
	for _, kind := range s.AvailableActions {
		if kind == ActionRecover || kind == ActionRetry || kind == ActionRecoverNode {
			return NodeStatusTarget{}, false
		}
		refresh = refresh || kind == ActionRefreshNode
	}
	target := NodeStatusTarget{Origin: s.Hub.Origin, HubID: s.Hub.HubID, AccountID: s.Account.AccountID,
		OwnerID: s.Account.OwnerID, DeviceID: s.Account.DeviceID, BindingID: n.Binding.ID, NodeID: n.Binding.NodeID,
		BindingVersion: n.Binding.Version, ReviewID: n.Access.ReviewID}
	return target, refresh && target.Origin != "" && target.HubID != "" && target.AccountID != "" && target.OwnerID != "" && target.DeviceID != ""
}

func (c *nativeController) automaticNodeTargetMatches(target NodeStatusTarget) bool {
	if c.node.Grant == nil || c.nodeConfirmation == nil || c.node.Current == nil || c.node.Current.Node == nil {
		return false
	}
	b := c.nodeConfirmation.Binding
	g, current := c.node.Grant.Claims, c.node.Current
	observation := current.Node
	if !observation.Authorized || observation.BindingState != "ACTIVE" || b.State != "ACTIVE" ||
		observation.NodeID != b.NodeID || observation.BindingID != b.OwnerBindingID || observation.BindingVersion != b.BindingVersion ||
		observation.CredentialVersion != b.CredentialVersion || observation.NodeKeyID != b.NodePublic.ID ||
		observation.NodeKeyFingerprint != b.NodeKeyFingerprint || observation.NodeKeyEpoch != b.NodeKeyEpoch ||
		c.node.ProvenanceID == "" || current.Authority.ConfirmationProvenanceID != c.node.ProvenanceID ||
		wire.ValidateAppNodeLiveResult(*current, g, c.hub, c.cfg.Now().UTC()) != nil {
		return false
	}
	switch g.Profile {
	case wire.AppNodeProfileInitial:
		if wire.ValidateAppNodeConfirmationBinding(g, b) != nil {
			return false
		}
	case wire.AppNodeProfileStatus:
		if g.Binding == nil || !reflect.DeepEqual(*g.Binding, b) || g.ConfirmationProvenanceID != c.node.ProvenanceID {
			return false
		}
	default:
		return false
	}
	return c.automaticNodeScopeMatches(target)
}

// Outcome checks compare immutable identity only: an authenticated terminal
// response is a settled read, even though it intentionally fails the live guard.
func (c *nativeController) automaticNodeScopeMatches(target NodeStatusTarget) bool {
	if c.node.Grant == nil || c.nodeConfirmation == nil {
		return false
	}
	b, g := c.nodeConfirmation.Binding, c.node.Grant.Claims
	want := NodeStatusTarget{Origin: c.connection.Origin, HubID: c.connection.HubID, AccountID: c.connection.AccountID,
		OwnerID: c.connection.OwnerID, DeviceID: c.state.DeviceID, BindingID: b.OwnerBindingID, NodeID: b.NodeID,
		BindingVersion: b.BindingVersion, ReviewID: wire.AppNodeClaimsDigest(g)}
	return target == want
}

// Called only after Dispatch has acquired actionMu. Automatic reads never
// discover availability, bootstrap context, adopt a proposal or recover a packet.
func (c *nativeController) refreshNodeAutomatically(ctx context.Context, target NodeStatusTarget) error {
	c.snapshotMu.RLock()
	globalError := c.snapshot.ErrorCode
	c.snapshotMu.RUnlock()
	if !c.nodeAvailable || !c.nodeGrantLive() || !c.nodeAccountReady() || !c.canBeginOperation() || c.hasNodePending() ||
		c.node.Proposal != nil || c.storageFault || globalError != "" || c.nodeError != "" || !c.automaticNodeTargetMatches(target) {
		return ErrInvalidAction
	}
	if !c.node.Client.Initialized || c.node.Client.Epoch != c.node.Grant.Claims.Scope.ClientSessionEpoch ||
		c.session.ExpiresAt != c.node.Grant.Claims.Scope.AccountSessionExpiresAt {
		return ErrInvalidAction
	}
	expires := parseExpiry(earlierNodeDeadline(c.node.Grant.Claims.LeaseExpiresAt, c.node.Grant.Claims.Scope.AccountSessionExpiresAt, c.session.ExpiresAt))
	remaining := expires.Sub(c.cfg.Now().UTC())
	if remaining <= 0 || ctx.Err() != nil {
		return ErrInvalidAction
	}
	if remaining > 10*time.Second {
		remaining = 10 * time.Second
	}
	readCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	err := c.refreshNode(readCtx)
	if readCtx.Err() == nil && c.cfg.Now().UTC().Before(expires) && c.automaticNodeScopeMatches(target) {
		return err
	}
	// Cancellation/deadline can remove freshness, never undo the authenticated
	// receipt's durable settlement or turn a known terminal outcome uncertain.
	c.nodeChecked, c.nodeReadRequestID = false, ""
	if err == nil {
		err = readCtx.Err()
		if err == nil {
			err = context.DeadlineExceeded
		}
	}
	c.publish()
	return err
}
