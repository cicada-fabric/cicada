package appcore

import (
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"reflect"
	"strings"
	"time"
)

// NodeSetupSnapshot is a display-only projection for one exact Node. Its
// permission is separate from the immutable N2 activation lease. No code,
// private key, grant, proof, session token or pending packet belongs here.
type NodeSetupSnapshot struct {
	Available    bool                     `json:"available"`
	Pending      bool                     `json:"pending"`
	Candidate    *NodeCandidateSnapshot   `json:"candidate,omitempty"`
	Access       NodeAccessSnapshot       `json:"access"`
	Binding      *NodeBindingSnapshot     `json:"binding,omitempty"`
	Connectivity NodeConnectivitySnapshot `json:"connectivity"`
	ErrorCode    string                   `json:"error_code,omitempty"`
	Pairing      *NodePairingSnapshot     `json:"pairing,omitempty"`
}

// ReviewID identifies all authenticated authorization claims, including the
// challenge/head/nonce, exact candidate, pins, epochs and expiry. It is a
// local confirmation fence, not a bearer.
type NodeCandidateSnapshot struct {
	ReviewID               string `json:"review_id"`
	NodeID                 string `json:"node_id"`
	Name                   string `json:"name"`
	NodeFingerprint        string `json:"node_fingerprint"`
	HubControlFingerprint  string `json:"hub_control_fingerprint"`
	NodeKeyEpoch           uint64 `json:"node_key_epoch"`
	CandidateVersion       uint64 `json:"candidate_version"`
	ExpiresAt              string `json:"expires_at"`
	AuthorizationExpiresAt string `json:"authorization_expires_at,omitempty"`
	StatusOnly             bool   `json:"status_only"`
}

type NodeAccessSnapshot struct {
	State     string `json:"state"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Confirmed bool   `json:"confirmed"`
	ReviewID  string `json:"review_id,omitempty"`
}

type NodeBindingSnapshot struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	Name       string `json:"name"`
	Version    uint64 `json:"version"`
	Authorized bool   `json:"authorized"`
}

// Current is true only for a new authenticated observation under the current
// authorization. Recovered historical receipts cannot set it. Connectivity
// describes the Node process; it never establishes native Runtime readiness.
type NodeConnectivitySnapshot struct {
	State           string `json:"state"`
	Known           bool   `json:"known"`
	Stale           bool   `json:"stale"`
	Current         bool   `json:"current"`
	ObservedAt      string `json:"observed_at,omitempty"`
	LastHeartbeatAt string `json:"last_heartbeat_at,omitempty"`
	FreshUntil      string `json:"fresh_until,omitempty"`
}

type NodeConnectionState string

const (
	NodeNotBound NodeConnectionState = "NOT_BOUND"
	NodeUnknown  NodeConnectionState = "UNKNOWN"
	NodeOnline   NodeConnectionState = "ONLINE"
	NodeOffline  NodeConnectionState = "OFFLINE"
	NodeStale    NodeConnectionState = "STALE"
)

// ConnectionState deliberately requires independent binding, access and
// liveness evidence. An accepted approval alone never means the Node is online.
func (n NodeSetupSnapshot) ConnectionState() NodeConnectionState {
	if n.Binding == nil {
		return NodeNotBound
	}
	if n.Binding.ID == "" || n.Binding.NodeID == "" || !n.Binding.Authorized || n.Pending || n.Access.State != "ACTIVE" || !n.Access.Confirmed || !n.Connectivity.Current || !n.Connectivity.Known {
		return NodeUnknown
	}
	if n.Candidate != nil && n.Binding.NodeID != n.Candidate.NodeID {
		return NodeUnknown
	}
	switch n.Connectivity.State {
	case "connected":
		if n.Connectivity.Stale {
			return NodeStale
		}
		return NodeOnline
	case "stale":
		return NodeStale
	case "offline":
		return NodeOffline
	default:
		return NodeUnknown
	}
}

// expireNodeView makes clock decay visible without a network call. It never
// mutates the durable permission, pending packet or account/N2 records.
func expireNodeView(view *Snapshot, now time.Time) {
	n := &view.Node
	if !n.Available && n.Binding == nil && n.Candidate == nil && !n.Pending {
		return
	}
	sessionReady := view.Hub.Verified && view.Account.RootState == RootStateActive &&
		(view.Account.State == AccountStateOwnerReady || view.Account.State == AccountStateSessionActive) &&
		now.Before(parseExpiry(view.Account.SessionExpiresAt))
	accessReady := n.Access.State == "ACTIVE" && n.Access.Confirmed && now.Before(parseExpiry(n.Access.ExpiresAt))
	if n.Access.State == "ACTIVE" && !now.Before(parseExpiry(n.Access.ExpiresAt)) {
		n.Access.State, n.Access.Confirmed = "EXPIRED", false
	}
	if !sessionReady || !accessReady {
		n.Access.Confirmed, n.Connectivity.Current = false, false
	}
	if n.Connectivity.Current && n.Connectivity.State == "connected" {
		// The deadline comes from the authenticated heartbeat projection. A
		// fresh status response must never extend an old Node heartbeat.
		if n.Connectivity.LastHeartbeatAt == "" || !now.Before(parseExpiry(n.Connectivity.FreshUntil)) {
			n.Connectivity.Stale = true
		}
	}
	candidateReady := n.Candidate != nil && now.Before(parseExpiry(n.Candidate.ExpiresAt)) &&
		now.Before(parseExpiry(n.Candidate.AuthorizationExpiresAt))
	var actions []ActionKind
	for _, action := range view.AvailableActions {
		if (action == ActionReauthorizeNodeStatus || action == ActionCancelNodeAccess) && !sessionReady {
			continue
		}
		if action == ActionApproveNode && (!sessionReady || !candidateReady || n.Pending) {
			continue
		}
		if action == ActionRefreshNode && n.Pending {
			continue
		}
		if action == ActionPreviewNode && (!sessionReady || n.Pending) {
			continue
		}
		actions = append(actions, action)
	}
	view.AvailableActions = actions
}

func cloneNodeSnapshot(n NodeSetupSnapshot) NodeSetupSnapshot {
	if n.Pairing != nil {
		pairing := *n.Pairing
		n.Pairing = &pairing
	}
	if n.Candidate != nil {
		candidate := *n.Candidate
		n.Candidate = &candidate
	}
	if n.Binding != nil {
		binding := *n.Binding
		n.Binding = &binding
	}
	return n
}

func (c *nativeController) nodeAccountReady() bool {
	return !c.storageFault && c.connected && c.vault != nil && c.device != nil && c.owner != nil && c.localOwnerMatchesHub() && c.state.RootState == RootStateActive &&
		c.session != nil && c.sessionInspected && !c.sessionNeedsCheck && c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) &&
		c.session.AccountEpoch >= c.state.ObservedAccountEpoch && c.session.DeviceEpoch >= c.state.ObservedDeviceEpoch && c.nodeHasN2History()
}

func (c *nativeController) nodeHasN2History() bool {
	e := c.state.Enrollment
	if e == nil || e.Challenge == nil || e.Target == nil || e.Target.Operation != wire.OperationActivationComplete || e.Result == nil || c.session == nil ||
		e.Result.LeaseState == wire.ActivationLeaseRevoked || e.Challenge.Binding.AccountEpoch != c.session.AccountEpoch || e.Challenge.Binding.DeviceEpoch != c.session.DeviceEpoch {
		return false
	}
	return (e.Result.Operation == wire.OperationActivationComplete && e.Result.State == wire.ActivationCompleted) ||
		(e.Result.Operation == wire.OperationActivationStatus && e.Result.TargetState == wire.ActivationCompleted && len(e.Result.ReceiptPacket) != 0)
}

func (c *nativeController) nodeGrantLive() bool {
	g, r := c.node.Grant, c.node.Current
	return c.nodeChecked && !c.node.Client.Conflict && c.nodeAccountReady() && !c.hasNodePending() && g != nil && r != nil &&
		r.Authority.GrantID == g.Claims.GrantID && r.Authority.State == wire.AppNodeActive && r.Authority.RootState == wire.RootActiveState && !r.Authority.LoginRequired &&
		r.Authority.CurrentHeadVersion == g.Claims.Scope.HeadVersion && c.node.HighestHead == g.Claims.Scope.HeadVersion &&
		reflect.DeepEqual(r.Authority.Scope, g.Claims.Scope) && c.nodeContextChecked && c.node.Context != nil &&
		c.node.Context.Authority.Scope.AccountSessionID == g.Claims.Scope.AccountSessionID &&
		c.node.Context.Authority.Scope.AccountSessionExpiresAt == g.Claims.Scope.AccountSessionExpiresAt &&
		c.node.Context.Authority.Scope.AccountEpoch == g.Claims.Scope.AccountEpoch && c.node.Context.Authority.Scope.DeviceEpoch == g.Claims.Scope.DeviceEpoch &&
		c.node.Context.Authority.Scope.ClientSessionEpoch == g.Claims.Scope.ClientSessionEpoch && c.node.Context.Authority.Scope.OwnerKeyVersion == g.Claims.Scope.OwnerKeyVersion &&
		c.cfg.Now().UTC().Before(parseExpiry(earlierNodeDeadline(g.Claims.LeaseExpiresAt, g.Claims.Scope.AccountSessionExpiresAt)))
}

func (c *nativeController) nodeProposalReviewable() bool {
	p := c.node.Proposal
	if !c.nodeAccountReady() || !c.nodeContextChecked || c.node.Client.Conflict || c.node.Context == nil || p == nil || p.Challenge == nil || c.hasNodePending() {
		return false
	}
	g := p.Challenge.Claims
	if c.node.Context.Authority.Scope.AccountSessionID != g.Scope.AccountSessionID || !c.nodeScopeMatches(g.Scope) {
		return false
	}
	if c.node.Grant != nil && c.node.Grant.Claims.GrantID == g.GrantID {
		return g.Profile == wire.AppNodeProfileInitial && g.Candidate != nil && c.nodeGrantLive() && c.node.Current.Authority.RemainingConfirmations == 1 &&
			c.cfg.Now().UTC().Before(parseExpiry(g.Candidate.ExpiresAt))
	}
	return wire.ValidateAppNodeGrantClaims(g, c.hub, c.cfg.Now().UTC()) == nil && c.node.HighestHead == g.ExpectedHeadVersion
}

func (c *nativeController) nodeCanReauthorizeStatus() bool {
	if !c.nodeAccountReady() || !c.nodeContextChecked || c.node.Client.Conflict || c.hasNodePending() || c.nodeConfirmation == nil || c.node.Grant == nil ||
		c.node.ProvenanceID == "" || c.node.Context == nil || c.node.LatestGrantID != c.node.Grant.Claims.GrantID {
		return false
	}
	old, current := c.node.Grant.Claims.Scope, c.node.Context.Authority.Scope
	if old.AccountEpoch != current.AccountEpoch || old.DeviceEpoch != current.DeviceEpoch || old.ClientSessionEpoch != current.ClientSessionEpoch ||
		old.OwnerKeyVersion != current.OwnerKeyVersion || !c.nodeScopeMatches(current) {
		return false
	}
	r := c.node.Current
	if r != nil && (r.Authority.State == wire.AppNodeRevoked || r.Authority.RootState != wire.RootActiveState) {
		return false
	}
	return !c.cfg.Now().UTC().Before(parseExpiry(earlierNodeDeadline(c.node.Grant.Claims.LeaseExpiresAt, old.AccountSessionExpiresAt))) ||
		old.AccountSessionID != current.AccountSessionID || (r != nil && (r.Authority.State == wire.AppNodeSessionEnded || (r.Authority.State == wire.AppNodeCancelled && c.node.SelfCancelledGrantID == c.node.Grant.Claims.GrantID)))
}

func (c *nativeController) nodeCanStartInitial() bool {
	if c.nodeConfirmation != nil || c.node.ProvenanceID != "" || c.hasNodePending() || c.node.Client.Conflict || c.node.Proposal != nil {
		return false
	}
	if c.node.Grant == nil {
		return c.node.LatestGrantID == "" && (c.node.Current == nil || (c.node.Current.Authority.State != wire.AppNodeRevoked && c.node.Current.Authority.RootState == wire.RootActiveState))
	}
	if c.node.Context == nil || !c.nodeContextChecked || c.node.Current == nil || c.node.Grant.Claims.Profile != wire.AppNodeProfileInitial ||
		c.node.LatestGrantID != c.node.Grant.Claims.GrantID || c.node.Current.Authority.GrantID != c.node.Grant.Claims.GrantID ||
		c.node.Context.Authority.ConfirmationProvenanceID != "" || c.node.Current.Authority.ConfirmationProvenanceID != "" {
		return false
	}
	old, current := c.node.Grant.Claims.Scope, c.node.Context.Authority.Scope
	if old.AccountEpoch != current.AccountEpoch || old.DeviceEpoch != current.DeviceEpoch || old.ClientSessionEpoch != current.ClientSessionEpoch || old.OwnerKeyVersion != current.OwnerKeyVersion ||
		c.node.Current.Authority.RootState != wire.RootActiveState {
		return false
	}
	switch c.node.Current.Authority.State {
	case wire.AppNodeExpired:
		return true
	case wire.AppNodeCancelled:
		return c.node.SelfCancelledGrantID == c.node.Grant.Claims.GrantID
	case wire.AppNodeSessionEnded:
		return old.AccountSessionID != current.AccountSessionID || !c.cfg.Now().UTC().Before(parseExpiry(old.AccountSessionExpiresAt))
	}
	return false
}

func (c *nativeController) nodeActions() []ActionKind {
	if c.nodePairTrustBusy() && !c.pairTrustWorking {
		return nil
	}
	if c.storageFault || !c.connected || c.device == nil || c.vault == nil {
		return nil
	}
	if c.hasNodePending() {
		if c.hasOwnerEndpointPending() {
			return nil
		}
		return []ActionKind{ActionRecoverNode}
	}
	if !c.canBeginOperation() {
		return nil
	}
	if !c.nodeAccountReady() {
		if c.node.Proposal != nil && c.node.Proposal.Challenge != nil {
			return []ActionKind{ActionRefreshNode}
		}
		return nil
	}
	if !c.nodeAvailable {
		if c.nodeVer != 0 {
			return []ActionKind{ActionRefreshNode}
		}
		return nil
	}
	var actions []ActionKind
	if c.node.Client.Conflict {
		return []ActionKind{ActionRefreshNode}
	}
	if p := c.node.Proposal; p != nil && p.Challenge != nil && (c.node.Grant == nil || p.Challenge.Claims.GrantID != c.node.Grant.Claims.GrantID) {
		if c.nodeProposalReviewable() {
			actions = append(actions, ActionApproveNode)
		}
		// Snapshot may outlive the proof without another publish. Keep the
		// diagnostic read available when clock decay removes approval.
		return append(actions, ActionRefreshNode, ActionCancelNodeAccess)
	}
	if c.nodeProposalReviewable() {
		actions = append(actions, ActionApproveNode)
	}
	if c.nodeGrantLive() {
		actions = append(actions, ActionRefreshNode, ActionCancelNodeAccess)
	}
	if c.nodeCanReauthorizeStatus() {
		actions = append(actions, ActionReauthorizeNodeStatus)
	}
	if c.nodeCanStartInitial() {
		actions = append(actions, ActionPreviewNode)
	}
	if c.node.Grant != nil && !c.nodeChecked && !c.hasNodePending() && !c.nodeGrantLive() {
		// A settled historical/cancelled read can require an explicit fresh
		// inspection. It does not authorize another background read by itself.
		actions = append(actions, ActionRefreshNode)
	}
	return actions
}

func (c *nativeController) populateNode(view *Snapshot) {
	n := NodeSetupSnapshot{Available: c.nodeAvailable || c.nodeVer != 0, Pending: c.hasNodePending() && !c.hasOwnerEndpointPending(), ErrorCode: c.nodeError,
		Access: NodeAccessSnapshot{State: "UNCONFIRMED"}}
	if r := c.node.Current; r != nil {
		n.Access.State = r.Authority.State
	}
	if g := c.node.Grant; g != nil {
		n.Access.ExpiresAt = earlierNodeDeadline(g.Claims.LeaseExpiresAt, g.Claims.Scope.AccountSessionExpiresAt)
		n.Access.Confirmed = c.nodeGrantLive()
		n.Access.ReviewID = wire.AppNodeClaimsDigest(g.Claims)
	}
	if p := c.node.Proposal; p != nil && p.Challenge != nil {
		g := p.Challenge.Claims
		candidate := &NodeCandidateSnapshot{ReviewID: wire.AppNodeClaimsDigest(g), ExpiresAt: earlierNodeDeadline(g.ProofExpiresAt, g.Scope.AccountSessionExpiresAt),
			AuthorizationExpiresAt: earlierNodeDeadline(g.LeaseExpiresAt, g.Scope.AccountSessionExpiresAt), StatusOnly: g.Profile == wire.AppNodeProfileStatus}
		if c.node.Grant != nil && c.node.Grant.Claims.GrantID == g.GrantID && g.Candidate != nil {
			candidate.ExpiresAt = earlierNodeDeadline(g.Candidate.ExpiresAt, g.LeaseExpiresAt, g.Scope.AccountSessionExpiresAt)
		}
		if v := g.Candidate; v != nil {
			candidate.NodeID, candidate.Name, candidate.NodeFingerprint, candidate.HubControlFingerprint, candidate.NodeKeyEpoch, candidate.CandidateVersion =
				v.NodeID, v.NodeName, v.NodeKeyFingerprint, v.HubNodeControlFingerprint, v.NodeKeyEpoch, v.Version
		}
		if v := g.Binding; v != nil {
			candidate.NodeID, candidate.Name, candidate.NodeFingerprint, candidate.HubControlFingerprint, candidate.NodeKeyEpoch, candidate.CandidateVersion =
				v.NodeID, v.NodeName, v.NodeKeyFingerprint, v.HubNodeControlFingerprint, v.NodeKeyEpoch, v.BindingVersion
		}
		n.Candidate = candidate
	}
	if c.nodeConfirmation != nil {
		b := c.nodeConfirmation.Binding
		n.Binding = &NodeBindingSnapshot{ID: b.OwnerBindingID, NodeID: b.NodeID, Name: b.NodeName, Version: b.BindingVersion}
	}
	if r := c.node.Current; r != nil && r.Node != nil && n.Access.Confirmed {
		o := r.Node
		if n.Binding != nil && o.BindingID == n.Binding.ID && o.NodeID == n.Binding.NodeID {
			n.Binding.Authorized = o.Authorized && o.BindingState == "ACTIVE"
			n.Connectivity = NodeConnectivitySnapshot{State: strings.ToLower(o.Connectivity), Known: o.Known, Stale: o.Stale, Current: c.nodeChecked,
				ObservedAt: o.ObservedAt, LastHeartbeatAt: o.LastHeartbeatAt, FreshUntil: o.FreshUntil}
		}
	}
	view.Node = n
	c.populateNodePairing(view)
}
