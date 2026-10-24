package appcore

import (
	"encoding/json"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"time"
)

const (
	ActionReviewNodePairing  ActionKind = "REVIEW_DEVICE_PAIRING_CODE"
	ActionApproveNodePairing ActionKind = "APPROVE_DEVICE_PAIRING"
	ActionRefreshNodePairing ActionKind = "CHECK_DEVICE_PAIRING_ACK"
	ActionRecoverNodePairing ActionKind = "RECOVER_DEVICE_PAIRING_REQUEST"
	ActionCancelNodePairing  ActionKind = "CANCEL_DEVICE_PAIRING"
)

// Pairing is a sanitized projection. No code, S, X, proof, token or packet is
// retained here; ACKED describes admission, not online/business authority.
type NodePairingSnapshot struct {
	DeadlineReached bool   `json:"deadline_reached"`
	Available       bool   `json:"available"`
	Availability    string `json:"availability"`
	State           string `json:"state"`
	ReviewID        string `json:"review_id,omitempty"`
	NodeID          string `json:"node_id,omitempty"`
	Name            string `json:"name,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
}

func marshalPairTrustBody(body any) ([]byte, error) { return json.Marshal(body) }
func (c *nativeController) failNodePairing(code string) error {
	if t := c.node.PairTrust; t != nil {
		t.LastError = code
	}
	return c.fail(PhaseUnavailable, code, wire.ErrInvalid)
}
func (c *nativeController) populateNodePairing(view *Snapshot) {
	if c.state.Transport == nil && c.node.PairTrust == nil {
		return
	}
	availability := c.pairTrustAvailability
	if availability == "" {
		availability = "UNKNOWN"
	}
	p := &NodePairingSnapshot{Available: c.pairTrustAvailable, Availability: availability, State: "CODE"}
	if t := c.node.PairTrust; t != nil {
		p.State, p.ReviewID, p.ExpiresAt, p.ErrorCode = t.Stage, c.nodePairingReviewID(), t.Code.ExpiresAt, t.LastError
		p.ExpiresAt = earlierNodeDeadline(t.Code.ExpiresAt, t.Scope.AccountSessionExpiresAt)
		if t.Approval != nil {
			p.ExpiresAt = earlierNodeDeadline(p.ExpiresAt, t.Approval.AcceptBefore)
		} else if proposal := c.node.Proposal; proposal != nil && proposal.Challenge != nil && t.Stage == "REVIEW" {
			p.ExpiresAt = earlierNodeDeadline(p.ExpiresAt, proposal.Challenge.Claims.ProofExpiresAt)
		}
		if c.nodePairTrustPending() || c.hasNodePending() {
			p.State = "UNKNOWN"
		}
		if t.Context != nil {
			if n := t.Context.Candidate; n != nil {
				p.NodeID, p.Name = n.NodeID, n.NodeName
			}
			if b := t.Context.Binding; b != nil {
				p.NodeID, p.Name = b.NodeID, b.NodeName
			}
		}
	}
	view.Node.Pairing = p
}
func (c *nativeController) nodePairingActions() []ActionKind {
	if c.storageFault || !c.connected || c.vault == nil || c.device == nil || c.owner == nil {
		return nil
	}
	t := c.node.PairTrust
	if t != nil && (c.nodePairTrustPending() || c.hasNodePending() || t.FencedOperation != "" || c.nodePairTrustNeedsCleanup() || (pairTrustTerminal(t.Stage) && t.Confirmation != nil && !t.Confirmation.Applied)) {
		return []ActionKind{ActionRecoverNodePairing}
	}
	if !c.nodeAccountReady() || !c.canBeginOperation() {
		return nil
	}
	if t == nil || !c.nodePairTrustBusy() {
		if c.state.Transport != nil && c.canBeginOperation() {
			return []ActionKind{ActionReviewNodePairing}
		}
		return nil
	}
	actions := []ActionKind{ActionRefreshNodePairing}
	if t.Context != nil {
		actions = append(actions, ActionCancelNodePairing)
	}
	if c.nodePairingReviewable() {
		actions = append(actions, ActionApproveNodePairing)
	}
	return actions
}
func expireNodePairingView(view *Snapshot, now time.Time) {
	p := view.Node.Pairing
	if p == nil {
		return
	}
	p.DeadlineReached = p.ExpiresAt != "" && !now.Before(parseExpiry(p.ExpiresAt))
	ready := view.Hub.Verified && now.Before(parseExpiry(view.Account.SessionExpiresAt)) && (view.Account.State == AccountStateOwnerReady || view.Account.State == AccountStateSessionActive) && view.Account.RootState == RootStateActive
	var kept []ActionKind
	for _, a := range view.AvailableActions {
		if a == ActionApproveNodePairing && (!ready || !now.Before(parseExpiry(p.ExpiresAt))) {
			continue
		}
		if (a == ActionReviewNodePairing || a == ActionRefreshNodePairing || a == ActionCancelNodePairing) && !ready {
			continue
		}
		kept = append(kept, a)
	}
	view.AvailableActions = kept
}
