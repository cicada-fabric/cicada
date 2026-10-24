package appui

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"slices"
	"time"
)

// NodePairingFlow projects only local controller-authorized choices. Public
// availability and an accepted approval never establish a Node binding.
type NodePairingSetupFlow struct {
	Stage   string
	Primary appcore.ActionKind
	Cancel  bool
}

func NodePairingFlow(s appcore.Snapshot, now time.Time) NodePairingSetupFlow {
	p := s.Node.Pairing
	if p == nil {
		return NodePairingSetupFlow{Stage: "unavailable"}
	}
	has := func(a appcore.ActionKind) bool { return slices.Contains(s.AvailableActions, a) }
	if has(appcore.ActionRecoverNodePairing) {
		return NodePairingSetupFlow{Stage: "recovery", Primary: appcore.ActionRecoverNodePairing}
	}
	cancel := has(appcore.ActionCancelNodePairing)
	switch p.State {
	case "LOOKUP", "APPROVING", "PENDING":
		f := NodePairingSetupFlow{Stage: "preparing", Cancel: cancel}
		if has(appcore.ActionRefreshNodePairing) {
			f.Primary = appcore.ActionRefreshNodePairing
		}
		return f
	case "REVIEW":
		if has(appcore.ActionApproveNodePairing) {
			end, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
			if err == nil && now.Before(end) {
				return NodePairingSetupFlow{Stage: "review", Primary: appcore.ActionApproveNodePairing, Cancel: cancel}
			}
		}
		return NodePairingSetupFlow{Stage: "expired", Cancel: cancel}
	case "OWNER_APPROVED":
		stage := "waiting"
		end, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
		if err != nil || !now.Before(end) {
			stage = "deadline"
		}
		f := NodePairingSetupFlow{Stage: stage, Cancel: cancel}
		if has(appcore.ActionRefreshNodePairing) {
			f.Primary = appcore.ActionRefreshNodePairing
		}
		return f
	case "ACKED":
		return NodePairingSetupFlow{Stage: "connected"}
	case "EXPIRED", "CANCELLED", "REVOKED", "FENCED":
		f := NodePairingSetupFlow{Stage: "ended"}
		if has(appcore.ActionReviewNodePairing) {
			f.Primary = appcore.ActionReviewNodePairing
		}
		return f
	}
	f := NodePairingSetupFlow{Stage: "code"}
	if has(appcore.ActionReviewNodePairing) {
		f.Primary = appcore.ActionReviewNodePairing
	}
	return f
}
