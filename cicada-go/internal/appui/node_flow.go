package appui

import "github.com/cicada-ai/cicada/internal/appcore"

// NodeFlow uses only controller-authorized actions. The renderer does not
// derive permission from Root ACTIVE, account login or public capabilities.
type NodeSetupFlow struct {
	Stage     string
	Primary   appcore.ActionKind
	Secondary []appcore.ActionKind
	Code      bool
	Consent   bool
	Notice    string // Localized guidance only; it never enables an action.
}

func NodeFlow(s appcore.Snapshot) NodeSetupFlow {
	has := func(kind appcore.ActionKind) bool {
		for _, action := range s.AvailableActions {
			if action == kind {
				return true
			}
		}
		return false
	}
	if s.Node.Pending || has(appcore.ActionRecoverNode) {
		if has(appcore.ActionRecover) || has(appcore.ActionRetry) {
			return NodeSetupFlow{Stage: "account-recovery"}
		}
		flow := NodeSetupFlow{Stage: "recovery"}
		if has(appcore.ActionRecoverNode) {
			flow.Primary = appcore.ActionRecoverNode
		}
		return flow
	}
	if !s.Node.Available {
		return NodeSetupFlow{Stage: "unavailable"}
	}
	if s.Node.Candidate != nil && has(appcore.ActionApproveNode) {
		flow := NodeSetupFlow{Stage: "review", Primary: appcore.ActionApproveNode, Consent: true}
		if has(appcore.ActionCancelNodeAccess) {
			flow.Secondary = []appcore.ActionKind{appcore.ActionCancelNodeAccess}
		}
		return flow
	}
	if s.Node.Candidate != nil {
		flow := NodeSetupFlow{Stage: "review-expired", Notice: "node.initial_review_expired"}
		if s.Node.Candidate.StatusOnly {
			flow.Notice = "node.status_review_expired"
		}
		if has(appcore.ActionRefreshNode) {
			flow.Primary = appcore.ActionRefreshNode
		}
		if has(appcore.ActionCancelNodeAccess) {
			if s.Node.Access.Confirmed {
				flow.Primary = appcore.ActionCancelNodeAccess
			} else {
				flow.Secondary = []appcore.ActionKind{appcore.ActionCancelNodeAccess}
			}
		}
		return flow
	}
	if s.Node.Binding != nil {
		flow := NodeSetupFlow{Stage: "bound"}
		if has(appcore.ActionRefreshNode) {
			flow.Primary = appcore.ActionRefreshNode
		}
		if has(appcore.ActionReauthorizeNodeStatus) {
			flow.Primary = appcore.ActionReauthorizeNodeStatus
		}
		if has(appcore.ActionCancelNodeAccess) {
			flow.Secondary = []appcore.ActionKind{appcore.ActionCancelNodeAccess}
		}
		return flow
	}
	if has(appcore.ActionPreviewNode) {
		return NodeSetupFlow{Stage: "code", Primary: appcore.ActionPreviewNode, Code: true, Notice: unboundNodeNotice(s.Node.Access.State)}
	}
	return NodeSetupFlow{Stage: "unavailable", Notice: unboundNodeNotice(s.Node.Access.State)}
}

// An unfinished connection can have an authenticated terminal authorization
// state. Show that reason without inventing a login, retry or pairing action.
func unboundNodeNotice(state string) string {
	switch state {
	case "REVOKED":
		return "node.access_revoked"
	case "EXPIRED":
		return "node.access_expired"
	case "CANCELLED":
		return "node.access_ended"
	case "SESSION_ENDED":
		return "node.unbound_session_ended"
	default:
		return ""
	}
}

// NodeApprovalAction binds a native consent gesture to the exact currently
// displayed review. Replacing any authenticated claim changes ReviewID and
// prevents old checkbox values from authorizing the replacement.
func NodeApprovalAction(s appcore.Snapshot, displayedReview string, identityChecked, accessChecked bool) (appcore.Action, bool) {
	f := NodeFlow(s)
	if f.Primary != appcore.ActionApproveNode || !f.Consent || s.Node.Candidate == nil || s.Node.Candidate.ReviewID == "" ||
		displayedReview != s.Node.Candidate.ReviewID || (!s.Node.Candidate.StatusOnly && !identityChecked) || !accessChecked {
		return appcore.Action{}, false
	}
	return appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: displayedReview, ConfirmNodeIdentity: true, ConfirmNodeAccess: true}, true
}
