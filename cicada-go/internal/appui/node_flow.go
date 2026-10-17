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
		flow := NodeSetupFlow{Stage: "review-expired"}
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
		return NodeSetupFlow{Stage: "code", Primary: appcore.ActionPreviewNode, Code: true}
	}
	return NodeSetupFlow{Stage: "unavailable"}
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
