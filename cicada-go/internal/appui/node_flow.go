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
	if !s.Node.Available && s.Node.Binding == nil {
		return NodeSetupFlow{Stage: "unavailable"}
	}
	if s.Node.Binding != nil && (has(appcore.ActionLogin) || has(appcore.ActionRecover) || has(appcore.ActionRetry)) {
		// Keep the saved Node visible while the account's primary step takes
		// precedence over Node diagnostics, consent or cancellation.
		return NodeSetupFlow{Stage: "bound"}
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

// NodeCardVisible keeps authenticated saved connection information independent
// of the current account flow. Visibility never establishes current access.
func NodeCardVisible(s appcore.Snapshot, account SetupFlow) bool {
	return s.Node.Pairing != nil || s.Node.Binding != nil || s.Node.Pending || account.Stage == "node-diagnostic" ||
		(account.Stage == "ready" && s.Node.Available)
}

// NodeStatusMessage explains the current observation without conflating the
// saved binding, finite status permission and Node heartbeat.
func NodeStatusMessage(s appcore.Snapshot) string {
	n := s.Node
	has := func(kind appcore.ActionKind) bool {
		for _, action := range s.AvailableActions {
			if action == kind {
				return true
			}
		}
		return false
	}
	if has(appcore.ActionRecover) || has(appcore.ActionRetry) {
		return "node.account_recovery_first"
	}
	if n.Pending {
		return "node.recovery"
	}
	if n.Binding == nil {
		return "node.not_bound"
	}
	if n.Access.State == "REVOKED" {
		return "node.access_revoked"
	}
	if has(appcore.ActionLogin) || s.Account.State == appcore.AccountStateLoginRequired {
		return "node.sign_in_for_status"
	}
	switch n.Access.State {
	case "EXPIRED", "CANCELLED", "SESSION_ENDED":
		if has(appcore.ActionReauthorizeNodeStatus) {
			return "node.reauthorize_to_check"
		}
		if has(appcore.ActionRefreshNode) {
			return "node.check_access_to_continue"
		}
		return map[string]string{"EXPIRED": "node.access_expired", "CANCELLED": "node.access_ended", "SESSION_ENDED": "node.session_ended"}[n.Access.State]
	}
	switch n.ConnectionState() {
	case appcore.NodeOnline:
		return "node.online"
	case appcore.NodeStale:
		return "node.stale"
	case appcore.NodeOffline:
		return "node.offline"
	}
	if n.Access.State == "ACTIVE" && n.Access.Confirmed && n.Connectivity.Current && !n.Connectivity.Known {
		return "node.awaiting_heartbeat"
	}
	if has(appcore.ActionRefreshNode) {
		if n.Access.State == "ACTIVE" && n.Access.Confirmed {
			return "node.check_for_current_status"
		}
		return "node.check_access_to_continue"
	}
	return "node.unknown"
}

// Observation timestamps describe current data only while the snapshot still
// has its independently confirmed access and authenticated observation.
func NodeObservationVisible(s appcore.Snapshot) bool {
	n := s.Node
	return s.Account.State != appcore.AccountStateLoginRequired && n.Binding != nil && n.Binding.Authorized && !n.Pending && n.Access.State == "ACTIVE" &&
		n.Access.Confirmed && n.Connectivity.Current
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
