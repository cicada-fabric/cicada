package appui

import (
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func savedNodeView() appcore.Snapshot {
	return appcore.Snapshot{
		Hub:     appcore.HubSnapshot{Verified: true},
		Account: appcore.AccountSnapshot{State: appcore.AccountStateSessionActive, RootState: appcore.RootStateActive},
		Node: appcore.NodeSetupSnapshot{Available: true,
			Binding:      &appcore.NodeBindingSnapshot{ID: "synthetic-binding", NodeID: "synthetic-node", Name: "Saved Ubuntu", Authorized: true},
			Access:       appcore.NodeAccessSnapshot{State: "ACTIVE", Confirmed: true},
			Connectivity: appcore.NodeConnectivitySnapshot{State: "connected", Known: true, Current: true}},
		AvailableActions: []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionLogout, appcore.ActionRefreshNode},
	}
}

func TestSavedNodeCardSurvivesAccountAndRecoverySteps(t *testing.T) {
	for _, tt := range []struct {
		name, accountStage string
		actions            []appcore.ActionKind
		pending, candidate bool
		primary            appcore.ActionKind
	}{
		{"login", "login", []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRefreshNode}, false, false, ""},
		{"login-before-old-status-review", "login", []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRefreshNode}, false, true, ""},
		{"account-recovery", "recovery", []appcore.ActionKind{appcore.ActionRecover, appcore.ActionRefreshNode}, false, false, ""},
		{"node-recovery", "node-recovery", []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRecoverNode}, true, false, appcore.ActionRecoverNode},
		{"account-before-node-recovery", "recovery", []appcore.ActionKind{appcore.ActionRecover, appcore.ActionRecoverNode}, true, false, ""},
		{"continue-status", "ready", []appcore.ActionKind{appcore.ActionRefresh, appcore.ActionReauthorizeNodeStatus}, false, false, appcore.ActionReauthorizeNodeStatus},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := savedNodeView()
			s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false
			s.Node.Connectivity.Current = false
			s.Node.Pending, s.AvailableActions = tt.pending, tt.actions
			if tt.candidate {
				s.Node.Candidate = &appcore.NodeCandidateSnapshot{ReviewID: "synthetic-old-status-review", StatusOnly: true}
			}
			account := Flow(s)
			if account.Stage != tt.accountStage || !NodeCardVisible(s, account) {
				t.Fatal("account step hid the saved connection or displaced its recovery priority")
			}
			flow := NodeFlow(s)
			if flow.Primary != tt.primary || flow.Code || flow.Consent || len(flow.Secondary) != 0 || s.Node.Binding.ID != "synthetic-binding" {
				t.Fatal("saved connection created a competing decision or returned to pairing")
			}
		})
	}
	s := savedNodeView()
	s.Node.Available = false
	if !NodeCardVisible(s, Flow(s)) || NodeFlow(s).Stage != "bound" {
		t.Fatal("public availability hid the authenticated saved binding")
	}
	s.Node.Binding = nil
	if NodeCardVisible(s, SetupFlow{Stage: "login"}) {
		t.Fatal("a profile without a binding invented saved connection information")
	}
}

func TestNodeStatusSeparatesAccessFromHeartbeatAndSavedBinding(t *testing.T) {
	for _, tt := range []struct {
		name, want string
		edit       func(*appcore.Snapshot)
	}{
		{"recent-heartbeat", "node.online", func(*appcore.Snapshot) {}},
		{"no-heartbeat-yet", "node.awaiting_heartbeat", func(s *appcore.Snapshot) { s.Node.Connectivity.State, s.Node.Connectivity.Known = "unknown", false }},
		{"stale-heartbeat", "node.stale", func(s *appcore.Snapshot) { s.Node.Connectivity.Stale = true }},
		{"current-observation-needed", "node.check_for_current_status", func(s *appcore.Snapshot) { s.Node.Connectivity.Current = false }},
		{"access-unconfirmed", "node.check_access_to_continue", func(s *appcore.Snapshot) { s.Node.Access.Confirmed = false }},
		{"sign-in-first", "node.sign_in_for_status", func(s *appcore.Snapshot) {
			s.Account.State = appcore.AccountStateLoginRequired
			s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false
			s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRefreshNode}
		}},
		{"continue-after-expiry", "node.reauthorize_to_check", func(s *appcore.Snapshot) {
			s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false
			s.AvailableActions = []appcore.ActionKind{appcore.ActionReauthorizeNodeStatus}
		}},
		{"continue-after-app-cancel", "node.reauthorize_to_check", func(s *appcore.Snapshot) {
			s.Node.Access.State, s.Node.Access.Confirmed = "CANCELLED", false
			s.AvailableActions = []appcore.ActionKind{appcore.ActionReauthorizeNodeStatus}
		}},
		{"new-login-old-access", "node.reauthorize_to_check", func(s *appcore.Snapshot) {
			s.Node.Access.State, s.Node.Access.Confirmed = "SESSION_ENDED", false
			s.AvailableActions = []appcore.ActionKind{appcore.ActionReauthorizeNodeStatus}
		}},
		{"revoked", "node.access_revoked", func(s *appcore.Snapshot) { s.Node.Access.State, s.Node.Access.Confirmed = "REVOKED", false }},
		{"expired-without-continue-action", "node.access_expired", func(s *appcore.Snapshot) {
			s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false
			s.AvailableActions = nil
		}},
		{"check-access-before-continue", "node.check_access_to_continue", func(s *appcore.Snapshot) { s.Node.Access.State, s.Node.Access.Confirmed = "EXPIRED", false }},
		{"cancelled-without-continue-action", "node.access_ended", func(s *appcore.Snapshot) {
			s.Node.Access.State, s.Node.Access.Confirmed = "CANCELLED", false
			s.AvailableActions = nil
		}},
		{"ended-without-continue-action", "node.session_ended", func(s *appcore.Snapshot) {
			s.Node.Access.State, s.Node.Access.Confirmed = "SESSION_ENDED", false
			s.AvailableActions = nil
		}},
		{"uncertain-request", "node.recovery", func(s *appcore.Snapshot) { s.Node.Pending = true }},
		{"account-recovery-first", "node.account_recovery_first", func(s *appcore.Snapshot) { s.AvailableActions = []appcore.ActionKind{appcore.ActionRecover} }},
		{"no-current-read-action", "node.unknown", func(s *appcore.Snapshot) { s.Node.Connectivity.Current, s.AvailableActions = false, nil }},
		{"no-saved-binding", "node.not_bound", func(s *appcore.Snapshot) { s.Node.Binding = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := savedNodeView()
			tt.edit(&s)
			before := append([]appcore.ActionKind(nil), s.AvailableActions...)
			if got := NodeStatusMessage(s); got != tt.want {
				t.Fatalf("got status explanation %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(before, s.AvailableActions) {
				t.Fatal("status explanation changed the controller's allowed actions")
			}
			if _, ok := NodeApprovalAction(s, "", true, true); ok {
				t.Fatal("status explanation silently granted new status access")
			}
		})
	}
}

func TestCurrentObservationTimesDisappearWithoutCurrentAccess(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*appcore.Snapshot)
	}{
		{"login-ended", func(s *appcore.Snapshot) { s.Account.State = appcore.AccountStateLoginRequired }},
		{"access-expired", func(s *appcore.Snapshot) { s.Node.Access.State = "EXPIRED" }},
		{"unconfirmed-access", func(s *appcore.Snapshot) { s.Node.Access.Confirmed = false }},
		{"historical-observation", func(s *appcore.Snapshot) { s.Node.Connectivity.Current = false }},
		{"pending", func(s *appcore.Snapshot) { s.Node.Pending = true }},
		{"binding-unavailable", func(s *appcore.Snapshot) { s.Node.Binding.Authorized = false }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := savedNodeView()
			if !NodeObservationVisible(s) {
				t.Fatal("current authorized observation was hidden")
			}
			tt.edit(&s)
			if NodeObservationVisible(s) || !NodeCardVisible(s, Flow(s)) || s.Node.Binding.ID != "synthetic-binding" {
				t.Fatal("old timestamps remained current or expiry removed the saved binding")
			}
		})
	}
}
