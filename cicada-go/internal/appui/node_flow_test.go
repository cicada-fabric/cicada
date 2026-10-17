package appui

import (
	"github.com/cicada-ai/cicada/internal/appcore"
	"testing"
)

func TestNodeFlowCannotInferPermissionFromOwnerOrN2(t *testing.T) {
	s := appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: true}, Account: appcore.AccountSnapshot{RootState: appcore.RootStateActive},
		Authorization: appcore.AuthorizationSnapshot{State: "ACTIVE", Confirmed: true}, Node: appcore.NodeSetupSnapshot{Available: true}}
	if f := NodeFlow(s); f.Primary != "" || f.Consent {
		t.Fatal("Root/N2 enabled a Node action")
	}
	s.Node.Candidate = &appcore.NodeCandidateSnapshot{ReviewID: "synthetic-reviewed-candidate"}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNode, appcore.ActionRecoverNode}
	if f := NodeFlow(s); f.Primary != appcore.ActionRecoverNode || f.Consent || f.Code {
		t.Fatal("recovery allowed a new Node decision")
	}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNode}
	if f := NodeFlow(s); f.Stage != "review" || !f.Consent || f.Primary != appcore.ActionApproveNode {
		t.Fatal("exact candidate consent unavailable")
	}
	s.Node.Pending = true
	if f := NodeFlow(s); f.Primary != "" || f.Consent {
		t.Fatal("uncertain operation allowed a fresh approval")
	}
}

func TestNodeApprovalRequiresConsentForTheExactDisplayedClaims(t *testing.T) {
	s := appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionApproveNode},
		Node: appcore.NodeSetupSnapshot{Available: true, Candidate: &appcore.NodeCandidateSnapshot{ReviewID: "synthetic-claims-A"}}}
	for _, tt := range []struct {
		name             string
		displayed        string
		identity, access bool
		want             bool
	}{
		{"reviewed", "synthetic-claims-A", true, true, true},
		{"replaced-grant-head-nonce-or-pin", "synthetic-claims-B", true, true, false},
		{"not-displayed", "", true, true, false},
		{"no-key-review", "synthetic-claims-A", false, true, false},
		{"no-authorization", "synthetic-claims-A", true, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := NodeApprovalAction(s, tt.displayed, tt.identity, tt.access)
			if ok != tt.want {
				t.Fatalf("consent accepted=%t, want %t", ok, tt.want)
			}
			if ok && (a.Kind != appcore.ActionApproveNode || a.NodeReviewID != "synthetic-claims-A" || !a.ConfirmNodeIdentity || !a.ConfirmNodeAccess) {
				t.Fatal("approval lost its exact review fence")
			}
		})
	}
	s.Node.Pending = true
	if _, ok := NodeApprovalAction(s, "synthetic-claims-A", true, true); ok {
		t.Fatal("uncertain packet permitted another approval")
	}
	s.Node.Pending, s.AvailableActions = false, nil
	if _, ok := NodeApprovalAction(s, "synthetic-claims-A", true, true); ok {
		t.Fatal("renderer inferred authority without a controller action")
	}
}

func TestNodeCancelIsSecondaryAndCannotCompeteWithRecovery(t *testing.T) {
	s := appcore.Snapshot{AvailableActions: []appcore.ActionKind{appcore.ActionApproveNode, appcore.ActionCancelNodeAccess},
		Node: appcore.NodeSetupSnapshot{Available: true, Candidate: &appcore.NodeCandidateSnapshot{ReviewID: "synthetic-review"}}}
	f := NodeFlow(s)
	if f.Primary != appcore.ActionApproveNode || len(f.Secondary) != 1 || f.Secondary[0] != appcore.ActionCancelNodeAccess {
		t.Fatal("cancel displaced the exact consent decision")
	}
	s.Node.Pending = true
	s.AvailableActions = append(s.AvailableActions, appcore.ActionRecoverNode)
	f = NodeFlow(s)
	if f.Primary != appcore.ActionRecoverNode || len(f.Secondary) != 0 {
		t.Fatal("uncertain operation offered a conflicting cancel")
	}
}

func TestNodeDiagnosticRecoveryRemainsReachableAfterLogout(t *testing.T) {
	s := appcore.Snapshot{Account: appcore.AccountSnapshot{State: appcore.AccountStateLoginRequired}, Node: appcore.NodeSetupSnapshot{Available: true, Pending: true},
		AvailableActions: []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRecoverNode}}
	if f := Flow(s); f.Stage != "node-recovery" || f.Password {
		t.Fatal("login screen hid saved Node recovery")
	}
	if f := NodeFlow(s); f.Primary != appcore.ActionRecoverNode || len(f.Secondary) != 0 {
		t.Fatal("diagnostic recovery enabled conflicting new work")
	}
	s.AvailableActions = append(s.AvailableActions, appcore.ActionRecover)
	if f := Flow(s); f.Primary != appcore.ActionRecover {
		t.Fatal("account pending lost its own recovery")
	}
	if f := NodeFlow(s); f.Stage != "account-recovery" || f.Primary != "" {
		t.Fatal("two recovery primaries were presented together")
	}
}

func TestNodeStatusReauthorizationHasOneExplicitConsentAndNoNewCode(t *testing.T) {
	s := appcore.Snapshot{Node: appcore.NodeSetupSnapshot{Available: true, Binding: &appcore.NodeBindingSnapshot{ID: "synthetic-binding"}, Access: appcore.NodeAccessSnapshot{State: "EXPIRED"}},
		AvailableActions: []appcore.ActionKind{appcore.ActionReauthorizeNodeStatus}}
	if f := NodeFlow(s); f.Primary != appcore.ActionReauthorizeNodeStatus || f.Code {
		t.Fatal("expired confirmed Node was sent to pairing again")
	}
	s.Node.Candidate = &appcore.NodeCandidateSnapshot{ReviewID: "synthetic-status-claims", StatusOnly: true}
	s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNode}
	if _, ok := NodeApprovalAction(s, "synthetic-status-claims", false, true); !ok {
		t.Fatal("exact status-only target required another physical pairing gesture")
	}
	if _, ok := NodeApprovalAction(s, "synthetic-old-status-claims", false, true); ok {
		t.Fatal("status-only consent adopted replaced claims")
	}
}

func TestExpiredProposalKeepsDiagnosticRefreshAheadOfLogin(t *testing.T) {
	s := appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: true}, Node: appcore.NodeSetupSnapshot{Available: true, Candidate: &appcore.NodeCandidateSnapshot{ReviewID: "synthetic-expired"}},
		AvailableActions: []appcore.ActionKind{appcore.ActionLogin, appcore.ActionRefreshNode}}
	if f := Flow(s); f.Stage != "node-diagnostic" || f.Password {
		t.Fatal("old login hid proposal diagnostics")
	}
	if f := NodeFlow(s); f.Primary != appcore.ActionRefreshNode || f.Consent || f.Code {
		t.Fatal("expired proposal offered consent instead of authenticated state refresh")
	}
}
