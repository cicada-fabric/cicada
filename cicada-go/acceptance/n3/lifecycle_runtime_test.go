package n3_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These cases consume the production App API reviewed and synced by root.
// They require the actual Hub/Node-only composition; absence is not a skip.
func TestN3ActualAppConsentBindingRelayAndWallClockDecay(t *testing.T) {
	f := newNodeHubFixture(t) // Missing production composition is FAIL, never skip.
	marker := filepath.Join(f.dir, "n3-app-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	var initial appActorCheckpoint
	readJSON(t, marker, &initial)
	if !initial.Current.Node.Available || initial.Current.Node.Access.Confirmed || initial.Current.Node.Binding != nil {
		t.Fatal("account login or public availability became implicit Node authority")
	}
	node := startNodeProcess(t, f, "synthetic-n3-selected")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	sequence := 0
	do := func(action *appcore.Action) appActorReply {
		sequence++
		return commandApp(t, f, app, sequence, appActorCommand{Action: action})
	}
	preview := do(&appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
	candidate := preview.Current.Node.Candidate
	if preview.ActionFailed || candidate == nil || candidate.NodeID != node.id || candidate.StatusOnly || candidate.ReviewID == "" ||
		candidate.NodeFingerprint != pending.PendingCandidate.NodeFingerprint || candidate.HubControlFingerprint != pending.PendingCandidate.HubFingerprint ||
		preview.Current.Node.Access.Confirmed || preview.Current.Node.Binding != nil {
		t.Fatal("production App preview substituted the exact Node or already granted authority")
	}
	posts := len(f.proxy.snapshot())
	for _, bad := range []appcore.Action{
		{Kind: appcore.ActionApproveNode, NodeReviewID: candidate.ReviewID},
		{Kind: appcore.ActionApproveNode, NodeReviewID: "synthetic-wrong-review", ConfirmNodeIdentity: true, ConfirmNodeAccess: true},
		{Kind: appcore.ActionApproveNode, NodeReviewID: candidate.ReviewID, ConfirmNodeIdentity: true},
	} {
		rejected := do(&bad)
		if !rejected.ActionFailed || len(f.proxy.snapshot()) != posts || rejected.Current.Node.Access.Confirmed || rejected.Current.Node.Binding != nil {
			t.Fatal("missing or substituted native consent sent a secret POST or activated authority")
		}
	}
	approved := do(&appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if approved.ActionFailed || approved.Current.Node.Pending || approved.Current.Node.Access.State != wire.AppNodeActive ||
		!approved.Current.Node.Access.Confirmed || approved.Current.Node.Binding == nil || approved.Current.Node.Binding.NodeID != node.id {
		t.Fatal("explicit production App flow did not establish the exact finite Node binding")
	}
	if approved.Current.Node.ConnectionState() == appcore.NodeOnline || approved.Current.Node.Connectivity.LastHeartbeatAt != "" {
		t.Fatal("binding a stopped Node fabricated online/Runtime readiness")
	}
	node = startNodeProcess(t, f, node.id)
	// A freshly retained PENDING candidate must reconcile exact approval after
	// restart. Legacy bearer-only agents do not enter this acceptance fixture.
	bound := node.awaitState(t, f, true)
	if bound.NodeFingerprint != pending.PendingCandidate.NodeFingerprint || bound.NodeKeyEpoch != pending.PendingCandidate.NodeKeyEpoch {
		t.Fatal("actual Node restart replaced the approved cryptographic identity")
	}
	var online appcore.Snapshot
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		read := do(&appcore.Action{Kind: appcore.ActionRefreshNode})
		if read.ActionFailed {
			t.Fatal("production App could not obtain a fresh authorized Node-only observation")
		}
		if read.Current.Node.ConnectionState() == appcore.NodeOnline {
			online = read.Current
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if online.Node.Binding == nil {
		t.Fatal("actual bound relay-only Node never established authenticated heartbeat freshness")
	}
	node.kill(t)
	// Inspect the quiescent production store. Relay-only updates last_seen but
	// must not manufacture a Worker-available machine or a Control local Node.
	f.hub.kill(t)
	db := f.db(t)
	machine := must(db.OwnerBoundNodeMachine(f.cfg.Material.OwnerID, node.id))
	if machine.Status != "offline" || machine.LastSeen == "" {
		t.Fatal("real relay-only heartbeat was inferred from Worker machine status")
	}
	if must(db.GetMachine("control-local")) != nil {
		t.Fatal("Hub/Node-only composition instantiated a Control local machine")
	}
	db.Close()
	f.start(t)
	// Refresh once after both writers were quiesced. A heartbeat already in
	// flight at Node SIGKILL may legally have committed after the first read.
	final := do(&appcore.Action{Kind: appcore.ActionRefreshNode})
	if final.ActionFailed || final.Current.Node.ConnectionState() != appcore.NodeOnline {
		t.Fatal("actual accepted final Node heartbeat disappeared after Hub restart")
	}
	online = final.Current
	heartbeat, err1 := time.Parse(time.RFC3339Nano, online.Node.Connectivity.LastHeartbeatAt)
	freshUntil, err2 := time.Parse(time.RFC3339Nano, online.Node.Connectivity.FreshUntil)
	stored, err3 := time.Parse(time.RFC3339Nano, machine.LastSeen)
	if err1 != nil || err2 != nil || err3 != nil || !heartbeat.Equal(stored) ||
		!freshUntil.Equal(heartbeat.Add(wire.AppNodeObservationStaleAfter)) || heartbeat.After(time.Now().UTC()) {
		t.Fatal("signed freshness does not derive from the final real accepted heartbeat")
	}
	before := len(f.proxy.snapshot())
	// This one case deliberately uses actual wall time, not App Config.Now.
	// The driver can report progress while its detached Docker test is running.
	for time.Now().Before(freshUntil.Add(50 * time.Millisecond)) {
		time.Sleep(100 * time.Millisecond)
	}
	aged := do(nil)
	if aged.ClockMode != "WALL_CLOCK" || aged.Current.Node.ConnectionState() == appcore.NodeOnline ||
		!aged.Current.Node.Connectivity.Stale || len(f.proxy.snapshot()) != before {
		t.Fatal("cached online state did not decay on actual elapsed time alone")
	}
	for i := 0; i < 2; i++ {
		read := do(&appcore.Action{Kind: appcore.ActionRefreshNode})
		if read.ActionFailed || read.Current.Node.ConnectionState() == appcore.NodeOnline ||
			read.Current.Node.Connectivity.LastHeartbeatAt != online.Node.Connectivity.LastHeartbeatAt ||
			read.Current.Node.Connectivity.FreshUntil != online.Node.Connectivity.FreshUntil {
			t.Fatal("newer observation time extended an old stopped Node heartbeat")
		}
	}
	app.kill(t)
	t.Log("ACTUAL_N3 actualAppCore=true actualHubCLI=true actualNodeCLI=true realCrypto=true persistentDB=true wall_clock_heartbeat_decay=true Windows_GUI_NOT_RUN=true native_Runtime_NOT_RUN=true App_SSE_NOT_RUN=true")
}

func TestN3ActualAppSelfCancelRequiresExplicitReadOnlyConsent(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "n3-read-app-ready.json")
	bootstrap := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, bootstrap.process, marker)
	bootstrap.kill(t)
	originalKeys := ownedAppPublicKeys(t, f)
	device := ownedAppIdentity(t, f, appvault.PurposeAppDevice)
	marker = filepath.Join(f.dir, "n3-read-app-resumed.json")
	app := startAppProcess(t, f, "resume-node", marker)
	awaitMarker(t, app.process, marker)
	node := startNodeProcess(t, f, "synthetic-n3-read-target")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	sequence := 0
	do := func(action appcore.Action) appActorReply {
		sequence++
		return commandApp(t, f, app, sequence, appActorCommand{Action: &action})
	}
	preview := do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
	if preview.ActionFailed || preview.Current.Node.Candidate == nil {
		t.Fatal("initial exact Node preview failed")
	}
	approved := do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: preview.Current.Node.Candidate.ReviewID,
		ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if approved.ActionFailed || approved.Current.Node.Binding == nil || !approved.Current.Node.Access.Confirmed {
		t.Fatal("initial production App confirmation failed")
	}
	oldBinding, oldExpiry := *approved.Current.Node.Binding, approved.Current.Authorization.ExpiresAt
	cancelled := do(appcore.Action{Kind: appcore.ActionCancelNodeAccess, NodeReviewID: approved.Current.Node.Access.ReviewID})
	if cancelled.ActionFailed || cancelled.Current.Node.Access.State != wire.AppNodeCancelled || cancelled.Current.Node.Access.Confirmed {
		t.Fatal("self-cancellation retained current App Node permission")
	}
	clientCount := func() int {
		n := 0
		for _, exchange := range f.proxy.snapshot() {
			if exchange.Path == "/v2/client/rpc" {
				n++
			}
		}
		return n
	}
	before := clientCount()
	readPreview := do(appcore.Action{Kind: appcore.ActionReauthorizeNodeStatus})
	candidate := readPreview.Current.Node.Candidate
	if readPreview.ActionFailed || candidate == nil || !candidate.StatusOnly || candidate.NodeID != node.id ||
		candidate.NodeFingerprint != pending.PendingCandidate.NodeFingerprint || candidate.HubControlFingerprint != pending.PendingCandidate.HubFingerprint ||
		candidate.NodeKeyEpoch != pending.PendingCandidate.NodeKeyEpoch || readPreview.Current.Node.Access.Confirmed || clientCount() != before {
		t.Fatal("status reauthorization silently renewed authority or changed the exact target")
	}
	withoutConsent := do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: candidate.ReviewID, ConfirmNodeIdentity: true})
	if !withoutConsent.ActionFailed || withoutConsent.Current.Node.Access.Confirmed {
		t.Fatal("read-only reauthorization bypassed a new explicit consent gesture")
	}
	readGrant := do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: candidate.ReviewID,
		ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if readGrant.ActionFailed || !readGrant.Current.Node.Access.Confirmed || readGrant.Current.Node.Binding == nil ||
		readGrant.Current.Node.Binding.ID != oldBinding.ID || readGrant.Current.Node.Binding.NodeID != oldBinding.NodeID ||
		readGrant.Current.Authorization.ExpiresAt != oldExpiry || clientCount() != before {
		t.Fatal("explicit status-only grant changed the binding/N2 history or executed another Client RPC")
	}
	var claims []e2ee.OwnerAppNodeGrantClaims
	var cancelledHead uint64
	for _, exchange := range f.proxy.snapshot() {
		if exchange.Path == wire.AppNodeHTTPPath(wire.OperationAppNodeCancel) && exchange.Status == 200 {
			outcome := must(wire.OpenAppNodeResponse(device, f.cfg.Hub, exchange.request, exchange.response))
			if outcome.Result != nil {
				cancelledHead = outcome.Result.Authority.CurrentHeadVersion
			}
		}
		if exchange.Path != wire.AppNodeHTTPPath(wire.OperationAppNodePrepare) || exchange.Status != 200 {
			continue
		}
		opened, err := wire.OpenAppNodeResponse(device, f.cfg.Hub, exchange.request, exchange.response)
		if err != nil || opened.Challenge == nil {
			t.Fatal("actual prepare response did not authenticate under the original App key")
		}
		claims = append(claims, opened.Challenge.Claims)
	}
	if len(claims) != 2 || claims[0].Profile != wire.AppNodeProfileInitial || claims[1].Profile != wire.AppNodeProfileStatus ||
		claims[0].GrantID == claims[1].GrantID || claims[1].PreviousGrantID != claims[0].GrantID ||
		cancelledHead == 0 || claims[1].ExpectedHeadVersion != cancelledHead || claims[1].Scope.HeadVersion != cancelledHead+1 || len(claims[1].AllowedOperations) != 0 ||
		claims[1].ConfirmationLimit != 0 || claims[1].Binding == nil || claims[1].Binding.OwnerBindingID != oldBinding.ID ||
		claims[1].ConfirmationProvenanceID == "" || wire.ValidateAppNodeConfirmationBinding(claims[0], *claims[1].Binding) != nil {
		t.Fatal("real reauthorization did not produce a new exact, finite, zero-confirmation read instance")
	}
	app.kill(t)
	if !reflect.DeepEqual(originalKeys, ownedAppPublicKeys(t, f)) {
		t.Fatal("explicit read reauthorization replaced an original Owner/App identity")
	}
	t.Log("ACTUAL_N3 self_cancel=true new_explicit_read_consent=true same_binding=true same_keys=true new_grant_and_head=true zero_read_grant_RPC=true N2_expiry_unchanged=true")
}

func TestN3ActualUnconfirmedSessionReplacementAllowsNewInitial(t *testing.T) {
	for _, phase := range []string{"prepared", "active-before-confirm"} {
		t.Run(phase, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "replacement-app-ready.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			var initial appActorCheckpoint
			readJSON(t, marker, &initial)
			node := startNodeProcess(t, f, "synthetic-n3-abandoned")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			sequence := 0
			do := func(action appcore.Action) appActorReply {
				sequence++
				return commandApp(t, f, app, sequence, appActorCommand{Action: &action})
			}
			preview := do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
			if preview.ActionFailed || preview.Current.Node.Candidate == nil {
				t.Fatal("original unconfirmed proposal was not prepared")
			}
			if phase == "active-before-confirm" {
				f.proxy.arm("/v2/client/rpc", "before-forward", 1)
				unknown := do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: preview.Current.Node.Candidate.ReviewID,
					ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
				if !unknown.ActionFailed || !unknown.Current.Node.Pending || unknown.Current.Node.Binding != nil {
					t.Fatal("unadmitted confirmation fixture reached an unexpected outcome")
				}
				f.proxy.arm("/v2/client/rpc", "before-forward", 1)
				fenced := do(appcore.Action{Kind: appcore.ActionRecoverNode})
				if fenced.ActionFailed || fenced.Current.Node.Pending || fenced.Current.Node.Binding != nil {
					t.Fatal("unadmitted original was not terminally fenced before changing login")
				}
			}
			logout := do(appcore.Action{Kind: appcore.ActionLogout})
			if logout.ActionFailed || logout.Current.Node.Access.Confirmed {
				t.Fatal("logout retained the old grant as current permission")
			}
			login := do(appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-user", Password: syntheticPassword})
			if login.ActionFailed {
				t.Fatal("actual login replacement could not complete independently of obsolete Node authority")
			}
			terminal := do(appcore.Action{Kind: appcore.ActionRefreshNode})
			if terminal.ActionFailed || terminal.Current.Node.Pending || terminal.Current.Node.Candidate != nil ||
				terminal.Current.Node.Access.Confirmed || terminal.Current.Node.Binding != nil {
				t.Fatal("fresh authenticated terminal status left an obsolete unconfirmed preview or revived authority")
			}
			freshNode := startNodeProcess(t, f, "synthetic-n3-after-login")
			freshPending := freshNode.awaitState(t, f, false)
			freshNode.kill(t)
			newPreview := do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: freshPending.PendingCode})
			if newPreview.ActionFailed || newPreview.Current.Node.Candidate == nil || newPreview.Current.Node.Candidate.NodeID != freshNode.id ||
				newPreview.Current.Node.Candidate.ReviewID == preview.Current.Node.Candidate.ReviewID {
				t.Fatal("terminal unconfirmed instance prevented a safe new INITIAL code/review")
			}
			approved := do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: newPreview.Current.Node.Candidate.ReviewID,
				ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
			if approved.ActionFailed || approved.Current.Node.Binding == nil || approved.Current.Node.Binding.NodeID != freshNode.id ||
				!approved.Current.Node.Access.Confirmed || approved.Current.Authorization.ExpiresAt != initial.Current.Authorization.ExpiresAt ||
				approved.Current.Account.OwnerFingerprint != initial.Current.Account.OwnerFingerprint || approved.Current.Account.DeviceID != initial.Current.Account.DeviceID {
				t.Fatal("new explicit INITIAL changed original identity/N2 history or bound the abandoned Node")
			}
			app.kill(t)
			f.hub.kill(t)
			db := f.db(t)
			defer db.Close()
			machines := must(db.ListOwnerBoundNodeMachines(f.cfg.Material.OwnerID))
			if len(machines) != 1 || machines[0].ID != freshNode.id {
				t.Fatal("abandoned original gained a binding after replacement login/new grant")
			}
			t.Logf("ACTUAL_N3 prior_phase=%s real_logout_and_login_replacement=true authenticated_terminal=true new_explicit_INITIAL=true abandoned_Node_unbound=true N2_expiry_unchanged=true", phase)
		})
	}
}
