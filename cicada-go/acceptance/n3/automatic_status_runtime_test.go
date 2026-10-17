package n3_test

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The actual App child receives the approved automatic Action DTO through its
// existing private mailbox. Explicit triggers test the production Core entry;
// they do not claim to execute the Windows window's 30-second scheduler.
type automaticStatusFixture struct {
	f        *hubFixture
	app      *appProcess
	node     *nodeProcess
	sequence int
	current  appcore.Snapshot
	keys     map[appvault.Purpose]e2ee.PublicIdentity
	device   *e2ee.Identity
}

func newAutomaticStatusFixture(t *testing.T, id string) *automaticStatusFixture {
	t.Helper()
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "auto-bootstrap.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	app.kill(t)
	a := &automaticStatusFixture{f: f, keys: ownedAppPublicKeys(t, f), device: ownedAppIdentity(t, f, appvault.PurposeAppDevice)}
	marker = filepath.Join(f.dir, "auto-resume.json")
	a.app = startAppProcess(t, f, "resume-node", marker)
	awaitMarker(t, a.app.process, marker)
	a.node = startNodeProcess(t, f, id)
	pending := a.node.awaitState(t, f, false)
	a.node.kill(t)
	preview := a.do(t, appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
	if preview.ActionFailed || preview.Current.Node.Candidate == nil {
		t.Fatal("automatic status fixture lacks its actual selected Node preview")
	}
	approved := a.do(t, appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: preview.Current.Node.Candidate.ReviewID,
		ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if approved.ActionFailed || approved.Current.Node.Binding == nil || !approved.Current.Node.Access.Confirmed ||
		approved.Current.Node.Candidate != nil || approved.Current.Node.Connectivity.Known {
		t.Fatal("automatic status fixture lacks confirmed access to its stopped, heartbeat-unknown Node")
	}
	return a
}

func (a *automaticStatusFixture) do(t *testing.T, action appcore.Action) appActorReply {
	t.Helper()
	a.sequence++
	reply := commandApp(t, a.f, a.app, a.sequence, appActorCommand{Action: &action})
	a.current = reply.Current
	return reply
}

func (a *automaticStatusFixture) target(t *testing.T) appcore.NodeStatusTarget {
	t.Helper()
	target, eligible := appcore.AutomaticNodeStatusTarget(a.current, time.Now().UTC())
	if !eligible || target.ReviewID == "" || target.BindingID != a.current.Node.Binding.ID || target.NodeID != a.node.id {
		t.Fatal("current authorized binding did not yield its exact automatic status target")
	}
	return target
}

func automaticAction(target appcore.NodeStatusTarget) appcore.Action {
	return appcore.Action{Kind: appcore.ActionRefreshNode, AutoNodeStatus: &target}
}

func automaticVaultDigest(t *testing.T, f *hubFixture) string {
	t.Helper()
	paths := must(filepath.Glob(filepath.Join(f.dir, "synthetic-app", "vaults", "*.vault")))
	if len(paths) != 1 {
		t.Fatal("automatic status fixture lacks its unique encrypted vault")
	}
	raw := readPrivate(t, paths[0])
	defer clear(raw)
	return hash(raw)
}

func (a *automaticStatusFixture) rejectedWithoutEffect(t *testing.T, target appcore.NodeStatusTarget) {
	t.Helper()
	count, digest := len(a.f.proxy.snapshot()), automaticVaultDigest(t, a.f)
	reply := a.do(t, automaticAction(target))
	if !reply.ActionFailed || reply.ActionError != "INVALID_ACTION" || len(a.f.proxy.snapshot()) != count ||
		automaticVaultDigest(t, a.f) != digest {
		t.Fatal("ineligible automatic trigger sent traffic, changed durable state or returned an unrelated error")
	}
}

func (a *automaticStatusFixture) latestResult(t *testing.T) wire.AppNodeResult {
	t.Helper()
	trace := a.f.proxy.snapshot()
	for i := len(trace) - 1; i >= 0; i-- {
		x := trace[i]
		if x.Path != wire.AppNodeHTTPPath(wire.OperationAppNodeStatus) || x.Status != 200 {
			continue
		}
		r := must(wire.OpenAppNodeResponse(a.device, a.f.cfg.Hub, x.request, x.response))
		if r.Result == nil || r.Result.Authority.GrantID == "" {
			t.Fatal("automatic status result lacks its authenticated original grant")
		}
		return *r.Result
	}
	t.Fatal("automatic status fixture has no authenticated status response")
	return wire.AppNodeResult{}
}

func (a *automaticStatusFixture) readOnlyResult(t *testing.T, before wire.AppNodeResult, from int) wire.AppNodeResult {
	t.Helper()
	trace := a.f.proxy.snapshot()[from:]
	if len(trace) != 1 || trace[0].Path != wire.AppNodeHTTPPath(wire.OperationAppNodeStatus) || !trace[0].Forwarded || trace[0].Status != 200 {
		t.Fatal("automatic entry sent anything except one real selected-grant status POST")
	}
	after := a.latestResult(t)
	x, y := before.Authority, after.Authority
	if after.Operation != wire.OperationAppNodeStatus || after.State != wire.AppNodeCompleted || y.State != wire.AppNodeActive ||
		x.GrantID != y.GrantID || x.CurrentHeadVersion != y.CurrentHeadVersion || !reflect.DeepEqual(x.Scope, y.Scope) ||
		!reflect.DeepEqual(x.Counters, y.Counters) || x.RemainingConfirmations != y.RemainingConfirmations {
		t.Fatal("automatic status changed scope, grant/head, Client counters or confirmation budget")
	}
	return after
}

func automaticNodeOnce(t *testing.T, f *hubFixture, id string) (*nodeProcess, nodeActorState) {
	t.Helper()
	node := startNodeProcessMode(t, f, id, true)
	select {
	case <-node.done:
		if node.cmd.ProcessState == nil || !node.cmd.ProcessState.Success() {
			node.reportFailure(t)
			t.Fatal("actual retained Node one-shot process failed")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("actual retained Node one-shot process did not finish")
	}
	var state nodeActorState
	readJSON(t, node.statePath(), &state)
	if state.BindingID == "" || state.PendingCandidate != nil || state.NodeID != id {
		t.Fatal("actual one-shot Node did not retain its approved binding")
	}
	return node, state
}

func TestN3ActualAutomaticStatusKeepsScopeAndSelfCancelledNode(t *testing.T) {
	a := newAutomaticStatusFixture(t, "synthetic-n3-auto-status")
	target := a.target(t)
	for _, edit := range []func(*appcore.NodeStatusTarget){
		func(v *appcore.NodeStatusTarget) { v.ReviewID = "synthetic-stale-review" },
		func(v *appcore.NodeStatusTarget) { v.BindingVersion++ },
		func(v *appcore.NodeStatusTarget) { v.OwnerID = "synthetic-other-owner" },
		func(v *appcore.NodeStatusTarget) { v.NodeID = "synthetic-n3-other-node" },
		func(v *appcore.NodeStatusTarget) { v.Origin = "http://127.0.0.1:1" },
	} {
		wrong := target
		edit(&wrong)
		a.rejectedWithoutEffect(t, wrong)
	}
	// This is an App-only logical guard test, not a real lease-expiry wait.
	count, image := len(a.f.proxy.snapshot()), automaticVaultDigest(t, a.f)
	a.sequence++
	action := automaticAction(target)
	expired := commandApp(t, a.f, a.app, a.sequence, appActorCommand{Action: &action, ClockOffsetSeconds: 16 * 60})
	if !expired.ActionFailed || expired.ActionError != "INVALID_ACTION" || expired.ClockMode != "APP_LOGICAL_CLOCK_ONLY" ||
		len(a.f.proxy.snapshot()) != count || automaticVaultDigest(t, a.f) != image {
		t.Fatal("logically expired automatic guard sent traffic or performed an account/vault transition")
	}
	// Reset the test-only clock and republish via another refused exact-scope
	// action. Neither rejection may mutate the persisted original authority.
	wrong := target
	wrong.ReviewID = "synthetic-clock-reset-rejected-review"
	a.rejectedWithoutEffect(t, wrong)
	before := a.latestResult(t)
	count = len(a.f.proxy.snapshot())
	unknown := a.do(t, automaticAction(target))
	if unknown.ActionFailed || unknown.Current.Node.Pending || unknown.Current.Node.Connectivity.Known {
		t.Fatal("valid automatic status failed for a bound Node without a heartbeat")
	}
	a.readOnlyResult(t, before, count)
	node, original := automaticNodeOnce(t, a.f, a.node.id)
	identityPath := filepath.Join(filepath.Dir(node.statePath()), "node-control-identity.bin")
	tokenPath := filepath.Join(filepath.Dir(node.statePath()), "relay.token")
	identity, token := readPrivate(t, identityPath), readPrivate(t, tokenPath)
	defer clear(identity)
	defer clear(token)
	count = len(a.f.proxy.snapshot())
	online := a.do(t, automaticAction(target))
	if online.ActionFailed || online.Current.Node.ConnectionState() != appcore.NodeOnline {
		t.Fatal("automatic entry did not observe the actual Node CLI heartbeat")
	}
	observed := a.readOnlyResult(t, before, count)
	if observed.Node == nil || observed.Node.LastHeartbeatAt == "" || observed.Node.NodeID != a.node.id {
		t.Fatal("automatic response lost its exact real Node observation")
	}
	cancelled := a.do(t, appcore.Action{Kind: appcore.ActionCancelNodeAccess, NodeReviewID: target.ReviewID})
	if cancelled.ActionFailed || cancelled.Current.Node.Access.State != wire.AppNodeCancelled {
		t.Fatal("explicit App self-cancellation failed")
	}
	a.rejectedWithoutEffect(t, target)
	_, retained := automaticNodeOnce(t, a.f, a.node.id)
	if original.BindingID != retained.BindingID || original.BindingVersion != retained.BindingVersion ||
		original.NodeKeyID != retained.NodeKeyID || original.NodeFingerprint != retained.NodeFingerprint || original.NodeKeyEpoch != retained.NodeKeyEpoch ||
		hash(readPrivate(t, identityPath)) != hash(identity) || hash(readPrivate(t, tokenPath)) != hash(token) {
		t.Fatal("App self-cancellation forced a new Node pairing, key or credential")
	}
	// A separate explicit human gesture creates READ_EXISTING for the exact
	// saved binding. These Owner-signed operations are not automatic traffic.
	preview := a.do(t, appcore.Action{Kind: appcore.ActionReauthorizeNodeStatus})
	if preview.ActionFailed || preview.Current.Node.Candidate == nil || !preview.Current.Node.Candidate.StatusOnly {
		t.Fatal("manual status-only consent did not obtain its original binding preview")
	}
	readGrant := a.do(t, appcore.Action{Kind: appcore.ActionApproveNode,
		NodeReviewID: preview.Current.Node.Candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if readGrant.ActionFailed || readGrant.Current.Node.Binding == nil || readGrant.Current.Node.Binding.ID != original.BindingID {
		t.Fatal("manual status-only consent changed or failed the saved binding")
	}
	readTarget := a.target(t)
	readBefore, count := a.latestResult(t), len(a.f.proxy.snapshot())
	if readBefore.Authority.Profile != wire.AppNodeProfileStatus || readBefore.Authority.RemainingConfirmations != 0 || len(readBefore.Authority.AllowedOperations) != 0 {
		t.Fatal("explicit read-only grant acquired a confirmation or business capability")
	}
	if a.do(t, automaticAction(readTarget)).ActionFailed {
		t.Fatal("automatic guard rejected an authorized READ_EXISTING binding")
	}
	a.readOnlyResult(t, readBefore, count)
	// Inject terminal authority only in the stopped private synthetic DB. The
	// actual Hub must sign that terminal status; it is not a local cancel skip.
	a.f.hub.kill(t)
	fixtureDB := must(sql.Open("sqlite", filepath.Join(a.f.dir, "synthetic-hub", "cicada.sqlite3")))
	t.Cleanup(func() { fixtureDB.Close() })
	changed, err := fixtureDB.Exec(`UPDATE hub_app_node_grants_v1 SET state='REVOKED',reason='SECURITY_FENCE' WHERE grant_id=? AND state='ACTIVE'`, readBefore.Authority.GrantID)
	if err != nil || must(changed.RowsAffected()) != 1 || fixtureDB.Close() != nil {
		t.Fatal("private grant revocation did not affect exactly its active instance")
	}
	a.f.start(t)
	count = len(a.f.proxy.snapshot())
	terminal := a.do(t, automaticAction(readTarget))
	if terminal.ActionFailed || terminal.Current.Node.Pending || terminal.Current.Node.Access.State != wire.AppNodeRevoked || terminal.Current.Node.Access.Confirmed {
		t.Fatal("authenticated terminal auto status became uncertainty or retained access")
	}
	terminalTrace := a.f.proxy.snapshot()[count:]
	ended := a.latestResult(t)
	if len(terminalTrace) != 1 || terminalTrace[0].Path != wire.AppNodeHTTPPath(wire.OperationAppNodeStatus) || terminalTrace[0].Status != 200 ||
		ended.State != wire.AppNodeCompleted || ended.Authority.State != wire.AppNodeRevoked || ended.Authority.GrantID != readBefore.Authority.GrantID ||
		ended.Node != nil || ended.Authority.RemainingConfirmations != 0 || len(ended.Authority.AllowedOperations) != 0 ||
		!reflect.DeepEqual(ended.Authority.Counters, readBefore.Authority.Counters) {
		t.Fatal("automatic entry did not consume the exact signed revoked read-only result")
	}
	for i := 0; i < 2; i++ {
		a.rejectedWithoutEffect(t, readTarget)
	}
	a.app.kill(t)
	if !reflect.DeepEqual(a.keys, ownedAppPublicKeys(t, a.f)) {
		t.Fatal("automatic status or cancellation replaced an original App/Owner key")
	}
	a.f.hub.kill(t)
	db := a.f.db(t)
	defer db.Close()
	machine := must(db.OwnerBoundNodeMachine(a.f.cfg.Material.OwnerID, a.node.id))
	if machine == nil || machine.LastSeen == "" || !must(time.Parse(time.RFC3339Nano, machine.LastSeen)).After(must(time.Parse(time.RFC3339Nano, observed.Node.LastHeartbeatAt))) {
		t.Fatal("Node failed to commit a later real heartbeat after App self-cancellation")
	}
	t.Log("ACTUAL_AUTO_CORE explicit_test_triggers=true automatic_segments_only_status_POST=true manual_INITIAL_READ_EXISTING_consent_separate=true signed_server_revocation_settled_no_pending=true unchanged_budget_Client_sequence=true wrong_scope_and_APP_LOGICAL_CLOCK_ONLY_expiry_zero_write=true unknown_then_actual_Node_heartbeat=true SELF_CANCEL_preserves_Node_pairing=true full_N3_natural_expiry_NOT_RUN=true Windows_30s_timer_NOT_RUN=true")
}

func TestN3ActualAutomaticStatusLossFreezesTicksUntilExactRecovery(t *testing.T) {
	a := newAutomaticStatusFixture(t, "synthetic-n3-auto-loss")
	target := a.target(t)
	before, count := a.latestResult(t), len(a.f.proxy.snapshot())
	a.f.proxy.arm(wire.AppNodeHTTPPath(wire.OperationAppNodeStatus), "drop-after-response", 1)
	lost := a.do(t, automaticAction(target))
	if !lost.ActionFailed || !lost.Current.Node.Pending || lost.Current.Node.Access.Confirmed {
		t.Fatal("lost automatic response did not retain original pending uncertainty")
	}
	a.readOnlyResult(t, before, count)
	trace := a.f.proxy.snapshot()
	original := trace[len(trace)-1]
	for i := 0; i < 3; i++ {
		a.rejectedWithoutEffect(t, target)
	}
	oldApp, oldHub := a.app.cmd.Process.Pid, a.f.hub.cmd.Process.Pid
	a.app.kill(t)
	vault := ownedAppVault(t, a.f)
	saved := decodePersistedNode(t, vault)
	vault.Close()
	if saved.Pending == nil || saved.Pending.Applied || len(saved.Pending.Response) != 0 ||
		saved.Pending.Operation != wire.OperationAppNodeStatus || !bytes.Equal(saved.Pending.Request, original.request) {
		t.Fatal("lost automatic status did not persist its exact original ciphertext")
	}
	defer clear(saved.Pending.Request)
	a.f.hub.kill(t)
	a.f.start(t)
	marker := filepath.Join(a.f.dir, "auto-loss-reopened.json")
	a.app = startAppProcess(t, a.f, "resume-node", marker)
	awaitMarker(t, a.app.process, marker)
	a.sequence = 0
	if a.app.cmd.Process.Pid == oldApp || a.f.hub.cmd.Process.Pid == oldHub {
		t.Fatal("automatic uncertainty test did not restart both real processes")
	}
	for i := 0; i < 3; i++ {
		a.rejectedWithoutEffect(t, target)
	}
	count = len(a.f.proxy.snapshot())
	recovered := a.do(t, appcore.Action{Kind: appcore.ActionRecoverNode})
	if recovered.ActionFailed || recovered.Current.Node.Pending || !recovered.Current.Node.Access.Confirmed {
		t.Fatal("manual exact recovery could not settle the original automatic read")
	}
	var retry []exchange
	for _, x := range a.f.proxy.snapshot()[count:] {
		if x.Path == wire.AppNodeCapabilitiesPath && x.Status == 200 {
			continue // Reopened App discovers before its first N3 secret POST.
		}
		if x.Path != original.Path || x.Status != 200 {
			t.Fatal("manual recovery sent an unrelated secret operation")
		}
		retry = append(retry, x)
	}
	if len(retry) != 3 || !bytes.Equal(retry[0].request, original.request) || !bytes.Equal(retry[0].response, original.response) {
		t.Fatal("manual recovery replaced the automatic ciphertext or its authenticated original receipt")
	}
	// Production recovery settles the immutable original first, then performs
	// two explicit fresh reads (context and grant). Historical success alone
	// must never make the background loop eligible again.
	for i, grantID := range []string{"", before.Authority.GrantID} {
		x := retry[i+1]
		fresh := must(wire.OpenAppNodeResponse(a.device, a.f.cfg.Hub, x.request, x.response))
		if bytes.Equal(x.request, original.request) || fresh.Result == nil || fresh.Result.State != wire.AppNodeCompleted || fresh.Result.Authority.GrantID != grantID {
			t.Fatal("manual recovery skipped the explicit fresh context/grant reads")
		}
	}
	count = len(a.f.proxy.snapshot())
	resumed := a.do(t, automaticAction(target))
	if resumed.ActionFailed || resumed.Current.Node.Pending {
		t.Fatal("settled original scope could not resume one new automatic status")
	}
	a.readOnlyResult(t, before, count)
	a.app.kill(t)
	if !reflect.DeepEqual(a.keys, ownedAppPublicKeys(t, a.f)) {
		t.Fatal("automatic error/restart/recovery replaced original identity keys")
	}
	t.Logf("ACTUAL_AUTO_CORE committed_reply_lost=true same_pending_sha256=%s three_triggers_before_and_after_real_App_Hub_restart_sent_no_new_packet=true manual_exact_recovery_required=true Windows_scheduler_NOT_RUN=true", hash(original.request))
}
