package n3_test

import (
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3ActualImmediateRelayHeartbeatRetainsSubsecondOrder(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "heartbeat-account-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	app.kill(t)
	a := newAuthorityWireActor(t, f)
	node := startNodeProcess(t, f, "synthetic-n3-immediate-heartbeat")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	prepare, original, challenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode})
	defer clear(original)
	live := a.complete(t, prepare, original, challenge)
	packet := must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, challenge.Claims, pending.PendingCode,
		live.Authority.Counters.LastRequestSequence+1, time.Now().UTC()))
	defer clear(packet)
	code, response := a.post(t, "/v2/client/rpc", packet)
	defer clear(response)
	if code != 200 {
		t.Fatal("immediate-heartbeat fixture did not confirm its real Node")
	}
	confirmation := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, challenge.Claims, packet, response,
		live.Authority.Counters.NextResponseSequence))
	if !confirmation.OK || confirmation.Binding == nil {
		t.Fatal("immediate-heartbeat fixture lacks its authenticated confirmation")
	}
	approved := must(time.Parse(time.RFC3339Nano, confirmation.Binding.ApprovedAt))
	var previous time.Time
	precise := false
	for i := 0; i < 3; i++ {
		// No wait/sleep to cross a second. A real relay-only one-shot agent
		// probes its just-approved bearer and immediately sends accepted {}.
		started := time.Now().UTC()
		once := startNodeProcessMode(t, f, node.id, true)
		select {
		case <-once.done:
			if once.cmd.ProcessState == nil || !once.cmd.ProcessState.Success() {
				once.reportFailure(t)
				t.Fatal("actual one-shot bound relay Node exited unsuccessfully")
			}
		case <-time.After(15 * time.Second):
			t.Fatal("actual one-shot relay heartbeat did not finish")
		}
		status := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
		_, observed := a.call(t, wire.OperationAppNodeStatus, status)
		if observed.Result == nil || observed.Result.Node == nil || observed.Result.Node.Connectivity != "CONNECTED" ||
			!observed.Result.Node.Known || observed.Result.Node.Stale {
			t.Fatal("immediate accepted heartbeat was misclassified as unknown/preapproval")
		}
		heartbeat := must(time.Parse(time.RFC3339Nano, observed.Result.Node.LastHeartbeatAt))
		if heartbeat.Before(approved) || heartbeat.Before(started) || (!previous.IsZero() && !heartbeat.After(previous)) {
			t.Fatal("accepted relay heartbeat truncated or reversed actual approval/send ordering")
		}
		precise = precise || heartbeat.Nanosecond() != 0
		previous = heartbeat
	}
	if !precise {
		t.Fatal("accepted relay heartbeat writers discarded all subsecond precision")
	}
	f.hub.kill(t)
	db := f.db(t)
	defer db.Close()
	machine := must(db.OwnerBoundNodeMachine(a.scope.OwnerID, node.id))
	if machine.Status != "offline" || !must(time.Parse(time.RFC3339Nano, machine.LastSeen)).Equal(previous) {
		t.Fatal("signed heartbeat does not match persisted last_seen or fabricated Worker availability")
	}
	t.Log("ACTUAL_N3 immediate_first_relay_heartbeat=true no_sleep_across_second=true accepted_last_seen_ge_approved_at=true three_actual_Node_CLI_processes=true heartbeat_monotone_nanosecond_precision=true Worker_status_offline=true")
}
