package n3_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3OriginalInstanceCannotBorrowNewInitialOrReadGrant(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "instance-account-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	app.kill(t)
	a := newAuthorityWireActor(t, f)
	node := startNodeProcess(t, f, "synthetic-n3-instance-target")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	target := wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode}
	prepare, original, old := a.prepare(t, target)
	defer clear(original)
	live := a.complete(t, prepare, original, old)
	// This retained frame is an independent wire adversary's material, outside
	// the real App pending ledger and never admitted by Hub. A product App may
	// not replace its own unresolved pending request with the next grant.
	oldPacket := must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, old.Claims, pending.PendingCode,
		live.Authority.Counters.LastRequestSequence+1, time.Now().UTC()))
	defer clear(oldPacket)
	cancel := must(wire.NewAppNodeCancel(a.session, old.Claims.GrantID, old.Claims.Scope.HeadVersion, time.Now().UTC()))
	_, ended := a.call(t, wire.OperationAppNodeCancel, cancel)
	if ended.Result == nil || ended.Result.Authority.State != wire.AppNodeCancelled {
		t.Fatal("old unconfirmed instance did not reach authenticated self-cancellation")
	}
	// Explicit re-entry of the same still-PENDING code/candidate is approved by
	// root. Keeping the candidate identical isolates the original grant ID from
	// independent target/key/version refusal guards.
	prepare2, original2, next := a.prepare(t, target)
	defer clear(original2)
	newLive := a.complete(t, prepare2, original2, next)
	if next.Claims.GrantID == old.Claims.GrantID || next.Claims.ExpectedHeadVersion != ended.Result.Authority.CurrentHeadVersion ||
		next.Claims.Scope.HeadVersion != ended.Result.Authority.CurrentHeadVersion+1 ||
		next.Claims.Candidate == nil || old.Claims.Candidate == nil || next.Claims.Candidate.CandidateDigest != old.Claims.Candidate.CandidateDigest {
		t.Fatal("new explicit instance did not retain the identical candidate while changing grant/head")
	}
	code, refused := a.post(t, "/v2/client/rpc", oldPacket)
	defer clear(refused)
	if code != 200 {
		t.Fatal("old unadmitted instance did not receive its durable original-route rejection")
	}
	oldOutcome := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, old.Claims, oldPacket, refused, live.Authority.Counters.NextResponseSequence))
	if oldOutcome.OK || oldOutcome.Error != "AUTHORITY_REVOKED" {
		t.Fatal("old packet borrowed a later instance with the identical valid candidate")
	}
	status := must(wire.NewAppNodeStatus(a.session, next.Claims.GrantID, time.Now().UTC()))
	_, untouched := a.call(t, wire.OperationAppNodeStatus, status)
	if untouched.Result == nil || untouched.Result.Node != nil || untouched.Result.Authority.RemainingConfirmations != 1 ||
		untouched.Result.Authority.Counters.LastRequestSequence != live.Authority.Counters.LastRequestSequence+1 ||
		untouched.Result.Authority.Counters.NextResponseSequence != live.Authority.Counters.NextResponseSequence+1 {
		t.Fatal("old-instance refusal consumed the new grant or did not fence exactly its own Client slot")
	}
	f.hub.kill(t)
	db := f.db(t)
	if len(must(db.ListOwnerBoundNodeMachines(a.scope.OwnerID))) != 0 {
		t.Fatal("old-instance request created a binding under later authority")
	}
	db.Close()
	f.start(t)
	code, repeated := a.post(t, "/v2/client/rpc", oldPacket)
	defer clear(repeated)
	if code != 200 || !bytes.Equal(refused, repeated) {
		t.Fatal("old instance's exact permanent fence changed after actual Hub restart")
	}
	newPacket := must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, next.Claims, pending.PendingCode,
		untouched.Result.Authority.Counters.LastRequestSequence+1, time.Now().UTC()))
	defer clear(newPacket)
	code, confirmed := a.post(t, "/v2/client/rpc", newPacket)
	defer clear(confirmed)
	if code != 200 {
		t.Fatal("new explicit grant could not use its own next counter slot after the old fence")
	}
	newOutcome := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, next.Claims, newPacket, confirmed,
		untouched.Result.Authority.Counters.NextResponseSequence))
	if !newOutcome.OK || newOutcome.Binding == nil || newOutcome.Binding.NodeID != node.id {
		t.Fatal("new explicit grant did not confirm only its exact unchanged target")
	}
	cancel2 := must(wire.NewAppNodeCancel(a.session, next.Claims.GrantID, next.Claims.Scope.HeadVersion, time.Now().UTC()))
	a.call(t, wire.OperationAppNodeCancel, cancel2)
	readPrepare, readOriginal, readChallenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetPrevious, PreviousGrantID: next.Claims.GrantID})
	defer clear(readOriginal)
	read := a.complete(t, readPrepare, readOriginal, readChallenge)
	if readChallenge.Claims.Profile != wire.AppNodeProfileStatus || len(readChallenge.Claims.AllowedOperations) != 0 || readChallenge.Claims.ConfirmationLimit != 0 {
		t.Fatal("new read-only instance widened its signed operation profile")
	}
	// Deliberately bypass the positive confirmation constructor's local profile
	// refusal. The real Hub must independently enforce READ_EXISTING's zero RPC.
	var base clientwire.Packet
	if json.Unmarshal(newPacket, &base) != nil {
		t.Fatal("genuine confirmation route cannot be inspected")
	}
	route := base.Route
	route.OperationID = must(wire.AppNodeBusinessOperationID(readChallenge.Claims.GrantID, must(wire.NewRequestID())))
	route.Sequence = read.Authority.Counters.LastRequestSequence + 1
	body := must(json.Marshal(struct {
		Code    string `json:"user_code"`
		Digest  string `json:"candidate_digest"`
		Version uint64 `json:"candidate_version"`
	}{must(wire.NormalizeAppNodeCode(pending.PendingCode)), next.Claims.Candidate.CandidateDigest, next.Claims.Candidate.Version}))
	binding := clientwire.Binding{HubID: f.cfg.Hub.HubID, OwnerID: a.scope.OwnerID, DeviceID: a.scope.DeviceID,
		SessionEpoch: readChallenge.Claims.Scope.ClientSessionEpoch, HubKeyVersion: f.cfg.Hub.KeyVersion, DeviceKeyVersion: wire.DeviceKeyVersion}
	forbidden := must(clientwire.SealRequest(a.device, f.cfg.Hub.Public, binding, route, body))
	defer clear(forbidden)
	code, denied := a.post(t, "/v2/client/rpc", forbidden)
	defer clear(denied)
	if code != 200 {
		t.Fatal("read-only business refusal did not retain its authenticated original-route result")
	}
	denial := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, readChallenge.Claims, forbidden, denied, read.Authority.Counters.NextResponseSequence))
	if denial.OK || denial.Error != "CONFIRMATION_USED" {
		t.Fatal("read-only profile authorized a confirmation or escaped its zero budget")
	}
	code, historical := a.post(t, "/v2/client/rpc", newPacket)
	defer clear(historical)
	if code != 200 || !bytes.Equal(historical, confirmed) {
		t.Fatal("new read authority replaced the exact original successful confirmation history")
	}
	readStatus := must(wire.NewAppNodeStatus(a.session, readChallenge.Claims.GrantID, time.Now().UTC()))
	_, current := a.call(t, wire.OperationAppNodeStatus, readStatus)
	if current.Result == nil || current.Result.Authority.Profile != wire.AppNodeProfileStatus ||
		current.Result.Authority.RemainingConfirmations != 0 || len(current.Result.Authority.AllowedOperations) != 0 ||
		current.Result.Node == nil || current.Result.Node.BindingID != newOutcome.Binding.OwnerBindingID ||
		newLive.Authority.Scope.HeadVersion != next.Claims.Scope.HeadVersion {
		t.Fatal("old receipt replay/read-only rejection changed current target or revived confirmation rights")
	}
	t.Log("ACTUAL_N3 wire_adversary_presealed_outside_App_pending_ledger=true same_candidate_new_explicit_grant=true old_instance_fenced_before_next_slot=true new_budget_not_borrowed=true read_profile_server_refuses_confirmation=true historical_receipt_does_not_revive_permission=true")
}
