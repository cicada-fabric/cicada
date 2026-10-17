package n3_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestN3StatusContainsOnlyExactSelectedNode(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "privacy-account-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	app.kill(t)
	a := newAuthorityWireActor(t, f)
	selected := startNodeProcess(t, f, "synthetic-n3-visible-node")
	pending := selected.awaitState(t, f, false)
	selected.kill(t)
	prepare, original, challenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode})
	defer clear(original)
	live := a.complete(t, prepare, original, challenge)
	confirm := must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, challenge.Claims, pending.PendingCode,
		live.Authority.Counters.LastRequestSequence+1, time.Now().UTC()))
	defer clear(confirm)
	code, receipt := a.post(t, "/v2/client/rpc", confirm)
	defer clear(receipt)
	if code != 200 {
		t.Fatal("privacy fixture did not confirm the actual selected Node")
	}
	confirmation := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, challenge.Claims, confirm, receipt,
		live.Authority.Counters.NextResponseSequence))
	if !confirmation.OK || confirmation.Binding == nil {
		t.Fatal("privacy fixture lacks a genuine exact confirmation receipt")
	}
	other := startNodeProcess(t, f, "synthetic-n3-private-other-node")
	otherPending := other.awaitState(t, f, false)
	other.kill(t)
	f.hub.kill(t)
	db := f.db(t)
	c := otherPending.PendingCandidate
	// Privileged fixture setup seeds unrelated, same-Owner business data through
	// existing Store methods. It is not an N3 App authorization or Runtime test.
	must(db.ConfirmNodeControlKeyRequest(a.scope.OwnerID, a.scope.DeviceID,
		must(wire.AppNodeCodeDigest(f.cfg.Hub.HubID, otherPending.PendingCode)), int64(c.Version), c.CandidateDigest, c.HubKeyID, c.HubFingerprint))
	goal := must(db.CreateOwnedGoal(a.scope.OwnerID, store.Goal{ID: "synthetic-n3-private-goal",
		Objective: "SYNTHETIC_N3_PRIVATE_GOAL", SuccessCriteria: "SYNTHETIC_N3_PRIVATE_CRITERIA", MachineID: other.id}))
	must(db.CreateWorkerAt("synthetic-n3-private-worker", goal.ID, other.id,
		filepath.Join(f.dir, "SYNTHETIC_N3_PRIVATE_RESULT"), filepath.Join(f.dir, "SYNTHETIC_N3_PRIVATE_WORKSPACE")))
	group := must(db.CreateGroup(store.Group{Name: "SYNTHETIC_N3_PRIVATE_GROUP", OwnerPrincipalID: a.scope.OwnerID, State: store.GroupStateActive}))
	must(db.CreateSharedTask(store.SharedTask{GroupID: group.ID, Objective: "SYNTHETIC_N3_PRIVATE_TASK", AcceptanceCriteria: "private fixture only"}))
	if len(must(db.ListOwnerBoundNodeMachines(a.scope.OwnerID))) != 2 {
		t.Fatal("privacy canary did not contain an unrelated same-Owner Node")
	}
	db.Close()
	f.start(t)
	request := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
	packet := must(wire.SealClientRequest(a.device, f.cfg.Hub, request))
	defer clear(packet)
	code, response := a.post(t, wire.AppNodeHTTPPath(wire.OperationAppNodeStatus), packet)
	defer clear(response)
	if code != 200 {
		t.Fatal("actual authorized Node-only status is unavailable")
	}
	opened := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, packet, response))
	if opened.Result == nil || opened.Result.Node == nil || opened.Result.Node.NodeID != selected.id ||
		opened.Result.Node.BindingID != confirmation.Binding.OwnerBindingID {
		t.Fatal("Node-only status did not select the exact original confirmed binding")
	}
	raw := rawAuthorityReply(t, a, packet, response)
	defer clear(raw)
	if bytes.Contains(raw, []byte("SYNTHETIC_N3_PRIVATE")) || bytes.Contains(raw, []byte(other.id)) ||
		bytes.Contains(raw, []byte("synthetic-n3-private-worker")) || bytes.Contains(raw, []byte(goal.ID)) {
		t.Fatal("Node-only status leaked unrelated same-Owner Node/business canary data")
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("actual privacy observation is not bounded JSON")
	}
	var inspect func(any)
	inspect = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				switch strings.ToLower(key) {
				case "goals", "tasks", "workers", "threads", "providers", "nodes", "capability_profiles", "messages", "canvas":
					t.Fatal("Node-only payload includes a forbidden owner-wide collection")
				}
				inspect(child)
			}
		case []any:
			for _, child := range value {
				inspect(child)
			}
		}
	}
	inspect(value)
	t.Log("ACTUAL_N3 selected_Node_only=true raw_JSON_inspected_after_real_PQ_open=true unrelated_same_Owner_Node_Goal_Task_Worker_canaries_absent=true Runtime_NOT_RUN=true")
}
