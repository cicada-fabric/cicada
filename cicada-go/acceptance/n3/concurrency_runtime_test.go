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

func TestN3ConcurrentPrepareConfirmAndConflictingReplay(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "concurrent-account-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	app.kill(t)
	a := newAuthorityWireActor(t, f)
	nodes := []string{"synthetic-n3-concurrent-a", "synthetic-n3-concurrent-b"}
	pending := make([]nodeActorState, 2)
	requests := make([]wire.AppNodePrepare, 2)
	packets := make([][]byte, 2)
	for i, id := range nodes {
		node := startNodeProcess(t, f, id)
		pending[i] = node.awaitState(t, f, false)
		node.kill(t)
		requests[i] = must(wire.NewAppNodePrepare(a.session, a.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending[i].PendingCode}, a.owner, time.Now().UTC()))
		packets[i] = must(wire.SealClientRequest(a.device, f.cfg.Hub, requests[i]))
	}
	path := wire.AppNodeHTTPPath(wire.OperationAppNodePrepare)
	results := parallelPosts(t, f, []string{path, path}, packets)
	winner, winners := -1, 0
	var challenge wire.AppNodeChallenge
	for i, result := range results {
		if result.status == 200 {
			opened := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, packets[i], result.response))
			if opened.Challenge != nil {
				winner, winners, challenge = i, winners+1, *opened.Challenge
			} else if opened.Result == nil || opened.Result.State != wire.AppNodeRejectedFenced {
				t.Fatal("concurrent prepare produced neither an exact challenge nor a terminal refusal")
			}
		} else if result.status != 403 && result.status != 409 {
			t.Fatalf("concurrent prepare reached unavailable/error HTTP=%d", result.status)
		}
		clear(result.response)
	}
	if winners != 1 {
		t.Fatal("same-App current-head reservation did not have exactly one durable winner")
	}
	live := a.complete(t, requests[winner], packets[winner], challenge)
	requestSequence, responseSequence := live.Authority.Counters.LastRequestSequence+1, live.Authority.Counters.NextResponseSequence
	confirm := make([][]byte, 2)
	for i := range confirm {
		confirm[i] = must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, challenge.Claims, pending[winner].PendingCode, requestSequence, time.Now().UTC()))
	}
	confirmationResults := parallelPosts(t, f, []string{"/v2/client/rpc", "/v2/client/rpc"}, confirm)
	confirmed, successes := -1, 0
	for i, result := range confirmationResults {
		if result.status == 200 {
			opened := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, challenge.Claims, confirm[i], result.response, responseSequence))
			if opened.OK {
				confirmed, successes = i, successes+1
				if opened.Binding == nil || opened.Binding.NodeID != nodes[winner] {
					t.Fatal("concurrent confirmation substituted the winning Node")
				}
			}
		} else if result.status != 403 && result.status != 409 {
			t.Fatalf("concurrent confirmation reached unavailable/error HTTP=%d", result.status)
		}
	}
	if successes != 1 {
		t.Fatal("one finite confirmation budget/counter slot had more or fewer than one successful mutation")
	}
	f.hub.kill(t)
	db := f.db(t)
	machines := must(db.ListOwnerBoundNodeMachines(f.cfg.Material.OwnerID))
	if len(machines) != 1 || machines[0].ID != nodes[winner] || machines[0].Status != "offline" || machines[0].LastSeen != "" {
		t.Fatal("concurrent confirmation left duplicate/substituted/partially-online bindings")
	}
	db.Close()
	f.start(t)
	code, receipt := a.post(t, "/v2/client/rpc", confirm[confirmed])
	defer clear(receipt)
	if code != 200 || !bytes.Equal(receipt, confirmationResults[confirmed].response) {
		t.Fatal("actual Hub restart did not preserve the winning exact confirmation receipt")
	}
	// Same operation ID and same semantic body, but genuinely different PQ
	// ciphertext, must not alias the permanent original request/digest receipt.
	var original clientwire.Packet
	if json.Unmarshal(confirm[confirmed], &original) != nil {
		t.Fatal("genuine confirmation packet cannot be inspected")
	}
	body := must(json.Marshal(struct {
		Code    string `json:"user_code"`
		Digest  string `json:"candidate_digest"`
		Version uint64 `json:"candidate_version"`
	}{must(wire.NormalizeAppNodeCode(pending[winner].PendingCode)), challenge.Claims.Candidate.CandidateDigest, challenge.Claims.Candidate.Version}))
	binding := clientwire.Binding{HubID: f.cfg.Hub.HubID, OwnerID: a.scope.OwnerID, DeviceID: a.scope.DeviceID,
		SessionEpoch: challenge.Claims.Scope.ClientSessionEpoch, HubKeyVersion: f.cfg.Hub.KeyVersion, DeviceKeyVersion: wire.DeviceKeyVersion}
	conflict := must(clientwire.SealRequest(a.device, f.cfg.Hub.Public, binding, original.Route, body))
	defer clear(conflict)
	if bytes.Equal(conflict, confirm[confirmed]) {
		t.Fatal("conflicting ciphertext fixture unexpectedly reused the exact original")
	}
	code, response := a.post(t, "/v2/client/rpc", conflict)
	defer clear(response)
	if code == 200 {
		opened := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, challenge.Claims, conflict, response, responseSequence))
		if opened.OK {
			t.Fatal("same ID/different ciphertext borrowed the original successful receipt")
		}
	} else if code != 403 && code != 409 {
		t.Fatal("conflicting replay reached an unavailable/error response")
	}
	status := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
	_, current := a.call(t, wire.OperationAppNodeStatus, status)
	if current.Result == nil || current.Result.Authority.RemainingConfirmations != 0 || len(current.Result.Authority.AllowedOperations) != 0 ||
		current.Result.Authority.Counters.LastRequestSequence != requestSequence || current.Result.Authority.Counters.NextResponseSequence != responseSequence+1 ||
		current.Result.Node == nil || current.Result.Node.NodeID != nodes[winner] {
		t.Fatal("replay/conflict changed finite budget, counters or the exact selected Node")
	}
	for _, packet := range packets {
		clear(packet)
	}
	for i := range confirm {
		clear(confirm[i])
		clear(confirmationResults[i].response)
	}
	t.Log("ACTUAL_N3 concurrent_initial_reservation_one_winner=true concurrent_confirmation_one_winner=true exact_receipt_after_actual_Hub_restart=true changed_ciphertext_conflict_refused=true counter_slot_consumed_once=true")
}
