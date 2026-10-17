package n3_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This is read-only inspection of actual private App persistence, not a wire
// DTO or replacement controller. It distinguishes three local commit windows.
type persistedNodeView struct {
	Pending *struct {
		Operation                string                        `json:"operation"`
		Request                  []byte                        `json:"request"`
		Response                 []byte                        `json:"response"`
		Applied                  bool                          `json:"applied"`
		ExpectedResponseSequence uint64                        `json:"expected_response_sequence"`
		GrantClaims              *e2ee.OwnerAppNodeGrantClaims `json:"grant_claims"`
	} `json:"pending"`
	Client struct {
		NextRequest  uint64 `json:"next_request"`
		NextResponse uint64 `json:"next_response"`
		Conflict     bool   `json:"conflict"`
	} `json:"client"`
}

func decodePersistedNode(t *testing.T, vault *appvault.Vault) persistedNodeView {
	t.Helper()
	raw, _, found, err := vault.LoadState("appcore.node.v1")
	defer clear(raw)
	var state persistedNodeView
	if err != nil || !found || json.Unmarshal(raw, &state) != nil {
		t.Fatal("actual private Node persistence cannot be inspected")
	}
	return state
}

func TestN3ActualConfirmationLocalCommitCrashBoundaries(t *testing.T) {
	for _, window := range []string{"response-durable", "confirmation-record-durable", "counter-state-durable"} {
		t.Run(window, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "commit-app-ready.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			node := startNodeProcess(t, f, "synthetic-n3-commit-target")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			preview := commandApp(t, f, app, 1, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode}})
			if preview.ActionFailed || preview.Current.Node.Candidate == nil {
				t.Fatal("production preview failed before local commit fault")
			}
			armVaultBarrier(t, f, app)
			action := appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: preview.Current.Node.Candidate.ReviewID,
				ConfirmNodeIdentity: true, ConfirmNodeAccess: true}
			command := queueAppCommand(t, f, app, 2, appActorCommand{Action: &action})
			var captured persistedNodeView
			var requestBefore, responseBefore uint64
			observed := false
			for gate := 1; gate <= 48; gate++ {
				image, release := vaultImageAtGate(t, f, app, gate)
				state := decodePersistedNode(t, image)
				proof, _, proofFound, err := image.LoadState("appcore.node-confirmation.v1")
				if image.Close() != nil || err != nil {
					t.Fatal("actual confirmation record cannot be inspected at the paused commit")
				}
				hasProof := proofFound && len(proof) > 0
				clear(proof)
				if gate == 1 {
					requestBefore, responseBefore = state.Client.NextRequest, state.Client.NextResponse
				}
				p := state.Pending
				match := p != nil && p.Operation == "nodes.confirm" && len(p.Response) > 0 && p.GrantClaims != nil
				if match {
					switch window {
					case "response-durable":
						match = !p.Applied && !hasProof
					case "confirmation-record-durable":
						match = !p.Applied && hasProof
					case "counter-state-durable":
						match = p.Applied && hasProof && state.Client.NextRequest == requestBefore+1 && state.Client.NextResponse == responseBefore+1
					}
				}
				if match {
					captured, observed = state, true
					app.kill(t)
					break
				}
				if p != nil {
					clear(p.Request)
					clear(p.Response)
				}
				release()
			}
			if !observed || captured.Pending == nil || requestBefore == 0 || responseBefore == 0 {
				t.Fatal("required actual local commit boundary was not observed")
			}
			defer clear(captured.Pending.Request)
			defer clear(captured.Pending.Response)
			if _, err := os.Stat(command + "-reply.json"); !os.IsNotExist(err) {
				t.Fatal("App action completed before the selected local crash boundary")
			}
			device := ownedAppIdentity(t, f, appvault.PurposeAppDevice)
			receipt := must(wire.OpenAppNodeConfirmationResponse(device, f.cfg.Hub, *captured.Pending.GrantClaims,
				captured.Pending.Request, captured.Pending.Response, captured.Pending.ExpectedResponseSequence))
			if !receipt.OK || receipt.Binding == nil || receipt.Binding.NodeID != node.id {
				t.Fatal("durable local receipt does not prove the exact actual Node confirmation")
			}
			f.hub.kill(t)
			db := f.db(t)
			machines := must(db.ListOwnerBoundNodeMachines(f.cfg.Material.OwnerID))
			if len(machines) != 1 || machines[0].ID != node.id || machines[0].Status != "offline" || machines[0].LastSeen != "" {
				t.Fatal("actual committed Hub effect differs from the captured local receipt")
			}
			db.Close()
			f.start(t)
			resumeMarker := filepath.Join(f.dir, "commit-app-resumed.json")
			resumed := startAppProcess(t, f, "resume-node", resumeMarker)
			awaitMarker(t, resumed.process, resumeMarker)
			var checkpoint appActorCheckpoint
			readJSON(t, resumeMarker, &checkpoint)
			if checkpoint.Current.Node.Pending || checkpoint.Current.Node.Binding == nil || checkpoint.Current.Node.Binding.ID != receipt.Binding.OwnerBindingID {
				t.Fatal("actual App restart lost its original authenticated confirmation")
			}
			resumed.kill(t)
			vault := ownedAppVault(t, f)
			after := decodePersistedNode(t, vault)
			vault.Close()
			if after.Client.Conflict || after.Client.NextRequest != requestBefore+1 || after.Client.NextResponse != responseBefore+1 {
				t.Fatal("local receipt replay reset or advanced Client counters twice")
			}
			confirmations := 0
			for _, exchange := range f.proxy.snapshot() {
				if exchange.Path == "/v2/client/rpc" {
					confirmations++
				}
			}
			if confirmations != 1 {
				t.Fatal("already durable confirmation response was replaced by another Client request")
			}
			t.Logf("ACTUAL_N3 local_commit_window=%s actual_App_and_Hub_SIGKILL=true original_response_sha256=%s counters_advanced_once=true", window, hash(captured.Pending.Response))
		})
	}
}
