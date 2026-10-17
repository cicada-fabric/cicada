package n3_test

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3ActualAppExactFaultRecoveryAndLateOriginal(t *testing.T) {
	for _, operation := range []string{wire.OperationAppNodePrepare, wire.OperationAppNodeComplete, "nodes.confirm", wire.OperationAppNodeStatus, wire.OperationAppNodeCancel} {
		for _, mode := range []string{"before-forward", "drop-after-response", "unsigned-403", "unsigned-429", "unsigned-500", "corrupt-response"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				f := newNodeHubFixture(t)
				marker := filepath.Join(f.dir, "fault-app-ready.json")
				app := startAppProcess(t, f, "bootstrap", marker)
				awaitMarker(t, app.process, marker)
				node := startNodeProcess(t, f, "synthetic-n3-fault-target")
				pending := node.awaitState(t, f, false)
				node.kill(t)
				sequence := 0
				do := func(action appcore.Action) appActorReply {
					sequence++
					return commandApp(t, f, app, sequence, appActorCommand{Action: &action})
				}
				path := wire.AppNodeHTTPPath(operation)
				if operation == "nodes.confirm" {
					path = "/v2/client/rpc"
				}
				var action appcore.Action
				if operation == wire.OperationAppNodePrepare {
					action = appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode}
				} else {
					preview := do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
					if preview.ActionFailed || preview.Current.Node.Candidate == nil {
						t.Fatal("fault fixture did not obtain its genuine preview")
					}
					action = appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: preview.Current.Node.Candidate.ReviewID,
						ConfirmNodeIdentity: true, ConfirmNodeAccess: true}
					if operation == wire.OperationAppNodeStatus || operation == wire.OperationAppNodeCancel {
						approved := do(action)
						if approved.ActionFailed || approved.Current.Node.Binding == nil {
							t.Fatal("fault fixture did not establish its genuine Node binding")
						}
						action = appcore.Action{Kind: appcore.ActionRefreshNode}
						if operation == wire.OperationAppNodeCancel {
							action = appcore.Action{Kind: appcore.ActionCancelNodeAccess, NodeReviewID: approved.Current.Node.Access.ReviewID}
						}
					}
				}
				traceBefore := len(f.proxy.snapshot())
				f.proxy.arm(path, mode, 1)
				unknown := do(action)
				if !unknown.ActionFailed || !unknown.Current.Node.Pending || unknown.Current.Node.Access.Confirmed {
					t.Fatal("unsigned/missing/corrupt response settled a production App pending request")
				}
				trace := f.proxy.snapshot()[traceBefore:]
				var original exchange
				for _, exchange := range trace {
					if exchange.Path == path {
						original = exchange
					}
				}
				if len(original.request) == 0 || (mode == "before-forward" && original.Forwarded) ||
					(mode != "before-forward" && (!original.Forwarded || original.Status != 200)) {
					t.Fatal("fault position did not match a genuine production request/committed response")
				}
				calls := len(f.proxy.snapshot())
				replacement := do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
				if !replacement.ActionFailed || !replacement.Current.Node.Pending || len(f.proxy.snapshot()) != calls {
					t.Fatal("uncertain original permitted a replacement secret POST")
				}
				oldPID, oldHubPID := app.cmd.Process.Pid, f.hub.cmd.Process.Pid
				app.kill(t)
				keys := ownedAppPublicKeys(t, f)
				device := ownedAppIdentity(t, f, appvault.PurposeAppDevice)
				vault := ownedAppVault(t, f)
				saved := decodePersistedNode(t, vault)
				vault.Close()
				p := saved.Pending
				if p == nil || p.Applied || p.Operation != operation || len(p.Response) != 0 || !bytes.Equal(p.Request, original.request) {
					t.Fatal("actual encrypted App persistence did not retain the exact uncertain original")
				}
				defer clear(p.Request)
				defer clear(p.Response)
				f.hub.kill(t)
				db := f.db(t)
				machines := must(db.ListOwnerBoundNodeMachines(f.cfg.Material.OwnerID))
				wantBindings := 0
				if operation == wire.OperationAppNodeStatus || operation == wire.OperationAppNodeCancel || (operation == "nodes.confirm" && mode != "before-forward") {
					wantBindings = 1
				}
				if len(machines) != wantBindings {
					t.Fatal("actual committed Hub binding effect differs from the fault position")
				}
				db.Close()
				f.start(t)
				resumeMarker := filepath.Join(f.dir, "fault-app-resumed.json")
				resumed := startAppProcess(t, f, "resume-node", resumeMarker)
				awaitMarker(t, resumed.process, resumeMarker)
				if resumed.cmd.Process.Pid == oldPID || f.hub.cmd.Process.Pid == oldHubPID {
					t.Fatal("fault recovery did not actually restart both processes")
				}
				if mode == "before-forward" {
					// Product recovery first retries the original exact frame. Keep
					// this retry unsent too, forcing actual diagnostic fencing before
					// the parent eventually releases the delayed original below.
					f.proxy.arm(path, "before-forward", 1)
				}
				recovered := commandApp(t, f, resumed, 1, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionRecoverNode}})
				if recovered.ActionFailed || recovered.Current.Node.Pending {
					t.Fatal("production App could not authenticate and settle the exact original outcome")
				}
				resumed.kill(t)
				if !reflect.DeepEqual(keys, ownedAppPublicKeys(t, f)) {
					t.Fatal("uncertainty recovery replaced an original Owner/App identity")
				}
				// Deliver the same original after settlement and process restart.
				// A fence/read-expiry must precede this delivery; a cached success
				// must recover byte-for-byte rather than execute another mutation.
				a := &authorityWireActor{f: f}
				code, response := a.post(t, path, original.request)
				defer clear(response)
				if code != 200 {
					t.Fatal("settled original lost its authenticated original-route receipt")
				}
				if mode != "before-forward" {
					if !bytes.Equal(original.response, response) {
						t.Fatal("committed original response changed after crash/reconciliation")
					}
				} else if operation == "nodes.confirm" {
					if p.GrantClaims == nil {
						t.Fatal("uncertain confirmation lost its original grant instance")
					}
					result := must(wire.OpenAppNodeConfirmationResponse(device, f.cfg.Hub, *p.GrantClaims, p.Request, response, p.ExpectedResponseSequence))
					if result.OK {
						t.Fatal("late previously-unadmitted confirmation crossed its durable original fence")
					}
				} else {
					result := must(wire.OpenAppNodeResponse(device, f.cfg.Hub, p.Request, response))
					want := wire.AppNodeRejectedFenced
					if operation == wire.OperationAppNodeStatus {
						want = wire.AppNodeReadExpired
					}
					if result.Result == nil || result.Result.State != want {
						t.Fatal("late original crossed its terminal mutation fence/read expiry")
					}
				}
				f.hub.kill(t)
				db = f.db(t)
				defer db.Close()
				if len(must(db.ListOwnerBoundNodeMachines(f.cfg.Material.OwnerID))) != wantBindings {
					t.Fatal("delayed original changed durable Node bindings after settlement")
				}
				t.Logf("ACTUAL_N3 fault=%s operation=%s actual_App_and_Hub_SIGKILL=true original_sha256=%s recovery_authenticated=true late_original_terminal=true", mode, operation, hash(original.request))
			})
		}
	}
}
