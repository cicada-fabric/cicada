package n3_test

import (
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3RealConfirmationVersusCancellationOrders(t *testing.T) {
	for _, order := range []string{"cancel-first", "confirm-first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "cancel-race-account.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			app.kill(t)
			a := newAuthorityWireActor(t, f)
			node := startNodeProcess(t, f, "synthetic-n3-cancel-race")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			prepare, original, challenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode})
			defer clear(original)
			live := a.complete(t, prepare, original, challenge)
			confirm := must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, challenge.Claims, pending.PendingCode,
				live.Authority.Counters.LastRequestSequence+1, time.Now().UTC()))
			defer clear(confirm)
			cancelBody := must(wire.NewAppNodeCancel(a.session, challenge.Claims.GrantID, challenge.Claims.Scope.HeadVersion, time.Now().UTC()))
			cancel := must(wire.SealClientRequest(a.device, f.cfg.Hub, cancelBody))
			defer clear(cancel)
			var confirmed, cancelled wireHTTPResult
			post := func(path string, packet []byte) wireHTTPResult {
				code, response := a.post(t, path, packet)
				return wireHTTPResult{status: code, response: response}
			}
			cancelPath := wire.AppNodeHTTPPath(wire.OperationAppNodeCancel)
			switch order {
			case "cancel-first":
				cancelled = post(cancelPath, cancel)
				confirmed = post("/v2/client/rpc", confirm)
			case "confirm-first":
				confirmed = post("/v2/client/rpc", confirm)
				cancelled = post(cancelPath, cancel)
			case "concurrent":
				got := parallelPosts(t, f, []string{"/v2/client/rpc", cancelPath}, [][]byte{confirm, cancel})
				confirmed, cancelled = got[0], got[1]
			}
			defer clear(confirmed.response)
			defer clear(cancelled.response)
			if cancelled.status != 200 {
				t.Fatal("explicit same-head cancellation did not produce an authenticated outcome")
			}
			cancelResult := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, cancel, cancelled.response))
			if cancelResult.Result == nil || cancelResult.Result.State != wire.AppNodeCompleted || cancelResult.Result.Authority.State != wire.AppNodeCancelled {
				t.Fatal("same-head cancellation did not remove current authority")
			}
			success := false
			if confirmed.status == 200 {
				result := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, challenge.Claims, confirm, confirmed.response, live.Authority.Counters.NextResponseSequence))
				success = result.OK
			} else if confirmed.status != 403 && confirmed.status != 409 {
				t.Fatal("confirmation race reached an unavailable/error response")
			}
			if (order == "cancel-first" && success) || (order == "confirm-first" && !success) {
				t.Fatal("confirmed effect violated the observed nonoverlapping terminal ordering")
			}
			status := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
			_, snapshot := a.call(t, wire.OperationAppNodeStatus, status)
			if snapshot.Result == nil || snapshot.Result.Authority.State != wire.AppNodeCancelled || snapshot.Result.Authority.LoginRequired ||
				len(snapshot.Result.Authority.AllowedOperations) != 0 || snapshot.Result.Node != nil {
				t.Fatal("cancelled same-login grant retained operations/Node or falsely required new login")
			}
			f.hub.kill(t)
			db := f.db(t)
			defer db.Close()
			machines := must(db.ListOwnerBoundNodeMachines(a.scope.OwnerID))
			want := 0
			if success {
				want = 1
			}
			if len(machines) != want || (want == 1 && machines[0].ID != node.id) {
				t.Fatal("racing confirmation/cancellation left a partial or substituted durable effect")
			}
			t.Logf("ACTUAL_N3 cancellation_order=%s confirmation_success=%t durable_effect_matches_legal_order=true same_valid_login_not_reprompted=true", order, success)
		})
	}
}
