package n3_test

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3RevokedNodeCannotPublishOrReuseReadProvenance(t *testing.T) {
	for _, fault := range []string{"credential-revoked", "owner-binding-revoked"} {
		t.Run(fault, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "node-revocation-account.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			app.kill(t)
			a := newAuthorityWireActor(t, f)
			node := startNodeProcess(t, f, "synthetic-n3-revoked-node")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			prepare, original, challenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode})
			defer clear(original)
			live := a.complete(t, prepare, original, challenge)
			confirm := must(wire.SealAppNodeConfirmation(a.device, f.cfg.Hub, challenge.Claims, pending.PendingCode,
				live.Authority.Counters.LastRequestSequence+1, time.Now().UTC()))
			defer clear(confirm)
			code, response := a.post(t, "/v2/client/rpc", confirm)
			defer clear(response)
			if code != 200 {
				t.Fatal("node revocation fixture did not confirm its genuine candidate")
			}
			bound := must(wire.OpenAppNodeConfirmationResponse(a.device, f.cfg.Hub, challenge.Claims, confirm, response, live.Authority.Counters.NextResponseSequence))
			if !bound.OK || bound.Binding == nil {
				t.Fatal("node revocation fixture lacks an exact authenticated binding")
			}
			tokenRaw := readPrivate(t, filepath.Join(node.state, "nodes", "node-"+url.PathEscape(node.id), "relay.token"))
			defer clear(tokenRaw)
			token := strings.TrimSpace(string(tokenRaw))
			f.hub.kill(t)
			db := must(sql.Open("sqlite", filepath.Join(f.dir, "synthetic-hub", "cicada.sqlite3")))
			t.Cleanup(func() { db.Close() })
			var changed sql.Result
			var err error
			if fault == "credential-revoked" {
				changed, err = db.Exec(`UPDATE fabric_node_credentials SET status='revoked',version=version+1 WHERE node_id=?`, node.id)
			} else {
				changed, err = db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED',version=version+1 WHERE id=?`, bound.Binding.OwnerBindingID)
			}
			if err != nil || must(changed.RowsAffected()) != 1 || db.Close() != nil {
				t.Fatal("owned node revocation did not affect its exact active row")
			}
			f.start(t)
			// A negative old-bearer probe is a wire adversary, never evidence of
			// positive Node liveness. All positive heartbeats use actual Node CLI.
			heartbeat := must(http.NewRequest(http.MethodPost, f.cfg.Origin+"/v2/relay/nodes/"+url.PathEscape(node.id)+"/heartbeat", bytes.NewReader([]byte(`{}`))))
			heartbeat.Header.Set("Authorization", "CicadaNode "+token)
			heartbeat.Header.Set("Content-Type", "application/json")
			denied := must(f.proxy.client.Do(heartbeat))
			denied.Body.Close()
			if denied.StatusCode != 401 && denied.StatusCode != 403 {
				t.Fatal("old revoked Node bearer was accepted or reached an unavailable route")
			}
			status := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
			_, observed := a.call(t, wire.OperationAppNodeStatus, status)
			if observed.Result == nil || observed.Result.Node != nil {
				t.Fatal("revoked Node retained an authorized freshness projection")
			}
			cancel := must(wire.NewAppNodeCancel(a.session, challenge.Claims.GrantID, observed.Result.Authority.CurrentHeadVersion, time.Now().UTC()))
			a.call(t, wire.OperationAppNodeCancel, cancel)
			context := must(wire.NewAppNodeStatus(a.session, "", time.Now().UTC()))
			_, current := a.call(t, wire.OperationAppNodeStatus, context)
			if current.Result == nil {
				t.Fatal("revocation fixture lost its retained App diagnostics")
			}
			a.scope = current.Result.Authority.Scope
			request := must(wire.NewAppNodePrepare(a.session, a.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetPrevious, PreviousGrantID: challenge.Claims.GrantID}, a.owner, time.Now().UTC()))
			_, refused := a.call(t, wire.OperationAppNodePrepare, request)
			if refused.Result == nil || refused.Result.State != wire.AppNodeRejectedFenced || refused.Result.Node != nil {
				t.Fatal("read-only reauthorization reused revoked confirmation provenance")
			}
			t.Logf("ACTUAL_N3 node_revocation=%s old_bearer_denied=true Node_projection_absent=true immutable_confirmation_provenance_not_reused=true", fault)
		})
	}
}
