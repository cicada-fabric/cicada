package n3_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3RealPersistedEpochAndRootSessionFences(t *testing.T) {
	for _, fault := range []string{"account-epoch", "device-epoch", "client-session-epoch", "account-session-revoked", "owner-key-revoked"} {
		t.Run(fault, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "epoch-account-ready.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			app.kill(t)
			a := newAuthorityWireActor(t, f)
			node := startNodeProcess(t, f, "synthetic-n3-epoch-target")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			request := must(wire.NewAppNodePrepare(a.session, a.scope,
				wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode}, a.owner, time.Now().UTC()))
			// Preserve this genuinely valid original; only the stopped owned
			// production database changes. This is stale state, not a zero/future
			// epoch fabricated in an invalid outgoing request constructor.
			packet := must(wire.SealClientRequest(a.device, f.cfg.Hub, request))
			defer clear(packet)
			f.hub.kill(t)
			db := must(sql.Open("sqlite", filepath.Join(f.dir, "synthetic-hub", "cicada.sqlite3")))
			var result sql.Result
			var err error
			switch fault {
			case "account-epoch":
				result, err = db.Exec(`UPDATE hub_account_config_v1 SET epoch=epoch+1 WHERE id=1`)
			case "device-epoch":
				result, err = db.Exec(`UPDATE hub_account_devices_v1 SET epoch=epoch+1 WHERE account_id=? AND device_id=?`, a.scope.AccountID, a.scope.DeviceID)
			case "client-session-epoch":
				result, err = db.Exec(`UPDATE client_devices_v2 SET session_epoch=session_epoch+1 WHERE owner_id=? AND device_id=?`, a.scope.OwnerID, a.scope.DeviceID)
			case "account-session-revoked":
				result, err = db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE session_id=?`, a.scope.AccountSessionID)
			case "owner-key-revoked":
				result, err = db.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED',revoked_at=?,updated_at=? WHERE owner_id=? AND key_id=?`,
					time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano), a.scope.OwnerID, a.scope.OwnerPublic.ID)
			}
			if err != nil || must(result.RowsAffected()) != 1 || db.Close() != nil {
				t.Fatal("owned persisted security-coordinate fault did not affect exactly one row")
			}
			f.start(t)
			code, response := a.post(t, wire.AppNodeHTTPPath(wire.OperationAppNodePrepare), packet)
			defer clear(response)
			if code == 200 {
				opened := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, packet, response))
				if opened.Result == nil || opened.Result.State != wire.AppNodeRejectedFenced || opened.Result.Node != nil || len(opened.Result.Authority.AllowedOperations) != 0 {
					t.Fatal("stale original activated N3 authority after persisted security change")
				}
			} else if code != 400 && code != 401 && code != 403 {
				t.Fatal("stale original reached an unavailable/error response")
			}
			diagnosticSession := a.session
			diagnosticSession.Token = nil
			diagnostic := must(wire.NewAppNodeStatus(diagnosticSession, "", time.Now().UTC()))
			_, observed := a.call(t, wire.OperationAppNodeStatus, diagnostic)
			if observed.Result == nil || observed.Result.Node != nil || len(observed.Result.Authority.AllowedOperations) != 0 ||
				observed.Result.Authority.CurrentHeadVersion != 0 || observed.Result.Authority.LatestGrantID != "" {
				t.Fatal("retained-key diagnostics revived authority or became unavailable after a security fence")
			}
			f.hub.kill(t)
			store := f.db(t)
			defer store.Close()
			if len(must(store.ListOwnerBoundNodeMachines(a.scope.OwnerID))) != 0 {
				t.Fatal("stale security state left a partial Node binding")
			}
			t.Logf("ACTUAL_N3 persisted_fault=%s actual_Hub_restart=true original_valid_ciphertext_preserved=true no_Node_authority=true retained_key_diagnostics_only=true", fault)
		})
	}
}
