package n3_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Test the same exported Store writer used by Control compatibility, with the
// real already proved Owner/device and the original code/candidate/key tuple.
// The production Hub is stopped so this is its only owned database writer.
func (v *nodePairFixture) compatibilityConfirmRefused(t *testing.T, missing bool) {
	t.Helper()
	if v.hub.hub.running() || v.node.running() || v.app.running() {
		t.Fatal("compatibility Store check requires exclusive owned stopped actors")
	}
	c, _ := v.side(t)
	db := must(store.New(filepath.Join(v.hub.state, "cicada.sqlite3")))
	defer db.Close()
	codeDigest := must(wire.AppNodeCodeDigest(c.Hub.HubID, v.local.Selector))
	binding, err := db.ConfirmNodeControlKeyRequest(v.original.Account.OwnerID, v.original.Account.DeviceID, codeDigest,
		int64(c.Candidate.Version), c.Candidate.CandidateDigest, c.Candidate.HubNodeControlPublic.ID, c.Candidate.HubNodeControlFingerprint)
	if binding != nil || err == nil || !missing && !errors.Is(err, store.ErrNodePairTrustACKRequired) {
		t.Fatal("Control compatibility's original Store writer bypassed the Node ACK gate")
	}
}

func nodePairLegacyConfirmRequiresACK(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.approve(t)
	saved := v.copiedAppState(t)
	defer saved.clear()
	confirm := saved.PairTrust.Confirmation
	if confirm == nil || confirm.GrantClaims == nil || len(confirm.Request) == 0 || confirm.Applied || len(confirm.Response) != 0 {
		t.Fatal("real Owner approval did not durably reserve its exact original unconfirmed Client packet")
	}
	var complete wire.NodePairTrustOwnerComplete
	if saved.PairTrust.Pending == nil || json.Unmarshal(saved.PairTrust.Pending.Body, &complete) != nil {
		t.Fatal("actual approval lacks its original authenticated account/device context")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	device := v.originalAppDevice(t)
	client := v.protocolClient(t)
	before := v.admission(t)
	if before.state != wire.NodePairTrustOwnerApproved || before.ownerBindings != 0 || before.keyBindings != 0 || before.remaining != 1 || before.required != 1 ||
		before.slotState != "RESERVED" || before.slotDigest != wire.AppNodePacketDigest(confirm.Request) || before.slotRequest != before.lastRequest+1 || before.slotResponse != before.nextResponse {
		t.Fatal("OWNER_APPROVED activated a binding or failed to retain the original unconsumed counter slot")
	}
	ordinary := nodePairHTTP(client, v.hub.material.Origin, "/v2/client/rpc", confirm.Request)
	defer clear(ordinary.response)
	if ordinary.err != nil || ordinary.status != http.StatusConflict || !bytes.Contains(ordinary.response, []byte("ACK_REQUIRED")) || v.admission(t) != before {
		t.Fatal("ordinary original nodes.confirm bypassed ACK_REQUIRED or wrote a PROCESSING/counter effect")
	}
	scope := complete.Scope
	session := wire.AppNodeSession{Hub: v.hub.descriptor.Claims.Hub, Origin: scope.Origin, AccountID: scope.AccountID,
		OwnerID: scope.OwnerID, DeviceID: scope.DeviceID, AccountEpoch: scope.AccountEpoch, DeviceEpoch: scope.DeviceEpoch, Token: complete.SessionToken}
	query := must(wire.NewAppNodeReconcile(session, wire.AppNodeOriginalClient, confirm.GrantClaims.GrantID, confirm.Request, time.Now().UTC()))
	packet := must(wire.SealClientRequest(device, session.Hub, query))
	defer clear(packet)
	reconcile := nodePairHTTP(client, session.Origin, wire.AppNodeHTTPPath(wire.OperationAppNodeReconcile), packet)
	defer clear(reconcile.response)
	if reconcile.err != nil || reconcile.status != http.StatusConflict || !bytes.Contains(reconcile.response, []byte("ACK_REQUIRED")) || v.admission(t) != before {
		t.Fatal("old original-confirm reconcile sealed a no-effect receipt or consumed counters before Node ACK")
	}
	v.hub.hub.kill(t)
	v.compatibilityConfirmRefused(t, false)
	if v.admission(t) != before {
		t.Fatal("compatibility refusal changed the durable original candidate/slot/counters")
	}
	v.hub.start(t)
	v.start(t)
	v.awaitHubACK(t)
	v.resumeApp(t)
	s := v.awaitACK(t)
	v.assertAutomaticOwnerPin(t, s)
	after := v.admission(t)
	if after.ownerBindings != 1 || after.keyBindings != 1 || after.remaining != 0 || after.slotState != "DONE" || after.slotDigest != before.slotDigest ||
		after.lastRequest != before.lastRequest+1 || after.nextResponse != before.nextResponse+1 || after.clientRows != before.clientRows+1 || after.required != 1 {
		t.Fatal("real Node ACK did not settle exactly the reserved original confirmation once")
	}
	final := v.copiedAppState(t)
	defer final.clear()
	nodePairAssertRetainedConsent(t, saved, final)
	if final.PairTrust.Confirmation == nil || !final.PairTrust.Confirmation.Applied || len(final.PairTrust.Confirmation.Response) == 0 {
		t.Fatal("actual App did not authenticate/apply its original ACK-settled Client receipt")
	}
	// A separate fixture deliberately loses only the side record after all
	// actors stop. This is a malformed-state fault, never a migration/restore
	// recommendation. The independent original RequireACK marker must survive.
	nodePairMissingSideRefuses(t)
	nodePairFacts(t, "NPT05_LegacyConfirmRequiresACK", map[string]bool{"all_confirmation_writers_fenced": true,
		"OWNER_APPROVED_not_bound": true, "no_missing_side_record_fallback": true, "original_counter_slot_retained": true})
}

func nodePairMissingSideRefuses(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.approve(t)
	saved := v.copiedAppState(t)
	defer saved.clear()
	if saved.PairTrust.Confirmation == nil {
		t.Fatal("malformed owned-state fixture lacks an actual original confirmation")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	v.hub.hub.kill(t)
	path := filepath.Join(v.hub.state, "cicada.sqlite3")
	db := must(sql.Open("sqlite", path))
	var historyGuard, accountingGuard string
	if db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name='hub_node_pair_trust_v1_no_delete'`).Scan(&historyGuard) != nil ||
		db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name='node_pair_budget_attempt_delete_v1'`).Scan(&accountingGuard) != nil {
		db.Close()
		t.Fatal("owned missing-side fixture could not retain its original schema guards")
	}
	// Deliberately remove the side history guard in this one synthetic fixture.
	// Do not remove or alter the original candidate's independent ACK marker.
	if _, err := db.Exec(`DROP TRIGGER hub_node_pair_trust_v1_no_delete`); err != nil {
		db.Close()
		t.Fatal("owned missing-side fault could not be injected")
	}
	// An authorized row cannot be a legitimate GC candidate. Disable only its
	// delete-accounting trigger for this corruption injection; otherwise its
	// anonymous-row decrement would correctly make the forged delete fail.
	if _, err := db.Exec(`DROP TRIGGER node_pair_budget_attempt_delete_v1`); err != nil {
		db.Close()
		t.Fatal("owned missing-side budget fault could not be injected")
	}
	result, err := db.Exec(`DELETE FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, v.local.AttemptID)
	if err != nil || must(result.RowsAffected()) != 1 {
		db.Close()
		t.Fatal("owned missing-side fault did not remove exactly its sole side history")
	}
	// Restore exact producer schema before starting Hub: the injected fault is
	// the missing side row, not a different schema or disabled runtime guard.
	if _, err := db.Exec(historyGuard); err != nil {
		db.Close()
		t.Fatal("owned history guard could not be restored")
	}
	if _, err := db.Exec(accountingGuard); err != nil {
		db.Close()
		t.Fatal("owned accounting guard could not be restored")
	}
	if db.Close() != nil {
		t.Fatal("owned missing-side fixture did not close before Hub restart")
	}
	before := v.admission(t)
	if before.state != "MISSING" || before.required != 1 || before.ownerBindings != 0 || before.keyBindings != 0 || before.remaining != 1 {
		t.Fatal("malformed fixture lost its independent original ACK provenance")
	}
	v.hub.start(t)
	response := nodePairHTTP(v.protocolClient(t), v.hub.material.Origin, "/v2/client/rpc", saved.PairTrust.Confirmation.Request)
	defer clear(response.response)
	if response.err != nil || response.status == http.StatusOK || response.status >= 500 || v.admission(t) != before {
		t.Fatal("missing side record fell back to ordinary legacy confirmation or uncertain effects")
	}
	// No recovered App, manual pin, regenerated candidate or replacement grant
	// is used to repair this deliberately malformed fixture.
}
