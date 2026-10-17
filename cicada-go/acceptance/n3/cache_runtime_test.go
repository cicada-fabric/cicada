package n3_test

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3ReadCacheRollingBoundsAndPermanentMutationRecovery(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "cache-account-ready.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	app.kill(t)
	a := newAuthorityWireActor(t, f)
	node := startNodeProcess(t, f, "synthetic-n3-cache-target")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	prepare, original, challenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode})
	defer clear(original)
	a.complete(t, prepare, original, challenge)
	var originalReceipt []byte
	for _, exchange := range f.proxy.snapshot() {
		if exchange.Path == wire.AppNodeHTTPPath(wire.OperationAppNodePrepare) && bytes.Equal(exchange.request, original) {
			originalReceipt = bytes.Clone(exchange.response)
		}
	}
	defer clear(originalReceipt)
	if len(originalReceipt) == 0 {
		t.Fatal("permanent mutation fixture lacks its actual original Hub receipt")
	}
	var oldestRead []byte
	for i := 0; i < wire.MaxAppNodeReadCacheEntriesPerDevice+12; i++ {
		request := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
		packet, result := a.call(t, wire.OperationAppNodeStatus, request)
		if result.Result == nil || result.Result.State != wire.AppNodeCompleted || result.Result.Authority.State != wire.AppNodeActive {
			t.Fatal("normal repeated status reads hit a lifetime quota or changed authority")
		}
		if i == 0 {
			oldestRead = bytes.Clone(packet)
		}
		clear(packet)
	}
	defer clear(oldestRead)
	f.hub.kill(t)
	db := must(sql.Open("sqlite", filepath.Join(f.dir, "synthetic-hub", "cicada.sqlite3")))
	var cacheRows int
	if db.QueryRow(`SELECT count(*) FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=?`, a.scope.OwnerID, a.scope.DeviceID).Scan(&cacheRows) != nil ||
		cacheRows > wire.MaxAppNodeReadCacheEntriesPerDevice || db.Close() != nil {
		t.Fatal("actual persisted read cache exceeded its rolling per-device bound")
	}
	f.start(t)
	readReconcile := must(wire.NewAppNodeReconcile(a.session, wire.AppNodeOriginalAuthority, challenge.Claims.GrantID, oldestRead, time.Now().UTC()))
	_, expired := a.call(t, wire.OperationAppNodeReconcile, readReconcile)
	if expired.Reconciled == nil || expired.Reconciled.State != wire.AppNodeReadExpired || len(expired.Reconciled.ReceiptPacket) != 0 ||
		wire.ValidateAppNodeReconcileTarget(*expired.Reconciled, wire.AppNodeOriginalAuthority, oldestRead) != nil {
		t.Fatal("evicted pure read was not settled only as exact-digest READ_EXPIRED")
	}
	code, late := a.post(t, wire.AppNodeHTTPPath(wire.OperationAppNodeStatus), oldestRead)
	defer clear(late)
	if code != 200 {
		t.Fatal("late expired read lost its authenticated exact-read settlement")
	}
	lateRead := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, oldestRead, late))
	if lateRead.Result == nil || lateRead.Result.State != wire.AppNodeReadExpired || lateRead.Result.Node != nil ||
		len(lateRead.Result.Authority.AllowedOperations) != 0 || lateRead.Result.Authority.RemainingConfirmations != 0 {
		t.Fatal("late read revived current Node permission or settled a mutation")
	}
	reconcile := must(wire.NewAppNodeReconcile(a.session, wire.AppNodeOriginalAuthority, challenge.Claims.GrantID, original, time.Now().UTC()))
	reconcilePacket, recovered := a.call(t, wire.OperationAppNodeReconcile, reconcile)
	defer clear(reconcilePacket)
	if recovered.Reconciled == nil || recovered.Reconciled.State != wire.AppNodeCompleted ||
		!bytes.Equal(recovered.Reconciled.ReceiptPacket, originalReceipt) ||
		wire.ValidateAppNodeReconcileTarget(*recovered.Reconciled, wire.AppNodeOriginalAuthority, original) != nil {
		t.Fatal("rolling reads evicted a primary mutation's permanent exact receipt")
	}
	// Explicit persisted-fixture cache aging is not a real five-minute wait.
	// Only the renewable reconciliation cache is aged; primary immutable
	// operations/provenance/fences and their receipt bytes are never modified.
	f.hub.kill(t)
	db = must(sql.Open("sqlite", filepath.Join(f.dir, "synthetic-hub", "cicada.sqlite3")))
	result, err := db.Exec(`UPDATE hub_app_node_reads_v1 SET created_at=? WHERE owner_id=? AND device_id=? AND operation_id=?`,
		time.Now().UTC().Add(-6*time.Minute).Format(time.RFC3339Nano), a.scope.OwnerID, a.scope.DeviceID, reconcile.Context.RequestID)
	if err != nil || must(result.RowsAffected()) != 1 || db.Close() != nil {
		t.Fatal("owned renewable-cache age fault did not affect exactly one row")
	}
	f.start(t)
	code, rebuilt := a.post(t, wire.AppNodeHTTPPath(wire.OperationAppNodeReconcile), reconcilePacket)
	defer clear(rebuilt)
	if code != 200 {
		t.Fatal("exact reconciliation retry could not reconstruct its target after outer-cache expiry")
	}
	again := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, reconcilePacket, rebuilt))
	if again.Reconciled == nil || again.Reconciled.State != wire.AppNodeCompleted ||
		!bytes.Equal(again.Reconciled.ReceiptPacket, originalReceipt) ||
		wire.ValidateAppNodeReconcileTarget(*again.Reconciled, wire.AppNodeOriginalAuthority, original) != nil {
		t.Fatal("aged outer diagnostic cache changed or forgot its permanent target outcome")
	}
	t.Logf("ACTUAL_N3 status_reads=%d rolling_cache_max=%d primary_receipt_permanent=true outer_cache_age=CONTROLLED_PERSISTED_FIXTURE exact_target_reconstructed_after_actual_Hub_restart=true receipt_bytes=%d", wire.MaxAppNodeReadCacheEntriesPerDevice+12, wire.MaxAppNodeReadCacheEntriesPerDevice, len(originalReceipt))
}
