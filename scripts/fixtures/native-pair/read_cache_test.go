package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Independent deterministic regression, linked only through the QA overlay.
// Synthetic guard fixture + real Store/PQ, NOT TCP/App/N2/Runtime acceptance.
// This file must never initialize a deployment. The original pre-fix failing
// overlay/receipt remains separately frozen; this version accepts the reviewed
// bounded backpressure instead of forcing fresh reads to be evicted.
func TestQANativePairReadCacheKeepsHistoryAcrossRateWindows(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, completeSeal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, completeSeal); err != nil {
		t.Fatal(err)
	}
	newRead := func(at time.Time, issued ...time.Time) (HubNativePairInput, HubNativePairSeal, []byte, error) {
		t.Helper()
		requestTime := at
		if len(issued) != 0 {
			requestTime = issued[0]
		}
		q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: f.context(t, requestTime),
			SessionToken: f.f.session.Token, PairID: ch.Bootstrap.PairID}
		in, seal := f.input(t, q, at)
		packet, err := f.f.db.ProcessHubNativePair(in, seal)
		return in, seal, packet, err
	}
	read := func(at time.Time) (HubNativePairInput, HubNativePairSeal, []byte) {
		t.Helper()
		in, seal, packet, err := newRead(at)
		var result wire.NativePairResult
		if err != nil || wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &result) != nil || result.Outcome != "COMPLETED" {
			t.Fatal("new legitimate status did not produce an authenticated observation", err)
		}
		return in, seal, packet
	}
	start := f.at.Add(2 * time.Second)
	read(start) // Start the first fixed one-minute diagnostic rate window.
	// This request is legitimately issued at the accepted +30-second skew.
	// Its freshness extends to +149s, beyond a 60-second server-age hold.
	original, seal, packet, err := newRead(start.Add(59*time.Second), start.Add(89*time.Second))
	var first wire.NativePairResult
	if err != nil || wire.OpenClientResponse(f.f.device, f.f.hub, original.Packet, packet, &first) != nil || first.Outcome != "COMPLETED" {
		t.Fatal("legitimate +30-second status could not be admitted", err)
	}
	if old, err := f.f.db.ProcessHubNativePair(original, seal); err != nil || !bytes.Equal(old, packet) {
		t.Fatal("pre-eviction exact replay failed")
	}
	for i := 0; i < 126; i++ {
		read(start.Add(59*time.Second + time.Duration(i+1)*time.Microsecond))
	}
	for i := 0; i < 2; i++ {
		_, _, _, err := newRead(start.Add(60*time.Second + time.Duration(i)*time.Millisecond))
		if !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
			t.Fatal("QA_FRESH_READ_CACHE_PROTECTION_MISSING: full protected cache must backpressure across rate-window reset")
		}
	}
	var entries, target int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_reads_v1`).Scan(&entries) != nil || entries != 128 ||
		f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_reads_v1 WHERE operation_id=?`, original.Body.(wire.NativePairStatusRequest).Context.RequestID).Scan(&target) != nil || target != 1 {
		t.Fatal("backpressure enlarged cache or discarded protected original")
	}
	if err := f.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.f.db = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	original.At = start.Add(60*time.Second + 2*time.Millisecond)
	if old, err := f.f.db.ProcessHubNativePair(original, seal); err != nil || !bytes.Equal(old, packet) {
		t.Fatal("protected original was re-observed instead of exact history after Store reopen")
	}
	// The first entry is now unprotected and may be replaced, but the target
	// is still fresh because of its legitimate future skew. A 60-second hold
	// would discard it on the following insertion instead of backpressuring.
	read(start.Add(119 * time.Second))
	if _, _, _, err := newRead(start.Add(119*time.Second + time.Millisecond)); !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
		t.Fatal("QA_FRESH_READ_CACHE_SKEW_PROTECTION_MISSING: original must remain protected for its entire freshness interval")
	}
	original.At = start.Add(119*time.Second + 2*time.Millisecond)
	if old, err := f.f.db.ProcessHubNativePair(original, seal); err != nil || !bytes.Equal(old, packet) {
		t.Fatal("future-skewed original acquired a new observation")
	}
	// At +150s the target's server-created +90s protection has elapsed. New
	// reads may now evict it, but its original request is no longer fresh.
	read(start.Add(150 * time.Second))
	read(start.Add(150*time.Second + time.Millisecond))
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_reads_v1 WHERE operation_id=?`, original.Body.(wire.NativePairStatusRequest).Context.RequestID).Scan(&target) != nil || target != 0 {
		t.Fatal("old unprotected target was not evicted by the bounded cache")
	}
	original.At = start.Add(150*time.Second + 2*time.Millisecond)
	expired, err := f.f.db.ProcessHubNativePair(original, seal)
	var result wire.NativePairResult
	if err != nil || wire.OpenClientResponse(f.f.device, f.f.hub, original.Packet, expired, &result) != nil ||
		result.Outcome != "READ_EXPIRED" || result.AdministrativePermission || result.SlotA != nil || result.SlotB != nil {
		t.Fatal("evicted old original revived current administration", err)
	}
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_reads_v1`).Scan(&entries) != nil || entries != 128 {
		t.Fatal("aged-original settlement enlarged the bounded read cache")
	}
	t.Log("QA_NATIVE_PAIR_READ_HISTORY protected_full_cache_backpressure=3 cache_bound=128 future_skew_protection_90s=true old_exact_receipt_preserved_after_Store_reopen=true after_protection_only_READ_EXPIRED=true trusted_synthetic_clock=true real_Runtime_NOT_RUN=true")
}

func TestQANativePairFutureStatusCannotSettleOrChangeRate(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, completeSeal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, completeSeal); err != nil {
		t.Fatal(err)
	}
	start := f.at.Add(2 * time.Second)
	writerNow := start
	q := wire.NativePairStatusRequest{Format: wire.NativePairFormat,
		Context: f.context(t, start.Add(31*time.Second)), SessionToken: f.f.session.Token,
		PairID: ch.Bootstrap.PairID}
	original, seal := f.input(t, q, start.Add(time.Hour))
	original.Now = func() time.Time { return writerNow }
	if packet, err := f.f.db.ProcessHubNativePair(original, seal); !errors.Is(err, ErrHubAccountRejected) || len(packet) != 0 {
		t.Fatal("future status bypassed writer time or received a forgettable settlement", err)
	}
	query := wire.NativePairReconcileRequest{Format: wire.NativePairFormat,
		Context: f.context(t, start), PairID: ch.Bootstrap.PairID, OriginalPacket: original.Packet}
	in, querySeal := f.input(t, query, start.Add(time.Hour))
	in.Now = func() time.Time { return writerNow }
	in.Original, in.OriginalSeal = &original, seal
	if packet, err := f.f.db.ProcessHubNativePair(in, querySeal); !errors.Is(err, ErrHubAccountRejected) || len(packet) != 0 {
		t.Fatal("reconciliation settled a future original using its untrusted time", err)
	}
	for _, table := range []string{"hub_native_pair_reads_v1", "hub_native_pair_rates_v1"} {
		var count int
		if f.f.db.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count) != nil || count != 0 {
			t.Fatal("future status or failed reconciliation left diagnostic state", table)
		}
	}
	// The same original bytes become legitimate later. An early READ_EXPIRED
	// settlement must not poison this first actual admission.
	writerNow = start.Add(31 * time.Second)
	packet, err := f.f.db.ProcessHubNativePair(original, seal)
	var result wire.NativePairResult
	if err != nil || wire.OpenClientResponse(f.f.device, f.f.hub, original.Packet, packet, &result) != nil || result.Outcome != "COMPLETED" || result.ObservedAt != appNodeStamp(writerNow) {
		t.Fatal("previously rejected future original did not receive its first legitimate observation", err)
	}
	writerNow = start.Add(-time.Minute)
	if old, err := f.f.db.ProcessHubNativePair(original, seal); err != nil || !bytes.Equal(old, packet) {
		t.Fatal("clock rollback re-observed an already admitted original", err)
	}
	t.Log("QA_NATIVE_PAIR_FUTURE_READ writer_time_authoritative=true direct_and_reconcile_rejected=true rejected_state_rolled_back=true later_first_admission=true rollback_exact_history=true real_Runtime_NOT_RUN=true")
}
