package store

import (
	"bytes"
	"errors"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"testing"
	"time"
)

func TestHubNativePairReadCacheProtectsFreshOriginalAcrossRateWindow(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, completeSeal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, completeSeal); err != nil {
		t.Fatal(err)
	}
	makeRead := func(at time.Time) (HubNativePairInput, HubNativePairSeal) {
		q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: f.context(t, at), SessionToken: f.f.session.Token, PairID: ch.Bootstrap.PairID}
		return f.input(t, q, at)
	}
	read := func(at time.Time) (HubNativePairInput, HubNativePairSeal, []byte) {
		in, seal := makeRead(at)
		packet, err := f.f.db.ProcessHubNativePair(in, seal)
		if err != nil {
			t.Fatal(err)
		}
		return in, seal, packet
	}
	start := f.at.Add(2 * time.Second)
	read(start)
	original, seal, packet := read(start.Add(59 * time.Second))
	for n := 0; n < 126; n++ {
		read(start.Add(59*time.Second + time.Duration(n+1)*time.Microsecond))
	}
	for n := 0; n < 2; n++ {
		in, seal := makeRead(start.Add(60*time.Second + time.Duration(n)*time.Millisecond))
		if out, err := f.f.db.ProcessHubNativePair(in, seal); !errors.Is(err, ErrHubOwnerDiagnosticsFull) || len(out) != 0 {
			t.Fatal("fresh cache was evicted instead of bounded backpressure", err)
		}
	}
	original.At = start.Add(60*time.Second + 2*time.Millisecond)
	if recovered, err := f.f.db.ProcessHubNativePair(original, seal); err != nil || !bytes.Equal(recovered, packet) {
		t.Fatal("fresh original acquired a new observation", err)
	}
	var count int
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_reads_v1`).Scan(&count) != nil || count != 128 {
		t.Fatal("cache bound expanded")
	}
	read(start.Add(90 * time.Second))  // Only the first read can now be evicted.
	read(start.Add(149 * time.Second)) // The target's full freshness window has ended.
	id := original.Body.(wire.NativePairStatusRequest).Context.RequestID
	if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_reads_v1 WHERE operation_id=?`, id).Scan(&count) != nil || count != 0 {
		t.Fatal("old target was not actually evicted")
	}
	original.At = start.Add(149*time.Second + time.Microsecond)
	recovered, err := f.f.db.ProcessHubNativePair(original, seal)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.NativePairResult
	if wire.OpenClientResponse(f.f.device, f.f.hub, original.Packet, recovered, &result) != nil || result.Outcome != "READ_EXPIRED" || result.AdministrativePermission || result.SlotA != nil || result.SlotB != nil {
		t.Fatal("evicted original became current again")
	}
}

func TestHubNativePairFutureReadCannotPublishForgettableSettlement(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, completeSeal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, completeSeal); err != nil {
		t.Fatal(err)
	}
	at := f.at.Add(2 * time.Second)
	q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: f.context(t, at.Add(time.Hour)), SessionToken: f.f.session.Token, PairID: ch.Bootstrap.PairID}
	original, seal := f.input(t, q, at)
	if packet, err := f.f.db.ProcessHubNativePair(original, seal); !errors.Is(err, ErrHubAccountRejected) || len(packet) != 0 {
		t.Fatal("far future read received a settlement", err)
	}
	query := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: f.context(t, at), PairID: ch.Bootstrap.PairID, OriginalPacket: original.Packet}
	in, querySeal := f.input(t, query, at)
	in.Original = &original
	in.OriginalSeal = seal
	if packet, err := f.f.db.ProcessHubNativePair(in, querySeal); !errors.Is(err, ErrHubAccountRejected) || len(packet) != 0 {
		t.Fatal("future original was settled by reconciliation", err)
	}
	for _, table := range []string{"hub_native_pair_reads_v1", "hub_native_pair_rates_v1"} {
		var count int
		if f.f.db.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count) != nil || count != 0 {
			t.Fatal("rejected future read left cache/rate state")
		}
	}
}
