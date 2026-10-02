package nodeinbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// This valid noncanonical timestamp also verifies that pagination retains the
// stored ordering key instead of rebuilding it from Delivery.CreatedAt.
const nativeRecoveryTestCreatedAt = "2026-10-02T00:00:00+00:00"

func seedNativeRecoveryDelivery(t *testing.T, inbox *Inbox, id string, state State) Delivery {
	t.Helper()
	ctx := context.Background()
	message := testMessage(id, "digest-"+id)
	message.Payload = []byte("synthetic original notice metadata for " + id)
	if _, _, err := inbox.Save(ctx, message); err != nil {
		t.Fatal(err)
	}
	if state != NODE_RECEIVED {
		claim, err := inbox.Claim(ctx, "synthetic-native-recovery")
		if err != nil || claim.MessageID != id {
			t.Fatalf("claim fixture %s: %#v %v", id, claim, err)
		}
		if _, err := inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
			t.Fatal(err)
		}
		receipt := Receipt{MessageID: claim.MessageID, Digest: claim.Digest,
			EndpointID: claim.EndpointID, SessionID: claim.SessionID,
			BindingEpoch: claim.BindingEpoch, AttemptID: claim.AttemptID}
		switch state {
		case INJECTING:
		case INJECTION_UNCERTAIN:
			receipt.State = INJECTION_UNCERTAIN
			if _, err := inbox.Acknowledge(ctx, receipt); err != nil {
				t.Fatal(err)
			}
		case CONSUMPTION_UNCONFIRMED:
			if _, err := inbox.RecordCodexQueueAccepted(ctx, receipt); err != nil {
				t.Fatal(err)
			}
		case RUNTIME_INJECTED:
			if _, err := inbox.RecordRuntimeInjected(ctx, receipt); err != nil {
				t.Fatal(err)
			}
		case FAILED:
			if _, err := inbox.RecordFailed(ctx, receipt, "synthetic known failure"); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unsupported fixture state %s", state)
		}
	}
	// Only fixture preparation writes timestamps; the page method must not.
	if _, err := inbox.db.ExecContext(ctx, `UPDATE node_inbox_deliveries
SET created_at=?, updated_at=? WHERE message_id=?`, nativeRecoveryTestCreatedAt, nativeRecoveryTestCreatedAt, id); err != nil {
		t.Fatal(err)
	}
	delivery, err := inbox.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return *delivery
}

func nativeRecoveryIDs(batch []Delivery) []string {
	ids := make([]string, 0, len(batch))
	for _, delivery := range batch {
		ids = append(ids, delivery.MessageID)
	}
	return ids
}

func TestNativeRecoveryBatchPagesAndWraps(t *testing.T) {
	inbox := openTestInbox(t)
	ctx := context.Background()
	want := make([]string, 33)
	for index := range want {
		want[index] = fmt.Sprintf("notice-%02d", index)
		state := CONSUMPTION_UNCONFIRMED
		if index == len(want)-1 {
			state = INJECTION_UNCERTAIN
		}
		seedNativeRecoveryDelivery(t, inbox, want[index], state)
	}
	var got []string
	for _, size := range []int{16, 16, 1} {
		batch, err := inbox.NextNativeRecoveryBatch(ctx, 16)
		if err != nil || len(batch) != size {
			t.Fatalf("page size=%d want=%d: %v", len(batch), size, err)
		}
		got = append(got, nativeRecoveryIDs(batch)...)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("accepted history starved later uncertainty: got=%v want=%v", got, want)
	}
	batch, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(batch), want[:16]) {
		t.Fatalf("short tail did not wrap on next call: %v %v", nativeRecoveryIDs(batch), err)
	}
}

func TestNativeRecoveryBatchExactTailWrapAndIndependentInbox(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-inbox")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inbox.sqlite3")
	inbox, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inbox.Close() })
	want := make([]string, 32)
	for index := range want {
		want[index] = fmt.Sprintf("notice-%02d", index)
		seedNativeRecoveryDelivery(t, inbox, want[index], CONSUMPTION_UNCONFIRMED)
	}
	ctx := context.Background()
	first, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(first), want[:16]) {
		t.Fatalf("first page: %v %v", nativeRecoveryIDs(first), err)
	}
	independent, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = independent.Close() })
	independentFirst, err := independent.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(independentFirst), want[:16]) {
		t.Fatalf("cursor leaked across Inbox handles: %v %v", nativeRecoveryIDs(independentFirst), err)
	}
	second, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(second), want[16:]) {
		t.Fatalf("second page: %v %v", nativeRecoveryIDs(second), err)
	}
	wrapped, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(wrapped), want[:16]) {
		t.Fatalf("full tail did not wrap boundedly: %v %v", nativeRecoveryIDs(wrapped), err)
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedFirst, err := reopened.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(reopenedFirst), want[:16]) {
		t.Fatalf("reopened Inbox did not start at head: %v %v", nativeRecoveryIDs(reopenedFirst), err)
	}
}

func TestNativeRecoveryBatchPreservesCoordinatesAndStatesWithoutWrites(t *testing.T) {
	inbox := openTestInbox(t)
	ctx := context.Background()
	states := []State{INJECTING, INJECTION_UNCERTAIN, CONSUMPTION_UNCONFIRMED, RUNTIME_INJECTED, FAILED, NODE_RECEIVED}
	originals := make(map[string]Delivery)
	var want []string
	for index, state := range states {
		id := fmt.Sprintf("notice-%02d", index)
		originals[id] = seedNativeRecoveryDelivery(t, inbox, id, state)
		if index < 3 {
			want = append(want, id)
		}
	}
	var changesBefore, schemaBefore int64
	if err := inbox.db.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&changesBefore); err != nil {
		t.Fatal(err)
	}
	if err := inbox.db.QueryRowContext(ctx, `PRAGMA schema_version`).Scan(&schemaBefore); err != nil {
		t.Fatal(err)
	}
	// The real SQLite connection now rejects every write, including schema work.
	if _, err := inbox.db.ExecContext(ctx, `PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	batch, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(batch), want) {
		t.Fatalf("native recovery state filter: %v %v", nativeRecoveryIDs(batch), err)
	}
	for _, delivery := range batch {
		if !reflect.DeepEqual(delivery, originals[delivery.MessageID]) || delivery.AttemptID == "" {
			t.Fatalf("original native recovery coordinates changed for %s", delivery.MessageID)
		}
	}
	batch[0].Payload[0] = 'X'
	for id, original := range originals {
		stored, err := inbox.Get(ctx, id)
		if err != nil || !reflect.DeepEqual(*stored, original) {
			t.Fatalf("page changed durable delivery %s: %v", id, err)
		}
	}
	var changesAfter, schemaAfter int64
	if err := inbox.db.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&changesAfter); err != nil {
		t.Fatal(err)
	}
	if err := inbox.db.QueryRowContext(ctx, `PRAGMA schema_version`).Scan(&schemaAfter); err != nil {
		t.Fatal(err)
	}
	if changesAfter != changesBefore || schemaAfter != schemaBefore {
		t.Fatalf("recovery read wrote database/schema: changes %d->%d schema %d->%d", changesBefore, changesAfter, schemaBefore, schemaAfter)
	}
}

func TestNativeRecoveryBatchFailureDoesNotAdvanceCursor(t *testing.T) {
	inbox := openTestInbox(t)
	ctx := context.Background()
	want := make([]string, 33)
	for index := range want {
		want[index] = fmt.Sprintf("notice-%02d", index)
		seedNativeRecoveryDelivery(t, inbox, want[index], CONSUMPTION_UNCONFIRMED)
	}
	// The malformed next-page row must not be loaded or scanned by page one.
	if _, err := inbox.db.ExecContext(ctx, `UPDATE node_inbox_deliveries SET updated_at='invalid-fixture-time' WHERE message_id=?`, want[17]); err != nil {
		t.Fatal(err)
	}
	first, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(first), want[:16]) {
		t.Fatalf("SQL page bound loaded later malformed row: %v %v", nativeRecoveryIDs(first), err)
	}
	cursor := inbox.nativeRecoveryCursor
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := inbox.NextNativeRecoveryBatch(canceled, 16); !errors.Is(err, context.Canceled) || inbox.nativeRecoveryCursor != cursor {
		t.Fatalf("canceled query advanced cursor: %v", err)
	}
	for _, limit := range []int{0, -1, 17} {
		if _, err := inbox.NextNativeRecoveryBatch(ctx, limit); err == nil || inbox.nativeRecoveryCursor != cursor {
			t.Fatalf("invalid limit %d advanced cursor or succeeded: %v", limit, err)
		}
	}
	// An actual SQLite database without this schema induces a query error;
	// there is no mock driver or production fault flag.
	uninitialized, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uninitialized.Close() })
	originalDB := inbox.db
	inbox.db = uninitialized
	batch, queryErr := inbox.NextNativeRecoveryBatch(ctx, 16)
	inbox.db = originalDB
	if queryErr == nil || batch != nil || inbox.nativeRecoveryCursor != cursor {
		t.Fatalf("query error advanced cursor or returned partial page: %v", queryErr)
	}
	if batch, err := inbox.NextNativeRecoveryBatch(ctx, 16); err == nil || batch != nil || inbox.nativeRecoveryCursor != cursor {
		t.Fatalf("scan error advanced cursor or returned partial page: %v", err)
	}
	if _, err := inbox.db.ExecContext(ctx, `UPDATE node_inbox_deliveries SET updated_at=? WHERE message_id=?`, nativeRecoveryTestCreatedAt, want[17]); err != nil {
		t.Fatal(err)
	}
	second, err := inbox.NextNativeRecoveryBatch(ctx, 16)
	if err != nil || !reflect.DeepEqual(nativeRecoveryIDs(second), want[16:32]) {
		t.Fatalf("recovered query skipped rows: %v %v", nativeRecoveryIDs(second), err)
	}
}
