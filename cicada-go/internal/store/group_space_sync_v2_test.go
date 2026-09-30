package store

import (
	"testing"
	"time"
)

func TestGroupSpaceSyncUsesCommitOrderAndRetainsWatermarkAfterPurge(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	first := f.prepare(t, "synthetic_sync_reserved_first", GroupSpaceKindJournal)
	second := f.prepare(t, "synthetic_sync_reserved_second", GroupSpaceKindJournal)
	if first.Sequence >= second.Sequence {
		t.Fatal("fixture did not reserve in record sequence order")
	}
	secondRecord, _ := f.commit(t, second, []byte("synthetic second reservation commits first"))
	reader := f.actor(t, f.sealed.target)
	initial, err := f.sealed.store.SyncGroupSpace(reader, GroupSpaceSyncInput{GroupID: f.sealed.groupID})
	if err != nil || initial.LatestSeq != 1 || initial.NextSeq != 1 || len(initial.Hints) != 1 ||
		initial.Hints[0].Sequence != 1 || initial.UnreadCount != 1 || initial.ReadSeq != 0 ||
		initial.WatermarkVersion != "commit_v1" || initial.HubID == "" || initial.NetworkID != f.networkID {
		t.Fatalf("first committed hint: %+v, %v", initial, err)
	}
	marked, err := f.sealed.store.MarkGroupSpaceRead(reader, GroupSpaceMarkReadInput{
		GroupID: f.sealed.groupID, ThroughSeq: initial.NextSeq})
	if err != nil || marked.ReadSeq != 1 || marked.UnreadCount != 0 {
		t.Fatalf("mark first committed change: %+v, %v", marked, err)
	}
	firstRecord, _ := f.commit(t, first, []byte("synthetic first reservation commits second"))
	late, err := f.sealed.store.SyncGroupSpace(reader, GroupSpaceSyncInput{
		GroupID: f.sealed.groupID, AfterSeq: initial.NextSeq})
	if err != nil || late.LatestSeq != 2 || late.NextSeq != 2 || len(late.Hints) != 1 ||
		late.Hints[0].Sequence != 2 || late.UnreadCount != 1 {
		t.Fatalf("late commit disappeared behind cursor: %+v, %v", late, err)
	}
	if _, err := f.sealed.store.MarkGroupSpaceRead(reader, GroupSpaceMarkReadInput{
		GroupID: f.sealed.groupID, ThroughSeq: 3}); err != ErrGroupSpaceConflict {
		t.Fatalf("mark beyond current watermark: %v", err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE group_space_records_v2 SET expires_at=?
WHERE record_id IN (?,?)`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		firstRecord.Snapshot.RecordID, secondRecord.Snapshot.RecordID); err != nil {
		t.Fatal(err)
	}
	if count, err := f.sealed.store.PurgeExpiredGroupSpaces(16); err != nil || count != 2 {
		t.Fatalf("purge fixture: count=%d err=%v", count, err)
	}
	afterPurge, err := f.sealed.store.SyncGroupSpace(reader, GroupSpaceSyncInput{
		GroupID: f.sealed.groupID, AfterSeq: late.NextSeq})
	if err != nil || afterPurge.LatestSeq != 2 || afterPurge.NextSeq != 2 ||
		len(afterPurge.Hints) != 0 || afterPurge.UnreadCount != 0 {
		t.Fatalf("purge moved committed watermark backwards: %+v, %v", afterPurge, err)
	}
}
