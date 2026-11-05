package store

import (
	"encoding/json"
	"errors"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests isolate transaction/CAS/retention mechanics, not caller authority.
// Actual Owner and Node authorization is tested by the real HTTP fixture.
func threadCollaborationStoreFixture(t *testing.T) (*Store, string, wire.GroupLockScope, wire.GroupCoordinationPolicy) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic-collaboration.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	scope := wire.GroupLockScope{HubID: "synthetic-hub", NetworkID: "synthetic-network", GroupID: "synthetic-group"}
	p := wire.GroupCoordinationPolicy{Format: wire.GroupCoordinationPolicyFormat, HubID: scope.HubID, NetworkID: scope.NetworkID, GroupID: scope.GroupID, PolicyID: "synthetic-policy", Revision: 1, State: "ENABLED", SlotCount: 8, Rights: wire.GroupCoordinationRights(), OwnerConsentDigest: strings.Repeat("a", 64)}
	raw, _ := json.Marshal(p)
	if _, err = s.db.Exec(`INSERT INTO group_coordination_policies_v1 VALUES(?,?,?,?,?,?,?,?,?)`, scope.GroupID, "synthetic-owner", scope.NetworkID, p.PolicyID, 1, p.State, string(raw), "2026-11-05T00:00:00Z", "2026-11-05T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	for slot := 1; slot <= 8; slot++ {
		if _, err = s.db.Exec(`INSERT INTO group_lock_slots_v1 VALUES(?,?,'FREE',1,0,'','','')`, scope.GroupID, slot); err != nil {
			t.Fatal(err)
		}
	}
	return s, path, scope, p
}
func TestThreadCollaborationStoreAtomicRaceRestartExpiry(t *testing.T) {
	s, path, scope, p := threadCollaborationStoreFixture(t)
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	callers := []wire.GroupLockHolder{{NodeID: "synthetic-A", EndpointID: "synthetic-A", PrincipalID: "shared-principal", Source: wire.ThreadRegistrationSource{RegistrationID: "synthetic-thread-A", SourceEpoch: 1}}, {NodeID: "synthetic-B", EndpointID: "synthetic-B", PrincipalID: "shared-principal", Source: wire.ThreadRegistrationSource{RegistrationID: "synthetic-thread-B", SourceEpoch: 1}}}
	requests := make([]wire.GroupLockAcquireRequest, 2)
	for i := range requests {
		o, e := wire.NewGroupLockOriginal(now)
		if e != nil {
			t.Fatal(e)
		}
		requests[i] = wire.GroupLockAcquireRequest{Scope: scope, Slot: 1, ExpectedVersion: 1, Original: o}
		requests[i].Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, callers[i], requests[i])
	}
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	receipts := make([]wire.GroupLockReceipt, 2)
	errs := make([]error, 2)
	for i, db := range []*Store{s, other} {
		go func(i int, db *Store) {
			defer wg.Done()
			<-start
			tx, e := db.db.Begin()
			if e != nil {
				errs[i] = e
				return
			}
			defer tx.Rollback()
			if _, e = tx.Exec(`UPDATE thread_collaboration_guard_v1 SET touched_at=touched_at WHERE id=1`); e != nil {
				errs[i] = e
				return
			}
			view, e := threadCollaborationSlotsTx(tx, scope, p, now)
			if e != nil {
				errs[i] = e
				return
			}
			receipts[i], errs[i] = threadCollaborationLockTx(tx, callers[i], wire.OperationGroupLocksAcquire, requests[i], view, now)
			if errs[i] == nil {
				errs[i] = tx.Commit()
			}
		}(i, db)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, e := range errs {
		if e == nil {
			if winner >= 0 {
				t.Fatal("two concurrent holders")
			}
			winner = i
		} else if e.Error() != wire.ThreadCollaborationErrorVersionConflict {
			t.Fatal(e)
		}
	}
	if winner < 0 {
		t.Fatal("no concurrent winner")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	tx, err := reopened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE thread_collaboration_guard_v1 SET touched_at=touched_at WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	view, err := threadCollaborationSlotsTx(tx, scope, p, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if view.Slots[0].State != "HELD" || *view.Slots[0].Holder != callers[winner] {
		t.Fatal("restart lost original holder")
	}
	exact, err := threadCollaborationLockTx(tx, callers[winner], wire.OperationGroupLocksAcquire, requests[winner], view, now.Add(time.Minute))
	if err != nil || exact != receipts[winner] {
		t.Fatal("lost-response exact recovery changed receipt", err)
	}
	view, err = threadCollaborationSlotsTx(tx, scope, p, now.Add(301*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if view.Slots[0].State != "FREE" || view.Slots[0].Generation != 1 || view.Slots[0].Version != 3 {
		t.Fatal("expiry did not advance exactly once")
	}
	again, err := threadCollaborationSlotsTx(tx, scope, p, now.Add(302*time.Second))
	if err != nil || again.Slots[0].Version != 3 {
		t.Fatal("expiry repeated")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func TestThreadCollaborationStoreBoundedOriginalRecovery(t *testing.T) {
	s, _, scope, p := threadCollaborationStoreFixture(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	caller := wire.GroupLockHolder{NodeID: "synthetic-node", EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-principal", Source: wire.ThreadRegistrationSource{RegistrationID: "synthetic-source", SourceEpoch: 1}}
	o, _ := wire.NewGroupLockOriginal(now)
	q := wire.GroupLockAcquireRequest{Scope: scope, Slot: 1, ExpectedVersion: 1, Original: o}
	q.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, caller, q)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	view, err := threadCollaborationSlotsTx(tx, scope, p, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = threadCollaborationLockTx(tx, caller, wire.OperationGroupLocksAcquire, q, view, now); err != nil {
		t.Fatal(err)
	}
	view, err = threadCollaborationSlotsTx(tx, scope, p, now.Add(25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = threadCollaborationGCTx(tx, now.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM group_lock_originals_v1`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired advanced original not reclaimed", count, err)
	}
	before := view.Slots[0]
	q.ExpectedVersion = before.Version
	q.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, caller, q)
	_, err = threadCollaborationLockTx(tx, caller, wire.OperationGroupLocksAcquire, q, view, now.Add(25*time.Hour))
	if err == nil || err.Error() != wire.ThreadCollaborationErrorReceiptUnavailable {
		t.Fatal("expired ID with new CAS/body executed", err)
	}
	after, e := threadCollaborationSlotsTx(tx, scope, p, now.Add(25*time.Hour))
	if e != nil || after.Slots[0] != before {
		t.Fatal("expired original changed free slot")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(wire.ValidateGroupLockOriginalWindow(q.Original, now.Add(-time.Minute)), wire.ErrInvalid) && wire.ValidateGroupLockOriginalWindow(q.Original, now.Add(-time.Minute)) == nil {
		t.Fatal("future ID accepted")
	}
}
