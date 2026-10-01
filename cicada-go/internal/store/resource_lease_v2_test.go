package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func claimedResourceTask(t *testing.T, s *Store, groupID, principalID, endpointID string) *SharedTask {
	t.Helper()
	task, err := s.CreateSharedTask(SharedTask{GroupID: groupID, Objective: "resource test", AcceptanceCriteria: "verified result"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = s.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	task, err = claimPreparingSharedTaskFixture(t, s, task.ID, task.Revision, principalID, endpointID, "claim-"+endpointID, 300)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestResourceLeaseCrossGroupSingleAuthorityAndQuarantine(t *testing.T) {
	s, groupA := newSharedTaskTestStore(t)
	defer s.Close()
	owner, err := s.CreatePrincipal(Principal{Kind: PrincipalKindHuman, Name: "owner-b", Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateGroup(Group{Name: "group-b", OwnerPrincipalID: owner.ID, State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	taskA := claimedResourceTask(t, s, groupA, "principal-a", "ep-a")
	taskB := claimedResourceTask(t, s, other.ID, "principal-b", "ep-b")
	resourceID := "machine/node-gpu2/gpu/0"
	leaseA, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: resourceID, GroupID: groupA, TaskID: taskA.ID, PrincipalID: "principal-a", TTLSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if leaseA.Enforcement != LeaseAdvisory {
		t.Fatalf("GPU lease falsely claimed executor fencing: %#v", leaseA)
	}
	if _, err = s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: resourceID, GroupID: other.ID, TaskID: taskB.ID, PrincipalID: "principal-b"}); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("second Group acquired same GPU: %v", err)
	}
	if _, err = s.QuarantineResourceLease(leaseA.ID, leaseA.FencingEpoch, "principal-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: resourceID, GroupID: other.ID, TaskID: taskB.ID, PrincipalID: "principal-b"}); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("quarantined GPU reused without stop confirmation: %v", err)
	}
	if err = s.ReconcileResourceLease(resourceID, leaseA.FencingEpoch, false, ""); !errors.Is(err, ErrResourceReconciliation) {
		t.Fatalf("missing stop confirmation accepted: %v", err)
	}
	if err = s.ReconcileResourceLease(resourceID, leaseA.FencingEpoch, true, "operator confirmed old GPU job stopped; execution log ref X"); err != nil {
		t.Fatal(err)
	}
	leaseB, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: resourceID, GroupID: other.ID, TaskID: taskB.ID, PrincipalID: "principal-b"})
	if err != nil {
		t.Fatal(err)
	}
	if leaseB.FencingEpoch <= leaseA.FencingEpoch {
		t.Fatalf("new Group reused stale epoch: old=%d new=%d", leaseA.FencingEpoch, leaseB.FencingEpoch)
	}
	if _, err = s.RenewResourceLease(leaseA.ID, leaseA.FencingEpoch, "principal-a", 300); !errors.Is(err, ErrResourceLeaseExpired) && !errors.Is(err, ErrResourceStaleEpoch) {
		t.Fatalf("old holder renewed after handoff: %v", err)
	}
}

func TestResourceLeaseCanonicalGPUIdentityAndLegacyAliasQuarantine(t *testing.T) {
	for _, raw := range []string{"00", "01", "+0", "-0", "0007"} {
		if _, err := resourceEnforcement("machine/node-gpu/gpu/" + raw); !errors.Is(err, ErrResourceInvalid) {
			t.Errorf("noncanonical GPU index %q was accepted: %v", raw, err)
		}
	}
	if enforcement, err := resourceEnforcement("machine/node-gpu/gpu/0"); err != nil || enforcement != LeaseAdvisory {
		t.Fatalf("canonical GPU key was rejected: enforcement=%q err=%v", enforcement, err)
	}

	for _, tc := range []struct {
		name        string
		legacyIndex string
		state       string
		leaseState  string
	}{
		{name: "active leading-zero alias", legacyIndex: "00", state: ResourceActive, leaseState: LeaseActive},
		{name: "reconciliation signed alias", legacyIndex: "+0", state: ResourceQuarantined, leaseState: LeaseUncertain},
		{name: "reconciliation negative-zero alias", legacyIndex: "-0", state: ResourceQuarantined, leaseState: LeaseUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, groupA := newSharedTaskTestStore(t)
			defer s.Close()
			owner, err := s.CreatePrincipal(Principal{Kind: PrincipalKindHuman, Name: "owner-gpu-alias", Status: PrincipalStatusActive})
			if err != nil {
				t.Fatal(err)
			}
			groupB, err := s.CreateGroup(Group{Name: "group-gpu-alias", OwnerPrincipalID: owner.ID, State: GroupStateActive})
			if err != nil {
				t.Fatal(err)
			}
			taskA := claimedResourceTask(t, s, groupA, "principal-a", "ep-a")
			taskB := claimedResourceTask(t, s, groupB.ID, "principal-b", "ep-b")
			legacyResourceID := "machine/node-gpu-alias/gpu/" + tc.legacyIndex
			legacyLeaseID := NewID("legacy_resource_lease")
			stamp := now()
			if _, err := s.db.Exec(`INSERT INTO resource_v2_authority
(resource_id,fencing_epoch,state,current_lease_id,reconciliation_evidence,updated_at)
VALUES(?,7,?,?,?,?)`, legacyResourceID, tc.state, legacyLeaseID, "legacy row retained", stamp); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`INSERT INTO resource_v2_leases
(id,resource_id,holder_group_id,holder_task_id,holder_principal_id,fencing_epoch,mode,enforcement,state,expires_at,created_at,updated_at)
VALUES(?,?,?,?,?,7,'exclusive',?,?,?, ?,?)`, legacyLeaseID, legacyResourceID,
				groupA, taskA.ID, "principal-a", LeaseAdvisory, tc.leaseState,
				time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), stamp, stamp); err != nil {
				t.Fatal(err)
			}
			if _, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: "machine/node-gpu-alias/gpu/0",
				GroupID: groupB.ID, TaskID: taskB.ID, PrincipalID: "principal-b"}); !errors.Is(err, ErrResourceBusy) {
				t.Fatalf("canonical GPU acquisition bypassed active legacy alias %q: %v", legacyResourceID, err)
			}
			var state, currentLease string
			if err := s.db.QueryRow(`SELECT state,current_lease_id FROM resource_v2_authority WHERE resource_id=?`, legacyResourceID).Scan(&state, &currentLease); err != nil {
				t.Fatal(err)
			}
			if state != tc.state || currentLease != legacyLeaseID {
				t.Fatalf("legacy alias authority was rewritten: state=%q lease=%q", state, currentLease)
			}
			var canonicalRows int
			if err := s.db.QueryRow(`SELECT count(*) FROM resource_v2_authority WHERE resource_id=?`,
				"machine/node-gpu-alias/gpu/0").Scan(&canonicalRows); err != nil {
				t.Fatal(err)
			}
			if canonicalRows != 0 {
				t.Fatalf("rejected canonical key left a partial authority row: %d", canonicalRows)
			}
		})
	}
}

func TestResourceLeaseExpiryDoesNotAssumeOldProcessStopped(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := claimedResourceTask(t, s, groupID, "principal-a", "ep-a")
	lease, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: "workspace/ws-test/write", GroupID: groupID, TaskID: task.ID, PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE resource_v2_leases SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: lease.ResourceID, GroupID: groupID, TaskID: task.ID, PrincipalID: "principal-a"}); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("expired lease auto-released resource: %v", err)
	}
	var state string
	if err = s.db.QueryRow(`SELECT state FROM resource_v2_authority WHERE resource_id=?`, lease.ResourceID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != ResourceQuarantined {
		t.Fatalf("expired resource state=%q want reconciliation", state)
	}
}

func TestManagedBlobExecutorRejectsStaleEpoch(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := claimedResourceTask(t, s, groupID, "principal-a", "ep-a")
	first, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: "managed_blob/result-a/write", GroupID: groupID, TaskID: task.ID, PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Enforcement != LeaseExecutorEnforced {
		t.Fatalf("managed executor was not labeled enforced: %#v", first)
	}
	if _, err = s.WriteManagedBlob(first.ID, first.FencingEpoch, "principal-a", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.QuarantineResourceLease(first.ID, first.FencingEpoch, "principal-a"); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileResourceLease(first.ResourceID, first.FencingEpoch, true, "managed blob operation ended at transaction boundary"); err != nil {
		t.Fatal(err)
	}
	second, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: first.ResourceID, GroupID: groupID, TaskID: task.ID, PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.WriteManagedBlob(first.ID, first.FencingEpoch, "principal-a", []byte("stale overwrite")); !errors.Is(err, ErrResourceStaleEpoch) && !errors.Is(err, ErrResourceLeaseExpired) {
		t.Fatalf("old executor epoch wrote: %v", err)
	}
	if _, err = s.WriteManagedBlob(second.ID, second.FencingEpoch, "principal-a", []byte("second")); err != nil {
		t.Fatal(err)
	}
	var value []byte
	var epoch int64
	if err = s.db.QueryRow(`SELECT value,writer_epoch FROM resource_v2_managed_blobs WHERE resource_id=?`, first.ResourceID).Scan(&value, &epoch); err != nil {
		t.Fatal(err)
	}
	if string(value) != "second" || epoch != second.FencingEpoch {
		t.Fatalf("executor outcome value=%q epoch=%d", value, epoch)
	}
}

func TestResourceLeaseConcurrentAcquireAcrossStoreHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	owner, err := a.CreatePrincipal(Principal{Kind: PrincipalKindHuman, Name: "owner", Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := a.CreateGroup(Group{Name: "g", OwnerPrincipalID: owner.ID, State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	task := claimedResourceTask(t, a, group.ID, "principal-a", "ep-a")
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, handle := range []*Store{a, b} {
		wg.Add(1)
		go func(i int, handle *Store) {
			defer wg.Done()
			_, results[i] = handle.AcquireResourceLease(ResourceLeaseRequest{
				ResourceID: "machine/node-a/gpu/0", GroupID: group.ID, TaskID: task.ID, PrincipalID: "principal-a"})
		}(i, handle)
	}
	wg.Wait()
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrResourceBusy) {
			t.Fatalf("unexpected cross-process acquisition error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners=%d errors=%#v", winners, results)
	}
}
