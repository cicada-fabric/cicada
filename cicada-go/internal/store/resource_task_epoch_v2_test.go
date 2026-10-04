package store

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func rejectResourceTaskWrites(t *testing.T, s *Store, scope *NativeActorScope, lease *ResourceLease) {
	t.Helper()
	before := snapshotResourceRelease(t, s, lease.ID)
	var renewErr, writeErr error
	if scope == nil {
		_, renewErr = s.RenewResourceLease(lease.ID, lease.FencingEpoch, lease.HolderPrincipalID, 900)
		_, writeErr = s.WriteManagedBlob(lease.ID, lease.FencingEpoch, lease.HolderPrincipalID, []byte("synthetic rejected publication"))
	} else {
		_, renewErr = s.RenewResourceLeaseForActor(*scope, lease.ID, lease.FencingEpoch, 900)
		_, writeErr = s.WriteManagedBlobForActor(*scope, lease.ID, lease.FencingEpoch, []byte("synthetic rejected publication"))
	}
	if !errors.Is(renewErr, ErrResourceStaleEpoch) || !errors.Is(writeErr, ErrResourceStaleEpoch) {
		t.Fatalf("stale Task admitted renew/write: renew=%v write=%v", renewErr, writeErr)
	}
	if after := snapshotResourceRelease(t, s, lease.ID); !reflect.DeepEqual(before, after) {
		t.Fatal("rejected Task generation changed lease, authority, blob or writer provenance")
	}
}

func resourceTaskHandoff(t *testing.T, s *Store, task *SharedTask, principal, endpoint string) *SharedTask {
	t.Helper()
	proposal, err := proposePreparingSharedTaskHandoffFixture(t, s, SharedTaskHandoff{
		TaskID: task.ID, GroupID: task.GroupID, FromPrincipalID: task.OwnerPrincipalID,
		FromEndpointID: task.OwnerEndpointID, ToPrincipalID: principal, ToEndpointID: endpoint,
		FromOwnerEpoch: task.OwnerEpoch, TaskRevision: task.Revision,
		PendingWork: "synthetic continuation under a new ownership generation",
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.AcceptSharedTaskHandoff(proposal.ID, principal, endpoint, 300)
	if err != nil {
		t.Fatal(err)
	}
	if current.OwnerEpoch <= task.OwnerEpoch {
		t.Fatal("handoff did not advance Task epoch")
	}
	return current
}

func TestResourceTaskEpochTrustedWritesAndRenewals(t *testing.T) {
	s, group := newSharedTaskTestStore(t)
	defer s.Close()
	for _, scenario := range []string{"expired", "released", "same_principal_reclaim", "different_principal_handoff", "same_principal_endpoint_handoff", "result_submitted"} {
		t.Run(scenario, func(t *testing.T) {
			task := claimedResourceTask(t, s, group, "principal-task", "endpoint-task")
			lease, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: "managed_blob/task-epoch-" + scenario + "/write", GroupID: group, TaskID: task.ID, PrincipalID: task.OwnerPrincipalID})
			if err != nil {
				t.Fatal(err)
			}
			if lease.HolderTaskEpoch != task.OwnerEpoch {
				t.Fatal("Acquire did not capture Task epoch")
			}
			if _, err := s.WriteManagedBlob(lease.ID, lease.FencingEpoch, task.OwnerPrincipalID, []byte("synthetic accepted publication")); err != nil {
				t.Fatal(err)
			}
			task, err = s.RenewSharedTaskClaim(task.ID, task.Revision, task.OwnerEpoch, task.OwnerPrincipalID, task.OwnerEndpointID, 300)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.RenewResourceLease(lease.ID, lease.FencingEpoch, task.OwnerPrincipalID, 300); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "expired":
				if _, err := s.db.Exec(`UPDATE shared_tasks_v2 SET lease_expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), task.ID); err != nil {
					t.Fatal(err)
				}
			case "released", "same_principal_reclaim":
				released, err := s.ReleaseSharedTaskClaim(task.ID, task.Revision, task.OwnerEpoch, task.OwnerPrincipalID, task.OwnerEndpointID)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "same_principal_reclaim" {
					current, err := s.ClaimSharedTask(task.ID, released.Revision, task.OwnerPrincipalID, task.OwnerEndpointID, "synthetic-new-generation", 300)
					if err != nil {
						t.Fatal(err)
					}
					if current.OwnerEpoch <= lease.HolderTaskEpoch {
						t.Fatal("reclaim did not advance epoch")
					}
				}
			case "different_principal_handoff":
				resourceTaskHandoff(t, s, task, "principal-next", "endpoint-next-"+scenario)
			case "same_principal_endpoint_handoff":
				resourceTaskHandoff(t, s, task, task.OwnerPrincipalID, "endpoint-next-"+scenario)
			case "result_submitted":
				if _, err := s.SubmitSharedTaskResult(task.ID, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, task.Revision, "synthetic result", []string{"synthetic:evidence"}); err != nil {
					t.Fatal(err)
				}
			}
			rejectResourceTaskWrites(t, s, nil, lease)
			// Revoked Task execution never makes a still-held physical conflict key free.
			if _, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: lease.ResourceID, GroupID: group, TaskID: task.ID, PrincipalID: task.OwnerPrincipalID}); !errors.Is(err, ErrResourceBusy) {
				t.Fatalf("lost Task freed resource: %v", err)
			}
			if _, err := s.QuarantineResourceLease(lease.ID, lease.FencingEpoch, lease.HolderPrincipalID); err != nil {
				t.Fatalf("Task loss prevented quarantine cleanup: %v", err)
			}
		})
	}
}

func acquireResourceTaskLeaseForActor(t *testing.T, s *Store, scope NativeActorScope, resourceID string) *ResourceLease {
	t.Helper()
	task, err := s.CreateSharedTask(SharedTask{GroupID: scope.GroupID, Objective: "synthetic bounded blob", AcceptanceCriteria: "current fenced writer"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = s.ReadySharedTask(task.ID, task.Revision, "synthetic-manager")
	if err != nil {
		t.Fatal(err)
	}
	task, err = s.ClaimSharedTaskForActor(scope, task.ID, task.Revision, "synthetic-claim-"+task.ID, 300)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: resourceID, GroupID: scope.GroupID, TaskID: task.ID, PrincipalID: scope.PrincipalID, TTLSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteManagedBlobForActor(scope, lease.ID, lease.FencingEpoch, []byte("synthetic original blob")); err != nil {
		t.Fatal(err)
	}
	return lease
}

func TestResourceTaskEpochNativeOwnerAndCleanup(t *testing.T) {
	f, scope, first := resourceReleaseFixture(t, "managed_blob/task-native-released/write", false)
	for _, scenario := range []string{"released", "expired", "same_principal_endpoint_handoff", "wrong_current_endpoint"} {
		t.Run(scenario, func(t *testing.T) {
			lease := first
			if scenario != "released" {
				lease = acquireResourceTaskLeaseForActor(t, f.store, scope, "managed_blob/task-native-"+scenario+"/write")
			}
			task, err := f.store.GetSharedTask(lease.HolderTaskID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.RenewResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch, 300); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "released":
				if _, err := f.store.ReleaseSharedTaskClaimForActor(scope, task.ID, task.Revision, task.OwnerEpoch); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := f.store.db.Exec(`UPDATE shared_tasks_v2 SET lease_expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), task.ID); err != nil {
					t.Fatal(err)
				}
			case "same_principal_endpoint_handoff":
				resourceTaskHandoff(t, f.store, task, scope.PrincipalID, "synthetic-next-endpoint")
			case "wrong_current_endpoint":
				// Simulate inconsistent legacy Task state without advancing its epoch;
				// the current NativeActor is valid but is not the Task owner Endpoint.
				if _, err := f.store.db.Exec(`UPDATE shared_tasks_v2 SET owner_endpoint_id=? WHERE id=?`, "synthetic-other-endpoint", task.ID); err != nil {
					t.Fatal(err)
				}
			}
			rejectResourceTaskWrites(t, f.store, &scope, lease)
			if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); err != nil {
				t.Fatalf("Task loss prevented safe managed cleanup: %v", err)
			}
		})
	}
}

func TestResourceTaskEpochMigrationPreservesLegacyUnknown(t *testing.T) {
	f, scope, lease := resourceReleaseFixture(t, "managed_blob/task-legacy/write", false)
	var path string
	if err := f.store.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	before := snapshotResourceRelease(t, f.store, lease.ID)
	if _, err := f.store.db.Exec(`UPDATE resource_v2_leases SET holder_task_epoch=holder_task_epoch+1 WHERE id=?`, lease.ID); err == nil {
		t.Fatal("new acquisition provenance was mutable")
	}
	// Reconstruct only the previous schema boundary in this disposable fixture.
	for _, statement := range []string{
		`DROP TRIGGER resource_v2_lease_task_provenance_immutable_v58`,
		`ALTER TABLE resource_v2_leases DROP COLUMN holder_task_epoch`,
		`DELETE FROM schema_migrations_v2 WHERE version=58`,
	} {
		if _, err := f.store.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before.Lease.HolderTaskEpoch = 0
	if got := snapshotResourceRelease(t, s, lease.ID); !reflect.DeepEqual(before, got) {
		t.Fatal("migration rewrote legacy lease or blob")
	}
	rejectResourceTaskWrites(t, s, &scope, lease)
	if _, err := s.db.Exec(`UPDATE resource_v2_leases SET holder_task_epoch=1 WHERE id=?`, lease.ID); err == nil {
		t.Fatal("legacy provenance could be reconstructed after migration")
	}
	if err := s.initializeResourceTaskEpochV2Schema(); err != nil {
		t.Fatalf("schema upgrade is not idempotent: %v", err)
	}
	if _, err := s.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); err != nil {
		t.Fatalf("unknown Task epoch prevented legacy cleanup: %v", err)
	}
}

func TestResourceTaskEpochCrossHandleTaskReleaseBoundary(t *testing.T) {
	s, group := newSharedTaskTestStore(t)
	defer s.Close()
	var path string
	if err := s.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, operation := range []string{"write", "renew"} {
		t.Run(operation, func(t *testing.T) {
			task := claimedResourceTask(t, s, group, "principal-race", "endpoint-race")
			lease, err := s.AcquireResourceLease(ResourceLeaseRequest{ResourceID: "managed_blob/task-race-" + operation + "/write", GroupID: group, TaskID: task.ID, PrincipalID: task.OwnerPrincipalID})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.WriteManagedBlob(lease.ID, lease.FencingEpoch, lease.HolderPrincipalID, []byte("synthetic before release")); err != nil {
				t.Fatal(err)
			}
			before := snapshotResourceRelease(t, s, lease.ID)
			start := make(chan struct{})
			var wg sync.WaitGroup
			var releaseErr, mutationErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, releaseErr = other.ReleaseSharedTaskClaim(task.ID, task.Revision, task.OwnerEpoch, task.OwnerPrincipalID, task.OwnerEndpointID)
			}()
			go func() {
				defer wg.Done()
				<-start
				if operation == "write" {
					_, mutationErr = s.WriteManagedBlob(lease.ID, lease.FencingEpoch, lease.HolderPrincipalID, []byte("synthetic raced publication"))
				} else {
					_, mutationErr = s.RenewResourceLease(lease.ID, lease.FencingEpoch, lease.HolderPrincipalID, 900)
				}
			}()
			close(start)
			wg.Wait()
			if releaseErr != nil {
				t.Fatal(releaseErr)
			}
			if mutationErr != nil && !errors.Is(mutationErr, ErrResourceStaleEpoch) {
				t.Fatalf("race mutation: %v", mutationErr)
			}
			after := snapshotResourceRelease(t, s, lease.ID)
			if errors.Is(mutationErr, ErrResourceStaleEpoch) && !reflect.DeepEqual(before, after) {
				t.Fatal("rejected raced mutation changed resource state")
			}
			if after.State != ResourceActive || after.Current != lease.ID || after.Epoch != lease.FencingEpoch {
				t.Fatal("Task release changed physical authority")
			}
			rejectResourceTaskWrites(t, s, nil, lease)
		})
	}
}
