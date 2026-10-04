package store

import (
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func resourceReleaseFixture(t *testing.T, resourceID string, mapped bool) (*groupEndpointKeyGrantFixture, NativeActorScope, *ResourceLease) {
	t.Helper()
	f := newGroupEndpointKeyGrantFixture(t)
	endpoint, err := f.store.GetEndpointV2(f.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	networkID := ""
	if mapped {
		hubID, err := f.store.GetClientHubID()
		if err != nil {
			t.Fatal(err)
		}
		network, err := f.store.CreateNetwork(Network{ID: "net_release", HubID: hubID, OwnerID: f.ownerID, Name: "Synthetic release"})
		if err != nil {
			t.Fatal(err)
		}
		group, err := f.store.GetGroup(f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic release mapping", group.Version); err != nil {
			t.Fatal(err)
		}
		if err := f.store.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
			t.Fatal(err)
		}
		networkID = network.ID
		stamp := now()
		if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), network.ID, endpoint.PrincipalID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'synthetic release',0,?,?)`, network.ID, endpoint.ID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.PrincipalID, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	membership, err = f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles,
		[]string{"task.claim", "resource.execute"}, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetSessionBinding(f.bindingID)
	if err != nil {
		t.Fatal(err)
	}
	scope := NativeActorScope{PrincipalID: endpoint.PrincipalID, EndpointID: endpoint.ID, GroupID: f.groupID,
		NetworkID: networkID, MembershipID: membership.ID, MembershipRevision: membership.Revision,
		BindingID: binding.ID, BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
	task, err := f.store.CreateSharedTask(SharedTask{GroupID: f.groupID, Objective: "synthetic bounded blob", AcceptanceCriteria: "current fenced writer"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ReadySharedTask(task.ID, task.Revision, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ClaimSharedTaskForActor(scope, task.ID, task.Revision, "synthetic-release-claim", 300)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.store.AcquireResourceLease(ResourceLeaseRequest{ResourceID: resourceID, GroupID: f.groupID,
		TaskID: task.ID, PrincipalID: scope.PrincipalID, TTLSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if lease.Enforcement == LeaseExecutorEnforced {
		if _, err := f.store.WriteManagedBlobForActor(scope, lease.ID, lease.FencingEpoch, []byte("synthetic original blob")); err != nil {
			t.Fatal(err)
		}
	}
	return f, scope, lease
}

type resourceReleaseSnapshot struct {
	Lease                                        ResourceLease
	Epoch                                        int64
	State, Current, Evidence, AuthorityUpdatedAt string
	Body                                         []byte
	Digest, WriterID, BlobUpdatedAt              string
	WriterEpoch                                  int64
}

func snapshotResourceRelease(t *testing.T, s *Store, id string) resourceReleaseSnapshot {
	t.Helper()
	lease, err := s.GetResourceLease(id)
	if err != nil {
		t.Fatal(err)
	}
	value := resourceReleaseSnapshot{Lease: *lease}
	if err := s.db.QueryRow(`SELECT fencing_epoch,state,current_lease_id,reconciliation_evidence,updated_at
FROM resource_v2_authority WHERE resource_id=?`, lease.ResourceID).Scan(&value.Epoch, &value.State, &value.Current, &value.Evidence, &value.AuthorityUpdatedAt); err != nil {
		t.Fatal(err)
	}
	err = s.db.QueryRow(`SELECT value,digest,writer_lease_id,writer_epoch,updated_at
FROM resource_v2_managed_blobs WHERE resource_id=?`, lease.ResourceID).Scan(&value.Body, &value.Digest, &value.WriterID, &value.WriterEpoch, &value.BlobUpdatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return value
}

func TestResourceLeaseReleaseRetainsFenceAndRejectsOldPublication(t *testing.T) {
	f, scope, first := resourceReleaseFixture(t, "managed_blob/release-result/write", false)
	before := snapshotResourceRelease(t, f.store, first.ID)
	released, err := f.store.ReleaseResourceLeaseForActor(scope, first.ID, first.FencingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	after := snapshotResourceRelease(t, f.store, first.ID)
	if released.State != LeaseReleased || after.State != ResourceAvailable || after.Current != "" || after.Epoch != before.Epoch || released.ExpiresAt != before.Lease.ExpiresAt {
		t.Fatalf("release changed epoch/expiry or failed to clear authority: %+v", after)
	}
	if !reflect.DeepEqual(after.Body, before.Body) || after.Digest != before.Digest || after.WriterID != before.WriterID || after.WriterEpoch != before.WriterEpoch || after.BlobUpdatedAt != before.BlobUpdatedAt {
		t.Fatal("release mutated the committed blob or its provenance")
	}
	if retry, err := f.store.ReleaseResourceLeaseForActor(scope, first.ID, first.FencingEpoch); err != nil || !reflect.DeepEqual(retry, released) {
		t.Fatalf("exact release retry: %+v %v", retry, err)
	}
	if got := snapshotResourceRelease(t, f.store, first.ID); !reflect.DeepEqual(got, after) {
		t.Fatal("release retry changed stored state")
	}
	if _, err := f.store.WriteManagedBlobForActor(scope, first.ID, first.FencingEpoch, []byte("stale")); !errors.Is(err, ErrResourceLeaseExpired) && !errors.Is(err, ErrResourceStaleEpoch) {
		t.Fatalf("released lease published: %v", err)
	}
	second, err := f.store.AcquireResourceLease(ResourceLeaseRequest{ResourceID: first.ResourceID, GroupID: scope.GroupID, TaskID: first.HolderTaskID, PrincipalID: scope.PrincipalID})
	if err != nil || second.FencingEpoch != first.FencingEpoch+1 || second.ID == first.ID {
		t.Fatalf("next acquisition did not increment fence: %+v %v", second, err)
	}
	newOwner := snapshotResourceRelease(t, f.store, second.ID)
	if _, err := f.store.ReleaseResourceLeaseForActor(scope, first.ID, first.FencingEpoch); !errors.Is(err, ErrResourceStaleEpoch) {
		t.Fatalf("old release retry after reacquisition: %v", err)
	}
	if got := snapshotResourceRelease(t, f.store, second.ID); !reflect.DeepEqual(got, newOwner) {
		t.Fatal("old release changed new authority")
	}
	if _, err := f.store.WriteManagedBlobForActor(scope, first.ID, first.FencingEpoch, []byte("stale")); !errors.Is(err, ErrResourceLeaseExpired) && !errors.Is(err, ErrResourceStaleEpoch) {
		t.Fatalf("old lease published after reacquisition: %v", err)
	}
	if _, err := f.store.WriteManagedBlobForActor(scope, second.ID, second.FencingEpoch, []byte("synthetic successor blob")); err != nil {
		t.Fatal(err)
	}
}

func TestResourceLeaseReleaseRefusesUnconfirmedOrInconsistentResource(t *testing.T) {
	cases := []struct {
		name, resource, mutation string
		want                     error
	}{
		{"GPU advisory", "machine/synthetic-gpu/gpu/0", "", ErrResourceReconciliation},
		{"workspace advisory", "workspace/synthetic-workspace/write", "", ErrResourceReconciliation},
		{"expired", "managed_blob/expired/write", "UPDATE resource_v2_leases SET expires_at='2000-01-01T00:00:00Z'", ErrResourceReconciliation},
		{"invalid expiry", "managed_blob/invalid-expiry/write", "UPDATE resource_v2_leases SET expires_at='unparseable'", ErrResourceReconciliation},
		{"uncertain lease", "managed_blob/uncertain/write", "UPDATE resource_v2_leases SET state='RECONCILIATION_REQUIRED'", ErrResourceReconciliation},
		{"quarantined authority", "managed_blob/quarantine/write", "UPDATE resource_v2_authority SET state='RECONCILIATION_REQUIRED'", ErrResourceReconciliation},
		{"enforcement mismatch", "managed_blob/label/write", "UPDATE resource_v2_leases SET enforcement='advisory'", ErrResourceReconciliation},
		{"mode mismatch", "managed_blob/mode/write", "UPDATE resource_v2_leases SET mode='shared'", ErrResourceReconciliation},
		{"authority epoch mismatch", "managed_blob/epoch/write", "UPDATE resource_v2_authority SET fencing_epoch=2", ErrResourceStaleEpoch},
		{"authority owner mismatch", "managed_blob/owner/write", "UPDATE resource_v2_authority SET current_lease_id='synthetic-foreign'", ErrResourceStaleEpoch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, scope, lease := resourceReleaseFixture(t, tc.resource, false)
			if tc.mutation != "" {
				if _, err := f.store.db.Exec(tc.mutation); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotResourceRelease(t, f.store, lease.ID)
			if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); !errors.Is(err, tc.want) {
				t.Fatalf("release refusal: %v want %v", err, tc.want)
			}
			if after := snapshotResourceRelease(t, f.store, lease.ID); !reflect.DeepEqual(before, after) {
				t.Fatal("refused release changed lease, authority or blob")
			}
		})
	}
}

func TestResourceLeaseReleaseRechecksNativeActorAcrossStoreHandles(t *testing.T) {
	for _, mutation := range []string{
		"UPDATE session_bindings SET epoch=epoch+1",
		"UPDATE session_bindings SET lease_owner='synthetic-foreign'",
		"UPDATE session_bindings SET lease_expires_at='2000-01-01T00:00:00Z'",
		"UPDATE memberships SET revision=revision+1",
		"UPDATE memberships SET grants_json='[]'",
		"UPDATE endpoint_group_memberships SET status='revoked'",
		"UPDATE groups SET state='ARCHIVED'",
		"UPDATE endpoint_network_memberships_v2 SET status='revoked'",
	} {
		t.Run(mutation, func(t *testing.T) {
			f, scope, lease := resourceReleaseFixture(t, "managed_blob/actor-fence/write", true)
			var path string
			if err := f.store.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
				t.Fatal(err)
			}
			other, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if _, err := other.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := snapshotResourceRelease(t, f.store, lease.ID)
			if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrNetworkPermission) {
				t.Fatalf("cached native actor survived revocation: %v", err)
			}
			if after := snapshotResourceRelease(t, f.store, lease.ID); !reflect.DeepEqual(before, after) {
				t.Fatal("stale actor changed resource state")
			}
		})
	}
}

func TestResourceLeaseReleaseGuardAlsoCoversIdempotentRetry(t *testing.T) {
	f, scope, lease := resourceReleaseFixture(t, "managed_blob/retry-fence/write", false)
	for name, invalid := range map[string]NativeActorScope{"missing identity": {}, "foreign principal": {PrincipalID: "synthetic-foreign"}, "foreign Group": {GroupID: "synthetic-foreign"}} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.store.ReleaseResourceLeaseForActor(invalid, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrNetworkPermission) {
				t.Fatalf("forged scope released resource: %v", err)
			}
		})
	}
	if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch+1); !errors.Is(err, ErrResourceStaleEpoch) {
		t.Fatalf("wrong epoch: %v", err)
	}
	if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); err != nil {
		t.Fatal(err)
	}
	// A historical expiry cannot turn a safe released retry into another release.
	if _, err := f.store.db.Exec(`UPDATE resource_v2_leases SET expires_at='2000-01-01T00:00:00Z' WHERE id=?`, lease.ID); err != nil {
		t.Fatal(err)
	}
	before := snapshotResourceRelease(t, f.store, lease.ID)
	if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); err != nil {
		t.Fatal(err)
	}
	if after := snapshotResourceRelease(t, f.store, lease.ID); !reflect.DeepEqual(before, after) {
		t.Fatal("historical expiry retry changed state")
	}
	if _, err := f.store.db.Exec(`UPDATE memberships SET grants_json='[]' WHERE id=?`, scope.MembershipID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked actor repeated released response: %v", err)
	}
}

func TestResourceLeaseReleaseRollsBackPartialAuthorityChange(t *testing.T) {
	f, scope, lease := resourceReleaseFixture(t, "managed_blob/rollback/write", false)
	if _, err := f.store.db.Exec(`CREATE TRIGGER synthetic_release_abort BEFORE UPDATE OF state ON resource_v2_leases
WHEN NEW.state='RELEASED' BEGIN SELECT RAISE(ABORT,'synthetic release second-write failure'); END`); err != nil {
		t.Fatal(err)
	}
	before := snapshotResourceRelease(t, f.store, lease.ID)
	if _, err := f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch); err == nil {
		t.Fatal("synthetic lease-update failure was ignored")
	}
	if after := snapshotResourceRelease(t, f.store, lease.ID); !reflect.DeepEqual(before, after) {
		t.Fatal("second-write error left the authority released")
	}
}

func TestResourceLeaseReleaseSerializesExecutorAndAcquireAcrossHandles(t *testing.T) {
	for _, action := range []string{"write", "acquire"} {
		t.Run(action, func(t *testing.T) {
			f, scope, lease := resourceReleaseFixture(t, "managed_blob/concurrent-release/write", false)
			var path string
			if err := f.store.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
				t.Fatal(err)
			}
			other, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			start := make(chan struct{})
			var wg sync.WaitGroup
			var releaseErr, concurrentErr error
			var next *ResourceLease
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, releaseErr = f.store.ReleaseResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch)
			}()
			go func() {
				defer wg.Done()
				<-start
				if action == "write" {
					_, concurrentErr = other.WriteManagedBlobForActor(scope, lease.ID, lease.FencingEpoch, []byte("synthetic concurrent old write"))
				} else {
					next, concurrentErr = other.AcquireResourceLease(ResourceLeaseRequest{ResourceID: lease.ResourceID, GroupID: scope.GroupID, TaskID: lease.HolderTaskID, PrincipalID: scope.PrincipalID})
				}
			}()
			close(start)
			wg.Wait()
			if releaseErr != nil {
				t.Fatal(releaseErr)
			}
			if action == "write" {
				if concurrentErr != nil && !errors.Is(concurrentErr, ErrResourceLeaseExpired) {
					t.Fatal(concurrentErr)
				}
			} else {
				if concurrentErr != nil && !errors.Is(concurrentErr, ErrResourceBusy) {
					t.Fatal(concurrentErr)
				}
				if next == nil {
					next, err = other.AcquireResourceLease(ResourceLeaseRequest{ResourceID: lease.ResourceID, GroupID: scope.GroupID, TaskID: lease.HolderTaskID, PrincipalID: scope.PrincipalID})
					if err != nil {
						t.Fatal(err)
					}
				}
				if next.FencingEpoch != lease.FencingEpoch+1 {
					t.Fatalf("successor epoch=%d", next.FencingEpoch)
				}
			}
			if _, err := other.WriteManagedBlobForActor(scope, lease.ID, lease.FencingEpoch, []byte("after release")); !errors.Is(err, ErrResourceLeaseExpired) {
				t.Fatalf("executor accepted publication after release boundary: %v", err)
			}
		})
	}
}
