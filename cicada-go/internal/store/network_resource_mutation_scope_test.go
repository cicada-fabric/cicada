package store

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestNetworkResourceMutationsRejectStaleNativeActorAcrossStores(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.store.CreateNetwork(Network{ID: "net_resource_mutation", HubID: hubID,
		OwnerID: f.ownerID, Name: "Synthetic resource mutation"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.store.GetGroup(f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.store.GetEndpointV2(f.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), network.ID,
		endpoint.PrincipalID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'resource actor',0,?,?)`, network.ID, endpoint.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.PrincipalID, group.ID)
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
	scope := NativeActorScope{PrincipalID: endpoint.PrincipalID, EndpointID: endpoint.ID,
		GroupID: group.ID, NetworkID: network.ID, MembershipID: membership.ID,
		MembershipRevision: membership.Revision, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
	task, err := f.store.CreateSharedTask(SharedTask{GroupID: group.ID,
		Objective: "network resource mutation", AcceptanceCriteria: "current actor fenced"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ClaimSharedTaskForActor(scope, task.ID, task.Revision,
		"claim-network-resource-mutation", 300)
	if err != nil {
		t.Fatalf("current mapped Network actor claim: %v", err)
	}
	lease, err := f.store.AcquireResourceLease(ResourceLeaseRequest{ResourceID: "managed_blob/network_resource/write",
		GroupID: group.ID, TaskID: task.ID, PrincipalID: scope.PrincipalID, TTLSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RenewResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch, 300); err != nil {
		t.Fatalf("current actor renew: %v", err)
	}
	first := []byte("authorized before revocation")
	if _, err := f.store.WriteManagedBlobForActor(scope, lease.ID, lease.FencingEpoch, first); err != nil {
		t.Fatalf("current actor write: %v", err)
	}
	var path string
	if err := f.store.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.LeaveEndpointNetwork(network.ID, endpoint.ID, 1); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"renew": func() error {
			_, err := f.store.RenewResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch, 300)
			return err
		},
		"quarantine": func() error {
			_, err := f.store.QuarantineResourceLeaseForActor(scope, lease.ID, lease.FencingEpoch)
			return err
		},
		"blob write": func() error {
			_, err := f.store.WriteManagedBlobForActor(scope, lease.ID, lease.FencingEpoch, []byte("denied after revocation"))
			return err
		},
	} {
		if err := run(); !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("stale actor %s: %v", name, err)
		}
	}
	current, err := f.store.GetResourceLease(lease.ID)
	if err != nil || current.State != LeaseActive {
		t.Fatalf("stale actor changed lease: %#v %v", current, err)
	}
	var body []byte
	if err := f.store.db.QueryRow(`SELECT value FROM resource_v2_managed_blobs WHERE resource_id=?`, lease.ResourceID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, first) {
		t.Fatalf("stale actor changed blob: %q", body)
	}
}
