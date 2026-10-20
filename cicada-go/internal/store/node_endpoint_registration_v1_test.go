package store

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

func endpointRPC(t *testing.T, s *Store, b *NodeControlKeyBinding, digest, op string, seq uint64) NodeControlRPCInput {
	t.Helper()
	rpc := recoveryStoreInput(b, digest, seq, NewID("synthetic-endpoint-op"))
	rpc.Operation = op
	if _, retry, err := s.BeginNodeControlRPC(rpc); err != nil || retry {
		t.Fatal("admit synthetic Endpoint operation", err)
	}
	return rpc
}

func endpointRegistration() nodewire.EndpointRegistration {
	return nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: "synthetic-original-thread", Name: "合成研究线程", Workspace: "/synthetic/private/project"}
}

func endpointStorePath(t *testing.T, s *Store) string {
	t.Helper()
	var seq int
	var name, path string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNodeEndpointRegistrationZeroRightsAndStableMetadata(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	in := endpointRegistration()
	rpc := endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 1)
	first, err := s.RegisterNodeEndpoint(rpc, in)
	if err != nil || first.Reused || first.Presence != "offline" {
		t.Fatal("zero registration", first, err)
	}
	ep, err := s.GetEndpointV2(first.EndpointID)
	if err != nil || ep.Owner != b.OwnerID || ep.MachineID != b.NodeID || ep.NativeSessionID != in.NativeSessionID || ep.BindingID != "" || ep.GroupID != "" {
		t.Fatal("original identity lost", err)
	}
	for _, query := range []string{
		`SELECT count(*) FROM memberships`, `SELECT count(*) FROM endpoint_group_memberships`,
		`SELECT count(*) FROM network_memberships_v2`, `SELECT count(*) FROM endpoint_network_memberships_v2`,
		`SELECT count(*) FROM session_bindings`, `SELECT count(*) FROM network_access_sessions_v2`,
		`SELECT count(*) FROM endpoint_key_candidates_v2`,
	} {
		var n int
		if err = s.db.QueryRow(query).Scan(&n); err != nil || n != 0 {
			t.Fatal("registration created authority", query, n, err)
		}
	}
	in.Name = "must not overwrite original"
	second, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 2), in)
	if err != nil || !second.Reused || second.EndpointID != first.EndpointID || second.Name != first.Name || second.StateDigest != first.StateDigest {
		t.Fatal("repeat changed metadata or identity", err)
	}
	in.Workspace = "/synthetic/other"
	if _, err = s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 3), in); !errors.Is(err, nodewire.ErrEndpointConflict) {
		t.Fatal("same SID changed workspace", err)
	}
	response := []byte("synthetic encrypted response fixture")
	if err = s.CompleteNodeControlRPC(NodeControlRPCCompletion{NodeControlRPCInput: rpc, ResponsePacket: response}); err != nil {
		t.Fatal(err)
	}
	path := endpointStorePath(t, s)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	receipt, retry, err := reopened.BeginNodeControlRPC(rpc)
	if err != nil || !retry || !bytes.Equal(receipt.ResponsePacket, response) {
		t.Fatal("restart lost exact receipt", err)
	}
	restored, err := reopened.GetEndpointV2(first.EndpointID)
	if err != nil || restored.NativeSessionID != ep.NativeSessionID || restored.PrincipalID != ep.PrincipalID || restored.Name != ep.Name || restored.Workspace != ep.Workspace {
		t.Fatal("restart replaced original identity", err)
	}
}

func TestNodeEndpointRegistrationCurrentAuthority(t *testing.T) {
	for _, mutation := range []struct{ name, sql string }{
		{"node credential", `UPDATE fabric_node_credentials SET status='revoked'`},
		{"owner binding", `UPDATE node_owner_bindings_v2 SET state='REVOKED'`},
		{"owner key", `UPDATE owner_approval_keys_v2 SET state='REVOKED'`},
		{"device", `UPDATE client_devices_v2 SET state='REVOKED'`},
		{"PQ key", `UPDATE node_control_key_bindings_v1 SET state='REVOKED'`},
		{"owner principal", `UPDATE principals SET status='revoked' WHERE kind='human'`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			s, b, digest := recoveryStoreFixture(t)
			rpc := endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 1)
			other, err := New(endpointStorePath(t, s))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if _, err = other.db.Exec(mutation.sql); err != nil {
				t.Fatal(err)
			}
			if _, err = s.RegisterNodeEndpoint(rpc, endpointRegistration()); err == nil {
				t.Fatal("admitted request bypassed committed revocation")
			}
			var n int
			if err = s.db.QueryRow(`SELECT count(*) FROM fabric_endpoints`).Scan(&n); err != nil || n != 0 {
				t.Fatal("denial left an Endpoint", n, err)
			}
		})
	}
}

func TestNodeEndpointRegistrationConcurrentSameSID(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	other, err := New(endpointStorePath(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	rpcs := []NodeControlRPCInput{endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 1), endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 2)}
	var wg sync.WaitGroup
	results := make([]*nodewire.EndpointRegistrationResult, 2)
	errs := make([]error, 2)
	for i, db := range []*Store{s, other} {
		wg.Add(1)
		go func(i int, db *Store) {
			defer wg.Done()
			results[i], errs[i] = db.RegisterNodeEndpoint(rpcs[i], endpointRegistration())
		}(i, db)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].EndpointID != results[1].EndpointID || results[0].Reused == results[1].Reused {
		t.Fatal("concurrent registration split identity", errs)
	}
}

func TestNodeEndpointLeaveCASAndNoRevival(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	in := endpointRegistration()
	first, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 1), in)
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := s.GetEndpointV2(first.EndpointID)
	group, err := s.CreateGroup(Group{Name: "synthetic authorized group", OwnerPrincipalID: b.OwnerID, TrustDomainID: b.OwnerID, State: GroupStateActive, ContextPolicy: "group_scoped", IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateMembership(Membership{PrincipalID: ep.PrincipalID, GroupID: group.ID, Role: "member", Status: "active", Grants: []string{"directory.read", "message.send"}}); err != nil {
		t.Fatal(err)
	}
	binding, err := s.CreateSessionBinding(SessionBinding{EndpointID: ep.ID, PrincipalID: ep.PrincipalID, GroupID: group.ID, NativeSessionID: in.NativeSessionID, NodeID: b.NodeID, WorkspaceID: in.Workspace, Status: SessionBindingStatusLeased, LeaseOwner: "synthetic-adapter", LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 2), in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE fabric_endpoints SET last_seen=?,updated_at=? WHERE id=?`, now(), now(), ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE session_bindings SET lease_expires_at=?,version=version+1 WHERE id=?`, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano), binding.ID); err != nil {
		t.Fatal(err)
	}
	afterHeartbeat, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 3), in)
	if err != nil || afterHeartbeat.StateDigest != before.StateDigest {
		t.Fatal("heartbeat invalidated authority digest", err)
	}
	if _, err = s.db.Exec(`UPDATE groups SET version=version+1,revision=revision+1 WHERE id=?`, group.ID); err != nil {
		t.Fatal(err)
	}
	leave := nodewire.EndpointLeave{Harness: in.Harness, NativeSessionID: in.NativeSessionID, StateDigest: before.StateDigest}
	if _, err = s.LeaveNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointLeaveOperation, 4), leave); !errors.Is(err, nodewire.ErrEndpointConflict) {
		t.Fatal("stale authorization review accepted", err)
	}
	current, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 5), in)
	if err != nil {
		t.Fatal(err)
	}
	leave.StateDigest = current.StateDigest
	left, err := s.LeaveNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointLeaveOperation, 6), leave)
	if err != nil || left.Presence != "left" {
		t.Fatal("leave", err)
	}
	if active, err := s.IsEndpointGroupActive(ep.ID, group.ID); err != nil || active {
		t.Fatal("leave retained Group", err)
	}
	old, err := s.GetSessionBinding(binding.ID)
	if err != nil || old.Status != "revoked" || old.Epoch != binding.Epoch+1 {
		t.Fatal("leave retained original lease", err)
	}
	repeated, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 7), in)
	if err != nil || repeated.Presence != "left" || repeated.EndpointID != first.EndpointID || repeated.StateDigest != left.StateDigest {
		t.Fatal("registration revived withdrawn identity", err)
	}
	// Even redispatching an old processing request cannot act on a later scope.
	if _, err = s.LeaveNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointLeaveOperation, 8), leave); !errors.Is(err, nodewire.ErrEndpointConflict) {
		t.Fatal("old leave replay changed later state", err)
	}
}

func TestNodeEndpointNetworkOnlyLeaveUsesCurrentEnrollmentVersion(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	in := endpointRegistration()
	registered, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 1), in)
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := s.GetEndpointV2(registered.EndpointID)
	hub, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := s.CreateNetwork(Network{HubID: hub, OwnerID: b.OwnerID, Name: "synthetic network-only"})
	if err != nil {
		t.Fatal(err)
	}
	stamp := now()
	// Synthetic admission fixture only; production enrollment retains the
	// original invitation and genuine per-native-session Owner proof path.
	if _, err = s.db.Exec(`INSERT INTO network_memberships_v2(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'["directory.discover"]','active','',1,?,?)`, NewID("netmem"), network.ID, ep.PrincipalID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO endpoint_network_memberships_v2(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'synthetic alias',0,?,?)`, network.ID, ep.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	access := NewID("synthetic-access")
	if _, err = s.db.Exec(`INSERT INTO network_access_sessions_v2(id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,lease_expires_at,status,credential_hash,owner_key_id,created_at,updated_at)
VALUES(?,?,?,?,?,?,1,'synthetic-lease',?,'active','synthetic credential hash',?,?,?)`, access, network.ID, ep.ID, ep.PrincipalID, in.NativeSessionID, b.NodeID, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), b.OwnerKeyID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	current, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 2), in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE networks_v2 SET version=version+1 WHERE id=?`, network.ID); err != nil {
		t.Fatal(err)
	}
	leave := nodewire.EndpointLeave{Harness: in.Harness, NativeSessionID: in.NativeSessionID, StateDigest: current.StateDigest}
	if _, err = s.LeaveNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointLeaveOperation, 3), leave); !errors.Is(err, nodewire.ErrEndpointConflict) {
		t.Fatal("old Network review withdrew newer authority", err)
	}
	current, err = s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 4), in)
	if err != nil {
		t.Fatal(err)
	}
	leave.StateDigest = current.StateDigest
	if _, err = s.LeaveNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointLeaveOperation, 5), leave); err != nil {
		t.Fatal("Network-only leave required a fake Group binding", err)
	}
	enrollment, err := s.GetEndpointNetworkMembership(network.ID, ep.ID)
	if err != nil || enrollment.Status != "revoked" || enrollment.Revision != 2 {
		t.Fatal("Network edge not revoked", err)
	}
	session, err := s.GetNetworkAccessSessionByID(access)
	if err != nil || session.Status != "revoked" || session.Epoch != 2 || session.LeaseOwner != "" || session.LeaseExpiresAt != "" {
		t.Fatal("Network access not fenced", err)
	}
	member, err := s.GetNetworkMembership(network.ID, ep.PrincipalID)
	if err != nil || member.Status != "active" || member.Revision != 1 {
		t.Fatal("leave changed Principal Network membership", err)
	}
}
