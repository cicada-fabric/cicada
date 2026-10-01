package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func insertClientNetworkDirectoryEndpoint(t *testing.T, s *Store, networkID,
	endpointID, ownerID, alias string, discoverable bool, status string, withSession bool) {
	t.Helper()
	stamp := now()
	principalID := "principal_" + endpointID
	if _, err := s.db.Exec(`INSERT INTO principals
(id,kind,owner_id,trust_domain_id,name,display_name,status,version,created_at,updated_at)
VALUES(?,'agent',?,? ,?,?,'active',1,?,?)`, principalID, ownerID, ownerID,
		endpointID, "Thread "+endpointID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	endpointStatus := status
	if _, err := s.db.Exec(`INSERT INTO fabric_endpoints
(id,name,role,harness,native_session_id,machine_id,workspace,status,owner,
	principal_id,group_id,binding_id,migration_state,joined_at,last_seen,created_at,updated_at)
VALUES(?,?,'thread','codex',?,?,?,?,?,?,'','','',?,?,?,?)`, endpointID, alias,
		"native-private-"+endpointID, "node-private-"+endpointID, "workspace-private-"+endpointID,
		endpointStatus, ownerID, principalID, stamp, stamp, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'["directory.publish"]','active','',1,?,?)`, NewID("netmem"),
		networkID, principalID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	discoverableValue := 0
	if discoverable {
		discoverableValue = 1
	}
	if _, err := s.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,?,?,?,?)`, networkID, endpointID, alias,
		discoverableValue, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if withSession {
		if _, err := s.db.Exec(`INSERT INTO network_access_sessions_v2
(id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,
	lease_expires_at,status,credential_hash,owner_key_id,created_at,updated_at)
VALUES(?,?,?,?,?,?,1,?,?,'active',?,?,?,?)`, "binding_"+endpointID, networkID,
			endpointID, principalID, "native-private-"+endpointID,
			"node-private-"+endpointID, "lease_"+endpointID,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			"credential_"+endpointID, "synthetic_owner_key", stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientOwnerNetworkEndpointDirectoryIsOptInAndCursorBounded(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	defer f.store.Close()
	stamp := now()
	if _, err := f.store.db.Exec(`INSERT INTO principals
(id,kind,owner_id,trust_domain_id,name,display_name,status,version,created_at,updated_at)
VALUES('owner_b','human','owner_b','owner_b','owner-b','Synthetic Owner B','active',1,?,?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateNetwork(Network{ID: "net_foreign_owner", HubID: f.hubID,
		Name: "Foreign owner network", OwnerID: "owner_b", State: NetworkStateActive}); err != nil {
		t.Fatal(err)
	}
	insertClientNetworkDirectoryEndpoint(t, f.store, "net_a", "ep_card_a", "owner_b",
		"shared-agent-a", true, "online", true)
	insertClientNetworkDirectoryEndpoint(t, f.store, "net_a", "ep_card_b", "owner_b",
		"shared-agent-b", true, "offline", false)
	insertClientNetworkDirectoryEndpoint(t, f.store, "net_a", "ep_card_hidden", "owner_b",
		"private-agent", false, "online", true)
	requestID := f.request(t, ClientOwnerNetworkEndpointDirectoryOperation)
	first, cursor, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", "", 1)
	if err != nil || len(first) != 1 || first[0].EndpointID != "ep_card_a" || cursor != "ep_card_a" ||
		first[0].Alias != "shared-agent-a" ||
		first[0].Presence != "ACCESS_RECENT" {
		t.Fatalf("first opted-in card page: %+v cursor=%q err=%v", first, cursor, err)
	}
	second, next, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", cursor, 1)
	if err != nil || len(second) != 1 || second[0].EndpointID != "ep_card_b" ||
		second[0].Presence != "UNKNOWN" || next != "" {
		t.Fatalf("second card page: %+v cursor=%q err=%v", second, next, err)
	}
	encoded, err := json.Marshal(first[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{"Synthetic Owner B", "owner-b", "native-private-",
		"node-private-", "workspace-private-", "credential_", "synthetic_owner_key"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("owner card exposed private Node/session data %q: %s", privateValue, encoded)
		}
	}
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_b", "net_a", "", 10); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("another Owner used the accepted Client request: %v", err)
	}
	wrongOperationRequest := f.request(t, "topology.snapshot")
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		wrongOperationRequest, "owner_a", "net_a", "", 10); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("borrowed an accepted request for another operation: %v", err)
	}
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_b", "", 10); err != nil {
		t.Fatalf("Network Owner could not read own Network: %v", err)
	}
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_foreign_owner", "", 10); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("different Network Owner became visible: %v", err)
	}
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", "", clientNetworkEndpointDirectoryPageMax+1); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("unbounded page limit accepted: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET expires_at=?
WHERE network_id='net_a' AND principal_id='principal_ep_card_b'`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	pageAfterMembershipExpiry, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", cursor, 1)
	if err != nil || len(pageAfterMembershipExpiry) != 0 {
		t.Fatalf("expired Network membership remained in owner directory: %+v %v", pageAfterMembershipExpiry, err)
	}
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET expires_at=''
WHERE network_id='net_a' AND principal_id='principal_ep_card_b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='revoked'
WHERE network_id='net_a' AND endpoint_id='ep_card_b'`); err != nil {
		t.Fatal(err)
	}
	pageAfterRevocation, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", cursor, 1)
	if err != nil || len(pageAfterRevocation) != 0 {
		t.Fatalf("revoked enrollment remained in owner directory: %+v %v", pageAfterRevocation, err)
	}
	if _, err := f.store.db.Exec(`UPDATE networks_v2 SET state='PAUSED' WHERE id='net_a'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", "", 10); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("paused Network remained in owner directory: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE networks_v2 SET state='ACTIVE',hub_id='hub_foreign' WHERE id='net_a'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.ListClientOwnerNetworkEndpointCards(
		requestID, "owner_a", "net_a", "", 10); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("foreign-Hub Network was projected: %v", err)
	}
}
