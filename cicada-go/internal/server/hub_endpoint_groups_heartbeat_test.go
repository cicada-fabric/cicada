package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestEndpointGroupsHTTPHeartbeatKeepsOnlyOriginalRegistrationWithDefaultDenied(t *testing.T) {
	f := endpointGroupsRealHTTP(t)
	a := f.a
	q, p, _, r := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic warm manual Group"})
	_, _, _, created := f.apply(t, q, p, r, nil)
	group := created.Operation.Target.GroupID
	key := f.activate(t, group, 0)
	anchor := key.Registration
	// Withdraw the original binding's G1 while G2 stays independently active.
	q, p, _, r = f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: f.domain.Policy.GroupID, EndpointID: anchor.Registration.EndpointID})
	defaultHead := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	f.apply(t, q, p, r, &defaultHead)
	service := a.f.http.Config.Handler.(*hubNodesHandler).base.fabricService
	if _, err := service.AuthenticateForGroup(f.joins[0].SessionToken, f.domain.Policy.GroupID); !errors.Is(err, fabric.ErrPermissionDenied) {
		t.Fatal("default relation was not denied", err)
	}
	if _, err := service.AuthenticateForGroup(f.joins[0].SessionToken, group); err != nil {
		t.Fatal("G1 denial blocked still-authorized G2", err)
	}
	db, err := sql.Open("sqlite", a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var credential string
	var operations int
	if err = db.QueryRow(`SELECT credential_hash FROM session_bindings WHERE id=?`, anchor.BindingID).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_node_operations_v1`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		before := time.Now().UTC()
		raw := a.pairHTTP(t, http.MethodPost, "/v2/fabric/heartbeat", "CicadaSession "+f.joins[0].SessionToken, "", nil, http.StatusOK)
		var actor fabric.Actor
		if json.Unmarshal(raw, &actor) != nil || actor.EndpointID != anchor.Registration.EndpointID || actor.PrincipalID != anchor.Registration.PrincipalID || actor.BindingID != anchor.BindingID || actor.BindingEpoch != anchor.BindingEpoch || actor.LeaseOwner != anchor.LeaseOwner || actor.GroupID != "" || actor.MembershipID != "" || actor.MembershipRevision != 0 {
			t.Fatal("registration heartbeat changed identity or returned Group authority")
		}
		end, err := time.Parse(time.RFC3339Nano, actor.LeaseExpiresAt)
		if err != nil || end.Before(before.Add(5*time.Minute)) || end.After(time.Now().UTC().Add(5*time.Minute)) {
			t.Fatal("registration heartbeat did not preserve the bounded warm lease", err)
		}
		if actor.Validate() == nil || !errors.Is(service.Authorize(actor, "directory.read"), fabric.ErrPermissionDenied) {
			t.Fatal("zero-Group heartbeat became a business actor")
		}
		var retained string
		var count int
		if err = db.QueryRow(`SELECT credential_hash FROM session_bindings WHERE id=? AND epoch=?`, anchor.BindingID, anchor.BindingEpoch).Scan(&retained); err != nil || retained != credential {
			t.Fatal("warm heartbeat replaced the original credential", err)
		}
		if err = db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_node_operations_v1`).Scan(&count); err != nil || count != operations {
			t.Fatal("warm heartbeat created a permanent Node mutation receipt", err)
		}
	}
	check()
	// Last Group removal also preserves the same zero-business registration.
	q, p, _, r = f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: anchor.Registration.EndpointID})
	f.apply(t, q, p, r, &key.OwnerControl)
	check()
	var described wire.EndpointGroupsNodeDescribeResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: anchor.Registration.EndpointID, NetworkID: anchor.NetworkID}, &described)
	if len(described.Authorities) != 0 || described.Registration.State != "REGISTERED" {
		t.Fatal("heartbeat revived removed Group rights or lost registration")
	}
	// Token possession alone cannot resume a cold lease. It takes the original
	// currently approved Node key and exact signed renewal.
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err = db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, past, anchor.BindingID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=? WHERE id=?`, past, anchor.NetworkAccessBindingID); err != nil {
		t.Fatal(err)
	}
	a.pairHTTP(t, http.MethodPost, "/v2/fabric/heartbeat", "CicadaSession "+f.joins[0].SessionToken, "", nil, http.StatusUnauthorized)
	var renewed wire.EndpointGroupsNodeRenewResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeRenew, wire.EndpointGroupsNodeRenew{EndpointID: anchor.Registration.EndpointID, RegistrationDigest: anchor.RegistrationDigest, ExpectedBindingID: anchor.BindingID, ExpectedBindingEpoch: anchor.BindingEpoch}, &renewed)
	if err = db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_node_operations_v1`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	check()
}
