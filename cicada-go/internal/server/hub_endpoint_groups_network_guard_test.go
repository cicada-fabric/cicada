package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestEndpointGroupsHTTPNetworkActorCannotBorrowPrincipalRightsOrLeaveRegistration(t *testing.T) {
	f := endpointGroupsRealHTTP(t)
	a := f.a
	m := f.joins[0].Member
	var description wire.EndpointGroupsNodeDescribeResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: m.EndpointID, NetworkID: f.domain.Policy.NetworkID}, &description)
	service := a.f.http.Config.Handler.(*hubNodesHandler).base.fabricService
	full := NewFabricHandler(service, "").(*Handler)
	if full.control != nil {
		t.Fatal("full Fabric test depends on Control")
	}
	listener := httptest.NewServer(full)
	defer listener.Close()
	base := listener.URL + "/v2/fabric/networks/" + url.PathEscape(f.domain.Policy.NetworkID)
	request := func(method, path string, body []byte) int {
		t.Helper()
		q, err := http.NewRequest(method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		q.Header.Set("Authorization", "Cicada-Network-Session "+f.joins[0].SessionToken)
		q.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(q)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if status := request(http.MethodGet, "/whoami", nil); status != http.StatusOK {
		t.Fatal("original shared token did not establish actual Network self identity", status)
	}
	db, err := sql.Open("sqlite", a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// An actual wider Principal row cannot enlarge this Endpoint's zero Network
	// business authority; the original access token and all identity stay fixed.
	grants, _ := json.Marshal([]string{"directory.discover", "direct.send", "direct.receive", "network.admin.invite", "task.offer.publish"})
	if _, err = db.Exec(`UPDATE network_memberships_v2 SET grants_json=?,revision=revision+1 WHERE network_id=? AND principal_id=?`, string(grants), f.domain.Policy.NetworkID, m.PrincipalID); err != nil {
		t.Fatal(err)
	}
	t.Run("wide_principal_directory", func(t *testing.T) {
		if status := request(http.MethodGet, "/directory", nil); status != http.StatusForbidden {
			t.Fatal("Network Actor borrowed wider Principal directory authority", status)
		}
	})
	t.Run("wide_principal_store", func(t *testing.T) {
		allowed, err := a.f.db.NetworkAllows(f.domain.Policy.NetworkID, m.PrincipalID, m.EndpointID, "direct.send")
		if allowed || err != nil && !errors.Is(err, store.ErrNetworkPermission) {
			t.Fatal("NetworkAllows enlarged original Endpoint authority", allowed, err)
		}
		actor, err := service.AuthenticateForNetwork(f.joins[0].SessionToken, f.domain.Policy.NetworkID)
		if err != nil {
			t.Fatal("self identity must remain available", err)
		}
		scope := store.NetworkAccessScope{NetworkID: actor.NetworkID, PrincipalID: actor.PrincipalID, EndpointID: actor.EndpointID, AccessSessionID: actor.BindingID, AccessEpoch: actor.BindingEpoch, LeaseOwner: actor.LeaseOwner, MembershipID: actor.MembershipID, MembershipRevision: actor.MembershipRevision, EndpointMembershipRevision: actor.EndpointMembershipRevision}
		if _, err = a.f.db.ListNetworkDirectory(scope, 1); !errors.Is(err, store.ErrNetworkPermission) {
			t.Fatal("transactional Network Actor borrowed wide Principal rights", err)
		}
	})
	t.Run("global_network_leave", func(t *testing.T) {
		if status := request(http.MethodPost, "/leave", []byte(`{}`)); status != http.StatusForbidden {
			t.Fatal("original token globally withdrew registration Network/access", status)
		}
	})
	enrollment, err := a.f.db.GetEndpointNetworkMembership(f.domain.Policy.NetworkID, m.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.f.db.LeaveEndpointNetwork(f.domain.Policy.NetworkID, m.EndpointID, enrollment.Revision); !errors.Is(err, store.ErrNetworkPermission) {
		t.Fatal("direct Store Network Leave bypassed managed source", err)
	}
	if status := request(http.MethodGet, "/whoami", nil); status != http.StatusOK {
		t.Fatal("denied operations destroyed original zero-right registration", status)
	}
}
