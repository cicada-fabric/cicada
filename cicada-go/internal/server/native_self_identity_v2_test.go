package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

type nativeSelfHTTPFixture struct {
	service      *fabric.Service
	state        *store.Store
	group        store.Group
	joined, peer *fabric.JoinResult
	nodeBinding  *store.NodeDeviceBinding
	hub          *httptest.Server
	identity     *e2ee.Identity
	proof        []byte
}

// The fixture uses real Store, bound Node credentials and an ACTIVE Network.
// Native session locators and all keys are synthetic, with no Runtime invocation.
func newNativeSelfHTTPFixture(t *testing.T) *nativeSelfHTTPFixture {
	t.Helper()
	service, state, group := newRelayNodeTestService(t)
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "node_synthetic_self"
	nodeBinding := bindRelayNodeTestCredential(t, state, nodeID, digest)
	join := func(native string) *fabric.JoinResult {
		t.Helper()
		result, err := service.JoinForNodeCredential(token, fabric.JoinInput{
			GroupID: group.ID, Harness: "codex", NativeSessionID: native, Workspace: "/synthetic/self"})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	joined, peer := join("native_synthetic_self"), join("native_synthetic_peer")
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.RegisterOwnerApprovalKeyLocal("owner", ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := state.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := state.CreateNetwork(store.Network{ID: "net_synthetic_self", HubID: hubID, OwnerID: "owner", Name: "synthetic self"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic explicit mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := state.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []*fabric.JoinResult{joined, peer} {
		invite := "synthetic-self-invite-" + endpoint.Endpoint.NativeSessionID
		grants := []string{"directory.discover", "directory.publish"}
		if err := state.IssueNetworkInvitation(network.ID, "owner", "owner", invite,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := ownerKey.SignOwnerNetworkJoinGrant("owner", hubID, network.ID, nodeID,
			endpoint.Endpoint.NativeSessionID, store.NetworkInvitationDigest(invite), ownerKey.Public().ID,
			grants, true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.JoinNetworkForNodeCredential(token, fabric.NetworkJoinInput{
			NetworkID: network.ID, InvitationToken: invite, OwnerJoinProof: string(proof), Harness: "codex",
			NativeSessionID: endpoint.Endpoint.NativeSessionID, EndpointName: endpoint.Endpoint.Name}); err != nil {
			t.Fatal(err)
		}
		member, err := state.GetMembershipByPrincipalGroup(endpoint.Endpoint.PrincipalID, group.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.UpdateMembershipAuthorization(member.ID, []string{"member"}, []string{},
			map[string]any{}, member.Version); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(joined.Endpoint.ID, joined.Endpoint.PrincipalID,
		nodeID, joined.BindingID, joined.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	hub := httptest.NewServer(NewFabricHandler(service, "synthetic-manager-token"))
	t.Cleanup(hub.Close)
	return &nativeSelfHTTPFixture{service: service, state: state, group: group, joined: joined,
		peer: peer, nodeBinding: nodeBinding, hub: hub, identity: identity, proof: proof}
}

func (f *nativeSelfHTTPFixture) call(t *testing.T, method, path, token, group string, body any) (int, []byte) {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, f.hub.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "CicadaSession "+token)
	}
	if group != "" {
		request.Header.Set("Cicada-Group-Scope", group)
	}
	response, err := f.hub.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

func TestNativeSelfHTTPZeroGrantMemberAndMonitorHaveOnlySelfAccess(t *testing.T) {
	for _, role := range []string{"member", "monitor"} {
		t.Run(role, func(t *testing.T) {
			f := newNativeSelfHTTPFixture(t)
			before, err := f.state.GetMembershipByPrincipalGroup(f.joined.Endpoint.PrincipalID, f.group.ID)
			if err != nil {
				t.Fatal(err)
			}
			if role == "monitor" {
				before, err = f.state.UpdateMembershipAuthorization(before.ID, []string{"monitor"},
					[]string{"federation.represent", "task.read", "task.verify", "artifact.share"}, map[string]any{}, before.Version)
				if err != nil {
					t.Fatal(err)
				}
			}
			code, data := f.call(t, http.MethodGet, "/v2/fabric/whoami", f.joined.SessionToken, f.group.ID, nil)
			var card fabric.NetworkCard
			if code != http.StatusOK || json.Unmarshal(data, &card) != nil || card.EndpointID != f.joined.Endpoint.ID ||
				card.NativeSessionID != f.joined.Endpoint.NativeSessionID || card.BindingID != f.joined.BindingID || card.BindingEpoch != f.joined.BindingEpoch ||
				bytes.Contains(data, []byte(f.peer.Endpoint.NativeSessionID)) {
				t.Fatalf("own identity status=%d", code)
			}
			body := map[string]any{"attestation": json.RawMessage(f.proof)}
			code, data = f.call(t, http.MethodPost, "/v2/fabric/endpoint-keys", f.joined.SessionToken, f.group.ID, body)
			var candidate store.EndpointKeyCandidate
			if code != http.StatusOK || json.Unmarshal(data, &candidate) != nil || candidate.KeyID != f.identity.Public().ID ||
				candidate.State != store.EndpointKeyCandidateStateCandidate || strings.Contains(string(data), "private") {
				t.Fatalf("own candidate publish status=%d", code)
			}
			for _, path := range []string{"/v2/fabric/members", "/v2/fabric/list", "/v2/fabric/endpoint-keys/" + f.peer.Endpoint.ID} {
				if code, _ := f.call(t, http.MethodGet, path, f.joined.SessionToken, f.group.ID, nil); code != http.StatusForbidden {
					t.Fatalf("peer read %s status=%d", path, code)
				}
			}
			if code, _ := f.call(t, http.MethodPost, "/v2/fabric/resolve", f.joined.SessionToken, f.group.ID,
				map[string]any{"query": f.peer.Endpoint.ID}); code != http.StatusForbidden {
				t.Fatalf("peer resolve status=%d", code)
			}
			code, data = f.call(t, http.MethodGet, "/v2/fabric/endpoint-keys/"+f.joined.Endpoint.ID, f.joined.SessionToken, f.group.ID, nil)
			if code != http.StatusOK || json.Unmarshal(data, &candidate) != nil || candidate.EndpointID != f.joined.Endpoint.ID {
				t.Fatalf("own candidate read status=%d", code)
			}
			if code, _ := f.call(t, http.MethodGet, "/v2/fabric/whoami", f.joined.SessionToken, "grp_other", nil); code != http.StatusForbidden {
				t.Fatalf("wrong Group self status=%d", code)
			}
			if code, _ := f.call(t, http.MethodPost, "/v2/fabric/endpoint-keys", f.peer.SessionToken, f.group.ID, body); code == http.StatusOK {
				t.Fatal("other caller published original caller's proof")
			}
			if code, _ := f.call(t, http.MethodPost, "/v2/fabric/endpoint-keys", "", f.group.ID, body); code != http.StatusUnauthorized {
				t.Fatalf("missing caller status=%d", code)
			}
			if code, _ := f.call(t, http.MethodPost, "/v2/fabric/endpoint-keys", f.joined.SessionToken, f.group.ID,
				map[string]any{"attestation": json.RawMessage(f.proof), "endpoint_id": f.peer.Endpoint.ID}); code != http.StatusBadRequest {
				t.Fatalf("body-supplied caller status=%d", code)
			}
			otherKey, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			otherProof, err := otherKey.SignEndpointKeyAttestation(f.joined.Endpoint.ID, f.joined.Endpoint.PrincipalID,
				f.nodeBinding.NodeID, f.joined.BindingID, f.joined.BindingEpoch)
			if err != nil {
				t.Fatal(err)
			}
			if code, _ := f.call(t, http.MethodPost, "/v2/fabric/endpoint-keys", f.joined.SessionToken, f.group.ID,
				map[string]any{"attestation": json.RawMessage(otherProof)}); code != http.StatusConflict {
				t.Fatalf("key substitution status=%d", code)
			}
			after, err := f.state.GetMembership(before.ID)
			if err != nil || after.Version != before.Version || after.Revision != before.Revision || after.Role != before.Role ||
				strings.Join(after.Grants, ",") != strings.Join(before.Grants, ",") {
				t.Fatal("self operations changed membership grants/version/role")
			}
			actor, err := f.service.AuthenticateForGroup(f.joined.SessionToken, f.group.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, grant := range []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive", "message.broadcast", "space.read", "space.write", "resource.execute"} {
				if err := f.service.Authorize(actor, grant); err == nil {
					t.Fatalf("self operations enabled %s", grant)
				}
			}
			if _, err := f.state.GetGroupEndpointKeyGrant("owner", f.group.ID, f.joined.Endpoint.ID); err == nil {
				t.Fatal("self candidate became an Owner key grant")
			}
		})
	}
}

func TestNativeSelfHTTPRechecksNodeRevocationAndBindingEpoch(t *testing.T) {
	for _, revoke := range []string{"node", "membership", "epoch"} {
		t.Run(revoke, func(t *testing.T) {
			f := newNativeSelfHTTPFixture(t)
			actor, err := f.service.AuthenticateForGroup(f.joined.SessionToken, f.group.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.RegisterEndpointKeyCandidate(actor, f.proof); err != nil {
				t.Fatal(err)
			}
			switch revoke {
			case "node":
				_, err = f.state.RevokeNodeDeviceBinding("owner", f.nodeBinding.ID, f.nodeBinding.Version)
			case "membership":
				_, err = f.state.RevokeMembership(actor.MembershipID, "synthetic revoke")
			case "epoch":
				_, err = f.state.RotateSessionBindingCredential(actor.BindingID, actor.BindingEpoch,
					fabric.HashSessionCredential("synthetic-replacement-session"), actor.LeaseOwner,
					time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
			}
			if err != nil {
				t.Fatal(err)
			}
			for name, run := range map[string]func() error{
				"identity": func() error { _, err := f.service.WhoAmI(actor); return err },
				"read":     func() error { _, err := f.service.EndpointKeyCandidate(actor, actor.EndpointID); return err },
				"publish":  func() error { _, err := f.service.RegisterEndpointKeyCandidate(actor, f.proof); return err },
			} {
				if err := run(); err == nil {
					t.Fatalf("cached actor %s survived %s revoke", name, revoke)
				}
			}
			for _, path := range []string{"/v2/fabric/whoami", "/v2/fabric/endpoint-keys/" + actor.EndpointID} {
				if code, _ := f.call(t, http.MethodGet, path, f.joined.SessionToken, f.group.ID, nil); code == http.StatusOK {
					t.Fatalf("HTTP self read survived %s revoke", revoke)
				}
			}
			if code, _ := f.call(t, http.MethodPost, "/v2/fabric/endpoint-keys", f.joined.SessionToken, f.group.ID,
				map[string]any{"attestation": json.RawMessage(f.proof)}); code == http.StatusOK {
				t.Fatalf("HTTP publish survived %s revoke", revoke)
			}
		})
	}
}
