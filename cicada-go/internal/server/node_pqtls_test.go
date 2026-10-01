package server

import (
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// Synthetic context tests verify request Guard only. Real TLS is separately
// exercised by tagged product runtime tests; these do not prove a handshake.
type syntheticPQStateConn struct {
	net.Conn
	state pqtls.State
}

func TestNetworkSessionTransportDerivesNodeAcrossIndependentAccessEpochs(t *testing.T) {
	service, db, _ := newRelayNodeTestService(t)
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	binding := bindRelayNodeTestCredential(t, db, "network-node", digest)
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterOwnerApprovalKeyLocal("owner", ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	network, err := db.CreateNetwork(store.Network{ID: "synthetic-pq-network", HubID: binding.HubID, Name: "synthetic PQ authority", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	invite := "synthetic-pq-network-invitation-test-only"
	grants := []string{"directory.discover", "directory.publish"}
	if err := db.IssueNetworkInvitation(network.ID, "owner", "owner", invite, time.Now().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	proof, err := ownerKey.SignOwnerNetworkJoinGrant("owner", binding.HubID, network.ID, binding.NodeID, "native-network-pq", store.NetworkInvitationDigest(invite), ownerKey.Public().ID, grants, true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	joined, err := service.JoinNetworkForNodeCredential(token, fabric.NetworkJoinInput{NetworkID: network.ID, InvitationToken: invite, OwnerJoinProof: string(proof), Harness: "codex", NativeSessionID: "native-network-pq", EndpointName: "synthetic-network-pq"})
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	pin[0] = 0xcd
	identity := nodetransport.Identity{Kind: "node", HubID: binding.HubID, NodeID: binding.NodeID, TLSEpoch: 29, DNSName: "network-node.synthetic.invalid"}
	cfg := &nodetransport.Config{Peers: []nodetransport.Approval{{Identity: identity, PinKind: "certificate-sha256", PinSHA256: hex.EncodeToString(pin[:]), OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.ID, BindingVersion: binding.Version, CredentialVersion: binding.NodeCredentialVersion}}}
	state := pqtls.State{TLSVersion: "TLSv1.3", Group: "MLKEM768", CipherSuite: "TLS_AES_256_GCM_SHA384", PeerSignature: "ML-DSA-65", ALPN: "http/1.1", HostnameVerified: true, Peer: identity.TLSIdentity(), CertificateSHA256: pin}
	ctx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: state})
	handler := WithNodePQTransport(NewFabricHandler(service, ""), service, cfg, true)
	call := func(token string, stateCtx context.Context) int {
		r := httptest.NewRequest(http.MethodGet, "/v2/fabric/networks/"+network.ID+"/whoami", nil).WithContext(stateCtx)
		r.Header.Set("Authorization", "Cicada-Network-Session "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := call(joined.SessionToken, ctx); code != http.StatusOK {
		t.Fatalf("current Network session status %d", code)
	}
	renewed, err := service.RenewNetworkForNodeCredential(token, fabric.NetworkRenewInput{NetworkID: network.ID, EndpointID: joined.Endpoint.ID, Harness: "codex", NativeSessionID: "native-network-pq"})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.BindingEpoch == joined.BindingEpoch {
		t.Fatal("access epoch did not advance")
	}
	if code := call(renewed.SessionToken, ctx); code != http.StatusOK {
		t.Fatal("independent access epoch invalidated TLS identity")
	}
	state.Peer.NodeID = "different-node"
	foreignCtx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: state})
	if code := call(renewed.SessionToken, foreignCtx); code != http.StatusUnauthorized {
		t.Fatal("foreign certificate borrowed Network session")
	}
}

func (c syntheticPQStateConn) PQTLSState() pqtls.State { return c.state }

func TestStrictNodeTransportKeepsClientBootstrapAndBlocksOrdinaryPeerRoutes(t *testing.T) {
	service, _, _ := newRelayNodeTestService(t)
	inner := NewFabricHandler(service, "synthetic-manager-token")
	front := WithNodePQTransport(inner, service, nil, false)
	for _, path := range []string{"/v2/relay/nodes/node/events", "/v2/fabric/node/join", "/v2/fabric/join", "/v2/fabric/whoami", "/v2/fabric/node/networks/join", "/v2/fabric/networks/network/directory", "/v2/artifacts/a", "/v2/node/control/rpc", "/v2/node/control/key-upgrade"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("Authorization", "Bearer synthetic-manager-token")
			w := httptest.NewRecorder()
			front.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("unenforced ordinary route: %d", w.Code)
			}
		})
	}
	for _, path := range []string{"/healthz", "/v2/client/capabilities", "/v2/client/identity", "/v2/node/identity", "/v2/nodes/device-code", "/v2/node/device-code/pending/status"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			a, b := httptest.NewRecorder(), httptest.NewRecorder()
			inner.ServeHTTP(a, r)
			front.ServeHTTP(b, r)
			if a.Code != b.Code || a.Body.String() != b.Body.String() {
				t.Fatal("Client/bootstrap boundary changed")
			}
		})
	}
}

func TestNodeCertificateCannotBorrowOtherNodeAndCurrentAuthorityFencesReuse(t *testing.T) {
	service, db, group := newRelayNodeTestService(t)
	// Reuse only the synthetic test authority, never deployment material.
	tokenA, digestA, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindingA := bindRelayNodeTestCredential(t, db, "node-a", digestA)
	tokenB, digestB, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, db, "node-b", digestB)
	var pin [32]byte
	pin[0] = 0xab
	identity := nodetransport.Identity{Kind: "node", HubID: bindingA.HubID, NodeID: "node-a", TLSEpoch: 17, DNSName: "node-a.synthetic.invalid"}
	approval := nodetransport.Approval{Identity: identity, PinKind: "certificate-sha256", PinSHA256: hex.EncodeToString(pin[:]), OwnerID: bindingA.OwnerID, OwnerKeyID: bindingA.OwnerKeyID, BindingID: bindingA.ID, BindingVersion: bindingA.Version, CredentialVersion: bindingA.NodeCredentialVersion}
	cfg := &nodetransport.Config{Peers: []nodetransport.Approval{approval}}
	state := pqtls.State{TLSVersion: "TLSv1.3", Group: "MLKEM768", CipherSuite: "TLS_AES_256_GCM_SHA384", PeerSignature: "ML-DSA-65", ALPN: "http/1.1", HostnameVerified: true, Peer: identity.TLSIdentity(), CertificateSHA256: pin}
	ctx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: state})
	handler := WithNodePQTransport(NewFabricHandler(service, ""), service, cfg, true)
	call := func(path, authorization string, ctx context.Context) int {
		r := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := call("/v2/relay/nodes/node-a/events", "CicadaNode "+tokenB, ctx); code != http.StatusUnauthorized {
		t.Fatalf("borrowed bearer status %d", code)
	}
	if code := call("/v2/relay/nodes/node-a/claim", "CicadaNode "+tokenA, ctx); code == http.StatusUnauthorized {
		t.Fatal("current independent TLS epoch rejected")
	}
	joined, err := service.JoinForNodeCredential(tokenB, fabric.JoinInput{GroupID: group.ID, Harness: "codex", NativeSessionID: "native-b"})
	if err != nil {
		t.Fatal(err)
	}
	if code := call("/v2/fabric/whoami", "CicadaSession "+joined.SessionToken, ctx); code != http.StatusUnauthorized {
		t.Fatal("borrowed Session accepted by another Node certificate")
	}
	oldState := state
	oldState.Peer.BindingEpoch = 16
	oldCtx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: oldState})
	if code := call("/v2/relay/nodes/node-a/claim", "CicadaNode "+tokenA, oldCtx); code != http.StatusUnauthorized {
		t.Fatal("old transport epoch accepted")
	}
	if _, err := db.RevokeNodeDeviceBinding(bindingA.OwnerID, bindingA.ID, bindingA.Version); err != nil {
		t.Fatal(err)
	}
	if code := call("/v2/relay/nodes/node-a/claim", "CicadaNode "+tokenA, ctx); code != http.StatusUnauthorized {
		t.Fatal("revoked binding accepted on reused TLS context")
	}
}
