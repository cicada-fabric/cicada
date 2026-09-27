package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func bindRelayNodeTestCredential(t *testing.T, persistence *store.Store, nodeID, digest string) *store.NodeDeviceBinding {
	t.Helper()
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	registeredKey, err := persistence.RegisterOwnerApprovalKeyLocal("owner", ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-" + nodeID
	grant, err := ownerKey.SignOwnerDeviceGrant("owner", deviceID, device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: "owner", OwnerKeyID: registeredKey.KeyID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	code := sha256.Sum256([]byte(t.Name() + nodeID))
	codeDigest := hex.EncodeToString(code[:])
	if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, nodeID, digest,
		codeDigest, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	binding, err := persistence.ConfirmPendingNodeDeviceBinding("owner", deviceID, codeDigest)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func newRelayNodeTestService(t *testing.T) (*fabricpkg.Service, *store.Store, store.Group) {
	t.Helper()
	persistence, err := store.New(filepath.Join(t.TempDir(), "relay-node.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: "owner", Kind: store.PrincipalKindHuman, OwnerID: "owner",
		TrustDomainID: "domain", Name: "owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		Name: "group", OwnerPrincipalID: owner.ID, TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, owner.ID, "domain")
	if err != nil {
		t.Fatal(err)
	}
	return service, persistence, *group
}

func TestRelayNodeOutboundEventStreamWakesAfterDurableAsk(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	join := func(name, node string) (*fabricpkg.JoinResult, fabricpkg.Actor) {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: group.ID, PrincipalName: name, EndpointName: name,
			Harness: "codex", NativeSessionID: "native-" + name, NodeID: node,
		})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := service.Authenticate(joined.SessionToken)
		if err != nil {
			t.Fatal(err)
		}
		return joined, actor
	}
	_, actorA := join("a", "node-a")
	b, _ := join("b", "node-b")
	nodeToken, nodeHash, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-b", nodeHash)
	server := httptest.NewServer(NewFabricHandler(service, "management-token"))
	defer server.Close()
	endpoint := server.URL + "/v2/relay/nodes/node-b/events"
	open := func(auth string) *http.Response {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", auth)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	for _, auth := range []string{"Bearer management-token", "CicadaNode wrong"} {
		response := open(auth)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthorized stream status=%d", response.StatusCode)
		}
	}
	response := open("CicadaNode " + nodeToken)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("event stream status=%d type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(response.Body)
	readEvent := func() string {
		t.Helper()
		result := make(chan string, 1)
		go func() {
			var event strings.Builder
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					result <- "read error: " + err.Error()
					return
				}
				event.WriteString(line)
				if line == "\n" {
					result <- event.String()
					return
				}
			}
		}()
		select {
		case value := <-result:
			return value
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for Relay event")
			return ""
		}
	}
	if ready := readEvent(); ready != "event: ready\ndata: claim\n\n" {
		t.Fatalf("unexpected ready event: %q", ready)
	}
	if _, err := service.Ask(actorA, fabricpkg.AskInput{Target: b.Endpoint.ID, Question: "private question"}); err != nil {
		t.Fatal(err)
	}
	if event := readEvent(); event != "event: wake\ndata: claim\n\n" {
		t.Fatalf("unexpected wake event: %q", event)
	}
	claimBody := bytes.NewBufferString(`{"consumer_id":"node-b-agent","limit":10}`)
	claimRequest, err := http.NewRequest(http.MethodPost, server.URL+"/v2/relay/nodes/node-b/claim", claimBody)
	if err != nil {
		t.Fatal(err)
	}
	claimRequest.Header.Set("Authorization", "CicadaNode "+nodeToken)
	claimResponse, err := http.DefaultClient.Do(claimRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer claimResponse.Body.Close()
	claimBytes, _ := io.ReadAll(claimResponse.Body)
	if claimResponse.StatusCode != http.StatusOK || !bytes.Contains(claimBytes, []byte("private question")) {
		t.Fatalf("durable claim status=%d body=%s", claimResponse.StatusCode, claimBytes)
	}
}

func TestRelayNodeEventStreamClosesAfterOwnerRevocation(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	join := func(name, node string) (*fabricpkg.JoinResult, fabricpkg.Actor) {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: group.ID, PrincipalName: name, EndpointName: name,
			Harness: "codex", NativeSessionID: "native-" + name, NodeID: node,
		})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := service.Authenticate(joined.SessionToken)
		if err != nil {
			t.Fatal(err)
		}
		return joined, actor
	}
	_, actorA := join("a", "node-a")
	b, _ := join("b", "node-b")
	nodeToken, nodeHash, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	binding := bindRelayNodeTestCredential(t, persistence, "node-b", nodeHash)
	server := httptest.NewServer(NewFabricHandler(service, "management-token"))
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/v2/relay/nodes/node-b/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "CicadaNode "+nodeToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("event stream status=%d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read ready event: %v", err)
		}
		if line == "\n" {
			break
		}
	}

	// Owner revocation removes the Node credential from the active authorization
	// view. The next wake must not be sent on the already-open stream.
	time.Sleep(relayNodeStreamRevalidateInterval + 50*time.Millisecond)
	if _, err := persistence.RevokeNodeDeviceBinding("owner", binding.ID, binding.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Ask(actorA, fabricpkg.AskInput{Target: b.Endpoint.ID, Question: "wake after revoke"}); err != nil {
		t.Fatal(err)
	}
	type streamRead struct {
		block string
		err   error
	}
	read := make(chan streamRead, 1)
	go func() {
		var block strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				read <- streamRead{block: block.String(), err: err}
				return
			}
			block.WriteString(line)
			if line == "\n" {
				read <- streamRead{block: block.String()}
				return
			}
		}
	}()
	select {
	case result := <-read:
		if !errors.Is(result.err, io.EOF) {
			t.Fatalf("revoked Node stream emitted %q or closed with err=%v", result.block, result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked Node event stream remained open without another credential check")
	}
}

func TestFabricJoinUsesManagementBearerWhenConfigured(t *testing.T) {
	service, _, group := newRelayNodeTestService(t)
	handler := NewFabricHandler(service, "management-token")
	body, _ := json.Marshal(fabricpkg.JoinInput{
		GroupID: group.ID, Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a",
	})
	request := func(authorization string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v2/fabric/join", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request(""); response.Code != http.StatusUnauthorized {
		t.Fatalf("join without management bearer status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request("Bearer management-token"); response.Code != http.StatusCreated {
		t.Fatalf("authorized join status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRelayNodeRequiresCredentialBoundToExactNode(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	join := func(name, session, node string) (*fabricpkg.JoinResult, fabricpkg.Actor) {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: group.ID, PrincipalName: name, EndpointName: name,
			Harness: "codex", NativeSessionID: session, NodeID: node,
		})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := service.Authenticate(joined.SessionToken)
		if err != nil {
			t.Fatal(err)
		}
		return joined, actor
	}
	_, actorA := join("a", "native-a", "node-a")
	b, _ := join("b", "native-b", "node-b")
	if _, err := service.Ask(actorA, fabricpkg.AskInput{Target: b.Endpoint.ID, Question: "secure node claim"}); err != nil {
		t.Fatal(err)
	}
	nodeAToken, nodeAHash, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nodeBToken, nodeBHash, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-a", nodeAHash)
	bindRelayNodeTestCredential(t, persistence, "node-b", nodeBHash)
	handler := NewFabricHandler(service, "management-token")
	heartbeat := func(auth, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v2/relay/nodes/node-b/heartbeat", strings.NewReader(body))
		request.Header.Set("Authorization", auth)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := heartbeat("CicadaNode "+nodeAToken, `{}`); response.Code != http.StatusForbidden {
		t.Fatalf("wrong Node heartbeat status=%d", response.Code)
	}
	if response := heartbeat("CicadaNode "+nodeBToken, `{"status":"available"}`); response.Code != http.StatusNoContent {
		t.Fatalf("explicit bound Node status update status=%d body=%s", response.Code, response.Body.String())
	}
	if response := heartbeat("CicadaNode "+nodeBToken, `{}`); response.Code != http.StatusNoContent {
		t.Fatalf("bound Node heartbeat status=%d body=%s", response.Code, response.Body.String())
	}
	if machine, err := persistence.GetMachine("node-b"); err != nil || machine == nil || machine.Status != "available" {
		t.Fatalf("bound Node heartbeat changed the explicitly reported status: machine=%#v err=%v", machine, err)
	}
	if err := persistence.SetMachineStatus("node-b", "busy"); err != nil {
		t.Fatal(err)
	}
	if response := heartbeat("CicadaNode "+nodeBToken, `{}`); response.Code != http.StatusNoContent {
		t.Fatalf("fabric-only transport heartbeat depends on Control status=%d body=%s", response.Code, response.Body.String())
	}
	if machine, err := persistence.GetMachine("node-b"); err != nil || machine == nil || machine.Status != "busy" || machine.LastSeen == "" {
		t.Fatalf("transport heartbeat should refresh liveness but preserve worker status: machine=%#v err=%v", machine, err)
	}
	claim := func(authorization string) *httptest.ResponseRecorder {
		body := bytes.NewReader([]byte(`{"consumer_id":"node-agent","limit":10}`))
		request := httptest.NewRequest(http.MethodPost, "/v2/relay/nodes/node-b/claim", body)
		request.Header.Set("Content-Type", "application/json")
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for _, authorization := range []string{"", "Bearer management-token"} {
		if response := claim(authorization); response.Code != http.StatusUnauthorized {
			t.Fatalf("non-node credential %q status=%d body=%s", authorization, response.Code, response.Body.String())
		}
	}
	if response := claim("CicadaNode " + nodeAToken); response.Code != http.StatusForbidden {
		t.Fatalf("node-a claimed node-b status=%d body=%s", response.Code, response.Body.String())
	}
	response := claim("CicadaNode " + nodeBToken)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"native_session_id":"native-b"`)) {
		t.Fatalf("node-b claim status=%d body=%s", response.Code, response.Body.String())
	}
}
