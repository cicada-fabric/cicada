package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

const multiHubFixtureManagementToken = "synthetic-multi-hub-management-token"

type multiHubServiceFixture struct {
	name            string
	nodeID          string
	ownerID         string
	hubID           string
	nodeToken       string
	database        *store.Store
	service         *fabric.Service
	httpServer      *httptest.Server
	pathMu          sync.Mutex
	paths           map[string]int
	badNodeAuth     atomic.Int32
	controlRequests atomic.Int32
}

func newMultiHubServiceFixture(t *testing.T, name, nodeID string) *multiHubServiceFixture {
	t.Helper()
	database, err := store.New(filepath.Join(t.TempDir(), "hub.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	ownerID := "owner_" + name
	if _, err := database.CreatePrincipal(store.Principal{
		ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: "synthetic " + name, Status: store.PrincipalStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	registeredKey, err := database.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := database.GetClientHubID()
	if err != nil || hubID == "" {
		t.Fatalf("read %s Hub identity: hub=%q err=%v", name, hubID, err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device_" + name
	now := time.Now().UTC()
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: registeredKey.KeyID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	code := sha256.Sum256([]byte("synthetic-multi-hub-node-code\x00" + name + "\x00" + nodeID))
	codeDigest := hex.EncodeToString(code[:])
	if _, err := database.CreatePendingNodeDeviceBinding(nodeID, "synthetic "+name+" Node",
		nodeDigest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(database, ownerID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &multiHubServiceFixture{
		name: name, nodeID: nodeID, ownerID: ownerID, hubID: hubID,
		nodeToken: nodeToken, database: database, service: service,
		paths: make(map[string]int),
	}
	handler := server.NewFabricHandler(service, multiHubFixtureManagementToken)
	fixture.httpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.pathMu.Lock()
		fixture.paths[r.Method+" "+r.URL.Path]++
		fixture.pathMu.Unlock()
		if r.URL.Path == "/v1/machines" || strings.HasPrefix(r.URL.Path, "/v1/actions") {
			fixture.controlRequests.Add(1)
		}
		if strings.HasPrefix(r.URL.Path, "/v2/relay/nodes/") ||
			strings.HasPrefix(r.URL.Path, "/v2/fabric/node/") {
			actual, parseErr := fabric.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
			if parseErr != nil || actual != fixture.nodeToken {
				fixture.badNodeAuth.Add(1)
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(fixture.httpServer.Close)
	return fixture
}

func (f *multiHubServiceFixture) requestCount(method, path string) int {
	f.pathMu.Lock()
	defer f.pathMu.Unlock()
	return f.paths[method+" "+path]
}

func TestMachineMultiHubAgentUsesTwoIndependentProductionFabricServices(t *testing.T) {
	const nodeID = "node_m5_shared"
	hubA := newMultiHubServiceFixture(t, "a", nodeID)
	hubB := newMultiHubServiceFixture(t, "b", nodeID)
	if hubA.hubID == hubB.hubID || hubA.httpServer.URL == hubB.httpServer.URL || hubA.nodeToken == hubB.nodeToken {
		t.Fatal("two-Hub fixture coordinates or Node credentials collided")
	}
	for _, pair := range []struct {
		fixture *multiHubServiceFixture
		foreign string
	}{{hubA, hubB.nodeToken}, {hubB, hubA.nodeToken}} {
		if authenticated, err := pair.fixture.service.AuthenticateNode(pair.fixture.nodeToken); err != nil || authenticated != nodeID {
			t.Fatalf("%s rejected its owner-bound Node credential: id=%q err=%v", pair.fixture.name, authenticated, err)
		}
		if _, err := pair.fixture.service.AuthenticateNode(pair.foreign); !errors.Is(err, fabric.ErrUnauthenticated) {
			t.Fatalf("%s accepted the other Hub's Node credential: %v", pair.fixture.name, err)
		}
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	entries := []machineHubConfig{
		{HubID: hubA.hubID, ControlURL: hubA.httpServer.URL, NodeID: nodeID, Name: "synthetic A"},
		{HubID: hubB.hubID, ControlURL: hubB.httpServer.URL, NodeID: nodeID, Name: "synthetic B"},
	}
	configPath := filepath.Join(root, "hubs.json")
	encoded, err := json.Marshal(machineHubConfigFile{Version: 1, Hubs: entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	stateA, stateB := machineHubStateDir(root, entries[0]), machineHubStateDir(root, entries[1])
	if stateA == stateB || !strings.HasPrefix(stateA, filepath.Join(root, "hubs")) ||
		!strings.HasPrefix(stateB, filepath.Join(root, "hubs")) {
		t.Fatalf("per-Hub state was not partitioned beneath the configured root: %q %q", stateA, stateB)
	}
	for _, pair := range []struct {
		state string
		token string
	}{{stateA, hubA.nodeToken}, {stateB, hubB.nodeToken}} {
		identityPath := filepath.Join(machineNodeStateDir(pair.state, nodeID), "identity.json")
		if err := persistMachineNodeIdentity(identityPath, machineNodeCredentialPath(pair.state, nodeID),
			&machineNodeIdentity{Version: machineNodeIdentityVersion, NodeID: nodeID, RelayToken: pair.token}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CICADA_NODE_TOKEN", "stale-global-node-token")
	t.Setenv("CICADA_HUB_ID", "stale-global-hub-id")
	if err := runMachineMultiHubAgent(configPath, root, time.Second, true); err != nil {
		t.Fatalf("production multi-Hub relay-only Agent run failed: %v", err)
	}
	for _, fixture := range []*multiHubServiceFixture{hubA, hubB} {
		if fixture.badNodeAuth.Load() != 0 {
			t.Fatalf("%s received a foreign Node credential during its Agent run", fixture.name)
		}
		if fixture.controlRequests.Load() != 0 {
			t.Fatalf("relay-only Agent attempted %d Control requests at %s", fixture.controlRequests.Load(), fixture.name)
		}
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/v2/relay/nodes/" + nodeID + "/events"},
			{http.MethodPost, "/v2/relay/nodes/" + nodeID + "/heartbeat"},
			{http.MethodPost, "/v2/relay/nodes/" + nodeID + "/sealed/claim"},
		} {
			if fixture.requestCount(route.method, route.path) == 0 {
				t.Errorf("%s did not receive the expected production Node route %s %s", fixture.name, route.method, route.path)
			}
		}
	}

	// The shared native writer owner/epoch is local to one Thread across both
	// Hub contexts, while API requests remain pinned to one origin each.
	writerA := withMachineHubContext(context.Background(), machineHubContext{
		HubID: hubA.hubID, Origin: hubA.httpServer.URL, NodeID: nodeID,
		WriterRoot: root, WriterScope: machineNativeWriterScope(),
	})
	writerB := withMachineHubContext(context.Background(), machineHubContext{
		HubID: hubB.hubID, Origin: hubB.httpServer.URL, NodeID: nodeID,
		WriterRoot: root, WriterScope: machineNativeWriterScope(),
	})
	lock, err := nodelock.AcquireNativeWriter(context.Background(), root,
		machineNativeWriterScope(), "codex", "same-native-thread")
	if err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := nodelock.AcquireNativeWriter(blocked, root,
		machineNativeWriterScope(), "codex", "same-native-thread"); !errors.Is(err, context.DeadlineExceeded) {
		_ = lock.Close()
		t.Fatalf("second Hub acquired a concurrent writer for the same native Thread: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := nodelock.AcquireNativeWriter(writerB, root,
		machineNativeWriterScope(), "codex", "same-native-thread")
	if err != nil || second.Epoch != lock.Epoch+1 {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("Hub B did not acquire the next durable writer epoch: lock=%#v err=%v", second, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	before := hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat")
	if err := machineAPIJSON(writerA, hubB.httpServer.URL+"/v2/relay/nodes/"+nodeID+"/heartbeat",
		http.MethodPost, map[string]any{}, nil); err == nil || !strings.Contains(err.Error(), "pinned Hub") {
		t.Fatalf("Hub A context crossed into Hub B origin: %v", err)
	}
	if got := hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat"); got != before {
		t.Fatalf("origin pin attempted a cross-Hub request: before=%d after=%d", before, got)
	}

	transplant, err := http.NewRequest(http.MethodPost, hubB.httpServer.URL+"/v2/relay/nodes/"+nodeID+"/heartbeat", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	transplant.Header.Set("Authorization", "CicadaNode "+hubA.nodeToken)
	transplant.Header.Set("Content-Type", "application/json")
	transplantResponse, err := http.DefaultClient.Do(transplant)
	if err != nil {
		t.Fatal(err)
	}
	_ = transplantResponse.Body.Close()
	if transplantResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-Hub credential transplant status=%d, want 401", transplantResponse.StatusCode)
	}

	controlProbe, err := http.NewRequest(http.MethodGet, hubA.httpServer.URL+"/v1/machines", nil)
	if err != nil {
		t.Fatal(err)
	}
	controlProbe.Header.Set("Authorization", "Bearer "+multiHubFixtureManagementToken)
	controlResponse, err := http.DefaultClient.Do(controlProbe)
	if err != nil {
		t.Fatal(err)
	}
	_ = controlResponse.Body.Close()
	if controlResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Fabric-only handler Control status=%d, want 503", controlResponse.StatusCode)
	}
	if hubA.controlRequests.Load() != 1 || hubB.controlRequests.Load() != 0 {
		t.Fatalf("Control route usage changed unexpectedly: A=%d B=%d", hubA.controlRequests.Load(), hubB.controlRequests.Load())
	}

	// A disconnected Hub is reported, while the worker pinned to the healthy
	// Hub still performs its own heartbeat and relay reconciliation.
	bHeartbeatsBefore := hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat")
	bClaimsBefore := hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/sealed/claim")
	hubA.httpServer.Close()
	if err := runMachineMultiHubAgent(configPath, root, time.Second, true); err == nil {
		t.Fatal("multi-Hub Agent hid an unavailable Hub")
	}
	if got := hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat"); got != bHeartbeatsBefore+1 {
		t.Fatalf("Hub B heartbeat stalled while Hub A was unavailable: before=%d after=%d", bHeartbeatsBefore, got)
	}
	if got := hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/sealed/claim"); got != bClaimsBefore+1 {
		t.Fatalf("Hub B relay reconciliation stalled while Hub A was unavailable: before=%d after=%d", bClaimsBefore, got)
	}

	// The same native Thread/message coordinates may occur at both Hubs. The
	// production state roots keep local replay records separate across restart.
	for _, pair := range []struct {
		state string
		name  string
	}{{stateA, "hub-a"}, {stateB, "hub-b"}} {
		path := machineNodeInboxPath(pair.state, nodeID)
		inbox, err := nodeinbox.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		message := nodeinbox.Message{MessageID: "same_native_message_id", Digest: "digest-" + pair.name,
			EndpointID: "ep-" + pair.name, SessionID: "same-native-thread", BindingEpoch: 1,
			Payload: []byte("synthetic local replay record for " + pair.name)}
		if _, created, err := inbox.Save(context.Background(), message); err != nil || !created {
			_ = inbox.Close()
			t.Fatalf("save %s local replay record: created=%t err=%v", pair.name, created, err)
		}
		if err := inbox.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := nodeinbox.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := reopened.Get(context.Background(), message.MessageID)
		if err != nil || stored.Digest != message.Digest || string(stored.Payload) != string(message.Payload) {
			_ = reopened.Close()
			t.Fatalf("%s replay state changed across restart: %#v err=%v", pair.name, stored, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
