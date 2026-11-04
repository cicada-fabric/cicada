//go:build linux && cicada_scoped_app_integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func TestNodeHubLifecycleStoppedOriginalAdoptionAcceptance(t *testing.T) {
	testNodeHubLifecycleStoppedOriginal(t, false)
}

func TestNodeHubLifecycleRetainedArtifactsReaddAcceptance(t *testing.T) {
	testNodeHubLifecycleStoppedOriginal(t, true)
}

func testNodeHubLifecycleStoppedOriginal(t *testing.T, readd bool) {
	t.Helper()
	f := newNodeHubLifecycleAcceptanceMode(t, false)
	hub := f.hubs[0]
	state, node := filepath.Join(f.root, "SYNTHETIC-original-node-state"), "SYNTHETIC-original-physical-Node"
	pairCtx, pairCancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer pairCancel()
	paired := make(chan error, 1)
	go func() {
		completed := false
		paired <- prepareMachineNodePairTrust(pairCtx, state, node, "SYNTHETIC original A", hub.dial, hub.native.d.Claims.Origin, true, false, false, io.Discard, &completed, "scoped")
	}()
	f.approvePendingNode(0, state, node)
	select {
	case err := <-paired:
		pairCancel()
		if err != nil {
			t.Fatal("actual original unmanaged scoped NPT/private ACK", err)
		}
	case <-pairCtx.Done():
		pairCancel()
		t.Fatal("original unmanaged NPT/private ACK timed out")
	}
	hub.dispatch(appcore.Action{Kind: appcore.ActionRefreshNodePairing})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	canonical, selected, err := canonicalNodeServiceArgs(f.root, []string{"--id", node, "--name", "SYNTHETIC original A", "--state-dir", state, "--control-url", hub.native.d.Claims.Origin, "--hub-address", hub.dial, "--mcp-session-state-file", filepath.Join(f.root, "SYNTHETIC-original-cache", "sessions.json"), "--mcp-outbox-state-file", filepath.Join(f.root, "SYNTHETIC-original-outbox", "outbox.sqlite3"), "--interval", "1s", "--relay-only"})
	if err != nil {
		t.Fatal(err)
	}
	service := nodeServiceConfig{Format: nodeServiceFormat, UserRoot: f.root, Binary: binary, CodexBin: "/usr/bin/false", Home: f.root, Path: "/usr/bin:/bin", CodexHome: os.Getenv("CODEX_HOME"), AgentArgs: canonical}
	rawService, err := json.Marshal(service)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := nodeHubRoot(context.Background(), f.root, false)
	if err != nil {
		t.Fatal(err)
	}
	err = writeNodeServiceConfig(r, append(rawService, '\n'))
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	legacyCtx, legacyCancel := context.WithCancel(context.Background())
	legacyCtx = context.WithValue(legacyCtx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: f.queueCommand})
	legacyEnd := make(chan error, 1)
	go func() {
		// The real single-Hub CLI resolves its transport from the original
		// scoped-NPT state. --hub-address cannot be combined with a separately
		// supplied pinned worker context; do not invent an alternate transport.
		legacyEnd <- runMachineAgentWithContext(legacyCtx, canonical, nil)
	}()
	legacyStopped := false
	stopOriginal := func() {
		t.Helper()
		if legacyStopped {
			return
		}
		legacyCancel()
		select {
		case err := <-legacyEnd:
			legacyStopped = true
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal("actual original Agent did not stop cleanly", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("actual original Agent did not quiesce before adoption")
		}
	}
	t.Cleanup(stopOriginal)
	var old LocalNodeConnection
	f.eventually("actual original unmanaged Agent discovery", 10*time.Second, func() bool {
		var e error
		old, e = ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: f.root, HubID: hub.native.d.Claims.Hub.HubID, NodeID: node}, nil)
		return e == nil && old.Pin.ConnectionID == "" && old.Pin.ConnectionEpoch == 0
	})
	group := f.activateGroup(0)
	sender, receiver := nodeHubSyntheticThread(t, "adopt-sender"), nodeHubSyntheticThread(t, "adopt-receiver")
	oldSender, oldReceiver := f.register(old, sender), f.register(old, receiver)
	originalMCP, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: f.root, HubID: old.Pin.HubID, NodeID: old.Pin.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	closedOriginalMCP := false
	closeOriginalMCP := func() {
		if !closedOriginalMCP {
			closeCodexMCPChild(originalMCP)
			closedOriginalMCP = true
		}
	}
	t.Cleanup(closeOriginalMCP)
	if _, err := f.tool(originalMCP, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("actual original Group self-view", err)
	}
	f.selectGroup(originalMCP, sender, old.Pin, group)
	id := f.send(originalMCP, sender, oldReceiver.EndpointID, "SYNTHETIC-before-adoption", "SYNTHETIC original A message before adoption")
	f.assertDelivered(old, oldReceiver, receiver, id, "SYNTHETIC original A message before adoption")
	// Keep a genuinely committed encrypted App request unknown through the
	// explicit stop/adoption transition. No synthetic outbox row is inserted.
	hub.mu.Lock()
	hub.dropPath = wire.LocalDomainHTTPPath(wire.OperationLocalDomainStatus)
	hub.mu.Unlock()
	if err := hub.app.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}); err == nil || !hub.app.Snapshot().LocalCollaboration.Pending {
		t.Fatal("original App read did not retain its unknown packet")
	}
	hub.mu.Lock()
	committed := hub.droppedStatus == http.StatusOK && hub.droppedDigest != ([32]byte{})
	hub.mu.Unlock()
	if !committed {
		t.Fatal("original unknown App response was not committed by actual Hub")
	}
	vaultBefore := readTreeHashesForNativeTLS(t, hub.vaultRoot)
	closeOriginalMCP()
	stopOriginal()
	if busy, err := nodeServiceAgentBusy(selected); err != nil || busy {
		t.Fatal("original Agent lock remained held before explicit adoption", err)
	}
	cacheBefore := readTreeHashesForNativeTLS(t, filepath.Dir(old.Pin.MCPSessionStateFile))
	outboxBefore := readTreeHashesForNativeTLS(t, filepath.Dir(old.Pin.MCPOutboxStateFile))
	keyPath, _ := machineNodeControlPaths(state, node)
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyBefore)
	credentialBefore, err := os.ReadFile(machineNodeCredentialPath(state, node))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentialBefore)
	serviceDigest := sha256.Sum256(append(rawService, '\n'))
	legacyUnit := nodeServiceUnit(service, selected)
	starts := 0
	// Only the service command orchestration is substituted. It starts the
	// actual manager/production workers and validates its actual PID over IPC.
	// These scripted show/version rows provide no systemd qualification.
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/systemctl" && strings.Join(args, " ") == "--user show --property=Version --value" {
			return "255.4\n", nil
		}
		if name == "/usr/bin/systemd-run" {
			starts++
			f.start()
			return "", nil
		}
		if name == "/usr/bin/systemctl" && len(args) >= 3 && args[0] == "--user" && args[1] == "show" {
			if args[2] == legacyUnit {
				return "LoadState=loaded\nActiveState=inactive\nMainPID=0\nTransient=yes\nDescription=Cicada managed Node " + hex.EncodeToString(serviceDigest[:]) + "\n", nil
			}
			if args[2] != nodeHubServiceUnit(f.root) {
				return "", errors.New("unowned fixture service selector")
			}
			if starts == 0 {
				return "LoadState=not-found\nActiveState=inactive\nMainPID=0\n", nil
			}
			current, err := os.ReadFile(filepath.Join(f.root, nodeServiceConfigName))
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("LoadState=loaded\nActiveState=active\nMainPID=%d\nTransient=yes\nDescription=%s\n", os.Getpid(), nodeHubServiceOwner(current)), nil
		}
		return "", errors.New("unexpected fixture service command")
	}
	adoptCtx := context.WithValue(context.Background(), nodeHubOperationHooksKey{}, nodeHubOperationHooks{ServiceRunner: runner, Output: io.Discard})
	view, err := AddLocalNodeHubConnection(adoptCtx, LocalNodeHubAddInput{UserRoot: f.root, FromService: true, Alias: "SYNTHETIC-A"})
	if err != nil || starts != 1 || view.ConnectionID == "" || view.LocalFence != 1 {
		t.Fatal("actual stopped-original adoption did not start actual manager", err)
	}
	var adopted LocalNodeConnection
	f.eventually("actual adopted worker reuses original state", 12*time.Second, func() bool {
		var e error
		adopted, e = ResolveAdoptedLocalNodeConnection(context.Background(), old.Pin)
		return e == nil
	})
	expected := old.Pin
	expected.ConnectionID, expected.ConnectionEpoch = view.ConnectionID, 1
	if adopted.Pin != expected || adopted.InstanceID == old.InstanceID || !reflect.DeepEqual(cacheBefore, readTreeHashesForNativeTLS(t, filepath.Dir(old.Pin.MCPSessionStateFile))) || !reflect.DeepEqual(outboxBefore, readTreeHashesForNativeTLS(t, filepath.Dir(old.Pin.MCPOutboxStateFile))) {
		t.Fatal("adoption replaced original authority/cache/outbox or reused stopped instance")
	}
	b := f.add(1)
	f.assertUnchanged(adopted)
	if b.Pin.WriterRoot != old.Pin.WriterRoot || !reflect.DeepEqual(cacheBefore, readTreeHashesForNativeTLS(t, filepath.Dir(old.Pin.MCPSessionStateFile))) || !reflect.DeepEqual(outboxBefore, readTreeHashesForNativeTLS(t, filepath.Dir(old.Pin.MCPOutboxStateFile))) || !reflect.DeepEqual(vaultBefore, readTreeHashesForNativeTLS(t, hub.vaultRoot)) || !hub.app.Snapshot().LocalCollaboration.Pending {
		t.Fatal("adding B changed original A writer/cache/outbox/unknown packet")
	}
	keyAfter, keyErr := os.ReadFile(keyPath)
	credentialAfter, credentialErr := os.ReadFile(machineNodeCredentialPath(state, node))
	defer clear(keyAfter)
	defer clear(credentialAfter)
	if keyErr != nil || credentialErr != nil || !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(credentialBefore, credentialAfter) {
		t.Fatal("adoption/add B replaced original private Node key or credential")
	}
	front, err := newRoutedLocalNodeMCPServer(f.root, ListVerifiedLocalNodeConnections)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.codexFacade.close(); close(front.stop) })
	if _, err := f.tool(front, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("actual default facade could not resume adopted original Thread", err)
	}
	f.selectGroup(front, sender, adopted.Pin, group)
	self, err := f.tool(front, sender, "cicada_whoami", map[string]any{})
	public, _ := json.Marshal(self)
	var identity struct {
		EndpointID string `json:"endpoint_id"`
		NativeID   string `json:"native_session_id"`
	}
	if err != nil || json.Unmarshal(public, &identity) != nil || identity.EndpointID != oldSender.EndpointID || identity.NativeID != sender.native {
		t.Fatal("default facade substituted adopted original Endpoint/native SID", err)
	}
	cached, err := newMCPSessionStateStore(old.Pin.MCPSessionStateFile).load(old.Pin.APIOrigin, harness.SessionContext{Harness: "codex", NativeSessionID: sender.native, MachineID: node, Workspace: sender.workspace})
	if err != nil || cached == nil || cached.ConnectionPin == nil || *cached.ConnectionPin != old.Pin || cached.EndpointID != oldSender.EndpointID {
		t.Fatal("current consumer rewrote original cache pin to bypass adoption", err)
	}
	id = f.send(front, sender, oldReceiver.EndpointID, "SYNTHETIC-after-adoption", "SYNTHETIC original A message after adoption and B")
	f.assertDelivered(adopted, oldReceiver, receiver, id, "SYNTHETIC original A message after adoption and B")
	f.assertUnchanged(adopted)
	t.Log("actual current NPT/unmanaged Agent/CLI Thread, explicit stop, protected from-service receipt and actual adopted manager+facade; original Endpoint/SID/keys retained; service runner scripted, actual systemd/native Runtime NOT_RUN")
	if !readd {
		return
	}
	// Exercise the real user's transitive history: original storage pin 0,
	// adopted live pin 1, removal fence 2 and explicit re-add live pin 3.
	groupB := f.activateGroup(1)
	f.register(b, sender)
	receiverB := f.register(b, receiver)
	if _, err := f.tool(front, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("actual A/B view before original re-add", err)
	}
	f.selectGroup(front, sender, b.Pin, groupB)
	id = f.send(front, sender, receiverB.EndpointID, "SYNTHETIC-B-before-readd", "SYNTHETIC B before original A re-add")
	f.assertDelivered(b, receiverB, receiver, id, "SYNTHETIC B before original A re-add")
	oldOutbox := nodeHubReadOnlyOutboxSnapshot(t, old.Pin.MCPOutboxStateFile)
	hub.mu.Lock()
	startsBefore := hub.paths[http.MethodPost+" "+wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedStart)]
	hub.mu.Unlock()
	removed, err := RemoveLocalNodeHubConnection(f.ctx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: adopted.Pin.ConnectionID})
	if err != nil || removed.State != "LOCAL_STOPPED" || removed.LocalFence != 2 || removed.RemoteRevocation != "NOT_REQUESTED" {
		t.Fatal("actual original A did not stop before explicit re-add", err)
	}
	f.assertUnchanged(b)
	id = f.send(front, sender, receiverB.EndpointID, "SYNTHETIC-B-during-readd", "SYNTHETIC B while original A is removed")
	f.assertDelivered(b, receiverB, receiver, id, "SYNTHETIC B while original A is removed")
	if nodeHubReadOnlyOutboxSnapshot(t, old.Pin.MCPOutboxStateFile).digest != oldOutbox.digest {
		t.Fatal("removal rewrote original A outbox rows or storage fence")
	}
	resumed, err := AddLocalNodeHubConnection(f.ctx, LocalNodeHubAddInput{UserRoot: f.root, Alias: "SYNTHETIC-A", HubAddress: hub.dial})
	if err != nil || resumed.ConnectionID != adopted.Pin.ConnectionID || resumed.LocalFence != 3 || resumed.RuntimeState != "RUNNING" {
		t.Fatal("explicit same-alias re-add did not resume original generation 3", err)
	}
	current, err := ResolveLocalNodeConnection(f.ctx, LocalNodeSelection{UserRoot: f.root, HubID: old.Pin.HubID, NodeID: old.Pin.NodeID}, nil)
	expected.ConnectionEpoch = 3
	if err != nil || current.Pin != expected || current.InstanceID == adopted.InstanceID {
		t.Fatal("re-add substituted original immutable scope or retained retired instance", err)
	}
	f.assertUnchanged(b)
	hub.mu.Lock()
	startsAfter := hub.paths[http.MethodPost+" "+wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedStart)]
	hub.mu.Unlock()
	if startsAfter != startsBefore || !reflect.DeepEqual(vaultBefore, readTreeHashesForNativeTLS(t, hub.vaultRoot)) || !hub.app.Snapshot().LocalCollaboration.Pending || nodeHubReadOnlyOutboxSnapshot(t, old.Pin.MCPOutboxStateFile).digest != oldOutbox.digest {
		t.Fatal("re-add issued fresh enrollment or rewrote an original packet/outbox")
	}
	// Storage continuity is error-only and cannot promote an old live pin.
	if err := ValidateRetainedLocalNodeArtifacts(f.ctx, old.Pin, current.Pin); err != nil {
		t.Fatal("actual protected legacy storage provenance did not reach live epoch 3", err)
	}
	beforeCount := f.queueCount(receiver.native)
	for index, stale := range []LocalNodeConnectionPin{old.Pin, adopted.Pin} {
		if _, err := ResolveLocalNodeConnection(f.ctx, LocalNodeSelection{UserRoot: f.root, HubID: stale.HubID, NodeID: stale.NodeID}, &stale); err == nil {
			t.Fatal("historical storage pin became a current live discovery authority")
		}
		err := runMachineNativeDelivery(nodeHubAcceptanceNativeContext(f.ctx, stale), receiver.native, nodeHubAcceptanceNativeOperation(stale, fmt.Sprintf("SYNTHETIC-readd-stale-%d", index)), func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
			return "SYNTHETIC forbidden old live generation", nil, nil
		}, nil)
		if err == nil || f.queueCount(receiver.native) != beforeCount {
			t.Fatal("historical live pin started work after current epoch 3")
		}
	}
	if _, err := f.tool(front, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("fresh production Host/Hook could not inspect retained original A", err)
	}
	f.selectGroup(front, sender, current.Pin, group)
	id = f.send(front, sender, oldReceiver.EndpointID, "SYNTHETIC-A-after-readd", "SYNTHETIC original A after epoch 3 re-add")
	f.assertDelivered(current, oldReceiver, receiver, id, "SYNTHETIC original A after epoch 3 re-add")
	f.assertUnchanged(b)
	retained, err := newMCPSessionStateStore(old.Pin.MCPSessionStateFile).load(old.Pin.APIOrigin, harness.SessionContext{Harness: "codex", NativeSessionID: sender.native, MachineID: node, Workspace: sender.workspace})
	if err != nil || retained == nil || retained.ConnectionPin == nil || *retained.ConnectionPin != old.Pin || retained.EndpointID != oldSender.EndpointID || retained.NativeSessionID != sender.native || retained.Workspace != sender.workspace {
		t.Fatal("fresh epoch-3 call replaced the original stored identity/pin")
	}
	storedPin, err := readCodexOriginalOutboxPin(old.Pin.MCPOutboxStateFile)
	if err != nil || storedPin == nil || *storedPin != old.Pin {
		t.Fatal("fresh epoch-3 call rewrote the original outbox metadata fence", err)
	}
	routeID, err := codexChildRouteID(current.Pin)
	if err != nil {
		t.Fatal(err)
	}
	child := front.codexFacade.children[routeID]
	if child == nil || child.localNode.Pin != current.Pin || child.outbox == nil || child.outbox.path != old.Pin.MCPOutboxStateFile || child.outbox.connectionPin == nil || *child.outbox.connectionPin != old.Pin {
		t.Fatal("fresh epoch-3 child created an alternate outbox or storage pin")
	}
	currentRows := nodeHubReadOnlyOutboxSnapshot(t, old.Pin.MCPOutboxStateFile)
	if currentRows.schema != oldOutbox.schema {
		t.Fatal("fresh epoch-3 call introduced an alternate outbox schema namespace")
	}
	present := make(map[string]bool, len(currentRows.rows))
	for _, row := range currentRows.rows {
		present[row] = true
	}
	for _, row := range oldOutbox.rows {
		if !present[row] {
			t.Fatal("fresh epoch-3 operation lost or rewrote an original outbox row")
		}
	}
	keyAfter, keyErr = os.ReadFile(keyPath)
	credentialAfter, credentialErr = os.ReadFile(machineNodeCredentialPath(state, node))
	defer clear(keyAfter)
	defer clear(credentialAfter)
	if keyErr != nil || credentialErr != nil || !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(credentialBefore, credentialAfter) || !reflect.DeepEqual(vaultBefore, readTreeHashesForNativeTLS(t, hub.vaultRoot)) {
		t.Fatal("epoch-3 continuation replaced original keys/credential/unknown App packet")
	}
	t.Log("actual legacy storage0 -> adopt live1 -> local stop2 -> explicit same-alias live3; original Endpoint/SID/keys/cache/outbox pin retained, fresh current Host/Guard succeeds, old live0/1 starts zero work, B instance unchanged; native Runtime/systemd NOT_RUN")
}
