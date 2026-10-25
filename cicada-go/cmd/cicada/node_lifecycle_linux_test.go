package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type nodeLifecycleFixture struct {
	c                     nodeServiceConfig
	s                     nodeServiceSelection
	client                *machineNodeControlClient
	hub                   machineHubContext
	bridge                *machineAgentJoinBridge
	lock                  *nodelock.AgentLock
	active, foreign, fail bool
	starts, stops         int
	startArgs             []string
}

func newNodeLifecycleFixture(t *testing.T) *nodeLifecycleFixture {
	t.Helper()
	n := newNativeNodeFixture(t)
	// Business is unavailable, rather than revoked: the process may run, but
	// no network grant, delivery, model call or Hub-online success is invented.
	server := n.server(t, n.metadata, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	hub, _, client := activateTestNativeNode(t, n, server.Listener.Addr().String())
	client.mu.Lock()
	client.state.HubID = n.d.Claims.Hub.HubID
	client.state.HubKeyID, client.state.HubPublicIdentity = n.d.Claims.NodeControl.ID, n.d.Claims.NodeControl
	client.state.HubFingerprint = nodewire.IdentityFingerprint(n.d.Claims.NodeControl)
	client.state.HubKeyVersion = 1
	client.state.NodeKeyID, client.state.NodeKeyFingerprint = client.identity.Public().ID, nodewire.IdentityFingerprint(client.identity.Public())
	client.state.NodeKeyVersion, client.state.NodeKeyEpoch, client.state.BindingVersion = 1, 1, 1
	client.state.BindingID = "SYNTHETIC-lifecycle-binding"
	err := client.persistLocked()
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	hub.HubID = n.d.Claims.Hub.HubID
	root := privateLocalNodeRoot(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--id", client.nodeID, "--name", "SYNTHETIC lifecycle Node", "--state-dir", client.stateDir, "--control-url", client.base,
		"--relay-only", "--mcp-session-state-file", filepath.Join(root, "original-mcp", "sessions.json"), "--mcp-outbox-state-file", filepath.Join(root, "original-outbox", "outbox.json")}
	canonical, selection, err := canonicalNodeServiceArgs(root, args)
	if err != nil {
		t.Fatal(err)
	}
	f := &nodeLifecycleFixture{c: nodeServiceConfig{nodeServiceFormat, root, binary, "/usr/bin/true", root, "/usr/bin:/bin", "", canonical}, s: selection, client: client, hub: hub}
	t.Cleanup(func() { f.stop() })
	return f
}

func (f *nodeLifecycleFixture) save(t *testing.T) {
	t.Helper()
	data, _ := json.Marshal(f.c)
	if err := os.WriteFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *nodeLifecycleFixture) start() error {
	var err error
	f.lock, err = nodelock.AcquireAgent(f.s.state, f.s.id)
	if err != nil {
		return err
	}
	ctx := withMachineHubContext(context.Background(), f.hub)
	f.bridge, err = startMachineAgentJoinBridge(ctx, f.s.state, f.s.origin, f.s.id, f.hub.Token)
	if err != nil {
		return err
	}
	if err = startLocalNodeDiscovery(f.bridge, localNodePublishConfig{f.c.UserRoot, f.s.session, f.s.outbox}); err != nil {
		return err
	}
	f.active = true
	return nil
}
func (f *nodeLifecycleFixture) stop() {
	if f.bridge != nil {
		f.bridge.Close()
		f.bridge = nil
	}
	if f.lock != nil {
		f.lock.Close()
		f.lock = nil
	}
	f.active = false
}
func (f *nodeLifecycleFixture) run(ctx context.Context, name string, args ...string) (string, error) {
	if strings.Join(args, " ") == "--user show --property=Version --value" {
		return "255.4\n", nil
	}
	if name == "/usr/bin/systemd-run" {
		f.starts++
		f.startArgs = append([]string(nil), args...)
		if f.fail {
			return "", errors.New("synthetic start failure")
		}
		return "", f.start()
	}
	if len(args) > 1 && args[1] == "stop" {
		f.stops++
		f.stop()
		return "", nil
	}
	if len(args) > 1 && args[1] == "reset-failed" {
		return "", nil
	}
	if len(args) > 1 && args[1] == "show" {
		if !f.active && !f.foreign {
			return "LoadState=not-found\nActiveState=inactive\nMainPID=0\n", errors.New("not found")
		}
		data, _ := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
		owner := nodeServiceOwner(data)
		if f.foreign {
			owner = "SYNTHETIC other owner"
		}
		return fmt.Sprintf("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=%d\nTransient=yes\nDescription=%s\n", os.Getpid(), owner), nil
	}
	return "", errors.New("unexpected command")
}
func (f *nodeLifecycleFixture) command(action string, out io.Writer, args ...string) error {
	return nodeLifecycle(action, append([]string{"--user-root", f.c.UserRoot}, args...), out, f.c.Binary, f.run)
}

func TestNodeLifecycleClosedConfigurationAndLiteralArguments(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	if requireExistingNodeServiceState(f.c, f.s) != nil {
		t.Fatal("existing fixture rejected")
	}
	for _, tail := range [][]string{{"--once"}, {"--retry-pairing"}, {"--hubs-file", "/synthetic/secret"}, {"--pqtls-config", "/synthetic/secret"}, {"--token", "SYNTHETIC-DO-NOT-LOG"}, {"--id", "other"}, {"--lan-discovery"}} {
		if _, _, err := canonicalNodeServiceArgs(f.c.UserRoot, append(append([]string(nil), f.c.AgentArgs...), tail...)); err == nil {
			t.Fatal("unsupported or duplicate flag accepted", tail[0])
		}
	}
	if err := f.command("off", io.Discard, "--user-root", f.c.UserRoot); !errors.Is(err, errNodeServiceConfig) {
		t.Fatal("duplicate outer root accepted", err)
	}
	c := f.c
	c.AgentArgs = append([]string(nil), f.c.AgentArgs...)
	c.AgentArgs[5] = "SYNTHETIC $(touch forbidden) $HOME %n"
	canonical, s, err := canonicalNodeServiceArgs(c.UserRoot, c.AgentArgs)
	if err != nil {
		t.Fatal(err)
	}
	c.AgentArgs = canonical
	args := nodeServiceStartArgs(c, nodeServiceUnit(c, s), "SYNTHETIC owner")
	joined := strings.Join(args, "\n")
	for _, required := range []string{"--expand-environment=no", "--property=Type=exec", "--property=Restart=no", "--property=UMask=0077", "SYNTHETIC $(touch forbidden) $HOME %n"} {
		if !strings.Contains(joined, required) {
			t.Fatal("missing literal argument or safety setting", required)
		}
	}
	for _, arg := range args {
		if strings.Contains(arg, "enable") || strings.Contains(arg, "linger") || arg == "--scope" {
			t.Fatal("implicit policy/service change")
		}
	}
	var decoded nodeServiceConfig
	data, _ := json.Marshal(f.c)
	for _, raw := range [][]byte{append([]byte(`{"format":"duplicate",`), data[1:]...), append(data, []byte(` {}`)...), []byte(strings.Replace(string(data), `"format":`, `"unknown":1,"format":`, 1))} {
		if decodeLocalNodeJSON(raw, &decoded) == nil {
			t.Fatal("ambiguous/unknown config accepted")
		}
	}
}

func TestNodeLifecycleOnOffRestartPreservesOriginalStateAndIdentity(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	// First on is the only configuration producer; capture the original
	// explicit runtime environment, without touching shell files.
	t.Setenv("PATH", f.c.Path)
	t.Setenv("CODEX_HOME", "")
	before, err := recoveryTreeDigest(machineNodeStateDir(f.s.state, f.s.id))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	first := append([]string{"--codex-bin", f.c.CodexBin, "--"}, f.c.AgentArgs...)
	if err := f.command("on", &output, first...); err != nil {
		t.Fatal(err)
	}
	var status nodeServiceStatus
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &status) != nil || status.State != "running" || status.HubOnline != "unknown" {
		t.Fatal("false process/Hub status")
	}
	data, _ := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
	if decodeLocalNodeJSON(data, &f.c) != nil {
		t.Fatal("cannot recover exact configuration")
	}
	info, _ := os.Stat(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
	if info.Mode().Perm() != 0600 {
		t.Fatal("public service configuration")
	}
	for _, action := range []string{"on", "status", "off", "off", "on", "off"} {
		if err := f.command(action, io.Discard); err != nil {
			t.Fatal(action, err)
		}
	}
	if f.starts != 2 || f.stops != 2 {
		t.Fatal("not idempotent", f.starts, f.stops)
	}
	after, err := recoveryTreeDigest(machineNodeStateDir(f.s.state, f.s.id))
	if err != nil || after != before {
		t.Fatal("controller changed product identity/state")
	}
	dataAfter, _ := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
	if !bytes.Equal(data, dataAfter) {
		t.Fatal("restart rewrote configuration")
	}
	if err := f.command("on", io.Discard, "--codex-bin", "/usr/bin/false"); !errors.Is(err, errNodeServiceConfig) {
		t.Fatal("Codex drift accepted", err)
	}
	other := f.c
	other.UserRoot = privateLocalNodeRoot(t)
	if nodeServiceUnit(other, f.s) == nodeServiceUnit(f.c, f.s) {
		t.Fatal("custom roots share a unit")
	}
}

func TestNodeLifecycleForegroundAndForeignUnitNeverStopped(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	f.save(t)
	lock, err := nodelock.AcquireAgent(f.s.state, f.s.id)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := f.command("on", io.Discard); !errors.Is(err, errNodeServiceConflict) {
		t.Fatal("foreground collected or ignored", err)
	}
	var output bytes.Buffer
	if err := f.command("status", &output); err != nil || !strings.Contains(output.String(), `"unmanaged_agent_running":true`) {
		t.Fatal("foreground hidden", err)
	}
	output.Reset()
	if err := f.command("off", &output); !errors.Is(err, errNodeServiceConflict) || f.stops != 0 || !strings.Contains(output.String(), `"unmanaged_agent_running":true`) {
		t.Fatal("off touched foreground", err)
	}
	f.foreign = true
	if err := f.command("off", io.Discard); !errors.Is(err, errNodeServiceConflict) || f.stops != 0 {
		t.Fatal("off touched foreign unit", err)
	}
}

func TestNodeLifecycleFailuresNeverGreenAndPrivateConfigRequired(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	f.save(t)
	if err := nodeLifecycle("status", []string{"--user-root", f.c.UserRoot}, io.Discard, f.c.Binary, func(context.Context, string, ...string) (string, error) { return "", errors.New("no user bus") }); !errors.Is(err, errNodeServiceManager) {
		t.Fatal("no bus became success", err)
	}
	f.fail = true
	if err := f.command("on", io.Discard); !errors.Is(err, errNodeServiceFailed) {
		t.Fatal("start failure became success", err)
	}
	f.active = true
	if err := f.command("status", io.Discard); !errors.Is(err, errNodeServiceFailed) {
		t.Fatal("active without live agent became success", err)
	}
	f.active = false
	path := filepath.Join(f.c.UserRoot, nodeServiceConfigName)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.command("off", io.Discard); !errors.Is(err, errNodeServiceConfig) {
		t.Fatal("public config accepted", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if err := f.command("off", io.Discard); !errors.Is(err, errNodeServiceConfig) {
		t.Fatal("symlink config accepted", err)
	}
}

func TestNodeLifecycleReadyRequiresExactPeerPID(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	if err := readyNodeService(context.Background(), f.c, f.s, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if err := readyNodeService(context.Background(), f.c, f.s, os.Getpid()+1); err == nil {
		t.Fatal("unrelated MainPID borrowed live bridge")
	}
}

func TestNodeLifecycleAddressOnlyRetainsOriginalOriginAndNeedsRealACK(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	var original []string
	for i := 0; i < len(f.c.AgentArgs); i++ {
		if f.c.AgentArgs[i] == "--control-url" {
			i++
			continue
		}
		original = append(original, f.c.AgentArgs[i])
	}
	original = append(original, "--hub-address", f.client.state.HubDialAddress)
	before, err := recoveryTreeDigest(machineNodeStateDir(f.s.state, f.s.id))
	if err != nil {
		t.Fatal(err)
	}
	canonical, selection, err := canonicalNodeServiceArgs(f.c.UserRoot, original)
	if err != nil || selection.origin != f.s.origin || selection.address != f.client.state.HubDialAddress {
		t.Fatal("address-only input lost original trusted origin/locator", err)
	}
	if !strings.Contains(strings.Join(canonical, " "), "--hub-address "+selection.address) || strings.Contains(strings.Join(canonical, " "), "--hub-dial-address") {
		t.Fatal("original pairing mode was rewritten")
	}
	c := f.c
	c.AgentArgs = canonical
	// This legacy native-TLS fixture has no NPT journal. Never manufacture ACK
	// evidence or silently turn it into a successful new-NPT service fixture.
	if requireExistingNodeServiceState(c, selection) == nil {
		t.Fatal("missing NPT ACK accepted")
	}
	after, err := recoveryTreeDigest(machineNodeStateDir(f.s.state, f.s.id))
	if err != nil || before != after {
		t.Fatal("origin selection or ACK refusal rewrote original state")
	}
}

func TestNodeLifecycleLostStartResponseRecoversSameService(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	f.save(t)
	lost := true
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		result, err := f.run(ctx, name, args...)
		if name == "/usr/bin/systemd-run" && err == nil && lost {
			lost = false
			return "", errors.New("SYNTHETIC response lost after start")
		}
		return result, err
	}
	args := []string{"--user-root", f.c.UserRoot}
	if err := nodeLifecycle("on", args, io.Discard, f.c.Binary, run); !errors.Is(err, errNodeServiceFailed) {
		t.Fatal("lost start response not uncertain", err)
	}
	if err := nodeLifecycle("on", args, io.Discard, f.c.Binary, run); err != nil || f.starts != 1 {
		t.Fatal("retry started a second service", err, f.starts)
	}
}

func TestNodeLifecycleConcurrentControllerRefusesWithoutManagerMutation(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	f.save(t)
	root, err := openLocalNodeDirectory(context.Background(), f.c.UserRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := lockNodeService(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := f.command("off", io.Discard); err == nil || !strings.Contains(err.Error(), "NODE_SERVICE_BUSY") {
		t.Fatal("concurrent operation admitted", err)
	}
	if f.stops != 0 || f.starts != 0 {
		t.Fatal("busy operation mutated manager")
	}
}

// The opt-in acceptance below runs the real machine agent in a distinct
// systemd-owned process. The tiny launcher only selects this Go test helper;
// agent arguments and original synthetic keys are passed unchanged.
func TestNodeLifecycleAgentProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" && len(os.Args) > i+3 && os.Args[i+1] == "machine" && os.Args[i+2] == "agent" {
			if err := runMachineAgent(os.Args[i+3:]); err != nil {
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
}

func TestNodeLifecycleActualUserService(t *testing.T) {
	if os.Getenv("CICADA_NODE_LIFECYCLE_SYSTEMD_ACCEPTANCE") != "1" {
		t.Skip("NOT_RUN: explicit isolated user-service acceptance required")
	}
	f := newNodeLifecycleFixture(t)
	version, err := runNodeServiceCommand(context.Background(), "/usr/bin/systemctl", "--user", "show", "--property=Version", "--value")
	if err != nil {
		t.Skip("NOT_RUN: systemd user bus unavailable")
	}
	major, _ := strconv.Atoi(strings.Split(strings.TrimSpace(version), ".")[0])
	if major < 254 {
		t.Skip("NOT_RUN: systemd user manager older than 254")
	}
	launcher := filepath.Join(f.c.UserRoot, "synthetic-agent-launcher")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	script := "#!/bin/sh\nexec " + quote(f.c.Binary) + " -test.run='^TestNodeLifecycleAgentProcess$' -- \"$@\"\n"
	if err := os.WriteFile(launcher, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	f.c.Binary = launcher
	f.save(t)
	t.Log("owned fixture unit", nodeServiceUnit(f.c, f.s))
	run := func(action string, out io.Writer) error {
		return nodeLifecycle(action, []string{"--user-root", f.c.UserRoot}, out, launcher, runNodeServiceCommand)
	}
	t.Cleanup(func() {
		if err := run("off", io.Discard); err != nil {
			t.Error("owned service cleanup", err)
		}
	})
	keyPath, _ := machineNodeControlPaths(f.s.state, f.s.id)
	keyBefore, _ := os.ReadFile(keyPath)
	credentialBefore, _ := os.ReadFile(machineNodeCredentialPath(f.s.state, f.s.id))
	var first, second nodeServiceStatus
	for i, action := range []string{"on", "on", "status", "off", "off", "on", "off"} {
		var out bytes.Buffer
		if err := run(action, &out); err != nil {
			t.Fatal(action, err)
		}
		var status nodeServiceStatus
		if json.Unmarshal(out.Bytes(), &status) != nil || status.HubOnline != "unknown" {
			t.Fatal("invalid status")
		}
		if i == 0 {
			first = status
		}
		if i == 1 {
			second = status
		}
		if action == "off" && status.State != "stopped" || action != "off" && status.State != "running" {
			t.Fatal("incorrect state", action, status.State)
		}
	}
	if first.MainPID <= 0 || first.MainPID != second.MainPID {
		t.Fatal("repeat on changed process")
	}
	keyAfter, _ := os.ReadFile(keyPath)
	credentialAfter, _ := os.ReadFile(machineNodeCredentialPath(f.s.state, f.s.id))
	if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(credentialBefore, credentialAfter) {
		t.Fatal("service restart replaced identity")
	}
	// Prove both processes were original-agent services, not the parent fixture.
	if reflect.DeepEqual(first.MainPID, os.Getpid()) {
		t.Fatal("borrowed parent agent")
	}
	// An actual service process exits unsuccessfully; status cannot report
	// running and off must safely clear only this owned failed transient unit.
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := run("on", io.Discard); !errors.Is(err, errNodeServiceFailed) {
		t.Fatal("actual service failure was green", err)
	}
	if err := run("status", io.Discard); !errors.Is(err, errNodeServiceFailed) {
		t.Fatal("actual failed status was green", err)
	}
	if err := run("off", io.Discard); err != nil {
		t.Fatal("failed owned unit could not stop", err)
	}
	data, _ := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
	state, err := inspectNodeService(context.Background(), runNodeServiceCommand, nodeServiceUnit(f.c, f.s), nodeServiceOwner(data))
	if err != nil || state["MainPID"] != "0" || state["ActiveState"] != "inactive" {
		t.Fatal("owned fixture not cleaned", err)
	}
	t.Log("owned fixture cleanup", "MainPID=0", "ActiveState=inactive", "LoadState="+state["LoadState"])
}
