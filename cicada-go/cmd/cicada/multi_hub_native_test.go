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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMCPSealedNativeThreadJoinsTwoIndependentHubsNative is an opt-in native
// integration test. It uses one real Codex Thread and two independent
// production Fabric Handler/Store instances served over TCP. One real
// multi-Hub Node Agent process opens a separate local bridge for each Hub.
// This is a same-process, same-OS-user test; it does not claim Docker or
// physical-machine isolation. It makes provider calls and is never run by the
// default deterministic test suite.
func TestMCPSealedNativeThreadJoinsTwoIndependentHubsNative(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CICADA_MULTI_HUB_NATIVE_E2E")) != "1" {
		t.Skip("set CICADA_MULTI_HUB_NATIVE_E2E=1 to run the real Codex multi-Hub Join test")
	}
	codexBinary, cicadaBinary := nativeE2EBinaries(t)
	if !nativeE2EHasCredentials() {
		t.Skip("Codex provider credentials are unavailable (expected API_KEY/OPENAI_API_KEY or CODEX_HOME/auth.json)")
	}

	ctx, cancel := nativeE2EContext(t)
	defer cancel()
	suffix, err := nativeE2ESuffix()
	if err != nil {
		t.Fatal("create isolated native test identities")
	}
	nodeID := "mh_" + suffix[:8]
	hubA := newMultiHubServiceFixture(t, "native_a_"+suffix, nodeID)
	hubB := newMultiHubServiceFixture(t, "native_b_"+suffix, nodeID)
	if hubA.hubID == hubB.hubID || hubA.httpServer.URL == hubB.httpServer.URL || hubA.nodeToken == hubB.nodeToken {
		t.Fatal("multi-Hub native fixture reused a Hub coordinate, TCP origin, or Node credential")
	}
	groupA := "group_mh_a_" + suffix
	groupB := "group_mh_b_" + suffix
	for _, item := range []struct {
		fixture *multiHubServiceFixture
		groupID string
	}{
		{hubA, groupA}, {hubB, groupB},
	} {
		if _, err := item.fixture.database.CreateGroup(store.Group{
			ID: item.groupID, Name: "Synthetic multi-Hub native Group", OwnerPrincipalID: item.fixture.ownerID,
			TrustDomainID: item.fixture.ownerID, State: store.GroupStateActive,
			ContextPolicy: "group_scoped",
		}); err != nil {
			t.Fatalf("create isolated Group in %s Hub: %v", item.fixture.name, err)
		}
	}
	for _, pair := range []struct {
		fixture *multiHubServiceFixture
		foreign string
	}{{hubA, hubB.nodeToken}, {hubB, hubA.nodeToken}} {
		if authenticated, err := pair.fixture.service.AuthenticateNode(pair.fixture.nodeToken); err != nil || authenticated != nodeID {
			t.Fatalf("%s rejected its own Node credential: authenticated=%q err=%v", pair.fixture.name, authenticated, err)
		}
		if _, err := pair.fixture.service.AuthenticateNode(pair.foreign); !errors.Is(err, fabric.ErrUnauthenticated) {
			t.Fatalf("%s accepted the other Hub's Node credential", pair.fixture.name)
		}
	}

	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal("protect disposable multi-Hub state root")
	}
	entries := []machineHubConfig{
		{HubID: hubA.hubID, ControlURL: hubA.httpServer.URL, NodeID: nodeID, Name: "synthetic native Hub A"},
		{HubID: hubB.hubID, ControlURL: hubB.httpServer.URL, NodeID: nodeID, Name: "synthetic native Hub B"},
	}
	configPath := filepath.Join(stateRoot, "hubs.json")
	encoded, err := json.Marshal(machineHubConfigFile{Version: 1, Hubs: entries})
	if err != nil {
		t.Fatal("encode disposable multi-Hub registry")
	}
	if err := os.WriteFile(configPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal("write disposable multi-Hub registry")
	}
	stateA, stateB := machineHubStateDir(stateRoot, entries[0]), machineHubStateDir(stateRoot, entries[1])
	if stateA == stateB {
		t.Fatal("multi-Hub Node state directories are not isolated")
	}
	socketBytesA := len([]byte(machineAgentJoinSocketPath(stateA, nodeID)))
	socketBytesB := len([]byte(machineAgentJoinSocketPath(stateB, nodeID)))
	maxSocketBytes := socketBytesA
	if socketBytesB > maxSocketBytes {
		maxSocketBytes = socketBytesB
	}
	if maxSocketBytes > machineAgentJoinSocketMaxPathBytes() {
		t.Fatalf("multi-Hub fixture Unix socket path exceeds the platform pathname limit: max_bytes=%d limit=%d",
			maxSocketBytes, machineAgentJoinSocketMaxPathBytes())
	}
	if !machineAgentJoinSocketUsesPrivateRuntime(machineAgentJoinSocketPath(stateA, nodeID)) ||
		!machineAgentJoinSocketUsesPrivateRuntime(machineAgentJoinSocketPath(stateB, nodeID)) {
		t.Fatal("long multi-Hub Node scopes did not use the private bounded socket paths")
	}
	t.Logf("multi-Hub fixture Unix socket path bytes=%d limit=%d", maxSocketBytes, machineAgentJoinSocketMaxPathBytes())
	for _, pair := range []struct {
		state string
		token string
	}{{stateA, hubA.nodeToken}, {stateB, hubB.nodeToken}} {
		identityPath := filepath.Join(machineNodeStateDir(pair.state, nodeID), "identity.json")
		if err := persistMachineNodeIdentity(identityPath, machineNodeCredentialPath(pair.state, nodeID),
			&machineNodeIdentity{Version: machineNodeIdentityVersion, NodeID: nodeID, RelayToken: pair.token}); err != nil {
			t.Fatal("prepare independent disposable Hub Node identity")
		}
	}
	t.Setenv("CICADA_MACHINE_ID", nodeID)
	t.Setenv("CICADA_HUB_ID", "")
	t.Setenv("CICADA_NODE_TOKEN", "")
	t.Setenv("CICADA_NODE_STATE_DIR", "")
	t.Setenv("CICADA_MCP_STATE_DIR", "")
	t.Setenv("CICADA_MCP_SESSION_STATE_FILE", "")
	t.Setenv("CICADA_SESSION_STATE_DIR", "")
	t.Setenv("CICADA_STATE_DIR", "")
	t.Setenv("CICADA_API_URL", "")
	t.Setenv("CICADA_API_TOKEN", "")
	t.Setenv("CICADA_API_TOKEN_FILE", "")
	t.Setenv("CICADA_ENDPOINT_ID", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_GROUP_ID", "")
	t.Setenv("CICADA_HARNESS", "codex")

	agent := startNativeMultiHubAgent(t, cicadaBinary, configPath, stateRoot)
	waitForNativeMultiHubAgent(t, ctx, agent, hubA, hubB, stateA, stateB, nodeID)
	if strings.TrimSpace(os.Getenv("CICADA_MULTI_HUB_NATIVE_STARTUP_ONLY")) == "1" {
		t.Skip("multi-Hub bridges are ready; startup-only diagnostic stopped before Codex provider calls")
	}

	workspace := nativeE2EWorkspace(t, "native-multi-hub-workspace-")
	model := strings.TrimSpace(os.Getenv("CICADA_NATIVE_MODEL"))
	if model == "" {
		model = "gpt-5.6-luna"
	}
	createConfig := nativeCodexConfig(cicadaBinary, hubA.httpServer.URL, stateA,
		filepath.Join(stateA, "mcp"), nodeID, false, "")
	created, nativeThreadID, err := runNativeCodexTurn(ctx, codexBinary, workspace, model,
		createConfig, "", "Create this one native Codex Thread for a controlled CICADA multi-Hub integration test. Do not use tools. Reply READY.")
	if err != nil {
		t.Fatalf("real Codex Thread creation failed (%s); native events=%s", nativeThreadID,
			nativeE2EEventSummary(created))
	}
	if err := verifyCodexSessionRecord(nativeThreadID, workspace); err != nil {
		t.Fatalf("thread.started UUID has no matching Codex session record before either Hub Join: %v", err)
	}

	joinOnHub := func(fixture *multiHubServiceFixture, entry machineHubConfig, hubState, groupID string) ([]byte, *nodeinbox.NativeContextScopeDecision) {
		t.Helper()
		base := nativeCodexConfig(cicadaBinary, entry.ControlURL, hubState,
			filepath.Join(hubState, "mcp"), nodeID, true, nativeThreadID)
		selected, err := nativeMultiHubCodexConfig(base, entry.HubID, configPath, stateRoot, groupID)
		if err != nil {
			t.Fatalf("build exact local Hub selection for %s: %v", fixture.name, err)
		}
		prompt := fmt.Sprintf("This MCP process is pinned to one exact Cicada Hub. In this same Thread, call cicada_join exactly once with group_id %q. When it succeeds, call cicada_whoami exactly once with no arguments. Do not use another tool. Finish with READY only after both tools succeed.", groupID)
		output, resumedID, err := runNativeCodexTurn(ctx, codexBinary, workspace, model, selected, nativeThreadID, prompt)
		if err != nil {
			t.Fatalf("Codex resume for %s failed (%s); events=%s; tool_failures=%s", fixture.name,
				resumedID, nativeE2EEventSummary(output), nativeE2EToolFailures(output))
		}
		if resumedID != nativeThreadID {
			t.Fatalf("Codex changed native Thread while selecting %s", fixture.name)
		}
		if err := verifyCodexSessionRecord(resumedID, workspace); err != nil {
			t.Fatalf("Codex Thread record changed after %s resume: %v", fixture.name, err)
		}
		joinResult := requireNativeMultiHubTool(t, output, "cicada_join", fixture.name)
		requireNativeMultiHubTool(t, output, "cicada_whoami", fixture.name)
		decision := nativeMultiHubScopeDecision(joinResult)
		if decision == nil || !decision.Accepted || decision.ContextPolicy != "group_scoped" ||
			decision.NativeHistoryCoverage != nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly {
			t.Fatalf("%s Join did not return the bounded current native-scope decision", fixture.name)
		}
		return output, decision
	}

	_, scopeA := joinOnHub(hubA, entries[0], stateA, groupA)
	if scopeA.SharedMemoryRisk || scopeA.KnownScopeCount != 1 {
		t.Fatalf("first Hub scope decision did not describe one known ordinary scope: %#v", scopeA)
	}
	_, scopeB := joinOnHub(hubB, entries[1], stateB, groupB)
	if !scopeB.SharedMemoryRisk || scopeB.KnownScopeCount != 2 {
		t.Fatalf("second Hub failed to report reuse of this native Thread across known Hub scopes: %#v", scopeB)
	}

	endpointA, err := nativeE2ECurrentSession(hubA.database, nativeThreadID, workspace, nodeID, groupA)
	if err != nil {
		t.Fatalf("Hub A did not persist the real joined Thread binding: %v", err)
	}
	endpointB, err := nativeE2ECurrentSession(hubB.database, nativeThreadID, workspace, nodeID, groupB)
	if err != nil {
		t.Fatalf("Hub B did not persist the same real joined Thread binding independently: %v", err)
	}
	if endpointA.ID == endpointB.ID || endpointA.GroupID != groupA || endpointB.GroupID != groupB {
		t.Fatal("the two Hubs did not retain separate Endpoint identities and Group selections")
	}
	bindingA, err := hubA.database.GetSessionBindingByNativeSession(nativeThreadID)
	if err != nil || bindingA.EndpointID != endpointA.ID || bindingA.Epoch == 0 {
		t.Fatal("Hub A did not retain a current native session binding")
	}
	bindingB, err := hubB.database.GetSessionBindingByNativeSession(nativeThreadID)
	if err != nil || bindingB.EndpointID != endpointB.ID || bindingB.Epoch == 0 {
		t.Fatal("Hub B did not retain a current native session binding")
	}
	if err := verifyCodexSessionRecord(nativeThreadID, workspace); err != nil {
		t.Fatalf("shared native Thread session record was not preserved after both Joins: %v", err)
	}

	sessionContext := harness.SessionContext{Harness: "codex", NativeSessionID: nativeThreadID,
		MachineID: nodeID, Workspace: workspace}
	cacheA, err := newMCPSessionStateStore(filepath.Join(stateA, "mcp", "sessions.json")).load(hubA.httpServer.URL, sessionContext)
	if err != nil {
		t.Fatal("load Hub A's local MCP credential cache")
	}
	cacheB, err := newMCPSessionStateStore(filepath.Join(stateB, "mcp", "sessions.json")).load(hubB.httpServer.URL, sessionContext)
	if err != nil {
		t.Fatal("load Hub B's local MCP credential cache")
	}
	if cacheA == nil || cacheB == nil || cacheA.SessionToken == "" || cacheB.SessionToken == "" ||
		cacheA.SessionToken == cacheB.SessionToken || cacheA.EndpointID != endpointA.ID ||
		cacheB.EndpointID != endpointB.ID || cacheA.GroupID != groupA || cacheB.GroupID != groupB ||
		cacheA.NativeSessionID != nativeThreadID || cacheB.NativeSessionID != nativeThreadID {
		t.Fatal("Hub-specific MCP caches did not retain independent credentials for the exact native Thread")
	}
	cardA := nativeMultiHubWhoAmI(t, hubA, cacheA, groupA)
	cardB := nativeMultiHubWhoAmI(t, hubB, cacheB, groupB)
	if cardA.EndpointID != endpointA.ID || cardA.GroupID != groupA || cardA.NodeID != nodeID ||
		cardA.NativeSessionID != nativeThreadID || cardB.EndpointID != endpointB.ID ||
		cardB.GroupID != groupB || cardB.NodeID != nodeID || cardB.NativeSessionID != nativeThreadID {
		t.Fatal("exact Hub selection returned a WhoAmI identity from the wrong Hub or native Thread")
	}
	if status := nativeMultiHubWhoAmIStatus(t, hubB, cacheA.SessionToken, groupB); status != http.StatusUnauthorized {
		t.Fatalf("Hub B accepted Hub A's session credential: HTTP %d, want 401", status)
	}

	// Replay ledgers remain per-Hub even when the record is keyed by the same
	// real native Thread and message coordinate. The payload here is synthetic;
	// it is not a delivered conversation or proof of native injection.
	messageID := "multi_hub_native_replay_" + suffix
	for _, item := range []struct {
		state    string
		endpoint string
		digest   string
		epoch    uint64
	}{{stateA, endpointA.ID, "synthetic-hub-a-digest", bindingA.Epoch},
		{stateB, endpointB.ID, "synthetic-hub-b-digest", bindingB.Epoch}} {
		inbox, err := nodeinbox.Open(machineNodeInboxPath(item.state, nodeID))
		if err != nil {
			t.Fatal("open per-Hub replay ledger")
		}
		_, created, saveErr := inbox.Save(context.Background(), nodeinbox.Message{
			MessageID: messageID, Digest: item.digest, EndpointID: item.endpoint,
			SessionID: nativeThreadID, BindingEpoch: item.epoch,
			Payload: []byte("synthetic native multi-Hub replay record"),
		})
		closeErr := inbox.Close()
		if saveErr != nil || !created || closeErr != nil {
			t.Fatalf("persist isolated replay metadata: created=%t save=%v close=%v", created, saveErr, closeErr)
		}
	}
	for _, item := range []struct {
		state  string
		digest string
	}{{stateA, "synthetic-hub-a-digest"}, {stateB, "synthetic-hub-b-digest"}} {
		inbox, err := nodeinbox.Open(machineNodeInboxPath(item.state, nodeID))
		if err != nil {
			t.Fatal("reopen per-Hub replay ledger")
		}
		message, getErr := inbox.Get(context.Background(), messageID)
		closeErr := inbox.Close()
		if getErr != nil || closeErr != nil || message.Digest != item.digest || message.SessionID != nativeThreadID {
			t.Fatal("one Hub's replay journal overwrote or revealed the other Hub's record")
		}
	}
	for _, fixture := range []*multiHubServiceFixture{hubA, hubB} {
		if fixture.controlRequests.Load() != 0 || fixture.badNodeAuth.Load() != 0 {
			t.Fatalf("%s used Control or received a foreign Node credential", fixture.name)
		}
		if fixture.requestCount(http.MethodPost, "/v2/fabric/node/join") == 0 ||
			fixture.requestCount(http.MethodGet, "/v2/fabric/whoami") == 0 {
			t.Fatalf("%s did not receive explicit production Join and WhoAmI requests", fixture.name)
		}
	}
}

func nativeMultiHubCodexConfig(base []string, hubID, hubsFile, stateRoot, groupID string) ([]string, error) {
	if strings.TrimSpace(hubID) == "" || strings.TrimSpace(hubsFile) == "" ||
		strings.TrimSpace(stateRoot) == "" || strings.TrimSpace(groupID) == "" {
		return nil, fmt.Errorf("exact Hub, registry, state root, and Group are required")
	}
	config := append([]string(nil), base...)
	argsIndexes := []int{}
	for index := 0; index+1 < len(config); index++ {
		if config[index] == "--config" && strings.HasPrefix(config[index+1], "mcp_servers.cicada.args=") {
			argsIndexes = append(argsIndexes, index+1)
		}
	}
	if len(argsIndexes) != 1 {
		return nil, fmt.Errorf("base Codex config must contain exactly one Cicada MCP args setting")
	}
	args, err := json.Marshal([]string{"mcp", "--hub-id", hubID, "--hubs-file", hubsFile, "--state-root", stateRoot})
	if err != nil {
		return nil, fmt.Errorf("encode exact multi-Hub MCP selection: %w", err)
	}
	config[argsIndexes[0]] = "mcp_servers.cicada.args=" + string(args)
	return append(config, "--config", "mcp_servers.cicada.env.CICADA_GROUP_ID="+strconv.Quote(groupID)), nil
}

func TestNativeMultiHubCodexConfigUsesExactHubSelection(t *testing.T) {
	base := []string{"--config", "mcp_servers.cicada.enabled=true", "--config", `mcp_servers.cicada.args=["mcp"]`}
	config, err := nativeMultiHubCodexConfig(base, "hub-synthetic-a", "/private/hubs.json",
		"/private/state", "group-synthetic-a")
	if err != nil {
		t.Fatal("construct pinned multi-Hub MCP configuration:", err)
	}
	var args []string
	for index := 0; index+1 < len(config); index++ {
		if config[index] == "--config" && strings.HasPrefix(config[index+1], "mcp_servers.cicada.args=") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(config[index+1], "mcp_servers.cicada.args=")), &args); err != nil {
				t.Fatal("decode pinned MCP args:", err)
			}
		}
	}
	want := []string{"mcp", "--hub-id", "hub-synthetic-a", "--hubs-file", "/private/hubs.json", "--state-root", "/private/state"}
	if len(args) != len(want) {
		t.Fatalf("MCP arguments=%#v, want exact multi-Hub selection", args)
	}
	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("MCP arguments=%#v, want exact multi-Hub selection %#v", args, want)
		}
	}
	if config[len(config)-2] != "--config" ||
		config[len(config)-1] != "mcp_servers.cicada.env.CICADA_GROUP_ID="+strconv.Quote("group-synthetic-a") {
		t.Fatal("MCP config did not pin the trusted synthetic Group for the selected Hub")
	}
	if len(base) != 4 || base[3] != `mcp_servers.cicada.args=["mcp"]` {
		t.Fatal("multi-Hub configuration mutated the caller's base Codex config")
	}
}

func TestNativeMultiHubAgentCommandUsesMachineAgentEntry(t *testing.T) {
	stateRoot := t.TempDir()
	missingConfig := filepath.Join(t.TempDir(), "missing-hubs.json")
	args := nativeMultiHubAgentArgs(missingConfig, stateRoot)
	err := clientCommand(args)
	if err == nil || !strings.Contains(err.Error(), "multi-Hub config must be a bounded regular file") {
		t.Fatalf("multi-Hub agent args did not reach the production machine agent parser: %v", err)
	}
}

func TestNativeMultiHubUnixSocketPathFitsLinuxLimit(t *testing.T) {
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := machineHubConfig{HubID: "hub-synthetic", ControlURL: "http://127.0.0.1:8787", NodeID: "mh_12345678"}
	pathBytes := len([]byte(machineAgentJoinSocketPath(machineHubStateDir(stateRoot, entry), entry.NodeID)))
	if pathBytes == 0 || pathBytes > machineAgentJoinSocketMaxPathBytes() {
		t.Fatalf("multi-Hub fixture Unix socket path bytes=%d, want 1..%d", pathBytes, machineAgentJoinSocketMaxPathBytes())
	}
	if !machineAgentJoinSocketUsesPrivateRuntime(machineAgentJoinSocketPath(machineHubStateDir(stateRoot, entry), entry.NodeID)) {
		t.Fatal("normal multi-Hub state root did not use the bounded private socket fallback")
	}
}

func TestNativeMultiHubAgentStartupDiagnosticIsBoundedAndClassified(t *testing.T) {
	diagnostic := &nativeMultiHubAgentDiagnostic{}
	input := append([]byte("unknown command "), bytes.Repeat([]byte("x"), nativeMultiHubAgentDiagnosticLimit+1)...)
	written, err := diagnostic.Write(input)
	if err != nil || written != len(input) || len(diagnostic.data) != nativeMultiHubAgentDiagnosticLimit {
		t.Fatalf("startup diagnostic was not bounded: written=%d retained=%d err=%v", written, len(diagnostic.data), err)
	}
	if got := nativeMultiHubAgentStartupDiagnosticClass(diagnostic.data); got != "CLI_COMMAND_ROUTING" {
		t.Fatalf("startup diagnostic class=%q, want CLI_COMMAND_ROUTING", got)
	}
}

type nativeMultiHubAgentProcess struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
	stderr  *nativeMultiHubAgentDiagnostic
}

const nativeMultiHubAgentDiagnosticLimit = 8 * 1024

type nativeMultiHubAgentDiagnostic struct {
	data []byte
}

func (d *nativeMultiHubAgentDiagnostic) Write(data []byte) (int, error) {
	n := len(data)
	remaining := nativeMultiHubAgentDiagnosticLimit - len(d.data)
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		d.data = append(d.data, data...)
	}
	return n, nil
}

func nativeMultiHubAgentStartupDiagnosticClass(stderr []byte) string {
	value := strings.ToLower(string(stderr))
	switch {
	case value == "":
		return "NO_CHILD_DIAGNOSTIC"
	case strings.Contains(value, "unknown command") || strings.Contains(value, "missing command"):
		return "CLI_COMMAND_ROUTING"
	case strings.Contains(value, "flag provided but not defined") || strings.Contains(value, "usage:"):
		return "CLI_ARGUMENT_VALIDATION"
	case strings.Contains(value, "multi-hub config"):
		return "MULTI_HUB_CONFIG_VALIDATION"
	case strings.Contains(value, "secure transport") || strings.Contains(value, "https"):
		return "TRANSPORT_POLICY"
	case strings.Contains(value, "node agent lock"):
		return "NODE_AGENT_LOCK"
	case strings.Contains(value, "local node identity") || strings.Contains(value, "identity.json"):
		return "NODE_IDENTITY_STATE"
	case strings.Contains(value, "unauthorized") || strings.Contains(value, "unauthenticated") || strings.Contains(value, "401"):
		return "HUB_NODE_AUTHORIZATION"
	case strings.Contains(value, "name too long") || strings.Contains(value, "path too long") ||
		strings.Contains(value, "bind: invalid argument"):
		return "LOCAL_UNIX_SOCKET_PATH_LIMIT"
	case strings.Contains(value, "address already in use"):
		return "LOCAL_UNIX_SOCKET_CONFLICT"
	case strings.Contains(value, "listen unix") || strings.Contains(value, "unix socket"):
		return "LOCAL_UNIX_SOCKET_STARTUP"
	case strings.Contains(value, "listen") || strings.Contains(value, "local bridge") || strings.Contains(value, "socket"):
		return "LOCAL_BRIDGE_STARTUP"
	case strings.Contains(value, "sqlite") || strings.Contains(value, "database") || strings.Contains(value, "state directory"):
		return "LOCAL_STATE_STORAGE"
	default:
		return "UNCLASSIFIED_CHILD_ERROR"
	}
}

func nativeMultiHubAgentArgs(configPath, stateRoot string) []string {
	return []string{"machine", "agent", "--hubs-file", configPath, "--state-root", stateRoot,
		"--relay-only", "--interval", "1s"}
}

func startNativeMultiHubAgent(t *testing.T, binary, configPath, stateRoot string) *nativeMultiHubAgentProcess {
	t.Helper()
	command := exec.Command(binary, nativeMultiHubAgentArgs(configPath, stateRoot)...)
	command.Stdout = io.Discard
	diagnostic := &nativeMultiHubAgentDiagnostic{}
	command.Stderr = diagnostic
	if err := command.Start(); err != nil {
		t.Fatalf("start production multi-Hub Node Agent: %v", err)
	}
	process := &nativeMultiHubAgentProcess{command: command, done: make(chan struct{}), stderr: diagnostic}
	go func() {
		process.err = command.Wait()
		close(process.done)
	}()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
		}
		select {
		case <-process.done:
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			<-process.done
		}
	})
	return process
}

func waitForNativeMultiHubAgent(t *testing.T, ctx context.Context, process *nativeMultiHubAgentProcess,
	hubA, hubB *multiHubServiceFixture, stateA, stateB, nodeID string) {
	t.Helper()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	timeout := time.NewTimer(25 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-process.done:
			classification := nativeMultiHubAgentStartupDiagnosticClass(process.stderr.data)
			t.Fatalf("production multi-Hub Node Agent exited before both local bridges became ready: status=%v diagnostic_class=%s",
				process.err, classification)
		default:
		}
		_, errA := os.Stat(machineAgentJoinSocketPath(stateA, nodeID))
		_, errB := os.Stat(machineAgentJoinSocketPath(stateB, nodeID))
		if errA == nil && errB == nil &&
			hubA.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat") > 0 &&
			hubB.requestCount(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat") > 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("test context ended while waiting for both multi-Hub local bridges")
		case <-timeout.C:
			t.Fatal("production multi-Hub Agent did not establish both per-Hub local bridges")
		case <-tick.C:
		}
	}
}

func requireNativeMultiHubTool(t *testing.T, output []byte, wanted, hubName string) json.RawMessage {
	t.Helper()
	completed := 0
	failed := 0
	var result json.RawMessage
	for _, line := range strings.Split(string(output), "\n") {
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type   string          `json:"type"`
				Name   string          `json:"name"`
				Tool   string          `json:"tool"`
				Status string          `json:"status"`
				Result json.RawMessage `json:"result"`
				Output json.RawMessage `json:"output"`
			} `json:"item"`
		}
		if json.Unmarshal([]byte(line), &event) != nil || event.Item.Type != "mcp_tool_call" {
			continue
		}
		name := event.Item.Tool
		if name == "" {
			name = event.Item.Name
		}
		if name != wanted {
			continue
		}
		switch event.Item.Status {
		case "completed":
			if event.Type == "item.completed" {
				completed++
				result = event.Item.Result
				if len(bytes.TrimSpace(result)) == 0 || bytes.Equal(bytes.TrimSpace(result), []byte("null")) {
					result = event.Item.Output
				}
			}
		case "failed":
			failed++
		}
	}
	if completed != 1 || failed != 0 {
		t.Fatalf("Codex %s turn did not complete exactly one %s tool call; events=%s; failures=%s",
			hubName, wanted, nativeE2EEventSummary(output), nativeE2EToolFailures(output))
	}
	return result
}

func nativeMultiHubScopeDecision(raw json.RawMessage) *nodeinbox.NativeContextScopeDecision {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	var find func(any, int) *nodeinbox.NativeContextScopeDecision
	find = func(current any, depth int) *nodeinbox.NativeContextScopeDecision {
		if depth > 10 {
			return nil
		}
		switch typed := current.(type) {
		case map[string]any:
			if scope, ok := typed["native_context_scope"]; ok {
				encoded, err := json.Marshal(scope)
				if err != nil {
					return nil
				}
				var decision nodeinbox.NativeContextScopeDecision
				if json.Unmarshal(encoded, &decision) == nil {
					return &decision
				}
			}
			for _, nested := range typed {
				if decision := find(nested, depth+1); decision != nil {
					return decision
				}
			}
		case []any:
			for _, nested := range typed {
				if decision := find(nested, depth+1); decision != nil {
					return decision
				}
			}
		case string:
			var nested any
			if json.Unmarshal([]byte(typed), &nested) == nil {
				return find(nested, depth+1)
			}
		}
		return nil
	}
	return find(value, 0)
}

func nativeMultiHubWhoAmI(t *testing.T, fixture *multiHubServiceFixture,
	session *mcpCachedSession, groupID string) fabric.NetworkCard {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, fixture.httpServer.URL+"/v2/fabric/whoami", nil)
	if err != nil {
		t.Fatal("build exact-Hub WhoAmI request")
	}
	request.Header.Set("Authorization", "CicadaSession "+session.SessionToken)
	request.Header.Set("Cicada-Group-Scope", groupID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("send WhoAmI to explicitly selected Hub origin")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("selected Hub WhoAmI returned HTTP %d", response.StatusCode)
	}
	var card fabric.NetworkCard
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&card); err != nil {
		t.Fatal("decode selected Hub WhoAmI response")
	}
	return card
}

func nativeMultiHubWhoAmIStatus(t *testing.T, fixture *multiHubServiceFixture, token, groupID string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, fixture.httpServer.URL+"/v2/fabric/whoami", nil)
	if err != nil {
		t.Fatal("build cross-Hub WhoAmI request")
	}
	request.Header.Set("Authorization", "CicadaSession "+token)
	request.Header.Set("Cicada-Group-Scope", groupID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("send cross-Hub credential rejection probe")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	return response.StatusCode
}
