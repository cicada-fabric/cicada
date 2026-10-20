package n3_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The actual Node is approved by the actual App child. The parent never reads
// an Owner key, signs a grant or adds database authority. No native session
// record is synthesized here. Actual installed-plugin/CLI acceptance uses this
// same service fixture separately from the process guard checks below.
type codexProductFixture struct {
	*endpointSecurityFixture
	actualNode                                 *nodeProcess
	bound                                      nodeActorState
	environment                                []string
	root, home, codexHome, workspace, mcpState string
}

func newCodexProductFixture(t *testing.T, interval string) *codexProductFixture {
	t.Helper()
	if interval != "1s" && interval != "1h" {
		t.Fatal("unreviewed product fixture reconciliation interval")
	}
	f := newHubFixtureAtProxied(t, "--hub-nodes-only", t.TempDir(), true)
	v := &codexProductFixture{endpointSecurityFixture: newEndpointSecurityAppAt(t, f)}
	v.root = filepath.Join(f.dir, "codex-product")
	v.home, v.codexHome = filepath.Join(v.root, "home"), filepath.Join(v.root, "codex")
	v.workspace, v.mcpState = filepath.Join(v.root, "workspace"), filepath.Join(v.root, "mcp", "sessions.json")
	id := "synthetic-n3-codex-product"
	state := filepath.Join(f.dir, id)
	for _, path := range []string{v.home, v.codexHome, v.workspace, filepath.Dir(v.mcpState), filepath.Join(v.root, "tmp")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal("private product fixture directory unavailable")
		}
	}
	// Use a small explicit environment, never an inherited real account, native
	// SID, Endpoint, Group, token, provider key or developer CODEX_HOME.
	v.environment = []string{"PATH=/out:/usr/local/bin:/usr/bin:/bin", "HOME=" + v.home,
		"CODEX_HOME=" + v.codexHome, "TMPDIR=" + filepath.Join(v.root, "tmp"), "TERM=xterm-256color",
		"LANG=C.UTF-8", "NO_PROXY=*", "CICADA_API_URL=" + f.cfg.Origin,
		"CICADA_MACHINE_ID=" + id, "CICADA_NODE_STATE_DIR=" + state, "CICADA_STATE_DIR=" + state,
		"CICADA_MCP_SESSION_STATE_FILE=" + v.mcpState}
	v.actualNode = startNodeProcessEnvironment(t, f, id, false, v.environment, "--interval", interval)
	pending := v.actualNode.awaitState(t, f, false)
	v.actualNode.kill(t)
	preview := v.do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
	candidate := preview.Node.Candidate
	if candidate == nil || candidate.NodeID != id || candidate.NodeFingerprint != pending.PendingCandidate.NodeFingerprint ||
		candidate.HubControlFingerprint != pending.PendingCandidate.HubFingerprint || candidate.NodeKeyEpoch != pending.PendingCandidate.NodeKeyEpoch ||
		candidate.CandidateVersion != pending.PendingCandidate.Version {
		t.Fatal("actual App review changed the actual Node's original cryptographic candidate")
	}
	approved := v.do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: candidate.ReviewID,
		ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if approved.Node.Binding == nil || approved.Node.Binding.NodeID != id || !approved.Node.Binding.Authorized || !approved.Node.Access.Confirmed {
		t.Fatal("actual App did not approve its exact original Node")
	}
	readyFrom := len(f.proxy.snapshot())
	v.actualNode = startNodeProcessEnvironment(t, f, id, false, v.environment, "--interval", interval)
	v.bound = v.actualNode.awaitState(t, f, true)
	if v.bound.BindingID != approved.Node.Binding.ID || v.bound.BindingVersion != approved.Node.Binding.Version ||
		v.bound.NodeKeyID != pending.PendingCandidate.NodeKeyID || v.bound.NodeFingerprint != pending.PendingCandidate.NodeFingerprint ||
		v.bound.NodeKeyEpoch != candidate.NodeKeyEpoch {
		t.Fatal("actual Node restart replaced its approved identity or binding")
	}
	// Wait for the actual first Relay liveness and empty-queue reconciliation
	// responses after this restart,
	// not merely the old durable binding file. The private bridge is created
	// before this route is reached. No Endpoint lease is inferred from it.
	deadline := time.Now().Add(15 * time.Second)
	ready, heartbeat := false, false
	for time.Now().Before(deadline) {
		for _, ex := range f.proxy.snapshot()[readyFrom:] {
			if ex.Method == http.MethodPost && ex.Path == "/v2/relay/nodes/"+id+"/heartbeat" && ex.Forwarded && ex.Status == http.StatusNoContent {
				heartbeat = true
			}
			if heartbeat && ex.Method == http.MethodPost && ex.Path == "/v2/relay/nodes/"+id+"/claim" && ex.Forwarded && ex.Status == http.StatusOK {
				ready = true
			}
		}
		if ready {
			break
		}
		if !v.actualNode.running() {
			v.actualNode.reportFailure(t)
			t.Fatal("actual Node exited before bridge readiness")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		v.actualNode.reportFailure(t)
		seen := make(map[string]bool)
		for _, ex := range f.proxy.snapshot()[readyFrom:] {
			key := ex.Method + ex.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			t.Logf("CODEX_PRODUCT_NODE_READINESS method=%s path=%s forwarded=%t HTTP=%d", ex.Method, ex.Path, ex.Forwarded, ex.Status)
		}
		t.Fatal("actual Node did not expose bridge/Relay readiness")
	}
	t.Log("CODEX_PRODUCT_PRECONDITION actual_App=true actual_Node=true original_binding=true parent_Owner_signer=false SQL_grant_injection=false Control_inference=false")
	return v
}

// A bounded JSON-RPC client invokes the actual executable over stdio. It does
// not emulate an MCP server, a Node bridge, a Hub result or a context authority.
type codexProductMCP struct {
	p        *process
	in       io.WriteCloser
	replies  chan []byte
	sequence int
	nonce    string
}

type codexProductRPCReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func (v *codexProductFixture) startMCP(t *testing.T) *codexProductMCP {
	t.Helper()
	cmd := exec.Command(os.Getenv("CICADA_N3_CICADA_BINARY"), "mcp", "--codex-context")
	cmd.Env, cmd.Dir = v.environment, v.workspace
	log := must(os.OpenFile(filepath.Join(v.root, "private-mcp.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600))
	t.Cleanup(func() { log.Close() })
	cmd.Stderr = log
	in, out := must(cmd.StdinPipe()), must(cmd.StdoutPipe())
	c := &codexProductMCP{in: in, replies: make(chan []byte, 8)}
	c.p = startProcess(t, cmd)
	t.Cleanup(func() { c.in.Close() })
	go func() {
		defer close(c.replies)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 4096), harnessPacketLimit)
		for scanner.Scan() {
			select {
			case c.replies <- bytes.Clone(scanner.Bytes()):
			case <-c.p.done:
				return
			}
		}
	}()
	c.rpc(t, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "synthetic-cicada-product-acceptance", "version": "1"}})
	_, err := io.WriteString(c.in, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
	if err != nil {
		t.Fatal("actual MCP initialization notification failed")
	}
	var listed struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if json.Unmarshal(c.rpc(t, "tools/list", map[string]any{}), &listed) != nil || len(listed.Tools) == 0 {
		t.Fatal("actual contextual MCP did not advertise its tools")
	}
	foundIdentity := false
	for _, tool := range listed.Tools {
		if tool.Name == "cicada_whoami" {
			foundIdentity = true
		}
		var context struct {
			Properties struct {
				Nonce struct {
					Const string `json:"const"`
				} `json:"connection_nonce"`
			} `json:"properties"`
			Additional *bool `json:"additionalProperties"`
		}
		if json.Unmarshal(tool.InputSchema.Properties["_cicada_context"], &context) != nil || context.Additional == nil || *context.Additional ||
			!containsText(tool.InputSchema.Required, "_cicada_context") || len(context.Properties.Nonce.Const) != 64 {
			t.Fatal("actual MCP tool lacks its required bounded context nonce")
		}
		nonce := context.Properties.Nonce.Const
		if _, err := hex.DecodeString(nonce); err != nil || strings.ToLower(nonce) != nonce || (c.nonce != "" && c.nonce != nonce) {
			t.Fatal("actual MCP tools disagree about their connection nonce")
		}
		c.nonce = nonce
	}
	if !foundIdentity {
		t.Fatal("actual MCP did not advertise the identity tool used by the refusal gate")
	}
	return c
}

func containsText(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (c *codexProductMCP) rpc(t *testing.T, method string, params any) json.RawMessage {
	t.Helper()
	c.sequence++
	raw := must(json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.sequence, "method": method, "params": params}))
	if _, err := c.in.Write(append(raw, '\n')); err != nil {
		t.Fatal("actual MCP stdin failed")
	}
	select {
	case reply, ok := <-c.replies:
		defer clear(reply)
		var response codexProductRPCReply
		if !ok || json.Unmarshal(reply, &response) != nil || response.ID != c.sequence || len(response.Error) != 0 || len(response.Result) == 0 {
			t.Fatal("actual MCP returned no exact bounded JSON-RPC result")
		}
		return response.Result
	case <-time.After(8 * time.Second):
		t.Fatal("actual MCP reply deadline exceeded")
	}
	return nil
}

func (v *codexProductFixture) requireContextRefusal(t *testing.T, c *codexProductMCP, arguments map[string]any) {
	t.Helper()
	before := len(v.f.proxy.snapshot())
	stateBefore, stateErr := os.ReadFile(v.mcpState)
	if stateErr != nil && !os.IsNotExist(stateErr) {
		t.Fatal("private MCP state cannot be inspected")
	}
	defer clear(stateBefore)
	var result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	if json.Unmarshal(c.rpc(t, "tools/call", map[string]any{"name": "cicada_whoami", "arguments": arguments}), &result) != nil ||
		!result.IsError || len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, "CODEX_CALL_CONTEXT_REQUIRED") || len(result.Structured) != 0 {
		t.Fatal("actual MCP accepted an unverified call or returned identity")
	}
	// The real resident Node may heartbeat concurrently. Observe the original
	// canonical TCP proxy and exclude only that exact liveness route, never an
	// Endpoint heartbeat or another RPC. The test cannot use a fake service as
	// an oracle for product authorization.
	for _, ex := range v.f.proxy.snapshot()[before:] {
		base := "/v2/relay/nodes/" + v.actualNode.id
		if (ex.Method == http.MethodPost && ex.Path == base+"/heartbeat") || (ex.Method == http.MethodGet && ex.Path == base+"/events") {
			continue
		}
		t.Fatal("unverified MCP context caused a Hub request")
	}
	stateAfter, stateErr := os.ReadFile(v.mcpState)
	if stateErr != nil && !os.IsNotExist(stateErr) {
		t.Fatal("private MCP state cannot be inspected after refusal")
	}
	defer clear(stateAfter)
	if !bytes.Equal(stateBefore, stateAfter) {
		t.Fatal("unverified MCP call changed durable session authority")
	}
}

func (v *codexProductFixture) requireEmptyOwnerDirectory(t *testing.T) {
	t.Helper()
	v.requireOwnerDirectory(t, nil)
}

func (v *codexProductFixture) requireOwnerDirectory(t *testing.T, expected map[string]string) appcore.Snapshot {
	t.Helper()
	s := v.command(t, appActorCommand{}).Current
	s = v.do(ownerDirectoryReadAction(t, s))
	if s.OwnerEndpoints.Pending || s.OwnerEndpoints.State != "SNAPSHOT_ONLY" || s.OwnerEndpoints.NodeID != v.actualNode.id ||
		len(s.OwnerEndpoints.Endpoints) != len(expected) || s.OwnerEndpoints.CapturedAt == "" || s.Canvas.State != appcore.CanvasNoAuthorization ||
		s.Account.RootState != appcore.RootStateActive {
		t.Fatal("refused product calls changed the actual Owner's original-Node zero-rights directory")
	}
	seen := make(map[string]bool)
	for _, card := range s.OwnerEndpoints.Endpoints {
		presence, found := expected[card.Name]
		if !found || seen[card.Name] || card.Presence != presence || card.Workspace != v.workspace || card.Harness != "codex" || card.EndpointID == "" {
			t.Fatal("actual App signed directory differs from its real CLI Thread metadata or presence")
		}
		seen[card.Name] = true
	}
	trace := ownerDirectoryTrace(v.f, 0)
	if len(trace) == 0 || trace[len(trace)-1].Method != http.MethodPost || trace[len(trace)-1].Path != wire.OwnerEndpointReadPath || trace[len(trace)-1].Status != http.StatusOK {
		t.Fatal("actual App did not obtain its authenticated Owner directory")
	}
	return s
}

func TestN3CodexProductContextRefusesMissingAndForged(t *testing.T) {
	// Keep the genuine Node bridge running while its independent empty inbox
	// reconciliation is quiet. This is not an Endpoint heartbeat acceptance.
	v := newCodexProductFixture(t, "1h")
	v.requireEmptyOwnerDirectory(t)
	c := v.startMCP(t)
	for _, name := range []string{"missing", "nonce-only", "wrong-nonce", "forged-ticket", "extra-SID"} {
		t.Run(name, func(t *testing.T) {
			context := map[string]any{"connection_nonce": c.nonce, "ticket": strings.Repeat("0", 64) + "." + strings.Repeat("0", 64)}
			arguments := map[string]any{"_cicada_context": context}
			switch name {
			case "missing":
				arguments = map[string]any{}
			case "nonce-only":
				delete(context, "ticket")
			case "wrong-nonce":
				prefix := "0"
				if strings.HasPrefix(c.nonce, prefix) {
					prefix = "1"
				}
				context["connection_nonce"] = prefix + c.nonce[1:]
			case "extra-SID":
				context["native_session_id"] = "SYNTHETIC_UNTRUSTED_SID"
			}
			v.requireContextRefusal(t, c, arguments)
		})
	}
	v.requireEmptyOwnerDirectory(t)
	t.Log("CODEX_PRODUCT_GUARD actual_MCP=true actual_Node_bridge=true missing_or_forged_context_refused=true actual_Codex_plugin=NOT_RUN")
}

func TestN3CodexProductMCPRestartRotatesConnectionNonce(t *testing.T) {
	v := newCodexProductFixture(t, "1h")
	v.requireEmptyOwnerDirectory(t)
	first := v.startMCP(t)
	first.p.kill(t)
	second := v.startMCP(t)
	if first.nonce == second.nonce {
		t.Fatal("actual MCP restart retained its connection nonce")
	}
	v.requireContextRefusal(t, second, map[string]any{"_cicada_context": map[string]any{
		"connection_nonce": first.nonce, "ticket": strings.Repeat("0", 64) + "." + strings.Repeat("0", 64)}})
	v.requireEmptyOwnerDirectory(t)
	t.Log("CODEX_PRODUCT_GUARD actual_MCP_restart=true old_nonce_refused=true valid_ticket_replay=NOT_RUN actual_Codex_plugin=NOT_RUN")
}

// This is a separate gate from direct stdio guard tests. Only the actual
// installed plugin may supply Hook/MCP declarations; the helper never writes
// a user hooks.json or a native session record.
func TestN3CodexProductInstalledPluginLiteralTUI(t *testing.T) {
	v := newCodexProductFixture(t, "1s")
	v.requireEmptyOwnerDirectory(t)
	canary := filepath.Join(v.workspace, "synthetic-workspace-canary.txt")
	atomicPrivate(t, canary, []byte("SYNTHETIC ACCEPTANCE WORKSPACE; NEVER A DEPLOYMENT\n"))
	canaryBefore := hash(readPrivate(t, canary))
	config, resultPath := filepath.Join(v.root, "private-cli-config.json"), filepath.Join(v.root, "private-cli-result.json")
	binary := os.Getenv("CICADA_N3_CODEX_BINARY")
	if binary != "/tools/codex" {
		t.Fatal("explicit read-only acceptance Codex binary mount required")
	}
	writeJSON(t, config, map[string]any{"root": v.root, "workspace": v.workspace, "codex_home": v.codexHome,
		"environment": v.environment, "codex_binary": binary, "codex_sha256": "399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215",
		"marketplace": "/repo", "step": "literal-tui", "result": resultPath})
	log := must(os.OpenFile(filepath.Join(v.root, "private-cli.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600))
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/codex_product_cli.py", config)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = v.environment, v.workspace, log, log
	p := startProcess(t, cmd)
	select {
	case <-p.done:
	case <-time.After(160 * time.Second):
		t.Fatal("actual installed-plugin CLI driver exceeded its fixture deadline")
	}
	retainCodexProductCLIDiagnostics(t, v)
	var result struct {
		Status           string            `json:"status"`
		Failure          string            `json:"failure_category"`
		NativeSessionID  string            `json:"native_session_id"`
		NativeRecord     string            `json:"native_record"`
		Name             string            `json:"name"`
		Workspace        string            `json:"workspace"`
		Visible          bool              `json:"literal_join_peers_visible"`
		PluginSource     bool              `json:"actual_plugin_hook_source"`
		RealModelTurns   int               `json:"real_model_turns"`
		ProviderRequests []json.RawMessage `json:"provider_http_requests"`
		LiteralRequests  int               `json:"literal_provider_requests"`
		WhoamiRequests   int               `json:"host_whoami_provider_requests"`
		WhoamiNotJoined  bool              `json:"host_whoami_not_joined"`
		ContextRequired  bool              `json:"host_context_required"`
	}
	readJSON(t, resultPath, &result)
	if p.cmd.ProcessState.ExitCode() != 0 || result.Status != "SCOPED_PASS" || !result.Visible || !result.PluginSource ||
		result.RealModelTurns != 0 || result.LiteralRequests != 0 || result.WhoamiRequests != 2 || !result.WhoamiNotJoined || result.ContextRequired || len(result.ProviderRequests) != 2 || result.NativeSessionID == "" ||
		result.Name != "Synthetic installed-plugin Thread" || result.Workspace != v.workspace {
		t.Logf("CODEX_PRODUCT_CLI failure_category=%q driver_exit=%d literal_visible=%t literal_provider_requests=%d host_provider_requests=%d host_whoami_not_joined=%t host_context_required=%t", result.Failure, p.cmd.ProcessState.ExitCode(), result.Visible, result.LiteralRequests, result.WhoamiRequests, result.WhoamiNotJoined, result.ContextRequired)
		t.Fatal("actual installed-plugin TUI did not confirm visible literal join/peers without a model")
	}
	if relative, err := filepath.Rel(v.codexHome, result.NativeRecord); err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatal("actual CLI returned a native record outside its private CODEX_HOME")
	}
	if hash(readPrivate(t, canary)) != canaryBefore {
		t.Fatal("literal registration changed its original workspace")
	}
	if info, err := os.Lstat(result.NativeRecord); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("literal registration lost its actual original native record")
	}
	v.requireOwnerDirectory(t, map[string]string{result.Name: "offline"})
	t.Log("CODEX_PRODUCT_CLI actual_installed_plugin=true literal_join_peers_PTY_visible=true literal_provider_requests=0 host_whoami_not_joined=true host_static_provider_requests=2 actual_App_signed_card=true native_record_retained=true workspace_canary_retained=true real_model_turns=0 leave_and_rejoin=NOT_RUN")
}

// Retain only this owned CLI's logs in private run state before TempDir is
// removed. Neither App vaults, Node credentials, raw environment, installer
// material nor full secret protocol packets are copied into evidence.
func retainCodexProductCLIDiagnostics(t *testing.T, v *codexProductFixture) {
	t.Helper()
	const root = "/state/private-codex-diagnostics"
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal("private CLI diagnostic root unavailable")
	}
	destination := filepath.Join(root, filepath.Base(v.f.dir))
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal("private CLI diagnostic scope unavailable")
	}
	names := []string{"private-cli-result.json", "private-cli.log"}
	for _, pattern := range []string{"cli-literal-tui/*.json", "cli-literal-tui/*.stdout", "cli-literal-tui/*.stderr", "cli-literal-tui/*.raw", "cli-literal-tui/*.txt", "cli-literal-tui/*.rpc.stderr"} {
		paths, err := filepath.Glob(filepath.Join(v.root, pattern))
		if err != nil {
			t.Fatal("private CLI diagnostic selection failed")
		}
		for _, path := range paths {
			relative, err := filepath.Rel(v.root, path)
			if err != nil {
				t.Fatal("private CLI diagnostic scope invalid")
			}
			names = append(names, relative)
		}
	}
	if len(names) > 48 {
		t.Fatal("private CLI diagnostic file bound exceeded")
	}
	for _, relative := range names {
		source := filepath.Join(v.root, relative)
		info, err := os.Lstat(source)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > harnessPacketLimit {
			t.Fatal("private CLI diagnostic file unsafe or too large")
		}
		target := filepath.Join(destination, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal("private CLI diagnostic directory unavailable")
		}
		raw := readPrivate(t, source)
		atomicPrivate(t, target, raw)
		clear(raw)
	}
	t.Log("CODEX_PRODUCT_CLI private_diagnostics_retained=true sensitive_protocol_material_exported=false")
}
