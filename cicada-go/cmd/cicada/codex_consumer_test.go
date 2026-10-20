package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// This is a synthetic local Node boundary, not a native Runtime or Hub gate.
func codexConsumerNode(t *testing.T, root, node string, respond func(net.Conn, json.RawMessage)) string {
	t.Helper()
	path := machineAgentJoinSocketPath(root, node)
	if path == "" {
		t.Fatal("missing test socket path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var q json.RawMessage
				if json.NewDecoder(c).Decode(&q) != nil {
					return
				}
				respond(c, q)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	return path
}

func codexConsumerCache(t *testing.T, origin, base, sid string) (harness.SessionContext, mcpCachedSession, fabric.NetworkCard) {
	t.Helper()
	c := mcpTestContext("codex", sid, "synthetic-node", filepath.Join(t.TempDir(), sid))
	r := mcpTestCachedSession(t, origin, c, "synthetic-token-"+sid, "synthetic-group-"+sid, "synthetic-endpoint-"+sid)
	r.OwnerID, r.BindingID, r.BindingEpoch, r.LeaseExpiresAt = "synthetic-owner", "synthetic-binding-"+sid, 7, time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	if err := newMCPSessionStateStore(base).save(r); err != nil {
		t.Fatal(err)
	}
	card := fabric.NetworkCard{EndpointID: r.EndpointID, GroupID: r.GroupID, PrincipalID: "synthetic-principal-" + sid, NodeID: c.MachineID, Harness: c.Harness, Workspace: c.Workspace, BindingID: r.BindingID, BindingEpoch: r.BindingEpoch}
	return c, r, card
}

func codexConsumerInstall(m *mcpServer, r mcpCachedSession, card fabric.NetworkCard) {
	m.setSession(r.SessionToken, r.EndpointID, r.GroupID, mcpTrustedContext{Harness: r.Harness, NativeSessionID: r.NativeSessionID, NodeID: r.NodeID, Workspace: r.Workspace}, r.Scope,
		mcpPublicJoinResult{Endpoint: store.Endpoint{ID: r.EndpointID, GroupID: r.GroupID, Owner: r.OwnerID}, NetworkCard: card, BindingID: r.BindingID, BindingEpoch: r.BindingEpoch, LeaseExpiresAt: r.LeaseExpiresAt})
}

func TestCodexManagedSchemaAndNoAmbientIdentity(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "synthetic-parent")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "synthetic-parent")
	m := newMCPServer("http://127.0.0.1:9", "configured-parent", filepath.Join(t.TempDir(), "mcp", "sessions.json"))
	if err := m.enableCodexContext("synthetic-node"); err != nil {
		t.Fatal(err)
	}
	other := newMCPServer(m.baseURL, "", m.sessionStatePath)
	if err := other.enableCodexContext("synthetic-node"); err != nil {
		t.Fatal(err)
	}
	if m.codexContext.nonce == other.codexContext.nonce || len(m.codexContext.nonce) != 64 {
		t.Fatal("connection nonce reused")
	}
	if _, err := m.detectCurrentSession(); !errors.Is(err, errCodexMCPContext) || m.isJoined() {
		t.Fatal("managed startup inherited ambient identity")
	}
	if _, err := os.Stat(filepath.Dir(m.sessionStatePath)); !os.IsNotExist(err) {
		t.Fatal("enabling context touched session storage")
	}
	for _, tool := range m.contextualMCPTools() {
		s := tool["inputSchema"].(map[string]any)
		p := s["properties"].(map[string]any)
		c := p[codexMCPContextArgument].(map[string]any)
		if c["additionalProperties"] != false || c["properties"].(map[string]any)["connection_nonce"].(map[string]any)["const"] != m.codexContext.nonce {
			t.Fatal("missing closed declared context")
		}
		found := false
		for _, r := range s["required"].([]string) {
			if r == codexMCPContextArgument {
				found = true
			}
		}
		if !found {
			t.Fatal("context not required")
		}
	}
	for _, tool := range cicadaMCPTools() {
		if _, exists := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)[codexMCPContextArgument]; exists {
			t.Fatal("managed schema mutated legacy schema")
		}
	}
}

func TestCodexManagedGuardPrecedesRestoreAndBusiness(t *testing.T) {
	var requests atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer hub.Close()
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	_, cache, card := codexConsumerCache(t, hub.URL, base, "synthetic-a")
	m := newMCPServer(hub.URL, "", base)
	m.hubStateDir = t.TempDir()
	if err := m.enableCodexContext(cache.NodeID); err != nil {
		t.Fatal(err)
	}
	codexConsumerInstall(m, cache, card)
	var consumes atomic.Int32
	codexConsumerNode(t, m.hubStateDir, cache.NodeID, func(c net.Conn, _ json.RawMessage) {
		consumes.Add(1)
		_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "synthetic-deny"})
	})
	for _, args := range []map[string]any{nil, {}, {codexMCPContextArgument: map[string]any{"connection_nonce": m.codexContext.nonce}}, {codexMCPContextArgument: map[string]any{"connection_nonce": "wrong", "ticket": "synthetic"}}, {codexMCPContextArgument: map[string]any{"connection_nonce": m.codexContext.nonce, "ticket": "synthetic", "sid": "forged"}}} {
		if _, err := m.callTool("cicada_whoami", args); err == nil {
			t.Fatal("missing/malformed context admitted")
		}
	}
	if consumes.Load() != 0 || requests.Load() != 0 {
		t.Fatal("invalid context reached Node or Hub")
	}
	args := map[string]any{codexMCPContextArgument: map[string]any{"connection_nonce": m.codexContext.nonce, "ticket": "synthetic-denied"}}
	if _, err := m.callTool("cicada_whoami", args); !errors.Is(err, errCodexMCPContext) {
		t.Fatal(err)
	}
	if consumes.Load() != 1 || requests.Load() != 0 || m.currentSessionToken() != cache.SessionToken {
		t.Fatal("denied proof restored, invoked, or replaced previous actor")
	}
	saved, err := m.sessionState.load(hub.URL, mcpTestContext(cache.Harness, cache.NativeSessionID, cache.NodeID, cache.Workspace))
	if err != nil || saved == nil || *saved != cache {
		t.Fatal("denied proof changed persisted actor")
	}
}

func TestCodexManagedEachCallConsumesAndSwitchesExactScope(t *testing.T) {
	var cards sync.Map
	var requests atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		value, ok := cards.Load(strings.TrimPrefix(r.Header.Get("Authorization"), "CicadaSession "))
		if !ok {
			w.WriteHeader(403)
			return
		}
		card := value.(fabric.NetworkCard)
		if r.Header.Get("Cicada-Group-Scope") != card.GroupID {
			t.Error("wrong Group")
		}
		if r.URL.Path == "/v2/fabric/whoami" {
			_ = json.NewEncoder(w).Encode(card)
		} else if r.URL.Path == "/v2/fabric/heartbeat" {
			_ = json.NewEncoder(w).Encode(map[string]any{"endpoint_id": card.EndpointID, "group_id": card.GroupID, "binding_id": card.BindingID, "binding_epoch": card.BindingEpoch})
		} else {
			t.Error("unexpected business request")
			w.WriteHeader(500)
		}
	}))
	defer hub.Close()
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	ctxA, a, cardA := codexConsumerCache(t, hub.URL, base, "synthetic-a")
	ctxB, b, cardB := codexConsumerCache(t, hub.URL, base, "synthetic-b")
	cards.Store(a.SessionToken, cardA)
	cards.Store(b.SessionToken, cardB)
	m := newMCPServer(hub.URL, "", base)
	m.hubStateDir = t.TempDir()
	if err := m.enableCodexContext(a.NodeID); err != nil {
		t.Fatal(err)
	}
	defer m.stopCodexHeartbeat()
	var authority localCodexContextAuthority
	digest, _ := codexArgumentsDigest(map[string]any{})
	issue := func(c harness.SessionContext) string {
		q := syntheticCodexContextIssue()
		q.APIOrigin = hub.URL
		q.NativeSessionID = c.NativeSessionID
		q.Workspace = c.Workspace
		q.ConnectionNonce = m.codexContext.nonce
		q.ToolName = "cicada_whoami"
		q.ArgumentsDigest = digest
		r, err := authority.issue(q, "synthetic-node-epoch", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return r.Ticket
	}
	codexConsumerNode(t, m.hubStateDir, a.NodeID, func(c net.Conn, raw json.RawMessage) {
		var q localCodexContextConsume
		_ = json.Unmarshal(raw, &q)
		r, err := authority.consume(q, "synthetic-node-epoch", time.Now())
		response := localJoinResponse{Version: 1, CodexContextConsume: r}
		if err != nil {
			response.Error = "synthetic-context-denied"
		}
		_ = json.NewEncoder(c).Encode(response)
	})
	call := func(ticket string) (any, error) {
		return m.callTool("cicada_whoami", map[string]any{codexMCPContextArgument: map[string]any{"connection_nonce": m.codexContext.nonce, "ticket": ticket}})
	}
	ticket := issue(ctxA)
	if _, err := call(ticket); err != nil {
		t.Fatal(err)
	}
	old := m.codexContext.heartbeat
	if old == nil {
		t.Fatal("valid scope did not start frozen heartbeat")
	}
	before := requests.Load()
	if _, err := call(ticket); !errors.Is(err, errCodexMCPContext) || requests.Load() != before {
		t.Fatal("replayed ticket invoked business")
	}
	if _, err := m.detectCurrentSession(); !errors.Is(err, errCodexMCPContext) {
		t.Fatal("active call context leaked into idle")
	}
	if _, err := call(issue(ctxB)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("B installed before A worker exit")
	}
	if m.currentSessionToken() != b.SessionToken || m.codexContext.heartbeat.cache.NativeSessionID != ctxB.NativeSessionID {
		t.Fatal("switch borrowed A credentials")
	}
	for _, entry := range []mcpCachedSession{a, b} {
		saved, err := m.sessionState.load(hub.URL, mcpTestContext(entry.Harness, entry.NativeSessionID, entry.NodeID, entry.Workspace))
		if err != nil || saved == nil || *saved != entry {
			t.Fatal("switch deleted/rewrote a cached scope")
		}
	}
}

func TestCodexFrozenHeartbeatCancellationWaitAndLateRevocation(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "CicadaSession synthetic-token-synthetic-a" {
			t.Error("renewal changed frozen credential")
		}
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer hub.Close()
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	_, a, cardA := codexConsumerCache(t, hub.URL, base, "synthetic-a")
	_, b, cardB := codexConsumerCache(t, hub.URL, base, "synthetic-b")
	m := newMCPServer(hub.URL, "", base)
	if err := m.enableCodexContext(a.NodeID); err != nil {
		t.Fatal(err)
	}
	codexConsumerInstall(m, a, cardA)
	h := m.codexHeartbeatSnapshot()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan struct{})
	m.codexContext.heartbeat = h
	ticks := make(chan time.Time, 1)
	go h.runWithTicks(ctx, m, ticks)
	ticks <- time.Now()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat did not start")
	}
	m.stopCodexHeartbeat()
	select {
	case <-h.done:
	default:
		t.Fatal("stop returned before worker exit")
	}
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("request not cancelled")
	}
	codexConsumerInstall(m, b, cardB)
	h.clearMemoryIfMatching(m)
	if m.currentSessionToken() != b.SessionToken {
		t.Fatal("late A revocation cleared B")
	}
	codexConsumerInstall(m, a, cardA)
	h.clearMemoryIfMatching(m)
	if m.isJoined() {
		t.Fatal("matching revoked actor remained in memory")
	}
	saved, err := m.sessionState.load(hub.URL, mcpTestContext(a.Harness, a.NativeSessionID, a.NodeID, a.Workspace))
	if err != nil || saved == nil || *saved != a {
		t.Fatal("background revocation deleted original cached actor")
	}
}

func TestCodexFrozenPQHeartbeatUsesFrozenTupleAndCancels(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	_, a, card := codexConsumerCache(t, "https://synthetic.invalid", base, "synthetic-a")
	m := newMCPServer(a.APIOrigin, "", base)
	m.hubStateDir = root
	m.pqtlsSelected = true
	codexConsumerInstall(m, a, card)
	h := m.codexHeartbeatSnapshot()
	received := make(chan localMCPMetadataRequest, 1)
	closed := make(chan struct{})
	codexConsumerNode(t, root, a.NodeID, func(c net.Conn, raw json.RawMessage) {
		var q localMCPMetadataRequest
		_ = json.Unmarshal(raw, &q)
		received <- q
		_, _ = io.Copy(io.Discard, c)
		close(closed)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.renew(ctx); done <- err }()
	var q localMCPMetadataRequest
	select {
	case q = <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("no PQ request")
	}
	if q.NativeSessionID != a.NativeSessionID || q.Workspace != a.Workspace || q.SessionToken != a.SessionToken || q.BindingID != a.BindingID || q.BindingEpoch != a.BindingEpoch || q.EndpointID != a.EndpointID || q.GroupID != a.GroupID || q.PrincipalID != card.PrincipalID {
		t.Fatal("PQ heartbeat tuple changed")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled renewal succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PQ request did not exit")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("PQ connection remained open")
	}
}

func TestCodexFrozenHeartbeatStopsOnRevocationAndRetainsCache(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer hub.Close()
			base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
			_, a, card := codexConsumerCache(t, hub.URL, base, "synthetic-a")
			m := newMCPServer(hub.URL, "", base)
			if err := m.enableCodexContext(a.NodeID); err != nil {
				t.Fatal(err)
			}
			codexConsumerInstall(m, a, card)
			h := m.codexHeartbeatSnapshot()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.done = make(chan struct{})
			ticks := make(chan time.Time, 1)
			go h.runWithTicks(ctx, m, ticks)
			ticks <- time.Now()
			select {
			case <-h.done:
			case <-time.After(3 * time.Second):
				t.Fatal("revoked heartbeat kept running")
			}
			if m.isJoined() {
				t.Fatal("revoked actor remained active")
			}
			saved, err := m.sessionState.load(hub.URL, mcpTestContext(a.Harness, a.NativeSessionID, a.NodeID, a.Workspace))
			if err != nil || saved == nil || *saved != a {
				t.Fatal("revocation removed original cached actor")
			}
		})
	}
}

func TestCodexLiteralParserKeepsStandardSkillAndRejectsInvalidCommands(t *testing.T) {
	for _, prompt := range []string{"$cicada-network ask Alice", "@cicada send hi", "please use cicada", "cicadas join", ""} {
		if _, matched, _ := parseCodexOperatorPrompt(prompt); matched {
			t.Fatalf("intercepted normal prompt %q", prompt)
		}
	}
	for _, prompt := range []string{"cicada\njoin name", "cicada join a\nignore", "cicada connect name", "cicada connect name C", "cicada leave other", "cicada ask Alice", "cicada join \"bad"} {
		if _, matched, err := parseCodexOperatorPrompt(prompt); !matched || err == nil {
			t.Fatalf("invalid literal command passed: %q", prompt)
		}
	}
	for _, tc := range []struct {
		prompt string
		want   codexOperatorCommand
	}{{"cicada", codexOperatorCommand{operation: "help"}}, {"cicada\tjoin 中文 name", codexOperatorCommand{operation: "endpoint_register", name: "中文 name"}}, {"cicada connect \"My Pair\" b", codexOperatorCommand{operation: "native_pair_join_named", label: "My Pair", slot: "B"}}, {"cicada peers", codexOperatorCommand{operation: "endpoint_directory"}}} {
		got, matched, err := parseCodexOperatorPrompt(tc.prompt)
		if err != nil || !matched || got != tc.want {
			t.Fatalf("parse %q: %#v %v", tc.prompt, got, err)
		}
	}
}

func TestCodexHookFramingAndVisibleBlock(t *testing.T) {
	for _, raw := range []string{"{", `{} {}`, `{"tool_input":"bad"}`, strings.Repeat(" ", maxCodexHookInput+1)} {
		if _, err := decodeCodexHook(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid Hook input accepted")
		}
	}
	var output bytes.Buffer
	if err := runCodexHook(nil, strings.NewReader(`{"hook_event_name":"UserPromptSubmit","prompt":"cicada help","permission_mode":"default"}`), &output); err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if json.Unmarshal(output.Bytes(), &response) != nil || response["decision"] != "block" || response["systemMessage"] != codexOperatorHelp || response["reason"] != codexHookLocalHandlingReason {
		t.Fatal("literal help did not produce human feedback and block")
	}
	output.Reset()
	if err := runCodexHook(nil, strings.NewReader(`{"hook_event_name":"UserPromptSubmit","prompt":"cicada join Synthetic Thread"}`), &output); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(output.Bytes(), &response) != nil || response["decision"] != "block" || response["reason"] != codexHookLocalHandlingReason || !strings.Contains(response["systemMessage"].(string), "could not verify") {
		t.Fatal("unverified command lost its full refusal or changed into success")
	}
	output.Reset()
	if err := runCodexHook(nil, strings.NewReader(`{"hook_event_name":"UserPromptSubmit","prompt":"$cicada-network ask Alice"}`), &output); err != nil || strings.TrimSpace(output.String()) != "{}" {
		t.Fatal("standard skill invocation intercepted")
	}
}

func TestCodexOperatorDisplayDoesNotOverclaim(t *testing.T) {
	r := &localEndpointResult{Registration: &nodewire.EndpointRegistrationResult{Name: "Synthetic Thread", Workspace: "/synthetic/work", Presence: "left"}}
	got := formatCodexOperatorResult(codexOperatorCommand{operation: "endpoint_register"}, r)
	if !strings.Contains(got, "remains left") || strings.Contains(got, "is registered") {
		t.Fatal("repeat registration revived left actor")
	}
	r = &localEndpointResult{Join: &fabric.JoinResult{SessionToken: "synthetic-private-token", BindingID: "synthetic-private-binding", Endpoint: store.Endpoint{Name: "Synthetic Thread", Workspace: "/synthetic/work"}}}
	got = formatCodexOperatorResult(codexOperatorCommand{operation: "native_pair_join_named"}, r)
	if strings.Contains(got, "synthetic-private") || !strings.Contains(got, "both Owner confirmations") {
		t.Fatal("Join feedback leaked private receipt or claimed authority")
	}
}

func TestCodexSinglePluginManagedConfiguration(t *testing.T) {
	root := filepath.Join("..", "..", "..", ".agents", "plugins", "cicada")
	read := func(name string) map[string]any {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		if json.Unmarshal(data, &d) != nil {
			t.Fatal("invalid asset JSON")
		}
		return d
	}
	// Codex 0.163 deliberately omits hooks for the schema-declared portable
	// format. A root portable entry would shadow this supported legacy bundle.
	for _, path := range []string{"plugin.json", "mcp.json"} {
		if _, err := os.Lstat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unsupported portable entry shadows the bundled Codex hooks")
		}
	}
	legacy := read(".codex-plugin/plugin.json")
	if legacy["hooks"] != "./hooks/hooks.json" || legacy["skills"] != "./skills/" || legacy["mcpServers"] != "./.mcp.json" {
		t.Fatal("plugin dropped or duplicated its supported shared entries")
	}
	if legacy["name"] != "cicada" {
		t.Fatal("plugin identity changed")
	}
	marketplace := read(filepath.Join("..", "marketplace.json"))
	plugins := marketplace["plugins"].([]any)
	if len(plugins) != 1 || plugins[0].(map[string]any)["name"] != "cicada" {
		t.Fatal("marketplace no longer selects the single Cicada bundle")
	}
	source := plugins[0].(map[string]any)["source"].(map[string]any)
	sourcePath, ok := source["path"].(string)
	// Codex resolves local sources from the repository marketplace root,
	// after stripping the .agents/plugins/marketplace.json layout suffix.
	resolved := filepath.Join("..", "..", "..", strings.TrimPrefix(sourcePath, "./"))
	if !ok || source["source"] != "local" || !strings.HasPrefix(sourcePath, "./") || filepath.Clean(resolved) != filepath.Clean(root) {
		t.Fatal("marketplace source does not resolve to the existing Cicada bundle from its repository root")
	}
	if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
		t.Fatal("marketplace source directory is missing")
	}
	compat := read(".mcp.json")
	if len(compat["mcpServers"].(map[string]any)) != 1 {
		t.Fatal("plugin no longer selects exactly one Cicada MCP server")
	}
	compatServer := compat["mcpServers"].(map[string]any)["cicada"].(map[string]any)
	// Codex 0.163 launches the supported legacy stdio definition directly,
	// with this explicit configuration-only environment allowlist.
	wantEnvironment := []any{
		"CICADA_API_URL", "CICADA_MACHINE_ID", "CICADA_USER_ROOT",
		"CICADA_NODE_STATE_DIR", "CICADA_STATE_DIR",
		"CICADA_MCP_SESSION_STATE_FILE", "CICADA_MCP_STATE_FILE",
		"CICADA_SESSION_STATE_DIR", "CICADA_MCP_STATE_DIR",
		"CICADA_MCP_OUTBOX_STATE_FILE", "CICADA_MCP_OUTBOX_FILE",
		"CICADA_MCP_OUTBOX_STATE_DIR", "CICADA_MCP_OUTBOX_DIR",
		"CICADA_NODE_PQTLS_CONFIG", "CICADA_NETWORK_JOIN_DIR",
		"CICADA_NETWORK_SESSION_DIR", "XDG_STATE_HOME",
	}
	if !reflect.DeepEqual(compatServer["env_vars"], wantEnvironment) {
		t.Fatal("plugin did not retain the reviewed configuration-only environment allowlist")
	}
	if len(compatServer) != 4 || compatServer["command"] != "cicada" || compatServer["type"] != "stdio" || !reflect.DeepEqual(compatServer["args"], []any{"mcp", "--codex-context"}) || compatServer["env"] != nil {
		t.Fatal("managed MCP missing or static identity configured")
	}
	hooks := read("hooks/hooks.json")["hooks"].(map[string]any)
	for _, name := range []string{"UserPromptSubmit", "PreToolUse"} {
		entries := hooks[name].([]any)
		if len(entries) != 1 {
			t.Fatal("duplicate Hook")
		}
		entry := entries[0].(map[string]any)
		commands := entry["hooks"].([]any)
		if len(commands) != 1 || commands[0].(map[string]any)["command"] != "cicada codex-hook" {
			t.Fatal("wrong Hook entry")
		}
		if name == "PreToolUse" && entry["matcher"] != "^mcp__(cicada|plugin_cicada_cicada)__" {
			t.Fatal("Hook matcher excludes legitimate non-cicada-prefixed aliases")
		}
	}
}

func TestCodexPreToolReplacesParentContextAndBindsBusinessArguments(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_NODE_STATE_DIR", root)
	t.Setenv("CICADA_MACHINE_ID", "synthetic-node")
	t.Setenv("CICADA_API_URL", "https://synthetic.invalid")
	var calls atomic.Int32
	codexConsumerNode(t, root, "synthetic-node", func(c net.Conn, raw json.RawMessage) {
		var q localCodexContextIssue
		if json.Unmarshal(raw, &q) != nil {
			t.Error("invalid issue request")
			return
		}
		calls.Add(1)
		want, _ := codexArgumentsDigest(map[string]any{"request_id": "synthetic-request"})
		if q.Operation != "codex_context_issue" || q.NativeSessionID != "synthetic-child" || q.Workspace != "/synthetic/child" || q.ArgumentsDigest != want || q.ToolName != "request_status" || q.TurnID != "synthetic-turn" || q.ToolUseID != "synthetic-call" {
			t.Error("Hook did not bind actual current call")
		}
		_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, CodexContextIssue: &localCodexContextIssueResult{Ticket: "synthetic-child-ticket", ExpiresAt: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)}})
	})
	event := codexHookInput{SessionID: "synthetic-child", CWD: "/synthetic/child", TranscriptPath: "/synthetic/transcript", Event: "PreToolUse", ToolName: "mcp__plugin_cicada_cicada__request_status", TurnID: "synthetic-turn", ToolUseID: "synthetic-call", ToolInput: map[string]any{"request_id": "synthetic-request", codexMCPContextArgument: map[string]any{"connection_nonce": strings.Repeat("a", 64), "ticket": "synthetic-parent-ticket", "native_session_id": "forged-parent"}}}
	var out bytes.Buffer
	if err := codexPreToolUse(event, &out); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Hook struct {
			Event    string         `json:"hookEventName"`
			Decision string         `json:"permissionDecision"`
			Updated  map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(out.Bytes(), &response) != nil || response.Hook.Decision != "allow" || response.Hook.Event != "PreToolUse" || response.Hook.Updated["request_id"] != "synthetic-request" {
		t.Fatal("missing complete supported replacement")
	}
	if !reflect.DeepEqual(response.Hook.Updated[codexMCPContextArgument], map[string]any{"connection_nonce": strings.Repeat("a", 64), "ticket": "synthetic-child-ticket"}) || bytes.Contains(out.Bytes(), []byte("parent")) {
		t.Fatal("provider context survived trusted replacement")
	}
	event.ToolInput = map[string]any{"request_id": "synthetic-request"}
	out.Reset()
	if err := codexPreToolUse(event, &out); err != nil || !bytes.Contains(out.Bytes(), []byte(`"permissionDecision":"deny"`)) || calls.Load() != 1 {
		t.Fatal("missing nonce reached Node or passed")
	}
	event.ToolName = "mcp__unrelated__request_status"
	out.Reset()
	if err := codexPreToolUse(event, &out); err != nil || strings.TrimSpace(out.String()) != "{}" || calls.Load() != 1 {
		t.Fatal("unrelated MCP intercepted")
	}
}

type codexConsumerWriter func([]byte) (int, error)

func (w codexConsumerWriter) Write(p []byte) (int, error) { return w(p) }

func TestCodexLiteralJoinPersistsBeforeOutputAndAckAndRecoversOriginal(t *testing.T) {
	for _, fault := range []string{"output", "cache"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			codexHome := filepath.Join(root, "codex")
			workspace := filepath.Join(root, "workspace")
			base := filepath.Join(root, "mcp", "sessions.json")
			if err := os.MkdirAll(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CODEX_HOME", codexHome)
			t.Setenv("CICADA_NODE_STATE_DIR", filepath.Join(root, "node"))
			t.Setenv("CICADA_MACHINE_ID", "synthetic-node")
			t.Setenv("CICADA_API_URL", "https://synthetic.invalid")
			t.Setenv("CICADA_MCP_SESSION_STATE_FILE", base)
			transcript := filepath.Join(codexHome, "sessions", "rollout-synthetic.jsonl")
			if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
				t.Fatal(err)
			}
			metadata, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": "synthetic-current-thread", "cwd": workspace, "source": "exec", "originator": "codex_exec"}})
			if err := os.WriteFile(transcript, append(metadata, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			event := codexHookInput{Event: "UserPromptSubmit", Prompt: `cicada connect "Synthetic Pair" A`, SessionID: "synthetic-current-thread", CWD: workspace, TranscriptPath: transcript}
			if err := verifyCodexContextTranscript(transcript, event.SessionID, workspace); err != nil {
				t.Fatal("synthetic transcript invalid", err)
			}
			ctx := mcpTestContext("codex", event.SessionID, "synthetic-node", workspace)
			scope, _, err := mcpSessionScope("https://synthetic.invalid", ctx)
			if err != nil {
				t.Fatal(err)
			}
			intentPath := filepath.Join(filepath.Dir(base), "scopes", scope, "operator-intent.json")
			readDisk := func() codexOperatorIntentDisk {
				data, err := os.ReadFile(intentPath)
				if err != nil {
					t.Fatal(err)
				}
				var d codexOperatorIntentDisk
				if json.Unmarshal(data, &d) != nil {
					t.Fatal("invalid private intent")
				}
				return d
			}
			var calls atomic.Int32
			codexConsumerNode(t, filepath.Join(root, "node"), "synthetic-node", func(c net.Conn, raw json.RawMessage) {
				var q localEndpointRequest
				if json.Unmarshal(raw, &q) != nil {
					t.Error("invalid operator request")
					return
				}
				calls.Add(1)
				disk := readDisk()
				if disk.Pending == nil || disk.Pending.Request != q || q.PairLabel != "Synthetic Pair" || q.Slot != "A" || q.NativeSessionID != event.SessionID {
					t.Error("IPC preceded exact original persistence")
				}
				j := &fabric.JoinResult{SessionToken: "synthetic-private-session-token", BindingID: "synthetic-binding", BindingEpoch: 5, LeaseExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Endpoint: store.Endpoint{ID: "synthetic-endpoint", GroupID: "synthetic-group", PrincipalID: "synthetic-principal", Owner: "synthetic-owner", MachineID: "synthetic-node", Harness: "codex", NativeSessionID: event.SessionID, Workspace: workspace, Name: "Synthetic Thread"}}
				r := &localEndpointResult{RequestID: q.RequestID, IntentDigest: codexOperatorDigest(q, false), HubID: "synthetic-hub", NodeID: "synthetic-node", Operation: q.Operation, State: "COMPLETED", Join: j}
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, EndpointOperation: r})
			})
			cachePath := filepath.Join(filepath.Dir(base), "scopes", scope+".json")
			if fault == "cache" {
				if err := os.MkdirAll(cachePath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			var first bytes.Buffer
			writer := io.Writer(&first)
			if fault == "output" {
				writer = codexConsumerWriter(func(p []byte) (int, error) {
					saved, err := newMCPSessionStateStore(base).load("https://synthetic.invalid", ctx)
					if err != nil || saved == nil || saved.SessionToken != "synthetic-private-session-token" || saved.OwnerID != "synthetic-owner" || saved.BindingEpoch != 5 {
						t.Fatalf("output preceded private Join save: response=%s load-error=%v", p, err)
					}
					if d := readDisk(); d.Pending == nil || d.Pending.Result == nil {
						t.Fatal("ACK preceded output")
					}
					return 0, errors.New("synthetic output failure")
				})
			}
			err = codexUserPrompt(event, writer)
			if (fault == "output" && err == nil) || (fault == "cache" && (err != nil || !strings.Contains(first.String(), "not safely saved"))) {
				t.Fatalf("fault became success: err=%v output=%s", err, first.String())
			}
			disk := readDisk()
			if disk.Pending == nil || disk.Pending.Result == nil || disk.LastAck != nil {
				t.Fatal("failed handoff lost original result")
			}
			original := disk.Pending.Request
			if fault == "cache" {
				if err := os.Remove(cachePath); err != nil {
					t.Fatal(err)
				}
			}
			var recovered bytes.Buffer
			if err := codexUserPrompt(event, &recovered); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("recovery redispatched completed original")
			}
			disk = readDisk()
			if disk.Pending != nil || disk.LastAck == nil || disk.LastAck.RequestID != original.RequestID {
				t.Fatal("successful saved output not acknowledged")
			}
			saved, err := newMCPSessionStateStore(base).load("https://synthetic.invalid", ctx)
			if err != nil || saved == nil || saved.BindingID != "synthetic-binding" || saved.SessionToken != "synthetic-private-session-token" {
				t.Fatal("recovered Join not stored")
			}
			if bytes.Contains(recovered.Bytes(), []byte("synthetic-private")) || !strings.Contains(recovered.String(), "both Owner confirmations") {
				t.Fatal("operator output leaked credential or claimed permission")
			}
		})
	}
}
