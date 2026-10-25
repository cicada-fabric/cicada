package main

// Private test overlay: real Hub/TCP/SQLite/crypto and two authorized Node
// registrations, using the producer's public-API fixture. Native records here
// are visibly synthetic protocol inputs, not actual Codex Runtime evidence.
// The separate peer_form_native.py lane supplies actual original native A/B.
import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

type qaPeerFrame struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  map[string]any  `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type qaPeerChild struct {
	cmd        *exec.Cmd
	in         io.WriteCloser
	frames     chan qaPeerFrame
	done       chan struct{}
	stop       chan struct{}
	once       sync.Once
	nonce      string
	sequence   int
	lateForm   json.RawMessage
	lateChoice string
}

func qaStartPeerChild(t *testing.T, root string, capabilities ...map[string]any) *qaPeerChild {
	t.Helper()
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	if binary == "" {
		t.Fatal("actual isolated CLI binary required")
	}
	c := &qaPeerChild{cmd: exec.Command(binary, "mcp", "--codex-context", "--user-root", root), frames: make(chan qaPeerFrame, 64), done: make(chan struct{}), stop: make(chan struct{})}
	var err error
	c.in, err = c.cmd.StdinPipe()
	if err != nil {
		t.Fatal("owned MCP stdin unavailable")
	}
	out, err := c.cmd.StdoutPipe()
	if err != nil {
		t.Fatal("owned MCP stdout unavailable")
	}
	c.cmd.Stderr = io.Discard // No payloads/credentials in public failure output.
	if c.cmd.Start() != nil {
		t.Fatal("actual isolated MCP process failed to start")
	}
	go func() { _ = c.cmd.Wait(); close(c.done) }()
	go func() {
		defer close(c.frames)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			var f qaPeerFrame
			if json.Unmarshal(scanner.Bytes(), &f) != nil || f.Version != "2.0" {
				select {
				case c.frames <- qaPeerFrame{}:
				case <-c.stop:
				}
				return
			}
			select {
			case c.frames <- f:
			case <-c.stop:
				return
			}
		}
	}()
	t.Cleanup(func() { c.close(t) })
	caps := map[string]any{"elicitation": map[string]any{"form": map[string]any{}}}
	if len(capabilities) > 1 {
		t.Fatal("invalid owned Host capability fixture")
	}
	if len(capabilities) == 1 {
		caps = capabilities[0]
	}
	c.send(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "synthetic-independent-peer-qa", "version": "1"}, "capabilities": caps}})
	if f := c.next(t); !bytes.Equal(f.ID, []byte("1")) || len(f.Error) != 0 {
		t.Fatal("actual MCP initialization refused")
	}
	c.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	c.sequence = 1
	listed := c.rpc(t, "tools/list", map[string]any{})
	raw, _ := json.Marshal(listed.Result)
	var catalog struct {
		Tools []struct {
			Name   string `json:"name"`
			Schema struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if json.Unmarshal(raw, &catalog) != nil {
		t.Fatal("actual MCP catalog invalid")
	}
	for _, tool := range catalog.Tools {
		if tool.Name != "cicada_select_peer" {
			continue
		}
		var context struct {
			Properties map[string]struct {
				Const string `json:"const"`
			} `json:"properties"`
		}
		if json.Unmarshal(tool.Schema.Properties[codexMCPContextArgument], &context) != nil {
			t.Fatal("actual context schema invalid")
		}
		c.nonce = context.Properties["connection_nonce"].Const
	}
	if len(c.nonce) != 64 {
		t.Fatal("actual selected peer schema/nonce not advertised")
	}
	return c
}

func (c *qaPeerChild) close(t *testing.T) {
	t.Helper()
	c.once.Do(func() {
		close(c.stop)
		_ = c.in.Close()
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			_ = c.cmd.Process.Kill()
			select {
			case <-c.done:
			case <-time.After(3 * time.Second):
				t.Error("owned MCP process did not exit")
			}
		}
	})
}
func (c *qaPeerChild) send(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 1<<20 {
		t.Fatal("owned MCP request invalid")
	}
	defer clear(raw)
	if _, err = c.in.Write(append(raw, '\n')); err != nil {
		t.Fatal("owned MCP request write failed")
	}
}
func (c *qaPeerChild) next(t *testing.T) qaPeerFrame {
	t.Helper()
	select {
	case f, ok := <-c.frames:
		if !ok || f.Version != "2.0" {
			t.Fatal("actual MCP stdout ended/invalid")
		}
		return f
	case <-time.After(25 * time.Second):
		t.Fatal("actual MCP response timeout")
	}
	return qaPeerFrame{}
}
func (c *qaPeerChild) request(t *testing.T, method string, params any) int {
	t.Helper()
	c.sequence++
	c.send(t, map[string]any{"jsonrpc": "2.0", "id": c.sequence, "method": method, "params": params})
	return c.sequence
}
func (c *qaPeerChild) response(t *testing.T, id int) qaPeerFrame {
	t.Helper()
	f := c.next(t)
	raw, _ := json.Marshal(id)
	if f.Method != "" || !bytes.Equal(f.ID, raw) || len(f.Error) != 0 {
		t.Fatal("actual MCP response correlation failed")
	}
	return f
}
func (c *qaPeerChild) rpc(t *testing.T, method string, params any) qaPeerFrame {
	t.Helper()
	return c.response(t, c.request(t, method, params))
}

func qaPeerHook(t *testing.T, n *peerNetworkFixture, m *mcpServer, c *qaPeerChild, tool string, args map[string]any) map[string]any {
	t.Helper()
	issue := localDomainConsumerIssue(t, n.f, 0) // Explicitly synthetic record; real Hook issuer and crypto.
	// The shared helper defaults to the desktop local-domain profile. This
	// independent Network uses the original strict private-record verifier.
	if os.Chmod(issue.TranscriptPath, 0600) != nil || os.Chmod(filepath.Dir(issue.TranscriptPath), 0700) != nil {
		t.Fatal("private original Network native-record permissions unavailable")
	}
	input := map[string]any{}
	for k, v := range args {
		input[k] = v
	}
	input[codexMCPContextArgument] = map[string]any{"connection_nonce": c.nonce}
	event := codexHookInput{Event: "PreToolUse", SessionID: n.f.native[0], CWD: n.f.workspace, TranscriptPath: issue.TranscriptPath, ToolName: "mcp__cicada__" + tool, ToolInput: input, TurnID: "SYNTHETIC-QA-peer-turn", ToolUseID: "SYNTHETIC-QA-peer-use"}
	var out bytes.Buffer
	if codexPreToolUseWithSelection(event, &out, &LocalNodeSelection{UserRoot: m.localNode.Pin.UserRoot}) != nil {
		t.Fatal("actual Hook failed")
	}
	defer clear(out.Bytes())
	var reply struct {
		Hook struct {
			Decision string         `json:"permissionDecision"`
			Reason   string         `json:"permissionDecisionReason"`
			Input    map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(out.Bytes(), &reply) != nil || reply.Hook.Decision != "allow" {
		code := "UNCLASSIFIED"
		for _, candidate := range []string{"CODEX_CALL_CONTEXT_REQUIRED", "CODEX_NATIVE_COORDINATES_INVALID", "CODEX_NATIVE_RECORD_UNVERIFIED", "CODEX_TOOL_INPUT_MISSING", "CODEX_CALL_CONTEXT_MISSING", "CODEX_CONNECTION_NONCE_INVALID", "CODEX_TOOL_ARGUMENTS_INVALID", "CODEX_ARGUMENT_DIGEST_UNAVAILABLE", "CODEX_NODE_TICKET_UNAVAILABLE"} {
			if strings.HasPrefix(reply.Hook.Reason, candidate+":") {
				code = candidate
				break
			}
		}
		t.Fatalf("actual Hook proof refused: deny=%t stage=%s", reply.Hook.Decision == "deny", code)
	}
	return reply.Hook.Input
}

func qaPeerCall(t *testing.T, n *peerNetworkFixture, m *mcpServer, c *qaPeerChild, tool string, args map[string]any) map[string]any {
	t.Helper()
	return c.rpc(t, "tools/call", map[string]any{"name": tool, "arguments": qaPeerHook(t, n, m, c, tool, args)}).Result
}

func qaPeerSelect(t *testing.T, n *peerNetworkFixture, m *mcpServer, c *qaPeerChild, action string) map[string]any {
	t.Helper()
	id := c.request(t, "tools/call", map[string]any{"name": "cicada_select_peer", "arguments": qaPeerHook(t, n, m, c, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})})
	f := c.next(t)
	if f.Method != "elicitation/create" || len(f.ID) == 0 {
		t.Fatal("real Hub authorized peer did not reach actual form")
	}
	var p struct {
		Mode   string `json:"mode"`
		Schema struct {
			Type       string   `json:"type"`
			Required   []string `json:"required"`
			Additional *bool    `json:"additionalProperties"`
			Properties map[string]struct {
				Type    string `json:"type"`
				Choices []struct {
					ID    string `json:"const"`
					Title string `json:"title"`
				} `json:"oneOf"`
			} `json:"properties"`
		} `json:"requestedSchema"`
	}
	if json.Unmarshal(f.Params, &p) != nil || p.Mode != "form" || p.Schema.Type != "object" || len(p.Schema.Required) != 1 || p.Schema.Required[0] != "peer" || p.Schema.Additional == nil || *p.Schema.Additional || len(p.Schema.Properties) != 1 {
		t.Fatal("actual form schema differs from closed contract")
	}
	options := p.Schema.Properties["peer"]
	if options.Type != "string" || len(options.Choices) != 1 {
		t.Fatal("actual authorized Network did not expose exactly its one permitted remote peer")
	}
	choice := options.Choices[0]
	name := n.joined[1].Endpoint.Name
	endpointRunes := []rune(n.joined[1].Endpoint.ID)
	if len(endpointRunes) > 8 {
		endpointRunes = endpointRunes[len(endpointRunes)-8:]
	}
	if name == "" || !strings.Contains(choice.Title, name) || !strings.HasSuffix(choice.Title, "…"+string(endpointRunes)) || choice.ID == "" || choice.ID == n.joined[1].Endpoint.ID {
		t.Fatal("form lost exact opaque target")
	}
	for _, private := range []string{n.f.workspace, n.f.native[0], n.f.native[1], n.nodes[0], n.nodes[1]} {
		if strings.Contains(choice.Title, private) {
			t.Fatal("Network form leaked hidden native/Node metadata")
		}
	}
	// Real pending request IDs, including cancelled/settled old requests,
	// are transport correlations. Neither a stale nor an unrelated response
	// may settle the current form. A later valid response still must work.
	c.send(t, map[string]any{"jsonrpc": "2.0", "id": "SYNTHETIC_QA_UNRELATED_FORM", "result": map[string]any{"action": "accept", "content": map[string]any{"peer": choice.ID}}})
	if len(c.lateForm) != 0 {
		if bytes.Equal(c.lateForm, f.ID) {
			t.Fatal("actual server reused a settled form request ID")
		}
		c.send(t, map[string]any{"jsonrpc": "2.0", "id": c.lateForm, "result": map[string]any{"action": "accept", "content": map[string]any{"peer": c.lateChoice}}})
	}
	result := map[string]any{"action": action}
	if action == "accept" {
		result["content"] = map[string]any{"peer": choice.ID}
	}
	if action == "forged" {
		result = map[string]any{"action": "accept", "content": map[string]any{"peer": "peeroption_SYNTHETIC_NOT_OFFERED"}}
	}
	c.send(t, map[string]any{"jsonrpc": "2.0", "id": f.ID, "result": result})
	response := c.response(t, id).Result
	c.lateForm = bytes.Clone(f.ID)
	c.lateChoice = choice.ID
	c.send(t, map[string]any{"jsonrpc": "2.0", "id": f.ID, "result": result}) // duplicate after settlement
	return response
}

func qaPeerMessageCount(t *testing.T, n *peerNetworkFixture) int {
	t.Helper()
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(n.f.root, "hub", "synthetic.sqlite3"), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal("readonly Hub observer unavailable")
	}
	defer db.Close()
	var count int
	if db.QueryRow(`SELECT count(*) FROM network_direct_message_routes_v2 WHERE network_id=?`, n.network).Scan(&count) != nil {
		t.Fatal("readonly actual Network count unavailable")
	}
	return count
}

func qaPeerStructured(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	out, ok := result["structuredContent"].(map[string]any)
	if !ok || result["isError"] == true {
		t.Fatal("actual selected operation did not return structured success")
	}
	return out
}

func qaRequirePeerError(t *testing.T, result map[string]any, code string) {
	t.Helper()
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 || result["isError"] != true {
		t.Fatal("actual peer operation did not return its typed tool error")
	}
	row, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("actual peer tool error shape invalid")
	}
	text, ok := row["text"].(string)
	if !ok || row["type"] != "text" || !strings.HasPrefix(text, code+":") {
		t.Fatal("actual peer tool error code differs from expected refusal")
	}
	if _, ok := result["structuredContent"]; ok {
		t.Fatal("refused peer operation included a structured success")
	}
}

type qaPeerAccessState struct {
	Epoch                     uint64
	Credential, Lease, Grants string
	Groups                    int
}

func qaReadPeerAccess(t *testing.T, n *peerNetworkFixture) qaPeerAccessState {
	t.Helper()
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(n.f.root, "hub", "synthetic.sqlite3"), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal("readonly original Network access observation unavailable")
	}
	defer db.Close()
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal("readonly original Network transaction unavailable")
	}
	defer tx.Rollback()
	var state qaPeerAccessState
	if tx.QueryRow(`SELECT a.epoch,a.credential_hash,a.lease_owner,m.grants_json,(SELECT count(*) FROM session_bindings b WHERE b.endpoint_id=a.endpoint_id)
FROM network_access_sessions_v2 a JOIN network_memberships_v2 m ON m.network_id=a.network_id AND m.principal_id=a.principal_id WHERE a.network_id=? AND a.endpoint_id=?`, n.network, n.joined[0].Endpoint.ID).Scan(&state.Epoch, &state.Credential, &state.Lease, &state.Grants, &state.Groups) != nil {
		t.Fatal("exact original independent Network access missing")
	}
	return state // Private memory only; never print the credential/lease/grants.
}

func TestQAPeerFormNetworkOnlyOriginalRecovery(t *testing.T) {
	for _, lose := range []bool{false, true} {
		name := "known-renewal"
		if lose {
			name = "post-commit-renewal-loss"
		}
		t.Run(name, func(t *testing.T) {
			n := newPeerNetworkFixture(t)
			m := n.formalMCP(t)
			if m.isJoined() {
				t.Fatal("Network-only fixture borrowed a Group")
			}
			before := qaReadPeerAccess(t, n)
			if before.Groups != 0 {
				t.Fatal("Network-only source already has Group authority")
			}
			path := peerFixtureNetworkStatePath(t, n, m)
			if os.Rename(path, path+".SYNTHETIC-original-retained") != nil {
				t.Fatal("original task-owned Network token could not be isolated")
			}
			var mu sync.Mutex
			posts := 0
			committedLoss := false
			n.f.mu.Lock()
			original := n.f.handler
			n.f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v2/fabric/node/networks/renew" {
					original.ServeHTTP(w, r)
					return
				}
				mu.Lock()
				posts++
				mu.Unlock()
				if !lose {
					original.ServeHTTP(w, r)
					return
				}
				recorder := httptest.NewRecorder()
				original.ServeHTTP(recorder, r)
				if recorder.Code >= 200 && recorder.Code < 300 {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = connection.Close()
						mu.Lock()
						committedLoss = true
						mu.Unlock()
						return
					}
				}
				for k, values := range recorder.Header() {
					for _, v := range values {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(recorder.Code)
				_, _ = w.Write(recorder.Body.Bytes())
			})
			n.f.mu.Unlock()
			c := qaStartPeerChild(t, m.localNode.Pin.UserRoot)
			if !lose {
				selected := qaPeerStructured(t, qaPeerSelect(t, n, m, c, "accept"))
				if selected["endpoint_id"] != n.joined[1].Endpoint.ID || qaPeerMessageCount(t, n) != 0 {
					t.Fatal("recovered Network-only selection did not retain exact peer without sending")
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal("known recovered original credential was not saved")
				}
				defer clear(raw)
				var recovered networkCLIState
				if decodeLocalNodeJSON(raw, &recovered) != nil || recovered.EndpointID != n.joined[0].Endpoint.ID || recovered.SessionToken == n.joined[0].SessionToken {
					t.Fatal("known renewal replaced original sender or did not save renewed token")
				}
				actor, err := n.service.AuthenticateForNetwork(recovered.SessionToken, n.network)
				if err != nil || actor.EndpointID != n.joined[0].Endpoint.ID {
					t.Fatal("known renewed token does not authenticate original endpoint")
				}
				if _, err := os.Stat(strings.TrimSuffix(path, ".session.json") + ".renew-pending.json"); !os.IsNotExist(err) {
					t.Fatal("known successful renewal retained a pending marker")
				}
			} else {
				refused := qaPeerCall(t, n, m, c, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})
				raw, _ := json.Marshal(refused)
				uncertain := refused["isError"] == true && bytes.Contains(raw, []byte("NETWORK_RENEW_UNCERTAIN"))
				clear(raw)
				if !uncertain {
					t.Fatal("lost committed original renewal did not remain uncertain")
				}
				c.close(t)
				c = qaStartPeerChild(t, m.localNode.Pin.UserRoot)
				for i := 0; i < 2; i++ {
					if qaPeerCall(t, n, m, c, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})["isError"] != true {
						t.Fatal("restart silently substituted a fresh renewal for unknown original")
					}
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("lost renewal response manufactured a saved token")
				}
				if _, err := os.Stat(strings.TrimSuffix(path, ".session.json") + ".renew-pending.json"); err != nil {
					t.Fatal("original renewal uncertainty fence disappeared")
				}
			}
			after := qaReadPeerAccess(t, n)
			if after.Epoch != before.Epoch+1 || after.Credential == before.Credential || after.Lease == before.Lease || after.Grants != before.Grants || after.Groups != 0 || qaPeerMessageCount(t, n) != 0 {
				t.Fatal("original independent renewal changed grants/Group authority, missed or repeated rotation")
			}
			mu.Lock()
			count, loss := posts, committedLoss
			mu.Unlock()
			if count != 1 || loss != lose {
				t.Fatal("original renewal was not exactly one observed real operation")
			}
			t.Log("QA_NETWORK_RECOVERY actual_CLI_TCP_Hub_Node=true original_network_only=true Group_bindings=0 renew_operations=1 no_new_grants=true no_business_effect=true explicit_synthetic_native_records=true")
		})
	}
}

func TestQAPeerFormRealNetworkProcessRestartAndLostResponse(t *testing.T) {
	n := newPeerNetworkFixture(t)
	m := n.formalMCP(t)
	keys := n.authorizeKeys(t)
	if n.nodes[0] == n.nodes[1] || n.joined[0].Endpoint.ID == n.joined[1].Endpoint.ID {
		t.Fatal("two distinct authorized Node/Endpoint registrations required")
	}
	// Keep the actual default Hub-Nodes entry. Existing permitted routes still
	// require their original credentials/Guard; prefix neighbors stay closed.
	for _, route := range []struct {
		method, path string
		exposed      bool
	}{
		{http.MethodGet, "/v2/fabric/networks/" + n.network + "/whoami", true},
		{http.MethodGet, "/v2/fabric/networks/" + n.network + "/directory", true},
		{http.MethodPost, "/v2/fabric/networks/" + n.network + "/resolve", true},
		{http.MethodPost, "/v2/fabric/node/networks/renew", true},
		{http.MethodPost, "/v2/fabric/node/networks/join", false},
		{http.MethodGet, "/v2/fabric/networks/" + n.network + "/whoami/extra", false},
		{http.MethodPost, "/v2/fabric/networks/" + n.network + "/directory", false},
		{http.MethodGet, "/v2/fabric/networks/" + n.network + "/synthetic-unknown", false},
	} {
		request, _ := http.NewRequest(route.method, n.f.server.URL+route.path, strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			t.Fatal("actual default Hub route probe failed")
		}
		_ = response.Body.Close()
		if route.exposed {
			if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
				t.Fatal("exposed default Hub route bypassed authentication or is missing")
			}
		} else if response.StatusCode != http.StatusNotFound {
			t.Fatal("default Hub route allowlist exposed a neighbor/method")
		}
	}
	t.Setenv("CICADA_NETWORK_SESSION_DIR", filepath.Join(t.TempDir(), "SYNTHETIC-poisoned-env-root"))
	for _, capability := range []struct {
		name  string
		value map[string]any
	}{
		{"missing", map[string]any{}},
		{"elicitation-null", map[string]any{"elicitation": nil}},
		{"form-null", map[string]any{"elicitation": map[string]any{"form": nil}}},
		{"form-bool", map[string]any{"elicitation": map[string]any{"form": true}}},
		{"url-only", map[string]any{"elicitation": map[string]any{"url": map[string]any{}}}},
	} {
		t.Run("unsupported-"+capability.name, func(t *testing.T) {
			old := qaStartPeerChild(t, m.localNode.Pin.UserRoot, capability.value)
			refused := qaPeerCall(t, n, m, old, "cicada_select_peer", map[string]any{"scope": "network", "network_id": n.network})
			qaRequirePeerError(t, refused, "PEER_FORM_UNSUPPORTED")
			if refused["isError"] != true || qaPeerMessageCount(t, n) != 0 {
				t.Fatal("unsupported Host selected or sent business")
			}
			old.close(t)
		})
	}
	var mu sync.Mutex
	var packetHashes []string
	drop := true
	lost := make(chan struct{}, 1)
	n.f.mu.Lock()
	original := n.f.handler
	n.f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/fabric/node/networks/direct/send" {
			original.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || len(raw) >= 1<<20 {
			http.Error(w, "SYNTHETIC bounded fault refusal", 500)
			return
		}
		defer clear(raw)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		digest := sha256.Sum256(raw)
		recorder := httptest.NewRecorder()
		original.ServeHTTP(recorder, r)
		mu.Lock()
		packetHashes = append(packetHashes, hex.EncodeToString(digest[:]))
		shouldDrop := drop
		drop = false
		mu.Unlock()
		if shouldDrop && recorder.Code == http.StatusAccepted {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
				lost <- struct{}{}
				return
			}
		}
		for k, values := range recorder.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	n.f.mu.Unlock()
	c := qaStartPeerChild(t, m.localNode.Pin.UserRoot)
	for _, action := range []string{"decline", "cancel", "forged"} {
		result := qaPeerSelect(t, n, m, c, action)
		if result["isError"] != true || qaPeerMessageCount(t, n) != 0 {
			t.Fatal("cancelled/forged Network choice produced business effect")
		}
		if _, ok := result["structuredContent"]; ok {
			t.Fatal("cancelled/forged choice produced a selection")
		}
		qaRequirePeerError(t, result, map[string]string{"decline": "MCP_FORM_DECLINED", "cancel": "MCP_FORM_CANCELLED", "forged": "MCP_FORM_INVALID"}[action])
	}
	selected := qaPeerStructured(t, qaPeerSelect(t, n, m, c, "accept"))
	if selected["endpoint_id"] != n.joined[1].Endpoint.ID || selected["scope_id"] != n.network || qaPeerMessageCount(t, n) != 0 {
		t.Fatal("real Hub Network selection retargeted/sent business")
	}
	handle, ok := selected["peer_selection_id"].(string)
	if !ok || handle == "" {
		t.Fatal("actual selection handle missing")
	}
	body := "SYNTHETIC-QA selected cross-Node sealed body"
	args := map[string]any{"peer_selection_id": handle, "body": body, "idempotency_key": "SYNTHETIC-QA-original-selected"}
	uncertain := qaPeerStructured(t, qaPeerCall(t, n, m, c, "cicada_send", args))
	operation, ok := uncertain["operation_id"].(string)
	if !ok || operation == "" || uncertain["status"] != mcpOutboxStatusUnknown {
		t.Fatal("post-commit response loss did not retain UNKNOWN original")
	}
	select {
	case <-lost:
	case <-time.After(time.Second):
		t.Fatal("actual post-commit TCP response was not dropped")
	}
	if qaPeerMessageCount(t, n) != 1 {
		t.Fatal("actual lost-response send did not commit exactly once")
	}
	pid := c.cmd.Process.Pid
	c.close(t) // Actual OS process exit loses every in-memory choice.
	c2 := qaStartPeerChild(t, m.localNode.Pin.UserRoot)
	if c2.cmd.Process.Pid == pid || c2.nonce == c.nonce {
		t.Fatal("actual MCP process/connection did not restart")
	}
	recovered := qaPeerStructured(t, qaPeerCall(t, n, m, c2, "cicada_send", args))
	if recovered["operation_id"] != operation || recovered["status"] != mcpOutboxStatusUnknown || qaPeerMessageCount(t, n) != 1 {
		t.Fatal("restart exact retry replaced/resent original uncertainty")
	}
	changed := map[string]any{"peer_selection_id": handle, "body": body + " changed", "idempotency_key": args["idempotency_key"]}
	if qaPeerCall(t, n, m, c2, "cicada_send", changed)["isError"] != true {
		t.Fatal("changed original intent was recovered")
	}
	retried := qaPeerStructured(t, qaPeerCall(t, n, m, c2, "cicada_operation_retry", map[string]any{"network_id": n.network, "operation_id": operation}))
	if retried["operation_id"] != operation || retried["status"] != mcpOutboxStatusSent || qaPeerMessageCount(t, n) != 1 {
		t.Fatal("explicit original packet retry did not recover one effect")
	}
	mu.Lock()
	hashes := append([]string(nil), packetHashes...)
	mu.Unlock()
	if len(hashes) != 2 || hashes[0] != hashes[1] {
		t.Fatal("explicit retry changed original sealed HTTP packet")
	}
	claimed, err := n.f.db.ClaimNetworkDirectSealedInbox(store.NetworkDirectClaimInput{NodeID: n.nodes[1], ConsumerID: "SYNTHETIC-QA-receiver", Limit: 4, CredentialDigest: fabric.HashSessionCredential(n.tokens[1])})
	if err != nil || len(claimed) != 1 {
		t.Fatal("exact selected second Node did not receive one sealed message")
	}
	auth, err := n.f.db.AuthorizeClaimedNetworkDirectDelivery(fabric.HashSessionCredential(n.tokens[1]), claimed[0].MessageID, claimed[0].AttemptID)
	if err != nil {
		t.Fatal("real current Hub Guard refused original delivery")
	}
	plain, _, err := e2ee.OpenNetworkDirectMessage(keys[1], keys[0].Public(), auth.Context, claimed[0].Ciphertext)
	defer clear(plain)
	if err != nil || string(plain) != body {
		t.Fatal("actual selected Endpoint could not decrypt original body")
	}
	if newArgs := map[string]any{"peer_selection_id": handle, "body": "SYNTHETIC new-after-restart", "idempotency_key": "SYNTHETIC different-key"}; qaPeerCall(t, n, m, c2, "cicada_send", newArgs)["isError"] != true || qaPeerMessageCount(t, n) != 1 {
		t.Fatal("restart revived a lost in-memory selection for new business")
	}
	t.Log("QA_PEER_NETWORK real_Hub_TCP_SQLite_crypto=true two_authorized_Node_registrations=true actual_MCP_process_restart=true synthetic_native_records=true native_Runtime=NOT_RUN standard_form=true cancelled_forged_zero_send=true selection_no_send=true exact_target_decrypt=true post_commit_response_loss=true UNKNOWN_retained=true fresh_Hook_per_call=true exact_retry_no_resend=true explicit_retry_same_packet=true one_effect=true environment_not_authority=true")
}
