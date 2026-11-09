//go:build linux && cicada_scoped_app_integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

type nodeHubAcceptanceThread struct {
	native, workspace, transcript string
}

type nodeHubOutboxSnapshot struct {
	digest [32]byte
	schema [32]byte
	rows   []string
}

func nodeHubReadOnlyOutboxSnapshot(t *testing.T, path string) nodeHubOutboxSnapshot {
	t.Helper()
	// Include live WAL rows through a read-only connection. File/WAL bytes may
	// change during a legitimate SQLite checkpoint; original row and metadata
	// contents must remain exact while another Hub or local lifecycle runs.
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String())
	if err != nil {
		t.Fatal("original outbox snapshot open", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tables, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal("original outbox schema snapshot", err)
	}
	var names []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	err = tables.Err()
	tables.Close()
	if err != nil || len(names) == 0 {
		t.Fatal("original outbox tables absent", err)
	}
	schema, err := json.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := []string{"tables:" + string(schema)}
	for _, name := range names {
		rows, err := db.Query(`SELECT * FROM "` + strings.ReplaceAll(name, `"`, `""`) + `"`)
		if err != nil {
			t.Fatal("original outbox row snapshot", err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			raw, err := json.Marshal([]any{name, columns, values})
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			snapshot = append(snapshot, string(raw))
			clear(raw)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(snapshot)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	return nodeHubOutboxSnapshot{digest: sha256.Sum256(raw), schema: sha256.Sum256(schema), rows: snapshot}
}

func nodeHubSyntheticThread(t *testing.T, label string) nodeHubAcceptanceThread {
	t.Helper()
	s := nodeHubAcceptanceThread{native: "SYNTHETIC-hub-lifecycle-" + label, workspace: privateLocalNodeRoot(t)}
	s.transcript = filepath.Join(os.Getenv("CODEX_HOME"), "sessions", "2026", "11", "04", "rollout-SYNTHETIC-"+s.native+".jsonl")
	if err := os.MkdirAll(filepath.Dir(s.transcript), 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": s.native, "session_id": s.native, "cwd": s.workspace, "source": "vscode", "originator": "codex-tui"}})
	if err != nil || os.WriteFile(s.transcript, append(raw, '\n'), 0600) != nil {
		t.Fatal("synthetic native record")
	}
	return s
}

func (f *nodeHubLifecycleAcceptance) activateGroup(index int) appcore.LocalCollaborationSnapshot {
	f.t.Helper()
	hub := f.hubs[index]
	connection, err := ResolveLocalNodeConnection(f.ctx, LocalNodeSelection{UserRoot: f.root, HubID: hub.native.d.Claims.Hub.HubID}, nil)
	if err != nil {
		f.t.Fatal("actual Node for App local collaboration", err)
	}
	f.eventually("actual worker signed local-user report", 10*time.Second, func() bool {
		client, _, err := loadMachineRecoveryClient(connection.Pin.StateDir, connection.Pin.NodeID)
		return err == nil && client.state.LocalDomainReport != nil && client.state.LocalDomainReport.Failures == 0 && client.state.LocalDomainReport.ObservedAt != ""
	})
	hub.dispatch(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration})
	hub.dispatch(appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration, LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "SYNTHETIC same Network name", GroupName: "SYNTHETIC same Group name"}})
	hub.dispatch(appcore.Action{Kind: appcore.ActionActivateLocalCollaboration, LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: hub.app.Snapshot().LocalCollaboration.ReviewID, ConfirmActivation: true}})
	s := hub.app.Snapshot().LocalCollaboration
	if s.State != wire.LocalDomainActive || s.NetworkID == "" || s.GroupID == "" || !s.Current {
		f.t.Fatal("actual App current Group activation absent")
	}
	return s
}

func (f *nodeHubLifecycleAcceptance) register(connection LocalNodeConnection, thread nodeHubAcceptanceThread) *mcpCachedSession {
	f.t.Helper()
	return f.registerAs(connection, thread, "")
}

func (f *nodeHubLifecycleAcceptance) registerAs(connection LocalNodeConnection, thread nodeHubAcceptanceThread, class string) *mcpCachedSession {
	f.t.Helper()
	// Use the current production CLI operator with an exact original owned
	// Thread record and managed alias. It owns intent persistence, actual Node
	// tickets, Join/key receipts and the original private cache. Historical
	// UserPromptSubmit internal Hooks do not qualify this current entry.
	alias := ""
	for _, candidate := range []string{"SYNTHETIC-A", "SYNTHETIC-B"} {
		if e, ok := f.entry(candidate); ok && e.ConnectionID == connection.Pin.ConnectionID {
			alias = candidate
		}
	}
	if alias == "" && connection.Pin.ConnectionID != "" {
		f.t.Fatal("actual current connection alias absent")
	}
	args := []string{"--thread", thread.native, "--name", "SYNTHETIC original Thread", "--user-root", f.root}
	if alias != "" {
		args = append(args, "--hub", alias)
	} else {
		args = append(args, "--hub-id", connection.Pin.HubID)
	}
	var output bytes.Buffer
	firstErr := nativeThreadOperatorCommand("join", args, &output)
	clear(output.Bytes())
	output.Reset()
	if firstErr != nil && !strings.Contains(firstErr.Error(), wire.ThreadCollaborationErrorClassificationRequired) && !strings.HasSuffix(firstErr.Error(), ": CLASSIFICATION_REQUIRED") {
		f.t.Fatal("actual CLI zero-stage registration", firstErr)
	}
	f.classifyThread(connection, thread, class)
	if err := nativeThreadOperatorCommand("join", args, &output); err != nil {
		f.t.Fatal("actual CLI original registration after explicit Owner classification", err)
	}
	clear(output.Bytes())
	cached, err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).load(connection.Pin.APIOrigin, harness.SessionContext{Harness: "codex", NativeSessionID: thread.native, MachineID: connection.Pin.NodeID, Workspace: thread.workspace})
	if err != nil || cached == nil {
		f.t.Fatalf("actual CLI cache absent after original Join: cache_present=%t read_error=%t", cached != nil, err != nil)
	}
	if cached.SessionToken == "" || cached.EndpointID == "" || cached.ConnectionPin == nil || *cached.ConnectionPin != connection.Pin {
		f.t.Fatalf("actual CLI did not retain original Endpoint/session/pin: token=%t endpoint=%t pin=%t same_pin=%t endpoint_groups=%d local_domain=%d", cached.SessionToken != "", cached.EndpointID != "", cached.ConnectionPin != nil, cached.ConnectionPin != nil && *cached.ConnectionPin == connection.Pin, cached.EndpointGroupsVersion, cached.LocalDomainVersion)
	}
	return cached
}

func (f *nodeHubLifecycleAcceptance) tool(m *mcpServer, thread nodeHubAcceptanceThread, name string, business map[string]any) (any, error) {
	f.t.Helper()
	input := make(map[string]any, len(business)+1)
	for k, v := range business {
		input[k] = v
	}
	nonce := ""
	reserved := map[string]any{}
	flags := []string{"--user-root", f.root}
	if m.codexFacade != nil {
		nonce = m.codexFacade.nonce
		reserved["routing_version"] = codexRoutingVersion
	} else {
		nonce = m.codexContext.nonce
		p := m.localNode.Pin
		flags = append(flags, "--hub-id", p.HubID, "--node-id", p.NodeID)
	}
	reserved["connection_nonce"] = nonce
	input[codexMCPContextArgument] = reserved
	event := codexHookInput{Event: "PreToolUse", SessionID: thread.native, CWD: thread.workspace, TranscriptPath: thread.transcript, ToolName: "mcp__cicada__" + name, ToolInput: input, TurnID: "SYNTHETIC-current-turn", ToolUseID: "SYNTHETIC-current-tool"}
	var output bytes.Buffer
	rawEvent, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	// Exercise the current CLI/stdin Hook entry and its production default
	// enumerator/adoption wiring. Host coordinates never enter tool business
	// arguments; child tickets are issued and replaced only by the real Hook.
	if err := runCodexHook(flags, bytes.NewReader(rawEvent), &output); err != nil {
		return nil, fmt.Errorf("actual Hook runner: %w", err)
	}
	var hook struct {
		Specific struct {
			Decision string         `json:"permissionDecision"`
			Reason   string         `json:"permissionDecisionReason"`
			Updated  map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(output.Bytes(), &hook); err != nil {
		return nil, err
	}
	clear(output.Bytes())
	if hook.Specific.Decision != "allow" {
		code := strings.SplitN(hook.Specific.Reason, ":", 2)[0]
		if code == "" || len(code) > 80 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			code = "REDACTED_NON_CODE_REASON"
		}
		return nil, fmt.Errorf("actual Hook denied: %s: %w", code, errCodexMCPContext)
	}
	value, err := m.callTool(name, hook.Specific.Updated)
	if err != nil {
		return nil, fmt.Errorf("actual MCP after Hook allow: %w", err)
	}
	return value, nil
}

func (f *nodeHubLifecycleAcceptance) selectGroup(m *mcpServer, thread nodeHubAcceptanceThread, pin LocalNodeConnectionPin, group appcore.LocalCollaborationSnapshot) {
	f.t.Helper()
	if _, err := f.tool(m, thread, "cicada_use_group", map[string]any{"hub_id": pin.HubID, "network_id": group.NetworkID, "group_id": group.GroupID}); err != nil {
		f.t.Fatal("actual exact Hub/Network/Group selection", err)
	}
}

func (f *nodeHubLifecycleAcceptance) send(m *mcpServer, sender nodeHubAcceptanceThread, target, key, body string) string {
	f.t.Helper()
	value, err := f.tool(m, sender, "cicada_send", map[string]any{"target": target, "body": body, "idempotency_key": key})
	if err != nil {
		f.t.Fatal("actual facade sealed SEND", err)
	}
	raw, err := json.Marshal(value)
	var result struct {
		MessageID string `json:"message_id"`
	}
	if err != nil || json.Unmarshal(raw, &result) != nil || result.MessageID == "" {
		f.t.Fatal("actual facade SEND receipt missing")
	}
	return result.MessageID
}

func (f *nodeHubLifecycleAcceptance) waitInbox(connection LocalNodeConnection, target *mcpCachedSession, thread nodeHubAcceptanceThread, id, body, want string) (string, uint64) {
	f.t.Helper()
	// Observe the production worker's durable inbox. Never compete with it
	// using an SDK claim, stop it to steal a delivery, or preseed an inbox row.
	var digest, state string
	var payload []byte
	var epoch uint64
	f.eventually("actual Agent decrypted inbox and native state "+want, 15*time.Second, func() bool {
		for _, path := range []string{machineLocalGroupInboxPath(connection.Pin.StateDir, connection.Pin.NodeID), machineNodeInboxPath(connection.Pin.StateDir, connection.Pin.NodeID)} {
			dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
			db, err := sql.Open("sqlite", dsn)
			if err != nil {
				continue
			}
			err = db.QueryRowContext(context.Background(), `SELECT digest,state,payload,binding_epoch FROM node_inbox_deliveries WHERE message_id=? AND endpoint_id=? AND session_id=?`, id, target.EndpointID, thread.native).Scan(&digest, &state, &payload, &epoch)
			_ = db.Close()
			if err == nil && state == want && bytes.Equal(payload, []byte(body)) && epoch == target.BindingEpoch {
				return true
			}
		}
		return false
	})
	clear(payload)
	return digest, epoch
}

func (f *nodeHubLifecycleAcceptance) assertDelivered(connection LocalNodeConnection, target *mcpCachedSession, thread nodeHubAcceptanceThread, id, body string) {
	f.t.Helper()
	digest, epoch := f.waitInbox(connection, target, thread, id, body, "CONSUMPTION_UNCONFIRMED")
	outcome, err := nodelock.InspectNativeMessageOutcome(connection.Pin.WriterRoot, machineNativeWriterScope(), "codex", thread.native, nodelock.NativeOperation{HubID: connection.Pin.HubID, NodeID: connection.Pin.NodeID, EndpointID: target.EndpointID, MessageID: id, Digest: digest, BindingEpoch: epoch})
	if err != nil || outcome != nodelock.NativeQueueAccepted {
		f.t.Fatal("actual exact original native writer outcome absent", err)
	}
	sum := sha256.Sum256([]byte(thread.native))
	raw, err := os.ReadFile(filepath.Join(f.queueRoot, hex.EncodeToString(sum[:])+".argv"))
	defer clear(raw)
	var argv []string
	if err != nil || json.Unmarshal(raw, &argv) != nil || len(argv) != 5 || argv[2] != thread.native || !strings.Contains(argv[4], body) {
		f.t.Fatal("real offline queue subprocess lost original Thread/plaintext")
	}
}

func TestNodeHubLifecycleNativeUnknownRemainsFencedAcceptance(t *testing.T) {
	f := newNodeHubLifecycleAcceptance(t)
	a, b := f.add(0), f.add(1)
	group := f.activateGroup(0)
	sender, receiver := nodeHubSyntheticThread(t, "unknown-sender"), nodeHubSyntheticThread(t, "unknown-receiver")
	f.register(a, sender)
	target := f.register(a, receiver)
	m, err := newRoutedLocalNodeMCPServer(f.root, ListVerifiedLocalNodeConnections)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.codexFacade.close(); close(m.stop) })
	if _, err := f.tool(m, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("actual A Group view before native uncertainty", err)
	}
	f.selectGroup(m, sender, a.Pin, group)
	f.queueMu.Lock()
	f.queueExit = 23
	f.queueMu.Unlock()
	body := "SYNTHETIC started queue with unconfirmed effect"
	id := f.send(m, sender, target.EndpointID, "SYNTHETIC-started-unknown", body)
	digest, epoch := f.waitInbox(a, target, receiver, id, body, "INJECTION_UNCERTAIN")
	outcome, err := nodelock.InspectNativeMessageOutcome(a.Pin.WriterRoot, machineNativeWriterScope(), "codex", receiver.native, nodelock.NativeOperation{HubID: a.Pin.HubID, NodeID: a.Pin.NodeID, EndpointID: target.EndpointID, MessageID: id, Digest: digest, BindingEpoch: epoch})
	if err != nil || outcome != nodelock.NativeUncertain || f.queueCount(receiver.native) != 1 {
		t.Fatal("started failing real queue did not retain exact native uncertainty", err)
	}
	removed, err := RemoveLocalNodeHubConnection(f.ctx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: a.Pin.ConnectionID})
	if err != nil || removed.State != "STOP_PENDING" || removed.LocalFence != a.Pin.ConnectionEpoch+1 || removed.RemoteRevocation != "NOT_REQUESTED" {
		t.Fatal("genuine native uncertainty was reported locally stopped", err)
	}
	f.assertUnchanged(b)
	f.stop()
	f.start()
	f.eventually("cold B remains available with uncertain A fenced", 12*time.Second, func() bool {
		v, e := ListVerifiedLocalNodeConnections(f.ctx, f.root)
		return e == nil && len(v) == 1 && v[0].Pin == b.Pin
	})
	entry, exists := f.entry("SYNTHETIC-A")
	if !exists || entry.DesiredState != "REMOVING" || entry.LocalFence != removed.LocalFence || f.queueCount(receiver.native) != 1 {
		t.Fatal("cold manager forgot uncertainty, resurrected A, or reinjected original")
	}
	_, _ = f.waitInbox(a, target, receiver, id, body, "INJECTION_UNCERTAIN")
	t.Log("actual Agent/Group/native Start with failing synthetic subprocess retains STOP_PENDING across cold reopen; no consumed/cancelled/remote-revoked result; native Runtime NOT_RUN")
}

func TestNodeHubLifecycleActualFacadeGroupAndInboxAcceptance(t *testing.T) {
	f := newNodeHubLifecycleAcceptance(t)
	sender, receiver := nodeHubSyntheticThread(t, "sender"), nodeHubSyntheticThread(t, "receiver")
	a := f.add(0)
	ga := f.activateGroup(0)
	sa, ra := f.register(a, sender), f.register(a, receiver)
	m, err := newRoutedLocalNodeMCPServer(f.root, ListVerifiedLocalNodeConnections)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.codexFacade.close(); close(m.stop) })
	if _, err := f.tool(m, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("actual original A Group view", err)
	}
	f.selectGroup(m, sender, a.Pin, ga)
	id := f.send(m, sender, ra.EndpointID, "SYNTHETIC-A-before-B", "SYNTHETIC A before adding B")
	f.assertDelivered(a, ra, receiver, id, "SYNTHETIC A before adding B")
	// Lose a genuine committed App Group-read response while the original
	// ciphertext is already durable. B must not recover or migrate A's work.
	f.hubs[0].mu.Lock()
	f.hubs[0].dropPath = wire.LocalDomainHTTPPath(wire.OperationLocalDomainStatus)
	f.hubs[0].mu.Unlock()
	if err := f.hubs[0].app.Dispatch(f.ctx, appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}); err == nil || !f.hubs[0].app.Snapshot().LocalCollaboration.Pending {
		t.Fatal("committed lost original did not remain uncertain in actual App")
	}
	f.hubs[0].mu.Lock()
	dropped, status := f.hubs[0].droppedDigest, f.hubs[0].droppedStatus
	f.hubs[0].mu.Unlock()
	if dropped == ([32]byte{}) || status != http.StatusOK {
		t.Fatal("lost original did not first commit through actual Hub Guard/Store")
	}
	originalVault := readTreeHashesForNativeTLS(t, f.hubs[0].vaultRoot)
	retainOriginal := func() {
		t.Helper()
		if !f.hubs[0].app.Snapshot().LocalCollaboration.Pending || !reflect.DeepEqual(originalVault, readTreeHashesForNativeTLS(t, f.hubs[0].vaultRoot)) {
			t.Fatal("B lifecycle rewrote A's original encrypted vault/CAS")
		}
	}
	b := f.add(1)
	f.assertUnchanged(a)
	retainOriginal()
	gb := f.activateGroup(1)
	sb, rb := f.register(b, sender), f.register(b, receiver)
	if sa.EndpointID == sb.EndpointID || ra.EndpointID == rb.EndpointID || sa.SessionToken == sb.SessionToken || ga.NetworkID == gb.NetworkID || ga.GroupID == gb.GroupID || ga.GroupName != gb.GroupName {
		t.Fatal("actual independently granted Group/Endpoint/session scopes collided")
	}
	value, err := f.tool(m, sender, "cicada_groups", map[string]any{})
	if err != nil {
		t.Fatal("actual two-Hub facade Group enumeration", err)
	}
	raw, _ := json.Marshal(value)
	var groups struct {
		Complete bool `json:"complete"`
		Groups   []struct {
			HubID     string `json:"hub_id"`
			NetworkID string `json:"network_id"`
			GroupID   string `json:"group_id"`
		} `json:"groups"`
	}
	if json.Unmarshal(raw, &groups) != nil || !groups.Complete || len(groups.Groups) != 2 {
		t.Fatal("actual facade did not expose both complete scoped Groups")
	}
	seen := map[string]bool{}
	for _, g := range groups.Groups {
		if g.HubID == a.Pin.HubID && g.NetworkID == ga.NetworkID && g.GroupID == ga.GroupID || g.HubID == b.Pin.HubID && g.NetworkID == gb.NetworkID && g.GroupID == gb.GroupID {
			seen[g.HubID] = true
		}
	}
	if len(seen) != 2 {
		t.Fatal("actual Group cards substituted a Network's authoritative Hub")
	}
	if _, err := f.tool(m, sender, "cicada_use_group", map[string]any{"hub_id": a.Pin.HubID, "network_id": gb.NetworkID, "group_id": gb.GroupID}); err == nil {
		t.Fatal("mixed A Hub/B Network/Group selection admitted")
	}
	f.selectGroup(m, sender, b.Pin, gb)
	id = f.send(m, sender, rb.EndpointID, "SYNTHETIC-B-after-add", "SYNTHETIC B after adding B")
	f.assertDelivered(b, rb, receiver, id, "SYNTHETIC B after adding B")
	// A real outage also drops active outbound event streams; Close alone
	// waits forever for the Agent's live SSE connection to finish normally.
	_ = f.hubs[0].server.Listener.Close() // prevent a new SSE connection
	f.hubs[0].server.CloseClientConnections()
	f.hubs[0].server.Close()
	// A has actual accepted queue history, with Hub consumption unconfirmed.
	// Offline transport alone is not a native uncertainty or remote revocation.
	removed, err := RemoveLocalNodeHubConnection(f.ctx, LocalNodeHubSelection{UserRoot: f.root, ConnectionID: a.Pin.ConnectionID})
	if err != nil || removed.State != "LOCAL_STOPPED" || removed.RemoteRevocation != "NOT_REQUESTED" {
		t.Fatal("used offline A did not locally quiesce with accepted history", err)
	}
	f.assertUnchanged(b)
	id = f.send(m, sender, rb.EndpointID, "SYNTHETIC-B-after-remove", "SYNTHETIC B after removing A")
	f.assertDelivered(b, rb, receiver, id, "SYNTHETIC B after removing A")
	retainOriginal()
	f.stop()
	f.start()
	f.eventually("cold original B ready", 12*time.Second, func() bool {
		v, e := ListVerifiedLocalNodeConnections(f.ctx, f.root)
		return e == nil && len(v) == 1 && v[0].Pin == b.Pin
	})
	if _, exists := f.entry("SYNTHETIC-A"); exists {
		t.Fatal("cold manager resurrected used A")
	}
	// Existing consumer refresh must retain the original Endpoint and SID;
	// no fresh Join or identity construction fills a restart failure.
	if _, err := f.tool(m, sender, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("cold actual Group view", err)
	}
	f.selectGroup(m, sender, b.Pin, gb)
	id = f.send(m, sender, rb.EndpointID, "SYNTHETIC-B-after-cold", "SYNTHETIC B after cold reopen")
	f.assertDelivered(b, rb, receiver, id, "SYNTHETIC B after cold reopen")
	retainOriginal()
	t.Log("SYNTHETIC current NPT/App/Group crypto/actual facade+Hook/Agent inbox/offline queue only; native Runtime/systemd/Windows NOT_RUN")
}
