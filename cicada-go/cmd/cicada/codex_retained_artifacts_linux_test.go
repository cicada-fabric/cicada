//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
)

func TestCodexRetainedArtifactsRequirePurposeProof(t *testing.T) {
	root := privateLocalNodeRoot(t)
	original := syntheticLocalNodePin(t, root, "synthetic-node")
	current := syntheticManagedAdoption(LocalNodeConnection{Pin: original}).Pin
	current.ConnectionEpoch = 3
	ctx := context.Background()
	// The adapter cannot infer the purpose proof from matching metadata. Both
	// accepted source relationships below use an explicitly injected producer.
	for _, historical := range []LocalNodeConnectionPin{original, func() LocalNodeConnectionPin { p := current; p.ConnectionEpoch = 1; return p }()} {
		if validateCodexStoredArtifact(ctx, historical, current, nil, nil) == nil {
			t.Fatal("matching IDs inferred retained custody")
		}
		calls := 0
		proof := func(_ context.Context, old, live LocalNodeConnectionPin) error {
			calls++
			if old != historical || live != current {
				return ErrLocalNodeBindingChanged
			}
			return nil
		}
		if err := validateCodexStoredArtifact(ctx, historical, current, nil, proof); err != nil || calls != 1 {
			t.Fatal("exact storage proof refused", err)
		}
		if sameLocalNodeAuthority(historical, current) || validateCodexAdoption(ctx, historical, current, nil) == nil {
			t.Fatal("storage purpose widened live/adoption equality")
		}
		denied := func(context.Context, LocalNodeConnectionPin, LocalNodeConnectionPin) error {
			return ErrLocalNodeBindingChanged
		}
		if validateCodexStoredArtifact(ctx, historical, current, nil, denied) == nil {
			t.Fatal("missing retirement proof accepted")
		}
		for _, change := range []func(*LocalNodeConnectionPin){
			func(p *LocalNodeConnectionPin) { p.ConnectionID = strings.Repeat("e", 32) },
			func(p *LocalNodeConnectionPin) { p.Binding.HubFingerprint = strings.Repeat("c", 64) },
			func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyEpoch++ },
			func(p *LocalNodeConnectionPin) { p.WriterRoot = filepath.Join(root, "SYNTHETIC-other-writer") },
			func(p *LocalNodeConnectionPin) { p.ConnectionEpoch = 0 },
		} {
			bad := current
			change(&bad)
			if validateCodexStoredArtifact(ctx, historical, bad, nil, proof) == nil {
				t.Fatal("changed authority borrowed data proof")
			}
		}
	}
}

func setCodexProducerEpoch(t *testing.T, f *codexFacadeProducerNode, epoch uint64) LocalNodeConnection {
	t.Helper()
	f.mu.Lock()
	f.connection.Pin.ConnectionID, f.connection.Pin.ConnectionEpoch = strings.Repeat("d", 32), epoch
	current := f.connection
	f.mu.Unlock()
	installRetainedArtifactEntry(t, current.Pin)
	return current
}

func switchCodexProducerThread(t *testing.T, f *codexFacadeProducerNode, sid string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	selected := f.last.Relation.GroupID
	f.profile.NativeSessionID = sid
	r := f.pages[0].Registration.Registration
	r.NativeSessionID, r.EndpointID, r.PrincipalID = sid, "SYNTHETIC-new-thread-endpoint", "SYNTHETIC-new-thread-principal"
	digest, err := e2ee.EndpointGroupRegistrationDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	f.profile.RegistrationDigest = digest
	for page := range f.pages {
		f.pages[page].Registration.Registration = r
		f.pages[page].Registration.RegistrationDigest = digest
		for i := range f.pages[page].Authorities {
			a := &f.pages[page].Authorities[i]
			a.Relation.EndpointID, a.Relation.PrincipalID, a.Relation.RegistrationDigest = r.EndpointID, r.PrincipalID, digest
			if a.Relation.GroupID == selected {
				f.last = *a
			}
		}
	}
}

// Real Hook/front/child, Unix issue/consume and SQLite adapters, but synthetic
// private peers. Production Hub Guard/current NPT/native writer belong to QA.
func TestCodexFacadeRetainedArtifactsKeepOriginalAndPermitFreshCalls(t *testing.T) {
	root, workspace := privateLocalNodeRoot(t), privateLocalNodeRoot(t)
	const sid = "synthetic-retained-original-thread"
	f := newCodexFacadeProducerNode(t, root, "synthetic-node", sid, workspace)
	f.mu.Lock()
	f.last = f.pages[0].Authorities[63]
	f.mu.Unlock()
	original := setCodexProducerEpoch(t, f, 1)
	connections := []LocalNodeConnection{original}
	list := func(context.Context, string) ([]LocalNodeConnection, error) { return connections, nil }
	front, err := newRoutedLocalNodeMCPServer(root, list)
	if err != nil {
		t.Fatal(err)
	}
	defer front.codexFacade.close()
	choice := map[string]any{"hub_id": original.Pin.HubID, "network_id": f.last.Relation.NetworkID, "group_id": f.last.Relation.GroupID}
	invoke := func(m *mcpServer, thread, tool string, args map[string]any) (any, error) {
		return m.callTool(tool, codexFacadeProducerInput(t, m, list, thread, workspace, tool, args))
	}
	if _, err := invoke(front, sid, "cicada_use_group", choice); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.loseSendReply = true
	f.mu.Unlock()
	value, err := invoke(front, sid, "cicada_send", map[string]any{"target": "SYNTHETIC-target", "body": "SYNTHETIC-original-message", "idempotency_key": "SYNTHETIC-original-key"})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	id := result["operation_id"].(string)
	if result["status"] != mcpOutboxStatusUnknown {
		t.Fatalf("lost reply not uncertain: %v", result["status"])
	}
	native := mcpTrustedContext{Harness: "codex", NativeSessionID: sid, NodeID: original.Pin.NodeID, Workspace: workspace}
	oldOp, pin, err := readMCPFacadeOperation(original.Pin, native, id)
	if err != nil || pin != original.Pin {
		t.Fatal("original outbox not pinned", err)
	}
	oldFrame := codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_whoami", map[string]any{})
	connections = nil
	if _, err := front.callTool("cicada_whoami", oldFrame); err == nil {
		t.Fatal("removed live route accepted")
	}
	current := setCodexProducerEpoch(t, f, 3)
	connections = []LocalNodeConnection{current}
	if _, err := front.callTool("cicada_whoami", oldFrame); err == nil {
		t.Fatal("old parent/child frame survived re-add")
	}
	if err := revalidateCodexLocalNode(context.Background(), &original); err == nil {
		t.Fatal("old live pin survived data bridge")
	}
	if _, err := invoke(front, sid, "cicada_whoami", map[string]any{}); err != nil {
		t.Fatal("fresh original Thread context refused retained cache", err)
	}
	// Storage validation alone leaves every original DB/WAL byte untouched.
	oldDB, _ := os.ReadFile(original.Pin.MCPOutboxStateFile)
	oldWAL, _ := os.ReadFile(original.Pin.MCPOutboxStateFile + "-wal")
	childID, _ := codexChildRouteID(current.Pin)
	child := front.codexFacade.children[childID]
	if _, err := child.ensureMCPOutbox(); err != nil {
		t.Fatal("retained DB adapter refused", err)
	}
	newDB, _ := os.ReadFile(original.Pin.MCPOutboxStateFile)
	newWAL, _ := os.ReadFile(original.Pin.MCPOutboxStateFile + "-wal")
	if !bytes.Equal(oldDB, newDB) || !bytes.Equal(oldWAL, newWAL) || child.localNode.Pin != current.Pin || child.outbox.connectionPin == nil || *child.outbox.connectionPin != original.Pin {
		t.Fatal("data adapter rewrote or promoted old storage pin")
	}
	// A known changed remote source cannot lend the original UNKNOWN a grant.
	f.mu.Lock()
	f.pages[0].Authorities[63].Relation.AuthorityEpoch++
	f.mu.Unlock()
	if _, err := invoke(front, sid, "cicada_operation_retry", map[string]any{"operation_id": id}); err == nil {
		t.Fatal("changed grant rescued original UNKNOWN")
	}
	still, _, err := readMCPFacadeOperation(current.Pin, native, id)
	if err != nil || still != oldOp {
		t.Fatal("denied retry changed original/attempt", err)
	}
	f.mu.Lock()
	f.pages[0].Authorities[63].Relation.AuthorityEpoch--
	f.mu.Unlock()
	// The private peer repeats the exact saved source check. This is not a
	// production Hub Guard acceptance claim.
	value, err = invoke(front, sid, "cicada_operation_retry", map[string]any{"operation_id": id})
	if err != nil || value.(map[string]any)["status"] != mcpOutboxStatusSent {
		t.Fatal("exact original retry refused", err)
	}
	f.mu.Lock()
	exactRetry := len(f.sends) == 2 && reflect.DeepEqual(f.sends[0], f.sends[1]) && len(f.deliveries) == 1
	f.mu.Unlock()
	if !exactRetry {
		t.Fatal("retry changed original packet/idempotency or duplicated synthetic effect")
	}
	for _, fresh := range []string{sid, "synthetic-retained-new-thread"} {
		m := front
		if fresh != sid {
			switchCodexProducerThread(t, f, fresh)
			m, err = newRoutedLocalNodeMCPServer(root, list)
			if err != nil {
				t.Fatal(err)
			}
			defer m.codexFacade.close()
		}
		if _, err := invoke(m, fresh, "cicada_use_group", choice); err != nil {
			t.Fatal("fresh current Group choice refused", err)
		}
		value, err := invoke(m, fresh, "cicada_send", map[string]any{"target": "SYNTHETIC-target", "body": "SYNTHETIC-fresh-message", "idempotency_key": "SYNTHETIC-fresh-" + fresh})
		if err != nil || value.(map[string]any)["status"] != mcpOutboxStatusSent {
			t.Fatalf("fresh %s send blocked by retained DB: %v", fresh, err)
		}
	}
	after, storedPin, err := readMCPFacadeOperation(current.Pin, native, id)
	if err != nil || storedPin != original.Pin || after.InputJSON != oldOp.InputJSON || after.InputDigest != oldOp.InputDigest || after.IdempotencyKey != oldOp.IdempotencyKey || after.codexOutboxBinding != oldOp.codexOutboxBinding {
		t.Fatal("new calls rewrote original packet or fence", err)
	}
	cached, err := newMCPSessionStateStore(original.Pin.MCPSessionStateFile).load(original.Pin.APIOrigin, harness.SessionContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, MachineID: native.NodeID, Workspace: native.Workspace})
	if err != nil || cached == nil || cached.ConnectionPin == nil || *cached.ConnectionPin != original.Pin || cached.NativeSessionID != sid || cached.EndpointID != oldOp.EndpointID {
		t.Fatal("fresh calls promoted or replaced original Thread cache", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deliveries) != 3 {
		t.Fatal("same/new Thread sends did not use existing outbox independently")
	}
}

func TestCodexRetainedIntentRequiresFreshOwnedInvocation(t *testing.T) {
	root, workspace := privateLocalNodeRoot(t), privateLocalNodeRoot(t)
	const sid = "synthetic-retained-terminal-thread"
	f := newCodexFacadeProducerNode(t, root, "synthetic-node", sid, workspace)
	current := setCodexProducerEpoch(t, f, 3)
	original := current
	original.Pin.ConnectionEpoch = 1
	native := harness.SessionContext{Harness: "codex", NativeSessionID: sid, MachineID: current.Pin.NodeID, Workspace: workspace}
	scope, _, _ := mcpSessionScope(current.Pin.APIOrigin, native)
	path := filepath.Join(filepath.Dir(current.Pin.MCPSessionStateFile), "scopes", scope, "operator-intent.json")
	c, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	c.retainedArtifacts = ValidateRetainedLocalNodeArtifacts
	binding, _ := codexContextBinding(f.profile)
	q := syntheticCodexOperatorTemplate()
	q.APIOrigin, q.NativeSessionID, q.Workspace = current.Pin.APIOrigin, sid, workspace
	q.codexEndpointGroupsBinding = binding.codexEndpointGroupsBinding
	q.endpointGroupsOperatorContextProof = endpointGroupsOperatorContextProof{ContextTicketID: strings.Repeat("a", 64), ContextConnectionNonce: strings.Repeat("b", 64)}
	q, err = c.prepareForConnection(q, original)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	posts := 0
	c.exchange = func(_ string, delivered localEndpointRequest) (*localEndpointResult, error) {
		posts++
		if delivered.InvocationProof == nil || f.tickets.consumeEndpointGroupsOperator(delivered, delivered.InvocationProof, time.Now()) != nil {
			t.Fatal("original intent did not carry fresh exact invocation proof")
		}
		data, _ := os.ReadFile(path)
		if !bytes.Equal(data, before) {
			t.Fatal("fresh authorizer rewrote original journal before exchange")
		}
		plain := delivered
		plain.InvocationProof = nil
		expected := q
		expected.InvocationProof = nil
		if plain != expected {
			t.Fatal("fresh proof changed original request bytes")
		}
		return nil, errors.New("SYNTHETIC lost terminal reply")
	}
	q.InvocationProof = &q.endpointGroupsOperatorContextProof
	if _, err := c.callForConnection(q, current); err == nil || posts != 0 {
		t.Fatal("supplied old proof/UserPrompt substituted for private authorizer")
	}
	c.retainedInvocation = func(localEndpointRequest, LocalNodeConnection) (*endpointGroupsOperatorContextProof, error) {
		return &q.endpointGroupsOperatorContextProof, nil
	}
	if _, err := c.callForConnection(q, current); err == nil || posts != 0 {
		t.Fatal("stale private proof accepted")
	}
	home := privateLocalNodeRoot(t)
	t.Setenv("CODEX_HOME", home)
	recordDir := filepath.Join(home, "sessions", "2026", "11", "04")
	if err := os.MkdirAll(recordDir, 0700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(recordDir, "rollout-2026-11-04T00-00-00-"+sid+".jsonl")
	writeRecord := func(id string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": id, "cwd": workspace, "source": "vscode", "originator": "codex-tui"}})
		if err := os.WriteFile(record, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRecord(sid)
	c.retainedInvocation = nativeThreadRetainedIntentAuthorizer(sid, record, workspace, q.Operation, native)
	if _, err := c.callForConnection(q, current); err == nil || posts != 1 {
		t.Fatal("fresh terminal invocation did not dispatch exact uncertain original", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || c.sameConnectionPin(&current.Pin, &original.Pin) {
		t.Fatal("unknown outcome changed original pin/request or widened intent authority")
	}
	c.exchange = func(_ string, delivered localEndpointRequest) (*localEndpointResult, error) {
		posts++
		if f.tickets.consumeEndpointGroupsOperator(delivered, delivered.InvocationProof, time.Now()) != nil {
			t.Fatal("fresh repeated proof rejected")
		}
		result := syntheticCodexOperatorResult(delivered, current.Pin.NodeID)
		result.HubID = current.Pin.HubID
		f.mu.Lock()
		description := f.pages[0]
		f.mu.Unlock()
		result.EndpointGroups = &description
		result.Registration.EndpointID = description.Registration.Registration.EndpointID
		return result, nil
	}
	if _, err := c.callForConnection(q, current); err != nil || posts != 2 {
		t.Fatal("original terminal completion refused", err)
	}
	completed, _ := os.ReadFile(path)
	c.retainedInvocation = nil
	if _, err := c.callForConnection(q, current); err == nil || posts != 2 {
		t.Fatal("cached COMPLETED bypassed fresh authorizer")
	}
	c.retainedInvocation = nativeThreadRetainedIntentAuthorizer(sid, record, workspace, q.Operation, native)
	writeRecord("synthetic-other-terminal-thread")
	if _, err := c.callForConnection(q, current); err == nil || posts != 2 {
		t.Fatal("changed real owned record authenticated cached completion")
	}
	writeRecord(sid)
	f.mu.Lock()
	f.profile.RegistrationRevision++
	f.mu.Unlock()
	if _, err := c.callForConnection(q, current); err == nil || posts != 2 {
		t.Fatal("changed remote registration authenticated original completion")
	}
	f.mu.Lock()
	f.profile.RegistrationRevision--
	f.mu.Unlock()
	if _, err := c.callForConnection(q, current); err != nil || posts != 2 {
		t.Fatal("fresh current proof could not read historical completion", err)
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(completed, after) {
		t.Fatal("cached completion checks changed retained journal")
	}
}
