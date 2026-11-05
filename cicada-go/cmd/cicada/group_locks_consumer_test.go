package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestGroupLockConsumerClosedArgumentsAndTTL(t *testing.T) {
	valid := map[string]any{"slot": json.Number("8"), "expected_version": json.Number("2"), "idempotency_key": "SYNTHETIC-key"}
	for i, change := range []struct {
		name  string
		value any
	}{
		{"slot", 0}, {"slot", 9}, {"slot", 1.1}, {"expected_version", nil}, {"expected_version", "2"},
		{"expected_version", json.Number("9223372036854775808")}, {"ttl_seconds", nil}, {"ttl_seconds", 0},
		{"ttl_seconds", 3601}, {"ttl_seconds", "300"}, {"recover", "true"}, {"note", strings.Repeat("中", 342)},
		{"note", "bad\x00note"}, {"group_id", "forged"}, {"holder", "forged"}, {"original", map[string]any{}},
		{"idempotency_key", ""},
	} {
		t.Run(fmt.Sprintf("%02d_%s", i, change.name), func(t *testing.T) {
			args := map[string]any{}
			for k, v := range valid {
				args[k] = v
			}
			args[change.name] = change.value
			if _, _, _, err := parseGroupLockMCPArguments("cicada_group_lock_acquire", args); err == nil {
				t.Fatal("invalid or caller-supplied authority accepted")
			}
		})
	}
	for _, ttl := range []any{nil, json.Number("1"), json.Number("3600")} {
		args := map[string]any{}
		for k, v := range valid {
			args[k] = v
		}
		if ttl != nil {
			args["ttl_seconds"] = ttl
		}
		v, _, _, err := parseGroupLockMCPArguments("cicada_group_lock_acquire", args)
		if err != nil || (ttl == nil) != (v.TTLSeconds == nil) {
			t.Fatal("omitted or bounded explicit TTL rejected", err)
		}
	}
	for _, tool := range []string{"cicada_thread_scope", "cicada_group_locks"} {
		if _, _, _, err := parseGroupLockMCPArguments(tool, map[string]any{"recover": true}); err == nil {
			t.Fatal("read admitted mutation arguments")
		}
	}
}

func TestGroupLockConsumerCatalogAndOperatorPurposes(t *testing.T) {
	counts := map[string]int{}
	for _, tool := range cicadaMCPTools() {
		name, _ := tool["name"].(string)
		counts[name]++
		if !isGroupLocksMCPTool(name) {
			continue
		}
		schema := tool["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatal("coordination tool accepts undeclared caller context", name)
		}
		properties := schema["properties"].(map[string]any)
		for _, identity := range []string{"thread_id", "node_id", "hub_id", "network_id", "group_id", "holder", "original"} {
			if properties[identity] != nil {
				t.Fatal("model can choose a trusted source identity", name, identity)
			}
		}
		if !isCicadaMCPTool(name) || codexOperatorContextTool(groupLockOperation(name)) != "codex.operator."+groupLockOperation(name) {
			t.Fatal("tool and terminal purposes are not aligned", name)
		}
	}
	for _, name := range []string{"cicada_thread_scope", "cicada_group_locks", "cicada_group_lock_acquire", "cicada_group_lock_renew", "cicada_group_lock_release"} {
		if counts[name] != 1 {
			t.Fatal("approved tool missing or duplicated", name, counts[name])
		}
	}
	t.Logf("catalog contains %d tool entries", len(cicadaMCPTools()))
}

func groupLockOutboxFixture(t *testing.T) (LocalNodeConnection, *mcpOutboxStore, mcpOutboxScope, mcpOutboxInput) {
	t.Helper()
	connection, _, store, scope, _, _ := syntheticFacadeOperation(t, privateLocalNodeRoot(t), "synthetic-lock-node", "")
	r := scope.EndpointGroupAuthority.Relation
	input := mcpOutboxInput{GroupLock: &mcpGroupLockIntent{Scope: wire.GroupLockScope{HubID: r.HubID, NetworkID: r.NetworkID, GroupID: r.GroupID}, Slot: 8, ExpectedVersion: 1, Note: "SYNTHETIC purpose"}}
	return connection, store, scope, input
}

func TestGroupLockConsumerOutboxReopenAndNewPromptRetainsOriginal(t *testing.T) {
	connection, store, scope, input := groupLockOutboxFixture(t)
	op, created, err := store.prepare(scope, wire.OperationGroupLocksAcquire, "SYNTHETIC-first", input)
	if err != nil || !created {
		t.Fatal("initial original not persisted", err)
	}
	var saved mcpOutboxInput
	if json.Unmarshal([]byte(op.InputJSON), &saved) != nil || saved.GroupLock.Original.OperationID != op.OperationID || saved.GroupLock.Original.RequestDigest != strings.Repeat("0", 64) {
		t.Fatal("trusted Node original identity was not preserved before RPC")
	}
	if _, err := store.markError(scope, op.OperationID, mcpOutboxStatusUnknown, errors.New("SYNTHETIC lost reply")); err != nil {
		t.Fatal(err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	reopened := newMCPOutbox(connection.Pin.MCPOutboxStateFile)
	reopened.connectionPin = &connection.Pin
	defer reopened.close()
	op, err = reopened.load(scope, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	changed := *input.GroupLock
	changed.Note, changed.ExpectedVersion = "SYNTHETIC new prompt", 9
	got, created, err := reopened.prepare(scope, wire.OperationGroupLocksAcquire, "SYNTHETIC-new-prompt", mcpOutboxInput{GroupLock: &changed})
	if err != nil || created || got != op {
		t.Fatal("new prompt replaced uncertain same-slot original", err)
	}
	public := mcpOutboxPublicResult(got)
	args := public["recovery_arguments"].(map[string]any)
	parsed, key, recover, err := parseGroupLockMCPArguments(groupLockTool(got.Kind), args)
	parsed.Scope = input.GroupLock.Scope
	if err != nil || !recover || key != op.IdempotencyKey || !groupLockInputsEqual(mcpOutboxInput{GroupLock: &parsed}, input) {
		t.Fatal("new prompt cannot recover exact saved business arguments", err)
	}
	got, created, err = reopened.prepare(scope, wire.OperationGroupLocksAcquire, op.IdempotencyKey, input)
	if err != nil || created || got != op {
		t.Fatal("same-key retry changed saved original", err)
	}
	if _, _, err := reopened.prepare(scope, wire.OperationGroupLocksAcquire, op.IdempotencyKey, mcpOutboxInput{GroupLock: &changed}); !errors.Is(err, errMCPOutboxConflict) {
		t.Fatal("same key changed semantic body", err)
	}
	prior, err := reopened.findGroupLockOperatorOriginal(scope, op.Kind, op.IdempotencyKey, 8, true)
	if err != nil || prior == nil || *prior != op || groupLockOriginalOutboxScope(*prior) != scope {
		t.Fatal("CLI recovery lost full original authority", err)
	}
	wrong := scope
	wrong.NativeSessionID = "SYNTHETIC-other-thread"
	if prior, err := reopened.findGroupLockOperatorOriginal(wrong, op.Kind, op.IdempotencyKey, 8, true); err != nil || prior != nil {
		t.Fatal("another Thread selected original", err)
	}
	if _, err := reopened.markResult(scope, op.OperationID, mcpOutboxStatusSent, "", `{"synthetic":"receipt"}`); err != nil {
		t.Fatal(err)
	}
	next, created, err := reopened.prepare(scope, wire.OperationGroupLocksAcquire, "SYNTHETIC-next", input)
	if err != nil || !created || next.OperationID == op.OperationID {
		t.Fatal("settled slot could not start another explicit intent", err)
	}
}

func TestGroupLockConsumerConcurrentProcessesCreateOneOriginal(t *testing.T) {
	connection, first, scope, input := groupLockOutboxFixture(t)
	second := newMCPOutbox(connection.Pin.MCPOutboxStateFile)
	second.connectionPin = &connection.Pin
	defer second.close()
	second.mu.Lock()
	err := second.openLocked()
	second.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		op      mcpOutboxOperation
		created bool
		err     error
	}
	results := make(chan result, 12)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			store := []*mcpOutboxStore{first, second}[i%2]
			op, created, err := store.prepare(scope, wire.OperationGroupLocksAcquire, fmt.Sprintf("SYNTHETIC-prompt-%d", i), input)
			results <- result{op, created, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var original mcpOutboxOperation
	createdCount := 0
	for r := range results {
		if r.err != nil {
			t.Fatal("concurrent persisted intent did not return original", r.err)
		}
		if original.OperationID == "" {
			original = r.op
		}
		if r.op != original {
			t.Fatal("same slot obtained multiple immutable originals")
		}
		if r.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatal("one original was not inserted exactly once", createdCount)
	}
}

func TestGroupLockConsumerCLIClosedSelectionAndBusinessFlags(t *testing.T) {
	base := []string{"--thread", "SYNTHETIC-thread", "--slot", "8", "--expected-version", "2", "--idempotency-key", "SYNTHETIC-key"}
	for _, action := range []string{"acquire", "renew", "release"} {
		args := append([]string{}, base...)
		if action != "acquire" {
			args = append(args, "--generation", "3")
		}
		args = append(args, "--recover", "--group-id", "SYNTHETIC-group")
		v, err := parseGroupLocksCLIArguments(action, args)
		if err != nil || !v.Recover || v.Intent.Slot != 8 || v.GroupID != "SYNTHETIC-group" || v.Key != "SYNTHETIC-key" {
			t.Fatal("exact terminal business choice rejected", action, err)
		}
	}
	for _, args := range [][]string{
		{"--thread", "SYNTHETIC-thread", "--ttl-seconds", "0"},
		{"--thread", "SYNTHETIC-thread", "--slot", "1"},
		{"--thread", "SYNTHETIC-thread", "--recover"},
		{"--thread", "SYNTHETIC-thread", "--hub", "one", "--hub-id", "two"},
		{"--thread", "SYNTHETIC-thread", "--group-id", ""},
		{"--thread", "SYNTHETIC-thread", "--holder", "forged"},
	} {
		if _, err := parseGroupLocksCLIArguments("read", args); err == nil {
			t.Fatal("read accepted unrelated or forged terminal choice", args)
		}
	}
}
