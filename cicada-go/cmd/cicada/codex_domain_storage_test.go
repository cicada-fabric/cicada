package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func syntheticCodexDomainBinding() codexDomainBinding {
	return codexDomainBinding{LocalDomainVersion: 1, LocalDomain: wire.LocalDomainSelection{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, PolicyDigest: strings.Repeat("b", 64)}}
}

func TestCodexDomainOutboxRetainsOriginalAcrossNewAdmissionAndPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.sqlite3")
	queue := newMCPOutbox(path)
	original := mcpOutboxScope{APIOrigin: "https://synthetic.invalid", Scope: "synthetic-scope", Harness: "codex", NativeSessionID: "synthetic-thread", NodeID: "synthetic-node", Workspace: "/synthetic/work", EndpointID: "synthetic-endpoint", GroupID: "synthetic-group", codexOutboxBinding: codexOutboxBinding{codexDomainBinding: syntheticCodexDomainBinding(), NativeBindingID: "synthetic-native-binding", NativeBindingEpoch: 1}}
	op, created, err := queue.prepare(original, "ask", "synthetic-idempotency-key", mcpOutboxInput{Question: "Synthetic retained original question"})
	if err != nil || !created {
		t.Fatal("initial domain outbox preparation", err)
	}
	op, err = queue.markAttempt(original, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.close(); err != nil {
		t.Fatal(err)
	}
	queue = newMCPOutbox(path)
	defer queue.close()
	for _, change := range []string{"legacy", "version", "policy", "epoch", "digest", "native-binding", "native-epoch"} {
		t.Run(change, func(t *testing.T) {
			current := original
			switch change {
			case "legacy":
				current.codexOutboxBinding = codexOutboxBinding{}
			case "version":
				current.LocalDomainVersion = 2
			case "policy":
				current.LocalDomain.PolicyID = strings.Repeat("c", 32)
			case "epoch":
				current.LocalDomain.PolicyEpoch++
			case "digest":
				current.LocalDomain.PolicyDigest = strings.Repeat("d", 64)
			case "native-binding":
				current.NativeBindingID = "synthetic-new-binding"
			case "native-epoch":
				current.NativeBindingEpoch++
			}
			if _, err := queue.load(current, op.OperationID); err == nil {
				t.Fatal("changed domain restored old queue operation")
			}
			if _, err := queue.markAttempt(current, op.OperationID); err == nil {
				t.Fatal("changed domain marked old queue operation")
			}
			if _, err := queue.markResult(current, op.OperationID, mcpOutboxStatusSent, "", "{}"); err == nil {
				t.Fatal("changed domain completed old queue operation")
			}
			if _, _, err := queue.prepare(current, "ask", op.IdempotencyKey, mcpOutboxInput{Question: "Synthetic retained original question"}); err == nil {
				t.Fatal("changed domain adopted original idempotency key")
			}
			retained, err := queue.load(original, op.OperationID)
			if err != nil || retained.Status != mcpOutboxStatusUnknown || retained.AttemptCount != op.AttemptCount || retained.InputJSON != op.InputJSON || retained.InputDigest != op.InputDigest {
				t.Fatal("rejected context mutated original operation", err)
			}
		})
	}
}

func TestCodexDomainCacheCannotStampLegacyOrDifferentPolicy(t *testing.T) {
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	state := newMCPSessionStateStore(base)
	ctx := mcpTestContext("codex", "synthetic-thread", "synthetic-node", "/synthetic/work")
	legacy := mcpTestCachedSession(t, "https://synthetic.invalid", ctx, "cicada_session_synthetic", "synthetic-group", "synthetic-endpoint")
	if err := state.save(legacy); err != nil {
		t.Fatal(err)
	}
	domain := legacy
	domain.codexDomainBinding = syntheticCodexDomainBinding()
	if err := state.save(domain); err == nil {
		t.Fatal("legacy cache was stamped as domain")
	}
	got, err := state.load(legacy.APIOrigin, ctx)
	if err != nil || got == nil || got.codexDomainBinding != (codexDomainBinding{}) {
		t.Fatal("legacy cache changed", err)
	}
	if err := state.remove(legacy.Scope); err != nil {
		t.Fatal(err)
	}
	if err := state.save(domain); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(state.scopePath(domain.Scope))
	if err != nil {
		t.Fatal(err)
	}
	var disk mcpSessionStateDisk
	if json.Unmarshal(raw, &disk) != nil || disk.Version != mcpDomainSessionStateVersion || disk.Version == mcpSessionStateVersion {
		t.Fatal("old binary could treat domain cache as legacy")
	}
	disk.Version = mcpSessionStateVersion
	wrongVersion, _ := json.Marshal(disk)
	if err := os.WriteFile(state.scopePath(domain.Scope), wrongVersion, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.load(domain.APIOrigin, ctx); err == nil {
		t.Fatal("domain fields in a legacy cache were silently accepted")
	}
	if err := os.WriteFile(state.scopePath(domain.Scope), raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = newMCPSessionStateStore(base).load(domain.APIOrigin, ctx)
	if err != nil || got == nil || got.Scope != legacy.Scope || got.codexDomainBinding != domain.codexDomainBinding {
		t.Fatal("domain cache did not retain original identity and selector", err)
	}
	changed := domain
	changed.LocalDomain.PolicyEpoch++
	changed.SessionToken = "cicada_session_synthetic_new"
	if err := state.save(changed); err == nil {
		t.Fatal("different policy replaced original cache")
	}
	got, err = state.load(domain.APIOrigin, ctx)
	if err != nil || got.SessionToken != domain.SessionToken || got.codexDomainBinding != domain.codexDomainBinding {
		t.Fatal("policy refusal rewrote original cache", err)
	}
}

func TestCodexVerifiedOperatorRetryKeepsOriginalSelectorAndRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-intent.json")
	client, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	q := syntheticCodexOperatorTemplate()
	binding := syntheticCodexDomainBinding()
	q.LocalDomainVersion, q.LocalDomain = binding.LocalDomainVersion, binding.LocalDomain
	original, err := client.prepare(q, "synthetic-node")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	client, err = openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	current := q
	current.LocalDomain.PolicyEpoch++
	current.LocalDomain.PolicyDigest = strings.Repeat("c", 64)
	recovered, err := client.originalVerifiedCommand(current, "synthetic-node", nil)
	if err != nil || recovered != original {
		t.Fatal("fresh policy replaced original unresolved request", err)
	}
	changed := current
	changed.Name = "Another command"
	if _, err := client.originalVerifiedCommand(changed, "synthetic-node", nil); !errors.Is(err, errCodexOperatorIntentConflict) {
		t.Fatal("different command adopted original selector", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retry preflight rewrote unresolved original")
	}
}

func TestCodexDomainLateHeartbeatCannotClearAnotherPolicy(t *testing.T) {
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	_, cache, card := codexConsumerCache(t, "https://synthetic.invalid", base, "synthetic-thread")
	m := newMCPServer(cache.APIOrigin, "", base)
	codexConsumerInstall(m, cache, card)
	m.sessionDomain = syntheticCodexDomainBinding()
	frozen := m.codexHeartbeatSnapshot()
	if frozen == nil {
		t.Fatal("missing frozen fixture")
	}
	m.sessionDomain.LocalDomain.PolicyEpoch++
	if frozen.same(m.codexHeartbeatSnapshot()) {
		t.Fatal("heartbeat ignored a changed policy epoch")
	}
	frozen.clearMemoryIfMatching(m)
	if m.currentSessionToken() != cache.SessionToken {
		t.Fatal("late old-policy heartbeat cleared a different policy")
	}
	m.sessionDomain = syntheticCodexDomainBinding()
	frozen.clearMemoryIfMatching(m)
	if m.currentSessionToken() != "" {
		t.Fatal("matching heartbeat did not fence revoked memory")
	}
	ctx := mcpTestContext(cache.Harness, cache.NativeSessionID, cache.NodeID, cache.Workspace)
	if saved, err := newMCPSessionStateStore(base).load(cache.APIOrigin, ctx); err != nil || saved == nil {
		t.Fatal("heartbeat discarded original durable cache", err)
	}
}
