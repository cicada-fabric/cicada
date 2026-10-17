package main

import (
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/harness"
)

func TestNativePairJoinSelectorRejectsIdentityOrGenerationFromModel(t *testing.T) {
	valid := map[string]any{"pair_id": strings.Repeat("a", 32), "slot": "A"}
	s, present, err := parseNativePairJoinSelection(valid)
	if err != nil || !present || s.Slot != "A" {
		t.Fatal("exact Pair/slot selection failed", err)
	}
	for _, key := range []string{"workspace", "native_session_id", "node_id", "owner_id", "group_id", "expected_generation", "bootstrap_proof_digest", "session_token", "endpoint_id"} {
		args := map[string]any{"pair_id": s.PairID, "slot": s.Slot, key: "synthetic-forged"}
		if _, _, err := parseNativePairJoinSelection(args); err == nil {
			t.Fatalf("model supplied %s", key)
		}
	}
	for _, args := range []map[string]any{{"pair_id": s.PairID}, {"slot": "A"}, {"pair_id": s.PairID, "slot": "a"}, {"pair_id": strings.ToUpper(s.PairID), "slot": "A"}, {"pair_id": s.PairID, "slot": float64(1)}} {
		if _, _, err := parseNativePairJoinSelection(args); err == nil {
			t.Fatal("noncanonical reserved-slot selection accepted")
		}
	}
	if _, present, err := parseNativePairJoinSelection(map[string]any{"group_id": "synthetic-legacy"}); present || err != nil {
		t.Fatal("legacy Group Join was silently converted to a Pair")
	}
}

func TestNativePairLocalContextPreservesOriginalSIDAndWorkspace(t *testing.T) {
	s := nativePairJoinSelection{PairID: strings.Repeat("a", 32), Slot: "B"}
	current := harness.SessionContext{Harness: "codex", NativeSessionID: "synthetic-existing-thread", MachineID: "synthetic-existing-node", Workspace: t.TempDir()}
	q, err := nativePairLocalJoinRequest(s, current)
	if err != nil || q.NativeSessionID != current.NativeSessionID || q.Workspace != current.Workspace || q.Slot != "B" {
		t.Fatal("local adapter changed the original native context", err)
	}
	for _, edit := range []func(*harness.SessionContext){func(c *harness.SessionContext) { c.Workspace = strings.Repeat("/synthetic", 120) }, func(c *harness.SessionContext) { c.NativeSessionID = "" }, func(c *harness.SessionContext) { c.NativeSessionID = "synthetic/path" }, func(c *harness.SessionContext) { c.Workspace = "relative" }} {
		bad := current
		edit(&bad)
		if _, err := nativePairLocalJoinRequest(s, bad); err == nil {
			t.Fatal("unverified native context accepted")
		}
	}
}
