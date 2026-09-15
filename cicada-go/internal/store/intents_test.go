package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestStorePersistsIntentResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	persistence, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := persistence.CreateIntent("compare the two implementations", "auto", "")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := persistence.ResolveIntent(intent.ID, "goal", "resolved", map[string]any{
		"type": "goal", "goal_id": "goal_test",
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Status != "resolved" || resolved.ResolvedKind != "goal" {
		t.Fatalf("unexpected intent resolution: %#v", resolved)
	}
	var result map[string]any
	if err := json.Unmarshal(resolved.Result, &result); err != nil || result["goal_id"] != "goal_test" {
		t.Fatalf("unexpected intent result: %s err=%v", resolved.Result, err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	intents, err := reopened.ListIntents("resolved")
	if err != nil || len(intents) != 1 || intents[0].ID != intent.ID {
		t.Fatalf("intent was not durable: %#v err=%v", intents, err)
	}
}

func TestStoreValidatesIntentTransitions(t *testing.T) {
	persistence, err := New(filepath.Join(t.TempDir(), "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	if _, err := persistence.CreateIntent(" ", "auto", ""); err == nil {
		t.Fatal("empty intent was accepted")
	}
	intent, err := persistence.CreateIntent("keep this for later", "idea", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ResolveIntent(intent.ID, "idea", "unknown", map[string]any{}, "", ""); err == nil {
		t.Fatal("invalid intent status was accepted")
	}
}
