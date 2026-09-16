package control

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestConnectorSecretOverridesGlobalWebhookSecret(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		WebhookSecret: "global", ConnectorSecrets: map[string]string{"telegram": "telegram-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	payload := []byte(`{"provider":"telegram","text":"hello"}`)
	sign := func(secret string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(payload)
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	if _, err := controlPlane.IngestExternalEvent("telegram", "update:1", "message.created", sign("global"), payload, ""); err == nil {
		t.Fatal("global secret unexpectedly authenticated Telegram event")
	}
	event, err := controlPlane.IngestExternalEvent("telegram", "update:1", "message.created", sign("telegram-secret"), payload, "")
	if err != nil || event.Status != "received" {
		t.Fatalf("connector secret did not authenticate: %#v err=%v", event, err)
	}
}

func TestTriageExternalEventLinksGoalAndAudits(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), WebhookSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	if _, err := controlPlane.RegisterMachine("triage-machine", "Triage machine", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(GoalInput{Objective: "triage", MachineID: "triage-machine", Harness: "shell", Resources: map[string]any{"argv": []any{"/bin/true"}}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := controlPlane.IngestExternalEvent("mail", "mail:1", "message.created", signPayload("secret", []byte(`{"text":"hi"}`)), []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	linked, err := controlPlane.TriageExternalEvent(event.ID, "linked", goal.ID)
	if err != nil || linked.Status != "linked" || linked.GoalID != goal.ID {
		t.Fatalf("event was not linked: %#v err=%v", linked, err)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, item := range events {
		seen = seen || item.Type == "ExternalEventTriaged"
	}
	if !seen {
		t.Fatal("triage audit event missing")
	}
}

func signPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
