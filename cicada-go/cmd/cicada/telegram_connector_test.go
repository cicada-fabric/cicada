package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/server"
)

func TestTelegramConnectorPollsNormalizesAndIngests(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		ConnectorSecrets: map[string]string{"telegram": "telegram-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	if _, err := controlPlane.RegisterMachine("telegram-machine", "Telegram machine", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(control.GoalInput{
		Objective: "receive Telegram messages", MachineID: "telegram-machine", Harness: "shell",
		Resources: map[string]any{"argv": []any{"/bin/true"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	telegramAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		if r.URL.Path != "/bot123:abc/getUpdates" || (offset != "0" && offset != "8") {
			t.Fatalf("unexpected Telegram API request: %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":7,"message":{"message_id":3,"chat":{"id":8,"type":"private"},"text":"hello"}}]}`))
	}))
	defer telegramAPI.Close()
	controlAPI := httptest.NewServer(server.NewHandler(controlPlane))
	defer controlAPI.Close()
	t.Setenv("CICADA_TELEGRAM_BOT_TOKEN", "123:abc")
	t.Setenv("CICADA_CONNECTOR_SECRET_TELEGRAM", "telegram-secret")
	t.Setenv("CICADA_TELEGRAM_POLL_SECONDS", "0")
	offsetFile := filepath.Join(root, "telegram-offset")
	if err := runTelegramConnector([]string{
		"--once", "--api-url", telegramAPI.URL, "--control-url", controlAPI.URL,
		"--offset-file", offsetFile, "--goal-id", goal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	// A restart resumes from the durable offset. Even if Telegram repeats the
	// last update, the connector must not post it to Control a second time.
	if err := runTelegramConnector([]string{
		"--once", "--api-url", telegramAPI.URL, "--control-url", controlAPI.URL,
		"--offset-file", offsetFile, "--goal-id", goal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := controlPlane.ExternalEvents("telegram")
	if err != nil || len(events) != 1 {
		t.Fatalf("Telegram event not ingested: %#v err=%v", events, err)
	}
	if events[0].ExternalID != "update:7" || events[0].GoalID != goal.ID || events[0].EventType != "message.created" {
		t.Fatalf("unexpected event: %#v", events[0])
	}
	var payload map[string]any
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil || payload["text"] != "hello" {
		t.Fatalf("unexpected normalized payload: %s err=%v", events[0].Payload, err)
	}
	if data, err := os.ReadFile(offsetFile); err != nil || string(data) != "8\n" {
		t.Fatalf("offset was not persisted: %q err=%v", data, err)
	}
}
