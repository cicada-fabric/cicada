package control

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestNotifyKeepsDurableHistoryAndLeavesLegacyPushRowsInert(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	databasePath := filepath.Join(stateDir, "cicada.sqlite3")
	legacyStore, err := store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	legacySubscription, err := legacyStore.UpsertPushSubscription(store.PushSubscription{
		ID: "push_retirement_synthetic", Endpoint: "https://127.0.0.1:1/synthetic",
		P256DH: "synthetic-public-key", Auth: "synthetic-auth-key", UserAgent: "historical fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyStore.Close(); err != nil {
		t.Fatal(err)
	}

	controlPlane, err := New(Config{
		StateDir: stateDir, WorkspaceRoot: filepath.Join(root, "workspace"),
		// Old VAPID settings remain accepted during config migration, but do not
		// re-enable external notification delivery.
		PushVAPIDPublicKey: "synthetic-public", PushVAPIDPrivateKey: "synthetic-private",
		PushVAPIDSubject: "mailto:synthetic@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	controlPlane.notify("", "approval.requested", "P1",
		"synthetic approval", "synthetic notification body")
	if err := controlPlane.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	notifications, err := reopened.ListNotifications(false)
	if err != nil || len(notifications) != 1 {
		t.Fatalf("durable notification history = %#v, err=%v", notifications, err)
	}
	got := notifications[0]
	if got.GoalID != "" || got.Kind != "approval.requested" ||
		got.Priority != "P1" || got.Title != "synthetic approval" || got.Body != "synthetic notification body" {
		t.Fatalf("durable notification changed: %#v", got)
	}
	subscriptions, err := reopened.ListPushSubscriptions()
	if err != nil || len(subscriptions) != 1 {
		t.Fatalf("legacy subscription data changed: %#v, err=%v", subscriptions, err)
	}
	if subscriptions[0].ID != legacySubscription.ID || subscriptions[0].Endpoint != legacySubscription.Endpoint ||
		subscriptions[0].LastError != "" {
		t.Fatalf("legacy subscription was modified by notification creation: %#v", subscriptions[0])
	}
}
