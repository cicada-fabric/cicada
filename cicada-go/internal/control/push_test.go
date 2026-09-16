package control

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestPushSubscriptionRequiresConfiguredVAPID(t *testing.T) {
	root := t.TempDir()
	c, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown(context.Background())
	if _, err := c.RegisterPushSubscription(PushSubscriptionInput{Endpoint: "https://push.example.test/sub"}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected configuration error, got %v", err)
	}
}

func TestPushSubscriptionRegistrationIsDurableAndRefreshable(t *testing.T) {
	root := t.TempDir()
	c, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		PushVAPIDPublicKey: "public", PushVAPIDPrivateKey: "private", PushVAPIDSubject: "mailto:test@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown(context.Background())
	input := PushSubscriptionInput{Endpoint: "https://push.example.test/sub", UserAgent: "browser"}
	input.Keys.P256DH = "p256dh"
	input.Keys.Auth = "auth"
	first, err := c.RegisterPushSubscription(input)
	if err != nil {
		t.Fatal(err)
	}
	input.UserAgent = "updated-browser"
	second, err := c.RegisterPushSubscription(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || second.Endpoint != input.Endpoint {
		t.Fatalf("subscription was not refreshed in place: first=%#v second=%#v", first, second)
	}
	if err := c.DeletePushSubscription(first.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPushConfigurationDoesNotExposePrivateKey(t *testing.T) {
	c := &Control{config: Config{PushVAPIDPublicKey: "public", PushVAPIDPrivateKey: "private", PushVAPIDSubject: "mailto:test@example.com"}}
	config := c.PushConfiguration()
	if !config.Enabled || config.PublicKey != "public" || config.Subject == "" {
		t.Fatalf("unexpected push configuration: %#v", config)
	}
}
