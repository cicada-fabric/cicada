package email

import (
	"strings"
	"testing"
)

func TestNormalizeDropsProviderEnvelope(t *testing.T) {
	id, kind, payload, err := Normalize([]byte(`{"message_id":"m-1","from":{"name":"Alice","email":"alice@example.com"},"to":["bob@example.com"],"subject":"hello","body":"read me","provider_token":"secret"}`))
	if err != nil || id != "m-1" || kind != "message.created" {
		t.Fatalf("normalize id=%q kind=%q err=%v", id, kind, err)
	}
	text := string(payload)
	if !strings.Contains(text, "alice@example.com") || strings.Contains(text, "provider_token") || strings.Contains(text, "secret") {
		t.Fatalf("provider envelope leaked into normalized payload: %s", text)
	}
}

func TestNormalizeRejectsUnknownType(t *testing.T) {
	if _, _, _, err := Normalize([]byte(`{"id":"m-1","type":"credential.request"}`)); err == nil {
		t.Fatal("unknown email event type was accepted")
	}
}
