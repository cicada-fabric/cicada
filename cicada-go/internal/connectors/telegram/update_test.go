package telegram

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeMessageUsesUpdateIDAndStableFields(t *testing.T) {
	raw := []byte(`{"update_id":42,"message":{"message_id":7,"from":{"id":9,"username":"alice"},"chat":{"id":-3,"type":"group","title":"Team"},"date":1700000000,"text":"  hello  ","reply_to_message":{"message_id":6}}}`)
	externalID, eventType, payload, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if externalID != "update:42" || eventType != "message.created" {
		t.Fatalf("unexpected identity: %q %q", externalID, eventType)
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	if value["text"] != "hello" || value["chat_title"] != "Team" || value["from_username"] != "alice" {
		t.Fatalf("unexpected normalized payload: %#v", value)
	}
}

func TestNormalizeRejectsUnsupportedOrOversizedUpdate(t *testing.T) {
	if _, _, _, err := Normalize([]byte(`{"update_id":1,"my_chat_member":{}}`)); err == nil {
		t.Fatal("unsupported update was accepted")
	}
	if _, _, _, err := Normalize([]byte(strings.Repeat("x", MaxUpdateBytes+1))); err == nil {
		t.Fatal("oversized update was accepted")
	}
}

func TestSignatureMatchesControlFormat(t *testing.T) {
	if !strings.HasPrefix(Signature("secret", []byte("body")), "sha256=") {
		t.Fatal("signature has no sha256 prefix")
	}
}
