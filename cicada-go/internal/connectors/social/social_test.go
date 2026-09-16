package social

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeSocialEnvelope(t *testing.T) {
	id, kind, payload, err := Normalize("x", []byte(`{"data":{"id":123,"text":"hello","author_id":"u1","type":"tweet.created"}}`))
	if err != nil || id != "123" || kind != "message.created" {
		t.Fatalf("normalize id=%q kind=%q err=%v", id, kind, err)
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	if value["text"] != "hello" || value["sender"] != "u1" || value["provider"] != "x" {
		t.Fatalf("unexpected normalized payload: %#v", value)
	}
	if strings.Contains(string(payload), "token") {
		t.Fatalf("provider secret leaked into payload: %s", payload)
	}
}

func TestNormalizeSocialRejectsUnknownProviderAndType(t *testing.T) {
	if _, _, _, err := Normalize("slack", []byte(`{"id":"1"}`)); err == nil {
		t.Fatal("unknown provider accepted")
	}
	if _, _, _, err := Normalize("qq", []byte(`{"id":"1","type":"reaction.added"}`)); err == nil {
		t.Fatal("unknown event type accepted")
	}
}
