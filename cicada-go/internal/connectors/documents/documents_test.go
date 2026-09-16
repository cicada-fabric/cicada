package documents

import (
	"strings"
	"testing"
)

func TestNormalizeDocumentWrapperAndSignature(t *testing.T) {
	raw := []byte(`{"data":{"id":"doc-1","name":"Plan","content":"hello","type":"updated"},"secret":"drop"}`)
	id, eventType, payload, err := Normalize(raw)
	if err != nil || id != "doc-1" || eventType != "document.updated" {
		t.Fatalf("normalize id=%q type=%q payload=%s err=%v", id, eventType, payload, err)
	}
	if strings.Contains(string(payload), "secret") || !strings.Contains(string(payload), "Plan") {
		t.Fatalf("document envelope was not minimized: %s", payload)
	}
	if !strings.HasPrefix(Signature("secret", raw), "sha256=") {
		t.Fatal("signature missing sha256 prefix")
	}
}

func TestNormalizeRejectsUnknownTypeAndMissingID(t *testing.T) {
	if _, _, _, err := Normalize([]byte(`{"title":"missing id"}`)); err == nil {
		t.Fatal("missing document id was accepted")
	}
	if _, _, _, err := Normalize([]byte(`{"id":"doc-1","type":"permission.changed"}`)); err == nil {
		t.Fatal("unknown document event type was accepted")
	}
}
