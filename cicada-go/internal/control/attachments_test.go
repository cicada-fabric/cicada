package control

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestCreateAttachmentStoresBytesAndRejectsUnsafeLinks(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	attachment, err := controlPlane.CreateAttachment(AttachmentInput{
		Name: "evidence.txt", MimeType: "text/plain", ContentBase64: base64.StdEncoding.EncodeToString([]byte("evidence")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if attachment.Size != 8 || attachment.Path == "" {
		t.Fatalf("attachment bytes were not recorded: %#v", attachment)
	}
	data, err := os.ReadFile(attachment.Path)
	if err != nil || string(data) != "evidence" {
		t.Fatalf("attachment bytes were not stored: %q err=%v", data, err)
	}
	if _, err := controlPlane.CreateAttachment(AttachmentInput{Name: "secret", SourceURL: "https://user:pass@example.com/private"}); err == nil {
		t.Fatal("URL with embedded credentials was accepted")
	}
}

func TestIntentAttachmentFailureIsDurable(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	intent, err := controlPlane.RouteIntent(IntentInput{Text: "inspect this", Kind: "question", Attachments: []string{"missing-attachment"}})
	if err == nil || intent == nil || intent.Status != "failed" || !strings.Contains(intent.Error, "attachment not found") {
		t.Fatalf("missing attachment was not recorded as a failure: intent=%#v err=%v", intent, err)
	}
}

func TestQuestionGoalCarriesAttachmentResources(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	attachment, err := controlPlane.CreateAttachment(AttachmentInput{
		Name: "results.json", MimeType: "application/json", ContentBase64: base64.StdEncoding.EncodeToString([]byte(`{"score":42}`)),
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := controlPlane.RouteIntent(IntentInput{
		Text: "Summarize the result", Kind: "question", Attachments: []string{attachment.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := decodeIntentResult(t, intent.Result)
	goal := waitTestGoal(t, controlPlane, result["goal_id"].(string))
	entries, ok := goal.Resources["attachments"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("attachment resources missing from Goal: %#v", goal.Resources)
	}
}
