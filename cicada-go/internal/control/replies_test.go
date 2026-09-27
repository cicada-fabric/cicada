package control

import (
	"context"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestRequestExternalReplyIsApprovalGatedAndBoundToEvent(t *testing.T) {
	controlPlane, goalID, workerID := newActionFixture(t)
	defer controlPlane.Shutdown(context.Background())
	event, err := controlPlane.store.CreateExternalEvent(store.ExternalEvent{
		Connector: "x", ExternalID: "x:reply-1", EventType: "message.created",
		Payload: []byte(`{"text":"please review"}`), Signature: "test", GoalID: goalID,
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := controlPlane.RequestExternalReply(ExternalReplyInput{
		GoalID: goalID, WorkerID: workerID, Connector: "x", EventID: event.ID,
		CallbackURL: "https://connector.example/reply", Text: "Thanks, I will review this.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if action.Kind != "reply" || action.Status != "pending_approval" || action.ApprovalID == "" {
		t.Fatalf("reply was not approval gated: %#v", action)
	}
	if _, err := controlPlane.RequestExternalReply(ExternalReplyInput{
		GoalID: goalID, WorkerID: workerID, Connector: "email", EventID: event.ID,
		CallbackURL: "https://connector.example/reply", Text: "mismatch",
	}); err == nil {
		t.Fatal("reply connector mismatch was accepted")
	}
}
