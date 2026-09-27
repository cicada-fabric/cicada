package control

import (
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestAcceptClientIntentIsDurableAndDispatchesAsynchronously(t *testing.T) {
	c := newTestControl(t, "success")
	input := IntentInput{Text: "想法：比较两种缓存策略", Kind: "idea", RevisitWhen: "after the next release"}
	accepted, err := c.AcceptClientIntent("client-operation-1", input)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "pending" {
		t.Fatalf("acceptance implied completion before dispatch: %#v", accepted)
	}
	job, err := c.store.GetClientIntent(accepted.ID)
	if err != nil || job == nil || job.State != store.ClientIntentQueued {
		t.Fatalf("accepted Client request was not QUEUED: %#v err=%v", job, err)
	}
	ideas, err := c.Ideas("")
	if err != nil || len(ideas) != 0 {
		t.Fatalf("acceptance ran business dispatch before returning: ideas=%#v err=%v", ideas, err)
	}

	retry, err := c.AcceptClientIntent("client-operation-1", input)
	if err != nil || retry.ID != accepted.ID {
		t.Fatalf("exact request retry created another Intent: %#v err=%v", retry, err)
	}
	if _, err := c.AcceptClientIntent("client-operation-1", IntentInput{Text: "different text", Kind: "idea"}); !errors.Is(err, store.ErrClientIntentConflict) {
		t.Fatalf("changed body reused Client request ID: %v", err)
	}
	if err := c.DispatchClientIntentAsync(accepted.ID); err != nil {
		t.Fatal(err)
	}
	waitForClientIntent(t, c, accepted.ID, store.ClientIntentDone)
	routed, err := c.Intent(accepted.ID)
	if err != nil || routed == nil || routed.Status != "resolved" || routed.ResolvedKind != "idea" {
		t.Fatalf("async request did not use the existing Control intent route: %#v err=%v", routed, err)
	}
	ideas, err = c.Ideas("")
	if err != nil || len(ideas) != 1 || ideas[0].RevisitWhen != input.RevisitWhen {
		t.Fatalf("full accepted IntentInput was not used after dispatch: ideas=%#v err=%v", ideas, err)
	}
	if err := c.DispatchClientIntentAsync(accepted.ID); err != nil {
		t.Fatalf("repeated dispatch should be an idempotent no-op: %v", err)
	}
}

func TestClientIntentRecoveryHookOnlyDispatchesQueued(t *testing.T) {
	c := newTestControl(t, "success")
	queued, err := c.AcceptClientIntent("request-to-recover", IntentInput{Text: "idea: restart-safe", Kind: "idea"})
	if err != nil {
		t.Fatal(err)
	}
	count, err := c.RecoverClientIntents()
	if err != nil || count != 1 {
		t.Fatalf("startup recovery dispatch count=%d err=%v", count, err)
	}
	waitForClientIntent(t, c, queued.ID, store.ClientIntentDone)
}

func waitForClientIntent(t *testing.T, c *Control, intentID, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, err := c.store.GetClientIntent(intentID)
		if err != nil {
			t.Fatal(err)
		}
		if job.State == state {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, err := c.store.GetClientIntent(intentID)
	t.Fatalf("Client intent did not reach %s: %#v err=%v", state, job, err)
}
