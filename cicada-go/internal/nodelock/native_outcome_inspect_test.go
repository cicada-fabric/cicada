package nodelock

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectNativeMessageOutcomeReadOnlyExactScope(t *testing.T) {
	root := t.TempDir()
	op := NativeOperation{HubID: "synthetic-hub", NodeID: "synthetic-node", EndpointID: "synthetic-endpoint", BindingID: "synthetic-binding", MessageID: "synthetic-message", Digest: "synthetic-digest", AttemptID: "synthetic-attempt", BindingEpoch: 1}
	if _, err := InspectNativeMessageOutcome(root, "synthetic-account", "codex", "synthetic-session", op); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".native-writers")); !os.IsNotExist(err) {
		t.Fatal("inspection initialized writer state")
	}
	w, err := AcquireNativeWriter(context.Background(), root, "synthetic-account", "codex", "synthetic-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.BeginNativeOperation(op); err != nil {
		t.Fatal(err)
	}
	if err = w.FinishNativeOperation(op, NativeQueueAccepted); err != nil {
		t.Fatal(err)
	}
	w.Close()
	lookup := op
	lookup.BindingID = ""
	lookup.AttemptID = ""
	state, err := InspectNativeMessageOutcome(root, "synthetic-account", "codex", "synthetic-session", lookup)
	if err != nil || state != NativeQueueAccepted {
		t.Fatal("original acceptance not inspectable", err)
	}
	lookup.Digest = "different"
	if _, err = InspectNativeMessageOutcome(root, "synthetic-account", "codex", "synthetic-session", lookup); err == nil {
		t.Fatal("changed immutable message borrowed acceptance")
	}
	lookup = op
	lookup.HubID = "other-hub"
	if state, err = InspectNativeMessageOutcome(root, "synthetic-account", "codex", "synthetic-session", lookup); err != nil || state != "" {
		t.Fatal("another Hub borrowed writer outcome", err)
	}
}
