package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestNodeControlJobListResponseUsesOneBoundedPrefix(t *testing.T) {
	first := control.MachineJob{WorkerID: "worker-first", GoalID: "goal-first",
		MachineID: "node-a", Harness: "codex", Workspace: "/workspace/first",
		Prompt: strings.Repeat("a", nodewire.MaxPlaintextBytes/2+8*1024), Attempt: 1}
	second := control.MachineJob{WorkerID: "worker-second", GoalID: "goal-second",
		MachineID: "node-a", Harness: "codex", Workspace: "/workspace/second",
		Prompt: strings.Repeat("b", nodewire.MaxPlaintextBytes/2+8*1024), Attempt: 1}
	body, err := nodeControlRPCResponseBody(store.NodeControlRPCInput{
		Operation: "node.jobs.list", OperationID: "jobs-page", Sequence: 9},
		nodeControlRPCJobList{Jobs: []control.MachineJob{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > nodewire.MaxPlaintextBytes {
		t.Fatalf("job page plaintext=%d exceeds %d", len(body), nodewire.MaxPlaintextBytes)
	}
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			Jobs []control.MachineJob `json:"jobs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || !decoded.OK || len(decoded.Result.Jobs) != 1 ||
		decoded.Result.Jobs[0].WorkerID != first.WorkerID {
		firstID := ""
		if len(decoded.Result.Jobs) > 0 {
			firstID = decoded.Result.Jobs[0].WorkerID
		}
		t.Fatalf("job page did not preserve the bounded queue prefix: jobs=%d first=%q err=%v",
			len(decoded.Result.Jobs), firstID, err)
	}
	// The omitted job remains queued in Store: response assembly only serializes
	// the supplied prefix and contains no claim/remove operation.
}

func TestNodeControlSingleOversizedJobIsSignedRefusal(t *testing.T) {
	job := control.MachineJob{WorkerID: "worker-large", GoalID: "goal-large",
		MachineID: "node-a", Harness: "codex", Workspace: "/workspace/large",
		Prompt: strings.Repeat("x", nodewire.MaxPlaintextBytes), Attempt: 1}
	body, err := nodeControlRPCResponseBody(store.NodeControlRPCInput{
		Operation: "node.jobs.list", OperationID: "large-job", Sequence: 10},
		nodeControlRPCJobList{Jobs: []control.MachineJob{job}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		OK        bool   `json:"ok"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.OK || decoded.ErrorCode != "RESULT_TOO_LARGE" {
		t.Fatalf("oversized queued job was hidden instead of explicitly refused: %#v err=%v", decoded, err)
	}
}
