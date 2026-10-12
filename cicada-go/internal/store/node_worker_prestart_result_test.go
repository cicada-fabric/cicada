package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestNodeControlPrestartResultAtomicallyMatchesSession(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	digest := nodeBindingTestCredentialDigest("synthetic-prestart-result-token")
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate := startStoreNodeControlRequest(t, s, "synthetic-prestart-node", digest,
		NodeControlPairingInitial, "", nodeKey, hubKey, "prestart-result")
	binding := confirmStoreNodeControlRequest(t, s, device, candidate, "prestart-result")
	owner := boundNodeFixture{ownerID: "owner_a", device: device, nodeID: binding.NodeID, digest: digest}
	worker := createOwnerWorker(t, s, owner, "prestart-result")
	claimed, err := s.ClaimBoundNodeWorker(digest, owner.nodeID, worker.ID)
	if err != nil {
		t.Fatal(err)
	}
	thread := "synthetic-claimed-native-session"
	if _, err := s.UpdateWorkerAtAttempt(worker.ID, owner.nodeID, "running", "running", claimed.Attempt,
		WorkerUpdate{ThreadID: &thread}); err != nil {
		t.Fatal(err)
	}
	approval, _, err := s.CreateBoundNodeApproval(digest, owner.nodeID, worker.ID, claimed.Attempt,
		"synthetic-prestart-approval", NodeApprovalCommandExecution, json.RawMessage(`{"command":["echo","synthetic"],"cwd":"/tmp"}`))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("synthetic exact result packet"))
	input := NodeControlRPCInput{CredentialDigest: digest, NodeID: owner.nodeID,
		BindingID: binding.OwnerBindingID, BindingVersion: binding.BindingVersion,
		NodeKeyID: binding.NodeKeyID, NodeKeyEpoch: binding.NodeKeyEpoch,
		Sequence: 1, OperationID: "synthetic-prestart-result", Operation: "node.jobs.result",
		RequestDigest: hex.EncodeToString(hash[:])}
	if _, _, err := s.BeginNodeControlRPC(input); err != nil {
		t.Fatal(err)
	}
	foreign := "synthetic-foreign-session"
	for _, item := range []struct {
		name    string
		rpc     NodeControlRPCInput
		attempt int
		thread  *string
	}{
		{"foreign-session", input, claimed.Attempt, &foreign},
		{"stale-attempt", input, claimed.Attempt + 1, &thread},
		{"foreign-node", func() NodeControlRPCInput { v := input; v.NodeID = "foreign-node"; return v }(), claimed.Attempt, &thread},
		{"wrong-epoch", func() NodeControlRPCInput { v := input; v.NodeKeyEpoch++; return v }(), claimed.Attempt, &thread},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := s.BeginBoundNodeWorkerResultNodeControl(item.rpc, worker.ID, item.attempt, item.thread); err == nil {
				t.Fatal("invalid prestart result admitted")
			}
			current, err := s.GetWorker(worker.ID)
			if err != nil || current.Status != "running" || current.ThreadID != thread {
				t.Fatalf("rejected result mutated Worker: %#v %v", current, err)
			}
			currentApproval, err := s.GetApproval(approval.ID)
			if err != nil || currentApproval.Status != "pending" {
				t.Fatalf("rejected result canceled approval: %#v %v", currentApproval, err)
			}
		})
	}
	admitted, err := s.BeginBoundNodeWorkerResultNodeControl(input, worker.ID, claimed.Attempt, &thread)
	if err != nil || admitted.Status != "verifying" {
		t.Fatalf("matching current session refused: %#v %v", admitted, err)
	}
}
