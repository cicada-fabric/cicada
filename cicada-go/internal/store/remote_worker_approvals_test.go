package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func TestBoundNodeWorkerApprovalCreateIsOwnerAttemptAndRequestFenced(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-fence")
	otherDevice := addSecondOwnerDevice(t, s)
	otherOwner := newBoundNodeFixture(t, s, "owner_b", otherDevice, "approval-fence-other")
	worker := createOwnerWorker(t, s, owner, "approval-fence")
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
		t.Fatal(err)
	}
	request := json.RawMessage(`{"command":["echo","synthetic approval body"],"cwd":"/tmp"}`)
	approval, created, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-attempt-1", NodeApprovalCommandExecution, request)
	if err != nil || !created || approval == nil || approval.Status != "pending" || approval.Attempt != 1 ||
		approval.NodeID != owner.nodeID || string(approval.Request) != string(request) {
		t.Fatalf("create bound approval: approval=%#v created=%v err=%v", approval, created, err)
	}
	retry, created, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-attempt-1", NodeApprovalCommandExecution, request)
	if err != nil || created || retry == nil || retry.ID != approval.ID {
		t.Fatalf("same request retry did not return durable approval: approval=%#v created=%v err=%v", retry, created, err)
	}
	if _, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-attempt-1", NodeApprovalCommandExecution,
		json.RawMessage(`{"command":["rm","-rf","/"],"cwd":"/tmp"}`)); !errors.Is(err, ErrNodeApprovalConflict) {
		t.Fatalf("same request ID accepted a different body: %v", err)
	}
	if _, _, err := s.CreateBoundNodeApproval(otherOwner.digest, otherOwner.nodeID, worker.ID, 1,
		"other-node-request", NodeApprovalCommandExecution, request); !errors.Is(err, ErrNodeApprovalNotAuthorized) {
		t.Fatalf("different owner's Node created approval for Worker: %v", err)
	}
	if _, _, err := s.CreateBoundNodeApproval(owner.digest, "different-node", worker.ID, 1,
		"wrong-path-request", NodeApprovalCommandExecution, request); !errors.Is(err, ErrNodeApprovalNotAuthorized) {
		t.Fatalf("wrong Node path created approval: %v", err)
	}
	if _, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"unsupported-method", "mcpServer/elicitation/request", request); !errors.Is(err, ErrNodeApprovalNotAuthorized) {
		t.Fatalf("unsupported Codex method was accepted: %v", err)
	}
	if _, err := s.GetBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 2, approval.ID); !errors.Is(err, ErrNodeApprovalStale) {
		t.Fatalf("wrong attempt read approval: %v", err)
	}
}

func TestBoundNodeWorkerApprovalPollsResolvedDecisionWithinLiveAttempt(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-resolved")
	worker := createOwnerWorker(t, s, owner, "approval-resolved")
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
		t.Fatal(err)
	}
	approval, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-resolved", NodeApprovalFileChange, json.RawMessage(`{"grantRoot":"/tmp"}`))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveApproval(approval.ID, "accept")
	if err != nil || resolved == nil || resolved.Status != "resolved" || resolved.Decision != "accept" {
		t.Fatalf("resolve owner decision: approval=%#v err=%v", resolved, err)
	}
	if _, err := s.BeginBoundNodeWorkerResult(owner.digest, owner.nodeID, worker.ID, 1); err != nil {
		t.Fatal(err)
	}
	polled, err := s.GetBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1, approval.ID)
	if err != nil || polled == nil || polled.Status != "resolved" || polled.Decision != "accept" {
		t.Fatalf("resolved decision lost during same-attempt result transition: approval=%#v err=%v", polled, err)
	}
	if _, err := s.UpdateBoundNodeWorkerAtAttempt(owner.digest, owner.nodeID, worker.ID,
		"verifying", "completed", 1, WorkerUpdate{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1, approval.ID); !errors.Is(err, ErrNodeApprovalStale) {
		t.Fatalf("terminal Worker exposed an old decision: %v", err)
	}
}

func TestBoundNodeWorkerApprovalInvalidatesOnResultRequeueAndRevocation(t *testing.T) {
	t.Run("result admission", func(t *testing.T) {
		s, _, _, device := newClientDeviceFixture(t)
		defer s.Close()
		owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-result")
		worker := createOwnerWorker(t, s, owner, "approval-result")
		if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
			t.Fatal(err)
		}
		approval, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
			"codex-request-result", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.BeginBoundNodeWorkerResult(owner.digest, owner.nodeID, worker.ID, 1); err != nil {
			t.Fatal(err)
		}
		stored, err := s.GetApproval(approval.ID)
		if err != nil || stored == nil || stored.Status != "cancelled" {
			t.Fatalf("Worker result did not cancel unanswered approval: %#v err=%v", stored, err)
		}
		if err := s.ValidateRemoteApprovalForDecision(approval.ID, true); !errors.Is(err, ErrNodeApprovalStale) {
			t.Fatalf("failed/finished attempt remained decision-capable: %v", err)
		}
	})
	t.Run("heartbeat requeue and next attempt", func(t *testing.T) {
		s, _, _, device := newClientDeviceFixture(t)
		defer s.Close()
		owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-requeue")
		worker := createOwnerWorker(t, s, owner, "approval-requeue")
		if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
			t.Fatal(err)
		}
		approval, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
			"codex-request-requeue", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RequeueRunningWorkersForMachine(owner.nodeID, "synthetic Node heartbeat expired"); err != nil {
			t.Fatal(err)
		}
		stored, err := s.GetApproval(approval.ID)
		if err != nil || stored == nil || stored.Status != "cancelled" {
			t.Fatalf("requeue did not cancel old approval: %#v err=%v", stored, err)
		}
		if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1, approval.ID); !errors.Is(err, ErrNodeApprovalStale) {
			t.Fatalf("old attempt poll was accepted after claim: %v", err)
		}
		if _, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
			"codex-request-old", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`)); !errors.Is(err, ErrNodeApprovalStale) {
			t.Fatalf("old attempt created an approval after reclaim: %v", err)
		}
	})
	t.Run("binding revoke", func(t *testing.T) {
		s, _, _, device := newClientDeviceFixture(t)
		defer s.Close()
		owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-revoke")
		worker := createOwnerWorker(t, s, owner, "approval-revoke")
		if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
			t.Fatal(err)
		}
		approval, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
			"codex-request-revoke", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RevokeNodeDeviceBinding(owner.ownerID, owner.binding.ID, owner.binding.Version); err != nil {
			t.Fatal(err)
		}
		stored, err := s.GetApproval(approval.ID)
		if err != nil || stored == nil || stored.Status != "cancelled" {
			t.Fatalf("binding revoke did not invalidate approval: %#v err=%v", stored, err)
		}
		if _, err := s.GetBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1, approval.ID); !errors.Is(err, ErrNodeApprovalNotAuthorized) {
			t.Fatalf("revoked Node credential polled an approval: %v", err)
		}
	})
}

func TestRemoteWorkerApprovalMigrationPreservesLegacyApproval(t *testing.T) {
	path := t.TempDir() + "/legacy-approval.sqlite3"
	seedLegacyV1State(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO approvals (id, goal_id, worker_id, method, request_json, status, decision, created_at)
VALUES ('legacy-approval-v30', 'goal_legacy', 'worker_legacy', 'review', '{"safe":true}', 'pending', NULL, '2026-09-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	approval, err := s.GetApproval("legacy-approval-v30")
	if err != nil || approval == nil || approval.Attempt != 0 || approval.NodeID != "" || approval.Status != "pending" {
		t.Fatalf("incremental migration changed legacy approval: %#v err=%v", approval, err)
	}
}

func TestBoundNodeApprovalUsesOwnerApprovalBindingNotWorkerClaims(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-owner-proof")
	worker := createOwnerWorker(t, s, owner, "approval-owner-proof")
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeOwnerApprovalKeyLocal(owner.ownerID, owner.binding.OwnerKeyID, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-owner-key-revoked", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`)); !errors.Is(err, ErrNodeApprovalNotAuthorized) {
		t.Fatalf("Node with revoked owner approval authority created an approval: %v", err)
	}
}

func TestAcceptedRemoteApprovalStopsAutomaticReplayAfterNodeLoss(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-uncertain")
	worker := createOwnerWorker(t, s, owner, "approval-uncertain")
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
		t.Fatal(err)
	}
	approval, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-uncertain", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveApproval(approval.ID, "accept"); err != nil {
		t.Fatal(err)
	}
	stopped, err := s.RequeueRunningWorkersForMachine(owner.nodeID, "synthetic Node heartbeat expired")
	if err != nil || len(stopped) != 1 || stopped[0].Status != RemoteWorkerOutcomeUncertain {
		t.Fatalf("accepted action was eligible for replay: workers=%#v err=%v", stopped, err)
	}
	jobs, err := s.ListWorkersForMachine(owner.nodeID)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("uncertain Worker was claimable: jobs=%#v err=%v", jobs, err)
	}
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err == nil {
		t.Fatal("accepted action was claimed again after Node loss")
	}
	decision, err := s.GetBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1, approval.ID)
	if err != nil || decision == nil || decision.Decision != "accept" {
		t.Fatalf("original Node could not retrieve its accepted decision: approval=%#v err=%v", decision, err)
	}
	admitted, err := s.BeginBoundNodeWorkerResult(owner.digest, owner.nodeID, worker.ID, 1)
	if err != nil || admitted == nil || admitted.Status != "verifying" {
		t.Fatalf("original Node could not reconcile its late result: worker=%#v err=%v", admitted, err)
	}
	completed, err := s.UpdateBoundNodeWorkerAtAttempt(owner.digest, owner.nodeID, worker.ID,
		"verifying", "completed", 1, WorkerUpdate{})
	if err != nil || completed == nil || completed.Status != "completed" {
		t.Fatalf("late result did not finish the same attempt: worker=%#v err=%v", completed, err)
	}
	if _, err := s.BeginBoundNodeWorkerResult(owner.digest, owner.nodeID, worker.ID, 1); !errors.Is(err, ErrNodeWorkerUnavailable) {
		t.Fatalf("duplicate result was accepted after completion: %v", err)
	}
}

func TestAcceptedRemoteApprovalStopsAutomaticReplayAfterHubRestart(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	owner := newBoundNodeFixture(t, s, "owner_a", device, "approval-restart-uncertain")
	worker := createOwnerWorker(t, s, owner, "approval-restart-uncertain")
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
		t.Fatal(err)
	}
	approval, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-restart", NodeApprovalCommandExecution, json.RawMessage(`{"command":["true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveApproval(approval.ID, "accept"); err != nil {
		t.Fatal(err)
	}
	pending, _, err := s.CreateBoundNodeApproval(owner.digest, owner.nodeID, worker.ID, 1,
		"codex-request-still-pending", NodeApprovalFileChange, json.RawMessage(`{"grantRoot":"/tmp"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CancelPendingRemoteWorkerApprovals(worker.ID, owner.nodeID, 1); err != nil {
		t.Fatal(err)
	}
	retired, err := s.GetApproval(pending.ID)
	if err != nil || retired == nil || retired.Status != "cancelled" {
		t.Fatalf("restart left an obsolete approval pending: approval=%#v err=%v", retired, err)
	}
	protected, err := s.ProtectApprovedRemoteWorker(worker.ID, 1, "synthetic Hub restart")
	if err != nil || !protected {
		t.Fatalf("accepted action was not protected: protected=%v err=%v", protected, err)
	}
	stored, err := s.GetWorker(worker.ID)
	if err != nil || stored == nil || stored.Status != RemoteWorkerOutcomeUncertain {
		t.Fatalf("unexpected Worker state after restart guard: worker=%#v err=%v", stored, err)
	}
}
