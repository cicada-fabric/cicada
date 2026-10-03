package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

type clientApprovalDecisionFixture struct {
	store      *Store
	ownerKey   *OwnerApprovalKey
	device     *ClientDevice
	approvalID string
	requestID  string
}

func newClientApprovalDecisionFixture(t *testing.T, goalOwner, operation string) *clientApprovalDecisionFixture {
	t.Helper()
	s, owner, _, device := newClientDeviceFixture(t)
	if _, err := s.CreatePrincipal(Principal{ID: "owner_b", Kind: PrincipalKindHuman,
		OwnerID: "owner_b", Name: "owner_b", Status: PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.GetOwnerApprovalKey("owner_a", owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := s.UpsertMachine("synthetic-approval-machine", "synthetic approval fixture", nil, "available")
	if err != nil {
		t.Fatal(err)
	}
	goal, err := s.CreateGoal("synthetic-approval-goal", "synthetic approval", "done", "", 50,
		machine.ID, "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	worker, err := s.CreateWorkerAtHarness("synthetic-approval-worker", goal.ID, machine.ID,
		"codex", filepath.Join(t.TempDir(), "result"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE goals SET owner_id=? WHERE id=?`, goalOwner, goal.ID); err != nil {
		t.Fatal(err)
	}
	approval, err := s.CreateApproval("synthetic-approval", goal.ID, worker.ID,
		"item/commandExecution/requestApproval", map[string]any{"command": []string{"synthetic"}})
	if err != nil {
		t.Fatal(err)
	}
	var sequence uint64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(sequence),0)+1 FROM client_device_requests_v2
WHERE owner_id=? AND device_id=? AND session_epoch=?`, device.OwnerID, device.DeviceID, device.SessionEpoch).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	requestID := "synthetic-approval-client-request"
	digest := sha256.Sum256([]byte(requestID))
	accepted, err := s.AcceptClientRequest(AcceptClientRequestInput{
		OwnerID: device.OwnerID, DeviceID: device.DeviceID, SessionEpoch: device.SessionEpoch,
		Sequence: sequence, OperationID: requestID, RouteOperation: operation,
		CiphertextDigest: hex.EncodeToString(digest[:]),
	})
	if err != nil || accepted == nil || accepted.Outcome != ClientRequestOutcomeNew || accepted.Request == nil {
		t.Fatalf("accept synthetic Client request: accepted=%#v err=%v", accepted, err)
	}
	return &clientApprovalDecisionFixture{store: s, ownerKey: ownerKey, device: device,
		approvalID: approval.ID, requestID: accepted.Request.ID}
}

func TestResolveApprovalForClientRequestCommitsForCurrentOwnerRequest(t *testing.T) {
	f := newClientApprovalDecisionFixture(t, "owner_a", "approvals.decide")
	resolved, err := f.store.ResolveApprovalForClientRequest(f.requestID, "owner_a", f.approvalID, "accept")
	if err != nil || resolved == nil || resolved.Status != "resolved" || resolved.Decision != "accept" {
		t.Fatalf("authorized decision = %#v, %v", resolved, err)
	}
}

func TestResolveApprovalForClientRequestRejectsStaleOrMismatchedAuthority(t *testing.T) {
	tests := []struct {
		name      string
		goalOwner string
		operation string
		ownerArg  string
		mutate    func(*testing.T, *clientApprovalDecisionFixture)
		want      error
	}{
		{name: "revoked_device", goalOwner: "owner_a", operation: "approvals.decide", ownerArg: "owner_a", want: ErrClientApprovalDecisionUnauthorized,
			mutate: func(t *testing.T, f *clientApprovalDecisionFixture) {
				if _, err := f.store.RevokeClientDevice("owner_a", f.device.DeviceID, f.device.Version); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "revoked_owner_key", goalOwner: "owner_a", operation: "approvals.decide", ownerArg: "owner_a", want: ErrClientApprovalDecisionUnauthorized,
			mutate: func(t *testing.T, f *clientApprovalDecisionFixture) {
				if _, err := f.store.RevokeOwnerApprovalKeyLocal("owner_a", f.ownerKey.KeyID, f.ownerKey.Version); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "stale_device_epoch", goalOwner: "owner_a", operation: "approvals.decide", ownerArg: "owner_a", want: ErrClientApprovalDecisionUnauthorized,
			mutate: func(t *testing.T, f *clientApprovalDecisionFixture) {
				if _, err := f.store.db.Exec(`UPDATE client_devices_v2 SET session_epoch=session_epoch+1 WHERE owner_id='owner_a' AND device_id=?`, f.device.DeviceID); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "wrong_authenticated_owner", goalOwner: "owner_a", operation: "approvals.decide", ownerArg: "owner_b", want: ErrClientApprovalDecisionUnauthorized},
		{name: "wrong_goal_owner", goalOwner: "owner_b", operation: "approvals.decide", ownerArg: "owner_a", want: ErrClientApprovalUnavailable},
		{name: "wrong_rpc_operation", goalOwner: "owner_a", operation: "topology.apply", ownerArg: "owner_a", want: ErrClientApprovalDecisionUnauthorized},
		{name: "request_not_processing", goalOwner: "owner_a", operation: "approvals.decide", ownerArg: "owner_a", want: ErrClientApprovalDecisionUnauthorized,
			mutate: func(t *testing.T, f *clientApprovalDecisionFixture) {
				if _, err := f.store.db.Exec(`UPDATE client_device_requests_v2 SET status='FAILED' WHERE id=?`, f.requestID); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newClientApprovalDecisionFixture(t, tc.goalOwner, tc.operation)
			if tc.mutate != nil {
				tc.mutate(t, f)
			}
			_, err := f.store.ResolveApprovalForClientRequest(f.requestID, tc.ownerArg, f.approvalID, "decline")
			if !errors.Is(err, tc.want) {
				t.Fatalf("mismatched approval authority returned %v, want %v", err, tc.want)
			}
			approval, err := f.store.GetApproval(f.approvalID)
			if err != nil || approval == nil || approval.Status != "pending" || approval.Decision != "" {
				t.Fatalf("denied decision changed approval: approval=%#v err=%v", approval, err)
			}
		})
	}
}

func TestResolveApprovalForClientRequestAcceptsOnlyNormalizedDecisions(t *testing.T) {
	f := newClientApprovalDecisionFixture(t, "owner_a", "approvals.decide")
	if _, err := f.store.ResolveApprovalForClientRequest(f.requestID, "owner_a", f.approvalID, "approved"); err == nil {
		t.Fatal("Store accepted a non-normalized decision")
	}
	approval, err := f.store.GetApproval(f.approvalID)
	if err != nil || approval == nil || approval.Status != "pending" {
		t.Fatalf("invalid decision changed approval: approval=%#v err=%v", approval, err)
	}
}
