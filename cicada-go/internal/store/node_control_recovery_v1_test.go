package store

import (
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func recoveryStoreFixture(t *testing.T) (*Store, *NodeControlKeyBinding, string) {
	t.Helper()
	s, _, _, device := newClientDeviceFixture(t)
	node, _ := e2ee.NewIdentity()
	hub, _ := e2ee.NewIdentity()
	digest := nodeBindingTestCredentialDigest("recovery-synthetic-token")
	candidate := startStoreNodeControlRequest(t, s, "node-recovery-query", digest, NodeControlPairingInitial, "", node, hub, "recovery-query")
	return s, confirmStoreNodeControlRequest(t, s, device, candidate, "recovery-query"), digest
}
func recoveryStoreRequest(digest string) nodewire.RecoveryRequest {
	return nodewire.RecoveryRequest{Nonce: make([]byte, 32), Origin: "https://synthetic.invalid", CredentialDigest: digest, RestoreDigest: nodewire.RecoveryDigest([]byte("restore")), PlanDigest: nodewire.RecoveryDigest([]byte("plan")), Operations: []nodewire.RecoveryOperationQuery{}}
}
func recoveryStoreInput(b *NodeControlKeyBinding, digest string, sequence uint64, id string) NodeControlRPCInput {
	return NodeControlRPCInput{CredentialDigest: digest, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKeyID, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: sequence, OperationID: id, Operation: "node.binding.status", RequestDigest: nodewire.RecoveryDigest([]byte(id))}
}
func TestNodeControlRecoverySnapshotDoesNotAdmitOrReturnBodies(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	input := recoveryStoreInput(b, digest, 40, "accepted")
	if _, _, err := s.BeginNodeControlRPC(input); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteNodeControlRPC(NodeControlRPCCompletion{NodeControlRPCInput: input, ResponsePacket: []byte("synthetic private result")}); err != nil {
		t.Fatal(err)
	}
	q := recoveryStoreRequest(digest)
	q.Operations = []nodewire.RecoveryOperationQuery{{OperationID: input.OperationID, Sequence: input.Sequence, RequestDigest: input.RequestDigest}, {OperationID: "absent", Sequence: 1, RequestDigest: nodewire.RecoveryDigest([]byte("absent"))}}
	for i := 0; i < 2; i++ {
		_, _, status, err := s.NodeControlRecoveryStatus(digest, b.NodeID, func(*NodeControlKeyBinding) (nodewire.RecoveryRequest, error) { return q, nil })
		if err != nil || status.AcceptedHighwater != 40 || status.Operations[0].State != NodeControlRPCComplete || status.Operations[1].State != "NOT_RECORDED" {
			t.Fatalf("snapshot: %+v %v", status, err)
		}
	}
	stale := recoveryStoreInput(b, digest, 1, "normal-stale")
	if _, _, err := s.BeginNodeControlRPC(stale); err == nil {
		t.Fatal("query reset normal sequence admission")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM node_control_rpc_inbox_v1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("query wrote inbox: %d %v", count, err)
	}
	q.Operations[0].RequestDigest = nodewire.RecoveryDigest([]byte("changed"))
	if _, _, _, err := s.NodeControlRecoveryStatus(digest, b.NodeID, func(*NodeControlKeyBinding) (nodewire.RecoveryRequest, error) { return q, nil }); !errors.Is(err, ErrNodeControlRPCConflict) {
		t.Fatalf("digest mismatch: %v", err)
	}
}
func TestNodeControlRecoveryCurrentAuthorityAndCorruptHighwater(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	q := recoveryStoreRequest(digest)
	auth := func(*NodeControlKeyBinding) (nodewire.RecoveryRequest, error) { return q, nil }
	if _, _, _, err := s.NodeControlRecoveryStatus(digest, "other-node", auth); !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatalf("wrong Node: %v", err)
	}
	if _, _, _, err := s.NodeControlRecoveryStatus(digest, b.NodeID, func(*NodeControlKeyBinding) (nodewire.RecoveryRequest, error) { return q, errors.New("forged proof") }); err == nil {
		t.Fatal("forged proof accepted")
	}
	input := recoveryStoreInput(b, digest, 4, "recorded")
	if _, _, err := s.BeginNodeControlRPC(input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_control_rpc_sequences_v1 SET last_sequence=3`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.NodeControlRecoveryStatus(digest, b.NodeID, auth); !errors.Is(err, ErrNodeControlRPCConflict) {
		t.Fatalf("corrupt highwater accepted: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE node_control_rpc_sequences_v1 SET last_sequence=4`); err != nil {
		t.Fatal(err)
	}
	// Separate handle bypasses s.mu. A read snapshot may precede revocation;
	// after the revocation commits, every new snapshot must reject it.
	var path string
	var seq int
	var name string
	rows, err := s.db.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		if err = rows.Scan(&seq, &name, &path); err != nil {
			t.Fatal(err)
		}
		if name == "main" {
			break
		}
	}
	rows.Close()
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := other.RevokeNodeDeviceBinding("owner_a", b.OwnerBindingID, int64(b.BindingVersion))
		done <- err
	}()
	_, _, _, _ = s.NodeControlRecoveryStatus(digest, b.NodeID, auth)
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.NodeControlRecoveryStatus(digest, b.NodeID, auth); !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatalf("committed independent revocation ignored: %v", err)
	}
	if _, err := s.NodeControlKeyForCredential(digest, b.NodeID); !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatalf("normal shared guard diverged: %v", err)
	}
}
func TestNodeControlRecoverySharedLookupPreservesMalformedKeyError(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	// Deliberately corrupt only this disposable fixture after removing its immutability trigger.
	if _, err := s.db.Exec(`DROP TRIGGER node_control_key_binding_immutable_v1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_control_key_bindings_v1 SET node_public_identity_json='{}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeControlKeyForCredential(digest, b.NodeID); !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatalf("malformed identity error changed: %v", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := nodeControlCurrentBindingTx(tx, digest, "absent"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing lookup must retain no-row classification: %v", err)
	}
}

func TestNodeControlRecoveryOwnerDeviceCredentialRevocation(t *testing.T) {
	for _, kind := range []string{"owner-key", "device", "credential", "node-key"} {
		t.Run(kind, func(t *testing.T) {
			s, b, digest := recoveryStoreFixture(t)
			q := recoveryStoreRequest(digest)
			switch kind {
			case "owner-key":
				if _, err := s.RevokeOwnerApprovalKeyLocal("owner_a", b.OwnerKeyID, 1); err != nil {
					t.Fatal(err)
				}
			case "device":
				device, err := s.GetClientDevice("owner_a", b.ClientDeviceID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.RevokeClientDevice("owner_a", b.ClientDeviceID, device.Version); err != nil {
					t.Fatal(err)
				}
			case "credential":
				if _, err := s.db.Exec(`UPDATE fabric_node_credentials SET status='revoked' WHERE node_id=?`, b.NodeID); err != nil {
					t.Fatal(err)
				}
			case "node-key":
				if _, err := s.db.Exec(`UPDATE node_control_key_bindings_v1 SET state='REVOKED' WHERE owner_binding_id=?`, b.OwnerBindingID); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, err := s.NodeControlRecoveryStatus(digest, b.NodeID, func(*NodeControlKeyBinding) (nodewire.RecoveryRequest, error) { return q, nil }); err == nil {
				t.Fatal("revoked current authority accepted")
			}
			if _, err := s.NodeControlKeyForCredential(digest, b.NodeID); err == nil {
				t.Fatal("normal lookup predicate diverged")
			}
		})
	}
}
