package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func nodeTLSRecoveryPrivateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestNodeTLSAuthorityRecoveryCurrentReadAndCapacity(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	node, hub := nodeTLSTestIdentity(t), nodeTLSTestIdentity(t)
	digest := nodeBindingTestCredentialDigest("synthetic-d2-recovery-read")
	candidate := startStoreNodeControlRequest(t, s, "synthetic-d2-node", digest, NodeControlPairingInitial, "", node, hub, "d2-recovery-read")
	binding := confirmStoreNodeControlRequest(t, s, device, candidate, "d2-recovery-read")
	input := NodeTLSAuthorityStatusInput{binding.NodeID, digest}
	status, err := s.ReadNodeTLSAuthorityRecoveryLocal(input)
	if err != nil || status.CurrentActiveState != NodeTLSAuthorityCurrentNone || status.CurrentActive != nil || status.BurnedTLSEpochFloor != 0 || status.OwnerKeyVersion != 1 || status.ClientDeviceVersion != uint64(device.Version) || status.CurrentBinding.NodeKeyID != node.Public().ID || len(status.Pending) != 0 {
		t.Fatal("read-only exact current binding was not returned")
	}
	for _, bad := range []NodeTLSAuthorityStatusInput{{"foreign-node", digest}, {binding.NodeID, nodeBindingTestCredentialDigest("foreign-credential")}, {binding.NodeID, ""}} {
		if _, err := s.ReadNodeTLSAuthorityRecoveryLocal(bad); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
			t.Fatal("foreign current status authorized")
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM node_tls_authority_v1`).Scan(&count); err != nil || count != 0 {
		t.Fatal("status read created an authority reservation")
	}
	// Capacity is checked before interpreting these deliberately synthetic,
	// unapproved metadata rows; they are not valid grant or certificate fixtures.
	for i := 0; i <= MaxNodeTLSAuthorityPending; i++ {
		id := fmt.Sprintf("synthetic_capacity_%d", i)
		if _, err := s.db.Exec(`INSERT INTO node_tls_authority_v1(request_id,hub_id,node_id,issuer_spki_hash,serial,tls_epoch,candidate_digest,claims_json,csr_pem,issuer_chain_pem,trust_anchor_pem,state,version,reservation_version,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'RESERVED',1,1,?)`, id, binding.HubID, binding.NodeID, nodeTLSTestHash("capacity-issuer"), fmt.Sprintf("%032x", i+1), i+1, nodeTLSTestHash(id), `{}`, []byte("synthetic-unapproved-csr"), []byte("synthetic-unapproved-chain"), []byte("synthetic-unapproved-root"), "synthetic"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ReadNodeTLSAuthorityRecoveryLocal(input); !errors.Is(err, ErrNodeTLSAuthorityCapacity) {
		t.Fatal("pending status silently truncated")
	}
}

func TestNodeTLSAuthorityRecoveryRequiresActualMaintenance(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	nodeID := "synthetic-maintenance-node"
	state, writer := nodeTLSRecoveryPrivateRoot(t), nodeTLSRecoveryPrivateRoot(t)
	action := NodeTLSAuthorityActionInput{RequestID: "synthetic-missing", NodeID: nodeID, CredentialDigest: nodeBindingTestCredentialDigest("maintenance"), ExpectedVersion: 2}
	for _, fake := range []*NodeTLSAuthorityMaintenance{nil, {}} {
		if _, err := s.BurnNodeTLSIssuanceUncertainLocal(action, fake); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
			t.Fatal("unheld maintenance capability burned a reservation")
		}
	}
	agent, err := nodelock.AcquireAgent(state, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := AcquireNodeTLSAuthorityMaintenanceLocal(state, writer, nodeID); !errors.Is(err, nodelock.ErrBusy) || m != nil {
		t.Fatal("live Agent did not prevent exclusive recovery")
	}
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := AcquireNodeTLSAuthorityMaintenanceLocal(state, writer, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	copy := *m
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := copy.Close(); err != nil {
		t.Fatal("copied capability duplicate Close was not idempotent")
	}
	if _, err := s.BurnNodeTLSIssuanceUncertainLocal(action, &copy); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("copied capability survived shared ownership Close")
	}
	if _, err := s.BurnNodeTLSIssuanceUncertainLocal(action, m); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("closed maintenance capability accepted")
	}
}

func TestNodeTLSAuthorityRecoveryNativeBurnReopenAndNewGrant(t *testing.T) {
	if !nodeTLSNativeRequired(t) {
		return
	}
	f := newNodeTLSNativeFixture(t)
	r, err := f.s.ReserveNodeTLSCandidate(f.input)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, r.Claims)
	if err != nil {
		t.Fatal(err)
	}
	action := NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: 1}
	issuing, err := f.s.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	action.ExpectedVersion = issuing.RowVersion
	state, writer := nodeTLSRecoveryPrivateRoot(t), nodeTLSRecoveryPrivateRoot(t)
	m, err := AcquireNodeTLSAuthorityMaintenanceLocal(state, writer, action.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	copy := *m
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.BurnNodeTLSIssuanceUncertainLocal(action, &copy); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("copied closed capability burned live ISSUING row")
	}
	unchanged, err := f.s.GetNodeTLSAuthorityReservationLocal(action.RequestID)
	if err != nil || unchanged.State != NodeTLSIssuing || unchanged.RowVersion != issuing.RowVersion || !bytes.Equal(unchanged.Grant, issuing.Grant) {
		t.Fatal("copied closed capability changed authority state")
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = AcquireNodeTLSAuthorityMaintenanceLocal(state, writer, action.NodeID)
	if err != nil {
		t.Fatal("shared close did not release real maintenance locks")
	}
	defer m.Close()
	stale := action
	stale.ExpectedVersion--
	if _, err := f.s.BurnNodeTLSIssuanceUncertainLocal(stale, m); !errors.Is(err, ErrNodeTLSAuthorityConflict) {
		t.Fatal("stale recovery CAS accepted")
	}
	burned, err := f.s.BurnNodeTLSIssuanceUncertainLocal(action, m)
	if err != nil || burned.State != NodeTLSUncertain || burned.RowVersion != issuing.RowVersion+1 || !bytes.Equal(burned.Grant, grant) {
		t.Fatal("known issuance did not burn without replacing proof")
	}
	if retry, err := f.s.BurnNodeTLSIssuanceUncertainLocal(action, m); err != nil || retry.RowVersion != burned.RowVersion {
		t.Fatal("same recovery retry mutated terminal state")
	}
	var sequence int
	var name, path string
	if err := f.s.db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.s.Close()
	status, err := f.s.ReadNodeTLSAuthorityRecoveryLocal(NodeTLSAuthorityStatusInput{action.NodeID, f.digest})
	if err != nil || status.BurnedTLSEpochFloor != 1 || status.CurrentActive != nil || len(status.Pending) != 0 {
		t.Fatal("restart lost permanent burn or treated it as pending/current")
	}
	next := f.input
	next.RequestID, next.ExpectedTLSEpochFloor, next.GrantNonce = "synthetic_d2_after_burn", 1, nodeTLSTestHash("d2-after-burn")
	r2, err := f.s.ReserveNodeTLSCandidate(next)
	if err != nil || r2.Claims.Serial == r.Claims.Serial || r2.Claims.TLSEpoch != 2 {
		t.Fatal("recovery reused burned serial or epoch")
	}
	if _, err := f.s.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: NodeTLSAuthorityActionInput{RequestID: r2.Claims.RequestID, NodeID: action.NodeID, CredentialDigest: f.digest, ExpectedVersion: 1}, Grant: grant}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("old Owner grant became renewal delegation")
	}
	active := nodeTLSActivateFixture(t, f, r2)
	status, err = f.s.ReadNodeTLSAuthorityRecoveryLocal(NodeTLSAuthorityStatusInput{action.NodeID, f.digest})
	if err != nil || status.CurrentActiveState != NodeTLSAuthorityCurrentVerified || status.CurrentActive == nil || !bytes.Equal(status.CurrentActive.Activation, active.Activation) || status.BurnedTLSEpochFloor != 2 {
		t.Fatal("fresh exact activation did not become independently current")
	}
	t.Run("missing_permanent_nonce_evidence_is_unavailable", func(t *testing.T) {
		// Inject a missing permanent-evidence table only in this disposable DB.
		// The real C-issued, Owner-approved ACTIVE was verified immediately above;
		// its signed receipt cannot replace missing independent nonce evidence.
		if _, err := f.s.db.Exec(`DROP TABLE node_tls_proof_nonces_v1`); err != nil {
			t.Fatal(err)
		}
		unavailable, err := f.s.ReadNodeTLSAuthorityRecoveryLocal(NodeTLSAuthorityStatusInput{action.NodeID, f.digest})
		if err != nil || unavailable.CurrentActiveState != NodeTLSAuthorityCurrentUnavailable || unavailable.CurrentActive != nil || unavailable.BurnedTLSEpochFloor != 2 {
			t.Fatal("missing permanent evidence returned a current snapshot or hid retained floor")
		}
		current, err := f.s.CurrentNodeTransportBinding(action.NodeID)
		if err != nil || current.TLSAuthority != nil {
			t.Fatal("receipt alone authorized after permanent evidence loss")
		}
	})
}
