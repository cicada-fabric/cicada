package store

import (
	"database/sql"
	"errors"
	"math"
	"sync"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

const (
	NodeTLSAuthorityCurrentNone        = "NONE"
	NodeTLSAuthorityCurrentVerified    = "CURRENT"
	NodeTLSAuthorityCurrentUnavailable = "UNAVAILABLE"
	MaxNodeTLSAuthorityPending         = 256
)

type NodeTLSAuthorityStatusInput struct {
	NodeID, CredentialDigest string
}

// Pending contains bounded progress metadata, never another approval or a
// certificate validation result. Burned and revoked history remains in D1.
type NodeTLSAuthorityPending struct {
	RequestID, State     string
	RowVersion, TLSEpoch uint64
}

type NodeTLSAuthorityRecoveryStatus struct {
	CurrentBinding                                            *NodeControlKeyBinding
	OwnerKeyVersion, ClientDeviceVersion, BurnedTLSEpochFloor uint64
	CurrentActiveState                                        string
	CurrentActive                                             *NodeTLSAuthoritySnapshot
	Pending                                                   []NodeTLSAuthorityPending
}

// ReadNodeTLSAuthorityRecoveryLocal reads one current transaction. Its trusted
// local caller must authenticate a remote request independently before using
// this source. NONE and UNAVAILABLE never authorize transport. In particular,
// an expired row remains inspectable for a new exact Owner-approved request.
// It does not admit RPC sequences, alter floors, clear quarantine or sign keys.
func (s *Store) ReadNodeTLSAuthorityRecoveryLocal(input NodeTLSAuthorityStatusInput) (*NodeTLSAuthorityRecoveryStatus, error) {
	if s == nil || s.db == nil || !validNodeBindingID(input.NodeID) || !validNodeCredentialDigest(input.CredentialDigest) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, owner, deviceVersion, err := nodeTLSCurrentAuthorityTx(tx, input.CredentialDigest, input.NodeID)
	if err != nil {
		return nil, err
	}
	status := &NodeTLSAuthorityRecoveryStatus{CurrentBinding: b, OwnerKeyVersion: uint64(owner.Version), ClientDeviceVersion: deviceVersion, CurrentActiveState: NodeTLSAuthorityCurrentNone, Pending: make([]NodeTLSAuthorityPending, 0)}
	err = tx.QueryRow(`SELECT floor FROM node_tls_epoch_floors_v1 WHERE hub_id=? AND node_id=?`, b.HubID, b.NodeID).Scan(&status.BurnedTLSEpochFloor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if status.BurnedTLSEpochFloor > math.MaxInt64 {
		return nil, ErrNodeTLSAuthorityDenied
	}
	rows, err := tx.Query(`SELECT request_id FROM node_tls_authority_v1 WHERE hub_id=? AND node_id=? AND state IN ('RESERVED','ISSUING','SIGNED','INSTALLED') ORDER BY tls_epoch LIMIT ?`, b.HubID, b.NodeID, MaxNodeTLSAuthorityPending+1)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > MaxNodeTLSAuthorityPending {
		return nil, ErrNodeTLSAuthorityCapacity
	}
	for _, id := range ids {
		r, err := readNodeTLSAuthorityTx(tx, id)
		if err != nil {
			return nil, err
		}
		status.Pending = append(status.Pending, NodeTLSAuthorityPending{r.Claims.RequestID, r.State, r.RowVersion, r.Claims.TLSEpoch})
	}
	status.CurrentActive, err = currentNodeTLSAuthorityTx(tx, b.NodeID, b.CredentialDigest)
	if err != nil {
		if !nodeTLSUnavailableSnapshotError(err) {
			return nil, err
		}
		status.CurrentActive = nil
		status.CurrentActiveState = NodeTLSAuthorityCurrentUnavailable
	} else if status.CurrentActive != nil {
		status.CurrentActiveState = NodeTLSAuthorityCurrentVerified
	}
	return status, nil
}

// NodeTLSAuthorityMaintenance is an opaque held-lock capability. Its roots
// must come from independently installed local coordinates, never a bundle.
// These Node locks do not stop a Hub issuer: the operator must also stop all
// signing before recovery. Frozen D1 direct callers have no issuance lock hook.
type NodeTLSAuthorityMaintenance struct {
	state *nodeTLSAuthorityMaintenanceState
}

// Every value copy shares the same lock ownership and lifecycle. Exporting a
// struct containing its own mutex/closed flag would let a copy survive Close.
type nodeTLSAuthorityMaintenanceState struct {
	mu           sync.Mutex
	nodeID       string
	writer, node *nodelock.Lock
	closed       bool
}

func AcquireNodeTLSAuthorityMaintenanceLocal(stateRoot, writerRoot, nodeID string) (*NodeTLSAuthorityMaintenance, error) {
	if !validNodeBindingID(nodeID) || stateRoot == "" || writerRoot == "" {
		return nil, ErrNodeTLSAuthorityDenied
	}
	writer, err := nodelock.AcquireWriterRootExclusive(writerRoot)
	if err != nil {
		return nil, err
	}
	node, err := nodelock.AcquireMaintenanceExclusive(stateRoot, nodeID)
	if err != nil {
		writer.Close()
		return nil, err
	}
	return &NodeTLSAuthorityMaintenance{state: &nodeTLSAuthorityMaintenanceState{nodeID: nodeID, writer: writer, node: node}}, nil
}

func (m *NodeTLSAuthorityMaintenance) Close() error {
	if m == nil || m.state == nil {
		return nil
	}
	state := m.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	state.closed = true
	return errors.Join(state.node.Close(), state.writer.Close())
}

// BurnNodeTLSIssuanceUncertainLocal is limited to one known ISSUING row and
// expected version under actual exclusive maintenance ownership. It does not
// issue, resume, approve or release quarantine. A repeat of the same original
// CAS may return that already-burned row; it never advances a terminal row.
func (s *Store) BurnNodeTLSIssuanceUncertainLocal(input NodeTLSAuthorityActionInput, maintenance *NodeTLSAuthorityMaintenance) (*NodeTLSAuthoritySnapshot, error) {
	if s == nil || s.db == nil || maintenance == nil || maintenance.state == nil || input.ExpectedVersion == 0 || input.ExpectedVersion >= math.MaxInt64 {
		return nil, ErrNodeTLSAuthorityDenied
	}
	state := maintenance.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.node == nil || state.writer == nil || state.nodeID != input.NodeID {
		return nil, ErrNodeTLSAuthorityDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, owner, dv, err := nodeTLSCurrentAuthorityTx(tx, input.CredentialDigest, input.NodeID)
	if err != nil {
		return nil, err
	}
	r, err := readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if !nodeTLSMatchesAuthority(r.Claims, b, owner, dv) {
		return nil, ErrNodeTLSAuthorityDenied
	}
	if r.State == NodeTLSUncertain && r.RowVersion == input.ExpectedVersion+1 {
		return r, nil
	}
	if r.State != NodeTLSIssuing || r.RowVersion != input.ExpectedVersion {
		return nil, ErrNodeTLSAuthorityConflict
	}
	if err = nodeTLSCASStateTx(tx, input.RequestID, NodeTLSIssuing, NodeTLSUncertain, input.ExpectedVersion); err != nil {
		return nil, err
	}
	r, err = readNodeTLSAuthorityTx(tx, input.RequestID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
