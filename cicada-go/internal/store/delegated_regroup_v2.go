package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	RegroupSetParent      = "SET_PARENT"
	RegroupCreateChild    = "CREATE_CHILD"
	regroupMaxName        = 80
	regroupMaxTTL         = 24 * time.Hour
	regroupProposalQuota  = 64
	regroupDedupRetention = 30 * 24 * time.Hour
	regroupRetainedQuota  = 4096
)

var (
	ErrRegroupDenied   = errors.New("delegated regroup access denied")
	ErrRegroupInvalid  = errors.New("invalid regroup request")
	ErrRegroupConflict = errors.New("regroup version or state conflict")
	ErrRegroupNotFound = errors.New("regroup proposal or delegation not found")
)

type RegroupProposalInput struct {
	OperationID           string `json:"operation_id"`
	NetworkID             string `json:"network_id"`
	SourceGroupID         string `json:"source_group_id"`
	TargetGroupID         string `json:"target_group_id"`
	Action                string `json:"action"`
	NewGroupName          string `json:"new_group_name,omitempty"`
	ExpectedSourceVersion int64  `json:"expected_source_version"`
	ExpectedTargetVersion int64  `json:"expected_target_version"`
}

type RegroupProposal struct {
	ProposalID   string               `json:"proposal_id"`
	HubID        string               `json:"hub_id"`
	OwnerID      string               `json:"owner_id"`
	EndpointID   string               `json:"endpoint_id"`
	PrincipalID  string               `json:"principal_id"`
	BindingID    string               `json:"binding_id"`
	BindingEpoch uint64               `json:"binding_epoch"`
	Input        RegroupProposalInput `json:"input"`
	State        string               `json:"state"`
	CreatedAt    string               `json:"created_at"`
	ExpiresAt    string               `json:"expires_at"`
	Delegation   *RegroupDelegation   `json:"delegation,omitempty"`
}

type RegroupDelegation struct {
	DelegationID          string `json:"delegation_id"`
	ProposalID            string `json:"proposal_id"`
	HubID                 string `json:"hub_id"`
	OwnerID               string `json:"owner_id"`
	NetworkID             string `json:"network_id"`
	SourceGroupID         string `json:"source_group_id"`
	TargetGroupID         string `json:"target_group_id"`
	Action                string `json:"action"`
	ExpectedSourceVersion int64  `json:"expected_source_version"`
	ExpectedTargetVersion int64  `json:"expected_target_version"`
	ExpiresAt             string `json:"expires_at"`
	MaxUses               int    `json:"max_uses"`
	UseCount              int    `json:"use_count"`
	State                 string `json:"state"`
	Version               int64  `json:"version"`
	CreatedAt             string `json:"created_at"`
}

type RegroupApplyResult struct {
	AuditID      string `json:"audit_id"`
	ProposalID   string `json:"proposal_id"`
	DelegationID string `json:"delegation_id"`
	Action       string `json:"action"`
	Group        Group  `json:"group"`
	AppliedAt    string `json:"applied_at"`
}

func (s *Store) initializeDelegatedRegroupSchema() error {
	if err := s.ensureColumn("client_device_requests_v2", "route_operation",
		`ALTER TABLE client_device_requests_v2 ADD COLUMN route_operation TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS regroup_proposals_v2 (
proposal_id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, operation_id TEXT NOT NULL,
proposal_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('PROPOSED','APPLIED')),
created_at TEXT NOT NULL, UNIQUE(endpoint_id,operation_id));
CREATE TABLE IF NOT EXISTS regroup_delegations_v2 (
delegation_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE,
delegation_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED','EXHAUSTED')),
version INTEGER NOT NULL CHECK(version>0), use_count INTEGER NOT NULL CHECK(use_count>=0),
request_id TEXT NOT NULL UNIQUE, revoke_request_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
FOREIGN KEY(proposal_id) REFERENCES regroup_proposals_v2(proposal_id));
CREATE TABLE IF NOT EXISTS regroup_audit_v2 (
audit_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE, delegation_id TEXT NOT NULL,
actor_endpoint_id TEXT NOT NULL, action TEXT NOT NULL, source_group_id TEXT NOT NULL,
target_group_id TEXT NOT NULL, before_source_version INTEGER NOT NULL,
before_target_version INTEGER NOT NULL, result_group_id TEXT NOT NULL,
result_json TEXT NOT NULL, applied_at TEXT NOT NULL);`)
	return err
}

func cleanupRegroupTx(tx *sql.Tx, at time.Time) error {
	cutoff := at.Add(-regroupDedupRetention).Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM regroup_delegations_v2 WHERE created_at<?
AND proposal_id NOT IN (SELECT proposal_id FROM regroup_audit_v2)`, cutoff); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM regroup_proposals_v2 WHERE created_at<?
AND proposal_id NOT IN (SELECT proposal_id FROM regroup_delegations_v2)
AND proposal_id NOT IN (SELECT proposal_id FROM regroup_audit_v2)`, cutoff)
	return err
}

type regroupGroupScope struct {
	id, networkID, ownerID, trustDomainID, hubID, state, parentID, externalMode string
	version                                                                     int64
}

func regroupGroupScopeTx(tx *sql.Tx, groupID string) (regroupGroupScope, error) {
	var group regroupGroupScope
	err := tx.QueryRow(`SELECT g.id,g.network_id,g.owner_principal_id,g.trust_domain_id,
n.hub_id,g.state,g.parent_group_id,g.external_mode,g.version FROM groups g
JOIN networks_v2 n ON n.id=g.network_id AND n.state='ACTIVE' WHERE g.id=?`, groupID).
		Scan(&group.id, &group.networkID, &group.ownerID, &group.trustDomainID,
			&group.hubID, &group.state, &group.parentID, &group.externalMode, &group.version)
	if err != nil {
		return group, ErrRegroupDenied
	}
	if group.state != GroupStateActive || group.ownerID == "" || group.trustDomainID == "" {
		return group, ErrRegroupDenied
	}
	return group, nil
}

// Target visibility is independent of source membership. A hidden and a
// nonexistent target receive the same error before any version is inspected.
func regroupTargetGuardTx(tx *sql.Tx, actor GroupSpaceActor, targetID string, at time.Time) error {
	var membershipID string
	var revision int64
	if tx.QueryRow(`SELECT m.id,m.revision FROM memberships m
JOIN endpoint_group_memberships eg ON eg.group_id=m.group_id AND eg.endpoint_id=? AND eg.status='active'
WHERE m.group_id=? AND m.principal_id=? AND m.status='active'`,
		actor.Scope.EndpointID, targetID, actor.Scope.PrincipalID).Scan(&membershipID, &revision) != nil {
		return ErrRegroupDenied
	}
	scope := actor.Scope
	scope.GroupID, scope.MembershipID, scope.MembershipRevision = targetID, membershipID, revision
	if guardNativeActorTx(tx, scope, "", at) != nil {
		return ErrRegroupDenied
	}
	return nil
}

func validateRegroupInput(in RegroupProposalInput) bool {
	in.NewGroupName = strings.TrimSpace(in.NewGroupName)
	if !validSameGroupSealedV1Token(in.OperationID) ||
		!validSameGroupSealedV1Token(in.NetworkID) ||
		!validSameGroupSealedV1Token(in.SourceGroupID) ||
		!validSameGroupSealedV1Token(in.TargetGroupID) ||
		in.ExpectedSourceVersion <= 0 || in.ExpectedTargetVersion <= 0 {
		return false
	}
	if in.Action == RegroupSetParent {
		return in.SourceGroupID != in.TargetGroupID && in.NewGroupName == ""
	}
	return in.Action == RegroupCreateChild && in.NewGroupName != "" &&
		len(in.NewGroupName) <= regroupMaxName
}

func regroupMonitorGuardTx(tx *sql.Tx, actor GroupSpaceActor, at time.Time) error {
	if guardGroupSpaceActorTx(tx, actor, "", at) != nil {
		return ErrRegroupDenied
	}
	var role string
	var rolesJSON string
	if tx.QueryRow(`SELECT role,roles_json FROM memberships WHERE id=? AND principal_id=? AND group_id=?`,
		actor.Scope.MembershipID, actor.Scope.PrincipalID, actor.Scope.GroupID).
		Scan(&role, &rolesJSON) != nil {
		return ErrRegroupDenied
	}
	if role == "monitor" {
		return nil
	}
	var roles []string
	if json.Unmarshal([]byte(rolesJSON), &roles) == nil {
		for _, value := range roles {
			if value == "monitor" {
				return nil
			}
		}
	}
	return ErrRegroupDenied
}

func (s *Store) ProposeRegroup(actor GroupSpaceActor, in RegroupProposalInput) (*RegroupProposal, error) {
	in.NewGroupName = strings.TrimSpace(in.NewGroupName)
	if !validateRegroupInput(in) || actor.Scope.GroupID != in.SourceGroupID ||
		actor.Scope.NetworkID != in.NetworkID {
		return nil, ErrRegroupInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err := cleanupRegroupTx(tx, at); err != nil {
		return nil, err
	}
	if err := regroupMonitorGuardTx(tx, actor, at); err != nil {
		return nil, err
	}
	if err := regroupTargetGuardTx(tx, actor, in.TargetGroupID, at); err != nil {
		return nil, err
	}
	var priorJSON string
	if err := tx.QueryRow(`SELECT proposal_json FROM regroup_proposals_v2 WHERE endpoint_id=? AND operation_id=?`,
		actor.Scope.EndpointID, in.OperationID).Scan(&priorJSON); err == nil {
		var prior RegroupProposal
		if json.Unmarshal([]byte(priorJSON), &prior) != nil || prior.Input != in ||
			prior.BindingID != actor.Scope.BindingID || prior.BindingEpoch != actor.Scope.BindingEpoch {
			return nil, ErrRegroupConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &prior, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	source, err := regroupGroupScopeTx(tx, in.SourceGroupID)
	if err != nil {
		return nil, err
	}
	target, err := regroupGroupScopeTx(tx, in.TargetGroupID)
	if err != nil || source.networkID != in.NetworkID || target.networkID != in.NetworkID ||
		source.ownerID != target.ownerID || source.trustDomainID != target.trustDomainID ||
		source.hubID != target.hubID {
		return nil, ErrRegroupDenied
	}
	if source.version != in.ExpectedSourceVersion || target.version != in.ExpectedTargetVersion {
		return nil, ErrRegroupConflict
	}
	if in.Action == RegroupSetParent && source.parentID == target.id {
		return nil, ErrRegroupConflict
	}
	proposal := RegroupProposal{ProposalID: NewID("rgrp"), HubID: source.hubID,
		OwnerID: source.ownerID, EndpointID: actor.Scope.EndpointID,
		PrincipalID: actor.Scope.PrincipalID, BindingID: actor.Scope.BindingID,
		BindingEpoch: actor.Scope.BindingEpoch, Input: in, State: "PROPOSED",
		CreatedAt: at.Format(time.RFC3339Nano), ExpiresAt: at.Add(regroupMaxTTL).Format(time.RFC3339Nano)}
	var activeCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM regroup_proposals_v2 WHERE state='PROPOSED'
AND json_extract(proposal_json,'$.owner_id')=? AND json_extract(proposal_json,'$.expires_at')>?`,
		proposal.OwnerID, at.Format(time.RFC3339Nano)).Scan(&activeCount); err != nil {
		return nil, err
	}
	if activeCount >= regroupProposalQuota {
		return nil, ErrGroupSpaceLimit
	}
	var retainedCount, auditCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM regroup_proposals_v2`).Scan(&retainedCount); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM regroup_audit_v2`).Scan(&auditCount); err != nil {
		return nil, err
	}
	if retainedCount >= regroupRetainedQuota || auditCount >= regroupRetainedQuota {
		return nil, ErrGroupSpaceLimit
	}
	encoded, _ := json.Marshal(proposal)
	_, err = tx.Exec(`INSERT INTO regroup_proposals_v2
(proposal_id,endpoint_id,operation_id,proposal_json,state,created_at) VALUES(?,?,?,?,?,?)`,
		proposal.ProposalID, proposal.EndpointID, in.OperationID, string(encoded), proposal.State, proposal.CreatedAt)
	if err != nil {
		return nil, ErrRegroupConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &proposal, nil
}

func readRegroupProposalTx(tx *sql.Tx, proposalID string) (RegroupProposal, error) {
	var proposal RegroupProposal
	var encoded, state string
	if tx.QueryRow(`SELECT proposal_json,state FROM regroup_proposals_v2 WHERE proposal_id=?`,
		proposalID).Scan(&encoded, &state) != nil || json.Unmarshal([]byte(encoded), &proposal) != nil {
		return proposal, ErrRegroupNotFound
	}
	proposal.State = state
	return proposal, nil
}

func (s *Store) RegroupProposalSourceGroupID(proposalID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var encoded string
	if s.db.QueryRow(`SELECT proposal_json FROM regroup_proposals_v2 WHERE proposal_id=?`,
		proposalID).Scan(&encoded) != nil {
		return "", ErrRegroupNotFound
	}
	var proposal RegroupProposal
	if json.Unmarshal([]byte(encoded), &proposal) != nil || proposal.Input.SourceGroupID == "" {
		return "", ErrRegroupNotFound
	}
	return proposal.Input.SourceGroupID, nil
}

func readRegroupDelegationTx(tx *sql.Tx, delegationID string) (RegroupDelegation, error) {
	var delegation RegroupDelegation
	var encoded, state string
	var version int64
	var useCount int
	if tx.QueryRow(`SELECT delegation_json,state,version,use_count FROM regroup_delegations_v2
WHERE delegation_id=?`, delegationID).Scan(&encoded, &state, &version, &useCount) != nil ||
		json.Unmarshal([]byte(encoded), &delegation) != nil {
		return delegation, ErrRegroupNotFound
	}
	delegation.State, delegation.Version, delegation.UseCount = state, version, useCount
	return delegation, nil
}

func regroupOwnerRequestTx(tx *sql.Tx, clientRequestID, ownerID, purpose string) (trustedClientRequest, error) {
	actor, err := trustedClientRequestTx(tx, clientRequestID)
	if err != nil || actor.OwnerID != ownerID {
		return actor, ErrRegroupDenied
	}
	var actual string
	if tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`,
		clientRequestID).Scan(&actual) != nil || actual != purpose {
		return actor, ErrRegroupDenied
	}
	return actor, nil
}

func (s *Store) GetRegroupProposalForClientRequest(clientRequestID, ownerID, proposalID string) (*RegroupProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := regroupOwnerRequestTx(tx, clientRequestID, ownerID, "topology.regroup_proposal")
	if err != nil {
		return nil, err
	}
	proposal, err := readRegroupProposalTx(tx, proposalID)
	if err != nil || proposal.OwnerID != ownerID || proposal.HubID != actor.HubID {
		return nil, ErrRegroupDenied
	}
	var delegationID string
	if err := tx.QueryRow(`SELECT delegation_id FROM regroup_delegations_v2 WHERE proposal_id=?`,
		proposalID).Scan(&delegationID); err == nil {
		delegation, err := readRegroupDelegationTx(tx, delegationID)
		if err != nil {
			return nil, err
		}
		proposal.Delegation = &delegation
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &proposal, nil
}

func (s *Store) IssueRegroupDelegationForClientRequest(clientRequestID, ownerID, proposalID, expiresAt string, maxUses int) (*RegroupDelegation, error) {
	deadline, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || maxUses != 1 {
		return nil, ErrRegroupInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := regroupOwnerRequestTx(tx, clientRequestID, ownerID, "topology.delegation_issue")
	if err != nil {
		return nil, err
	}
	var existingID string
	if err := tx.QueryRow(`SELECT delegation_id FROM regroup_delegations_v2 WHERE request_id=?`,
		clientRequestID).Scan(&existingID); err == nil {
		existing, err := readRegroupDelegationTx(tx, existingID)
		if err != nil || existing.OwnerID != ownerID || existing.HubID != actor.HubID ||
			existing.ProposalID != proposalID || existing.ExpiresAt != deadline.UTC().Format(time.RFC3339Nano) ||
			existing.MaxUses != maxUses {
			return nil, ErrRegroupConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &existing, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	at := time.Now().UTC()
	if !deadline.After(at) || deadline.After(at.Add(regroupMaxTTL)) {
		return nil, ErrRegroupInvalid
	}
	proposal, err := readRegroupProposalTx(tx, proposalID)
	if err != nil || proposal.State != "PROPOSED" || proposal.OwnerID != ownerID ||
		proposal.HubID != actor.HubID || !networkExpiryAllows(proposal.ExpiresAt, at) {
		return nil, ErrRegroupDenied
	}
	source, err := regroupGroupScopeTx(tx, proposal.Input.SourceGroupID)
	if err != nil {
		return nil, err
	}
	target, err := regroupGroupScopeTx(tx, proposal.Input.TargetGroupID)
	if err != nil || source.hubID != actor.HubID || target.hubID != actor.HubID ||
		source.ownerID != ownerID || target.ownerID != ownerID ||
		source.networkID != proposal.Input.NetworkID || target.networkID != proposal.Input.NetworkID ||
		source.version != proposal.Input.ExpectedSourceVersion || target.version != proposal.Input.ExpectedTargetVersion {
		return nil, ErrRegroupConflict
	}
	delegation := RegroupDelegation{DelegationID: NewID("rdlg"), ProposalID: proposalID,
		HubID: actor.HubID, OwnerID: ownerID, NetworkID: proposal.Input.NetworkID,
		SourceGroupID: proposal.Input.SourceGroupID, TargetGroupID: proposal.Input.TargetGroupID,
		Action: proposal.Input.Action, ExpectedSourceVersion: proposal.Input.ExpectedSourceVersion,
		ExpectedTargetVersion: proposal.Input.ExpectedTargetVersion, ExpiresAt: deadline.UTC().Format(time.RFC3339Nano),
		MaxUses: maxUses, State: "ACTIVE", Version: 1, CreatedAt: at.Format(time.RFC3339Nano)}
	encoded, _ := json.Marshal(delegation)
	_, err = tx.Exec(`INSERT INTO regroup_delegations_v2
(delegation_id,proposal_id,delegation_json,state,version,use_count,request_id,created_at)
VALUES(?,?,?,'ACTIVE',1,0,?,?)`, delegation.DelegationID, proposalID, string(encoded), clientRequestID, delegation.CreatedAt)
	if err != nil {
		return nil, ErrRegroupConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &delegation, nil
}

func (s *Store) RevokeRegroupDelegationForClientRequest(clientRequestID, ownerID, delegationID string, expectedVersion int64) (*RegroupDelegation, error) {
	if expectedVersion <= 0 {
		return nil, ErrRegroupInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := regroupOwnerRequestTx(tx, clientRequestID, ownerID, "topology.delegation_revoke")
	if err != nil {
		return nil, err
	}
	delegation, err := readRegroupDelegationTx(tx, delegationID)
	if err != nil || delegation.OwnerID != ownerID || delegation.HubID != actor.HubID {
		return nil, ErrRegroupDenied
	}
	var revokeRequestID string
	if err := tx.QueryRow(`SELECT revoke_request_id FROM regroup_delegations_v2 WHERE delegation_id=?`,
		delegationID).Scan(&revokeRequestID); err != nil {
		return nil, err
	}
	if delegation.State == "REVOKED" && revokeRequestID == clientRequestID &&
		delegation.Version == expectedVersion+1 {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &delegation, nil
	}
	if delegation.Version != expectedVersion || delegation.State != "ACTIVE" {
		return nil, ErrRegroupConflict
	}
	result, err := tx.Exec(`UPDATE regroup_delegations_v2 SET state='REVOKED',version=version+1,
revoke_request_id=? WHERE delegation_id=? AND state='ACTIVE' AND version=?`,
		clientRequestID, delegationID, expectedVersion)
	if err != nil {
		return nil, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return nil, ErrRegroupConflict
	}
	delegation.State, delegation.Version = "REVOKED", delegation.Version+1
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &delegation, nil
}

func (s *Store) ApplyDelegatedRegroup(actor GroupSpaceActor, proposalID, delegationID string) (*RegroupApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err := regroupMonitorGuardTx(tx, actor, at); err != nil {
		return nil, err
	}
	proposal, err := readRegroupProposalTx(tx, proposalID)
	if err != nil || proposal.EndpointID != actor.Scope.EndpointID ||
		proposal.PrincipalID != actor.Scope.PrincipalID || proposal.BindingID != actor.Scope.BindingID ||
		proposal.BindingEpoch != actor.Scope.BindingEpoch || proposal.Input.SourceGroupID != actor.Scope.GroupID ||
		proposal.Input.NetworkID != actor.Scope.NetworkID {
		return nil, ErrRegroupDenied
	}
	if err := regroupTargetGuardTx(tx, actor, proposal.Input.TargetGroupID, at); err != nil {
		return nil, err
	}
	delegation, err := readRegroupDelegationTx(tx, delegationID)
	if err != nil || delegation.ProposalID != proposalID ||
		delegation.OwnerID != proposal.OwnerID || delegation.HubID != proposal.HubID ||
		delegation.NetworkID != proposal.Input.NetworkID ||
		delegation.SourceGroupID != proposal.Input.SourceGroupID ||
		delegation.TargetGroupID != proposal.Input.TargetGroupID ||
		delegation.Action != proposal.Input.Action ||
		delegation.ExpectedSourceVersion != proposal.Input.ExpectedSourceVersion ||
		delegation.ExpectedTargetVersion != proposal.Input.ExpectedTargetVersion {
		return nil, ErrRegroupDenied
	}
	if proposal.State == "APPLIED" {
		var encoded string
		if tx.QueryRow(`SELECT result_json FROM regroup_audit_v2 WHERE proposal_id=? AND delegation_id=?
AND actor_endpoint_id=?`, proposalID, delegationID, actor.Scope.EndpointID).Scan(&encoded) != nil {
			return nil, ErrRegroupDenied
		}
		var prior RegroupApplyResult
		if json.Unmarshal([]byte(encoded), &prior) != nil {
			return nil, ErrRegroupConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &prior, nil
	}
	if proposal.State != "PROPOSED" || !networkExpiryAllows(proposal.ExpiresAt, at) ||
		delegation.State != "ACTIVE" || delegation.UseCount >= delegation.MaxUses ||
		!networkExpiryAllows(delegation.ExpiresAt, at) {
		return nil, ErrRegroupDenied
	}
	source, err := regroupGroupScopeTx(tx, proposal.Input.SourceGroupID)
	if err != nil {
		return nil, err
	}
	target, err := regroupGroupScopeTx(tx, proposal.Input.TargetGroupID)
	if err != nil || source.hubID != proposal.HubID || target.hubID != proposal.HubID ||
		source.ownerID != proposal.OwnerID || target.ownerID != proposal.OwnerID ||
		source.networkID != proposal.Input.NetworkID || target.networkID != proposal.Input.NetworkID ||
		source.trustDomainID != target.trustDomainID {
		return nil, ErrRegroupDenied
	}
	if source.version != proposal.Input.ExpectedSourceVersion ||
		target.version != proposal.Input.ExpectedTargetVersion {
		return nil, ErrRegroupConflict
	}
	if proposal.Input.Action == RegroupSetParent && source.parentID == target.id {
		return nil, ErrRegroupConflict
	}
	var group *Group
	stamp := at.Format(time.RFC3339Nano)
	switch proposal.Input.Action {
	case RegroupSetParent:
		var cycle int
		err = tx.QueryRow(`WITH RECURSIVE ancestors(id) AS (
 SELECT ? UNION SELECT g.parent_group_id FROM groups g JOIN ancestors a ON g.id=a.id
 WHERE g.parent_group_id<>'') SELECT 1 FROM ancestors WHERE id=? LIMIT 1`,
			proposal.Input.TargetGroupID, proposal.Input.SourceGroupID).Scan(&cycle)
		if err == nil {
			return nil, ErrGroupHierarchyCycle
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
		result, err := tx.Exec(`UPDATE groups SET parent_group_id=?,version=version+1,
revision=revision+1,updated_at=? WHERE id=? AND version=?`, proposal.Input.TargetGroupID,
			stamp, proposal.Input.SourceGroupID, source.version)
		if err != nil {
			return nil, err
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return nil, ErrRegroupConflict
		}
		if _, err := tx.Exec(`UPDATE groups SET version=version+1,updated_at=? WHERE id=?`, stamp, target.id); err != nil {
			return nil, err
		}
		if source.parentID != "" && source.parentID != target.id {
			if _, err := tx.Exec(`UPDATE groups SET version=version+1,updated_at=? WHERE id=?`,
				stamp, source.parentID); err != nil {
				return nil, err
			}
		}
		group, err = scanGroup(tx.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id=?`, source.id))
		if err != nil {
			return nil, err
		}
	case RegroupCreateChild:
		id := NewID("grp")
		externalMode := target.externalMode
		if externalMode == "" {
			externalMode = "monitor_mediated"
		}
		_, err := tx.Exec(`INSERT INTO groups
(id,network_id,parent_group_id,owner_principal_id,trust_domain_id,name,state,purpose,
revision,policy_ref,context_policy,isolation_profile,external_mode,version,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,1,?,?)`, id, source.networkID, target.id,
			source.ownerID, source.trustDomainID, proposal.Input.NewGroupName,
			GroupStateActive, "", "", "group_scoped", "trusted_host", externalMode, stamp, stamp)
		if err != nil {
			return nil, err
		}
		// Match ordinary Group creation: the human Owner can manage the new
		// empty Group, while no Endpoint, reader, key or history is copied.
		_, err = tx.Exec(`INSERT INTO memberships
(id,principal_id,group_id,role,roles_json,grants_json,authorization_json,status,
revision,version,created_at,updated_at)
VALUES(?,?,?,'owner','["owner"]','["group.manage","membership.manage","representative.manage","policy.manage"]','{}','active',1,1,?,?)`,
			NewID("mbr"), source.ownerID, id, stamp, stamp)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE groups SET version=version+1,updated_at=? WHERE id=?`, stamp, target.id); err != nil {
			return nil, err
		}
		group, err = scanGroup(tx.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id=?`, id))
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrRegroupInvalid
	}
	result := RegroupApplyResult{AuditID: NewID("raud"), ProposalID: proposalID,
		DelegationID: delegationID, Action: proposal.Input.Action, Group: *group, AppliedAt: stamp}
	encoded, _ := json.Marshal(result)
	_, err = tx.Exec(`INSERT INTO regroup_audit_v2
(audit_id,proposal_id,delegation_id,actor_endpoint_id,action,source_group_id,target_group_id,
before_source_version,before_target_version,result_group_id,result_json,applied_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, result.AuditID, proposalID, delegationID,
		actor.Scope.EndpointID, proposal.Input.Action, source.id, target.id,
		source.version, target.version, group.ID, string(encoded), stamp)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE regroup_proposals_v2 SET state='APPLIED' WHERE proposal_id=? AND state='PROPOSED'`, proposalID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE regroup_delegations_v2 SET state='EXHAUSTED',
version=version+1,use_count=use_count+1 WHERE delegation_id=? AND state='ACTIVE'`, delegationID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &result, nil
}
