package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	CommunicationLinkProposed = "PROPOSED"
	CommunicationLinkRevoked  = "REVOKED"
)

var (
	ErrCommunicationLinkNotFound = errors.New("communication link not found or not authorized")
	ErrCommunicationLinkScope    = errors.New("communication link endpoint/group scope is not active")
)

// CommunicationLink is a durable proposal, not yet a route. Existing manager
// bearer credentials are also used for Node enrollment, so they cannot prove
// an independent user's consent. There is deliberately no ACTIVE transition
// until authenticated bilateral grants and endpoint ciphertext are available.
type CommunicationLink struct {
	ID                string                         `json:"link_id"`
	SourceEndpointID  string                         `json:"source_endpoint_id"`
	SourcePrincipalID string                         `json:"source_principal_id"`
	SourceGroupID     string                         `json:"source_group_id"`
	SourceOwnerID     string                         `json:"source_owner_id"`
	SourceNodeID      string                         `json:"source_node_id"`
	TargetEndpointID  string                         `json:"target_endpoint_id"`
	TargetPrincipalID string                         `json:"target_principal_id"`
	TargetGroupID     string                         `json:"target_group_id"`
	TargetOwnerID     string                         `json:"target_owner_id"`
	TargetNodeID      string                         `json:"target_node_id"`
	Direction         string                         `json:"direction"`
	Actions           []string                       `json:"actions"`
	DataScopes        []string                       `json:"data_scopes"`
	TransportHubID    string                         `json:"transport_hub_id,omitempty"`
	ExpiresAt         string                         `json:"expires_at"`
	ScopeSnapshot     CommunicationLinkScopeSnapshot `json:"scope_snapshot"`
	ContractDigest    string                         `json:"contract_digest"`
	State             string                         `json:"state"`
	Version           int64                          `json:"version"`
	CreatedAt         string                         `json:"created_at"`
	UpdatedAt         string                         `json:"updated_at"`
	RevokedAt         string                         `json:"revoked_at,omitempty"`
	RevokedByOwnerID  string                         `json:"revoked_by_owner_id,omitempty"`
	RevocationReason  string                         `json:"revocation_reason,omitempty"`
}

type CommunicationLinkScopeSnapshot struct {
	SourceMembershipRevision int64 `json:"source_membership_revision"`
	SourceJoinRevision       int64 `json:"source_join_revision"`
	SourceGroupVersion       int64 `json:"source_group_version"`
	TargetMembershipRevision int64 `json:"target_membership_revision"`
	TargetJoinRevision       int64 `json:"target_join_revision"`
	TargetGroupVersion       int64 `json:"target_group_version"`
}

type CommunicationLinkProposal struct {
	SourceEndpointID string
	SourceGroupID    string
	TargetEndpointID string
	TargetGroupID    string
	Direction        string
	Actions          []string
	DataScopes       []string
	TransportHubID   string
	ExpiresAt        string
	ActorOwnerID     string // Injected by the authenticated manager; never read from HTTP JSON.
}

const communicationLinkColumns = `id, source_endpoint_id, source_principal_id, source_group_id,
source_owner_id, source_node_id, target_endpoint_id, target_principal_id,
target_group_id, target_owner_id, target_node_id, direction, actions_json,
data_scopes_json, transport_hub_id, expires_at, scope_snapshot_json, contract_digest, state,
version, created_at, updated_at, revoked_at, revoked_by_owner_id, revocation_reason`

func (s *Store) initializeCommunicationLinksV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS communication_links_v2 (
  id TEXT PRIMARY KEY,
  source_endpoint_id TEXT NOT NULL,
  source_principal_id TEXT NOT NULL,
  source_group_id TEXT NOT NULL,
  source_owner_id TEXT NOT NULL,
  source_node_id TEXT NOT NULL,
  target_endpoint_id TEXT NOT NULL,
  target_principal_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  target_owner_id TEXT NOT NULL,
  target_node_id TEXT NOT NULL,
  direction TEXT NOT NULL CHECK(direction IN ('forward', 'bidirectional')),
  actions_json TEXT NOT NULL,
  data_scopes_json TEXT NOT NULL,
  transport_hub_id TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  scope_snapshot_json TEXT NOT NULL,
  contract_digest TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'PROPOSED' CHECK(state IN ('PROPOSED', 'REVOKED')),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  revoked_by_owner_id TEXT NOT NULL DEFAULT '',
  revocation_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS communication_links_v2_source_owner_idx
  ON communication_links_v2(source_owner_id, state, updated_at);
CREATE INDEX IF NOT EXISTS communication_links_v2_target_owner_idx
  ON communication_links_v2(target_owner_id, state, updated_at);
CREATE INDEX IF NOT EXISTS communication_links_v2_endpoints_idx
  ON communication_links_v2(source_endpoint_id, target_endpoint_id, state);
`)
	return err
}

func normalizeLinkWords(values []string, allowed map[string]bool, limit int) ([]string, error) {
	if len(values) == 0 || len(values) > limit {
		return nil, errors.New("communication link requires a bounded nonempty list")
	}
	unique := make(map[string]bool, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || len(value) > 128 || strings.ContainsAny(value, " \t\n\r") || value == "*" {
			return nil, errors.New("communication link contains an invalid action or data scope")
		}
		if allowed != nil && !allowed[value] {
			return nil, errors.New("communication link contains an unsupported action")
		}
		unique[value] = true
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

type linkEndpointScope struct {
	principalID        string
	ownerID            string
	nodeID             string
	membershipRevision int64
	joinRevision       int64
	groupVersion       int64
}

func readLinkEndpointScope(tx *sql.Tx, endpointID, groupID string, at time.Time) (linkEndpointScope, error) {
	var scope linkEndpointScope
	var endpointState, migrationState, joinState, memberState, principalState, groupState, memberEffective, memberExpiry string
	err := tx.QueryRow(`SELECT e.principal_id, p.owner_id, e.machine_id, e.status,
 e.migration_state, eg.status, m.status, p.status, g.state, m.effective_at, m.expires_at,
 m.revision, eg.revision, g.version
FROM fabric_endpoints e
JOIN principals p ON p.id = e.principal_id
JOIN endpoint_group_memberships eg ON eg.endpoint_id = e.id AND eg.group_id = ?
JOIN memberships m ON m.principal_id = e.principal_id AND m.group_id = eg.group_id
JOIN groups g ON g.id = eg.group_id
WHERE e.id = ?`, groupID, endpointID).Scan(&scope.principalID, &scope.ownerID,
		&scope.nodeID, &endpointState, &migrationState, &joinState, &memberState,
		&principalState, &groupState, &memberEffective, &memberExpiry,
		&scope.membershipRevision, &scope.joinRevision, &scope.groupVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return linkEndpointScope{}, ErrCommunicationLinkScope
	}
	if err != nil {
		return linkEndpointScope{}, err
	}
	if scope.ownerID == "" || scope.nodeID == "" || endpointState == "left" ||
		migrationState != EndpointMigrationReady || joinState != "active" ||
		memberState != MembershipStatusActive || principalState != PrincipalStatusActive ||
		groupState != GroupStateActive {
		return linkEndpointScope{}, ErrCommunicationLinkScope
	}
	if memberEffective != "" {
		effective, err := time.Parse(time.RFC3339Nano, memberEffective)
		if err != nil || effective.After(at) {
			return linkEndpointScope{}, ErrCommunicationLinkScope
		}
	}
	if memberExpiry != "" {
		expires, err := time.Parse(time.RFC3339Nano, memberExpiry)
		if err != nil || !expires.After(at) {
			return linkEndpointScope{}, ErrCommunicationLinkScope
		}
	}
	return scope, nil
}

func (s *Store) ProposeCommunicationLink(input CommunicationLinkProposal) (*CommunicationLink, error) {
	input.SourceEndpointID = strings.TrimSpace(input.SourceEndpointID)
	input.SourceGroupID = strings.TrimSpace(input.SourceGroupID)
	input.TargetEndpointID = strings.TrimSpace(input.TargetEndpointID)
	input.TargetGroupID = strings.TrimSpace(input.TargetGroupID)
	input.ActorOwnerID = strings.TrimSpace(input.ActorOwnerID)
	input.Direction = strings.ToLower(strings.TrimSpace(input.Direction))
	input.TransportHubID = strings.TrimSpace(input.TransportHubID)
	if input.SourceEndpointID == "" || input.SourceGroupID == "" || input.TargetEndpointID == "" || input.TargetGroupID == "" ||
		input.ActorOwnerID == "" || input.SourceEndpointID == input.TargetEndpointID {
		return nil, ErrCommunicationLinkScope
	}
	if input.Direction != "forward" && input.Direction != "bidirectional" {
		return nil, errors.New("communication link direction must be forward or bidirectional")
	}
	actions, err := normalizeLinkWords(input.Actions, map[string]bool{"send": true, "ask": true, "reply": true}, 3)
	if err != nil {
		return nil, err
	}
	if len(actions) == 1 && actions[0] == "reply" {
		return nil, errors.New("communication link requires send or ask")
	}
	scopes, err := normalizeLinkWords(input.DataScopes, nil, 16)
	if err != nil {
		return nil, err
	}
	expires, err := time.Parse(time.RFC3339, strings.TrimSpace(input.ExpiresAt))
	if err != nil || !expires.After(time.Now().UTC()) {
		return nil, errors.New("communication link expiry must be a future RFC3339 timestamp")
	}
	input.Actions = actions
	input.DataScopes = scopes
	input.ExpiresAt = expires.UTC().Format(time.RFC3339)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	currentTime := time.Now().UTC()
	source, err := readLinkEndpointScope(tx, input.SourceEndpointID, input.SourceGroupID, currentTime)
	if err != nil {
		return nil, err
	}
	if source.ownerID != input.ActorOwnerID {
		return nil, ErrCommunicationLinkNotFound
	}
	target, err := readLinkEndpointScope(tx, input.TargetEndpointID, input.TargetGroupID, currentTime)
	if err != nil {
		return nil, err
	}
	// A foreign Endpoint ID is not an invitation. Until a bilateral trusted
	// contact/card exchange exists, even a non-routable proposal must not
	// reveal another owner's Node or Principal metadata to the proposer.
	if target.ownerID != source.ownerID {
		return nil, ErrCommunicationLinkScope
	}
	link, err := insertCommunicationLinkProposalTx(tx, input, source, target, currentTime)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return link, nil
}

// insertCommunicationLinkProposalTx creates only a durable PROPOSED contract.
// Callers must establish actor/consent policy before using it. The public
// ProposeCommunicationLink path deliberately keeps its same-owner guard;
// external invite acceptance is the only current cross-owner caller.
func insertCommunicationLinkProposalTx(
	tx *sql.Tx,
	input CommunicationLinkProposal,
	source, target linkEndpointScope,
	currentTime time.Time,
) (*CommunicationLink, error) {
	timestamp := currentTime.UTC().Format(time.RFC3339)
	actions, scopes := input.Actions, input.DataScopes
	if source.nodeID != target.nodeID && input.TransportHubID == "" {
		return nil, errors.New("cross-node link requires one selected transport Hub")
	}
	if source.nodeID == target.nodeID && input.TransportHubID != "" {
		return nil, errors.New("same-node link must not select a Hub relay")
	}
	link := CommunicationLink{ID: NewID("link"), SourceEndpointID: input.SourceEndpointID,
		SourcePrincipalID: source.principalID, SourceGroupID: input.SourceGroupID,
		SourceOwnerID: source.ownerID, SourceNodeID: source.nodeID,
		TargetEndpointID: input.TargetEndpointID, TargetPrincipalID: target.principalID,
		TargetGroupID: input.TargetGroupID, TargetOwnerID: target.ownerID,
		TargetNodeID: target.nodeID, Direction: input.Direction, Actions: actions,
		DataScopes: scopes, TransportHubID: input.TransportHubID, ExpiresAt: input.ExpiresAt,
		State: CommunicationLinkProposed, Version: 1, CreatedAt: timestamp, UpdatedAt: timestamp}
	link.ScopeSnapshot = CommunicationLinkScopeSnapshot{
		SourceMembershipRevision: source.membershipRevision, SourceJoinRevision: source.joinRevision,
		SourceGroupVersion: source.groupVersion, TargetMembershipRevision: target.membershipRevision,
		TargetJoinRevision: target.joinRevision, TargetGroupVersion: target.groupVersion,
	}
	digest, err := communicationLinkContractDigest(link)
	if err != nil {
		return nil, err
	}
	link.ContractDigest = digest
	actionsJSON, _ := json.Marshal(link.Actions)
	scopesJSON, _ := json.Marshal(link.DataScopes)
	snapshotJSON, _ := json.Marshal(link.ScopeSnapshot)
	_, err = tx.Exec(`INSERT INTO communication_links_v2
(id, source_endpoint_id, source_principal_id, source_group_id, source_owner_id, source_node_id,
 target_endpoint_id, target_principal_id, target_group_id, target_owner_id, target_node_id,
 direction, actions_json, data_scopes_json, transport_hub_id, expires_at, scope_snapshot_json, contract_digest,
 state, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		link.ID, link.SourceEndpointID, link.SourcePrincipalID, link.SourceGroupID,
		link.SourceOwnerID, link.SourceNodeID, link.TargetEndpointID, link.TargetPrincipalID,
		link.TargetGroupID, link.TargetOwnerID, link.TargetNodeID, link.Direction,
		string(actionsJSON), string(scopesJSON), link.TransportHubID, link.ExpiresAt, string(snapshotJSON),
		link.ContractDigest, link.State, link.Version, link.CreatedAt, link.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("persist communication link proposal: %w", err)
	}
	return &link, nil
}

func scanCommunicationLink(row v2Scanner) (*CommunicationLink, error) {
	var link CommunicationLink
	var actionsJSON, scopesJSON, snapshotJSON string
	err := row.Scan(&link.ID, &link.SourceEndpointID, &link.SourcePrincipalID,
		&link.SourceGroupID, &link.SourceOwnerID, &link.SourceNodeID,
		&link.TargetEndpointID, &link.TargetPrincipalID, &link.TargetGroupID,
		&link.TargetOwnerID, &link.TargetNodeID, &link.Direction, &actionsJSON,
		&scopesJSON, &link.TransportHubID, &link.ExpiresAt, &snapshotJSON, &link.ContractDigest,
		&link.State, &link.Version, &link.CreatedAt, &link.UpdatedAt, &link.RevokedAt,
		&link.RevokedByOwnerID, &link.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCommunicationLinkNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(actionsJSON), &link.Actions); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopesJSON), &link.DataScopes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(snapshotJSON), &link.ScopeSnapshot); err != nil {
		return nil, err
	}
	return &link, nil
}

func (s *Store) GetCommunicationLinkForOwner(id, ownerID string) (*CommunicationLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanCommunicationLink(s.db.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ? AND (source_owner_id = ? OR target_owner_id = ?)`,
		strings.TrimSpace(id), strings.TrimSpace(ownerID), strings.TrimSpace(ownerID)))
}

func (s *Store) ListCommunicationLinksForOwner(ownerID string, limit int) ([]CommunicationLink, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE source_owner_id = ? OR target_owner_id = ?
ORDER BY created_at DESC, id DESC LIMIT ?`, strings.TrimSpace(ownerID), strings.TrimSpace(ownerID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CommunicationLink, 0)
	for rows.Next() {
		link, err := scanCommunicationLink(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *link)
	}
	return result, rows.Err()
}

func (s *Store) RevokeCommunicationLink(id, actorOwnerID string, expectedVersion int64, reason string) (*CommunicationLink, error) {
	id, actorOwnerID = strings.TrimSpace(id), strings.TrimSpace(actorOwnerID)
	if expectedVersion <= 0 {
		return nil, errors.New("expected link version is required")
	}
	if len(reason) > 512 {
		return nil, errors.New("revocation reason is too long")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ? AND (source_owner_id = ? OR target_owner_id = ?)`,
		id, actorOwnerID, actorOwnerID))
	if err != nil {
		return nil, err
	}
	if link.Version != expectedVersion {
		return nil, ErrVersionConflict
	}
	if link.State != CommunicationLinkRevoked {
		stamp := now()
		result, err := tx.Exec(`UPDATE communication_links_v2 SET state = 'REVOKED', version = version + 1,
updated_at = ?, revoked_at = ?, revoked_by_owner_id = ?, revocation_reason = ?
WHERE id = ? AND version = ? AND state = 'PROPOSED'`, stamp, stamp, actorOwnerID,
			strings.TrimSpace(reason), id, expectedVersion)
		if err != nil {
			return nil, err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed != 1 {
			return nil, ErrVersionConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return scanCommunicationLink(s.db.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id = ?`, id))
}
