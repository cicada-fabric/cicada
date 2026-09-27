package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ExternalThreadInvitePending   = "PENDING"
	ExternalThreadInviteAccepted  = "ACCEPTED"
	ExternalThreadInviteTTL       = time.Hour
	externalThreadInviteTokenSize = 32 // 256 bits before base64url encoding.
)

var (
	ErrExternalThreadInviteUnavailable = errors.New("external Thread invitation is unavailable")
	ErrExternalThreadInviteScope       = errors.New("external Thread invitation scope is not active")
)

// ExternalThreadInviteInput is an authenticated local owner's request to
// invite one other owner to a bounded forward contract. OwnerID must be
// derived by the caller from the authenticated Client session. An omitted
// Actions list defaults to ask+reply; acceptance cannot broaden either list.
type ExternalThreadInviteInput struct {
	OwnerID          string
	SourceEndpointID string
	SourceGroupID    string
	HubID            string
	Actions          []string
	DataScopes       []string
	ExpiresAt        string
}

// ExternalThreadInviteCreated returns the bearer token once. The database
// stores only its SHA-256 digest; callers should deliver Token to the intended
// invitee through a trusted channel.
type ExternalThreadInviteCreated struct {
	InviteID  string `json:"invite_id"`
	Token     string `json:"token"`
	HubID     string `json:"hub_id"`
	ExpiresAt string `json:"expires_at"`
}

// ExternalThreadInvitePreview contains only the labels and bounded terms
// needed for a token holder to decide whether to accept. It intentionally
// omits Endpoint, Group, Principal, owner, Node, and SessionBinding IDs.
type ExternalThreadInvitePreview struct {
	SourceEndpointLabel string   `json:"source_endpoint_label"`
	SourceGroupLabel    string   `json:"source_group_label"`
	HubID               string   `json:"hub_id"`
	Direction           string   `json:"direction"`
	Actions             []string `json:"actions"`
	DataScopes          []string `json:"data_scopes"`
	ExpiresAt           string   `json:"expires_at"`
}

// ExternalThreadInviteAcceptance acknowledges token consumption without
// returning the Link's private scope coordinates. The resulting Link remains
// PROPOSED and cannot route messages.
type ExternalThreadInviteAcceptance struct {
	LinkID    string `json:"link_id"`
	State     string `json:"state"`
	Version   int64  `json:"version"`
	ExpiresAt string `json:"expires_at"`
}

type externalThreadInviteRow struct {
	id                       string
	tokenDigest              string
	sourceEndpointID         string
	sourceGroupID            string
	sourceOwnerID            string
	sourcePrincipalID        string
	sourceNodeID             string
	sourceMembershipRevision int64
	sourceJoinRevision       int64
	sourceGroupVersion       int64
	hubID                    string
	direction                string
	actionsJSON              string
	dataScopesJSON           string
	expiresAt                string
	state                    string
	targetOwnerID            string
	targetEndpointID         string
	targetGroupID            string
	linkID                   string
	createdAt                string
	acceptedAt               string
}

const externalThreadInviteColumns = `invite_id, token_digest, source_endpoint_id, source_group_id,
source_owner_id, source_principal_id, source_node_id, source_membership_revision,
source_join_revision, source_group_version, hub_id, direction, actions_json, data_scopes_json,
expires_at, state, target_owner_id, target_endpoint_id, target_group_id,
communication_link_id, created_at, accepted_at`

func (s *Store) initializeExternalThreadInvitesV2Schema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS external_thread_invites_v2 (
  invite_id TEXT PRIMARY KEY,
  token_digest TEXT NOT NULL CHECK(length(token_digest) = 64),
  source_endpoint_id TEXT NOT NULL,
  source_group_id TEXT NOT NULL,
  source_owner_id TEXT NOT NULL,
  source_principal_id TEXT NOT NULL,
  source_node_id TEXT NOT NULL,
  source_membership_revision INTEGER NOT NULL CHECK(source_membership_revision > 0),
  source_join_revision INTEGER NOT NULL CHECK(source_join_revision > 0),
  source_group_version INTEGER NOT NULL CHECK(source_group_version > 0),
  hub_id TEXT NOT NULL,
  direction TEXT NOT NULL CHECK(direction = 'forward'),
  actions_json TEXT NOT NULL CHECK(actions_json IN
    ('["ask"]', '["ask","reply"]', '["ask","reply","send"]', '["ask","send"]', '["reply","send"]', '["send"]')),
  data_scopes_json TEXT NOT NULL CHECK(data_scopes_json <> '[]'),
  expires_at TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING', 'ACCEPTED')),
  target_owner_id TEXT NOT NULL DEFAULT '',
  target_endpoint_id TEXT NOT NULL DEFAULT '',
  target_group_id TEXT NOT NULL DEFAULT '',
  communication_link_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL DEFAULT '',
  CHECK ((state = 'PENDING' AND target_owner_id = '' AND target_endpoint_id = '' AND
          target_group_id = '' AND communication_link_id = '' AND accepted_at = '') OR
         (state = 'ACCEPTED' AND target_owner_id <> '' AND target_endpoint_id <> '' AND
          target_group_id <> '' AND communication_link_id <> '' AND accepted_at <> '')),
  CHECK (state <> 'ACCEPTED' OR communication_link_id <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS external_thread_invites_v2_digest_idx
  ON external_thread_invites_v2(token_digest);
CREATE UNIQUE INDEX IF NOT EXISTS external_thread_invites_v2_link_idx
  ON external_thread_invites_v2(communication_link_id) WHERE communication_link_id <> '';
CREATE INDEX IF NOT EXISTS external_thread_invites_v2_source_idx
  ON external_thread_invites_v2(source_owner_id, state, expires_at);
`)
	if err != nil {
		return fmt.Errorf("initialize external Thread invite schema: %w", err)
	}
	return nil
}

func scanExternalThreadInvite(row v2Scanner) (*externalThreadInviteRow, error) {
	var invite externalThreadInviteRow
	err := row.Scan(&invite.id, &invite.tokenDigest, &invite.sourceEndpointID,
		&invite.sourceGroupID, &invite.sourceOwnerID, &invite.sourcePrincipalID,
		&invite.sourceNodeID, &invite.sourceMembershipRevision, &invite.sourceJoinRevision,
		&invite.sourceGroupVersion, &invite.hubID, &invite.direction, &invite.actionsJSON,
		&invite.dataScopesJSON, &invite.expiresAt, &invite.state, &invite.targetOwnerID,
		&invite.targetEndpointID, &invite.targetGroupID, &invite.linkID, &invite.createdAt,
		&invite.acceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrExternalThreadInviteUnavailable
	}
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

func externalThreadInviteTokenDigest(token string) (string, error) {
	if len(token) != base64.RawURLEncoding.EncodedLen(externalThreadInviteTokenSize) {
		return "", ErrExternalThreadInviteUnavailable
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != externalThreadInviteTokenSize || base64.RawURLEncoding.EncodeToString(raw) != token {
		return "", ErrExternalThreadInviteUnavailable
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:]), nil
}

func readExternalThreadInviteHubID(tx *sql.Tx) (string, error) {
	var hubID string
	err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id = 1`).Scan(&hubID)
	if errors.Is(err, sql.ErrNoRows) || strings.TrimSpace(hubID) == "" {
		return "", ErrExternalThreadInviteUnavailable
	}
	return hubID, err
}

func validateExternalThreadInviteOwnerGroupTx(
	tx *sql.Tx,
	ownerID, groupID, endpointPrincipalID string,
) error {
	var ownerKind, ownerOwnerID, ownerTrustDomain, ownerStatus string
	var groupOwnerPrincipalID, groupTrustDomain string
	var endpointOwnerID, endpointTrustDomain, endpointStatus string
	err := tx.QueryRow(`SELECT owner.kind, owner.owner_id, owner.trust_domain_id, owner.status,
g.owner_principal_id, g.trust_domain_id, endpoint_principal.owner_id,
endpoint_principal.trust_domain_id, endpoint_principal.status
FROM principals owner
JOIN groups g ON g.id = ?
JOIN principals endpoint_principal ON endpoint_principal.id = ?
WHERE owner.id = ?`, groupID, endpointPrincipalID, ownerID).Scan(
		&ownerKind, &ownerOwnerID, &ownerTrustDomain, &ownerStatus,
		&groupOwnerPrincipalID, &groupTrustDomain, &endpointOwnerID,
		&endpointTrustDomain, &endpointStatus)
	if err != nil {
		return ErrExternalThreadInviteScope
	}
	if ownerKind != PrincipalKindHuman || ownerOwnerID != ownerID || ownerStatus != PrincipalStatusActive ||
		groupOwnerPrincipalID != ownerID || groupTrustDomain != ownerTrustDomain ||
		endpointOwnerID != ownerID || endpointTrustDomain != ownerTrustDomain ||
		endpointStatus != PrincipalStatusActive {
		return ErrExternalThreadInviteScope
	}
	return nil
}

func (s *Store) CreateExternalThreadInvite(input ExternalThreadInviteInput) (*ExternalThreadInviteCreated, error) {
	input.OwnerID = strings.TrimSpace(input.OwnerID)
	input.SourceEndpointID = strings.TrimSpace(input.SourceEndpointID)
	input.SourceGroupID = strings.TrimSpace(input.SourceGroupID)
	input.HubID = strings.TrimSpace(input.HubID)
	if input.OwnerID == "" || input.SourceEndpointID == "" || input.SourceGroupID == "" || input.HubID == "" {
		return nil, ErrExternalThreadInviteScope
	}
	if len(input.Actions) == 0 {
		input.Actions = []string{"ask", "reply"}
	}
	actions, err := normalizeLinkWords(input.Actions, map[string]bool{"send": true, "ask": true, "reply": true}, 3)
	if err != nil {
		return nil, err
	}
	if len(actions) == 1 && actions[0] == "reply" {
		return nil, errors.New("external Thread invite requires send or ask")
	}
	scopes, err := normalizeLinkWords(input.DataScopes, nil, 16)
	if err != nil {
		return nil, err
	}
	expires, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(input.ExpiresAt))
	if err != nil {
		return nil, errors.New("external Thread invite expiry must be a future RFC3339 timestamp")
	}
	rawToken := make([]byte, externalThreadInviteTokenSize)
	if _, err := rand.Read(rawToken); err != nil {
		return nil, fmt.Errorf("generate external Thread invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	digest := sha256.Sum256([]byte(token))
	digestText := hex.EncodeToString(digest[:])
	actionsJSON, _ := json.Marshal(actions)
	scopesJSON, _ := json.Marshal(scopes)

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	currentTime := time.Now().UTC()
	if !expires.After(currentTime) || expires.After(currentTime.Add(ExternalThreadInviteTTL)) {
		return nil, fmt.Errorf("external Thread invite expiry must be within %s", ExternalThreadInviteTTL)
	}
	expiresAt := expires.UTC().Format(time.RFC3339Nano)
	hubID, err := readExternalThreadInviteHubID(tx)
	if err != nil {
		return nil, err
	}
	if input.HubID != hubID {
		return nil, ErrExternalThreadInviteScope
	}
	source, err := readLinkEndpointScope(tx, input.SourceEndpointID, input.SourceGroupID, currentTime)
	if err != nil {
		return nil, ErrExternalThreadInviteScope
	}
	if source.ownerID != input.OwnerID {
		return nil, ErrExternalThreadInviteScope
	}
	if err := validateExternalThreadInviteOwnerGroupTx(tx, source.ownerID, input.SourceGroupID, source.principalID); err != nil {
		return nil, err
	}
	if _, err := readCommunicationLinkGrantBinding(tx, input.SourceEndpointID, source.principalID, source.nodeID, currentTime); err != nil {
		return nil, ErrExternalThreadInviteScope
	}
	id := NewID("invite")
	createdAt := currentTime.Format(time.RFC3339Nano)
	_, err = tx.Exec(`INSERT INTO external_thread_invites_v2
(invite_id, token_digest, source_endpoint_id, source_group_id, source_owner_id,
 source_principal_id, source_node_id, source_membership_revision, source_join_revision,
 source_group_version, hub_id, direction, actions_json, data_scopes_json, expires_at, state,
 created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'forward', ?, ?, ?, 'PENDING', ?)`,
		id, digestText, input.SourceEndpointID, input.SourceGroupID, source.ownerID,
		source.principalID, source.nodeID, source.membershipRevision, source.joinRevision,
		source.groupVersion, hubID, string(actionsJSON), string(scopesJSON), expiresAt, createdAt)
	if err != nil {
		return nil, fmt.Errorf("persist external Thread invite: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ExternalThreadInviteCreated{InviteID: id, Token: token, HubID: hubID, ExpiresAt: expiresAt}, nil
}

func pendingExternalThreadInvite(tx *sql.Tx, digest string, at time.Time) (*externalThreadInviteRow, error) {
	invite, err := scanExternalThreadInvite(tx.QueryRow(`SELECT `+externalThreadInviteColumns+`
FROM external_thread_invites_v2 WHERE token_digest = ?`, digest))
	if err != nil {
		return nil, err
	}
	expiresAt, parseErr := time.Parse(time.RFC3339Nano, invite.expiresAt)
	if invite.state != ExternalThreadInvitePending || parseErr != nil || !expiresAt.After(at) {
		return nil, ErrExternalThreadInviteUnavailable
	}
	return invite, nil
}

func decodeExternalThreadInviteTerms(invite *externalThreadInviteRow) ([]string, []string, error) {
	var rawActions, rawScopes []string
	if json.Unmarshal([]byte(invite.actionsJSON), &rawActions) != nil ||
		json.Unmarshal([]byte(invite.dataScopesJSON), &rawScopes) != nil {
		return nil, nil, ErrExternalThreadInviteUnavailable
	}
	actions, err := normalizeLinkWords(rawActions, map[string]bool{"send": true, "ask": true, "reply": true}, 3)
	if err != nil || (len(actions) == 1 && actions[0] == "reply") {
		return nil, nil, ErrExternalThreadInviteUnavailable
	}
	scopes, err := normalizeLinkWords(rawScopes, nil, 16)
	if err != nil {
		return nil, nil, ErrExternalThreadInviteUnavailable
	}
	canonicalActions, _ := json.Marshal(actions)
	canonicalScopes, _ := json.Marshal(scopes)
	if string(canonicalActions) != invite.actionsJSON || string(canonicalScopes) != invite.dataScopesJSON {
		return nil, nil, ErrExternalThreadInviteUnavailable
	}
	return actions, scopes, nil
}

func validateExternalThreadInviteSource(tx *sql.Tx, invite *externalThreadInviteRow, hubID string, at time.Time) (linkEndpointScope, error) {
	if hubID != invite.hubID || invite.direction != "forward" {
		return linkEndpointScope{}, ErrExternalThreadInviteUnavailable
	}
	if _, _, err := decodeExternalThreadInviteTerms(invite); err != nil {
		return linkEndpointScope{}, err
	}
	source, err := readLinkEndpointScope(tx, invite.sourceEndpointID, invite.sourceGroupID, at)
	if err != nil || source.ownerID != invite.sourceOwnerID || source.principalID != invite.sourcePrincipalID ||
		source.nodeID != invite.sourceNodeID || source.membershipRevision != invite.sourceMembershipRevision ||
		source.joinRevision != invite.sourceJoinRevision || source.groupVersion != invite.sourceGroupVersion {
		return linkEndpointScope{}, ErrExternalThreadInviteUnavailable
	}
	if err := validateExternalThreadInviteOwnerGroupTx(tx, source.ownerID, invite.sourceGroupID, source.principalID); err != nil {
		return linkEndpointScope{}, ErrExternalThreadInviteUnavailable
	}
	if _, err := readCommunicationLinkGrantBinding(tx, invite.sourceEndpointID, source.principalID, source.nodeID, at); err != nil {
		return linkEndpointScope{}, ErrExternalThreadInviteUnavailable
	}
	return source, nil
}

func inviteDisplayLabel(value, fallback string) string {
	var result []rune
	for _, char := range strings.TrimSpace(value) {
		if char >= 0x20 && char != 0x7f {
			result = append(result, char)
		}
		if len(result) >= 80 {
			break
		}
	}
	label := strings.TrimSpace(string(result))
	if label == "" {
		return fallback
	}
	return label
}

func (s *Store) PreviewExternalThreadInvite(token string) (*ExternalThreadInvitePreview, error) {
	digest, err := externalThreadInviteTokenDigest(token)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	currentTime := time.Now().UTC()
	invite, err := pendingExternalThreadInvite(tx, digest, currentTime)
	if err != nil {
		return nil, err
	}
	hubID, err := readExternalThreadInviteHubID(tx)
	if err != nil {
		return nil, err
	}
	if _, err := validateExternalThreadInviteSource(tx, invite, hubID, currentTime); err != nil {
		return nil, err
	}
	actions, dataScopes, err := decodeExternalThreadInviteTerms(invite)
	if err != nil {
		return nil, err
	}
	var endpointName, groupName string
	if err := tx.QueryRow(`SELECT e.name, g.name FROM fabric_endpoints e JOIN groups g ON g.id = ?
WHERE e.id = ?`, invite.sourceGroupID, invite.sourceEndpointID).Scan(&endpointName, &groupName); err != nil {
		return nil, ErrExternalThreadInviteUnavailable
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ExternalThreadInvitePreview{
		SourceEndpointLabel: inviteDisplayLabel(endpointName, "Endpoint"),
		SourceGroupLabel:    inviteDisplayLabel(groupName, "Group"),
		HubID:               invite.hubID,
		Direction:           "forward",
		Actions:             actions,
		DataScopes:          dataScopes,
		ExpiresAt:           invite.expiresAt,
	}, nil
}

func (s *Store) AcceptExternalThreadInvite(
	token, targetOwnerID, targetEndpointID, targetGroupID string,
) (*ExternalThreadInviteAcceptance, error) {
	digest, err := externalThreadInviteTokenDigest(token)
	if err != nil {
		return nil, err
	}
	targetOwnerID = strings.TrimSpace(targetOwnerID)
	targetEndpointID = strings.TrimSpace(targetEndpointID)
	targetGroupID = strings.TrimSpace(targetGroupID)
	if targetOwnerID == "" || targetEndpointID == "" || targetGroupID == "" {
		return nil, ErrExternalThreadInviteScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	currentTime := time.Now().UTC()
	invite, err := pendingExternalThreadInvite(tx, digest, currentTime)
	if err != nil {
		return nil, err
	}
	hubID, err := readExternalThreadInviteHubID(tx)
	if err != nil {
		return nil, err
	}
	source, err := validateExternalThreadInviteSource(tx, invite, hubID, currentTime)
	if err != nil {
		return nil, err
	}
	actions, dataScopes, err := decodeExternalThreadInviteTerms(invite)
	if err != nil {
		return nil, err
	}
	target, err := readLinkEndpointScope(tx, targetEndpointID, targetGroupID, currentTime)
	if err != nil || target.ownerID != targetOwnerID || target.ownerID == source.ownerID || targetEndpointID == invite.sourceEndpointID {
		return nil, ErrExternalThreadInviteScope
	}
	if err := validateExternalThreadInviteOwnerGroupTx(tx, target.ownerID, targetGroupID, target.principalID); err != nil {
		return nil, ErrExternalThreadInviteScope
	}
	if _, err := readCommunicationLinkGrantBinding(tx, targetEndpointID, target.principalID, target.nodeID, currentTime); err != nil {
		return nil, ErrExternalThreadInviteScope
	}

	transportHubID := ""
	if source.nodeID != target.nodeID {
		transportHubID = invite.hubID
	}
	// The invited owner's grant of scope must not outlive the expiry chosen
	// when issuing the invitation. Later owner key grants may narrow it.
	linkExpiry := invite.expiresAt
	proposal := CommunicationLinkProposal{
		SourceEndpointID: invite.sourceEndpointID, SourceGroupID: invite.sourceGroupID,
		TargetEndpointID: targetEndpointID, TargetGroupID: targetGroupID,
		Direction: "forward", Actions: actions, DataScopes: dataScopes,
		TransportHubID: transportHubID, ExpiresAt: linkExpiry,
	}
	link, err := insertCommunicationLinkProposalTx(tx, proposal, source, target, currentTime)
	if err != nil {
		return nil, err
	}
	acceptedAt := currentTime.Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE external_thread_invites_v2
SET state = 'ACCEPTED', target_owner_id = ?, target_endpoint_id = ?, target_group_id = ?,
    communication_link_id = ?, accepted_at = ?
WHERE invite_id = ? AND token_digest = ? AND state = 'PENDING' AND expires_at = ?`,
		target.ownerID, targetEndpointID, targetGroupID, link.ID, acceptedAt,
		invite.id, digest, invite.expiresAt)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, ErrExternalThreadInviteUnavailable
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ExternalThreadInviteAcceptance{LinkID: link.ID, State: link.State,
		Version: link.Version, ExpiresAt: link.ExpiresAt}, nil
}
