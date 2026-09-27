package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

var (
	ErrLocalDeliveryNotAuthorized        = errors.New("local delivery is not authorized")
	ErrLocalDeliveryAmbiguousTarget      = errors.New("local delivery target is ambiguous")
	ErrLocalDeliveryNotLocal             = errors.New("resolved delivery target is on another Node")
	ErrLocalDeliveryTargetKeyUnavailable = errors.New("local delivery target key is unavailable")
)

const (
	localDeliveryAuthorizationTTL = 10 * time.Second
	localDeliveryTargetLimit      = 1000
)

type LocalDeliveryAuthorizationInput struct {
	GroupID string `json:"group_id"`
	Target  string `json:"target"`
	Action  string `json:"action"`
}

type LocalDeliveryRevalidationInput struct {
	GroupID            string `json:"group_id"`
	SourceEndpointID   string `json:"source_endpoint_id"`
	SourceBindingID    string `json:"source_binding_id"`
	SourceBindingEpoch uint64 `json:"source_binding_epoch"`
	TargetEndpointID   string `json:"target_endpoint_id"`
	Action             string `json:"action"`
}

// LocalDeliveryEndpointAuthorization is the bounded, current identity and
// binding snapshot a same-Node adapter needs to derive its EndpointMessageContext.
// It deliberately contains no message body, history, workspace, or locator.
type LocalDeliveryEndpointAuthorization struct {
	EndpointID         string `json:"endpoint_id"`
	PrincipalID        string `json:"principal_id"`
	OwnerID            string `json:"owner_id"`
	GroupID            string `json:"group_id"`
	NodeID             string `json:"node_id"`
	MembershipRevision int64  `json:"membership_revision"`
	GroupJoinRevision  int64  `json:"group_join_revision"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	NativeSessionID    string `json:"native_session_id,omitempty"`
}

type LocalDeliveryKeyCandidate struct {
	Public      e2ee.PublicIdentity `json:"public_identity"`
	KeyID       string              `json:"key_id"`
	Version     int64               `json:"version"`
	Proof       []byte              `json:"proof"`
	ProofDigest string              `json:"proof_digest"`
}

// LocalDeliveryAuthorization is a short-lived read-only snapshot. A Node
// must re-request it immediately before local queue injection; the revision
// changes when any authorization, binding, owner, or candidate changes.
type LocalDeliveryAuthorization struct {
	Action                string                             `json:"action"`
	AuthorizationRevision string                             `json:"authorization_revision"`
	AuthorizedAt          string                             `json:"authorized_at"`
	ValidUntil            string                             `json:"valid_until"`
	Source                LocalDeliveryEndpointAuthorization `json:"source"`
	SourceKey             LocalDeliveryKeyCandidate          `json:"source_key_candidate"`
	Target                LocalDeliveryEndpointAuthorization `json:"target"`
	TargetKey             LocalDeliveryKeyCandidate          `json:"target_key_candidate"`
}

type localDeliveryEndpointSnapshot struct {
	LocalDeliveryEndpointAuthorization
	Name             string
	MembershipStatus string
	MembershipExpiry string
	MembershipStart  string
	GroupState       string
	GroupRevision    int64
	PrincipalStatus  string
	PrincipalOwnerID string
	EndpointOwnerID  string
	EndpointStatus   string
	MigrationState   string
	BindingStatus    string
	BindingVersion   int64
	LeaseOwner       string
	LeaseExpiresAt   string
}

// AuthorizeLocalDeliveryForNodeCredential resolves a same-Group, same-owner,
// same-Node local route from current credentials and state in one read
// transaction. The Node credential must be bound to the owner of both
// Endpoint Principals, which fences shared-machine cross-owner delivery from
// this local-only path.
func (s *Store) AuthorizeLocalDeliveryForNodeCredential(nodeCredentialDigest, sessionCredentialDigest string,
	input LocalDeliveryAuthorizationInput) (*LocalDeliveryAuthorization, error) {
	nodeCredentialDigest = strings.TrimSpace(nodeCredentialDigest)
	sessionCredentialDigest = strings.TrimSpace(sessionCredentialDigest)
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.Target = strings.TrimSpace(input.Target)
	input.Action = strings.TrimSpace(input.Action)
	if !validNodeCredentialDigest(nodeCredentialDigest) || !validNodeCredentialDigest(sessionCredentialDigest) ||
		input.GroupID == "" || len(input.GroupID) > 256 || input.Target == "" || len(input.Target) > 256 ||
		strings.ContainsAny(input.Target, "\r\n\x00") ||
		(input.Action != "message.send" && input.Action != "message.ask" && input.Action != "message.reply") {
		return nil, ErrLocalDeliveryNotAuthorized
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	nowTime := time.Now().UTC()
	nowText := nowTime.Format(time.RFC3339Nano)
	nodeID, nodeOwnerID, nodeCredentialVersion, nodeBindingVersion, err := readCurrentBoundNodeOwnerTx(tx, nodeCredentialDigest)
	if err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}

	source, err := readLocalDeliverySourceTx(tx, sessionCredentialDigest, input.GroupID, nowText)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLocalDeliveryNotAuthorized
		}
		return nil, err
	}
	if source.NodeID != nodeID || source.PrincipalOwnerID != nodeOwnerID || source.EndpointOwnerID != nodeOwnerID {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if err := validateLocalDeliveryEndpointSnapshot(source, input.GroupID, nowTime); err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	allowed, err := localDeliveryMembershipAllows(tx, source.PrincipalID, input.GroupID, input.Action, nowText)
	if err != nil || !allowed {
		return nil, ErrLocalDeliveryNotAuthorized
	}

	targets, err := listLocalDeliveryTargetsTx(tx, input.GroupID, nowText)
	if err != nil {
		return nil, err
	}
	target, err := resolveLocalDeliveryTarget(input.Target, input.GroupID, targets)
	if err != nil {
		return nil, err
	}
	if target.EndpointID == source.EndpointID {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if err := validateLocalDeliveryEndpointSnapshot(target, input.GroupID, nowTime); err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if target.NodeID != nodeID {
		// This is returned only after one currently authorized target in the
		// selected Group has been resolved. Callers may then use their normal
		// remote path. Invisible or ambiguous targets fail closed above.
		return nil, ErrLocalDeliveryNotLocal
	}
	if target.PrincipalOwnerID != nodeOwnerID || target.EndpointOwnerID != nodeOwnerID {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if err := networkGuardRelaySecurityTx(tx, &RelayMessageSecurity{SenderPrincipalID: source.PrincipalID, SenderEndpointID: source.EndpointID, SenderGroupID: input.GroupID, ReceiverPrincipalID: target.PrincipalID, ReceiverEndpointID: target.EndpointID, ReceiverGroupID: input.GroupID}, input.GroupID, nowTime); err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}

	sourceKey, err := readCurrentLocalDeliveryKeyTx(tx, source)
	if err != nil {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	targetKey, err := readCurrentLocalDeliveryKeyTx(tx, target)
	if err != nil {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}

	result, err := buildLocalDeliveryAuthorization(input.Action, nowTime, nodeCredentialVersion,
		nodeBindingVersion, source, target, sourceKey, targetKey)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// RevalidateLocalDeliveryForNodeCredential checks an exact persisted local
// route after a Node restart, without requiring the original Session bearer.
// The Node credential and explicit source binding coordinates fence the
// route; all Endpoint and authorization facts are re-read from SQLite.
func (s *Store) RevalidateLocalDeliveryForNodeCredential(nodeCredentialDigest string,
	input LocalDeliveryRevalidationInput) (*LocalDeliveryAuthorization, error) {
	nodeCredentialDigest = strings.TrimSpace(nodeCredentialDigest)
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.SourceEndpointID = strings.TrimSpace(input.SourceEndpointID)
	input.SourceBindingID = strings.TrimSpace(input.SourceBindingID)
	input.TargetEndpointID = strings.TrimSpace(input.TargetEndpointID)
	input.Action = strings.TrimSpace(input.Action)
	if !validNodeCredentialDigest(nodeCredentialDigest) || input.GroupID == "" || len(input.GroupID) > 256 ||
		input.SourceEndpointID == "" || len(input.SourceEndpointID) > 256 || input.SourceBindingID == "" ||
		len(input.SourceBindingID) > 256 || input.SourceBindingEpoch == 0 || input.TargetEndpointID == "" ||
		len(input.TargetEndpointID) > 256 || (input.Action != "message.send" && input.Action != "message.ask" && input.Action != "message.reply") {
		return nil, ErrLocalDeliveryNotAuthorized
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	nowTime := time.Now().UTC()
	nowText := nowTime.Format(time.RFC3339Nano)
	nodeID, nodeOwnerID, nodeCredentialVersion, nodeBindingVersion, err := readCurrentBoundNodeOwnerTx(tx, nodeCredentialDigest)
	if err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	source, err := readLocalDeliveryEndpointByIDTx(tx, input.GroupID, input.SourceEndpointID, nowText)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLocalDeliveryNotAuthorized
		}
		return nil, err
	}
	target, err := readLocalDeliveryEndpointByIDTx(tx, input.GroupID, input.TargetEndpointID, nowText)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLocalDeliveryNotAuthorized
		}
		return nil, err
	}
	if source.EndpointID == target.EndpointID ||
		source.BindingID != input.SourceBindingID || source.BindingEpoch != input.SourceBindingEpoch {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if source.NodeID != nodeID || target.NodeID != nodeID ||
		source.PrincipalOwnerID != nodeOwnerID || source.EndpointOwnerID != nodeOwnerID ||
		target.PrincipalOwnerID != nodeOwnerID || target.EndpointOwnerID != nodeOwnerID {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if err := validateLocalDeliveryEndpointSnapshot(source, input.GroupID, nowTime); err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if err := validateLocalDeliveryEndpointSnapshot(target, input.GroupID, nowTime); err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	if err := networkGuardRelaySecurityTx(tx, &RelayMessageSecurity{SenderPrincipalID: source.PrincipalID, SenderEndpointID: source.EndpointID, SenderGroupID: input.GroupID, ReceiverPrincipalID: target.PrincipalID, ReceiverEndpointID: target.EndpointID, ReceiverGroupID: input.GroupID}, input.GroupID, nowTime); err != nil {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	allowed, err := localDeliveryMembershipAllows(tx, source.PrincipalID, input.GroupID, input.Action, nowText)
	if err != nil || !allowed {
		return nil, ErrLocalDeliveryNotAuthorized
	}
	sourceKey, err := readCurrentLocalDeliveryKeyTx(tx, source)
	if err != nil {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	targetKey, err := readCurrentLocalDeliveryKeyTx(tx, target)
	if err != nil {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	result, err := buildLocalDeliveryAuthorization(input.Action, nowTime, nodeCredentialVersion,
		nodeBindingVersion, source, target, sourceKey, targetKey)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func readCurrentBoundNodeOwnerTx(tx *sql.Tx, credentialDigest string) (nodeID, ownerID string,
	credentialVersion, bindingVersion int64, err error) {
	err = tx.QueryRow(`SELECT credential.node_id, binding.owner_id,
credential.version, binding.version
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
 AND binding.node_credential_digest=credential.credential_hash
 AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
 AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
 AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).
		Scan(&nodeID, &ownerID, &credentialVersion, &bindingVersion)
	return
}

func buildLocalDeliveryAuthorization(action string, nowTime time.Time, nodeCredentialVersion,
	nodeBindingVersion int64, source, target localDeliveryEndpointSnapshot,
	sourceKey, targetKey *LocalDeliveryKeyCandidate) (*LocalDeliveryAuthorization, error) {
	validUntil := nowTime.Add(localDeliveryAuthorizationTTL)
	for _, expiry := range []string{source.LeaseExpiresAt, target.LeaseExpiresAt,
		source.MembershipExpiry, target.MembershipExpiry} {
		if expiry == "" {
			continue
		}
		deadline, err := time.Parse(time.RFC3339Nano, expiry)
		if err != nil || !deadline.After(nowTime) {
			return nil, ErrLocalDeliveryNotAuthorized
		}
		if deadline.Before(validUntil) {
			validUntil = deadline
		}
	}
	// Only the target's native Session ID is needed to address queue injection.
	source.NativeSessionID = ""
	revision, err := localDeliveryAuthorizationRevision(action, nodeCredentialVersion,
		nodeBindingVersion, source, target, sourceKey, targetKey)
	if err != nil {
		return nil, err
	}
	return &LocalDeliveryAuthorization{
		Action: action, AuthorizationRevision: revision,
		AuthorizedAt: nowTime.Format(time.RFC3339Nano), ValidUntil: validUntil.UTC().Format(time.RFC3339Nano),
		Source: source.LocalDeliveryEndpointAuthorization, SourceKey: *sourceKey,
		Target: target.LocalDeliveryEndpointAuthorization, TargetKey: *targetKey,
	}, nil
}

func readLocalDeliverySourceTx(tx *sql.Tx, sessionCredentialDigest, groupID, nowText string) (localDeliveryEndpointSnapshot, error) {
	var endpoint localDeliveryEndpointSnapshot
	err := tx.QueryRow(`SELECT e.id, e.name, e.native_session_id, e.principal_id,
p.owner_id, e.owner, eg.group_id, e.machine_id, eg.revision,
sb.id, sb.epoch, sb.status, sb.lease_owner, sb.lease_expires_at,
e.status, e.migration_state, p.status, m.effective_at, m.expires_at,
g.state, g.revision, m.revision
FROM session_bindings sb
JOIN fabric_endpoints e ON e.binding_id=sb.id AND e.id=sb.endpoint_id
JOIN principals p ON p.id=sb.principal_id AND p.id=e.principal_id
JOIN memberships m ON m.principal_id=p.id AND m.group_id=?
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=m.group_id
JOIN groups g ON g.id=m.group_id
WHERE sb.credential_hash=? AND sb.status='leased' AND sb.lease_owner!=''
  AND e.migration_state='READY' AND e.status!='left'
  AND sb.node_id=e.machine_id AND sb.native_session_id=e.native_session_id
  AND eg.status='active' AND m.status='active' AND p.status='active' AND g.state='ACTIVE'
  AND (m.effective_at='' OR julianday(m.effective_at)<=julianday(?))
  AND (m.expires_at='' OR julianday(m.expires_at)>julianday(?))
LIMIT 1`, groupID, sessionCredentialDigest, nowText, nowText).Scan(
		&endpoint.EndpointID, &endpoint.Name, &endpoint.NativeSessionID, &endpoint.PrincipalID,
		&endpoint.PrincipalOwnerID, &endpoint.EndpointOwnerID, &endpoint.GroupID, &endpoint.NodeID,
		&endpoint.GroupJoinRevision, &endpoint.BindingID, &endpoint.BindingEpoch,
		&endpoint.BindingStatus, &endpoint.LeaseOwner, &endpoint.LeaseExpiresAt, &endpoint.EndpointStatus,
		&endpoint.MigrationState, &endpoint.PrincipalStatus, &endpoint.MembershipStart,
		&endpoint.MembershipExpiry, &endpoint.GroupState, &endpoint.GroupRevision,
		&endpoint.MembershipRevision)
	if err != nil {
		return endpoint, err
	}
	endpoint.OwnerID = endpoint.PrincipalOwnerID
	endpoint.MembershipStatus = MembershipStatusActive
	endpoint.MembershipStart = strings.TrimSpace(endpoint.MembershipStart)
	endpoint.MembershipExpiry = strings.TrimSpace(endpoint.MembershipExpiry)
	return endpoint, nil
}

func localDeliveryMembershipAllows(tx *sql.Tx, principalID, groupID, action, nowText string) (bool, error) {
	var grantsJSON, authorizationJSON, status, effectiveAt, expiresAt string
	err := tx.QueryRow(`SELECT grants_json, authorization_json, status, effective_at, expires_at
FROM memberships WHERE principal_id=? AND group_id=?`, principalID, groupID).
		Scan(&grantsJSON, &authorizationJSON, &status, &effectiveAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || status != MembershipStatusActive {
		return false, err
	}
	nowTime, parseErr := time.Parse(time.RFC3339Nano, nowText)
	if parseErr != nil {
		return false, parseErr
	}
	if effectiveAt != "" {
		effectiveTime, err := time.Parse(time.RFC3339Nano, effectiveAt)
		if err != nil || effectiveTime.After(nowTime) {
			return false, nil
		}
	}
	if expiresAt != "" {
		expiresTime, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil || !expiresTime.After(nowTime) {
			return false, nil
		}
	}
	var grants []string
	var authorization map[string]any
	if json.Unmarshal([]byte(grantsJSON), &grants) != nil || json.Unmarshal([]byte(authorizationJSON), &authorization) != nil {
		return false, errors.New("invalid membership authorization record")
	}
	for _, grant := range grants {
		if grant == action {
			return true, nil
		}
	}
	return authorization[action] == true, nil
}

const localDeliveryTargetSelect = `SELECT e.id, e.name, e.native_session_id, e.principal_id, p.owner_id, e.owner, eg.group_id,
	e.machine_id, eg.revision, sb.id, sb.epoch, sb.status,
sb.lease_owner, sb.lease_expires_at, e.status, e.migration_state,
p.status, m.effective_at, m.expires_at, g.state, g.revision, m.revision
FROM fabric_endpoints e
JOIN principals p ON p.id=e.principal_id
JOIN memberships m ON m.principal_id=p.id AND m.group_id=?
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=m.group_id
JOIN groups g ON g.id=m.group_id
JOIN session_bindings sb ON sb.id=e.binding_id AND sb.endpoint_id=e.id
WHERE e.migration_state='READY' AND e.status!='left'
  AND eg.status='active' AND m.status='active' AND p.status='active' AND g.state='ACTIVE'
  AND (m.effective_at='' OR julianday(m.effective_at)<=julianday(?))
  AND (m.expires_at='' OR julianday(m.expires_at)>julianday(?))
  AND sb.status='leased' AND sb.lease_owner!='' AND julianday(sb.lease_expires_at)>julianday(?)
  AND sb.node_id=e.machine_id AND sb.native_session_id=e.native_session_id`

// Exact delivery revalidation must remain O(1) in Group size. The bounded
// enumeration below is only for human-readable alias disambiguation.
func readLocalDeliveryEndpointByIDTx(tx *sql.Tx, groupID, endpointID, nowText string) (localDeliveryEndpointSnapshot, error) {
	return scanLocalDeliveryEndpoint(tx.QueryRow(localDeliveryTargetSelect+`
  AND e.id=? LIMIT 1`, groupID, nowText, nowText, nowText, endpointID))
}

func listLocalDeliveryTargetsTx(tx *sql.Tx, groupID, nowText string) ([]localDeliveryEndpointSnapshot, error) {
	rows, err := tx.Query(localDeliveryTargetSelect+`
ORDER BY e.id LIMIT ?`, groupID, nowText, nowText, nowText, localDeliveryTargetLimit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]localDeliveryEndpointSnapshot, 0)
	for rows.Next() {
		if len(result) == localDeliveryTargetLimit {
			return nil, ErrLocalDeliveryAmbiguousTarget
		}
		endpoint, err := scanLocalDeliveryEndpoint(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, endpoint)
	}
	return result, rows.Err()
}

func scanLocalDeliveryEndpoint(row interface{ Scan(...any) error }) (localDeliveryEndpointSnapshot, error) {
	var endpoint localDeliveryEndpointSnapshot
	err := row.Scan(&endpoint.EndpointID, &endpoint.Name, &endpoint.NativeSessionID, &endpoint.PrincipalID,
		&endpoint.PrincipalOwnerID, &endpoint.EndpointOwnerID, &endpoint.GroupID,
		&endpoint.NodeID, &endpoint.GroupJoinRevision, &endpoint.BindingID,
		&endpoint.BindingEpoch, &endpoint.BindingStatus,
		&endpoint.LeaseOwner, &endpoint.LeaseExpiresAt, &endpoint.EndpointStatus,
		&endpoint.MigrationState, &endpoint.PrincipalStatus, &endpoint.MembershipStart,
		&endpoint.MembershipExpiry, &endpoint.GroupState, &endpoint.GroupRevision,
		&endpoint.MembershipRevision)
	if err != nil {
		return localDeliveryEndpointSnapshot{}, err
	}
	endpoint.OwnerID = endpoint.PrincipalOwnerID
	return endpoint, nil
}

func resolveLocalDeliveryTarget(query, groupID string, endpoints []localDeliveryEndpointSnapshot) (localDeliveryEndpointSnapshot, error) {
	query = strings.TrimSpace(query)
	for _, endpoint := range endpoints {
		if endpoint.EndpointID == query {
			return endpoint, nil
		}
	}
	lower := strings.ToLower(query)
	var exact, aliases []localDeliveryEndpointSnapshot
	for _, endpoint := range endpoints {
		address := strings.ToLower(groupID + "/" + endpoint.Name + "@" + endpoint.NodeID)
		nameAtNode := strings.ToLower(endpoint.Name + "@" + endpoint.NodeID)
		groupName := strings.ToLower(groupID + "/" + endpoint.Name)
		switch {
		case strings.EqualFold(address, query), strings.EqualFold(nameAtNode, query), strings.EqualFold(groupName, query):
			exact = append(exact, endpoint)
		case strings.ToLower(endpoint.Name) == lower:
			aliases = append(aliases, endpoint)
		}
	}
	candidates := exact
	if len(candidates) == 0 {
		candidates = aliases
	}
	if len(candidates) == 0 {
		return localDeliveryEndpointSnapshot{}, ErrLocalDeliveryNotAuthorized
	}
	if len(candidates) != 1 {
		return localDeliveryEndpointSnapshot{}, ErrLocalDeliveryAmbiguousTarget
	}
	return candidates[0], nil
}

func validateLocalDeliveryEndpointSnapshot(endpoint localDeliveryEndpointSnapshot, groupID string, nowTime time.Time) error {
	if endpoint.EndpointID == "" || endpoint.PrincipalID == "" || endpoint.OwnerID == "" || endpoint.PrincipalOwnerID == "" ||
		endpoint.PrincipalOwnerID != endpoint.EndpointOwnerID || endpoint.GroupID != groupID || endpoint.NodeID == "" ||
		endpoint.GroupJoinRevision <= 0 || endpoint.MembershipRevision <= 0 || endpoint.BindingID == "" ||
		endpoint.BindingEpoch == 0 || endpoint.BindingStatus != SessionBindingStatusLeased ||
		endpoint.LeaseOwner == "" || endpoint.NativeSessionID == "" || endpoint.EndpointStatus == "left" || endpoint.MigrationState != EndpointMigrationReady ||
		endpoint.PrincipalStatus != PrincipalStatusActive || endpoint.GroupState != GroupStateActive {
		return ErrLocalDeliveryNotAuthorized
	}
	if endpoint.MembershipStart != "" {
		startTime, err := time.Parse(time.RFC3339Nano, endpoint.MembershipStart)
		if err != nil || startTime.After(nowTime) {
			return ErrLocalDeliveryNotAuthorized
		}
	}
	if endpoint.MembershipExpiry != "" {
		expires, err := time.Parse(time.RFC3339Nano, endpoint.MembershipExpiry)
		if err != nil || !expires.After(nowTime) {
			return ErrLocalDeliveryNotAuthorized
		}
	}
	leaseDeadline, err := time.Parse(time.RFC3339Nano, endpoint.LeaseExpiresAt)
	if err != nil || !leaseDeadline.After(nowTime) {
		return ErrLocalDeliveryNotAuthorized
	}
	return nil
}

func readCurrentLocalDeliveryKeyTx(tx *sql.Tx, endpoint localDeliveryEndpointSnapshot) (*LocalDeliveryKeyCandidate, error) {
	candidate, err := scanEndpointKeyCandidate(tx.QueryRow(`SELECT `+endpointKeyCandidateColumns+`
FROM endpoint_key_candidates_v2 WHERE endpoint_id=? AND state=?`,
		endpoint.EndpointID, EndpointKeyCandidateStateCandidate))
	if err != nil {
		return nil, err
	}
	if candidate.EndpointID != endpoint.EndpointID || candidate.PrincipalID != endpoint.PrincipalID ||
		candidate.OwnerID != endpoint.PrincipalOwnerID || candidate.NodeID != endpoint.NodeID ||
		candidate.BindingID != endpoint.BindingID || candidate.BindingEpoch != endpoint.BindingEpoch || candidate.Version <= 0 {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	proofDigest := sha256.Sum256(candidate.Proof)
	if candidate.ProofDigest != hex.EncodeToString(proofDigest[:]) {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(candidate.Proof,
		endpoint.EndpointID, endpoint.PrincipalID, endpoint.NodeID, endpoint.BindingID, endpoint.BindingEpoch)
	if err != nil || verified.ID != candidate.KeyID || verified.ID != candidate.Public.ID {
		return nil, ErrLocalDeliveryTargetKeyUnavailable
	}
	return &LocalDeliveryKeyCandidate{
		Public: candidate.Public, KeyID: candidate.KeyID, Version: candidate.Version,
		Proof: append([]byte(nil), candidate.Proof...), ProofDigest: candidate.ProofDigest,
	}, nil
}

func localDeliveryAuthorizationRevision(action string, nodeCredentialVersion, nodeBindingVersion int64,
	source, target localDeliveryEndpointSnapshot, sourceKey, targetKey *LocalDeliveryKeyCandidate) (string, error) {
	material := struct {
		Action, NodeID                                        string
		NodeCredentialVersion, NodeBindingVersion             int64
		SourceEndpoint, SourcePrincipal, SourceOwner, GroupID string
		SourceJoinRevision, SourceMembershipRevision          int64
		SourceBindingID                                       string
		SourceBindingEpoch                                    uint64
		SourceKeyVersion                                      int64
		SourceKeyID, SourceProofDigest                        string
		TargetEndpoint, TargetPrincipal, TargetOwner          string
		TargetJoinRevision, TargetMembershipRevision          int64
		TargetBindingID                                       string
		TargetBindingEpoch                                    uint64
		TargetKeyVersion                                      int64
		TargetKeyID, TargetProofDigest                        string
		GroupRevision                                         int64
	}{
		Action: action, NodeID: source.NodeID, NodeCredentialVersion: nodeCredentialVersion,
		NodeBindingVersion: nodeBindingVersion, SourceEndpoint: source.EndpointID,
		SourcePrincipal: source.PrincipalID, SourceOwner: source.PrincipalOwnerID,
		GroupID: source.GroupID, SourceJoinRevision: source.GroupJoinRevision,
		SourceMembershipRevision: source.MembershipRevision, SourceBindingID: source.BindingID,
		SourceBindingEpoch: source.BindingEpoch,
		SourceKeyVersion:   sourceKey.Version, SourceKeyID: sourceKey.KeyID,
		SourceProofDigest: sourceKey.ProofDigest, TargetEndpoint: target.EndpointID,
		TargetPrincipal: target.PrincipalID, TargetOwner: target.PrincipalOwnerID,
		TargetJoinRevision: target.GroupJoinRevision, TargetMembershipRevision: target.MembershipRevision,
		TargetBindingID: target.BindingID, TargetBindingEpoch: target.BindingEpoch,
		TargetKeyVersion: targetKey.Version,
		TargetKeyID:      targetKey.KeyID, TargetProofDigest: targetKey.ProofDigest,
		GroupRevision: source.GroupRevision,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode local authorization revision: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "local-v1:" + hex.EncodeToString(digest[:]), nil
}
