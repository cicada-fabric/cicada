package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	CrossOwnerMemberAdmitOperation  = "space.foreign_member_admit"
	CrossOwnerEndpointJoinOperation = "space.foreign_endpoint_join"
	CrossOwnerMemberRevokeOperation = "space.foreign_member_revoke"
	crossOwnerAdmissionQuota        = 1024
)

var (
	ErrCrossOwnerGroupDenied   = errors.New("cross-Owner Group access denied")
	ErrCrossOwnerGroupConflict = errors.New("cross-Owner Group version or idempotency conflict")
)

// CrossOwnerGroupAdmission is an explicit Group Owner permission for one
// already enrolled foreign Endpoint. It creates only a restricted Principal
// Membership; the Endpoint cannot join until its own Owner separately consents.
type CrossOwnerGroupAdmission struct {
	ID                 string   `json:"admission_id"`
	HubID              string   `json:"hub_id"`
	NetworkID          string   `json:"network_id"`
	GroupID            string   `json:"group_id"`
	GroupRevision      int64    `json:"group_revision"`
	EndpointID         string   `json:"endpoint_id"`
	PrincipalID        string   `json:"principal_id"`
	EndpointOwnerID    string   `json:"endpoint_owner_id"`
	GroupOwnerID       string   `json:"group_owner_id"`
	MembershipID       string   `json:"membership_id"`
	MembershipRevision int64    `json:"membership_revision"`
	Grants             []string `json:"grants"`
	ExpiresAt          string   `json:"expires_at"`
	State              string   `json:"state"`
}

// CrossOwnerGroupJoinConsent is a second, independent Owner decision. The
// prior binding epoch is pinned before trusted Node Join rotates its session
// credential; consent cannot create a native Endpoint or change its Owner.
type CrossOwnerGroupJoinConsent struct {
	ID                            string `json:"join_consent_id"`
	AdmissionID                   string `json:"admission_id"`
	GroupID                       string `json:"group_id"`
	EndpointID                    string `json:"endpoint_id"`
	EndpointOwnerID               string `json:"endpoint_owner_id"`
	NodeID                        string `json:"node_id"`
	BindingID                     string `json:"binding_id"`
	ExpectedBindingEpoch          uint64 `json:"expected_binding_epoch"`
	AppliedBindingEpoch           uint64 `json:"applied_binding_epoch,omitempty"`
	AppliedJoinRevision           int64  `json:"applied_join_revision,omitempty"`
	SharedContextRiskAcknowledged bool   `json:"shared_context_risk_acknowledged"`
	ExpiresAt                     string `json:"expires_at"`
	State                         string `json:"state"`
}

func (s *Store) initializeCrossOwnerGroupSpaceSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS cross_owner_group_admissions_v2 (
 id TEXT PRIMARY KEY, client_request_id TEXT NOT NULL UNIQUE,
 hub_id TEXT NOT NULL, network_id TEXT NOT NULL, group_id TEXT NOT NULL,
 group_revision INTEGER NOT NULL CHECK(group_revision>0), endpoint_id TEXT NOT NULL,
 principal_id TEXT NOT NULL, endpoint_owner_id TEXT NOT NULL, group_owner_id TEXT NOT NULL,
 membership_id TEXT NOT NULL, membership_revision INTEGER NOT NULL CHECK(membership_revision>0),
 grants_json TEXT NOT NULL, expires_at TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')),
 revoked_request_id TEXT NOT NULL DEFAULT '', revoked_at TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(group_id) REFERENCES groups(id), FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE INDEX IF NOT EXISTS cross_owner_group_admissions_scope_idx
 ON cross_owner_group_admissions_v2(group_id,endpoint_id,state);
CREATE TABLE IF NOT EXISTS cross_owner_group_joins_v2 (
 id TEXT PRIMARY KEY, client_request_id TEXT NOT NULL UNIQUE,
 admission_id TEXT NOT NULL UNIQUE, endpoint_owner_id TEXT NOT NULL,
 node_id TEXT NOT NULL, binding_id TEXT NOT NULL, expected_binding_epoch INTEGER NOT NULL CHECK(expected_binding_epoch>0),
 applied_binding_epoch INTEGER NOT NULL DEFAULT 0, applied_join_revision INTEGER NOT NULL DEFAULT 0,
 shared_context_risk_acknowledged INTEGER NOT NULL CHECK(shared_context_risk_acknowledged=1),
 expires_at TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(admission_id) REFERENCES cross_owner_group_admissions_v2(id)
);
CREATE INDEX IF NOT EXISTS cross_owner_group_joins_admission_idx
 ON cross_owner_group_joins_v2(admission_id,state);
CREATE TABLE IF NOT EXISTS cross_owner_group_key_proofs_v2 (
 id TEXT PRIMARY KEY, client_request_id TEXT NOT NULL UNIQUE,
 group_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
 signer_owner_id TEXT NOT NULL, signer_side TEXT NOT NULL CHECK(signer_side IN ('ENDPOINT','GROUP')),
 owner_key_id TEXT NOT NULL, manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64),
 manifest_json TEXT NOT NULL, proof BLOB NOT NULL CHECK(length(proof)>0),
 proof_nonce TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')),
 accepted_at TEXT NOT NULL,
 UNIQUE(signer_owner_id,owner_key_id,proof_nonce),
 FOREIGN KEY(group_id) REFERENCES groups(id), FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE INDEX IF NOT EXISTS cross_owner_group_key_proofs_scope_idx
 ON cross_owner_group_key_proofs_v2(group_id,endpoint_id,signer_side,accepted_at DESC);`)
	return err
}

func crossOwnerClientRequestTx(tx *sql.Tx, requestID, ownerID, operation string) (trustedClientRequest, error) {
	actor, err := trustedClientRequestTx(tx, requestID)
	if err != nil || actor.OwnerID != ownerID {
		return actor, ErrCrossOwnerGroupDenied
	}
	var route string
	if tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`, requestID).Scan(&route) != nil || route != operation {
		return actor, ErrCrossOwnerGroupDenied
	}
	return actor, nil
}

func normalizeCrossOwnerGrants(grants []string) ([]string, error) {
	if len(grants) == 0 || len(grants) > 3 {
		return nil, ErrCrossOwnerGroupDenied
	}
	seen := make(map[string]bool, len(grants))
	for _, grant := range grants {
		if grant != "space.read" && grant != "space.write" && grant != "space.moderate" || seen[grant] {
			return nil, ErrCrossOwnerGroupDenied
		}
		seen[grant] = true
	}
	// A writer or moderator must also be a reader to consume the producer's
	// exact reader snapshot. Reject unusable authorizations at issue time.
	if !seen["space.read"] {
		return nil, ErrCrossOwnerGroupDenied
	}
	result := make([]string, 0, 3)
	for _, grant := range []string{"space.read", "space.write", "space.moderate"} {
		if seen[grant] {
			result = append(result, grant)
		}
	}
	return result, nil
}

func scanCrossOwnerAdmission(row v2Scanner) (*CrossOwnerGroupAdmission, error) {
	var a CrossOwnerGroupAdmission
	var grants string
	if err := row.Scan(&a.ID, &a.HubID, &a.NetworkID, &a.GroupID, &a.GroupRevision,
		&a.EndpointID, &a.PrincipalID, &a.EndpointOwnerID, &a.GroupOwnerID,
		&a.MembershipID, &a.MembershipRevision, &grants, &a.ExpiresAt, &a.State); err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(grants), &a.Grants) != nil {
		return nil, ErrCrossOwnerGroupConflict
	}
	return &a, nil
}

const crossOwnerAdmissionColumns = `id,hub_id,network_id,group_id,group_revision,endpoint_id,
principal_id,endpoint_owner_id,group_owner_id,membership_id,membership_revision,grants_json,expires_at,state`

func (s *Store) AdmitCrossOwnerGroupMemberForClientRequest(requestID, ownerID, groupID, endpointID string,
	grants []string, expiresAt string, expectedGroupRevision, expectedMembershipRevision int64) (*CrossOwnerGroupAdmission, error) {
	grants, err := normalizeCrossOwnerGrants(grants)
	if err != nil || expectedGroupRevision <= 0 || expectedMembershipRevision < 0 {
		return nil, ErrCrossOwnerGroupDenied
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	at := time.Now().UTC()
	if err != nil || !expiry.After(at) || expiry.After(at.Add(30*24*time.Hour)) {
		return nil, ErrCrossOwnerGroupDenied
	}
	groupID, endpointID = strings.TrimSpace(groupID), strings.TrimSpace(endpointID)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, CrossOwnerMemberAdmitOperation)
	if err != nil {
		return nil, err
	}
	if prior, err := scanCrossOwnerAdmission(tx.QueryRow(`SELECT `+crossOwnerAdmissionColumns+` FROM cross_owner_group_admissions_v2 WHERE client_request_id=?`, requestID)); err == nil {
		want, _ := json.Marshal(grants)
		have, _ := json.Marshal(prior.Grants)
		if prior.GroupID != groupID || prior.EndpointID != endpointID || prior.ExpiresAt != expiresAt || prior.GroupRevision != expectedGroupRevision ||
			prior.MembershipRevision != expectedMembershipRevision+1 || string(want) != string(have) || prior.GroupOwnerID != ownerID {
			return nil, ErrCrossOwnerGroupConflict
		}
		return prior, tx.Commit()
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	var a CrossOwnerGroupAdmission
	var groupState, contextPolicy, networkState, endpointState, principalState, networkMemberState, enrollmentState, networkExpiry string
	err = tx.QueryRow(`SELECT g.network_id,g.revision,g.state,n.state,e.principal_id,e.owner,e.status,p.status,
 nm.status,nm.expires_at,en.status,g.context_policy
FROM groups g JOIN principals gp ON gp.id=g.owner_principal_id AND gp.owner_id=? AND gp.status='active'
JOIN networks_v2 n ON n.id=g.network_id AND n.hub_id=?
JOIN fabric_endpoints e ON e.id=? AND e.migration_state='READY'
JOIN principals p ON p.id=e.principal_id AND p.owner_id=e.owner AND p.status='active'
JOIN network_memberships_v2 nm ON nm.network_id=n.id AND nm.principal_id=p.id
JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=e.id
WHERE g.id=?`, ownerID, actor.HubID, endpointID, groupID).Scan(
		&a.NetworkID, &a.GroupRevision, &groupState, &networkState, &a.PrincipalID,
		&a.EndpointOwnerID, &endpointState, &principalState, &networkMemberState, &networkExpiry, &enrollmentState, &contextPolicy)
	if err != nil || groupState != GroupStateActive || contextPolicy != "group_scoped" || networkState != NetworkStateActive || endpointState == "left" ||
		principalState != PrincipalStatusActive || networkMemberState != "active" || enrollmentState != "active" ||
		!networkExpiryAllows(networkExpiry, at) || a.EndpointOwnerID == "" || a.EndpointOwnerID == ownerID {
		return nil, ErrCrossOwnerGroupDenied
	}
	if a.GroupRevision != expectedGroupRevision {
		return nil, ErrCrossOwnerGroupConflict
	}
	var existing int
	if tx.QueryRow(`SELECT COUNT(*) FROM cross_owner_group_admissions_v2`).Scan(&existing) != nil || existing >= crossOwnerAdmissionQuota {
		return nil, ErrGroupSpaceLimit
	}
	a.ID, a.HubID, a.GroupID, a.EndpointID, a.GroupOwnerID, a.ExpiresAt, a.State =
		NewID("coadm"), actor.HubID, groupID, endpointID, ownerID, expiresAt, "ACTIVE"
	a.Grants = grants
	grantJSON, _ := json.Marshal(grants)
	stamp := at.Format(time.RFC3339Nano)
	var memberID, memberState string
	var memberRevision, memberVersion int64
	err = tx.QueryRow(`SELECT id,status,revision,version FROM memberships WHERE principal_id=? AND group_id=?`, a.PrincipalID, groupID).Scan(&memberID, &memberState, &memberRevision, &memberVersion)
	if err == sql.ErrNoRows {
		if expectedMembershipRevision != 0 {
			return nil, ErrCrossOwnerGroupConflict
		}
		a.MembershipID, a.MembershipRevision = NewID("mship"), 1
		_, err = tx.Exec(`INSERT INTO memberships
(id,principal_id,group_id,role,roles_json,grants_json,authorization_json,status,effective_at,expires_at,
revoked_at,revocation_reason,revision,version,created_at,updated_at)
VALUES(?,?,?,'member','["member"]',?,'{}','active',?,?,'','',1,1,?,?)`,
			a.MembershipID, a.PrincipalID, groupID, string(grantJSON), stamp, expiresAt, stamp, stamp)
	} else if err == nil && memberState == MembershipStatusRevoked && memberRevision == expectedMembershipRevision {
		a.MembershipID, a.MembershipRevision = memberID, memberRevision+1
		_, err = tx.Exec(`UPDATE memberships SET role='member',roles_json='["member"]',grants_json=?,authorization_json='{}',
status='active',effective_at=?,expires_at=?,revoked_at='',revocation_reason='',revision=revision+1,
version=version+1,updated_at=? WHERE id=? AND status='revoked' AND revision=? AND version=?`,
			string(grantJSON), stamp, expiresAt, stamp, memberID, memberRevision, memberVersion)
		if err == nil {
			_, err = tx.Exec(`UPDATE cross_owner_group_admissions_v2 SET state='REVOKED',updated_at=? WHERE group_id=? AND endpoint_id=? AND state='ACTIVE'`, stamp, groupID, endpointID)
		}
		if err == nil {
			_, err = tx.Exec(`UPDATE cross_owner_group_joins_v2 SET state='REVOKED',updated_at=? WHERE admission_id IN
(SELECT id FROM cross_owner_group_admissions_v2 WHERE group_id=? AND endpoint_id=? AND state='REVOKED') AND state='ACTIVE'`, stamp, groupID, endpointID)
		}
		if err == nil {
			_, err = tx.Exec(`UPDATE cross_owner_group_key_proofs_v2 SET state='REVOKED' WHERE group_id=? AND endpoint_id=? AND state='ACTIVE'`, groupID, endpointID)
		}
	} else {
		return nil, ErrCrossOwnerGroupConflict
	}
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO cross_owner_group_admissions_v2
(id,client_request_id,hub_id,network_id,group_id,group_revision,endpoint_id,principal_id,
endpoint_owner_id,group_owner_id,membership_id,membership_revision,grants_json,expires_at,state,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',?,?)`, a.ID, requestID, a.HubID, a.NetworkID,
		groupID, a.GroupRevision, endpointID, a.PrincipalID, a.EndpointOwnerID, ownerID,
		a.MembershipID, a.MembershipRevision, string(grantJSON), expiresAt, stamp, stamp)
	if err != nil {
		return nil, err
	}
	return &a, tx.Commit()
}

// RevokeCrossOwnerGroupAdmissionForClientRequest is the Group Owner's exact
// removal of one admitted foreign reader. It fences the Member, Endpoint Join,
// pending consent and both key proofs in one transaction. An exact lost-response
// retry returns the original revoked admission without granting any access.
func (s *Store) RevokeCrossOwnerGroupAdmissionForClientRequest(requestID, ownerID, admissionID string,
	expectedMembershipRevision int64) (*CrossOwnerGroupAdmission, error) {
	if admissionID == "" || expectedMembershipRevision <= 0 {
		return nil, ErrCrossOwnerGroupDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, CrossOwnerMemberRevokeOperation)
	if err != nil {
		return nil, err
	}
	a, err := scanCrossOwnerAdmission(tx.QueryRow(`SELECT `+crossOwnerAdmissionColumns+` FROM cross_owner_group_admissions_v2 WHERE id=?`, admissionID))
	if err != nil || a.GroupOwnerID != ownerID || a.HubID != actor.HubID || a.MembershipRevision != expectedMembershipRevision {
		return nil, ErrCrossOwnerGroupDenied
	}
	var priorRequest string
	if tx.QueryRow(`SELECT revoked_request_id FROM cross_owner_group_admissions_v2 WHERE id=?`, admissionID).Scan(&priorRequest) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	if a.State == "REVOKED" {
		if priorRequest != requestID {
			return nil, ErrCrossOwnerGroupConflict
		}
		return a, tx.Commit()
	}
	if crossOwnerAdmissionCurrentTx(tx, a, time.Now().UTC()) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	stamp := now()
	result, err := tx.Exec(`UPDATE memberships SET status='revoked',revoked_at=?,revocation_reason='cross-owner Group Owner revoke',
revision=revision+1,version=version+1,updated_at=? WHERE id=? AND status='active' AND revision=?`,
		stamp, stamp, a.MembershipID, expectedMembershipRevision)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrCrossOwnerGroupConflict
	}
	if _, err := tx.Exec(`UPDATE endpoint_group_memberships SET status='revoked',revision=revision+1,updated_at=?
WHERE endpoint_id=? AND group_id=? AND status='active'`, stamp, a.EndpointID, a.GroupID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE cross_owner_group_joins_v2 SET state='REVOKED',updated_at=? WHERE admission_id=? AND state='ACTIVE'`, stamp, a.ID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE cross_owner_group_key_proofs_v2 SET state='REVOKED' WHERE group_id=? AND endpoint_id=? AND state='ACTIVE'`, a.GroupID, a.EndpointID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE cross_owner_group_admissions_v2 SET state='REVOKED',revoked_request_id=?,revoked_at=?,updated_at=?
WHERE id=? AND state='ACTIVE'`, requestID, stamp, stamp, a.ID); err != nil {
		return nil, err
	}
	// A foreign Join begins with an already bound Endpoint in its own Group.
	// If that Group was independently revoked meanwhile, fence its native lease
	// rather than leaving a writer with no active Group at all.
	if _, err := tx.Exec(`UPDATE session_bindings SET status=?,lease_owner='',lease_expires_at='',epoch=epoch+1,
version=version+1,revocation_reason='last Group membership revoked',updated_at=?
WHERE endpoint_id=? AND status IN ('active','leased','online','ready','acquired')
AND NOT EXISTS (SELECT 1 FROM endpoint_group_memberships eg
 JOIN memberships m ON m.principal_id=session_bindings.principal_id AND m.group_id=eg.group_id
 JOIN groups g ON g.id=eg.group_id WHERE eg.endpoint_id=session_bindings.endpoint_id
 AND eg.status='active' AND m.status='active' AND g.state='ACTIVE')`,
		SessionBindingStatusRevoked, stamp, a.EndpointID); err != nil {
		return nil, err
	}
	a.State = "REVOKED"
	return a, tx.Commit()
}

func (s *Store) ConsentCrossOwnerGroupJoinForClientRequest(requestID, ownerID, admissionID,
	bindingID string, bindingEpoch uint64, sharedContextRiskAcknowledged bool) (*CrossOwnerGroupJoinConsent, error) {
	if bindingEpoch == 0 || admissionID == "" || bindingID == "" || !sharedContextRiskAcknowledged {
		return nil, ErrCrossOwnerGroupDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, CrossOwnerEndpointJoinOperation)
	if err != nil {
		return nil, err
	}
	a, err := scanCrossOwnerAdmission(tx.QueryRow(`SELECT `+crossOwnerAdmissionColumns+` FROM cross_owner_group_admissions_v2 WHERE id=?`, admissionID))
	if err != nil || a.EndpointOwnerID != ownerID || a.HubID != actor.HubID || crossOwnerAdmissionCurrentTx(tx, a, time.Now().UTC()) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	var prior CrossOwnerGroupJoinConsent
	if err := tx.QueryRow(`SELECT id,admission_id,endpoint_owner_id,node_id,binding_id,expected_binding_epoch,
applied_binding_epoch,applied_join_revision,shared_context_risk_acknowledged,expires_at,state
FROM cross_owner_group_joins_v2 WHERE client_request_id=?`, requestID).Scan(&prior.ID, &prior.AdmissionID,
		&prior.EndpointOwnerID, &prior.NodeID, &prior.BindingID, &prior.ExpectedBindingEpoch,
		&prior.AppliedBindingEpoch, &prior.AppliedJoinRevision, &prior.SharedContextRiskAcknowledged, &prior.ExpiresAt, &prior.State); err == nil {
		if prior.AdmissionID != admissionID || prior.BindingID != bindingID || prior.ExpectedBindingEpoch != bindingEpoch || prior.EndpointOwnerID != ownerID {
			return nil, ErrCrossOwnerGroupConflict
		}
		prior.GroupID, prior.EndpointID = a.GroupID, a.EndpointID
		return &prior, tx.Commit()
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	var nodeID, currentBinding, nativeID, status string
	var currentEpoch uint64
	if tx.QueryRow(`SELECT e.machine_id,e.binding_id,e.native_session_id,b.status,b.epoch
FROM fabric_endpoints e JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id
WHERE e.id=? AND e.principal_id=? AND e.owner=? AND e.status!='left' AND e.migration_state='READY'`,
		a.EndpointID, a.PrincipalID, ownerID).Scan(&nodeID, &currentBinding, &nativeID, &status, &currentEpoch) != nil ||
		currentBinding != bindingID || currentEpoch != bindingEpoch || !isActiveBindingStatus(status) || nativeID == "" ||
		requireCurrentOwnerBoundGroupNodeTx(tx, nodeID, ownerID, actor.HubID) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	var count int
	if tx.QueryRow(`SELECT COUNT(*) FROM cross_owner_group_joins_v2`).Scan(&count) != nil || count >= crossOwnerAdmissionQuota {
		return nil, ErrGroupSpaceLimit
	}
	consent := &CrossOwnerGroupJoinConsent{ID: NewID("cojoin"), AdmissionID: admissionID, GroupID: a.GroupID,
		EndpointID: a.EndpointID, EndpointOwnerID: ownerID, NodeID: nodeID, BindingID: bindingID,
		ExpectedBindingEpoch: bindingEpoch, SharedContextRiskAcknowledged: true, ExpiresAt: a.ExpiresAt, State: "ACTIVE"}
	stamp := now()
	_, err = tx.Exec(`INSERT INTO cross_owner_group_joins_v2
(id,client_request_id,admission_id,endpoint_owner_id,node_id,binding_id,expected_binding_epoch,
shared_context_risk_acknowledged,expires_at,state,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,1,?,'ACTIVE',?,?)`, consent.ID, requestID, admissionID, ownerID, nodeID, bindingID, bindingEpoch, a.ExpiresAt, stamp, stamp)
	if err != nil {
		return nil, err
	}
	return consent, tx.Commit()
}

func crossOwnerAdmissionCurrentTx(tx *sql.Tx, a *CrossOwnerGroupAdmission, at time.Time) error {
	if a == nil || a.State != "ACTIVE" || !networkExpiryAllows(a.ExpiresAt, at) {
		return ErrCrossOwnerGroupDenied
	}
	var groupRevision, memberRevision int64
	var groupState, contextPolicy, networkState, memberState, memberExpiry, endpointState, enrollmentState, networkMemberState, networkMemberExpiry string
	var memberID, endpointOwner, principalID string
	err := tx.QueryRow(`SELECT g.revision,g.state,n.state,m.id,m.revision,m.status,m.expires_at,
 e.owner,e.principal_id,e.status,en.status,nm.status,nm.expires_at,g.context_policy
FROM groups g JOIN networks_v2 n ON n.id=g.network_id AND n.hub_id=? AND n.id=?
JOIN memberships m ON m.group_id=g.id AND m.principal_id=?
JOIN fabric_endpoints e ON e.id=? AND e.principal_id=m.principal_id AND e.migration_state='READY'
JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=e.id
JOIN network_memberships_v2 nm ON nm.network_id=n.id AND nm.principal_id=m.principal_id
WHERE g.id=?`, a.HubID, a.NetworkID, a.PrincipalID, a.EndpointID, a.GroupID).Scan(
		&groupRevision, &groupState, &networkState, &memberID, &memberRevision, &memberState, &memberExpiry,
		&endpointOwner, &principalID, &endpointState, &enrollmentState, &networkMemberState, &networkMemberExpiry, &contextPolicy)
	if err != nil || groupRevision != a.GroupRevision || groupState != GroupStateActive || contextPolicy != "group_scoped" || networkState != NetworkStateActive ||
		memberID != a.MembershipID || memberRevision != a.MembershipRevision || memberState != MembershipStatusActive ||
		!networkExpiryAllows(memberExpiry, at) || endpointOwner != a.EndpointOwnerID || principalID != a.PrincipalID ||
		endpointState == "left" || enrollmentState != "active" || networkMemberState != "active" || !networkExpiryAllows(networkMemberExpiry, at) {
		return ErrCrossOwnerGroupDenied
	}
	return nil
}

// CheckCrossOwnerGroupJoin verifies both encrypted Owner decisions before a
// trusted Node rotates its existing native session credential.
func (s *Store) CheckCrossOwnerGroupJoin(ownerID, endpointID, groupID, nodeID, bindingID string, bindingEpoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return crossOwnerGroupJoinTx(tx, ownerID, endpointID, groupID, nodeID, bindingID, bindingEpoch, false)
}

// RotateAndJoinEndpointGroupCrossOwner commits the credential rotation and
// Endpoint Join together. A revoked admission cannot strand the prior native
// session by letting credential rotation commit before the Join fails.
func (s *Store) RotateAndJoinEndpointGroupCrossOwner(ownerID, endpointID, groupID, nodeID,
	bindingID string, priorEpoch uint64, credentialHash, leaseOwner, leaseExpiresAt string) (*SessionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := crossOwnerGroupJoinTx(tx, ownerID, endpointID, groupID, nodeID, bindingID, priorEpoch, false); err != nil {
		return nil, err
	}
	binding, err := getSessionBindingLeaseTx(tx, bindingID)
	if err != nil || binding.EndpointID != endpointID || binding.NodeID != nodeID || binding.Epoch != priorEpoch ||
		!isActiveBindingStatus(binding.Status) || credentialHash == "" || leaseOwner == "" {
		return nil, ErrCrossOwnerGroupDenied
	}
	at := time.Now().UTC()
	if err := validFutureLeaseExpiry(leaseExpiresAt, at); err != nil {
		return nil, err
	}
	if binding.LeaseOwner != "" {
		priorExpiry, err := parseSessionBindingLeaseExpiry(binding.LeaseExpiresAt)
		if err != nil {
			return nil, err
		}
		if binding.LeaseOwner != leaseOwner && priorExpiry.After(at) {
			return nil, ErrSessionBindingLeaseHeld
		}
	}
	result, err := tx.Exec(`UPDATE session_bindings SET credential_hash=?,credential_hash_version=credential_hash_version+1,
lease_owner=?,lease_expires_at=?,status=?,epoch=epoch+1,version=version+1,updated_at=?
WHERE id=? AND epoch=? AND version=? AND status IN ('active','leased','online','ready','acquired')`,
		credentialHash, leaseOwner, leaseExpiresAt, SessionBindingStatusLeased, now(), bindingID, priorEpoch, binding.Version)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrSessionBindingStaleEpoch
	}
	if err := upsertEndpointGroupMembershipTx(tx, endpointID, groupID); err != nil {
		return nil, err
	}
	var joinRevision int64
	if tx.QueryRow(`SELECT revision FROM endpoint_group_memberships WHERE endpoint_id=? AND group_id=? AND status='active'`, endpointID, groupID).Scan(&joinRevision) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	if _, err := tx.Exec(`UPDATE cross_owner_group_joins_v2 SET applied_binding_epoch=?,applied_join_revision=?,updated_at=?
WHERE admission_id=(SELECT id FROM cross_owner_group_admissions_v2 WHERE group_id=? AND endpoint_id=? AND state='ACTIVE'
ORDER BY created_at DESC LIMIT 1) AND state='ACTIVE'`, priorEpoch+1, joinRevision, now(), groupID, endpointID); err != nil {
		return nil, err
	}
	if err := networkGuardGroupEndpointTx(tx, mustEndpointPrincipalTx(tx, endpointID), endpointID, groupID, time.Now().UTC()); err != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	updated, err := getSessionBindingLeaseTx(tx, bindingID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

func mustEndpointPrincipalTx(tx *sql.Tx, endpointID string) string {
	var principalID string
	_ = tx.QueryRow(`SELECT principal_id FROM fabric_endpoints WHERE id=?`, endpointID).Scan(&principalID)
	return principalID
}

func crossOwnerGroupJoinTx(tx *sql.Tx, ownerID, endpointID, groupID, nodeID, bindingID string,
	priorEpoch uint64, afterRotation bool) error {
	var a CrossOwnerGroupAdmission
	var grants string
	err := tx.QueryRow(`SELECT `+crossOwnerAdmissionColumns+` FROM cross_owner_group_admissions_v2
WHERE group_id=? AND endpoint_id=? AND endpoint_owner_id=? AND state='ACTIVE'
ORDER BY created_at DESC LIMIT 1`, groupID, endpointID, ownerID).Scan(&a.ID, &a.HubID, &a.NetworkID,
		&a.GroupID, &a.GroupRevision, &a.EndpointID, &a.PrincipalID, &a.EndpointOwnerID,
		&a.GroupOwnerID, &a.MembershipID, &a.MembershipRevision, &grants, &a.ExpiresAt, &a.State)
	if err != nil || crossOwnerAdmissionCurrentTx(tx, &a, time.Now().UTC()) != nil {
		return ErrCrossOwnerGroupDenied
	}
	var consentNode, consentBinding, consentOwner, consentState, consentExpiry string
	var consentEpoch, appliedEpoch uint64
	var appliedJoinRevision int64
	if tx.QueryRow(`SELECT endpoint_owner_id,node_id,binding_id,expected_binding_epoch,applied_binding_epoch,applied_join_revision,expires_at,state
FROM cross_owner_group_joins_v2 WHERE admission_id=? ORDER BY created_at DESC LIMIT 1`, a.ID).Scan(
		&consentOwner, &consentNode, &consentBinding, &consentEpoch, &appliedEpoch, &appliedJoinRevision, &consentExpiry, &consentState) != nil ||
		consentOwner != ownerID || consentNode != nodeID || consentBinding != bindingID ||
		consentState != "ACTIVE" || !networkExpiryAllows(consentExpiry, time.Now().UTC()) ||
		requireCurrentOwnerBoundGroupNodeTx(tx, nodeID, ownerID, a.HubID) != nil {
		return ErrCrossOwnerGroupDenied
	}
	if consentEpoch != priorEpoch {
		var currentJoinRevision int64
		if appliedEpoch != priorEpoch || appliedJoinRevision <= 0 ||
			tx.QueryRow(`SELECT revision FROM endpoint_group_memberships WHERE endpoint_id=? AND group_id=? AND status='active'`, endpointID, groupID).Scan(&currentJoinRevision) != nil ||
			currentJoinRevision != appliedJoinRevision {
			return ErrCrossOwnerGroupDenied
		}
	}
	var endpointOwner, endpointNode, endpointBinding, nativeID, bindingNative, bindingStatus string
	var currentEpoch uint64
	if tx.QueryRow(`SELECT e.owner,e.machine_id,e.binding_id,e.native_session_id,b.native_session_id,b.status,b.epoch
FROM fabric_endpoints e JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id AND b.principal_id=e.principal_id
WHERE e.id=? AND e.principal_id=? AND e.status!='left' AND e.migration_state='READY'`,
		endpointID, a.PrincipalID).Scan(&endpointOwner, &endpointNode, &endpointBinding, &nativeID,
		&bindingNative, &bindingStatus, &currentEpoch) != nil || endpointOwner != ownerID || endpointNode != nodeID ||
		endpointBinding != bindingID || nativeID == "" || bindingNative != nativeID || !isActiveBindingStatus(bindingStatus) {
		return ErrCrossOwnerGroupDenied
	}
	if afterRotation && currentEpoch != priorEpoch+1 || !afterRotation && currentEpoch != priorEpoch {
		return ErrCrossOwnerGroupDenied
	}
	return nil
}
