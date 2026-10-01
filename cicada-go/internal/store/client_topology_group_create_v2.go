package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// This ledger is separate from the encrypted Client request ledger: a request
// can commit a Group before its encrypted response packet is durably recorded.
func (s *Store) initializeClientTopologyGroupCreateSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS client_topology_group_create_guard_v2 (
 id INTEGER PRIMARY KEY CHECK(id=1), touched_at TEXT NOT NULL
);
INSERT OR IGNORE INTO client_topology_group_create_guard_v2(id,touched_at) VALUES(1,'');
CREATE TABLE IF NOT EXISTS client_topology_group_creates_v2 (
 request_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, network_id TEXT NOT NULL,
 input_digest TEXT NOT NULL CHECK(length(input_digest)=64), group_id TEXT NOT NULL UNIQUE,
 created_group_json TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(request_id) REFERENCES client_device_requests_v2(id),
 FOREIGN KEY(group_id) REFERENCES groups(id)
);`)
	return err
}

// CreateClientTopologyGroupAtomic is the topology.apply group.create write.
// Parent inspection, current Client/Network authority, Group insertion, owner
// Membership and request recovery identity all share one SQLite transaction.
// A missing Client request is accepted only by the legacy PREPARING Control
// entrypoint, which cannot create a Network-scoped Group.
func (s *Store) CreateClientTopologyGroupAtomic(group Group, parentID, clientRequestID string) (*Group, error) {
	group.ID = strings.TrimSpace(group.ID)
	group.NetworkID = strings.TrimSpace(group.NetworkID)
	group.OwnerPrincipalID = strings.TrimSpace(group.OwnerPrincipalID)
	group.Name = strings.TrimSpace(group.Name)
	parentID = strings.TrimSpace(parentID)
	clientRequestID = strings.TrimSpace(clientRequestID)
	if group.ID != "" || group.ParentGroupID != "" || group.Name == "" || group.OwnerPrincipalID == "" ||
		(group.State != "" && group.State != GroupStateActive) || !validGroupContextPolicy(group.ContextPolicy) {
		return nil, ErrNetworkPermission
	}
	group.State = GroupStateActive
	group.Revision, group.Version = 1, 1
	if parentID != "" {
		// Preserve the visible version/revision of the former create +
		// SetGroupParent path without exposing a partially created root.
		group.Revision, group.Version = 2, 2
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Obtain the database writer lock before checking mutable authorization,
	// including when another Store handle shares the same SQLite file.
	guardWrite, err := tx.Exec(`UPDATE client_topology_group_create_guard_v2 SET touched_at=? WHERE id=1`, now())
	if err != nil {
		return nil, err
	}
	guardRows, err := guardWrite.RowsAffected()
	if err != nil || guardRows != 1 {
		return nil, ErrNetworkPermission
	}
	if clientRequestID != "" {
		actor, requestErr := trustedTopologyGroupCreateRequestTx(tx, clientRequestID)
		if requestErr != nil || actor.OwnerID != group.OwnerPrincipalID {
			return nil, ErrNetworkPermission
		}
		var operation string
		if tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`,
			clientRequestID).Scan(&operation) != nil || operation != "topology.apply" {
			return nil, ErrNetworkPermission
		}
		if group.NetworkID != "" {
			var authorized int
			err = tx.QueryRow(`SELECT 1 FROM networks_v2 n
JOIN client_device_hub_config_v2 h ON h.id=1 AND h.hub_id=n.hub_id
WHERE n.id=? AND n.hub_id=? AND n.owner_id=? AND n.state='ACTIVE'`,
				group.NetworkID, actor.HubID, actor.OwnerID).Scan(&authorized)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNetworkPermission
			}
			if err != nil {
				return nil, err
			}
		}
	} else if group.NetworkID != "" {
		return nil, ErrNetworkPermission
	}
	if group.NetworkID == "" {
		var phase string
		if err := tx.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&phase); err != nil {
			return nil, err
		}
		if phase == NetworkModeActive {
			return nil, ErrNetworkPermission
		}
	}
	var ownerID, kind, status, trustDomain string
	if err := tx.QueryRow(`SELECT owner_id,kind,status,trust_domain_id FROM principals WHERE id=?`,
		group.OwnerPrincipalID).Scan(&ownerID, &kind, &status, &trustDomain); err != nil ||
		ownerID != group.OwnerPrincipalID || kind != PrincipalKindHuman || status != PrincipalStatusActive ||
		group.TrustDomainID != trustDomain {
		return nil, ErrNetworkPermission
	}
	if parentID != "" {
		var parentOwner, parentDomain, parentNetwork, parentState string
		err = tx.QueryRow(`SELECT owner_principal_id,trust_domain_id,network_id,state FROM groups WHERE id=?`,
			parentID).Scan(&parentOwner, &parentDomain, &parentNetwork, &parentState)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		if err != nil {
			return nil, err
		}
		if parentNetwork != group.NetworkID {
			return nil, ErrNetworkConflict
		}
		if parentState != GroupStateActive || parentOwner != group.OwnerPrincipalID ||
			parentDomain == "" || parentDomain != group.TrustDomainID {
			return nil, ErrGroupParentOwnerScope
		}
		allowed, err := localDeliveryMembershipAllows(tx, group.OwnerPrincipalID,
			parentID, "group.manage", now())
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrNetworkPermission
		}
	}
	// Hash only the request's semantic input; the newly generated Group ID
	// must not change the digest on a lost-response retry.
	inputJSON, err := json.Marshal(struct {
		Group    Group  `json:"group"`
		ParentID string `json:"parent_id"`
	}{group, parentID})
	if err != nil {
		return nil, err
	}
	digestBytes := sha256.Sum256(inputJSON)
	digest := hex.EncodeToString(digestBytes[:])
	if clientRequestID != "" {
		var oldDigest, oldGroupID, oldGroupJSON string
		err = tx.QueryRow(`SELECT input_digest,group_id,created_group_json
FROM client_topology_group_creates_v2 WHERE request_id=? AND owner_id=? AND network_id=?`,
			clientRequestID, group.OwnerPrincipalID, group.NetworkID).Scan(&oldDigest, &oldGroupID, &oldGroupJSON)
		if err == nil {
			if oldDigest != digest {
				return nil, ErrVersionConflict
			}
			var existing Group
			if json.Unmarshal([]byte(oldGroupJSON), &existing) != nil || existing.ID != oldGroupID {
				return nil, ErrVersionConflict
			}
			var currentState string
			if tx.QueryRow(`SELECT state FROM groups WHERE id=? AND owner_principal_id=? AND network_id=?`,
				oldGroupID, group.OwnerPrincipalID, group.NetworkID).Scan(&currentState) != nil || currentState != GroupStateActive {
				return nil, ErrVersionConflict
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return &existing, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	group.ID = NewID("grp")
	group.ParentGroupID = parentID
	timestamp := now()
	_, err = tx.Exec(`INSERT INTO groups
(id,network_id,parent_group_id,owner_principal_id,trust_domain_id,name,state,purpose,revision,
 policy_ref,context_policy,isolation_profile,external_mode,version,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		group.ID, group.NetworkID, parentID, group.OwnerPrincipalID, group.TrustDomainID, group.Name,
		group.State, group.Purpose, group.Revision, group.PolicyRef, group.ContextPolicy,
		group.IsolationProfile, group.ExternalMode, group.Version, timestamp, timestamp)
	if err != nil {
		return nil, err
	}
	membership, roles, grants, authorization, err := normalizeMembership(Membership{
		PrincipalID: group.OwnerPrincipalID, GroupID: group.ID, Role: "owner", Roles: []string{"owner"},
		Grants: []string{"group.manage", "membership.manage", "representative.manage", "policy.manage"},
		Status: MembershipStatusActive,
	})
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO memberships
(id,principal_id,group_id,role,roles_json,grants_json,authorization_json,status,
 effective_at,expires_at,revoked_at,revocation_reason,revision,version,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		membership.ID, membership.PrincipalID, membership.GroupID, membership.Role, roles, grants, authorization,
		membership.Status, membership.EffectiveAt, membership.ExpiresAt, membership.RevokedAt,
		membership.RevocationReason, membership.Revision, membership.Version, timestamp, timestamp)
	if err != nil {
		return nil, err
	}
	created, err := scanGroup(tx.QueryRow(`SELECT `+groupColumns+` FROM groups WHERE id=?`, group.ID))
	if err != nil {
		return nil, err
	}
	if clientRequestID != "" {
		createdJSON, err := json.Marshal(created)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO client_topology_group_creates_v2
(request_id,owner_id,network_id,input_digest,group_id,created_group_json,created_at)
VALUES (?,?,?,?,?,?,?)`, clientRequestID, group.OwnerPrincipalID, group.NetworkID,
			digest, group.ID, string(createdJSON), timestamp); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return created, nil
}

// This route has no OwnerID==trust-domain requirement: the active human
// Principal's current trust domain is checked against the new Group and parent
// below. Keep the accepted request/device/key/epoch/Hub guard identical to
// trustedClientRequestTx without widening unrelated Client mutations.
func trustedTopologyGroupCreateRequestTx(tx *sql.Tx, requestID string) (trustedClientRequest, error) {
	var actor trustedClientRequest
	if requestID == "" {
		return actor, ErrNetworkPermission
	}
	err := tx.QueryRow(`SELECT r.owner_id,r.device_id,h.hub_id
FROM client_device_requests_v2 r
JOIN client_devices_v2 d ON d.owner_id=r.owner_id AND d.device_id=r.device_id
  AND d.session_epoch=r.session_epoch AND d.state='ACTIVE'
JOIN owner_approval_keys_v2 k ON k.owner_id=d.owner_id AND k.key_id=d.owner_key_id AND k.state='ACTIVE'
JOIN principals p ON p.id=r.owner_id AND p.owner_id=p.id AND p.kind='human' AND p.status='active'
JOIN client_device_hub_config_v2 h ON h.id=1
WHERE r.id=? AND r.status='PROCESSING'`, requestID).Scan(&actor.OwnerID, &actor.DeviceID, &actor.HubID)
	if errors.Is(err, sql.ErrNoRows) {
		return actor, ErrNetworkPermission
	}
	return actor, err
}
