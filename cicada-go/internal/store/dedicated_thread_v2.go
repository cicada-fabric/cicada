package store

import (
	"database/sql"
	"errors"
	"time"
)

const DedicatedThreadContextPolicy = "dedicated_thread"

var ErrDedicatedThreadContextConflict = errors.New("native Thread has known context in another sharing scope")

func validGroupContextPolicy(policy string) bool {
	return policy == "" || policy == "group_scoped" || policy == DedicatedThreadContextPolicy
}

func configuredGroupContextPolicy(policy string) bool {
	return policy == "group_scoped" || policy == DedicatedThreadContextPolicy
}

func validNetworkContextPolicy(policy string) bool {
	return policy == "" || policy == DedicatedThreadContextPolicy
}

// guardDedicatedThreadGroupEndpointTx refuses to reuse a known native Thread
// in a scope that requires a dedicated context. It consults current Endpoint
// identity and every durable SessionBinding identity, plus retained Group and
// Network membership history. A new Endpoint ID or binding does not erase
// prior known associations. This is intentionally limited to Hub-known state;
// it cannot prove that a Runtime or another Hub forgot earlier plaintext.
func guardDedicatedThreadGroupEndpointTx(tx *sql.Tx, endpointID, groupID string, _ time.Time) error {
	var groupPolicy, networkID, networkPolicy, machineID, nativeSessionID string
	if err := tx.QueryRow(`SELECT g.context_policy,g.network_id,COALESCE(n.context_policy,''),
e.machine_id,e.native_session_id
FROM groups g LEFT JOIN networks_v2 n ON n.id=g.network_id
JOIN fabric_endpoints e ON e.id=? WHERE g.id=?`, endpointID, groupID).
		Scan(&groupPolicy, &networkID, &networkPolicy, &machineID, &nativeSessionID); err != nil {
		return ErrNetworkPermission
	}
	if !validGroupContextPolicy(groupPolicy) || !validNetworkContextPolicy(networkPolicy) {
		return ErrNetworkPermission
	}
	checkOtherGroups := groupPolicy == DedicatedThreadContextPolicy
	checkOtherNetworks := groupPolicy == DedicatedThreadContextPolicy ||
		networkPolicy == DedicatedThreadContextPolicy
	checkNetworkGroupHistory := networkPolicy == DedicatedThreadContextPolicy
	existingConflict, err := dedicatedThreadExistingPolicyConflictTx(tx,
		endpointID, groupID, networkID, false)
	if err != nil {
		return err
	}
	if existingConflict {
		return ErrDedicatedThreadContextConflict
	}
	if !checkOtherGroups && !checkOtherNetworks {
		return nil
	}
	if machineID == "" || nativeSessionID == "" {
		return ErrDedicatedThreadContextConflict
	}
	conflict, err := dedicatedThreadHistoryConflictTx(tx, endpointID, groupID, networkID,
		checkOtherGroups, checkOtherNetworks, checkNetworkGroupHistory,
		groupPolicy == DedicatedThreadContextPolicy)
	if err != nil {
		return err
	}
	if conflict {
		return ErrDedicatedThreadContextConflict
	}
	return nil
}

// guardDedicatedThreadNetworkTrafficTx rejects Network-scoped peer content
// for a Thread that has ever belonged to a dedicated Group. A dedicated
// Network permits its own Groups and traffic, but rejects known use in other
// Networks. Metadata-only directory operations do not call this content Guard.
func guardDedicatedThreadNetworkTrafficTx(tx *sql.Tx, endpointID, networkID string, _ time.Time) error {
	var networkPolicy string
	if err := tx.QueryRow(`SELECT context_policy FROM networks_v2 WHERE id=?`, networkID).
		Scan(&networkPolicy); err != nil || !validNetworkContextPolicy(networkPolicy) {
		return ErrNetworkPermission
	}
	existingConflict, err := dedicatedThreadExistingPolicyConflictTx(tx,
		endpointID, "", networkID, true)
	if err != nil {
		return err
	}
	if existingConflict {
		return ErrDedicatedThreadContextConflict
	}
	if networkPolicy != DedicatedThreadContextPolicy {
		return nil
	}
	conflict, err := dedicatedThreadHistoryConflictTx(tx, endpointID, "", networkID,
		false, true, true, false)
	if err != nil {
		return err
	}
	if conflict {
		return ErrDedicatedThreadContextConflict
	}
	return nil
}

func dedicatedThreadHistoryConflictTx(tx *sql.Tx, endpointID, groupID, networkID string,
	checkOtherGroups, checkOtherNetworks, checkNetworkGroupHistory, checkNetworkContent bool) (bool, error) {
	var conflict int
	err := tx.QueryRow(`WITH identities(node_id,native_session_id) AS (
 SELECT machine_id,native_session_id FROM fabric_endpoints WHERE id=? AND machine_id<>'' AND native_session_id<>''
 UNION SELECT node_id,native_session_id FROM session_bindings WHERE endpoint_id=? AND node_id<>'' AND native_session_id<>''
), related(endpoint_id) AS (
 SELECT ? UNION
 SELECT DISTINCT e.id FROM fabric_endpoints e
 WHERE EXISTS(SELECT 1 FROM identities i WHERE i.node_id=e.machine_id AND i.native_session_id=e.native_session_id)
 OR EXISTS(SELECT 1 FROM session_bindings b JOIN identities i
   ON i.node_id=b.node_id AND i.native_session_id=b.native_session_id WHERE b.endpoint_id=e.id)
)
SELECT EXISTS(
 SELECT 1 FROM endpoint_group_memberships eg JOIN related r ON r.endpoint_id=eg.endpoint_id
 WHERE ?=1 AND eg.group_id<>?
 UNION ALL
 SELECT 1 FROM fabric_endpoints e JOIN related r ON r.endpoint_id=e.id
 WHERE ?=1 AND e.group_id<>'' AND e.group_id<>?
	UNION ALL
	SELECT 1 FROM session_bindings b JOIN related r ON r.endpoint_id=b.endpoint_id
	WHERE ?=1 AND b.group_id<>'' AND b.group_id<>?
 UNION ALL
 SELECT 1 FROM endpoint_network_memberships_v2 en JOIN related r ON r.endpoint_id=en.endpoint_id
 WHERE ?=1 AND en.network_id<>
   CASE WHEN ?=1 THEN ? ELSE ? END
 UNION ALL
 SELECT 1 FROM network_access_sessions_v2 a JOIN related r ON r.endpoint_id=a.endpoint_id
 WHERE ?=1 AND a.network_id<>
   CASE WHEN ?=1 THEN ? ELSE ? END
 UNION ALL
 SELECT 1 FROM session_bindings b JOIN related r ON r.endpoint_id=b.endpoint_id
 JOIN groups g ON g.id=b.group_id
 WHERE ?=1 AND (g.network_id='' OR g.network_id<>?)
 UNION ALL
 SELECT 1 FROM endpoint_group_memberships eg JOIN related r ON r.endpoint_id=eg.endpoint_id
 JOIN groups g ON g.id=eg.group_id
 WHERE ?=1 AND (g.network_id='' OR g.network_id<>?)
 UNION ALL
 SELECT 1 FROM network_direct_message_routes_v2 d JOIN related r
   ON r.endpoint_id=d.sender_endpoint_id OR r.endpoint_id=d.receiver_endpoint_id
 WHERE ?=1
)`, endpointID, endpointID, endpointID,
		dedicatedThreadBoolInt(checkOtherGroups), groupID,
		dedicatedThreadBoolInt(checkOtherGroups), groupID,
		dedicatedThreadBoolInt(checkOtherGroups), groupID,
		dedicatedThreadBoolInt(checkOtherNetworks), dedicatedThreadBoolInt(checkOtherNetworks), networkID, "",
		dedicatedThreadBoolInt(checkOtherNetworks), dedicatedThreadBoolInt(checkOtherNetworks), networkID, "",
		dedicatedThreadBoolInt(checkNetworkGroupHistory), networkID,
		dedicatedThreadBoolInt(checkNetworkGroupHistory), networkID,
		dedicatedThreadBoolInt(checkNetworkContent)).
		Scan(&conflict)
	if err != nil {
		return false, err
	}
	return conflict != 0, nil
}

func dedicatedThreadExistingPolicyConflictTx(tx *sql.Tx, endpointID, groupID,
	networkID string, anyDedicatedGroup bool) (bool, error) {
	var conflict int
	err := tx.QueryRow(`WITH identities(node_id,native_session_id) AS (
 SELECT machine_id,native_session_id FROM fabric_endpoints WHERE id=? AND machine_id<>'' AND native_session_id<>''
 UNION SELECT node_id,native_session_id FROM session_bindings WHERE endpoint_id=? AND node_id<>'' AND native_session_id<>''
), related(endpoint_id) AS (
 SELECT ? UNION
 SELECT DISTINCT e.id FROM fabric_endpoints e
 WHERE EXISTS(SELECT 1 FROM identities i WHERE i.node_id=e.machine_id AND i.native_session_id=e.native_session_id)
 OR EXISTS(SELECT 1 FROM session_bindings b JOIN identities i
   ON i.node_id=b.node_id AND i.native_session_id=b.native_session_id WHERE b.endpoint_id=e.id)
)
SELECT EXISTS(
 SELECT 1 FROM endpoint_group_memberships eg JOIN related r ON r.endpoint_id=eg.endpoint_id
 JOIN groups g ON g.id=eg.group_id
 WHERE g.context_policy=? AND (?=1 OR eg.group_id<>?)
 UNION ALL
 SELECT 1 FROM fabric_endpoints e JOIN related r ON r.endpoint_id=e.id
 JOIN groups g ON g.id=e.group_id
 WHERE g.context_policy=? AND e.group_id<>'' AND (?=1 OR e.group_id<>?)
 UNION ALL
 SELECT 1 FROM session_bindings b JOIN related r ON r.endpoint_id=b.endpoint_id
 JOIN groups g ON g.id=b.group_id
 WHERE g.context_policy=? AND b.group_id<>'' AND (?=1 OR b.group_id<>?)
 UNION ALL
 SELECT 1 FROM endpoint_network_memberships_v2 en JOIN related r ON r.endpoint_id=en.endpoint_id
 JOIN networks_v2 n ON n.id=en.network_id
 WHERE n.context_policy=? AND en.network_id<>?
 UNION ALL
 SELECT 1 FROM network_access_sessions_v2 a JOIN related r ON r.endpoint_id=a.endpoint_id
 JOIN networks_v2 n ON n.id=a.network_id
 WHERE n.context_policy=? AND a.network_id<>?
)`, endpointID, endpointID, endpointID,
		DedicatedThreadContextPolicy, dedicatedThreadBoolInt(anyDedicatedGroup), groupID,
		DedicatedThreadContextPolicy, dedicatedThreadBoolInt(anyDedicatedGroup), groupID,
		DedicatedThreadContextPolicy, dedicatedThreadBoolInt(anyDedicatedGroup), groupID,
		DedicatedThreadContextPolicy, networkID,
		DedicatedThreadContextPolicy, networkID).Scan(&conflict)
	if err != nil {
		return false, err
	}
	return conflict != 0, nil
}

func dedicatedThreadBoolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Store) initializeDedicatedThreadPolicySchema() error {
	if err := s.ensureColumn("networks_v2", "context_policy", `ALTER TABLE networks_v2
ADD COLUMN context_policy TEXT NOT NULL DEFAULT '' CHECK(context_policy IN ('','dedicated_thread'))`); err != nil {
		return err
	}
	_, err := s.db.Exec(`
CREATE INDEX IF NOT EXISTS session_bindings_native_history_v52_idx
 ON session_bindings(node_id,native_session_id,endpoint_id)
 WHERE node_id<>'' AND native_session_id<>'';
CREATE INDEX IF NOT EXISTS endpoint_network_memberships_endpoint_history_v52_idx
 ON endpoint_network_memberships_v2(endpoint_id,network_id,status);
CREATE INDEX IF NOT EXISTS network_access_sessions_endpoint_history_v52_idx
 ON network_access_sessions_v2(endpoint_id,network_id,status);
`)
	return err
}
