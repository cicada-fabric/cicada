package store

import (
	"database/sql"
	"errors"
	"strings"
)

// NativeContextScopeMetadata is the current Hub-authoritative sharing scope
// carried beside a Node delivery/join authorization. It contains no native
// session identifier; the caller combines it with the binding already in that
// authorization when calling nodeinbox.NativeContextRegistry.
type NativeContextScopeMetadata struct {
	HubID                string `json:"hub_id"`
	NetworkID            string `json:"network_id,omitempty"`
	GroupID              string `json:"group_id,omitempty"`
	GroupContextPolicy   string `json:"group_context_policy,omitempty"`
	NetworkContextPolicy string `json:"network_context_policy,omitempty"`
}

func readNativeContextScopeForGroupTx(tx *sql.Tx, groupID string) (NativeContextScopeMetadata, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return NativeContextScopeMetadata{}, ErrNetworkPermission
	}
	var scope NativeContextScopeMetadata
	err := tx.QueryRow(`SELECT hub.hub_id,g.network_id,g.id,g.context_policy,
COALESCE(n.context_policy,'')
FROM groups g JOIN client_device_hub_config_v2 hub ON hub.id=1
LEFT JOIN networks_v2 n ON n.id=g.network_id
WHERE g.id=? AND g.state='ACTIVE'`, groupID).Scan(&scope.HubID,
		&scope.NetworkID, &scope.GroupID, &scope.GroupContextPolicy, &scope.NetworkContextPolicy)
	if err != nil || scope.HubID == "" || scope.GroupID != groupID ||
		!validGroupContextPolicy(scope.GroupContextPolicy) || !validNetworkContextPolicy(scope.NetworkContextPolicy) {
		return NativeContextScopeMetadata{}, ErrNetworkPermission
	}
	return scope, nil
}

func readNativeContextScopeForNetworkTx(tx *sql.Tx, networkID string) (NativeContextScopeMetadata, error) {
	networkID = strings.TrimSpace(networkID)
	if networkID == "" {
		return NativeContextScopeMetadata{}, ErrNetworkPermission
	}
	var scope NativeContextScopeMetadata
	err := tx.QueryRow(`SELECT n.hub_id,n.id,n.context_policy FROM networks_v2 n
JOIN client_device_hub_config_v2 hub ON hub.id=1
WHERE n.id=? AND n.state='ACTIVE'`, networkID).Scan(&scope.HubID,
		&scope.NetworkID, &scope.NetworkContextPolicy)
	if err != nil || scope.HubID == "" || scope.NetworkID != networkID ||
		!validNetworkContextPolicy(scope.NetworkContextPolicy) {
		return NativeContextScopeMetadata{}, ErrNetworkPermission
	}
	return scope, nil
}

// readNativeContextScopeForEndpointTx requires the currently active endpoint
// membership before returning policy metadata to a Node.
func readNativeContextScopeForEndpointTx(tx *sql.Tx, endpointID, groupID string) (NativeContextScopeMetadata, error) {
	scope, err := readNativeContextScopeForGroupTx(tx, groupID)
	if err != nil {
		return NativeContextScopeMetadata{}, err
	}
	var active int
	err = tx.QueryRow(`SELECT EXISTS(
SELECT 1 FROM fabric_endpoints e
JOIN principals p ON p.id=e.principal_id AND p.status='active'
JOIN memberships m ON m.principal_id=p.id AND m.group_id=? AND m.status='active'
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=m.group_id AND eg.status='active'
WHERE e.id=? AND e.status NOT IN ('left','offline') AND e.migration_state='READY'
)`, groupID, endpointID).Scan(&active)
	if err != nil || active != 1 {
		return NativeContextScopeMetadata{}, errors.Join(ErrNetworkPermission, err)
	}
	return scope, nil
}
