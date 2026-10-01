package store

import (
	"strings"
	"time"
)

const clientNetworkEndpointDirectoryPageMax = 64

const ClientOwnerNetworkEndpointDirectoryOperation = "network.directory"

// ClientNetworkEndpointCard is the smallest owner-facing projection of an
// opted-in Endpoint in an Owner-managed Network. It deliberately excludes
// native Session IDs, Node locators, workspaces, grants, keys and Group data.
type ClientNetworkEndpointCard struct {
	NetworkID  string `json:"network_id"`
	EndpointID string `json:"endpoint_id"`
	Alias      string `json:"alias"`
	Presence   string `json:"presence"`
}

// ListClientOwnerNetworkEndpointCards lists only Endpoints that are currently
// enrolled in an ACTIVE Network and explicitly opted into directory
// publication. The authenticated Owner must own the Network and the accepted
// Client request must belong to that same Owner and Hub. afterEndpointID is a
// bounded, best-effort cursor; an empty next cursor means the page is complete.
func (s *Store) ListClientOwnerNetworkEndpointCards(clientRequestID,
	authenticatedOwnerID, networkID, afterEndpointID string, limit int) ([]ClientNetworkEndpointCard, string, error) {
	clientRequestID = strings.TrimSpace(clientRequestID)
	authenticatedOwnerID = strings.TrimSpace(authenticatedOwnerID)
	networkID = strings.TrimSpace(networkID)
	if clientRequestID == "" || authenticatedOwnerID == "" || networkID == "" ||
		len(afterEndpointID) > 256 || limit <= 0 || limit > clientNetworkEndpointDirectoryPageMax {
		return nil, "", ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	actor, err := trustedClientRequestTx(tx, clientRequestID)
	if err != nil || actor.OwnerID != authenticatedOwnerID {
		return nil, "", ErrNetworkPermission
	}
	var routeOperation string
	if err := tx.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE id=?`,
		clientRequestID).Scan(&routeOperation); err != nil ||
		routeOperation != ClientOwnerNetworkEndpointDirectoryOperation {
		return nil, "", ErrNetworkPermission
	}
	var networkHubID, networkState string
	if err := tx.QueryRow(`SELECT hub_id,state FROM networks_v2
WHERE id=? AND owner_id=?`, networkID, actor.OwnerID).Scan(&networkHubID, &networkState); err != nil ||
		networkHubID != actor.HubID || networkState != NetworkStateActive {
		return nil, "", ErrNetworkPermission
	}
	at := time.Now().UTC()
	stamp := at.Format(time.RFC3339Nano)
	rows, err := tx.Query(`SELECT enrollment.network_id,endpoint.id,enrollment.nickname,
CASE WHEN endpoint.status!='offline' AND EXISTS(SELECT 1 FROM network_access_sessions_v2 binding
	WHERE binding.network_id=network.id AND binding.endpoint_id=endpoint.id
	AND binding.status='active' AND binding.lease_expires_at!=''
	AND cicada_network_expiry_allows(binding.lease_expires_at,?)=1)
	THEN 'ACCESS_RECENT' ELSE 'UNKNOWN' END
FROM endpoint_network_memberships_v2 enrollment
JOIN networks_v2 network ON network.id=enrollment.network_id AND network.state='ACTIVE'
JOIN network_memberships_v2 membership ON membership.network_id=network.id
	AND membership.principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=enrollment.endpoint_id)
JOIN fabric_endpoints endpoint ON endpoint.id=enrollment.endpoint_id AND endpoint.status!='left'
JOIN principals principal ON principal.id=endpoint.principal_id AND principal.status='active'
	AND principal.owner_id=endpoint.owner
JOIN principals owner ON owner.id=endpoint.owner AND owner.kind='human' AND owner.status='active'
WHERE enrollment.network_id=? AND network.owner_id=? AND network.hub_id=?
	AND enrollment.status='active' AND enrollment.discoverable=1
	AND membership.status='active' AND cicada_network_expiry_allows(membership.expires_at,?)=1
	AND EXISTS(SELECT 1 FROM json_each(membership.grants_json)
		WHERE json_each.value='directory.publish')
	AND endpoint.id>?
ORDER BY endpoint.id LIMIT ?`, stamp, networkID, actor.OwnerID, actor.HubID,
		stamp, afterEndpointID, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([]ClientNetworkEndpointCard, 0, limit+1)
	for rows.Next() {
		var card ClientNetworkEndpointCard
		if err := rows.Scan(&card.NetworkID, &card.EndpointID, &card.Alias,
			&card.Presence); err != nil {
			return nil, "", err
		}
		result = append(result, card)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if err := rows.Close(); err != nil {
		return nil, "", err
	}
	nextCursor := ""
	if len(result) > limit {
		result = result[:limit]
		nextCursor = result[len(result)-1].EndpointID
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return result, nextCursor, nil
}
