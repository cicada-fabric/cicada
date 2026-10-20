package store

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type OwnerEndpointReadInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Device            e2ee.PublicIdentity
	Packet            []byte
	Request           wire.OwnerEndpointReadRequest
	At                time.Time
	Now               func() time.Time
}

// ReadOwnerEndpoints is a separate, one-request Owner proof, not an expansion
// of a pre-existing activation lease or N3 Node-status purpose. The same writer
// snapshot validates all current authority and captures the private page.
func (s *Store) ReadOwnerEndpoints(in OwnerEndpointReadInput, seal HubAppNodeSeal) ([]byte, error) {
	if s.requireOwnerSetupStartupAllowed() != nil || seal == nil || in.At.IsZero() {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c := in.Request.Context
	// Take the actual SQLite writer before sampling the security clock. A
	// request waiting behind another writer cannot retain its pre-wait TTL.
	if _, err = tx.Exec(`UPDATE hub_app_node_rates_v1 SET requests=requests WHERE owner_id=? AND device_id=?`, c.OwnerID, c.DeviceID); err != nil {
		return nil, err
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	// Rate bookkeeping takes the writer before authority reads. It commits only
	// with an accepted read/receipt and adds no Owner or communication grant.
	if err = appNodeDiagnosticRate(tx, c.OwnerID, c.DeviceID, in.At); err != nil {
		return nil, err
	}
	a, err := appNodeActor(tx, in.Hub, c.DeviceID, in.Device, in.Request.SessionToken, in.At)
	if err != nil {
		return nil, ErrHubAccountRejected
	}
	claims, err := e2ee.VerifyOwnerEndpointRead(a.scope.OwnerPublic, in.Request.OwnerProof, time.Time{})
	if err != nil || !appNodeScopeCurrent(a, claims.Scope) || c.RequestID != claims.RequestID ||
		c.Origin != a.scope.Origin || c.HubID != a.scope.HubID || c.OwnerID != a.scope.OwnerID || c.AccountID != a.scope.AccountID ||
		c.AccountEpoch != a.scope.AccountEpoch || c.DeviceEpoch != a.scope.DeviceEpoch || c.IssuedAt != claims.IssuedAt || hex.EncodeToString(c.ClientNonce) != claims.Nonce {
		return nil, ErrHubAccountRejected
	}
	// appNodeScopeCurrent requires the original completed N2 provenance,
	// ACTIVE lease row and unchanged identity epochs. Its old operation TTL
	// does not authorize this read: this independent Owner purpose has its own
	// <=60-second deadline and never renews the original activation lease.
	if _, err = nativePairProvenNode(tx, a, claims.Node, in.NodeControlPublic); err != nil {
		return nil, err
	}
	digest := wire.AppNodePacketDigest(in.Packet)
	if cached, _, e := appNodeCached(tx, c.OwnerID, c.DeviceID, c.RequestID, wire.OperationOwnerEndpointRead, digest, in.At); e != nil {
		return nil, e
	} else if len(cached) > 0 {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return cached, nil
	}
	result := wire.OwnerEndpointReadResult{Format: wire.OwnerEndpointReadResultFormat, RequestID: c.RequestID, RequestPacketDigest: digest, HubID: c.HubID,
		OwnerID: c.OwnerID, DeviceID: c.DeviceID, NodeID: claims.Node.NodeID, State: wire.AppNodeCompleted, CapturedAt: appNodeStamp(in.At), Freshness: "SNAPSHOT_ONLY", Endpoints: []wire.OwnerEndpointCard{}}
	if e2ee.ValidateOwnerEndpointReadClaims(claims, in.At) != nil {
		result.State = wire.AppNodeReadExpired
	} else {
		if claims.Cursor != "" {
			var found int
			if tx.QueryRow(`SELECT 1 FROM fabric_endpoints e JOIN principals p ON p.id=e.principal_id AND p.owner_id=e.owner AND p.status='active'
WHERE e.id=? AND e.owner=? AND e.machine_id=?`, claims.Cursor, c.OwnerID, claims.Node.NodeID).Scan(&found) != nil {
				return nil, ErrHubAccountRejected
			}
		}
		rows, err := tx.Query(`SELECT id,name,workspace,harness,
CASE WHEN e.status='left' THEN 'left' WHEN e.status='offline' THEN 'offline'
 WHEN EXISTS(SELECT 1 FROM session_bindings b WHERE b.endpoint_id=e.id
  AND b.status IN ('active','leased','online','ready','acquired')
  AND b.lease_expires_at!='' AND cicada_network_expiry_allows(b.lease_expires_at,?)=1)
 OR EXISTS(SELECT 1 FROM network_access_sessions_v2 a WHERE a.endpoint_id=e.id
  AND a.status='active' AND a.lease_expires_at!='' AND cicada_network_expiry_allows(a.lease_expires_at,?)=1)
 THEN 'LEASE_RECENT' ELSE 'UNKNOWN' END FROM fabric_endpoints e
WHERE owner=? AND machine_id=? AND id>? AND EXISTS(SELECT 1 FROM principals p
 WHERE p.id=e.principal_id AND p.owner_id=e.owner AND p.kind='agent' AND p.status='active')
ORDER BY id LIMIT ?`, appNodeStamp(in.At), appNodeStamp(in.At), c.OwnerID, claims.Node.NodeID, claims.Cursor, claims.Limit+1)
		if err != nil {
			return nil, err
		}
		var cards []wire.OwnerEndpointCard
		for rows.Next() {
			var card wire.OwnerEndpointCard
			if err = rows.Scan(&card.EndpointID, &card.Name, &card.Workspace, &card.Harness, &card.Presence); err != nil {
				rows.Close()
				return nil, err
			}
			cards = append(cards, card)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		for i, card := range cards {
			if i == claims.Limit {
				result.NextCursor = result.Endpoints[len(result.Endpoints)-1].EndpointID
				break
			}
			result.Endpoints = append(result.Endpoints, card)
			// Reserve space for a maximal next cursor. Bound the complete result,
			// before nested PQ/base64 overhead, rather than only counting rows.
			result.NextCursor = card.EndpointID
			raw, e := json.Marshal(result)
			if e != nil {
				return nil, e
			}
			if len(raw) > wire.MaxOwnerEndpointPageBytes-512 {
				result.Endpoints = result.Endpoints[:len(result.Endpoints)-1]
				if len(result.Endpoints) == 0 {
					return nil, ErrHubAccountRejected
				}
				result.NextCursor = result.Endpoints[len(result.Endpoints)-1].EndpointID
				break
			}
			result.NextCursor = ""
		}
	}
	packet, err := seal(result)
	if err != nil {
		return nil, err
	}
	if err = appNodeSaveRead(tx, c, wire.OperationOwnerEndpointRead, digest, result.State, packet, in.At); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}
