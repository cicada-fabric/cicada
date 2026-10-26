package nodekeys

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type endpointGroupsPinAuthority struct {
	Local wire.EndpointGroupCurrentEndpoint `json:"local"`
	Peer  wire.EndpointGroupCurrentEndpoint `json:"peer"`
}

func bindEndpointGroupsPeerAuthority(ctx context.Context, conn *sql.Conn, pin, oldPin *PeerKeyPin, local, peer wire.EndpointGroupCurrentEndpoint, now time.Time) (*PeerKeyPin, error) {
	if pin == nil || local.Relation.EndpointID != pin.Scope.LocalEndpointID || peer.Relation.EndpointID != pin.Scope.PeerEndpointID || local.Relation.GroupID != pin.Scope.LocalGroupID || peer.Relation.GroupID != pin.Scope.PeerGroupID {
		return nil, ErrEndpointGroupsPolicy
	}
	r := local.Relation
	var count int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM node_endpoint_group_peer_bindings_v1 WHERE local_endpoint_id=? AND group_id=? AND peer_endpoint_id=?`, pin.Scope.LocalEndpointID, pin.Scope.LocalGroupID, pin.Scope.PeerEndpointID).Scan(&count); err != nil || count > 1 {
		return nil, ErrEndpointGroupsConflict
	}
	var old []byte
	var version int64
	err := conn.QueryRowContext(ctx, `SELECT authority_json,pin_version FROM node_endpoint_group_peer_bindings_v1 WHERE hub_id=? AND network_id=? AND local_endpoint_id=? AND group_id=? AND peer_endpoint_id=?`, r.HubID, r.NetworkID, pin.Scope.LocalEndpointID, pin.Scope.LocalGroupID, pin.Scope.PeerEndpointID).Scan(&old, &version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) && count != 0 {
		return nil, ErrEndpointGroupsConflict
	}
	if err == nil && (oldPin == nil || version != oldPin.Version) {
		return nil, ErrEndpointGroupsConflict
	}
	raw, err := json.Marshal(endpointGroupsPinAuthority{local, peer})
	if err != nil {
		return nil, err
	}
	if oldPin != nil && pin.Version == oldPin.Version && !bytes.Equal(old, raw) {
		result, err := conn.ExecContext(ctx, `UPDATE node_crypto_peer_pins SET version=version+1,updated_at=? WHERE local_endpoint_id=? AND local_group_id=? AND peer_endpoint_id=? AND peer_group_id=? AND communication_link_id='' AND revoked_at='' AND version=?`, now.UTC().Format(time.RFC3339Nano), pin.Scope.LocalEndpointID, pin.Scope.LocalGroupID, pin.Scope.PeerEndpointID, pin.Scope.PeerGroupID, pin.Version)
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return nil, ErrPeerPinConflict
		}
		pin, err = loadPeerPin(ctx, conn, pin.Scope)
		if err != nil {
			return nil, err
		}
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO node_endpoint_group_peer_bindings_v1 VALUES(?,?,?,?,?,?,?) ON CONFLICT(hub_id,network_id,local_endpoint_id,group_id,peer_endpoint_id) DO UPDATE SET authority_json=excluded.authority_json,pin_version=excluded.pin_version`, r.HubID, r.NetworkID, pin.Scope.LocalEndpointID, pin.Scope.LocalGroupID, pin.Scope.PeerEndpointID, raw, pin.Version)
	return pin, err
}

// The source association is private admission metadata. It does not change the
// Endpoint key, original candidate version or SessionBinding. An old cached pin
// cannot borrow a re-added source simply because the Endpoint key stayed equal.
func endpointGroupsPinAdmission(ctx context.Context, q endpointGroupsQuery, pin PeerKeyPin, now time.Time) error {
	if pin.Scope.LocalGroupID != pin.Scope.PeerGroupID {
		if err := endpointGroupsLegacyAllowed(ctx, q, pin.Scope.LocalGroupID, pin.Scope.LocalEndpointID); err != nil {
			return err
		}
		return endpointGroupsLegacyAllowed(ctx, q, pin.Scope.PeerGroupID, pin.Scope.PeerEndpointID)
	}
	var count int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM node_endpoint_group_peer_bindings_v1 WHERE local_endpoint_id=? AND group_id=? AND peer_endpoint_id=?`, pin.Scope.LocalEndpointID, pin.Scope.LocalGroupID, pin.Scope.PeerEndpointID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return endpointGroupsLegacyAllowed(ctx, q, pin.Scope.LocalGroupID, pin.Scope.LocalEndpointID, pin.Scope.PeerEndpointID)
	}
	if count != 1 {
		return ErrEndpointGroupsConflict
	}
	var raw []byte
	var hub, network string
	var version int64
	err := q.QueryRowContext(ctx, `SELECT hub_id,network_id,authority_json,pin_version FROM node_endpoint_group_peer_bindings_v1 WHERE local_endpoint_id=? AND group_id=? AND peer_endpoint_id=?`, pin.Scope.LocalEndpointID, pin.Scope.LocalGroupID, pin.Scope.PeerEndpointID).Scan(&hub, &network, &raw, &version)
	if err != nil || version != pin.Version {
		return ErrEndpointGroupsConflict
	}
	var authority endpointGroupsPinAuthority
	if json.Unmarshal(raw, &authority) != nil || authority.Local.Relation.EndpointID != pin.Scope.LocalEndpointID || authority.Peer.Relation.EndpointID != pin.Scope.PeerEndpointID || authority.Local.Relation.GroupID != pin.Scope.LocalGroupID || authority.Peer.Relation.GroupID != pin.Scope.PeerGroupID ||
		authority.Peer.Relation.CandidateKeyID != pin.KeyID || authority.Peer.Relation.CandidateFingerprint != pin.Fingerprint || authority.Peer.Relation.BindingID != pin.BindingID || authority.Peer.Relation.BindingEpoch != pin.BindingEpoch || authority.Peer.Relation.CandidateProofDigest != pin.AttestationDigest {
		return ErrEndpointGroupsConflict
	}
	for _, snapshot := range []wire.EndpointGroupCurrentEndpoint{authority.Local, authority.Peer} {
		r := snapshot.Relation
		if r.HubID != hub || r.NetworkID != network || r.State != "ACTIVE" || snapshot.OwnerControl.DenyReason != "NONE" {
			return ErrEndpointGroupsPolicy
		}
		if r.ExpiresAt != "" {
			end, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
			if err != nil || !now.Before(end) {
				return ErrEndpointGroupsPolicy
			}
		}
		var headJSON, relationJSON, ownerPublic []byte
		var digest, ownerKey string
		var trustVersion int64
		if err := q.QueryRowContext(ctx, `SELECT head_json,head_digest FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=?`, hub, network, r.GroupID, r.EndpointID).Scan(&headJSON, &digest); err != nil {
			return ErrEndpointGroupsPolicy
		}
		var head e2ee.EndpointGroupOwnerControl
		if json.Unmarshal(headJSON, &head) != nil || head != snapshot.OwnerControl || head.DenyReason != "NONE" || digest != r.OwnerControlDigest {
			return ErrEndpointGroupsPolicy
		}
		if err := q.QueryRowContext(ctx, `SELECT relation_json,owner_key_id,owner_trust_version,owner_public_identity FROM node_endpoint_group_sources_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=? AND source=?`, hub, network, r.GroupID, r.EndpointID, r.Source).Scan(&relationJSON, &ownerKey, &trustVersion, &ownerPublic); err != nil {
			return ErrEndpointGroupsPolicy
		}
		expectedJSON, err := json.Marshal(r)
		if err != nil || !bytes.Equal(expectedJSON, relationJSON) {
			return ErrEndpointGroupsConflict
		}
		trust, err := loadNodeOwnerKeyTrust(ctx, q, r.OwnerID, ownerKey)
		if err != nil || trust.State != NodeOwnerKeyTrustActive || trust.Version != trustVersion {
			return ErrEndpointGroupsPolicy
		}
		var public e2ee.PublicIdentity
		if json.Unmarshal(ownerPublic, &public) != nil || !samePublicIdentity(public, trust.PublicIdentity) {
			return ErrEndpointGroupsPolicy
		}
	}
	return nil
}
