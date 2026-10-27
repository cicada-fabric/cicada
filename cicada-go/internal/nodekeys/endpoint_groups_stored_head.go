package nodekeys

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// ReadEndpointGroupStoredOwnerHead reads retained control evidence, not fresh
// Current or business authority. It requires an existing-only handle and never
// creates, repairs or advances registration, trust, source or control state.
func (s *CryptoState) ReadEndpointGroupStoredOwnerHead(ctx context.Context, hub wire.HubIdentity, anchor wire.EndpointGroupsRegistrationAnchor, groupID string) (e2ee.EndpointGroupOwnerControl, error) {
	var zero e2ee.EndpointGroupOwnerControl
	if ctx == nil || validateCryptoToken("Group", groupID) != nil || wire.ValidateEndpointGroupsRegistrationAnchor(anchor, hub) != nil {
		return zero, ErrEndpointGroupsPolicy
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if s == nil {
		return zero, ErrCryptoStateClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return zero, err
	}
	if !s.existingOnly {
		return zero, ErrEndpointGroupsPolicy
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return zero, err
	}
	defer conn.Close()
	if err = s.configureConnection(ctx, conn); err != nil {
		return zero, err
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	// Registration, independent ACTIVE Owner pin and head must all belong to
	// the same SQLite snapshot, including when another handle advances a deny.
	original, err := checkEndpointGroupsRegistration(ctx, tx, hub, anchor)
	if err != nil {
		return zero, err
	}
	var headJSON, identityJSON []byte
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT head_json,head_digest,identity_json FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND network_id=? AND group_id=? AND endpoint_id=?`, hub.HubID, anchor.NetworkID, groupID, anchor.Registration.EndpointID).Scan(&headJSON, &digest, &identityJSON)
	if err != nil {
		return zero, err
	}
	var identity wire.EndpointGroupRelation
	if json.Unmarshal(identityJSON, &identity) != nil || identity.GroupID != groupID || !endpointGroupsAnchorRelationMatches(anchor, identity) {
		return zero, ErrEndpointGroupsConflict
	}
	// Observe intentionally preserves the old identity for terminal heads. Its
	// decision revision/digest need not describe the independently parsed head.
	var head e2ee.EndpointGroupOwnerControl
	if json.Unmarshal(headJSON, &head) != nil || e2ee.ValidateEndpointGroupOwnerControl(head) != nil {
		return zero, ErrEndpointGroupsConflict
	}
	expected, err := e2ee.EndpointGroupOwnerControlDigest(original.NativeDigest, groupID, head)
	if err != nil || digest != expected {
		return zero, ErrEndpointGroupsConflict
	}
	return head, nil
}
