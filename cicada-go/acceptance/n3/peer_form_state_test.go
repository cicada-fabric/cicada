package n3_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
)

// A read-only audit of the actual fixture's existing shared access relation.
// In particular, a form/Network selection must not rotate the credential used
// by a local-domain or legacy Pair Group binding. Values remain private; only
// hashes/counts can be included in public evidence. No authority is seeded.
// Lease timestamps and the database row version are heartbeat metadata:
// ordinary lease renewal increments version without changing authority. Keep
// binding ID, epoch, credential hash, lease owner and capabilities exact.
type peerSharedAccessAudit struct {
	AccessRows, GroupRows, MembershipRows, EndpointRows int
	Access, Group, Membership, Endpoint                 string
}

func peerSharedAccessState(t *testing.T, database, network, endpoint string) peerSharedAccessAudit {
	t.Helper()
	if network == "" || endpoint == "" {
		t.Fatal("shared-access observation requires exact original fixture coordinates")
	}
	db := nodePairReadOnlyDB(t, database)
	defer db.Close()
	ctx := context.Background()
	tx := must(db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true}))
	defer tx.Rollback()
	observe := func(query string, args ...any) (string, int) {
		rows := must(tx.QueryContext(ctx, query, args...))
		defer rows.Close()
		columns := must(rows.Columns())
		if len(columns) != 1 {
			t.Fatal("shared-access audit query changed its bounded projection")
		}
		var encoded []json.RawMessage
		defer func() {
			for _, row := range encoded {
				clear(row)
			}
		}()
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) != nil || !json.Valid(raw) || len(raw) > 64<<10 || len(encoded) >= 64 {
				clear(raw)
				t.Fatal("actual shared-access audit exceeded its private bounded observation")
			}
			encoded = append(encoded, raw)
		}
		if rows.Err() != nil {
			t.Fatal("actual shared-access audit did not complete its coherent read")
		}
		combined := must(json.Marshal(encoded))
		defer clear(combined)
		return hash(combined), len(encoded)
	}
	var result peerSharedAccessAudit
	result.Access, result.AccessRows = observe(`SELECT json_object('id',id,'network',network_id,'endpoint',endpoint_id,'principal',principal_id,
'native',native_session_id,'node',node_id,'epoch',epoch,'lease_owner',lease_owner,'credential',credential_hash,
'owner_key',owner_key_id,'status',status) FROM network_access_sessions_v2 WHERE network_id=? AND endpoint_id=? ORDER BY id`, network, endpoint)
	result.Group, result.GroupRows = observe(`SELECT json_object('id',id,'endpoint',endpoint_id,'principal',principal_id,'group',group_id,
'native',native_session_id,'node',node_id,'workspace',workspace_id,'epoch',epoch,'lease_owner',lease_owner,
'credential',credential_hash,'status',status,'mode',mode,'capabilities',capabilities_json)
FROM session_bindings WHERE endpoint_id=? ORDER BY id`, endpoint)
	result.Membership, result.MembershipRows = observe(`SELECT json_object('id',id,'network',network_id,'principal',principal_id,
'grants',grants_json,'status',status,'expires',expires_at,'revision',revision) FROM network_memberships_v2
WHERE network_id=? AND principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=?) ORDER BY id`, network, endpoint)
	result.Endpoint, result.EndpointRows = observe(`SELECT json_object('network',network_id,'endpoint',endpoint_id,'status',status,
'revision',revision,'nickname',nickname,'discoverable',discoverable) FROM endpoint_network_memberships_v2
WHERE network_id=? AND endpoint_id=? ORDER BY endpoint_id`, network, endpoint)
	if result.AccessRows != 1 || result.MembershipRows != 1 || result.EndpointRows != 1 {
		t.Fatal("original shared-access fixture does not have its exact existing Network relations")
	}
	return result
}
