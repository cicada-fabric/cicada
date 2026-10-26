package n3_test

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// Closed coordinates let the implementation owner compare authority lineages
// without exporting a grant, key, token, request, response or message body.
func ownerGroupsCoordinate(r wire.EndpointGroupRelation, head *e2ee.EndpointGroupOwnerControl) map[string]any {
	result := map[string]any{"endpoint_sha256": hash([]byte(r.EndpointID)), "group_sha256": hash([]byte(r.GroupID)),
		"source": r.Source, "state": r.State, "authority_sha256": hash([]byte(r.AuthorityID)), "authority_epoch": r.AuthorityEpoch,
		"contribution_revision": r.ContributionRevision, "decision_revision": r.DecisionRevision,
		"policy_sha256": hash([]byte(r.PolicyID)), "policy_epoch": r.PolicyEpoch, "registration_revision": r.RegistrationRevision,
		"binding_epoch": r.BindingEpoch, "membership_revision": r.MembershipRevision, "endpoint_join_revision": r.EndpointJoinRevision,
		"candidate_version": r.CandidateVersion, "owner_control_digest": r.OwnerControlDigest}
	if head != nil {
		result["head"] = map[string]any{"mode": head.Mode, "revision": head.Revision, "deny_reason": head.DenyReason,
			"policy_sha256": hash([]byte(head.PolicyID)), "policy_epoch": head.PolicyEpoch}
	}
	return result
}

func ownerGroupsAuditDB(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

func ownerGroupsNodeCoordinates(path string) map[string]any {
	result := map[string]any{"available": false}
	db, err := ownerGroupsAuditDB(path)
	if err != nil {
		return result
	}
	defer db.Close()
	rows, err := db.Query(`SELECT head_json,identity_json FROM node_endpoint_group_heads_v1 ORDER BY endpoint_id,group_id LIMIT 129`)
	if err != nil {
		return result
	}
	var heads, sources []map[string]any
	for rows.Next() {
		var headRaw, relationRaw []byte
		var head e2ee.EndpointGroupOwnerControl
		var relation wire.EndpointGroupRelation
		err := rows.Scan(&headRaw, &relationRaw)
		valid := err == nil && len(headRaw) <= 64<<10 && len(relationRaw) <= 64<<10 &&
			json.Unmarshal(headRaw, &head) == nil && json.Unmarshal(relationRaw, &relation) == nil
		clear(headRaw)
		clear(relationRaw)
		if !valid || len(heads) >= 128 {
			rows.Close()
			return result
		}
		heads = append(heads, ownerGroupsCoordinate(relation, &head))
	}
	if rows.Err() != nil || rows.Close() != nil {
		return result
	}
	rows, err = db.Query(`SELECT relation_json FROM node_endpoint_group_sources_v1 ORDER BY endpoint_id,group_id,source LIMIT 129`)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var relation wire.EndpointGroupRelation
		err := rows.Scan(&raw)
		valid := err == nil && len(raw) <= 64<<10 && json.Unmarshal(raw, &relation) == nil
		clear(raw)
		if !valid || len(sources) >= 128 {
			return result
		}
		sources = append(sources, ownerGroupsCoordinate(relation, nil))
	}
	if rows.Err() == nil {
		result["available"], result["heads"], result["sources"] = true, heads, sources
	}
	return result
}

func ownerGroupsOutboxDiagnostics(path string) map[string]any {
	result := map[string]any{"available": false}
	db, err := ownerGroupsAuditDB(path)
	if err != nil {
		return result
	}
	defer db.Close()
	rows, err := db.Query(`SELECT operation_id,kind,status,endpoint_id,group_id,attempt_count,last_error,input_digest FROM mcp_outbox_operations ORDER BY created_at DESC LIMIT 128`)
	if err != nil {
		return result
	}
	defer rows.Close()
	var operations []map[string]any
	for rows.Next() {
		var id, kind, state, endpoint, group, lastError, inputDigest string
		var attempts int
		if rows.Scan(&id, &kind, &state, &endpoint, &group, &attempts, &lastError, &inputDigest) != nil {
			return result
		}
		row := map[string]any{"operation_sha256": hash([]byte(id)), "kind": kind, "status": state,
			"endpoint_sha256": hash([]byte(endpoint)), "group_sha256": hash([]byte(group)), "attempts": attempts,
			"error_sha256": hash([]byte(lastError)), "input_digest": inputDigest}
		if lastError == nodekeys.ErrEndpointGroupsConflict.Error() {
			row["known_error"] = "nodekeys.ErrEndpointGroupsConflict"
		}
		operations = append(operations, row)
	}
	if rows.Err() == nil {
		result["available"], result["operations"] = true, operations
	}
	return result
}

func ownerGroupsAuditLocalCoordinates(v *codexProductFixture) map[string]any {
	return map[string]any{"node": ownerGroupsNodeCoordinates(filepath.Join(ownerGroupsNodeRoot(v), "node-crypto-state.sqlite")),
		"outbox":      ownerGroupsOutboxDiagnostics(filepath.Join(filepath.Dir(v.mcpState), "outbox.sqlite3")),
		"relay_inbox": ownerGroupsInboxDiagnostics(filepath.Join(ownerGroupsNodeRoot(v), "inbox.sqlite")),
		"local_inbox": ownerGroupsInboxDiagnostics(filepath.Join(ownerGroupsNodeRoot(v), "local-inbox.sqlite3"))}
}

func ownerGroupsInboxDiagnostics(path string) map[string]any {
	result := map[string]any{"available": false}
	db, err := ownerGroupsAuditDB(path)
	if err != nil {
		return result
	}
	defer db.Close()
	rows, err := db.Query(`SELECT d.message_id,d.endpoint_id,d.session_id,d.binding_epoch,d.state,
COALESCE(g.group_id,''),COALESCE(r.kind,''),COALESCE(r.request_id,''),COALESCE(d.failure,''),d.updated_at
FROM node_inbox_deliveries d LEFT JOIN node_inbox_message_groups g ON g.message_id=d.message_id
LEFT JOIN node_inbox_message_routes r ON r.message_id=d.message_id ORDER BY d.updated_at DESC LIMIT 128`)
	if err != nil {
		return result
	}
	defer rows.Close()
	var deliveries []map[string]any
	counts := map[string]int{}
	for rows.Next() {
		var message, endpoint, sid, state, group, kind, request, failure, updated string
		var epoch uint64
		if rows.Scan(&message, &endpoint, &sid, &epoch, &state, &group, &kind, &request, &failure, &updated) != nil {
			return result
		}
		counts[state]++
		deliveries = append(deliveries, map[string]any{"message_sha256": hash([]byte(message)),
			"endpoint_sha256": hash([]byte(endpoint)), "sid_sha256": hash([]byte(sid)), "binding_epoch": epoch,
			"state": state, "group_sha256": hash([]byte(group)), "kind": kind, "request_sha256": hash([]byte(request)),
			"failure_present": failure != "", "failure_sha256": hash([]byte(failure)), "updated_at": updated})
	}
	if rows.Err() == nil {
		result["available"], result["state_counts"], result["deliveries"] = true, counts, deliveries
	}
	return result
}
