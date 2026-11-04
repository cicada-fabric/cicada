package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
)

func isMCPFacadeOperationTool(name string) bool {
	return isMCPFacadeOperationStatus(name) || name == "cicada_operation_retry" || name == "cicada_outbox_retry"
}

func isMCPFacadeOperationStatus(name string) bool {
	return name == "cicada_operation_status" || name == "cicada_outbox_status"
}

// Historical lookup is separate from the mutable store opener: no schema
// upgrade, pin replacement, row update, dispatch or current-membership match.
// mode=ro retains SQLite's WAL visibility; immutable=1 would miss live unknown
// requests and could hide a cross-Hub ID collision. Only original private paths
// from verified discovery are used, and all result/input columns are bounded.
func readMCPFacadeOperation(pin LocalNodeConnectionPin, native mcpTrustedContext, id string) (mcpOutboxOperation, LocalNodeConnectionPin, error) {
	var zero mcpOutboxOperation
	var original LocalNodeConnectionPin
	if validateLocalNodePin(pin) != nil || !sameMCPRouteThread(native, native) || !localContextText(id, 128) {
		return zero, original, errMCPOutboxContext
	}
	before, err := codexOperatorPrivateFile(pin.MCPOutboxStateFile, true)
	if err != nil {
		return zero, original, errMCPOutboxPersistence
	}
	if before == nil {
		return zero, original, errMCPOutboxNotFound
	}
	db, err := sql.Open("sqlite", mcpOutboxSQLiteURI(pin.MCPOutboxStateFile, "mode=ro"))
	if err != nil {
		return zero, original, errMCPOutboxPersistence
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return zero, original, errMCPOutboxPersistence
	}
	defer tx.Rollback()
	var format string
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT format,CASE WHEN length(CAST(pin AS BLOB))<=? THEN pin ELSE NULL END FROM mcp_outbox_connection_pin WHERE slot=1`, localNodeMaxPinBytes).Scan(&format, &raw); err != nil || format != mcpOutboxConnectionFormat ||
		decodeLocalNodeJSON(raw, &original) != nil || validateLocalNodePin(original) != nil || !sameMCPFacadeHistoricalStore(pin, original) {
		return zero, original, errMCPOriginalGroupRoute
	}
	var op mcpOutboxOperation
	err = scanMCPOutboxOperation(tx.QueryRowContext(ctx, `SELECT operation_id, kind, status, api_origin, scope, harness, native_session_id,
node_id, workspace, endpoint_id, group_id, network_id, idempotency_key, input_json,
input_digest, attempt_count, last_error, result_json, created_at, updated_at,codex_domain_binding
FROM mcp_outbox_operations WHERE operation_id=? AND harness=? AND native_session_id=? AND node_id=? AND workspace=?
AND length(CAST(input_json AS BLOB))<=? AND length(CAST(result_json AS BLOB))<=? AND length(CAST(last_error AS BLOB))<=?
AND length(CAST(codex_domain_binding AS BLOB))<=?`, id, native.Harness, native.NativeSessionID, pin.NodeID, native.Workspace,
		mcpOutboxMaxInputBytes, mcpOutboxMaxResultBytes, mcpOutboxMaxErrorBytes, 16<<10), &op)
	if errors.Is(err, sql.ErrNoRows) {
		var exists int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM mcp_outbox_operations WHERE operation_id=? AND harness=? AND native_session_id=? AND node_id=? AND workspace=?`, id, native.Harness, native.NativeSessionID, pin.NodeID, native.Workspace).Scan(&exists) != nil || exists != 0 {
			return zero, original, errMCPOutboxPersistence
		}
		return zero, original, errMCPOutboxNotFound
	}
	if err != nil {
		return zero, original, errMCPOutboxPersistence
	}
	after, err := os.Lstat(pin.MCPOutboxStateFile)
	if err != nil || !os.SameFile(before, after) {
		return zero, original, errMCPOutboxPersistence
	}
	scope, _, err := mcpSessionScope(pin.APIOrigin, harness.SessionContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, MachineID: pin.NodeID, Workspace: native.Workspace})
	if err != nil || op.APIOrigin != pin.APIOrigin || op.Scope != scope || op.EndpointGroupsVersion != 1 || op.GroupID == "" {
		return zero, original, errMCPOutboxContext
	}
	relation := op.EndpointGroupAuthority.Relation
	registration := e2ee.EndpointGroupRegistration{HubID: pin.HubID, OwnerID: relation.OwnerID, NodeID: pin.NodeID, Harness: op.Harness, NativeSessionID: op.NativeSessionID,
		Workspace: op.Workspace, EndpointID: op.EndpointID, PrincipalID: relation.PrincipalID}
	digest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	inputDigest := sha256.Sum256([]byte(op.InputJSON))
	if err != nil || digest != op.RegistrationDigest || relation.HubID != pin.HubID || relation.NodeID != pin.NodeID || relation.EndpointID != op.EndpointID || relation.GroupID != op.GroupID ||
		!localContextText(relation.NetworkID, 256) || op.NetworkID != "" && op.NetworkID != relation.NetworkID || !json.Valid([]byte(op.InputJSON)) || hex.EncodeToString(inputDigest[:]) != op.InputDigest ||
		op.ResultJSON != "" && !json.Valid([]byte(op.ResultJSON)) {
		return zero, original, errMCPOutboxContext
	}
	return op, original, nil
}

func validateMCPFacadeOperationArguments(arguments map[string]any) error {
	if len(arguments) != 1 || !localContextText(stringArgument(arguments, "operation_id"), 128) {
		return errMCPOutboxContext
	}
	return nil
}

func sameMCPFacadeHistoricalStore(a, b LocalNodeConnectionPin) bool {
	return a.UserRoot == b.UserRoot && a.HubID == b.HubID && a.APIOrigin == b.APIOrigin && a.NodeID == b.NodeID &&
		a.SocketPath == b.SocketPath && a.StateDir == b.StateDir && a.WriterRoot == b.WriterRoot && a.MCPSessionStateFile == b.MCPSessionStateFile && a.MCPOutboxStateFile == b.MCPOutboxStateFile &&
		a.Binding.HubKeyID == b.Binding.HubKeyID && a.Binding.HubFingerprint == b.Binding.HubFingerprint && a.Binding.HubKeyVersion == b.Binding.HubKeyVersion
}

func locateMCPFacadeOperation(connections []LocalNodeConnection, native mcpTrustedContext, id string) ([]LocalNodeConnection, error) {
	var found []LocalNodeConnection
	for _, connection := range connections {
		_, _, err := readMCPFacadeOperation(connection.Pin, native, id)
		if errors.Is(err, errMCPOutboxNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		found = append(found, connection)
	}
	if len(found) == 0 {
		return nil, errMCPOutboxNotFound
	}
	if len(found) != 1 {
		return nil, errMCPGroupRouteAmbiguous
	}
	return found, nil
}

func (m *mcpServer) facadeOperationStatus(native harness.SessionContext, verified localCodexContext, business map[string]any) (any, error) {
	if m.localNode == nil || verified.EndpointGroupsVersion != 1 {
		return nil, errCodexMCPContext
	}
	op, _, err := readMCPFacadeOperation(m.localNode.Pin, mcpTrustedContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace}, stringArgument(business, "operation_id"))
	if err != nil {
		return nil, err
	}
	if verified.RegistrationDigest != op.RegistrationDigest {
		return nil, errMCPOriginalGroupRoute
	}
	return mcpOutboxPublicResult(op), nil
}

func (m *mcpServer) facadeOperationRetry(native harness.SessionContext, verified localCodexContext, fresh *localEndpointGroupsResult, business map[string]any) (any, error) {
	if m.localNode == nil || verified.EndpointGroupsVersion != 1 {
		return nil, errCodexMCPContext
	}
	op, originalPin, err := readMCPFacadeOperation(m.localNode.Pin, mcpTrustedContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace}, stringArgument(business, "operation_id"))
	if err != nil {
		return nil, err
	}
	if verified.RegistrationDigest != op.RegistrationDigest {
		return nil, errMCPOriginalGroupRoute
	}
	if op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
		return mcpOutboxPublicResult(op), nil
	}
	if fresh == nil {
		return nil, errMCPOriginalGroupRoute
	}
	if validateCodexStoredArtifact(context.Background(), originalPin, m.localNode.Pin, m.adoptConnection, m.retainedArtifacts) != nil {
		return nil, errMCPOriginalGroupRoute
	}
	current, err := codexContextBinding(verified)
	if err != nil || current != op.codexDomainBinding {
		return nil, errMCPOutboxContext
	}
	// New membership, policy or keys cannot lend an old packet authority. The
	// exact original source must still be current before marking an attempt.
	found, seen := false, false
	for _, authority := range fresh.Description.Authorities {
		if authority.Relation.GroupID == op.GroupID {
			seen, found = true, authority == op.EndpointGroupAuthority
			break
		}
	}
	for _, relation := range fresh.Description.Relations {
		if relation.GroupID == op.GroupID {
			seen = true
			break
		}
	}
	if !found && (seen || fresh.Description.Complete) {
		return nil, errMCPOutboxContext
	}
	// An unseen partial page is not authorization or absence. Keep the exact
	// original authority in the immutable operation; the original Node repeats
	// its targeted current-source Guard before any dispatch/queue write.
	m.sessionMu.Lock()
	if m.endpointID != op.EndpointID || m.sessionPublic.BindingID != op.NativeBindingID || m.sessionPublic.BindingEpoch != op.NativeBindingEpoch || m.sessionToken == "" {
		m.sessionMu.Unlock()
		return nil, errMCPOutboxContext
	}
	selected, authority, public := m.sessionGroupID, m.sessionEndpointGroupAuthority, m.sessionPublic
	// The explicit operation ID chooses its saved Group for this dispatch only.
	// This neither changes the Thread selection nor persists a new grant.
	m.sessionGroupID, m.sessionEndpointGroupAuthority = op.GroupID, op.EndpointGroupAuthority
	m.sessionPublic.Endpoint.GroupID, m.sessionPublic.NetworkCard.GroupID = op.GroupID, op.GroupID
	m.sessionMu.Unlock()
	defer func() {
		m.sessionMu.Lock()
		m.sessionGroupID, m.sessionEndpointGroupAuthority, m.sessionPublic = selected, authority, public
		m.sessionMu.Unlock()
	}()
	scope, err := m.currentMCPOutboxScope()
	if err != nil || !mcpOutboxScopeMatches(op, scope) {
		return nil, errMCPOutboxContext
	}
	store, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	// Re-read after the read-only locator: an exact concurrent retry may have
	// completed. Existing store CAS and the original Node Guard still apply.
	op, err = store.load(scope, op.OperationID)
	if err != nil {
		return nil, err
	}
	if op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPOutbox(store, scope, op)
}
