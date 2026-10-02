package nodeinbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	NativeContextPolicyDedicatedThread          = "dedicated_thread"
	NativeContextPolicyDedicatedNetwork         = "dedicated_network"
	NativeContextPolicyGroupScoped              = "group_scoped"
	NativeContextHistoryCoverageCicadaKnownOnly = "CICADA_KNOWN_ONLY"
	NativeContextHistoryCoverageNotChecked      = "NOT_CHECKED"
	nativeContextHistoryPerIdentityCap          = 64
	nativeContextHistoryGlobalCap               = 100000
)

var (
	ErrNativeContextScopeInvalid   = errors.New("native context scope input is invalid")
	ErrNativeContextScopeConflict  = errors.New("native context is dedicated to another scope")
	ErrNativeContextHistoryAtLimit = errors.New("native context scope history reached its safe bound")
	ErrNativeContextRegistryClosed = errors.New("native context registry is closed")
)

// NativeContextScopeInput is built from current, trusted Node and Hub
// authorization records. NativeSessionID is hashed immediately and never
// persisted; no conversation content or filesystem locator is accepted.
type NativeContextScopeInput struct {
	AccountID       string `json:"account_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	HubID           string `json:"hub_id"`
	NetworkID       string `json:"network_id,omitempty"`
	GroupID         string `json:"group_id"`
	ContextPolicy   string `json:"context_policy,omitempty"`
	EndpointID      string `json:"endpoint_id"`
	BindingID       string `json:"binding_id"`
	BindingEpoch    uint64 `json:"binding_epoch"`
}

// NativeContextScopeDecision reports only bounded scope metadata.
// SharedMemoryRisk is true when an ordinary native context has been deliberately
// reused across more than one Cicada scope. NativeHistoryCoverage is always
// CICADA_KNOWN_ONLY for a registry decision: an empty local history does not
// prove that an external Runtime or an unobserved path has no earlier context.
type NativeContextScopeDecision struct {
	Accepted              bool   `json:"accepted"`
	SharedMemoryRisk      bool   `json:"shared_memory_risk"`
	KnownScopeCount       int    `json:"known_scope_count"`
	ContextPolicy         string `json:"context_policy"`
	NativeHistoryCoverage string `json:"native_history_coverage"`
}

type nativeContextHistoryScope struct {
	hubID, networkID, groupID, policy string
}

// NativeContextRegistry must be opened under the common Node WriterRoot, not
// inside a Hub-specific inbox. This metadata-only sidecar lets Hub contexts
// share known native-scope history without mixing their message journals or
// cryptographic state.
type NativeContextRegistry struct {
	db               *sql.DB
	perIdentityCap   int
	globalHistoryCap int
	mu               sync.Mutex
	closed           bool
}

func OpenNativeContextRegistry(path string) (*NativeContextRegistry, error) {
	return openNativeContextRegistry(path, nativeContextHistoryPerIdentityCap, nativeContextHistoryGlobalCap)
}

// openNativeContextRegistry keeps production bounds fixed at Open while
// allowing package tests to exercise capacity behavior with small datasets.
func openNativeContextRegistry(path string, perIdentityCap, globalHistoryCap int) (*NativeContextRegistry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("shared Node context registry path is required")
	}
	if perIdentityCap <= 0 || globalHistoryCap <= 0 {
		return nil, errors.New("native context history bounds must be positive")
	}
	if path != ":memory:" {
		if err := preparePrivateInboxPath(path); err != nil {
			return nil, err
		}
	}
	dsn := "file::memory:"
	if path != ":memory:" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve shared Node context registry: %w", err)
		}
		dsn = (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}).String()
	}
	// Driver options apply the bounded busy handler before its initialization
	// pragmas and acquire the writer reservation before reading scope history.
	// This serializes check-and-record across processes without stale snapshots.
	parameters := url.Values{"_busy_timeout": {"5000"}, "_txlock": {"immediate"}}
	db, err := sql.Open("sqlite", dsn+"?"+parameters.Encode())
	if err != nil {
		return nil, fmt.Errorf("open shared Node context registry: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	// Configure the retained connection before WAL recovery or schema access.
	// Parallel Hub workers can open this shared WriterRoot database together.
	if _, err := db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS node_native_context_history_v1 (
 record_id TEXT PRIMARY KEY, identity_digest TEXT NOT NULL, account_digest TEXT NOT NULL,
 harness TEXT NOT NULL, hub_id TEXT NOT NULL, network_id TEXT NOT NULL, group_id TEXT NOT NULL,
 context_policy TEXT NOT NULL, endpoint_id TEXT NOT NULL, binding_id TEXT NOT NULL,
 binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0), first_seen_ms INTEGER NOT NULL,
 last_seen_ms INTEGER NOT NULL,
 UNIQUE(identity_digest,hub_id,network_id,group_id,context_policy,endpoint_id,binding_id,binding_epoch)
);
CREATE INDEX IF NOT EXISTS node_native_context_identity_v1_idx
 ON node_native_context_history_v1(identity_digest,hub_id,network_id,group_id);
CREATE INDEX IF NOT EXISTS node_native_context_history_cap_v1_idx
 ON node_native_context_history_v1(last_seen_ms,identity_digest);`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize shared Node context registry: %w", err)
	}
	return &NativeContextRegistry{db: db, perIdentityCap: perIdentityCap,
		globalHistoryCap: globalHistoryCap}, nil
}

func (r *NativeContextRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.db.Close()
}

// CheckAndRecordNativeContext enforces known dedicated-scope history and
// appends the current binding to the durable local history. Leave, rebind, or
// new Endpoint creation never deletes previous scope rows.
func (r *NativeContextRegistry) CheckAndRecordNativeContext(ctx context.Context,
	input NativeContextScopeInput) (*NativeContextScopeDecision, error) {
	return r.checkAndRecordNativeContext(ctx, input, false)
}

// CheckAndRecordNetworkEnrollmentContext observes Network enrollment scope,
// not a native writer binding. Access credential rotation keeps its stable
// enrollment binding ID and introduces no new native context. Preserve the
// first actually observed epoch for this exact enrollment/scope/policy and
// refresh only its last-seen time on renewal. Dedicated-scope checks still run
// every time, and genuinely new observations retain the ordinary history caps.
func (r *NativeContextRegistry) CheckAndRecordNetworkEnrollmentContext(ctx context.Context,
	input NativeContextScopeInput) (*NativeContextScopeDecision, error) {
	if strings.TrimSpace(input.GroupID) != "" || strings.TrimSpace(input.NetworkID) == "" {
		return nil, ErrNativeContextScopeInvalid
	}
	return r.checkAndRecordNativeContext(ctx, input, true)
}

func (r *NativeContextRegistry) checkAndRecordNativeContext(ctx context.Context,
	input NativeContextScopeInput, networkEnrollment bool) (*NativeContextScopeDecision, error) {
	input, identityDigest, accountDigest, err := normalizeNativeContextScopeInput(input)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.db == nil {
		return nil, ErrNativeContextRegistryClosed
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin native context history: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT hub_id,network_id,group_id,context_policy
FROM node_native_context_history_v1 WHERE identity_digest=? ORDER BY first_seen_ms,record_id`, identityDigest)
	if err != nil {
		return nil, err
	}
	var scopes []nativeContextHistoryScope
	for rows.Next() {
		var scope nativeContextHistoryScope
		if err := rows.Scan(&scope.hubID, &scope.networkID, &scope.groupID, &scope.policy); err != nil {
			rows.Close()
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	current := nativeContextHistoryScope{hubID: input.HubID, networkID: input.NetworkID,
		groupID: input.GroupID, policy: input.ContextPolicy}
	sharedRisk := false
	knownScopes := make(map[string]struct{}, len(scopes)+1)
	for _, previous := range scopes {
		knownScopes[previous.hubID+"\x00"+previous.networkID+"\x00"+previous.groupID] = struct{}{}
		exact := previous.hubID == current.hubID && previous.networkID == current.networkID && previous.groupID == current.groupID
		sameNetwork := current.networkID != "" && previous.hubID == current.hubID && previous.networkID == current.networkID
		if previous.hubID != current.hubID || previous.networkID != current.networkID || previous.groupID != current.groupID {
			sharedRisk = true
		}
		if nativeContextScopesConflict(previous, current, exact, sameNetwork) {
			return nil, ErrNativeContextScopeConflict
		}
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM node_native_context_history_v1 WHERE identity_digest=?`, identityDigest).Scan(&existing); err != nil {
		return nil, err
	}
	var exactExisting int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM node_native_context_history_v1
WHERE identity_digest=? AND hub_id=? AND network_id=? AND group_id=? AND context_policy=? AND endpoint_id=? AND binding_id=? AND binding_epoch=?`,
		identityDigest, input.HubID, input.NetworkID, input.GroupID, input.ContextPolicy,
		input.EndpointID, input.BindingID, input.BindingEpoch).Scan(&exactExisting); err != nil {
		return nil, err
	}
	var enrollmentRecordID string
	if networkEnrollment {
		err := tx.QueryRowContext(ctx, `SELECT record_id FROM node_native_context_history_v1
WHERE identity_digest=? AND hub_id=? AND network_id=? AND group_id=? AND context_policy=? AND endpoint_id=? AND binding_id=?
ORDER BY first_seen_ms,binding_epoch,record_id LIMIT 1`, identityDigest, input.HubID, input.NetworkID, input.GroupID,
			input.ContextPolicy, input.EndpointID, input.BindingID).Scan(&enrollmentRecordID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if enrollmentRecordID != "" {
			exactExisting = 1
		}
	}
	if existing >= r.perIdentityCap && exactExisting == 0 {
		return nil, ErrNativeContextHistoryAtLimit
	}
	knownScopes[input.HubID+"\x00"+input.NetworkID+"\x00"+input.GroupID] = struct{}{}
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM node_native_context_history_v1`).Scan(&total); err != nil {
		return nil, err
	}
	if total >= r.globalHistoryCap && exactExisting == 0 {
		return nil, ErrNativeContextHistoryAtLimit
	}
	nowMS := time.Now().UTC().UnixMilli()
	if enrollmentRecordID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE node_native_context_history_v1 SET last_seen_ms=? WHERE record_id=?`,
			nowMS, enrollmentRecordID); err != nil {
			return nil, err
		}
	} else {
		recordID, err := randomNativeContextRecordID()
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO node_native_context_history_v1
(record_id,identity_digest,account_digest,harness,hub_id,network_id,group_id,context_policy,
 endpoint_id,binding_id,binding_epoch,first_seen_ms,last_seen_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(identity_digest,hub_id,network_id,group_id,context_policy,endpoint_id,binding_id,binding_epoch)
DO UPDATE SET last_seen_ms=excluded.last_seen_ms`, recordID, identityDigest, accountDigest, input.Harness,
			input.HubID, input.NetworkID, input.GroupID, input.ContextPolicy, input.EndpointID,
			input.BindingID, input.BindingEpoch, nowMS, nowMS)
		if err != nil {
			return nil, fmt.Errorf("record native context scope: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit native context history: %w", err)
	}
	return &NativeContextScopeDecision{Accepted: true, SharedMemoryRisk: sharedRisk,
		KnownScopeCount: len(knownScopes), ContextPolicy: input.ContextPolicy,
		NativeHistoryCoverage: NativeContextHistoryCoverageCicadaKnownOnly}, nil
}

func nativeContextScopesConflict(previous, current nativeContextHistoryScope, exact, sameNetwork bool) bool {
	switch previous.policy {
	case NativeContextPolicyDedicatedThread:
		if !exact {
			return true
		}
	case NativeContextPolicyDedicatedNetwork:
		if !sameNetwork {
			return true
		}
	}
	switch current.policy {
	case NativeContextPolicyDedicatedThread:
		return !exact
	case NativeContextPolicyDedicatedNetwork:
		return !sameNetwork
	default:
		return false
	}
}

func normalizeNativeContextScopeInput(input NativeContextScopeInput) (NativeContextScopeInput,
	string, string, error) {
	input.AccountID = strings.TrimSpace(input.AccountID)
	input.Harness = strings.ToLower(strings.TrimSpace(input.Harness))
	input.NativeSessionID = strings.TrimSpace(input.NativeSessionID)
	input.HubID = strings.TrimSpace(input.HubID)
	input.NetworkID = strings.TrimSpace(input.NetworkID)
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.ContextPolicy = strings.TrimSpace(input.ContextPolicy)
	input.EndpointID = strings.TrimSpace(input.EndpointID)
	input.BindingID = strings.TrimSpace(input.BindingID)
	for _, value := range []string{input.AccountID, input.Harness, input.NativeSessionID, input.HubID,
		input.EndpointID, input.BindingID} {
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return NativeContextScopeInput{}, "", "", ErrNativeContextScopeInvalid
		}
	}
	if (input.NetworkID != "" && (len(input.NetworkID) > 256 || strings.ContainsAny(input.NetworkID, "\x00\r\n"))) ||
		input.BindingEpoch == 0 || (input.GroupID == "" && input.NetworkID == "") ||
		len(input.GroupID) > 256 || strings.ContainsAny(input.GroupID, "\x00\r\n") || (input.ContextPolicy != "" &&
		input.ContextPolicy != NativeContextPolicyGroupScoped &&
		input.ContextPolicy != NativeContextPolicyDedicatedThread &&
		input.ContextPolicy != NativeContextPolicyDedicatedNetwork) ||
		(input.ContextPolicy == NativeContextPolicyDedicatedThread && input.GroupID == "") ||
		(input.ContextPolicy == NativeContextPolicyDedicatedNetwork && input.NetworkID == "") {
		return NativeContextScopeInput{}, "", "", ErrNativeContextScopeInvalid
	}
	identityDigest := nativeContextDigest("identity", input.Harness, input.NativeSessionID)
	accountDigest := nativeContextDigest("account", input.AccountID)
	return input, identityDigest, accountDigest, nil
}

func nativeContextDigest(purpose string, values ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cicada/node/native-context/" + purpose + "/v1\x00"))
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func randomNativeContextRecordID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
