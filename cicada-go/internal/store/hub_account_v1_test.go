package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func TestHubAccountMigrationPreservesExistingOwnerHistoryKeysAndCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	db, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := db.InitializeHubOwnerLocal("Synthetic migration owner", "https://hub.migration.synthetic", false)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	pairing := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: setup.Origin,
		Hub: ownerbootstrap.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: hub.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite},
		Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: setup.AccountID, OwnerID: setup.OwnerID,
			HubID: setup.HubID, AuthorityID: NewID("root"), OperationID: NewID("bootstrap"),
			CandidatePublic: owner.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(owner.Public()),
			ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano)}}
	pairing, nonce, err := ownerbootstrap.CreateChallenge(hub, pairing, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.IssueOwnerBootstrapLocal(pairing, nonce); err != nil {
		t.Fatal(err)
	}
	proof, err := ownerbootstrap.CreateProof(owner, pairing, at)
	if err != nil {
		t.Fatal(err)
	}
	proofHash := sha256.Sum256(proof)
	receipt, err := ownerbootstrap.CreateReceipt(hub, pairing, ownerbootstrap.Receipt{Format: ownerbootstrap.Format,
		ManifestDigest: pairing.Manifest.Digest(), AuthorityID: pairing.Manifest.AuthorityID, AccountID: setup.AccountID,
		OwnerID: setup.OwnerID, KeyID: owner.Public().ID, State: OwnerApprovalKeyActive, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CompleteOwnerBootstrap(pairing.Manifest.AuthorityID, nonce, hex.EncodeToString(proofHash[:]), receipt); err != nil {
		t.Fatal(err)
	}
	clientJSON, err := json.Marshal(client.Public())
	if err != nil {
		t.Fatal(err)
	}
	clientFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(client.Public())
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	requestID := "synthetic-counter-request"
	if _, err = db.db.Exec(`INSERT INTO client_devices_v2(owner_id,device_id,public_identity_json,key_id,key_fingerprint,key_version,owner_key_id,state,version,session_epoch,last_request_sequence,next_response_sequence,created_at,updated_at,revoked_at) VALUES(?,?,?,?,?,1,?,'ACTIVE',1,1,7,10,?,?, '')`, setup.OwnerID, "synthetic-counter-device", string(clientJSON), client.Public().ID, clientFingerprint, owner.Public().ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	requestDigest := strings.Repeat("a", 64)
	if _, err = db.db.Exec(`INSERT INTO client_device_requests_v2(id,owner_id,device_id,session_epoch,sequence,operation_id,route_operation,ciphertext_digest,status,response_packet,created_at,updated_at) VALUES(?,?,?,1,7,?,'status.snapshot',?,'UNCERTAIN',NULL,?,?)`, requestID, setup.OwnerID, "synthetic-counter-device", "synthetic-counter-operation", requestDigest, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`INSERT INTO client_device_request_recovery_v2(request_id,reserved_response_sequence,recovery_packet,created_at,updated_at) VALUES(?,9,NULL,?,?)`, requestID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	priorTables := []string{"hub_owner_setup_v1", "owner_root_history_v1", "owner_bootstrap_authority_v1", "owner_approval_keys_v2", "client_device_hub_config_v2", "client_devices_v2", "client_device_requests_v2", "client_device_request_recovery_v2"}
	prior := make(map[string][][]any, len(priorTables))
	for _, table := range priorTables {
		prior[table] = accountTestRows(t, db.db, table)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}

	// Recreate the exact pre-v61 boundary on this disposable database. Migration
	// 61 adds account tables and must leave v1-v60 identity, trust and sequence
	// records byte-for-byte intact.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"hub_native_pair_node_operations_v1", "hub_native_pair_messages_v1", "hub_native_pair_consents_v1", "hub_native_pair_plans_v1", "hub_native_pair_slots_v1", "hub_native_pair_operations_v1", "hub_native_pair_reads_v1", "hub_native_pair_rates_v1", "hub_native_pair_guard_v1", "hub_native_pairs_v1", "hub_app_node_rates_v1", "hub_app_node_reads_v1", "hub_app_node_provenance_v1", "hub_app_node_operations_v1", "hub_app_node_grants_v1", "hub_app_node_heads_v1", "hub_owner_operations_v1", "hub_app_leases_v1", "hub_owner_activation_v1", "hub_account_requests_v1", "hub_account_sessions_v1", "hub_account_attempts_v1", "hub_account_public_association_v1", "hub_account_devices_v1", "hub_account_credentials_v1", "hub_account_claims_v1", "hub_account_config_v1"} {
		if _, err = raw.Exec(`DROP TABLE IF EXISTS ` + table); err != nil {
			raw.Close()
			t.Fatalf("drop disposable %s: %v", table, err)
		}
	}
	if _, err = raw.Exec(`DELETE FROM schema_migrations_v2 WHERE version>=61`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, table := range priorTables {
		current := accountTestRows(t, reopened.db, table)
		if !reflect.DeepEqual(current, prior[table]) {
			t.Fatalf("schema 61 changed existing %s rows", table)
		}
	}
	entry, err := reopened.readV2Migration(61)
	if err != nil || entry == nil || entry.State != v2MigrationApplied {
		t.Fatalf("schema 61 was not installed after restart: entry=%+v err=%v", entry, err)
	}
}

func TestHubAccountReplayIndexesCoverExactLookupAndRevocation(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.InitializeHubOwnerLocal("Synthetic index owner", "https://hub.index.synthetic", false); err != nil {
		t.Fatal(err)
	}
	plan := func(query string, args ...any) string {
		t.Helper()
		rows, e := db.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if e != nil {
			t.Fatalf("explain %q: %v", query, e)
		}
		defer rows.Close()
		var details []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if e = rows.Scan(&id, &parent, &unused, &detail); e != nil {
				t.Fatal(e)
			}
			details = append(details, detail)
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		return strings.Join(details, " | ")
	}
	checks := []struct {
		name, query, index string
		args               []any
	}{
		{"token digest", `SELECT session_id FROM hub_account_sessions_v1 WHERE token_digest=?`, "hub_account_sessions_v1_token_digest", []any{strings.Repeat("a", 64)}},
		{"session revocation", `UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE account_id=? AND device_id=? AND state='ACTIVE'`, "hub_account_sessions_v1_account_device_state", []any{"account", "device"}},
		{"login receipt", `SELECT attempt_id FROM hub_account_attempts_v1 WHERE purpose='LOGIN' AND state='CONSUMED' AND account_id=? AND device_id=? AND epoch=? AND device_epoch=? AND complete_id=? AND request_digest=?`, "hub_account_attempts_v1_completion_replay", []any{"account", "device", 1, 1, "operation", strings.Repeat("b", 64)}},
		{"session receipt", `SELECT s.session_id FROM hub_account_requests_v1 r JOIN hub_account_sessions_v1 s ON s.session_id=r.session_id WHERE r.operation_id=? AND r.operation=? AND r.request_digest=? AND s.account_id=? AND s.owner_id=? AND s.device_id=?`, "hub_account_requests_v1_operation_replay", []any{"operation", "owner.account.session.logout", strings.Repeat("c", 64), "account", "owner", "device"}},
	}
	for _, check := range checks {
		got := plan(check.query, check.args...)
		if !strings.Contains(got, check.index) {
			t.Errorf("%s query does not use targeted index %s: %s", check.name, check.index, got)
		}
	}
	noncePlan := plan(`SELECT 1 FROM hub_account_requests_v1 r JOIN hub_account_sessions_v1 s ON s.session_id=r.session_id WHERE s.account_id=? AND s.device_id=? AND r.nonce_digest=?`, "account", "device", strings.Repeat("d", 64))
	if !strings.Contains(noncePlan, "hub_account_requests_v1_nonce") {
		t.Errorf("account/device nonce join does not use its nonce index: %s", noncePlan)
	}
	t.Logf("account/device nonce join plan: %s", noncePlan)

	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	digest := strings.Repeat("e", 64)
	if _, err = db.db.Exec(`INSERT INTO hub_account_sessions_v1 VALUES(?,?,?,?,1,1,1,?,'ACTIVE',?)`, "synthetic-session-one", "synthetic-account", "synthetic-owner", "synthetic-device", digest, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`INSERT INTO hub_account_sessions_v1 VALUES(?,?,?,?,1,1,1,?,'ACTIVE',?)`, "synthetic-session-two", "synthetic-account", "synthetic-owner", "synthetic-device", digest, stamp); err == nil {
		t.Fatal("duplicate random token digest was accepted")
	}
}

func TestHubAccountRestoreFencesPendingAuthorityButRetainsCredentialsAndCandidate(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setup, err := db.InitializeHubOwnerLocal("Synthetic restore owner", "https://hub.restore.synthetic", false)
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceJSON, _ := json.Marshal(device.Public())
	candidateJSON, _ := json.Marshal(candidate.Public())
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	deviceID := "accountdev_00000000000000000000000000000001"
	claimID := fmt.Sprintf("%032x", 1)
	claimAttemptID := fmt.Sprintf("%032x", 2)
	loginAttemptID := fmt.Sprintf("%032x", 3)
	prepareID := fmt.Sprintf("%032x", 4)
	claimCodeDigest, hubPin, attemptDigest := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	challengeDigest, prepareNonce := strings.Repeat("d", 64), strings.Repeat("e", 64)
	if _, err = db.db.Exec(`INSERT INTO hub_account_credentials_v1 VALUES(?,?,?,?,?,?,1)`, setup.AccountID, setup.OwnerID, "synthetic-user", "PBKDF2-SHA256-600000-v1", make([]byte, 32), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`INSERT INTO hub_account_devices_v1 VALUES(?,?,?,?,1,'ACTIVE',?)`, setup.AccountID, setup.OwnerID, deviceID, string(deviceJSON), stamp); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(candidate.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`INSERT INTO hub_account_public_association_v1 VALUES(?,?,?,?,'PENDING_PROOF')`, setup.AccountID, setup.OwnerID, string(candidateJSON), fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`INSERT INTO hub_account_claims_v1 VALUES(?,?,?,?,?,?,?,1,'PREPARED',?,?)`, claimID, setup.AccountID, setup.OwnerID, setup.HubID, setup.Origin, hubPin, claimCodeDigest, stamp, claimAttemptID); err != nil {
		t.Fatal(err)
	}
	attemptInsert := `INSERT INTO hub_account_attempts_v1(attempt_id,purpose,claim_id,account_id,owner_id,device_id,public_identity_json,epoch,device_epoch,prepare_id,prepare_digest,challenge_digest,challenge_packet,expires_at,state,prepare_nonce_digest,complete_nonce_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?,?)`
	for _, attempt := range []struct{ id, purpose, claim string }{{claimAttemptID, "CLAIM", claimID}, {loginAttemptID, "LOGIN", ""}} {
		if _, err = db.db.Exec(attemptInsert, attempt.id, attempt.purpose, attempt.claim, setup.AccountID, setup.OwnerID, deviceID, string(deviceJSON), 1, 1, prepareID+attempt.id[1:], attemptDigest, challengeDigest, []byte("synthetic-sealed-challenge"), time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), prepareNonce, ""); err != nil {
			t.Fatal(err)
		}
		// Different attempts must carry different client prepare nonces.
		prepareNonce = strings.Repeat("9", 64)
	}
	sessionID := fmt.Sprintf("%032x", 5)
	tokenDigest := strings.Repeat("8", 64)
	if _, err = db.db.Exec(`INSERT INTO hub_account_sessions_v1 VALUES(?,?,?,?,1,1,1,?,'ACTIVE',?)`, sessionID, setup.AccountID, setup.OwnerID, deviceID, tokenDigest, time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err = db.fenceHubAccountRestore(strings.Repeat("7", 64)); err != nil {
		t.Fatal(err)
	}
	_, epoch, err := db.HubAccountSetup()
	if err != nil || epoch != 2 {
		t.Fatalf("restore did not advance the account auth epoch: epoch=%d err=%v", epoch, err)
	}
	var claimState, claimAttemptState, loginAttemptState, sessionState string
	if err = db.db.QueryRow(`SELECT state FROM hub_account_claims_v1 WHERE claim_id=?`, claimID).Scan(&claimState); err != nil {
		t.Fatal(err)
	}
	if err = db.db.QueryRow(`SELECT state FROM hub_account_attempts_v1 WHERE attempt_id=?`, claimAttemptID).Scan(&claimAttemptState); err != nil {
		t.Fatal(err)
	}
	if err = db.db.QueryRow(`SELECT state FROM hub_account_attempts_v1 WHERE attempt_id=?`, loginAttemptID).Scan(&loginAttemptState); err != nil {
		t.Fatal(err)
	}
	if err = db.db.QueryRow(`SELECT state FROM hub_account_sessions_v1 WHERE session_id=?`, sessionID).Scan(&sessionState); err != nil {
		t.Fatal(err)
	}
	if claimState != "CANCELLED" || claimAttemptState != "CANCELLED" || loginAttemptState != "CANCELLED" || sessionState != "REVOKED" {
		t.Fatalf("restore left stale account authority: claim=%s claimAttempt=%s loginAttempt=%s session=%s", claimState, claimAttemptState, loginAttemptState, sessionState)
	}
	var retainedCredential, retainedDevice, retainedCandidate int
	if err = db.db.QueryRow(`SELECT count(*) FROM hub_account_credentials_v1 WHERE account_id=?`, setup.AccountID).Scan(&retainedCredential); err != nil {
		t.Fatal(err)
	}
	if err = db.db.QueryRow(`SELECT count(*) FROM hub_account_devices_v1 WHERE account_id=? AND status='ACTIVE'`, setup.AccountID).Scan(&retainedDevice); err != nil {
		t.Fatal(err)
	}
	if err = db.db.QueryRow(`SELECT count(*) FROM hub_account_public_association_v1 WHERE account_id=? AND public_identity_json=? AND state='PENDING_PROOF'`, setup.AccountID, string(candidateJSON)).Scan(&retainedCandidate); err != nil {
		t.Fatal(err)
	}
	if retainedCredential != 1 || retainedDevice != 1 || retainedCandidate != 1 {
		t.Fatal("restore fencing discarded the password credential, registered device or pending Owner candidate")
	}
}

func accountTestRows(t *testing.T, db *sql.DB, table string) [][]any {
	t.Helper()
	rows, err := db.Query(`SELECT * FROM ` + table + ` ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	result := [][]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		for i, value := range values {
			if blob, ok := value.([]byte); ok {
				values[i] = append([]byte(nil), blob...)
			}
		}
		result = append(result, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
