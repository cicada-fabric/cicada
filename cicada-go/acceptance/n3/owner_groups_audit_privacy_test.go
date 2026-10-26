package n3_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// Synthetic SQLite observation test only. It cannot create a Hub grant or
// satisfy a Runtime case. Private diagnostic strings must remain unexported.
func TestN3OwnerGroupsOutboxAuditRetainsOnlyClosedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-outbox.sqlite3")
	db := must(sql.Open("sqlite", path))
	_, err := db.Exec(`CREATE TABLE mcp_outbox_operations(operation_id TEXT,kind TEXT,status TEXT,endpoint_id TEXT,
group_id TEXT,attempt_count INTEGER,last_error TEXT,input_digest TEXT,created_at TEXT,session_token TEXT)`)
	if err != nil {
		t.Fatal("synthetic audit table unavailable")
	}
	const sentinel = "SYNTHETIC_PRIVATE_ERROR_BODY_MUST_NOT_EXPORT"
	for index, message := range []string{sentinel, nodekeys.ErrEndpointGroupsConflict.Error()} {
		_, err := db.Exec(`INSERT INTO mcp_outbox_operations VALUES(?,'ask','FAILED','SYNTHETIC_ENDPOINT','SYNTHETIC_GROUP',1,?,?,?,'SYNTHETIC_PRIVATE_TOKEN_MUST_NOT_EXPORT')`,
			index, message, hash([]byte("SYNTHETIC_INTENT")), index)
		if err != nil {
			t.Fatal("synthetic closed observation unavailable")
		}
	}
	db.Close()
	before := must(os.ReadFile(path))
	result := ownerGroupsOutboxDiagnostics(path)
	raw := must(json.Marshal(result))
	if result["available"] != true || !bytes.Contains(raw, []byte("nodekeys.ErrEndpointGroupsConflict")) ||
		!bytes.Contains(raw, []byte(hash([]byte(sentinel)))) || bytes.Contains(raw, []byte(sentinel)) ||
		bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_TOKEN_MUST_NOT_EXPORT")) {
		t.Fatal("closed observation lost its refusal or exported private content")
	}
	if !bytes.Equal(before, must(os.ReadFile(path))) {
		t.Fatal("readonly audit modified its synthetic persistent source")
	}
}

func TestN3OwnerGroupsInboxAuditRetainsOnlyClosedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-inbox.sqlite")
	db := must(sql.Open("sqlite", path))
	for _, statement := range []string{
		`CREATE TABLE node_inbox_deliveries(message_id TEXT,endpoint_id TEXT,session_id TEXT,binding_epoch INTEGER,state TEXT,failure TEXT,updated_at TEXT,payload TEXT)`,
		`CREATE TABLE node_inbox_message_groups(message_id TEXT,group_id TEXT)`,
		`CREATE TABLE node_inbox_message_routes(message_id TEXT,kind TEXT,request_id TEXT)`,
		`INSERT INTO node_inbox_deliveries VALUES('SYNTHETIC_MESSAGE','SYNTHETIC_ENDPOINT','SYNTHETIC_SID',2,'CONSUMPTION_UNCONFIRMED','SYNTHETIC_PRIVATE_FAILURE','2026-10-26T00:00:00Z','SYNTHETIC_PRIVATE_PAYLOAD')`,
		`INSERT INTO node_inbox_message_groups VALUES('SYNTHETIC_MESSAGE','SYNTHETIC_GROUP')`,
		`INSERT INTO node_inbox_message_routes VALUES('SYNTHETIC_MESSAGE','REPLY','SYNTHETIC_REQUEST')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal("synthetic inbox observation unavailable")
		}
	}
	db.Close()
	before := must(os.ReadFile(path))
	result := ownerGroupsInboxDiagnostics(path)
	raw := must(json.Marshal(result))
	if result["available"] != true || !bytes.Contains(raw, []byte(`"kind":"REPLY"`)) ||
		!bytes.Contains(raw, []byte(`"binding_epoch":2`)) || !bytes.Contains(raw, []byte("CONSUMPTION_UNCONFIRMED")) {
		t.Fatal("closed inbox observation lost its delivery coordinates")
	}
	for _, private := range []string{"SYNTHETIC_MESSAGE", "SYNTHETIC_ENDPOINT", "SYNTHETIC_SID", "SYNTHETIC_GROUP", "SYNTHETIC_REQUEST", "SYNTHETIC_PRIVATE_FAILURE", "SYNTHETIC_PRIVATE_PAYLOAD"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("closed inbox observation exported private content")
		}
	}
	if !bytes.Contains(raw, []byte(hash([]byte("SYNTHETIC_PRIVATE_FAILURE")))) || !bytes.Equal(before, must(os.ReadFile(path))) {
		t.Fatal("readonly inbox observation lost the failure digest or modified its source")
	}
	missing := filepath.Join(t.TempDir(), "missing-inbox.sqlite")
	if ownerGroupsInboxDiagnostics(missing)["available"] != false {
		t.Fatal("missing inbox reported available")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("readonly inbox observation initialized missing state")
	}
}
