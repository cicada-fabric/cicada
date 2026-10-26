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
