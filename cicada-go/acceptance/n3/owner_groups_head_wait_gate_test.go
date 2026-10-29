package n3_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// Synthetic persistent SQLite only. This validates the observation boundary;
// it cannot supply a production head, authority or a Runtime pass.
func TestN3OwnerGroupsNodeHeadWaitUsesOriginalWindow(t *testing.T) {
	const hub, endpoint, group = "SYNTHETIC_HUB", "SYNTHETIC_ENDPOINT", "SYNTHETIC_GROUP"
	expected := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 2, DenyReason: "NONE", PolicyID: strings.Repeat("a", 32), PolicyEpoch: 2}
	path := filepath.Join(t.TempDir(), "synthetic-head.sqlite")
	writer := must(sql.Open("sqlite", path))
	_, err := writer.Exec(`CREATE TABLE node_endpoint_group_heads_v1(hub_id TEXT,endpoint_id TEXT,group_id TEXT,head_json BLOB)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.Exec(`INSERT INTO node_endpoint_group_heads_v1 VALUES(?,?,?,?)`, hub, endpoint, group, must(json.Marshal(expected)))
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
	db := nodePairReadOnlyDB(t, path)
	defer db.Close()
	baseline := must(os.ReadFile(path))
	var events []map[string]any
	observe := func(row map[string]any) { events = append(events, row) }
	check := func(parent, expiry time.Time, want string) {
		t.Helper()
		events = nil
		started := time.Now()
		err := waitOwnerGroupsNodeHead(db, hub, endpoint, group, expected, parent, expiry, func() bool { return true }, observe)
		if want == "" && err != nil || want != "" && (err == nil || err.Error() != want) {
			t.Fatalf("closed outcome=%v want=%s", err, want)
		}
		if len(events) != 2 || events[0]["phase"] != "BEGIN" || events[1]["phase"] != "END" {
			t.Fatal("missing closed begin/end")
		}
		if time.Since(started) > time.Second {
			t.Fatal("query exceeded narrow test bound")
		}
		if !bytes.Equal(baseline, must(os.ReadFile(path))) {
			t.Fatal("read-only wait changed database")
		}
		closed := must(json.Marshal(events))
		for _, private := range []string{hub, endpoint, group, expected.PolicyID} {
			if bytes.Contains(closed, []byte(private)) {
				t.Fatal("head timing exported a private coordinate")
			}
		}
	}
	t.Run("exact_head_inside_original_window", func(t *testing.T) {
		now := time.Now()
		check(now.Add(time.Second), now.Add(time.Second), "")
		if events[1]["outcome"] != "EXACT_HEAD_OBSERVED" || events[1]["query_count"] != 1 {
			t.Fatal("exact head not witnessed")
		}
	})
	t.Run("equal_head_after_expiry_is_failure_without_query", func(t *testing.T) {
		now := time.Now()
		check(now.Add(time.Second), now.Add(-time.Second), "CURRENT_WINDOW_EXPIRED")
		if events[1]["query_count"] != 0 {
			t.Fatal("expired proof performed SQL")
		}
	})
	for _, kind := range []string{"current", "parent"} {
		t.Run("blocked_SQL_uses_"+kind+"_deadline", func(t *testing.T) {
			// Holding the only connection deterministically blocks QueryRowContext
			// before SQLite executes. It must cancel at the original shared bound.
			conn := must(db.Conn(context.Background()))
			defer conn.Close()
			now := time.Now()
			parent, expiry := now.Add(time.Second), now.Add(40*time.Millisecond)
			want := "CURRENT_WINDOW_EXPIRED"
			if kind == "parent" {
				parent, expiry, want = expiry, parent, "TAKEOVER_DEADLINE_EXCEEDED"
			}
			check(parent, expiry, want)
			if events[1]["last_query_code"] != "QUERY_CONTEXT_DONE" || events[1]["query_count"] != 1 {
				t.Fatal("blocked query was not context bounded")
			}
		})
	}
}
