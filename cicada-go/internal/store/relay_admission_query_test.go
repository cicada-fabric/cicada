package store

import (
	"bytes"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRelayAskExpiryOrderKeyMatchesRFC3339NanoAdmissionSemantics(t *testing.T) {
	cases := []struct {
		name, expiry, current string
	}{
		{"future", "2026-10-08T12:00:00.000000001Z", "2026-10-08T12:00:00Z"},
		{"offset same instant", "2026-10-08T13:00:00+01:00", "2026-10-08T12:00:00Z"},
		{"offset future nanosecond", "2026-10-08T13:00:00.000000001+01:00", "2026-10-08T12:00:00Z"},
		{"exact equality", "2026-10-08T12:00:00Z", "2026-10-08T12:00:00Z"},
		{"past nanosecond", "2026-10-08T11:59:59.999999999Z", "2026-10-08T12:00:00Z"},
		{"unbounded", "", "9999-12-31T23:59:59.999999999Z"},
		{"year zero", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"},
		{"year zero before local boundary", "0000-01-01T00:00:00+01:00", "0000-01-01T00:00:00Z"},
		{"year 9999", "9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59.999999998Z"},
		{"invalid expiry", "synthetic-invalid-time", "2026-10-08T12:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cutoff, valid := relayAskExpiryCutoff(tc.current)
			if !valid {
				t.Fatalf("fixture cutoff did not parse: %q", tc.current)
			}
			key := relayAskExpiryOrderKey(tc.expiry)
			got := key != nil && bytes.Compare(key, cutoff) > 0
			want := networkExpiryAllows(tc.expiry, mustParseExpiryTime(t, tc.current))
			if got != want {
				t.Fatalf("indexed comparison=%v want existing RFC3339Nano semantics=%v", got, want)
			}
			if key != nil && len(key) != 12 {
				t.Fatalf("expiry key length=%d, want 12", len(key))
			}
		})
	}
	if _, valid := relayAskExpiryCutoff("synthetic-invalid-current-time"); valid {
		t.Fatal("invalid current time was accepted")
	}
}

func mustParseExpiryTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestRelayAskExpiryExpressionReturnsBlobOrSQLNull(t *testing.T) {
	s := newRelayAdmissionIndexTestStore(t)
	defer s.Close()
	var validType, invalidType, blankType string
	var validLength, blankLength int
	var blankKey []byte
	if err := s.db.QueryRow(`SELECT typeof(cicada_relay_expiry_order_key_v1(?)),
typeof(cicada_relay_expiry_order_key_v1(?)), length(cicada_relay_expiry_order_key_v1(?)),
typeof(cicada_relay_expiry_order_key_v1('')), length(cicada_relay_expiry_order_key_v1('')),
cicada_relay_expiry_order_key_v1('')`,
		"2026-10-08T12:00:00Z", "synthetic-invalid-time", "2026-10-08T12:00:00Z").Scan(&validType, &invalidType, &validLength, &blankType, &blankLength, &blankKey); err != nil {
		t.Fatal(err)
	}
	if validType != "blob" || invalidType != "null" || validLength != 12 || blankType != "blob" || blankLength != 12 || !bytes.Equal(blankKey, relayUnboundedExpiryOrderKey) {
		t.Fatalf("expiry key SQLite types=%q/%q/%q lengths=%d/%d blank=%x", validType, invalidType, blankType, validLength, blankLength, blankKey)
	}
}

func TestRelayPendingAskCountScopesUseExpiryIndexRange(t *testing.T) {
	s := newRelayAdmissionIndexTestStore(t)
	defer s.Close()
	cutoff := "2026-10-08T12:00:00Z"
	for _, scope := range []string{
		RelayAdmissionScopeSenderEndpoint,
		RelayAdmissionScopeSenderPrincipal,
		RelayAdmissionScopeSenderGroup,
		RelayAdmissionScopeReceiver,
		RelayAdmissionScopeGlobal,
	} {
		query, ok := relayPendingAskCountSQL(scope)
		if !ok {
			t.Fatalf("missing query for scope %q", scope)
		}
		args := []any{FabricRequestOpen, FabricRequestCancelRequested, relayAskOrderTestTimeKey(t, cutoff)}
		if scope != RelayAdmissionScopeGlobal {
			args = append(args, "synthetic-scope")
		}
		rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			t.Fatalf("explain scope %s: %v", scope, err)
		}
		var details []string
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			details = append(details, strings.ToLower(detail))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		plan := strings.Join(details, " ")
		compactPlan := strings.Join(strings.Fields(plan), "")
		usesExpiryExpression := strings.Contains(plan, "<expr>") || strings.Contains(plan, relayAskExpiryOrderKeyFunction)
		if !strings.Contains(plan, "search") || !strings.Contains(plan, relayAskExpiryOrderIndex) || !strings.Contains(compactPlan, "state=?") || !usesExpiryExpression || !strings.Contains(compactPlan, ">?") {
			t.Fatalf("scope %s did not use indexed expiry range: %s", scope, plan)
		}
	}
}

func TestRelayPendingAskCountPreservesStateScopeAndExpiryRules(t *testing.T) {
	s := newRelayAdmissionIndexTestStore(t)
	defer s.Close()
	cutoff := "2026-10-08T12:00:00Z"
	target := relayQuotaTestScope{endpoint: "target-endpoint", principal: "target-principal", group: "target-group", receiver: "target-receiver"}
	rows := []relayQuotaTestRow{
		{"live_open", FabricRequestOpen, "2026-10-08T12:00:00.000000001Z", target},
		{"live_cancel", FabricRequestCancelRequested, "2026-10-08T13:00:00.000000001+01:00", target},
		{"unbounded", FabricRequestOpen, "", target},
		{"exact", FabricRequestOpen, cutoff, target},
		{"past", FabricRequestOpen, "2026-10-08T11:59:59.999999999Z", target},
		{"malformed", FabricRequestOpen, "synthetic-invalid-time", target},
		{"terminal", FabricRequestReplied, "2026-10-08T13:00:00Z", target},
		{"unrelated", FabricRequestOpen, "2026-10-08T13:00:00Z", relayQuotaTestScope{"other-endpoint", "other-principal", "other-group", "other-receiver"}},
	}
	seedRelayQuotaTestRows(t, s, rows)

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	checks := []struct {
		scope string
		want  int
	}{
		{RelayAdmissionScopeSenderEndpoint, 3},
		{RelayAdmissionScopeSenderPrincipal, 3},
		{RelayAdmissionScopeSenderGroup, 3},
		{RelayAdmissionScopeReceiver, 3},
		{RelayAdmissionScopeGlobal, 4},
	}
	for _, check := range checks {
		got, err := relayPendingAskCountTx(tx, check.scope, target.endpoint, target.principal, target.group, target.receiver, cutoff)
		if err != nil || got != check.want {
			t.Errorf("scope %s count=%d want=%d err=%v", check.scope, got, check.want, err)
		}
	}
	for _, invalidCutoff := range []string{"", "synthetic-invalid-current-time"} {
		got, err := relayPendingAskCountTx(tx, RelayAdmissionScopeGlobal, target.endpoint, target.principal, target.group, target.receiver, invalidCutoff)
		if err != nil || got != 0 {
			t.Errorf("invalid cutoff %q count=%d want=0 err=%v", invalidCutoff, got, err)
		}
	}
	if _, err := relayPendingAskCountTx(tx, "synthetic-unknown-scope", "", "", "", "", "synthetic-invalid-current-time"); err == nil {
		t.Error("unknown scope was accepted when the cutoff was invalid")
	}
}

type relayQuotaTestScope struct {
	endpoint, principal, group, receiver string
}

type relayQuotaTestRow struct {
	id, state, expires string
	scope              relayQuotaTestScope
}

func newRelayAdmissionIndexTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func relayAskOrderTestTimeKey(t *testing.T, value string) []byte {
	t.Helper()
	key, ok := relayAskExpiryCutoff(value)
	if !ok {
		t.Fatalf("invalid synthetic cutoff %q", value)
	}
	return key
}

func seedRelayQuotaTestRows(t testing.TB, s *Store, rows []relayQuotaTestRow) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	message, err := tx.Prepare(`INSERT INTO fabric_messages(id,from_endpoint_id,to_endpoint_id,kind,body,created_at)
VALUES(?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer message.Close()
	request, err := tx.Prepare(`INSERT INTO relay_v2_requests
(request_id,message_id,sender_endpoint_id,sender_principal_id,sender_group_id,receiver_endpoint_id,receiver_group_id,digest,state,expires_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	for _, row := range rows {
		messageID := "synthetic_quota_message_" + row.id
		if _, err := message.Exec(messageID, row.scope.endpoint, row.scope.receiver, "ask", "synthetic body", "2026-10-08T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		if _, err := request.Exec(row.id, messageID, row.scope.endpoint, row.scope.principal, row.scope.group,
			row.scope.receiver, "synthetic_receiver_group", "synthetic_digest", row.state, row.expires,
			"2026-10-08T00:00:00Z", "2026-10-08T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkRelayAdmissionCountHistoricalBacklog(b *testing.B) {
	for _, expiredCount := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("expired=%d", expiredCount), func(b *testing.B) {
			s, err := New(b.TempDir() + "/state/cicada.sqlite3")
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			rows := make([]relayQuotaTestRow, 0, expiredCount+16)
			expiredScope := relayQuotaTestScope{"historical-endpoint", "historical-principal", "historical-group", "historical-receiver"}
			for i := 0; i < expiredCount; i++ {
				state := FabricRequestOpen
				if i%2 == 1 {
					state = FabricRequestCancelRequested
				}
				rows = append(rows, relayQuotaTestRow{
					id: fmt.Sprintf("expired_%05d", i), state: state,
					expires: "2000-01-01T00:00:00Z", scope: expiredScope,
				})
			}
			for i := 0; i < 16; i++ {
				rows = append(rows, relayQuotaTestRow{
					id: fmt.Sprintf("live_%02d", i), state: FabricRequestOpen,
					expires: "2026-10-09T00:00:00Z",
					scope: relayQuotaTestScope{
						endpoint:  fmt.Sprintf("unrelated-endpoint-%02d", i),
						principal: fmt.Sprintf("unrelated-principal-%02d", i),
						group:     fmt.Sprintf("unrelated-group-%02d", i),
						receiver:  fmt.Sprintf("unrelated-receiver-%02d", i),
					},
				})
			}
			seedRelayQuotaTestRows(b, s, rows)
			tx, err := s.db.Begin()
			if err != nil {
				b.Fatal(err)
			}
			security := RelayMessageSecurity{
				SenderEndpointID: "target-endpoint", SenderPrincipalID: "target-principal",
				SenderGroupID: "target-group", ReceiverEndpointID: "target-receiver",
			}
			limits := RelayAdmissionLimits{PerSenderPrincipal: 64, PerSenderGroup: 256, PerReceiver: 64, Global: 1024, RetryAfterSeconds: 1}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := relayCheckPendingAskQuotaTx(tx, security, limits, "2026-10-08T12:00:00Z"); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			var logicalPages, pageSize int64
			if err := tx.QueryRow(`PRAGMA page_count`).Scan(&logicalPages); err != nil {
				b.Fatal(err)
			}
			if err := tx.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(logicalPages*pageSize), "db-logical-B")
			if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
				b.Fatal(err)
			}
		})
	}
}
