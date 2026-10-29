package n3_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// Observation only: the same retained Current and the parent takeover deadline
// bound every SQL read. An equal head after either deadline is still a failure.
func waitOwnerGroupsNodeHead(db *sql.DB, hub, endpoint, group string, expected e2ee.EndpointGroupOwnerControl, parentDeadline, currentExpiry time.Time, running func() bool, observe func(map[string]any)) (result error) {
	started := time.Now()
	deadline := parentDeadline
	if currentExpiry.Before(deadline) {
		deadline = currentExpiry
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	queries := 0
	var queryElapsed, maxQueryElapsed time.Duration
	lastCode, lastHash, lastMode := "NOT_READ", "", ""
	var lastRevision uint64
	emit := func(phase, outcome string) {
		now := time.Now()
		observe(map[string]any{"phase": phase, "outcome": outcome, "actual_wall": now.UTC().Format(time.RFC3339Nano),
			"elapsed_ms": now.Sub(started).Milliseconds(), "query_count": queries, "query_total_ms": queryElapsed.Milliseconds(), "query_max_ms": maxQueryElapsed.Milliseconds(),
			"last_query_code": lastCode, "head_sha256": lastHash, "head_mode": lastMode, "head_revision": lastRevision,
			"parent_deadline": parentDeadline.UTC().Format(time.RFC3339Nano), "current_expires_at": currentExpiry.UTC().Format(time.RFC3339Nano),
			"current_remaining_ms": currentExpiry.Sub(now).Milliseconds()})
	}
	expired := func() error {
		if !time.Now().Before(currentExpiry) {
			return errors.New("CURRENT_WINDOW_EXPIRED")
		}
		if !time.Now().Before(parentDeadline) || ctx.Err() != nil {
			return errors.New("TAKEOVER_DEADLINE_EXCEEDED")
		}
		return nil
	}
	emit("BEGIN", "WAITING")
	defer func() {
		outcome := "EXACT_HEAD_OBSERVED"
		if result != nil {
			outcome = result.Error()
		}
		emit("END", outcome)
	}()
	for {
		if err := expired(); err != nil {
			return err
		}
		var raw []byte
		queryStarted := time.Now()
		err := db.QueryRowContext(ctx, `SELECT head_json FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND endpoint_id=? AND group_id=?`, hub, endpoint, group).Scan(&raw)
		elapsed := time.Since(queryStarted)
		queries++
		queryElapsed += elapsed
		if elapsed > maxQueryElapsed {
			maxQueryElapsed = elapsed
		}
		var head e2ee.EndpointGroupOwnerControl
		valid := false
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			lastCode = "QUERY_CONTEXT_DONE"
		case errors.Is(err, sql.ErrNoRows):
			lastCode = "NO_ROWS"
		case err != nil:
			lastCode = "QUERY_ERROR"
		case json.Unmarshal(raw, &head) != nil || e2ee.ValidateEndpointGroupOwnerControl(head) != nil:
			lastCode = "INVALID_HEAD"
		default:
			lastCode, lastHash, lastMode, lastRevision = "HEAD_READ", hash(must(json.Marshal(head))), head.Mode, head.Revision
			valid = true
		}
		clear(raw)
		if err := expired(); err != nil {
			return err
		}
		if valid && head == expected {
			return nil
		}
		if !running() {
			return errors.New("NODE_STOPPED")
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
