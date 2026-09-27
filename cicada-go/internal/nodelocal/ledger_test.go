package nodelocal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSchemaV1MigratesToV2PreservingRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ledger-v1.sqlite")
	fixture, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	route := testRoute("ASK", "ep-v1-source", "ep-v1-target")
	routeJSON, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := []byte("preserved v1 ciphertext")
	digest := sha256.Sum256(ciphertext)
	expiresAt := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Microsecond)
	acceptedAt := time.Now().UTC().Truncate(time.Microsecond)
	for _, statement := range []string{
		"CREATE TABLE node_local_schema (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL)",
		"INSERT INTO node_local_schema(singleton, version) VALUES (1, 1)",
		"CREATE TABLE node_local_messages (message_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('SEND','ASK','REPLY')), request_id TEXT NOT NULL DEFAULT '', reply_to_message_id TEXT NOT NULL DEFAULT '', digest BLOB NOT NULL CHECK(length(digest) = 32), route_json TEXT NOT NULL, source_endpoint_id TEXT NOT NULL, target_endpoint_id TEXT NOT NULL, target_session_id TEXT NOT NULL, target_binding_epoch INTEGER NOT NULL CHECK(target_binding_epoch > 0), scope TEXT NOT NULL, ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0), delivery_state TEXT NOT NULL CHECK(delivery_state IN ('PENDING','NODE_INBOX_ACCEPTED','LATE')), expires_at_us INTEGER, accepted_at_us INTEGER NOT NULL, handed_off_at_us INTEGER)",
		"CREATE INDEX node_local_pending_idx ON node_local_messages(target_endpoint_id, delivery_state, accepted_at_us, message_id)",
		"CREATE UNIQUE INDEX node_local_one_ask_per_request_idx ON node_local_messages(request_id) WHERE kind = 'ASK'",
		"CREATE UNIQUE INDEX node_local_one_reply_per_request_idx ON node_local_messages(request_id) WHERE kind = 'REPLY'",
		"CREATE TABLE node_local_requests (request_id TEXT PRIMARY KEY, ask_message_id TEXT NOT NULL UNIQUE REFERENCES node_local_messages(message_id), source_endpoint_id TEXT NOT NULL, target_endpoint_id TEXT NOT NULL, source_group_id TEXT NOT NULL, target_group_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at_us INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('OPEN','ANSWERED','CANCELLED','EXPIRED')), created_at_us INTEGER NOT NULL, updated_at_us INTEGER NOT NULL, cancelled_at_us INTEGER, answered_at_us INTEGER, reply_message_id TEXT NOT NULL DEFAULT '')",
		"CREATE INDEX node_local_request_deadline_idx ON node_local_requests(state, expires_at_us)",
	} {
		if _, err := fixture.ExecContext(ctx, statement); err != nil {
			_ = fixture.Close()
			t.Fatalf("create v1 fixture: %v", err)
		}
	}
	if _, err := fixture.ExecContext(ctx, "INSERT INTO node_local_messages(message_id, kind, request_id, reply_to_message_id, digest, route_json, source_endpoint_id, target_endpoint_id, target_session_id, target_binding_epoch, scope, ciphertext, delivery_state, expires_at_us, accepted_at_us) VALUES (?, 'ASK', ?, '', ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)",
		"msg-v1-ask", "rq_v1_existing", digest[:], string(routeJSON), route.SourceEndpointID, route.TargetEndpointID,
		route.TargetSessionID, route.TargetBindingEpoch, route.Scope, ciphertext, expiresAt.UnixMicro(), acceptedAt.UnixMicro()); err != nil {
		_ = fixture.Close()
		t.Fatalf("insert v1 message: %v", err)
	}
	if _, err := fixture.ExecContext(ctx, "INSERT INTO node_local_requests(request_id, ask_message_id, source_endpoint_id, target_endpoint_id, source_group_id, target_group_id, scope, expires_at_us, state, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)",
		"rq_v1_existing", "msg-v1-ask", route.SourceEndpointID, route.TargetEndpointID, route.SourceGroupID, route.TargetGroupID,
		route.Scope, expiresAt.UnixMicro(), acceptedAt.UnixMicro(), acceptedAt.UnixMicro()); err != nil {
		_ = fixture.Close()
		t.Fatalf("insert v1 request: %v", err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err := Open(path)
	if err != nil {
		t.Fatalf("open and migrate v1 ledger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	var version int
	if err := ledger.db.QueryRowContext(ctx, "SELECT version FROM node_local_schema WHERE singleton = 1").Scan(&version); err != nil || version != 2 {
		t.Fatalf("migrated schema version = %d, err=%v", version, err)
	}
	message, err := ledger.GetMessage(ctx, "msg-v1-ask")
	if err != nil || message.State != DeliveryPending || message.Digest != hex.EncodeToString(digest[:]) || string(message.Ciphertext) != string(ciphertext) || message.RejectionCode != "" || !message.RejectedAt.IsZero() {
		t.Fatalf("v1 message after migration = %+v, err=%v", message, err)
	}
	if message.Route.SourceEndpointID != route.SourceEndpointID || message.Route.TargetEndpointID != route.TargetEndpointID {
		t.Fatalf("v1 route was not preserved: %+v", message.Route)
	}
	request, err := ledger.GetRequest(ctx, "rq_v1_existing")
	if err != nil || request.State != RequestOpen || request.MessageID != "msg-v1-ask" || request.Scope != route.Scope {
		t.Fatalf("v1 request after migration = %+v, err=%v", request, err)
	}
	pending, err := ledger.PendingAll(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].MessageID != "msg-v1-ask" || string(pending[0].Ciphertext) != string(ciphertext) {
		t.Fatalf("v1 pending row after migration = %+v, err=%v", pending, err)
	}
	var terminalState, rejectionCode string
	var rejectedAt sql.NullInt64
	if err := ledger.db.QueryRowContext(ctx, "SELECT terminal_state, rejection_code, rejected_at_us FROM node_local_messages WHERE message_id = ?", "msg-v1-ask").Scan(&terminalState, &rejectionCode, &rejectedAt); err != nil {
		t.Fatal(err)
	}
	if terminalState != "" || rejectionCode != "" || rejectedAt.Valid {
		t.Fatalf("v1 terminal defaults = state %q, code %q, rejectedAt %+v", terminalState, rejectionCode, rejectedAt)
	}
}

func TestFreshSchemaV2AndUnknownFutureVersionFailsClosed(t *testing.T) {
	ctx := context.Background()
	fresh := openTestLedger(t, filepath.Join(t.TempDir(), "fresh.sqlite"))
	var version int
	if err := fresh.db.QueryRowContext(ctx, "SELECT version FROM node_local_schema WHERE singleton = 1").Scan(&version); err != nil || version != 2 {
		t.Fatalf("fresh schema version = %d, err=%v", version, err)
	}

	futurePath := filepath.Join(t.TempDir(), "future.sqlite")
	future, err := sql.Open("sqlite", futurePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.ExecContext(ctx, "CREATE TABLE node_local_schema (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := future.ExecContext(ctx, "INSERT INTO node_local_schema(singleton, version) VALUES (1, 99)"); err != nil {
		t.Fatal(err)
	}
	if err := future.Close(); err != nil {
		t.Fatal(err)
	}
	if ledger, err := Open(futurePath); err == nil {
		_ = ledger.Close()
		t.Fatal("unknown future schema version was accepted")
	}
	check, err := sql.Open("sqlite", futurePath)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	if err := check.QueryRowContext(ctx, "SELECT version FROM node_local_schema WHERE singleton = 1").Scan(&version); err != nil || version != 99 {
		t.Fatalf("future schema version changed = %d, err=%v", version, err)
	}
	var messageTableCount int
	if err := check.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'node_local_messages'").Scan(&messageTableCount); err != nil || messageTableCount != 0 {
		t.Fatalf("future schema was modified with message table count %d, err=%v", messageTableCount, err)
	}
}

func TestSendIdempotencyAndImmutableRoute(t *testing.T) {
	ctx := context.Background()
	ledger := openTestLedger(t, filepath.Join(t.TempDir(), "ledger.sqlite"))
	route := testRoute("SEND", "ep-a", "ep-b")
	ciphertext := []byte("sealed body a")
	input := MessageInput{MessageID: "msg-send-1", Route: route, Ciphertext: ciphertext}

	first, err := ledger.AcceptSend(ctx, input)
	if err != nil || !first.Created || first.State != DeliveryPending {
		t.Fatalf("first SEND acceptance = %+v, err=%v", first, err)
	}
	ciphertext[0] = 'X'
	route.AuthorizationValidUntil = time.Now().Add(2 * time.Minute)
	second, err := ledger.AcceptSend(ctx, MessageInput{MessageID: "msg-send-1", Route: route, Ciphertext: []byte("sealed body a")})
	if err != nil || second.Created || second.Digest != first.Digest {
		t.Fatalf("exact retry = %+v, err=%v", second, err)
	}
	stored, err := ledger.GetMessage(ctx, "msg-send-1")
	if err != nil || string(stored.Ciphertext) != "sealed body a" {
		t.Fatalf("stored ciphertext = %q, err=%v", stored.Ciphertext, err)
	}
	if !stored.Route.AuthorizationValidUntil.Before(route.AuthorizationValidUntil) {
		t.Fatal("idempotent retry rewrote the original authorization snapshot")
	}

	conflictingRoute := route
	conflictingRoute.TargetGroupID = "group-other"
	if _, err := ledger.AcceptSend(ctx, MessageInput{MessageID: "msg-send-1", Route: conflictingRoute, Ciphertext: []byte("sealed body a")}); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("route conflict error = %v", err)
	}
	secret := "secret-plaintext-should-not-appear"
	_, err = ledger.AcceptSend(ctx, MessageInput{MessageID: "msg-send-1", Route: route, Ciphertext: []byte(secret)})
	if !errors.Is(err, ErrMessageConflict) || strings.Contains(err.Error(), secret) {
		t.Fatalf("payload conflict leaked body or missed conflict: %v", err)
	}

	expired := testRoute("SEND", "ep-a", "ep-b")
	expired.AuthorizationValidUntil = time.Now().Add(-time.Second)
	if _, err := ledger.AcceptSend(ctx, MessageInput{MessageID: "msg-expired-auth", Route: expired, Ciphertext: []byte("sealed")}); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("expired new authorization error = %v", err)
	}
}

func TestAskPersistsAtomicallyAndRecoversPendingAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	ledger := openTestLedger(t, path)
	expiresAt := time.Now().Add(5 * time.Minute)
	askRoute := testRoute("ASK", "ep-a", "ep-b")
	accepted, err := ledger.AcceptAsk(ctx, AskInput{
		MessageInput: MessageInput{MessageID: "msg-ask-1", Route: askRoute, Ciphertext: []byte("sealed ask")},
		RequestID:    "rq_operation_1", ExpiresAt: expiresAt,
	})
	if err != nil || !accepted.Created || accepted.RequestID != "rq_operation_1" {
		t.Fatalf("ASK acceptance = %+v, err=%v", accepted, err)
	}

	// A retried MCP operation keeps the caller-derived request ID and refreshes
	// only the short authorization deadline.
	retryRoute := askRoute
	retryRoute.AuthorizationValidUntil = time.Now().Add(2 * time.Minute)
	retried, err := ledger.AcceptAsk(ctx, AskInput{
		MessageInput: MessageInput{MessageID: "msg-ask-1", Route: retryRoute, Ciphertext: []byte("sealed ask")},
		RequestID:    "rq_operation_1", ExpiresAt: expiresAt,
	})
	if err != nil || retried.Created || retried.RequestID != accepted.RequestID {
		t.Fatalf("ASK retry = %+v, err=%v", retried, err)
	}
	if _, err := ledger.AcceptAsk(ctx, AskInput{
		MessageInput: MessageInput{MessageID: "msg-ask-other", Route: retryRoute, Ciphertext: []byte("sealed ask")},
		RequestID:    "rq_operation_1", ExpiresAt: expiresAt,
	}); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("reused request ID with another ASK error = %v", err)
	}
	if _, err := ledger.AcceptAsk(ctx, AskInput{
		MessageInput: MessageInput{MessageID: "msg-ask-1", Route: retryRoute, Ciphertext: []byte("different sealed ask")},
		RequestID:    "rq_operation_1", ExpiresAt: expiresAt,
	}); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("reused ASK message ID with another digest error = %v", err)
	}
	request, err := ledger.GetRequest(ctx, accepted.RequestID)
	if err != nil || request.MessageID != "msg-ask-1" || request.SourceEndpointID != "ep-a" ||
		request.TargetEndpointID != "ep-b" || request.Scope != askRoute.Scope || request.State != RequestOpen {
		t.Fatalf("persisted request = %+v, err=%v", request, err)
	}
	if !request.ExpiresAt.Equal(time.UnixMicro(expiresAt.UTC().UnixMicro()).UTC()) {
		t.Fatalf("request deadline = %s, want %s", request.ExpiresAt, expiresAt)
	}
	pending, err := ledger.Pending(ctx, "ep-b", 20)
	if err != nil || len(pending) != 1 || pending[0].MessageID != "msg-ask-1" || string(pending[0].Ciphertext) != "sealed ask" {
		t.Fatalf("pending ASK = %+v, err=%v", pending, err)
	}
	if err := ledger.MarkNodeInboxAccepted(ctx, accepted.MessageID, accepted.Digest); err != nil {
		t.Fatalf("mark nodeinbox acceptance: %v", err)
	}
	sendRoute := testRoute("SEND", "ep-c", "ep-d")
	if _, err := ledger.AcceptSend(ctx, MessageInput{MessageID: "msg-pending-send", Route: sendRoute, Ciphertext: []byte("sealed pending send")}); err != nil {
		t.Fatalf("accept second target SEND: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen ledger: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	pending, err = reopened.PendingAll(ctx, 20)
	if err != nil || len(pending) != 1 || pending[0].MessageID != "msg-pending-send" || pending[0].Route.TargetEndpointID != "ep-d" {
		t.Fatalf("PendingAll after restart = %+v, err=%v", pending, err)
	}
	message, err := reopened.GetMessage(ctx, "msg-ask-1")
	if err != nil || message.Kind != KindAsk || message.RequestID != accepted.RequestID || message.State != DeliveryHandedOff ||
		message.Route.TargetSessionID != "native-ep-b" || string(message.Ciphertext) != "sealed ask" {
		t.Fatalf("recovered message = %+v, err=%v", message, err)
	}
	recoveredRequest, err := reopened.GetRequest(ctx, accepted.RequestID)
	if err != nil || recoveredRequest.State != RequestOpen || recoveredRequest.Route.SourceBindingID != "binding-ep-a" {
		t.Fatalf("recovered request = %+v, err=%v", recoveredRequest, err)
	}
}

func TestConcurrentRepliesStayCorrelatedAndOnlyOneFinalReplyWins(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	firstLedger := openTestLedger(t, path)
	secondLedger, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondLedger.Close() })

	taskA := acceptTestAsk(t, firstLedger, "msg-ask-a", "rq_ask_a", "ep-a", "ep-b")
	taskB := acceptTestAsk(t, firstLedger, "msg-ask-b", "rq_ask_b", "ep-c", "ep-d")
	var wait sync.WaitGroup
	errCh := make(chan error, 2)
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, err := firstLedger.AcceptReply(ctx, ReplyInput{
			MessageInput: MessageInput{MessageID: "msg-reply-a", Route: reverseTestRoute(taskA.Route), Ciphertext: []byte("sealed reply a")},
			RequestID:    taskA.RequestID, ReplyToMessageID: taskA.MessageID,
		})
		errCh <- err
	}()
	go func() {
		defer wait.Done()
		_, err := secondLedger.AcceptReply(ctx, ReplyInput{
			MessageInput: MessageInput{MessageID: "msg-reply-b", Route: reverseTestRoute(taskB.Route), Ciphertext: []byte("sealed reply b")},
			RequestID:    taskB.RequestID, ReplyToMessageID: taskB.MessageID,
		})
		errCh <- err
	}()
	wait.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent independent reply failed: %v", err)
		}
	}

	requestA, err := firstLedger.GetRequest(ctx, taskA.RequestID)
	if err != nil || requestA.ReplyMessageID != "msg-reply-a" || requestA.State != RequestAnswered {
		t.Fatalf("request A association = %+v, err=%v", requestA, err)
	}
	requestB, err := firstLedger.GetRequest(ctx, taskB.RequestID)
	if err != nil || requestB.ReplyMessageID != "msg-reply-b" || requestB.State != RequestAnswered {
		t.Fatalf("request B association = %+v, err=%v", requestB, err)
	}
	duplicateReply, err := firstLedger.AcceptReply(ctx, ReplyInput{
		MessageInput: MessageInput{MessageID: "msg-reply-a", Route: reverseTestRoute(taskA.Route), Ciphertext: []byte("sealed reply a")},
		RequestID:    taskA.RequestID, ReplyToMessageID: taskA.MessageID,
	})
	if err != nil || duplicateReply.Created || duplicateReply.RequestID != taskA.RequestID {
		t.Fatalf("idempotent REPLY retry = %+v, err=%v", duplicateReply, err)
	}
	if _, err := firstLedger.AcceptReply(ctx, ReplyInput{
		MessageInput: MessageInput{MessageID: "msg-reply-wrong-correlation", Route: reverseTestRoute(taskA.Route), Ciphertext: []byte("sealed wrong reply")},
		RequestID:    taskA.RequestID, ReplyToMessageID: taskB.MessageID,
	}); !errors.Is(err, ErrInvalidReply) {
		t.Fatalf("reply pointing at a concurrent ASK error = %v", err)
	}

	competing := acceptTestAsk(t, firstLedger, "msg-ask-race", "rq_ask_race", "ep-r1", "ep-r2")
	replyRoute := reverseTestRoute(competing.Route)
	start := make(chan struct{})
	errCh = make(chan error, 2)
	wait.Add(2)
	for i, ledger := range []*Ledger{firstLedger, secondLedger} {
		messageID := []string{"msg-race-reply-a", "msg-race-reply-b"}[i]
		go func(ledger *Ledger, messageID string) {
			defer wait.Done()
			<-start
			_, err := ledger.AcceptReply(ctx, ReplyInput{
				MessageInput: MessageInput{MessageID: messageID, Route: replyRoute, Ciphertext: []byte("sealed competing reply")},
				RequestID:    competing.RequestID, ReplyToMessageID: competing.MessageID,
			})
			errCh <- err
		}(ledger, messageID)
	}
	close(start)
	wait.Wait()
	close(errCh)
	acceptedCount := 0
	closedCount := 0
	for err := range errCh {
		switch {
		case err == nil:
			acceptedCount++
		case errors.Is(err, ErrRequestAlreadyAnswered):
			closedCount++
		default:
			t.Fatalf("competing final reply error = %v", err)
		}
	}
	if acceptedCount != 1 || closedCount != 1 {
		t.Fatalf("competing reply outcomes: accepted=%d already-answered=%d", acceptedCount, closedCount)
	}
}

func TestCancelledAndExpiredAsksRetainLateRepliesWithoutHandoff(t *testing.T) {
	ctx := context.Background()
	ledger := openTestLedger(t, filepath.Join(t.TempDir(), "ledger.sqlite"))

	cancelled := acceptTestAsk(t, ledger, "msg-ask-cancel", "rq_cancel", "ep-a", "ep-b")
	if _, err := ledger.CancelRequest(ctx, cancelled.RequestID, "ep-wrong"); !errors.Is(err, ErrNotRequester) {
		t.Fatalf("wrong requester cancellation error = %v", err)
	}
	if _, err := ledger.CancelRequest(ctx, cancelled.RequestID, "ep-a"); err != nil {
		t.Fatalf("cancel request: %v", err)
	}
	if _, err := ledger.CancelRequest(ctx, cancelled.RequestID, "ep-a"); err != nil {
		t.Fatalf("idempotent cancellation: %v", err)
	}
	if pending, err := ledger.Pending(ctx, "ep-b", 10); err != nil || len(pending) != 0 {
		t.Fatalf("cancelled ASK remained pending: %+v, err=%v", pending, err)
	}
	late, err := ledger.AcceptReply(ctx, ReplyInput{
		MessageInput: MessageInput{MessageID: "msg-reply-late-cancel", Route: reverseTestRoute(cancelled.Route), Ciphertext: []byte("sealed late reply")},
		RequestID:    cancelled.RequestID, ReplyToMessageID: cancelled.MessageID,
	})
	if err != nil || late.State != DeliveryLate {
		t.Fatalf("late reply after cancellation = %+v, err=%v", late, err)
	}
	if pending, err := ledger.Pending(ctx, "ep-a", 10); err != nil || len(pending) != 0 {
		t.Fatalf("late reply entered pending handoff: %+v, err=%v", pending, err)
	}
	storedLate, err := ledger.GetMessage(ctx, late.MessageID)
	if err != nil || storedLate.State != DeliveryLate || storedLate.RequestID != cancelled.RequestID ||
		storedLate.ReplyToMessageID != cancelled.MessageID || string(storedLate.Ciphertext) != "sealed late reply" {
		t.Fatalf("late reply evidence = %+v, err=%v", storedLate, err)
	}
	duplicateLate, err := ledger.AcceptReply(ctx, ReplyInput{
		MessageInput: MessageInput{MessageID: "msg-reply-late-cancel", Route: reverseTestRoute(cancelled.Route), Ciphertext: []byte("sealed late reply")},
		RequestID:    cancelled.RequestID, ReplyToMessageID: cancelled.MessageID,
	})
	if err != nil || duplicateLate.Created || duplicateLate.State != DeliveryLate {
		t.Fatalf("duplicate late reply = %+v, err=%v", duplicateLate, err)
	}
	request, err := ledger.GetRequest(ctx, cancelled.RequestID)
	if err != nil || request.State != RequestCancelled || request.ReplyMessageID != "" ||
		len(request.LateReplyMessageIDs) != 1 || request.LateReplyMessageIDs[0] != late.MessageID {
		t.Fatalf("cancelled request was reopened by late reply: %+v, err=%v", request, err)
	}

	expiring := acceptTestAsk(t, ledger, "msg-ask-expire", "rq_expire", "ep-c", "ep-d")
	changed, err := ledger.ExpireRequests(ctx, time.Now().Add(10*time.Minute))
	if err != nil || changed != 1 {
		t.Fatalf("expire request count=%d, err=%v", changed, err)
	}
	lateExpired, err := ledger.AcceptReply(ctx, ReplyInput{
		MessageInput: MessageInput{MessageID: "msg-reply-late-expired", Route: reverseTestRoute(expiring.Route), Ciphertext: []byte("sealed expired reply")},
		RequestID:    expiring.RequestID, ReplyToMessageID: expiring.MessageID,
	})
	if err != nil || lateExpired.State != DeliveryLate {
		t.Fatalf("late reply after expiry = %+v, err=%v", lateExpired, err)
	}
	if pending, err := ledger.Pending(ctx, "ep-d", 10); err != nil || len(pending) != 0 {
		t.Fatalf("expired ASK or late reply remained pending: %+v, err=%v", pending, err)
	}
	expiredRequest, err := ledger.GetRequest(ctx, expiring.RequestID)
	if err != nil || expiredRequest.State != RequestExpired || expiredRequest.ReplyMessageID != "" ||
		len(expiredRequest.LateReplyMessageIDs) != 1 || expiredRequest.LateReplyMessageIDs[0] != lateExpired.MessageID {
		t.Fatalf("expired request was reopened by late reply: %+v, err=%v", expiredRequest, err)
	}
}

func TestRejectPendingIsDurableIdempotentAndTerminal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	ledger := openTestLedger(t, path)

	accepted, err := ledger.AcceptSend(ctx, MessageInput{
		MessageID:  "msg-reject-send",
		Route:      testRoute("SEND", "ep-source", "ep-target"),
		Ciphertext: []byte("sealed rejected payload"),
	})
	if err != nil || !accepted.Created {
		t.Fatalf("accept SEND before rejection: %+v, err=%v", accepted, err)
	}
	if err := ledger.RejectPending(ctx, accepted.MessageID, strings.Repeat("0", 64), "ROUTE_REVOKED"); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("wrong-digest rejection error = %v", err)
	}
	pending, err := ledger.PendingAll(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].MessageID != accepted.MessageID {
		t.Fatalf("wrong digest changed pending state: %+v, err=%v", pending, err)
	}
	if err := ledger.RejectPending(ctx, accepted.MessageID, accepted.Digest, "ROUTE_REVOKED"); err != nil {
		t.Fatalf("reject pending SEND: %v", err)
	}
	if err := ledger.RejectPending(ctx, accepted.MessageID, accepted.Digest, "ROUTE_REVOKED"); err != nil {
		t.Fatalf("duplicate rejection was not idempotent: %v", err)
	}
	if err := ledger.RejectPending(ctx, accepted.MessageID, accepted.Digest, "KEY_REVOKED"); !errors.Is(err, ErrRejectConflict) {
		t.Fatalf("conflicting rejection code error = %v", err)
	}
	if err := ledger.RejectPending(ctx, accepted.MessageID, accepted.Digest, "peer payload secret"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("free-form rejection reason error = %v", err)
	}
	if pending, err := ledger.PendingAll(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("rejected SEND remained pending: %+v, err=%v", pending, err)
	}
	stored, err := ledger.GetMessage(ctx, accepted.MessageID)
	if err != nil || stored.State != DeliveryRejected || stored.RejectionCode != "ROUTE_REVOKED" || stored.RejectedAt.IsZero() {
		t.Fatalf("durable rejection record = %+v, err=%v", stored, err)
	}
	if err := ledger.MarkNodeInboxAccepted(ctx, accepted.MessageID, accepted.Digest); !errors.Is(err, ErrNotPending) {
		t.Fatalf("rejected SEND was handed off: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen ledger after rejection: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	stored, err = reopened.GetMessage(ctx, accepted.MessageID)
	if err != nil || stored.State != DeliveryRejected || stored.RejectionCode != "ROUTE_REVOKED" || stored.RejectedAt.IsZero() {
		t.Fatalf("recovered rejection record = %+v, err=%v", stored, err)
	}

	ask := acceptTestAsk(t, reopened, "msg-reject-ask", "rq_reject_ask", "ep-asker", "ep-answerer")
	askRecord, err := reopened.GetMessage(ctx, ask.MessageID)
	if err != nil {
		t.Fatalf("read ASK before rejection: %v", err)
	}
	if err := reopened.RejectPending(ctx, ask.MessageID, askRecord.Digest, "TARGET_REVOKED"); err != nil {
		t.Fatalf("reject pending ASK: %v", err)
	}
	request, err := reopened.GetRequest(ctx, ask.RequestID)
	if err != nil || request.State != RequestRejected {
		t.Fatalf("rejected ASK request state = %+v, err=%v", request, err)
	}
	if pending, err := reopened.Pending(ctx, "ep-answerer", 10); err != nil || len(pending) != 0 {
		t.Fatalf("rejected ASK remained pending: %+v, err=%v", pending, err)
	}
	lateReply, err := reopened.AcceptReply(ctx, ReplyInput{
		MessageInput: MessageInput{MessageID: "msg-reply-after-reject", Route: reverseTestRoute(ask.Route), Ciphertext: []byte("sealed late reply")},
		RequestID:    ask.RequestID, ReplyToMessageID: ask.MessageID,
	})
	if err != nil || lateReply.State != DeliveryLate {
		t.Fatalf("reply after rejected ASK = %+v, err=%v", lateReply, err)
	}
	if pending, err := reopened.Pending(ctx, "ep-asker", 10); err != nil || len(pending) != 0 {
		t.Fatalf("late reply after rejected ASK remained pending: %+v, err=%v", pending, err)
	}
}

func TestAskMessageAndRequestCommitAtomically(t *testing.T) {
	ctx := context.Background()
	ledger := openTestLedger(t, filepath.Join(t.TempDir(), "ledger.sqlite"))
	if _, err := ledger.db.Exec("CREATE TRIGGER fail_local_request BEFORE INSERT ON node_local_requests BEGIN SELECT RAISE(ABORT, 'request storage unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	input := AskInput{
		MessageInput: MessageInput{MessageID: "msg-atomic-ask", Route: testRoute("ASK", "ep-a", "ep-b"), Ciphertext: []byte("sealed atomic ask")},
		RequestID:    "rq_atomic", ExpiresAt: time.Now().Add(time.Minute),
	}
	if _, err := ledger.AcceptAsk(ctx, input); err == nil {
		t.Fatal("request insert failure was accepted")
	}
	if _, err := ledger.GetMessage(ctx, input.MessageID); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("failed ASK left its message row: %v", err)
	}
	if _, err := ledger.db.Exec("DROP TRIGGER fail_local_request"); err != nil {
		t.Fatal(err)
	}
	accepted, err := ledger.AcceptAsk(ctx, input)
	if err != nil || !accepted.Created || accepted.RequestID != input.RequestID {
		t.Fatalf("retry after atomic rollback = %+v, err=%v", accepted, err)
	}
}

func openTestLedger(t *testing.T, path string) *Ledger {
	t.Helper()
	ledger, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func acceptTestAsk(t *testing.T, ledger *Ledger, messageID, requestID, source, target string) Request {
	t.Helper()
	accepted, err := ledger.AcceptAsk(context.Background(), AskInput{
		MessageInput: MessageInput{MessageID: messageID, Route: testRoute("ASK", source, target), Ciphertext: []byte("sealed ask body")},
		RequestID:    requestID, ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	if err != nil || !accepted.Created {
		t.Fatalf("accept test ASK: accepted=%+v err=%v", accepted, err)
	}
	request, err := ledger.GetRequest(context.Background(), requestID)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testRoute(action, source, target string) Route {
	now := time.Now().UTC()
	return Route{
		SourceOwnerID: "owner-" + source, TargetOwnerID: "owner-" + target,
		SourceNodeID: "node-local", TargetNodeID: "node-local",
		SourcePrincipalID: "principal-" + source, TargetPrincipalID: "principal-" + target,
		SourceEndpointID: source, TargetEndpointID: target,
		SourceGroupID: "group-" + source, TargetGroupID: "group-" + target,
		SourceMembershipRevision: 1, TargetMembershipRevision: 2,
		SourceJoinRevision: 3, TargetJoinRevision: 4,
		SourceBindingID: "binding-" + source, TargetBindingID: "binding-" + target,
		SourceBindingEpoch: 5, TargetBindingEpoch: 6,
		SourceKeyID: "key-" + source, TargetKeyID: "key-" + target,
		SourceSessionID: "native-" + source, TargetSessionID: "native-" + target,
		SourceCandidateID: "candidate-" + source, TargetCandidateID: "candidate-" + target,
		SourceCandidateVersion: 7, TargetCandidateVersion: 8,
		AuthorizationRevision: "auth-revision-1", Action: action,
		Scope: "scope-shared", AuthorizationValidUntil: now.Add(time.Minute),
	}
}

func reverseTestRoute(route Route) Route {
	route.SourceOwnerID, route.TargetOwnerID = route.TargetOwnerID, route.SourceOwnerID
	route.SourceNodeID, route.TargetNodeID = route.TargetNodeID, route.SourceNodeID
	route.SourcePrincipalID, route.TargetPrincipalID = route.TargetPrincipalID, route.SourcePrincipalID
	route.SourceEndpointID, route.TargetEndpointID = route.TargetEndpointID, route.SourceEndpointID
	route.SourceGroupID, route.TargetGroupID = route.TargetGroupID, route.SourceGroupID
	route.SourceMembershipRevision, route.TargetMembershipRevision = route.TargetMembershipRevision, route.SourceMembershipRevision
	route.SourceJoinRevision, route.TargetJoinRevision = route.TargetJoinRevision, route.SourceJoinRevision
	route.SourceBindingID, route.TargetBindingID = route.TargetBindingID, route.SourceBindingID
	route.SourceBindingEpoch, route.TargetBindingEpoch = route.TargetBindingEpoch, route.SourceBindingEpoch
	route.SourceKeyID, route.TargetKeyID = route.TargetKeyID, route.SourceKeyID
	route.SourceSessionID, route.TargetSessionID = route.TargetSessionID, route.SourceSessionID
	route.SourceCandidateID, route.TargetCandidateID = route.TargetCandidateID, route.SourceCandidateID
	route.SourceCandidateVersion, route.TargetCandidateVersion = route.TargetCandidateVersion, route.SourceCandidateVersion
	route.Action = "REPLY"
	route.AuthorizationRevision = "reply-auth-revision"
	route.AuthorizationValidUntil = time.Now().Add(time.Minute)
	return route
}
