package nodeinbox

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestScopedVisibleInboxFollowsNativeInjectionOrderAndGroup(t *testing.T) {
	inbox := openTestInbox(t)
	ctx := context.Background()
	first := testMessage("msg-visible-first", "digest-visible-first")
	first.GroupID = "group-one"
	first.Route = RouteMetadata{Kind: "SEND", SenderEndpointID: "ep-sender"}
	second := testMessage("msg-visible-second", "digest-visible-second")
	second.GroupID = "group-one"
	second.Route = RouteMetadata{Kind: "REQUEST", RequestID: "rq-visible-second", SenderEndpointID: "ep-sender"}
	second.Payload = []byte("second private body")
	for _, message := range []Message{first, second} {
		if _, _, err := inbox.Save(ctx, message); err != nil {
			t.Fatal(err)
		}
	}
	claimFirst, err := inbox.Claim(ctx, "consumer-first")
	if err != nil || claimFirst.MessageID != first.MessageID {
		t.Fatalf("claim first: %+v, %v", claimFirst, err)
	}
	claimSecond, err := inbox.Claim(ctx, "consumer-second")
	if err != nil || claimSecond.MessageID != second.MessageID {
		t.Fatalf("claim second: %+v, %v", claimSecond, err)
	}
	read := func(group string, after int64) []VisibleMessage {
		t.Helper()
		items, err := inbox.ListInjectedForSession(ctx, first.EndpointID, first.SessionID,
			first.BindingEpoch, group, after, 8)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	if got := read("group-one", 0); len(got) != 0 {
		t.Fatalf("unconfirmed native injection exposed %d messages", len(got))
	}
	if _, err := inbox.BeginInjection(ctx, claimSecond.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.RecordRuntimeInjected(ctx, receiptFrom(claimSecond, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
	visible := read("group-one", 0)
	if len(visible) != 1 || visible[0].MessageID != second.MessageID ||
		visible[0].Body != "second private body" || visible[0].Sequence < 1 ||
		visible[0].Kind != "REQUEST" || visible[0].RequestID != "rq-visible-second" ||
		visible[0].ReplyTo != "" || visible[0].SenderEndpointID != "ep-sender" {
		t.Fatalf("wrong first visible message: %+v", visible)
	}
	if got := read("group-two", 0); len(got) != 0 {
		t.Fatalf("another Group read private body: %+v", got)
	}
	if got, err := inbox.ListInjectedForSession(ctx, first.EndpointID, "other-session",
		first.BindingEpoch, first.GroupID, 0, 8); err != nil || len(got) != 0 {
		t.Fatalf("another native Session read private body: %+v, %v", got, err)
	}
	if got, err := inbox.ListInjectedForSession(ctx, first.EndpointID, first.SessionID,
		first.BindingEpoch+1, first.GroupID, 0, 8); err != nil || len(got) != 0 {
		t.Fatalf("another binding epoch read private body: %+v, %v", got, err)
	}
	if _, err := inbox.BeginInjection(ctx, claimFirst.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.RecordRuntimeInjected(ctx, receiptFrom(claimFirst, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
	more := read("group-one", visible[0].Sequence)
	if len(more) != 1 || more[0].MessageID != first.MessageID ||
		more[0].Sequence <= visible[0].Sequence || more[0].Kind != "SEND" ||
		more[0].RequestID != "" || more[0].ReplyTo != "" || more[0].SenderEndpointID != "ep-sender" {
		t.Fatalf("late injection disappeared behind cursor: %+v", more)
	}
	conflict := second
	conflict.GroupID = "group-two"
	if _, _, err := inbox.Save(ctx, conflict); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("message ID reused in another Group: %v", err)
	}
}

func TestVerifiedRouteMetadataIsImmutableAndLegacyRowsStayUnannotated(t *testing.T) {
	path := privateTestInboxPath(t)
	ctx := context.Background()
	message := testMessage("msg-route-metadata", "digest-route-metadata")
	message.GroupID = "group-one"
	message.Route = RouteMetadata{
		Kind: "REPLY", RequestID: "rq-route", ReplyTo: "msg-original-ask",
		SenderEndpointID: "ep-original-asker",
	}
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := writer.Save(ctx, message); err != nil || !created {
		t.Fatalf("save verified route: created=%t err=%v", created, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	// Recovery repeats the exact Node Save after reopening. The immutable route
	// survives that window, while an omitted or changed route is a conflict.
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, created, err := recovered.Save(ctx, message); err != nil || created {
		t.Fatalf("idempotent recovery Save: created=%t err=%v", created, err)
	}
	conflict := message
	conflict.Route.SenderEndpointID = "ep-forged"
	if _, _, err := recovered.Save(ctx, conflict); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("changed verified route error=%v, want conflict", err)
	}
	omitted := message
	omitted.Route = RouteMetadata{}
	if _, _, err := recovered.Save(ctx, omitted); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("omitted previously verified route error=%v, want conflict", err)
	}

	legacy := testMessage("msg-unverified-legacy", "digest-unverified-legacy")
	legacy.GroupID = "group-one"
	if _, _, err := recovered.Save(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	recovery := testMessage("msg-route-recovery", "digest-route-recovery")
	recovery.GroupID = "group-one"
	if _, _, err := recovered.Save(ctx, recovery); err != nil {
		t.Fatal(err)
	}
	recoveredRoute := recovery
	recoveredRoute.Route = RouteMetadata{Kind: "REQUEST", RequestID: "rq-recovery", SenderEndpointID: "ep-recovery-sender"}
	if _, created, err := recovered.Save(ctx, recoveredRoute); err != nil || created {
		t.Fatalf("complete verified route for old delivery: created=%t err=%v", created, err)
	}
	if _, created, err := recovered.Save(ctx, recoveredRoute); err != nil || created {
		t.Fatalf("repeat recovered route Save: created=%t err=%v", created, err)
	}
	changedRecoveryRoute := recoveredRoute
	changedRecoveryRoute.Route.SenderEndpointID = "ep-changed"
	if _, _, err := recovered.Save(ctx, changedRecoveryRoute); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("changed recovered route error=%v, want conflict", err)
	}
	claim, err := recovered.Claim(ctx, "route-metadata-test")
	if err != nil || claim.MessageID != message.MessageID {
		t.Fatalf("claim verified route: %+v, %v", claim, err)
	}
	if _, err := recovered.BeginInjection(ctx, claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.RecordRuntimeInjected(ctx, receiptFrom(claim, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
	items, err := recovered.ListInjectedForSession(ctx, message.EndpointID, message.SessionID,
		message.BindingEpoch, message.GroupID, 0, 8)
	if err != nil || len(items) != 1 {
		t.Fatalf("list verified and legacy routes: %+v, %v", items, err)
	}
	got := items[0]
	if got.MessageID != message.MessageID || got.Kind != "REPLY" || got.RequestID != "rq-route" ||
		got.ReplyTo != "msg-original-ask" || got.SenderEndpointID != "ep-original-asker" {
		t.Fatalf("verified route metadata was not returned: %+v", got)
	}
	// The legacy delivery is still readable; absent route metadata stays empty.
	legacyClaim, err := recovered.Claim(ctx, "route-metadata-test")
	if err != nil || legacyClaim.MessageID != legacy.MessageID {
		t.Fatalf("claim legacy route: %+v, %v", legacyClaim, err)
	}
	if _, err := recovered.BeginInjection(ctx, legacyClaim.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.RecordRuntimeInjected(ctx, receiptFrom(legacyClaim, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
	legacyItems, err := recovered.ListInjectedForSession(ctx, legacy.EndpointID, legacy.SessionID,
		legacy.BindingEpoch, legacy.GroupID, got.Sequence, 8)
	if err != nil || len(legacyItems) != 1 {
		t.Fatalf("legacy visible message: %+v, %v", legacyItems, err)
	}
	if legacyItems[0].MessageID != legacy.MessageID || legacyItems[0].Kind != "" ||
		legacyItems[0].RequestID != "" || legacyItems[0].ReplyTo != "" ||
		legacyItems[0].SenderEndpointID != "" {
		t.Fatalf("unverified historical message exposed guessed route: %+v", legacyItems[0])
	}
	recoveryClaim, err := recovered.Claim(ctx, "route-metadata-test")
	if err != nil || recoveryClaim.MessageID != recovery.MessageID {
		t.Fatalf("claim recovered route: %+v, %v", recoveryClaim, err)
	}
	if _, err := recovered.BeginInjection(ctx, recoveryClaim.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.RecordRuntimeInjected(ctx, receiptFrom(recoveryClaim, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
	recoveredItems, err := recovered.ListInjectedForSession(ctx, recovery.EndpointID, recovery.SessionID,
		recovery.BindingEpoch, recovery.GroupID, legacyItems[0].Sequence, 8)
	if err != nil || len(recoveredItems) != 1 {
		t.Fatalf("recovered route visible message: %+v, %v", recoveredItems, err)
	}
	if recoveredItems[0].MessageID != recovery.MessageID || recoveredItems[0].Kind != "REQUEST" ||
		recoveredItems[0].RequestID != "rq-recovery" || recoveredItems[0].ReplyTo != "" ||
		recoveredItems[0].SenderEndpointID != "ep-recovery-sender" {
		t.Fatalf("verified recovery route was not exposed: %+v", recoveredItems[0])
	}
}

func TestRouteMetadataRejectsIncompleteAndUnboundedCorrelation(t *testing.T) {
	inbox := openTestInbox(t)
	cases := []RouteMetadata{
		{Kind: "SEND", RequestID: "rq-unexpected", SenderEndpointID: "ep-sender"},
		{Kind: "REQUEST", SenderEndpointID: "ep-sender"},
		{Kind: "REPLY", RequestID: "rq-missing-reply-to", SenderEndpointID: "ep-sender"},
		{Kind: "UNKNOWN", SenderEndpointID: "ep-sender"},
		{Kind: "SEND"},
		{Kind: "SEND", SenderEndpointID: strings.Repeat("e", maxIDLength+1)},
	}
	for index, route := range cases {
		message := testMessage("msg-invalid-route-"+string(rune('a'+index)), "digest-invalid-route")
		message.Route = route
		if _, _, err := inbox.Save(context.Background(), message); err == nil {
			t.Fatalf("invalid route metadata was stored: %+v", route)
		}
	}
}

func TestReadOnlyInboxDoesNotRecoverLiveInjection(t *testing.T) {
	path := privateTestInboxPath(t)
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	ctx := context.Background()
	message := testMessage("msg-live-injection", "digest-live-injection")
	message.GroupID = "group-one"
	if _, _, err := writer.Save(ctx, message); err != nil {
		t.Fatal(err)
	}
	claim, err := writer.Claim(ctx, "live-node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.BeginInjection(ctx, claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := reader.ListInjectedForSession(ctx, message.EndpointID, message.SessionID,
		message.BindingEpoch, message.GroupID, 0, 8)
	if err != nil || len(items) != 0 {
		t.Fatalf("read-only view exposed an in-flight injection: %+v, %v", items, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	stored, err := writer.Get(ctx, message.MessageID)
	if err != nil || stored.State != INJECTING {
		t.Fatalf("reading restarted live injection: %+v, %v", stored, err)
	}
	if _, err := writer.RecordRuntimeInjected(ctx, receiptFrom(claim, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyInboxReadsLegacySchemaWithoutAddingRouteMetadataTable(t *testing.T) {
	path := privateTestInboxPath(t)
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	message := testMessage("msg-readonly-old-schema", "digest-readonly-old-schema")
	message.GroupID = "group-one"
	message.Route = RouteMetadata{Kind: "SEND", SenderEndpointID: "ep-sender"}
	if _, _, err := writer.Save(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	claim, err := writer.Claim(context.Background(), "legacy-schema-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.RecordRuntimeInjected(context.Background(), receiptFrom(claim, RUNTIME_INJECTED)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.db.Exec(`DROP TABLE node_inbox_message_routes`); err != nil {
		t.Fatalf("prepare pre-route-migration schema: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	visible, err := reader.ListInjectedForSession(context.Background(), message.EndpointID,
		message.SessionID, message.BindingEpoch, message.GroupID, 0, 8)
	if err != nil || len(visible) != 1 || visible[0].MessageID != message.MessageID ||
		visible[0].Body != string(message.Payload) || visible[0].Kind != "" ||
		visible[0].RequestID != "" || visible[0].ReplyTo != "" || visible[0].SenderEndpointID != "" {
		t.Fatalf("read-only legacy schema result: %+v, %v", visible, err)
	}
	var routeTable int
	err = reader.db.QueryRow(`SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_inbox_message_routes'`).Scan(&routeTable)
	if !errors.Is(err, sql.ErrNoRows) || routeTable != 0 {
		t.Fatalf("read-only legacy open created route metadata schema: table=%d err=%v", routeTable, err)
	}
}
