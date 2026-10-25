package nodeinbox

import (
	"context"
	"testing"
)

func TestNativeContextExistingNetworkEndpointLookupIsExactAndReadOnly(t *testing.T) {
	r, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	input := nativeContextHistoryInput()
	if _, err := r.CheckAndRecordNativeContext(ctx, input); err != nil {
		t.Fatal(err)
	}
	lookup := func(account, runtime, sid, hub, network string) (string, error) {
		return r.ExistingNetworkEnrollmentEndpoint(ctx, account, runtime, sid, hub, network)
	}
	if _, err := lookup(input.AccountID, input.Harness, input.NativeSessionID, input.HubID, input.NetworkID); err == nil {
		t.Fatal("Group history was borrowed as independent Network registration")
	}
	input.GroupID = ""
	input.ContextPolicy = ""
	if _, err := r.CheckAndRecordNetworkEnrollmentContext(ctx, input); err != nil {
		t.Fatal(err)
	}
	var beforeCount int
	var beforeSeen int64
	if err := r.db.QueryRow(`SELECT count(*),sum(last_seen_ms) FROM node_native_context_history_v1`).Scan(&beforeCount, &beforeSeen); err != nil {
		t.Fatal(err)
	}
	endpoint, err := lookup(input.AccountID, input.Harness, input.NativeSessionID, input.HubID, input.NetworkID)
	if err != nil || endpoint != input.EndpointID {
		t.Fatal("original independent endpoint unavailable", err)
	}
	for _, values := range [][5]string{{"other", input.Harness, input.NativeSessionID, input.HubID, input.NetworkID}, {input.AccountID, "other", input.NativeSessionID, input.HubID, input.NetworkID}, {input.AccountID, input.Harness, "other", input.HubID, input.NetworkID}, {input.AccountID, input.Harness, input.NativeSessionID, "other", input.NetworkID}, {input.AccountID, input.Harness, input.NativeSessionID, input.HubID, "other"}} {
		if _, err := lookup(values[0], values[1], values[2], values[3], values[4]); err == nil {
			t.Fatal("lookup crossed a trusted coordinate")
		}
	}
	var afterCount int
	var afterSeen int64
	if err := r.db.QueryRow(`SELECT count(*),sum(last_seen_ms) FROM node_native_context_history_v1`).Scan(&afterCount, &afterSeen); err != nil || beforeCount != afterCount || beforeSeen != afterSeen {
		t.Fatal("lookup changed history", err)
	}
	input.EndpointID = "endpoint-other"
	input.BindingID = "binding-other"
	if _, err := r.CheckAndRecordNetworkEnrollmentContext(ctx, input); err != nil {
		t.Fatal(err)
	}
	if _, err := lookup(input.AccountID, input.Harness, input.NativeSessionID, input.HubID, input.NetworkID); err == nil {
		t.Fatal("ambiguous original endpoint was guessed")
	}
}
