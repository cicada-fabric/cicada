package main

import (
	"encoding/json"
	"testing"
)

func TestMCPBroadcastProgressKeepsOneFixedSnapshotAcrossBatches(t *testing.T) {
	progress := mcpBroadcastProgress{BroadcastID: "bc_123", GroupID: "group-a"}
	first := groupBroadcastResult{
		BroadcastID: "bc_123", GroupID: "group-a", SnapshotDigest: "snapshot-1",
		RecipientCount: 2, Offset: 0, NextOffset: 1, Complete: false,
		Recipients: []groupBroadcastRecipientResult{{
			EndpointID: "ep-a", NodeID: "node-a", MessageID: "msg-a", State: "ACCEPTED",
		}},
	}
	if err := progress.apply(first, 0); err != nil {
		t.Fatal(err)
	}
	if progress.allAccepted() {
		t.Fatal("one accepted child cannot complete a two-recipient broadcast")
	}
	second := groupBroadcastResult{
		BroadcastID: "bc_123", GroupID: "group-a", SnapshotDigest: "snapshot-1",
		RecipientCount: 2, Offset: 1, NextOffset: 2, Complete: true,
		Recipients: []groupBroadcastRecipientResult{{
			EndpointID: "ep-b", NodeID: "node-b", MessageID: "msg-b", State: "ACCEPTED",
		}},
	}
	if err := progress.apply(second, 1); err != nil || !progress.allAccepted() {
		t.Fatalf("fixed snapshot did not complete: %v, %+v", err, progress)
	}
	if len(progress.Recipients) != 2 || progress.Recipients[0].EndpointID != "ep-a" ||
		progress.Recipients[1].EndpointID != "ep-b" {
		t.Fatalf("recipient results were not deterministic: %+v", progress.Recipients)
	}
	changed := second
	changed.Offset, changed.NextOffset = 0, 1
	changed.SnapshotDigest = "different-snapshot"
	if err := progress.apply(changed, 0); err == nil {
		t.Fatal("retry accepted a changed member snapshot")
	}
}

func TestMCPBroadcastProgressRejectsChangedChildIdentity(t *testing.T) {
	progress := mcpBroadcastProgress{BroadcastID: "bc_123", GroupID: "group-a"}
	first := groupBroadcastResult{
		BroadcastID: "bc_123", GroupID: "group-a", SnapshotDigest: "snapshot-1",
		RecipientCount: 1, Offset: 0, NextOffset: 1, Complete: true,
		Recipients: []groupBroadcastRecipientResult{{
			EndpointID: "ep-a", NodeID: "node-a", MessageID: "msg-original", State: "ACCEPTED",
		}},
	}
	if err := progress.apply(first, 0); err != nil {
		t.Fatal(err)
	}
	retry := first
	retry.Recipients = []groupBroadcastRecipientResult{{
		EndpointID: "ep-a", NodeID: "node-a", MessageID: "msg-substitute", State: "ACCEPTED",
	}}
	if err := progress.apply(retry, 0); err == nil {
		t.Fatal("retry substituted an accepted recipient message ID")
	}
}

func TestMCPBroadcastRetryRetainsAcceptanceAndUncertainty(t *testing.T) {
	progress := mcpBroadcastProgress{BroadcastID: "bc_123", GroupID: "group-a"}
	batch := groupBroadcastResult{BroadcastID: "bc_123", GroupID: "group-a", SnapshotDigest: "snapshot-1",
		RecipientCount: 2, NextOffset: 2, Complete: true, Recipients: []groupBroadcastRecipientResult{
			{EndpointID: "ep-a", NodeID: "node-a", MessageID: "msg-a", State: "ACCEPTED"},
			{EndpointID: "ep-b", NodeID: "node-b", State: "UNKNOWN", FailureCode: "DELIVERY_OUTCOME_UNKNOWN"},
		}}
	if err := progress.apply(batch, 0); err != nil {
		t.Fatal(err)
	}
	// Persist/reopen the progress, then retry during a revoked/offline window.
	saved, _ := json.Marshal(progress)
	var recovered mcpBroadcastProgress
	if err := json.Unmarshal(saved, &recovered); err != nil {
		t.Fatal(err)
	}
	batch.Recipients = []groupBroadcastRecipientResult{
		{EndpointID: "ep-a", NodeID: "node-a", State: "FAILED", FailureCode: "DELIVERY_REJECTED"},
		{EndpointID: "ep-b", NodeID: "node-b", State: "FAILED", FailureCode: "DELIVERY_REJECTED"},
	}
	if err := recovered.apply(batch, 0); err != nil {
		t.Fatal(err)
	}
	if recovered.Recipients[0].State != "ACCEPTED" || recovered.Recipients[0].MessageID != "msg-a" ||
		recovered.Recipients[1].State != "UNKNOWN" || recovered.allAccepted() {
		t.Fatalf("retry erased prior evidence: %+v", recovered)
	}
	batch.Recipients[1] = groupBroadcastRecipientResult{EndpointID: "ep-b", NodeID: "node-b", State: "ACCEPTED", MessageID: "msg-b"}
	if err := recovered.apply(batch, 0); err != nil || !recovered.allAccepted() {
		t.Fatalf("positive stable-child evidence did not resolve uncertainty: %v %+v", err, recovered)
	}
}

func TestMCPBroadcastInvalidBatchCannotAdvanceProgress(t *testing.T) {
	for _, invalid := range []groupBroadcastRecipientResult{
		{EndpointID: "ep-b", NodeID: "node-b", State: "CONSUMED"},
		{EndpointID: "ep-b", NodeID: "node-b", State: "ACCEPTED"},
		{EndpointID: "ep-a", NodeID: "substituted-node", State: "ACCEPTED", MessageID: "msg-a"},
	} {
		progress := mcpBroadcastProgress{BroadcastID: "bc_123", GroupID: "group-a", SnapshotDigest: "snapshot-1",
			RecipientCount: 2, NextOffset: 1, Recipients: []groupBroadcastRecipientResult{
				{EndpointID: "ep-a", NodeID: "node-a", State: "ACCEPTED", MessageID: "msg-a"},
			}}
		before, _ := json.Marshal(progress)
		batch := groupBroadcastResult{BroadcastID: "bc_123", GroupID: "group-a", SnapshotDigest: "snapshot-1",
			RecipientCount: 2, Offset: 1, NextOffset: 2, Complete: true,
			Recipients: []groupBroadcastRecipientResult{invalid}}
		if err := progress.apply(batch, 1); err == nil {
			t.Fatalf("invalid batch accepted: %+v", invalid)
		}
		after, _ := json.Marshal(progress)
		if string(before) != string(after) {
			t.Fatal("rejected result mutated the existing progress")
		}
	}
}
