package main

import "testing"

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
