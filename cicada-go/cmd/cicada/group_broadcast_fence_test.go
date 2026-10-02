package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	"github.com/cicada-ai/cicada/internal/store"
)

// Real Store, Hub authorization and Node ledger exercise the check before
// sealing/persistence. A fresh, otherwise valid SEND authorization must not
// override the earlier broadcast recipient/key/binding scope.
func TestGroupBroadcastLocalChildRejectsStaleSnapshotBeforePersistence(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	f.sourceMCP.sessionMu.RLock()
	card, token := f.sourceMCP.sessionPublic.NetworkCard, f.sourceMCP.sessionToken
	f.sourceMCP.sessionMu.RUnlock()
	f.targetMCP.sessionMu.RLock()
	target := f.targetMCP.sessionPublic.NetworkCard
	f.targetMCP.sessionMu.RUnlock()
	grantGroupBroadcastSend(t, f.store, f.ownerID, f.groupID,
		card.PrincipalID, card.EndpointID, target.PrincipalID, target.EndpointID)
	snapshot, err := f.store.CreateSameGroupBroadcastV2Snapshot(store.SameGroupBroadcastV2SnapshotInput{
		NodeCredentialDigest:    fabric.HashSessionCredential(f.nodeToken),
		SessionCredentialDigest: fabric.HashSessionCredential(token), GroupID: f.groupID,
		BroadcastID: "bc_0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := groupBroadcastRequest{
		Harness: "codex", NativeSessionID: f.nativeA, NodeID: f.nodeID, Workspace: f.workspace,
		SessionToken: token, EndpointID: card.EndpointID, PrincipalID: card.PrincipalID,
		OwnerID: f.ownerID, GroupID: f.groupID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch,
		BroadcastID: snapshot.BroadcastID, Body: "synthetic snapshot-fenced broadcast",
	}
	recipient := snapshot.Recipients[0]
	opID := groupBroadcastChildOperationID(snapshot.BroadcastID, recipient.EndpointID)
	// Seed the immutable historical child through the pre-fallback primitive.
	ledger, err := nodelocal.Open(machineLocalGroupLedgerPath(f.stateDir, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	legacy := localGroupRequest{Version: localGroupProtocolVersion, Operation: "local_send", Harness: request.Harness, NativeSessionID: request.NativeSessionID, NodeID: request.NodeID, Workspace: request.Workspace, SessionToken: request.SessionToken, EndpointID: request.EndpointID, PrincipalID: request.PrincipalID, OwnerID: request.OwnerID, GroupID: request.GroupID, BindingID: request.BindingID, BindingEpoch: request.BindingEpoch, OperationID: opID, IdempotencyKey: opID, Target: recipient.EndpointID, Body: request.Body}
	if _, err := f.bridge.submitLocalGroupMessage(ledger, legacy, &groupBroadcastDeliveryFence{source: snapshot.Source, recipient: recipient}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*store.SameGroupBroadcastV2Endpoint)
	}{
		{"binding epoch", func(e *store.SameGroupBroadcastV2Endpoint) { e.BindingEpoch++ }},
		{"membership", func(e *store.SameGroupBroadcastV2Endpoint) { e.MembershipRevision++ }},
		{"group join", func(e *store.SameGroupBroadcastV2Endpoint) { e.GroupJoinRevision++ }},
		{"key candidate", func(e *store.SameGroupBroadcastV2Endpoint) { e.KeyVersion++ }},
		{"key proof", func(e *store.SameGroupBroadcastV2Endpoint) { e.KeyProofDigest = "different" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			stale := recipient
			test.mutate(&stale)
			_, err := f.bridge.sendLocalGroupBroadcastChild(request, snapshot.Source, stale, opID)
			if !errors.Is(err, errGroupBroadcastSnapshotChanged) {
				t.Fatalf("stale snapshot was not rejected by the send fence: %v", err)
			}
		})
	}
	pending, err := ledger.PendingAll(context.Background(), 8)
	if err != nil || len(pending) != 1 {
		t.Fatalf("rejected replay changed the historical delivery ledger: count=%d err=%v", len(pending), err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := f.bridge.sendLocalGroupBroadcastChild(request, snapshot.Source, recipient, opID); err != nil {
			t.Fatalf("unchanged snapshot retry %d: %v", attempt, err)
		}
	}
	pending, err = ledger.PendingAll(context.Background(), 8)
	if err != nil || len(pending) != 1 {
		t.Fatalf("valid retry must preserve one delivery: count=%d err=%v", len(pending), err)
	}
}

func TestGroupBroadcastRemoteFenceChecksBothEndpoints(t *testing.T) {
	_, snapshot, _ := validGroupBroadcastFixture(t, 1)
	convert := func(e store.SameGroupBroadcastV2Endpoint) crossNodeGroupEndpointEvidence {
		return crossNodeGroupEndpointEvidence{
			EndpointID: e.EndpointID, PrincipalID: e.PrincipalID, OwnerID: e.OwnerID,
			NodeID: e.NodeID, GroupID: e.GroupID, GroupRevision: e.GroupRevision,
			MembershipRevision: e.MembershipRevision, EndpointJoinRevision: e.GroupJoinRevision,
			BindingID: e.BindingID, BindingEpoch: e.BindingEpoch, NativeSessionID: e.NativeSessionID,
			Candidate: store.EndpointKeyCandidate{KeyID: e.KeyID, Version: e.KeyVersion,
				ProofDigest: e.KeyProofDigest, Public: e.PublicKey},
		}
	}
	fence := &groupBroadcastDeliveryFence{source: snapshot.Source, recipient: snapshot.Recipients[0]}
	current := crossNodeGroupPeerKey{Sender: convert(fence.source), Receiver: convert(fence.recipient)}
	if err := fence.validateRemote(current); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*crossNodeGroupEndpointEvidence){
		func(e *crossNodeGroupEndpointEvidence) { e.BindingEpoch++ },
		func(e *crossNodeGroupEndpointEvidence) { e.OwnerID = "other-owner" },
		func(e *crossNodeGroupEndpointEvidence) { e.GroupRevision++ },
		func(e *crossNodeGroupEndpointEvidence) { e.MembershipRevision++ },
		func(e *crossNodeGroupEndpointEvidence) { e.EndpointJoinRevision++ },
		func(e *crossNodeGroupEndpointEvidence) { e.Candidate.Version++ },
		func(e *crossNodeGroupEndpointEvidence) { e.Candidate.ProofDigest = "changed" },
		func(e *crossNodeGroupEndpointEvidence) { e.Candidate.Public.KEMPublic = []byte("changed") },
	} {
		for _, source := range []bool{true, false} {
			changed := current
			endpoint := &changed.Receiver
			if source {
				endpoint = &changed.Sender
			}
			change(endpoint)
			if !errors.Is(fence.validateRemote(changed), errGroupBroadcastSnapshotChanged) {
				t.Fatal("broadcast accepted a replacement endpoint authorization")
			}
		}
	}
}
