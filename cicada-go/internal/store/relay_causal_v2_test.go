package store

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func relayCausalRequestInput(t *testing.T, f *localDeliveryAuthorizationFixture, requestID string,
	sender, receiver *Endpoint, parentID string) FabricRequest {
	t.Helper()
	senderBinding, err := f.store.GetActiveSessionBinding(sender.ID)
	if err != nil {
		t.Fatal(err)
	}
	receiverBinding, err := f.store.GetActiveSessionBinding(receiver.ID)
	if err != nil {
		t.Fatal(err)
	}
	return FabricRequest{
		RequestID: requestID, MessageID: "msg_" + requestID,
		SenderEndpointID: sender.ID, SenderPrincipalID: sender.PrincipalID,
		SenderGroupID: f.group.ID, SenderBindingID: senderBinding.ID,
		SenderBindingEpoch: senderBinding.Epoch,
		ReceiverEndpointID: receiver.ID, ReceiverPrincipalID: receiver.PrincipalID,
		ReceiverGroupID: f.group.ID, ReceiverBindingID: receiverBinding.ID,
		ReceiverBindingEpoch: receiverBinding.Epoch, ParentRequestID: parentID,
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		Body:      "synthetic causal Ask",
	}
}

func relayCausalCreate(t *testing.T, f *localDeliveryAuthorizationFixture, requestID string,
	sender, receiver *Endpoint, parentID string) *FabricRequest {
	t.Helper()
	created, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f, requestID, sender, receiver, parentID))
	if err != nil {
		t.Fatalf("create request %q: %v", requestID, err)
	}
	return created
}

func relayCausalReceive(t *testing.T, f *localDeliveryAuthorizationFixture, request *FabricRequest) {
	t.Helper()
	claimed, err := f.store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: request.ReceiverEndpointID,
		ConsumerID:          "causal-" + request.RequestID,
		BindingID:           request.ReceiverBindingID,
		BindingEpoch:        request.ReceiverBindingEpoch,
		Limit:               1,
	})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != request.MessageID {
		t.Fatalf("claim request %q: claims=%#v err=%v", request.RequestID, claimed, err)
	}
	attempt := claimed[0]
	if _, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: attempt.AttemptID, MessageID: attempt.MessageID, Digest: attempt.Digest,
		TargetEndpointID: attempt.RecipientEndpointID, BindingID: attempt.BindingID,
		BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatalf("record Node receipt for %q: %v", request.RequestID, err)
	}
}

func relayCausalExtraEndpoint(t *testing.T, f *localDeliveryAuthorizationFixture, suffix string) *Endpoint {
	t.Helper()
	endpoint, _ := addLocalDeliveryEndpoint(t, f.store, f.group.ID, "ep_"+suffix, suffix,
		f.nodeID, []string{"message.send", "message.ask", "message.reply", "message.receive"},
		"cicada_session_"+suffix)
	return endpoint
}

func TestRelayCausalAskDerivesReceivedParentAndBoundsDepthAndCycles(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	c := relayCausalExtraEndpoint(t, f, "causal_c")
	d := relayCausalExtraEndpoint(t, f, "causal_d")
	e := relayCausalExtraEndpoint(t, f, "causal_e")
	endpointF := relayCausalExtraEndpoint(t, f, "causal_f")
	g := relayCausalExtraEndpoint(t, f, "causal_g")

	root := relayCausalCreate(t, f, "rq_causal_root", f.source, f.target, "")
	if root.CausalRootRequestID != root.RequestID || root.CausalDepth != 0 || root.ParentRequestID != "" {
		t.Fatalf("parentless request did not derive its own root: %#v", root)
	}
	relayCausalReceive(t, f, root)

	if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
		"rq_causal_cycle_root", f.target, f.source, root.RequestID)); !errors.Is(err, ErrRelayCausalCycle) {
		t.Fatalf("A→B→A causal cycle was accepted: %v", err)
	}
	first := relayCausalCreate(t, f, "rq_causal_depth_1", f.target, c, root.RequestID)
	relayCausalReceive(t, f, first)
	second := relayCausalCreate(t, f, "rq_causal_depth_2", c, d, first.RequestID)
	relayCausalReceive(t, f, second)
	third := relayCausalCreate(t, f, "rq_causal_depth_3", d, e, second.RequestID)
	relayCausalReceive(t, f, third)
	fourth := relayCausalCreate(t, f, "rq_causal_depth_4", e, endpointF, third.RequestID)
	relayCausalReceive(t, f, fourth)
	if fourth.CausalRootRequestID != root.RequestID || fourth.CausalDepth != MaxRelayCausalAskDepth {
		t.Fatalf("lineage was not derived to the bounded depth: %#v", fourth)
	}
	if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
		"rq_causal_depth_5", endpointF, g, fourth.RequestID)); !errors.Is(err, ErrRelayCausalBudget) {
		t.Fatalf("Ask beyond max depth was not refused with a permanent budget error: %v", err)
	}
	if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
		"rq_causal_cycle_ancestor", e, f.source, third.RequestID)); !errors.Is(err, ErrRelayCausalCycle) {
		t.Fatalf("request revisiting root endpoint was accepted: %v", err)
	}

	// A normal independent reverse Ask has no claimed causal parent and remains
	// an independent root even when it travels between the same Endpoints.
	independent := relayCausalCreate(t, f, "rq_causal_independent_reverse", f.target, f.source, "")
	if independent.CausalRootRequestID != independent.RequestID || independent.CausalDepth != 0 {
		t.Fatalf("independent reverse Ask inherited unrelated ancestry: %#v", independent)
	}
}

func TestRelayCausalAskRejectsForgedStaleAndUnreceivedParents(t *testing.T) {
	t.Run("unknown parent", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
			"rq_causal_unknown_parent", f.target, f.source, "rq_missing_parent")); !errors.Is(err, ErrRelayCausalParentInvalid) {
			t.Fatalf("unknown parent was accepted: %v", err)
		}
	})

	t.Run("parent not yet durably received", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		root := relayCausalCreate(t, f, "rq_causal_unreceived_root", f.source, f.target, "")
		if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
			"rq_causal_unreceived_child", f.target, f.source, root.RequestID)); !errors.Is(err, ErrRelayCausalParentInvalid) {
			t.Fatalf("unreceived parent was accepted: %v", err)
		}
	})

	t.Run("current receiver binding changed", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		root := relayCausalCreate(t, f, "rq_causal_stale_root", f.source, f.target, "")
		relayCausalReceive(t, f, root)
		if _, err := f.store.RotateSessionBindingCredential(f.targetBinding.ID,
			f.targetBinding.Epoch, localDeliveryDigest("rotated causal session"),
			f.targetBinding.LeaseOwner, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
			"rq_causal_stale_child", f.target, f.source, root.RequestID)); !errors.Is(err, ErrRelayCausalParentInvalid) {
			t.Fatalf("old parent was accepted after the receiver binding epoch changed: %v", err)
		}
	})

	t.Run("forged receiver principal", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		root := relayCausalCreate(t, f, "rq_causal_wrong_actor_root", f.source, f.target, "")
		relayCausalReceive(t, f, root)
		childInput := relayCausalRequestInput(t, f, "rq_causal_wrong_actor_child", f.target, f.source, root.RequestID)
		childInput.SenderPrincipalID = "pr_other"
		if _, err := f.store.CreateFabricRequest(childInput); !errors.Is(err, ErrRelayCausalParentInvalid) {
			t.Fatalf("different authenticated actor borrowed parent ancestry: %v", err)
		}
	})

	t.Run("cross Group scope", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		root := relayCausalCreate(t, f, "rq_causal_scope_root", f.source, f.target, "")
		relayCausalReceive(t, f, root)
		childInput := relayCausalRequestInput(t, f, "rq_causal_scope_child", f.target, f.source, root.RequestID)
		childInput.SenderGroupID = "group_other"
		childInput.ReceiverGroupID = "group_other"
		if _, err := f.store.CreateFabricRequest(childInput); !errors.Is(err, ErrRelayCausalParentInvalid) {
			t.Fatalf("cross-Group child borrowed parent ancestry: %v", err)
		}
	})
}

func TestRelayCausalAskDoesNotContinueFromCancelledOrExpiredAncestor(t *testing.T) {
	for _, terminal := range []string{FabricRequestCancelled, FabricRequestExpired} {
		t.Run(terminal, func(t *testing.T) {
			f := newLocalDeliveryAuthorizationFixture(t)
			c := relayCausalExtraEndpoint(t, f, "causal_terminal_c")
			d := relayCausalExtraEndpoint(t, f, "causal_terminal_d")
			root := relayCausalCreate(t, f, "rq_causal_terminal_root_"+terminal, f.source, f.target, "")
			relayCausalReceive(t, f, root)
			child := relayCausalCreate(t, f, "rq_causal_terminal_child_"+terminal, f.target, c, root.RequestID)
			relayCausalReceive(t, f, child)
			switch terminal {
			case FabricRequestCancelled:
				if _, err := f.store.CancelFabricRequest(root.RequestID, "synthetic root cancellation"); err != nil {
					t.Fatal(err)
				}
			case FabricRequestExpired:
				if _, err := f.store.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
					time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), root.RequestID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.ExpireFabricRequest(root.RequestID, "synthetic root expiry"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
				"rq_causal_terminal_grandchild_"+terminal, c, d, child.RequestID)); !errors.Is(err, ErrRelayCausalParentInvalid) {
				t.Fatalf("descendant continued from a %s ancestor: %v", terminal, err)
			}
			stillOpen, err := f.store.GetRelayFabricRequest(child.RequestID)
			if err != nil || stillOpen == nil || stillOpen.State != FabricRequestOpen {
				t.Fatalf("root terminal transition unexpectedly cascaded to existing child: %#v err=%v", stillOpen, err)
			}
		})
	}
}

func TestRelayCausalAskRootBudgetsAreFiniteAndIdempotent(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	c := relayCausalExtraEndpoint(t, f, "causal_budget_c")
	root := relayCausalCreate(t, f, "rq_causal_budget_root", f.source, f.target, "")
	relayCausalReceive(t, f, root)
	first := relayCausalCreate(t, f, "rq_causal_budget_1", f.target, c, root.RequestID)
	retried, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
		first.RequestID, f.target, c, root.RequestID))
	if err != nil || retried.RequestID != first.RequestID || retried.CausalRootRequestID != root.RequestID {
		t.Fatalf("exact child retry did not recover the stored lineage: %#v err=%v", retried, err)
	}
	if _, err := f.store.CancelFabricRequest(first.RequestID, "free pending causal budget"); err != nil {
		t.Fatal(err)
	}
	for index := 2; index <= MaxRelayCausalRequestsPerRoot-1; index++ {
		child := relayCausalCreate(t, f, fmt.Sprintf("rq_causal_budget_%d", index), f.target, c, root.RequestID)
		if _, err := f.store.CancelFabricRequest(child.RequestID, "free pending causal budget"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.CreateFabricRequest(relayCausalRequestInput(t, f,
		"rq_causal_budget_over_total", f.target, c, root.RequestID)); !errors.Is(err, ErrRelayCausalBudget) {
		t.Fatalf("root exceeded its lifetime request budget: %v", err)
	}

	// A separate root verifies that five concurrent OPEN requests (root plus
	// four children) fill, but do not exceed, the finite per-root pending cap.
	f2 := newLocalDeliveryAuthorizationFixture(t)
	c2 := relayCausalExtraEndpoint(t, f2, "causal_pending_c")
	budgetRoot := relayCausalCreate(t, f2, "rq_causal_pending_root", f2.source, f2.target, "")
	relayCausalReceive(t, f2, budgetRoot)
	for index := 1; index < MaxRelayCausalPendingPerRoot; index++ {
		relayCausalCreate(t, f2, fmt.Sprintf("rq_causal_pending_%d", index), f2.target, c2, budgetRoot.RequestID)
	}
	if _, err := f2.store.CreateFabricRequest(relayCausalRequestInput(t, f2,
		"rq_causal_pending_over", f2.target, c2, budgetRoot.RequestID)); !errors.Is(err, ErrRelayResourceExhausted) {
		t.Fatalf("root exceeded its concurrent pending budget: %v", err)
	}
}
