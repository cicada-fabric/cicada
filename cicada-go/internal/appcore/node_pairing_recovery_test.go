package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestNodePairingSavedReviewRestoresWithoutRenewingConsent(t *testing.T) {
	for _, mode := range []string{wire.NodePairTrustInitial, wire.NodePairTrustExisting} {
		t.Run(mode, func(t *testing.T) {
			f := newNodePairingFixture(t)
			ctx := context.Background()
			if mode == wire.NodePairTrustExisting {
				if err := f.n.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.n.code}); err != nil {
					t.Fatal(err)
				}
				f.n.approve(t)
				binding := f.n.bindingDTO()
				f.context.Mode, f.context.Candidate, f.context.Binding = mode, nil, &binding
				var err error
				f.code, err = wire.EncodeNodePairTrustCode(f.context, "", f.secret)
				if err != nil {
					t.Fatal(err)
				}
				digest, _ := wire.NodePairTrustContextDigest(f.context)
				f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
			}
			f.review()
			c := f.n.c
			review, deadline := c.Snapshot().Node.Pairing.ReviewID, c.Snapshot().Node.Pairing.ExpiresAt
			original, _ := json.Marshal(c.node.PairTrust)
			proposal, _ := json.Marshal(c.node.Proposal)
			counters := c.node.Client
			owner, device := c.owner.Public().ID, c.device.Public().ID
			oldCompletes := len(f.n.posts[wire.OperationAppNodeComplete])

			// Restore the real encrypted profile/session without the fixture's
			// explicit context refresh: production initialization must perform it.
			f.reopenSession()
			c = f.n.c
			if c.nodeContextChecked {
				t.Fatal("historical profile restored fresh Node authority")
			}
			c.initializeNode(ctx)
			if !c.nodeContextChecked || !containsAction(c.Snapshot().AvailableActions, ActionApproveNodePairing) {
				t.Fatal("saved review did not restore approval through initialization")
			}
			restored, _ := json.Marshal(c.node.PairTrust)
			if !bytes.Equal(original, restored) {
				t.Fatal("initialization changed original review or pairing packet")
			}
			if err := c.Dispatch(ctx, Action{Kind: ActionRefreshNodePairing}); err != nil {
				t.Fatal(err)
			}
			checked := c.Snapshot()
			restoredProposal, _ := json.Marshal(c.node.Proposal)
			if checked.Node.Pairing.State != "REVIEW" || checked.Node.Pairing.ReviewID != review || checked.Node.Pairing.ExpiresAt != deadline ||
				!containsAction(checked.AvailableActions, ActionApproveNodePairing) || !bytes.Equal(proposal, restoredProposal) ||
				!bytes.Equal(c.node.PairTrust.Code.OOBSecret, f.secret) || c.node.Client != counters || c.owner.Public().ID != owner || c.device.Public().ID != device ||
				c.node.PairTrust.ConsentReviewID != "" || len(f.requests[wire.OperationOwnerNodePairTrustPrepare]) != 0 || len(f.n.posts[wire.OperationAppNodeComplete]) != oldCompletes {
				t.Fatal("public status lost the original review, renewed consent or mutated admission")
			}
			// Model a crash after this exact authenticated status response was
			// persisted but before apply. Unlock must retain a historical review
			// while freshness remains unavailable until initialization reads it.
			statusRequest, statusResponse := bytes.Clone(c.node.PairTrust.Pending.Request), bytes.Clone(c.node.PairTrust.Pending.Response)
			c.node.PairTrust.Pending.Applied = false
			if err := c.persistNode(); err != nil {
				t.Fatal(err)
			}
			f.reopenSession()
			c = f.n.c
			if c.node.PairTrust.Stage != "REVIEW" || c.nodeContextChecked || !c.node.PairTrust.Pending.Applied ||
				!bytes.Equal(statusRequest, c.node.PairTrust.Pending.Request) || !bytes.Equal(statusResponse, c.node.PairTrust.Pending.Response) ||
				containsAction(c.Snapshot().AvailableActions, ActionApproveNodePairing) {
				t.Fatal("historical status lost the review or granted fresh approval")
			}
			c.initializeNode(ctx)

			// A current authenticated observation from another account session
			// cannot authorize this original review, even before its deadline.
			sessionID := f.n.scope.AccountSessionID
			f.n.scope.AccountSessionID = "synthetic-other-review-session"
			if err := c.refreshNodePairingContext(ctx); err != nil {
				t.Fatal(err)
			}
			if containsAction(c.Snapshot().AvailableActions, ActionApproveNodePairing) || f.approve() == nil || c.node.PairTrust.ConsentReviewID != "" {
				t.Fatal("different current session approved or renewed saved review")
			}
			f.n.scope.AccountSessionID = sessionID
			if err := c.refreshNodePairingContext(ctx); err != nil {
				t.Fatal(err)
			}
			if c.nodePairingReviewID() != review || c.Snapshot().Node.Pairing.ExpiresAt != deadline {
				t.Fatal("read-only context refresh replaced the original review")
			}
			if err := f.approve(); err != nil {
				t.Fatal(err)
			}
			if c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved || c.node.PairTrust.ConsentReviewID != review || c.node.Client != counters {
				t.Fatal("explicit original approval failed or advanced original counters")
			}
			if mode == wire.NodePairTrustExisting {
				f.state = wire.NodePairTrustRevoked
				if err := c.Dispatch(ctx, Action{Kind: ActionRefreshNodePairing}); err != nil {
					t.Fatal(err)
				}
				if c.node.PairTrust.Stage != wire.NodePairTrustRevoked || containsAction(c.Snapshot().AvailableActions, ActionApproveNodePairing) {
					t.Fatal("real terminal observation restored an approval")
				}
			}
		})
	}
}

func TestNodePairingPacketFenceObservesAttemptInsteadOfInventingTerminal(t *testing.T) {
	for _, op := range []string{wire.OperationOwnerNodePairTrustLookup, wire.OperationOwnerNodePairTrustPrepare, wire.OperationOwnerNodePairTrustComplete, wire.OperationOwnerNodePairTrustStatus, wire.OperationOwnerNodePairTrustCancel} {
		t.Run(op, func(t *testing.T) {
			f := newNodePairingFixture(t)
			if op != wire.OperationOwnerNodePairTrustLookup {
				f.review()
			}
			f.failBefore = op
			var err error
			switch op {
			case wire.OperationOwnerNodePairTrustLookup:
				err = f.n.c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: f.code})
			case wire.OperationOwnerNodePairTrustStatus:
				if err = f.approve(); err != nil {
					t.Fatal(err)
				}
				f.ack()
				err = f.n.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing})
			case wire.OperationOwnerNodePairTrustCancel:
				if err = f.approve(); err != nil {
					t.Fatal(err)
				}
				err = f.n.c.Dispatch(context.Background(), Action{Kind: ActionCancelNodePairing, NodePairingReviewID: f.n.c.nodePairingReviewID()})
			default:
				err = f.approve()
			}
			if err == nil {
				t.Fatal("before-forward loss reported success")
			}
			original := bytes.Clone(f.n.c.node.PairTrust.Pending.Request)
			proof, capsule := bytes.Clone(f.n.c.node.PairTrust.OwnerProof), bytes.Clone(f.n.c.node.PairTrust.Capsule)
			f.denyPacket = wire.NodePairTrustPacketDigest(original)
			f.reopen()
			if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
				t.Fatal(err)
			}
			target := wire.NodePairTrustOwnerApproved
			if op == wire.OperationOwnerNodePairTrustLookup {
				target = "REVIEW"
			}
			if op == wire.OperationOwnerNodePairTrustStatus {
				target = wire.NodePairTrustACKed
			}
			if op == wire.OperationOwnerNodePairTrustCancel {
				target = wire.NodePairTrustCancelled
			}
			p := f.n.c.node.PairTrust
			if p.Stage != target || p.FencedOperation != "" || !bytes.Equal(p.Code.OOBSecret, f.secret) {
				t.Fatal("single request fence changed attempt outcome/S")
			}
			if len(proof) != 0 && (!bytes.Equal(proof, p.OwnerProof) || !bytes.Equal(capsule, p.Capsule)) {
				t.Fatal("fence regenerated original Owner proof/E")
			}
			if op == wire.OperationOwnerNodePairTrustStatus && (f.n.c.nodeConfirmation == nil || f.n.c.node.Client.NextRequest != 2) {
				t.Fatal("fenced read lost the real ACK/original receipt")
			}
			if len(f.requests[wire.OperationNodePairTrustReconcile]) == 0 {
				t.Fatal("fixture did not authenticate no-effect fence")
			}
		})
	}
}

func TestNodePairingCancelledInitialGrantAllowsNewCodeWithoutChangingNode(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	c := f.n.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionCancelNodePairing, NodePairingReviewID: c.nodePairingReviewID()}); err != nil {
		t.Fatal(err)
	}
	if !c.node.PairTrust.CleanupComplete || !c.node.PairTrust.Confirmation.Applied || !c.nodeCanStartInitial() || c.nodeConfirmation != nil || f.n.binding != nil {
		t.Fatal("failed ceremony left INITIAL grant blocking new code or bound Node")
	}
	owner, node, control := c.owner.Public().ID, f.n.nodeKey.Public().ID, f.n.controlKey.Public().ID
	f.context.AttemptID = strings.Repeat("3a", 16)
	f.context.NodeNonce = strings.Repeat("5b", 32)
	f.state = wire.NodePairTrustPending
	var err error
	f.code, err = wire.EncodeNodePairTrustCode(f.context, f.n.code, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.NodePairTrustContextDigest(f.context)
	f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
	f.review()
	if c.owner.Public().ID != owner || f.n.nodeKey.Public().ID != node || f.n.controlKey.Public().ID != control || c.node.PairTrust.Context.AttemptID != f.context.AttemptID {
		t.Fatal("retry replaced identity or retained old attempt")
	}
}

func TestNodePairingCapacityRefusalPrecedesNewPacketAndPreservesOriginal(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	c := f.n.c
	original := bytes.Clone(c.node.PairTrust.Pending.Request)
	// Three actual encrypted records stay below the total vault bound, but leave
	// insufficient room for the future reply/reconciliation. No placeholder CAS.
	for _, ns := range []string{"synthetic.budget.a", "synthetic.budget.b", "synthetic.budget.c"} {
		if _, err := c.vault.CompareAndSwapState(ns, 0, make([]byte, 700<<10)); err != nil {
			t.Fatal(err)
		}
	}
	before := len(f.requests[wire.OperationOwnerNodePairTrustPrepare])
	if f.approve() == nil {
		t.Fatal("full future receipt budget accepted")
	}
	if c.storageFault || len(f.requests[wire.OperationOwnerNodePairTrustPrepare]) != before || !bytes.Equal(original, c.node.PairTrust.Pending.Request) {
		t.Fatal("capacity check posted, replaced original or mislabeled disk failure")
	}
	if c.Snapshot().ErrorCode != "APP_NODE_PAIRING_STORAGE_FULL" {
		t.Fatal("missing actionable capacity refusal")
	}
}

func TestNodePairingRecoveryCanonicalBodyHasOneOriginalCopy(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing lost response")
	}
	f.deny = wire.OperationOwnerNodePairTrustComplete
	f.drop = wire.OperationNodePairTrustReconcile
	if f.n.c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}) == nil {
		t.Fatal("missing uncertain outer recovery")
	}
	c := f.n.c
	p := c.node.PairTrust.Recovery
	if p == nil {
		t.Fatal("missing saved recovery")
	}
	var compact wire.NodePairTrustReconcile
	if json.Unmarshal(p.Body, &compact) != nil || len(compact.OriginalPacket) != 0 {
		t.Fatal("recovery duplicated original plaintext")
	}
	q, err := c.nodePairTrustBody(p)
	if err != nil || !bytes.Equal(q.(*wire.NodePairTrustReconcile).OriginalPacket, c.node.PairTrust.Pending.Request) {
		t.Fatal("could not restore exact original DTO")
	}
	request := bytes.Clone(p.Request)
	f.reopen()
	c = f.n.c
	if c.node.PairTrust.Recovery != nil && !bytes.Equal(request, c.node.PairTrust.Recovery.Request) {
		t.Fatal("reopen resealed recovery")
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved {
		t.Fatal("could not restore approval after outer loss")
	}
}

func TestNodePairingMaxCandidateMetadataFitsActualPQVaultAndRecovery(t *testing.T) {
	f := newNodePairingFixture(t)
	f.context.Candidate.NodeName = strings.Repeat("<", 128)
	f.context.Candidate.NodeID = strings.Repeat(">", 128)
	f.context.Candidate.RequestID = strings.Repeat("&", 128)
	f.context.Candidate.Version, f.context.Candidate.NodeKeyEpoch = math.MaxInt64, math.MaxInt64
	f.n.candidateOverride = f.context.Candidate
	var err error
	f.code, err = wire.EncodeNodePairTrustCode(f.context, f.n.code, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.NodePairTrustContextDigest(f.context)
	f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing lost complete")
	}
	f.deny = wire.OperationOwnerNodePairTrustComplete
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if f.n.c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved {
		t.Fatal("bounded metadata prevented normal recovery")
	}
	f.ack()
	f.drop = wire.OperationOwnerNodePairTrustStatus
	if f.n.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}) == nil {
		t.Fatal("missing lost maximal ACK status")
	}
	f.deny = wire.OperationOwnerNodePairTrustStatus
	if err := f.n.c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if f.n.c.node.PairTrust.Stage != wire.NodePairTrustACKed {
		t.Fatal("maximal ACK/original receipt did not fit recovery")
	}
	for operation, size := range f.stateSizes {
		t.Logf("max-metadata operation=%s namespace_plaintext_bytes=%d", operation, size)
		if size > maxNodeStateRecordBytes {
			t.Fatal("max legal metadata exceeded namespace")
		}
	}
}

func TestNodePairingExpiredOriginalCompleteAfterRestartAndNewLogin(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing lost committed complete")
	}
	target := f.n.c.node.PairTrust
	original, proof, capsule := bytes.Clone(target.Pending.Request), bytes.Clone(target.OwnerProof), bytes.Clone(target.Capsule)
	approval := *target.Approval
	f.n.n2.now = f.n.n2.now.Add(10*time.Minute + time.Second)
	f.reopen()
	c := f.n.c
	f.n.scope.AccountSessionID = "synthetic-current-login-after-expiry"
	f.n.scope.AccountSessionExpiresAt = f.n.stamp(f.n.n2.now.Add(12 * time.Minute))
	c.session.ExpiresAt = f.n.scope.AccountSessionExpiresAt
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	p := c.node.PairTrust
	if p.Stage != wire.NodePairTrustExpired || !p.CleanupComplete || !p.Confirmation.Applied || c.node.Client.NextRequest != 2 || c.nodeConfirmation != nil || f.n.binding != nil {
		t.Fatal("expired ceremony did not settle exact original negative safely")
	}
	if !reflect.DeepEqual(approval, *p.Approval) || !bytes.Equal(proof, p.OwnerProof) || !bytes.Equal(capsule, p.Capsule) || !bytes.Equal(p.Code.OOBSecret, f.secret) {
		t.Fatal("expiry/new login renewed original approval or replaced S/proof/E")
	}
	requests := f.requests[wire.OperationOwnerNodePairTrustComplete]
	if len(requests) < 2 {
		t.Fatal("restart did not recover exact old complete")
	}
	for _, raw := range requests {
		if !bytes.Equal(raw, original) {
			t.Fatal("expired complete was resealed")
		}
	}
	if !c.nodeCanStartInitial() {
		t.Fatal("settled expired ceremony blocked a new code")
	}
	f.context.AttemptID = strings.Repeat("7c", 16)
	f.context.NodeNonce = strings.Repeat("6d", 32)
	f.context.IssuedAt = f.n.stamp(f.n.n2.now)
	f.context.ExpiresAt = f.n.stamp(f.n.n2.now.Add(10 * time.Minute))
	f.context.Candidate.ExpiresAt = f.context.ExpiresAt
	f.n.candidateOverride = f.context.Candidate
	f.secret = bytes.Repeat([]byte{0x54}, 32)
	var err error
	f.code, err = wire.EncodeNodePairTrustCode(f.context, f.n.code, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.NodePairTrustContextDigest(f.context)
	f.o, _ = wire.NodePairTrustOOBCommitment(digest, f.secret)
	f.state = wire.NodePairTrustPending
	f.review()
}

func TestNodePairingNodeACKWinsOverCancelOnlyWithOriginalReceipt(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	f.ack()
	c := f.n.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionCancelNodePairing, NodePairingReviewID: c.nodePairingReviewID()}); err != nil {
		t.Fatal(err)
	}
	if c.node.PairTrust.Stage != wire.NodePairTrustACKed || c.nodeConfirmation == nil || !bytes.Equal(c.nodeConfirmation.Operation.Response, f.confirmationResponse) || c.node.Client.NextRequest != 2 || c.node.Client.NextResponse != 2 {
		t.Fatal("cancel race bypassed original ACK receipt or advanced counters incorrectly")
	}
	if f.n.state != wire.AppNodeActive || c.node.PairTrust.CleanupComplete {
		t.Fatal("ACKed binding was cleaned up as a failed INITIAL grant")
	}
}

func TestNodePairingCleanupLostOriginalGrantCancelRestoresExactPacket(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	if err := f.approve(); err != nil {
		t.Fatal(err)
	}
	c := f.n.c
	f.n.drop = wire.OperationAppNodeCancel
	if c.Dispatch(context.Background(), Action{Kind: ActionCancelNodePairing, NodePairingReviewID: c.nodePairingReviewID()}) == nil {
		t.Fatal("lost cleanup cancellation reported success")
	}
	if !c.hasNodePending() || c.node.Pending.Operation != wire.OperationAppNodeCancel || c.node.PairTrust.CleanupComplete || !c.node.PairTrust.Confirmation.Applied {
		t.Fatal("cleanup lost original cancel or skipped negative settlement")
	}
	original := bytes.Clone(c.node.Pending.Request)
	f.reopen()
	c = f.n.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if !c.node.PairTrust.CleanupComplete || !c.nodeCanStartInitial() || c.nodeConfirmation != nil || f.n.binding != nil {
		t.Fatal("lost cancellation did not release only the unfinished grant")
	}
	var found bool
	for _, packet := range f.n.requests {
		if bytes.Equal(packet, original) {
			found = true
		}
	}
	if !found || c.node.Client.NextRequest != 2 {
		t.Fatal("cleanup rebuilt cancel or repeated Client negative slot")
	}
}

func TestNodePairingRecoveredSignedUncertaintyKeepsTargetRecoverable(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing uncertain target")
	}
	c := f.n.c
	p := c.node.PairTrust.Pending
	original := bytes.Clone(p.Request)
	digest := wire.NodePairTrustPacketDigest(original)
	var h wire.NodePairTrustPacket
	if json.Unmarshal(original, &h) != nil {
		t.Fatal("invalid original")
	}
	body, err := c.nodePairTrustBody(p)
	if err != nil {
		t.Fatal(err)
	}
	r := wire.NodePairTrustResult{Format: wire.NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: digest, State: wire.NodePairTrustPending, ErrorCode: "OUTCOME_UNCERTAIN", ObservedAt: f.n.stamp(f.n.n2.now)}
	f.receipts[digest], err = wire.SealNodePairTrustResponse(f.n.n2.hubKey, c.hub, original, body, r)
	if err != nil {
		t.Fatal(err)
	}
	f.errorCode, f.denyPacket = "", digest
	if c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}) == nil {
		t.Fatal("recovered uncertain original settled")
	}
	if p.Applied || len(p.Response) != 0 || c.node.PairTrust.Recovery != nil || !bytes.Equal(p.Request, original) {
		t.Fatal("outer uncertainty dropped target or pinned completed recovery")
	}
	delete(f.receipts, digest)
	f.denyPacket = ""
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Request, original) || !p.Applied || c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved {
		t.Fatal("target retry was replaced or could not settle")
	}
}

func TestNodePairingExpiredOuterObservationRefreshesOnlySameOriginalTarget(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing lost complete")
	}
	c := f.n.c
	original := bytes.Clone(c.node.PairTrust.Pending.Request)
	proof, capsule, secret := bytes.Clone(c.node.PairTrust.OwnerProof), bytes.Clone(c.node.PairTrust.Capsule), bytes.Clone(c.node.PairTrust.Code.OOBSecret)
	approval := *c.node.PairTrust.Approval
	f.denyPacket = wire.NodePairTrustPacketDigest(original)
	f.drop = wire.OperationNodePairTrustReconcile
	if c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}) == nil {
		t.Fatal("missing outer loss")
	}
	outer := bytes.Clone(c.node.PairTrust.Recovery.Request)
	f.n.n2.now = f.n.n2.now.Add(61 * time.Second)
	f.reopen()
	c = f.n.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	p := c.node.PairTrust
	if p.Stage != wire.NodePairTrustOwnerApproved || !reflect.DeepEqual(approval, *p.Approval) || !bytes.Equal(proof, p.OwnerProof) || !bytes.Equal(capsule, p.Capsule) || !bytes.Equal(secret, p.Code.OOBSecret) {
		t.Fatal("fresh observation renewed consent or original trust material")
	}
	queries := f.requests[wire.OperationNodePairTrustReconcile]
	if len(queries) < 2 || bytes.Equal(queries[len(queries)-1], outer) || f.expiredOuterPosts != 0 {
		t.Fatal("expired outer was endlessly replayed instead of refreshed")
	}
	var h wire.NodePairTrustPacket
	if json.Unmarshal(queries[len(queries)-1], &h) != nil {
		t.Fatal("bad outer")
	}
	q := f.bodies[wire.NodePairTrustPacketDigest(queries[len(queries)-1])].(*wire.NodePairTrustReconcile)
	if !bytes.Equal(q.OriginalPacket, original) || q.OriginalPacketDigest != wire.NodePairTrustPacketDigest(original) || len(f.requests[wire.OperationOwnerNodePairTrustComplete]) != 2 || c.node.Client.NextRequest != 1 {
		t.Fatal("fresh outer dispatched or replaced original mutation/counters")
	}
}

func TestNodePairingDurableOuterReceiptWinsOverObservationExpiry(t *testing.T) {
	f := newNodePairingFixture(t)
	f.review()
	f.drop = wire.OperationOwnerNodePairTrustComplete
	if f.approve() == nil {
		t.Fatal("missing original loss")
	}
	c := f.n.c
	f.denyPacket = wire.NodePairTrustPacketDigest(c.node.PairTrust.Pending.Request)
	f.drop = wire.OperationNodePairTrustReconcile
	if c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}) == nil {
		t.Fatal("missing outer loss")
	}
	p := c.node.PairTrust.Recovery
	p.Response = bytes.Clone(f.receipts[wire.NodePairTrustPacketDigest(p.Request)])
	if err := c.persistNodePairRecovery(); err != nil {
		t.Fatal(err)
	}
	before := len(f.requests[wire.OperationNodePairTrustReconcile])
	f.n.n2.now = f.n.n2.now.Add(61 * time.Second)
	f.reopen()
	c = f.n.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverNodePairing}); err != nil {
		t.Fatal(err)
	}
	if c.node.PairTrust.Stage != wire.NodePairTrustOwnerApproved || len(f.requests[wire.OperationNodePairTrustReconcile]) != before {
		t.Fatal("durable historical outer receipt was replaced by a new query")
	}
}
