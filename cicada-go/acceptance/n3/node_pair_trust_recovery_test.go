package n3_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

type nodePairCachedReceipt struct {
	operation, digest, state string
	response                 []byte
	count                    int
}

// This observer has no Store handle, signing key or write connection. The two
// production receipt classes must together contain exactly one original.
// It is safe to call from an opaque TCP fault's worker without testing.Fatal.
func nodePairCachedOriginal(hub *directIPHub, raw []byte) (nodePairCachedReceipt, error) {
	var h wire.NodePairTrustPacket
	if json.Unmarshal(raw, &h) != nil || h.RequestID == "" || h.SenderPublic.ID == "" {
		return nodePairCachedReceipt{}, wire.ErrInvalid
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(hub.state, "cicada.sqlite3"), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nodePairCachedReceipt{}, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT operation,request_digest,state,response_packet FROM hub_node_pair_trust_receipts_v1 WHERE sender_key_id=? AND request_id=? AND attempt_id=?
UNION ALL SELECT operation,request_digest,state,response_packet FROM hub_node_pair_trust_reads_v1 WHERE sender_key_id=? AND request_id=? AND attempt_id=?`,
		h.SenderPublic.ID, h.RequestID, h.AttemptID, h.SenderPublic.ID, h.RequestID, h.AttemptID)
	if err != nil {
		return nodePairCachedReceipt{}, err
	}
	defer rows.Close()
	var saved nodePairCachedReceipt
	for rows.Next() {
		var item nodePairCachedReceipt
		if err := rows.Scan(&item.operation, &item.digest, &item.state, &item.response); err != nil {
			return saved, err
		}
		saved.count++
		if saved.count == 1 {
			saved.operation, saved.digest, saved.state, saved.response = item.operation, item.digest, item.state, item.response
		} else {
			clear(item.response)
		}
	}
	return saved, rows.Err()
}

func nodePairOriginalBody(t *testing.T, p *nodePairSavedOperation) any {
	t.Helper()
	var body any
	switch p.Operation {
	case wire.OperationOwnerNodePairTrustPrepare:
		body = new(wire.NodePairTrustOwnerPrepare)
	case wire.OperationOwnerNodePairTrustComplete:
		body = new(wire.NodePairTrustOwnerComplete)
	case wire.OperationOwnerNodePairTrustStatus:
		body = new(wire.NodePairTrustOwnerStatus)
	default:
		t.Fatal("unexpected original operation in the owned recovery fault")
	}
	if json.Unmarshal(p.Body, body) != nil || !bytes.Equal(must(json.Marshal(body)), p.Body) {
		t.Fatal("durable original typed body is not canonical")
	}
	return body
}

// The real App must be closed before this independent receipt verification.
// Only APP_DEVICE is retrieved; the QA parent never obtains an Owner signer.
func (v *nodePairFixture) originalAppDevice(t *testing.T) *e2ee.Identity {
	t.Helper()
	if v.app.running() {
		t.Fatal("independent original-device check requires the actual App to be closed")
	}
	vault := must(syntheticVaultOpener(filepath.Join(v.app.dir, "home", ".cicada", "app", "vaults"))(context.Background(), directIPScope(v.hub), false))
	defer vault.Close()
	for _, entry := range must(vault.List()) {
		if entry.Purpose == appvault.PurposeAppDevice {
			key := must(vault.Get(appvault.PurposeAppDevice, entry.KeyID))
			t.Cleanup(key.Close)
			return must(key.E2EE())
		}
	}
	t.Fatal("original scoped App-device identity unavailable")
	return nil
}

func (v *nodePairFixture) replayOriginal(t *testing.T, original *nodePairSavedOperation) []byte {
	t.Helper()
	client := must(hubtransport.NewHTTPClient(v.hub.descriptor, v.hub.address, 10*time.Second))
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := must(http.NewRequestWithContext(ctx, http.MethodPost, v.hub.material.Origin+wire.NodePairTrustHTTPPath(original.Operation), bytes.NewReader(original.Request)))
	request.Header.Set("Content-Type", "application/json")
	reply := must(client.Do(request))
	defer reply.Body.Close()
	raw := must(io.ReadAll(io.LimitReader(reply.Body, wire.MaxNodePairTrustResponsePacketBytes+1)))
	if reply.StatusCode != http.StatusOK || len(raw) == 0 || len(raw) > wire.MaxNodePairTrustResponsePacketBytes {
		clear(raw)
		t.Fatal("actual Hub did not return a bounded exact replay receipt")
	}
	return raw
}

func nodePairAssertRetainedConsent(t *testing.T, before, after *nodePairSavedApp) {
	t.Helper()
	a, b := before.PairTrust, after.PairTrust
	if len(a.Code) == 0 || !bytes.Equal(a.Code, b.Code) || a.Confirmation == nil || b.Confirmation == nil || !bytes.Equal(a.Confirmation.Request, b.Confirmation.Request) ||
		a.Confirmation.ExpectedResponseSequence != b.Confirmation.ExpectedResponseSequence ||
		(len(a.OwnerProof) != 0 && !bytes.Equal(a.OwnerProof, b.OwnerProof)) || (len(a.Capsule) != 0 && !bytes.Equal(a.Capsule, b.Capsule)) ||
		(a.Approval != nil && !reflect.DeepEqual(a.Approval, b.Approval)) {
		t.Fatal("recovery replaced original confirmation, reserved sequence, Owner proof or capsule")
	}
}

func nodePairLostCommittedComplete(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t) // Retain OWNER_APPROVED independently of a racing Node ACK.
	v.review(t)
	v.app.command(t, directIPAppCommand{Close: true})
	appDir := v.app.dir
	fault := newDirectIPCipherFault(t, v.hub.address, func() bool {
		image, err := nodePairCopiedAppState(v.hub, appDir)
		if err != nil {
			return false
		}
		defer image.clear()
		p := image.PairTrust.Pending
		if p == nil || p.Operation != wire.OperationOwnerNodePairTrustComplete || len(p.Request) == 0 || len(p.Response) != 0 || p.Applied {
			return false
		}
		cached, err := nodePairCachedOriginal(v.hub, p.Request)
		defer clear(cached.response)
		return err == nil && cached.count == 1 && cached.operation == p.Operation &&
			cached.digest == wire.NodePairTrustPacketDigest(p.Request) && cached.state == wire.NodePairTrustOwnerApproved && len(cached.response) != 0
	})
	s := v.resumeAppAddress(t, fault.listener.Addr().String())
	if s.Node.Pairing == nil || s.Node.Pairing.State != "REVIEW" {
		t.Fatal("actual App failed to restore the same consent review before TLS response loss")
	}
	// Follow the actual reopened UI before attempting approval. A readonly
	// Check must retain the original review/code/deadline and restore approval
	// availability; it must not silently replace consent or create a new code.
	canApprove, canCheck := false, false
	for _, action := range s.AvailableActions {
		canApprove = canApprove || action == appcore.ActionApproveNodePairing
		canCheck = canCheck || action == appcore.ActionRefreshNodePairing
	}
	if !canApprove {
		if !canCheck {
			t.Fatal("reopened original review exposes neither approval nor readonly Check")
		}
		beforeCheck := v.copiedAppState(t)
		defer beforeCheck.clear()
		review, expiry := s.Node.Pairing.ReviewID, s.Node.Pairing.ExpiresAt
		s = v.action(t, appcore.Action{Kind: appcore.ActionRefreshNodePairing})
		afterCheck := v.copiedAppState(t)
		defer afterCheck.clear()
		for _, action := range s.AvailableActions {
			canApprove = canApprove || action == appcore.ActionApproveNodePairing
		}
		stage := "NONE"
		sameReview, sameExpiry := false, false
		if p := s.Node.Pairing; p != nil {
			stage, sameReview, sameExpiry = p.State, p.ReviewID == review, p.ExpiresAt == expiry
		}
		sameCode := len(beforeCheck.PairTrust.Code) != 0 && bytes.Equal(beforeCheck.PairTrust.Code, afterCheck.PairTrust.Code)
		if stage != "REVIEW" || !sameReview || !sameExpiry || !sameCode || !canApprove {
			t.Fatalf("actual reopened review Check did not preserve a reachable original approval: before_approve=false Check=true after_pairing=%s after_approve=%t review_same=%t expiry_same=%t secret_code_same=%t", stage, canApprove, sameReview, sameExpiry, sameCode)
		}
	}
	fault.armed.Store(true)
	time.Sleep(time.Second)
	failed := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: s.Node.Pairing.ReviewID, ConfirmNodePairing: true}})
	fault.armed.Store(false)
	if !failed.ActionFailed || !fault.dropped.Load() || fault.cuts.Load() != 1 || fault.bytes.Load() == 0 || failed.Snapshot.Node.Binding != nil {
		stage := "NONE"
		if failed.Snapshot.Node.Pairing != nil {
			stage = failed.Snapshot.Node.Pairing.State
		}
		t.Fatalf("lost committed OwnerComplete response was not retained as an uncertain unbound result: action_failed=%t dropped=%t cuts=%d opaque_bytes=%d bound=%t pairing=%s error=%s Node_error=%s",
			failed.ActionFailed, fault.dropped.Load(), fault.cuts.Load(), fault.bytes.Load(), failed.Snapshot.Node.Binding != nil, stage, failed.Snapshot.ErrorCode, failed.Snapshot.Node.ErrorCode)
	}
	before := v.copiedAppState(t)
	defer before.clear()
	original := before.PairTrust.Pending
	if original == nil || original.Operation != wire.OperationOwnerNodePairTrustComplete || len(original.Response) != 0 || original.Applied {
		t.Fatal("actual App lost its exact durable OwnerComplete after network response loss")
	}
	cached := must(nodePairCachedOriginal(v.hub, original.Request))
	defer clear(cached.response)
	if cached.count != 1 || cached.digest != wire.NodePairTrustPacketDigest(original.Request) || cached.state != wire.NodePairTrustOwnerApproved {
		t.Fatal("independent durable observation did not confirm the exact original OwnerComplete")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	device := v.originalAppDevice(t)
	result := must(wire.OpenNodePairTrustResponse(device, v.hub.descriptor.Claims.Hub, original.Request, cached.response, nodePairOriginalBody(t, original)))
	if result.State != wire.NodePairTrustOwnerApproved || result.ErrorCode != "" {
		t.Fatal("original scoped App device could not authenticate the committed original receipt")
	}
	v.hub.hub.kill(t)
	v.hub.start(t)
	v.start(t)
	v.awaitHubACK(t)
	v.resumeApp(t)
	v.action(t, appcore.Action{Kind: appcore.ActionRecoverNodePairing})
	s = v.awaitACK(t)
	known := v.replayOriginal(t, original)
	defer clear(known)
	if !bytes.Equal(known, cached.response) {
		t.Fatal("actual Hub replay changed the original committed ciphertext after process restart")
	}
	after := v.copiedAppState(t)
	defer after.clear()
	nodePairAssertRetainedConsent(t, before, after)
	final := must(nodePairCachedOriginal(v.hub, original.Request))
	defer clear(final.response)
	if final.count != 1 || !bytes.Equal(final.response, cached.response) || s.Node.Binding == nil {
		t.Fatal("recovery duplicated the original effect or failed to project its original binding")
	}
	v.assertAutomaticOwnerPin(t, s)
	t.Logf("NODE_PAIR_RECOVERY committed_original_digest=%s receipt_sha256=%s rows=1 opaque_cipher_bytes=%d", cached.digest, hash(cached.response), fault.bytes.Load())
}

func nodePairUnforwardedOriginal(t *testing.T, target string) {
	v := newNodePairFixture(t, "127.0.0.1")
	if target == wire.OperationOwnerNodePairTrustStatus {
		v.approve(t)
		v.awaitHubACK(t) // Deliberately leave the actual App at OWNER_APPROVED.
	} else {
		v.node.kill(t)
		v.review(t)
	}
	v.app.command(t, directIPAppCommand{Close: true})
	var mu sync.Mutex
	originalDigest := ""
	appDir := v.app.dir
	fault := newDirectIPCipherFaultDirection(t, v.hub.address, func() bool {
		image, err := nodePairCopiedAppState(v.hub, appDir)
		if err != nil {
			return false
		}
		defer image.clear()
		p := image.PairTrust.Pending
		if image.PairTrust.Recovery != nil || p == nil || p.Applied || len(p.Response) != 0 || len(p.Request) == 0 || p.Operation != target {
			return false
		}
		digest := wire.NodePairTrustPacketDigest(p.Request)
		mu.Lock()
		defer mu.Unlock()
		if originalDigest == "" {
			originalDigest = digest
		}
		return originalDigest == digest // A known no-effect successor is not the old request.
	}, true, true)
	s := v.resumeAppAddress(t, fault.listener.Addr().String())
	var action appcore.Action
	if target == wire.OperationOwnerNodePairTrustStatus {
		action.Kind = appcore.ActionRefreshNodePairing
	} else {
		if s.Node.Pairing == nil || s.Node.Pairing.State != "REVIEW" {
			t.Fatal("actual App lost its original review before the unforwarded request")
		}
		action = appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: s.Node.Pairing.ReviewID, ConfirmNodePairing: true}
	}
	fault.armed.Store(true)
	time.Sleep(time.Second)
	failed := v.app.command(t, directIPAppCommand{Action: &action})
	if !failed.ActionFailed || !fault.dropped.Load() {
		t.Fatal("before-forward TLS cut did not retain an uncertain original operation")
	}
	before := v.copiedAppState(t)
	defer before.clear()
	original := before.PairTrust.Pending
	if original == nil || original.Operation != target || original.Applied || len(original.Request) == 0 || len(original.Response) != 0 {
		t.Fatal("unforwarded original request was not durably retained")
	}
	cached := must(nodePairCachedOriginal(v.hub, original.Request))
	clear(cached.response)
	if cached.count != 0 {
		t.Fatal("before-forward cut allowed the exact original request to reach Hub")
	}
	contextBefore, stateBefore := v.side(t)
	if target == wire.OperationOwnerNodePairTrustStatus && stateBefore != wire.NodePairTrustACKed ||
		target != wire.OperationOwnerNodePairTrustStatus && stateBefore != wire.NodePairTrustPending {
		t.Fatal("unforwarded request unexpectedly changed the actual attempt state")
	}
	// Keep the original and its retry cut. A durable separately sealed reconcile
	// is allowed through unchanged, so Hub must fence this exact absent request.
	recovered := v.action(t, appcore.Action{Kind: appcore.ActionRecoverNodePairing})
	fault.armed.Store(false)
	if fault.cuts.Load() < 2 || recovered.Node.Pairing == nil || recovered.Node.Pairing.State == wire.NodePairTrustFenced {
		t.Fatal("single original request FENCED was confused with an attempt terminal state")
	}
	fenced := must(nodePairCachedOriginal(v.hub, original.Request))
	defer clear(fenced.response)
	if fenced.count != 1 || fenced.state != wire.NodePairTrustFenced || fenced.digest != wire.NodePairTrustPacketDigest(original.Request) {
		t.Fatal("actual reconcile did not durably fence only the exact unadmitted original")
	}
	afterFence := v.copiedAppState(t)
	defer afterFence.clear()
	nodePairAssertRetainedConsent(t, before, afterFence)
	contextAfter, _ := v.side(t)
	if !reflect.DeepEqual(contextBefore, contextAfter) {
		t.Fatal("known no-effect recovery renewed or replaced the immutable attempt")
	}
	if target != wire.OperationOwnerNodePairTrustStatus {
		v.start(t)
	}
	s = v.awaitACK(t)
	v.assertAutomaticOwnerPin(t, s)
	v.app.command(t, directIPAppCommand{Close: true})
	device := v.originalAppDevice(t)
	late := v.replayOriginal(t, original)
	defer clear(late)
	result := must(wire.OpenNodePairTrustResponse(device, v.hub.descriptor.Claims.Hub, original.Request, late, nodePairOriginalBody(t, original)))
	if !bytes.Equal(late, fenced.response) || result.State != wire.NodePairTrustFenced || result.ErrorCode != "FENCED" {
		t.Fatal("late original packet bypassed its immutable authenticated no-effect fence")
	}
	_, finalState := v.side(t)
	if finalState != wire.NodePairTrustACKed {
		t.Fatal("late fenced request changed the separately completed actual attempt")
	}
	t.Logf("NODE_PAIR_RECOVERY fenced_operation=%s original_digest=%s receipt_sha256=%s cuts=%d", target, fenced.digest, hash(late), fault.cuts.Load())
}

func nodePairOriginalResponseLoss(t *testing.T) {
	// These are sequential, separately owned full installations. The fault peer
	// has no TLS/Hub/App keys and observes only private durable state predicates.
	nodePairLostCommittedComplete(t)
	for _, target := range []string{wire.OperationOwnerNodePairTrustPrepare, wire.OperationOwnerNodePairTrustComplete, wire.OperationOwnerNodePairTrustStatus} {
		nodePairUnforwardedOriginal(t, target)
	}
	nodePairAgedOuterRecovery(t)
	nodePairFacts(t, "NPT08_OriginalResponseLoss", map[string]bool{"actual_TLS_response_loss": true,
		"independent_commit_observation": true, "same_request_and_receipt_bytes": true,
		"authenticated_original_recovery": true, "unadmitted_original_fenced": true})
}

func nodePairRecoveryTarget(t *testing.T, saved *nodePairSavedApp) wire.NodePairTrustReconcile {
	t.Helper()
	if saved.PairTrust == nil || saved.PairTrust.Pending == nil || saved.PairTrust.Recovery == nil {
		t.Fatal("actual durable outer recovery target unavailable")
	}
	p := saved.PairTrust.Recovery
	var q wire.NodePairTrustReconcile
	if json.Unmarshal(p.Body, &q) != nil || len(q.OriginalPacket) != 0 || q.OriginalPacketDigest != wire.NodePairTrustPacketDigest(saved.PairTrust.Pending.Request) {
		t.Fatal("compact recovery target changed or duplicated its original raw packet")
	}
	q.OriginalPacket = bytes.Clone(saved.PairTrust.Pending.Request)
	if p.BodyDigest != wire.NodePairTrustPacketDigest(must(json.Marshal(q))) {
		t.Fatal("compact recovery rehydration changed its original canonical body commitment")
	}
	return q
}

func nodePairAgedOuterRecovery(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.review(t)
	v.app.command(t, directIPAppCommand{Close: true})
	appDir := v.app.dir
	// Two opaque peers preserve the original TLS connection end to end. The
	// first holds only original Complete bytes; the other cuts two separately
	// committed outer observations, with a real >60s offline interval between.
	var observedMu sync.Mutex
	observed := make(map[string]bool)
	outer := newDirectIPCipherFaultDirection(t, v.hub.address, func() bool {
		image, err := nodePairCopiedAppState(v.hub, appDir)
		if err != nil {
			return false
		}
		defer image.clear()
		p := image.PairTrust.Recovery
		if p == nil || len(p.Request) == 0 || len(p.Response) != 0 {
			return false
		}
		digest := wire.NodePairTrustPacketDigest(p.Request)
		observedMu.Lock()
		defer observedMu.Unlock()
		if observed[digest] || len(observed) >= 2 {
			return false
		}
		cached, err := nodePairCachedOriginal(v.hub, p.Request)
		defer clear(cached.response)
		if err != nil || cached.count != 1 || cached.operation != wire.OperationNodePairTrustReconcile || cached.digest != digest {
			return false
		}
		observed[digest] = true
		return true
	}, false, true)
	var originalMu sync.Mutex
	originalDigest := ""
	originalFault := newDirectIPCipherFaultDirection(t, outer.listener.Addr().String(), func() bool {
		image, err := nodePairCopiedAppState(v.hub, appDir)
		if err != nil {
			return false
		}
		defer image.clear()
		p := image.PairTrust.Pending
		if image.PairTrust.Recovery != nil || p == nil || p.Operation != wire.OperationOwnerNodePairTrustComplete || p.Applied || len(p.Response) != 0 {
			return false
		}
		digest := wire.NodePairTrustPacketDigest(p.Request)
		originalMu.Lock()
		defer originalMu.Unlock()
		if originalDigest == "" {
			originalDigest = digest
		}
		return originalDigest == digest
	}, true, true)
	s := v.resumeAppAddress(t, originalFault.listener.Addr().String())
	if s.Node.Pairing == nil || s.Node.Pairing.ReviewID == "" {
		t.Fatal("aged outer recovery lost its original consent review")
	}
	originalFault.armed.Store(true)
	outer.armed.Store(true)
	time.Sleep(time.Second)
	failed := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: s.Node.Pairing.ReviewID, ConfirmNodePairing: true}})
	if !failed.ActionFailed || originalFault.cuts.Load() != 1 {
		t.Fatal("aged outer recovery did not hold the exact original Complete")
	}
	time.Sleep(time.Second)
	lost := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionRecoverNodePairing}})
	if !lost.ActionFailed || originalFault.cuts.Load() < 2 || outer.cuts.Load() != 1 {
		t.Fatal("outer observation response was not lost after the exact original was durably fenced")
	}
	before := v.copiedAppState(t)
	defer before.clear()
	first := nodePairRecoveryTarget(t, before)
	defer clear(first.OriginalPacket)
	original := before.PairTrust.Pending
	fenced := must(nodePairCachedOriginal(v.hub, original.Request))
	defer clear(fenced.response)
	if fenced.count != 1 || fenced.state != wire.NodePairTrustFenced {
		t.Fatal("lost outer observation did not independently commit the original no-effect fence")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	// Keep real time and unchanged deadlines. A historical response is useful
	// evidence, never an extension of the original approval's acceptance window.
	issued := must(time.Parse(time.RFC3339Nano, first.IssuedAt))
	if wait := time.Until(issued.Add(61 * time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	v.hub.hub.kill(t)
	v.hub.start(t)
	v.app = startDirectIPApp(t, appDir)
	profiles := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if profiles.ActionFailed || len(profiles.Snapshot.Profiles) != 1 {
		t.Fatal("actual aged recovery lost its sole original profile")
	}
	resumed := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles.Snapshot.Profiles[0].ID, HubAddress: originalFault.listener.Addr().String()}})
	if !resumed.Snapshot.Hub.Verified || resumed.Snapshot.Account.DeviceID != v.original.Account.DeviceID || resumed.Snapshot.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID {
		t.Fatal("actual offline recovery replaced its original identity")
	}
	if outer.cuts.Load() < 2 {
		time.Sleep(time.Second)
		v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionRecoverNodePairing}})
	}
	if outer.cuts.Load() != 2 {
		t.Fatal("expired outer query deadlocked instead of persisting a fresh observation for the same target")
	}
	secondImage := v.copiedAppState(t)
	defer secondImage.clear()
	second := nodePairRecoveryTarget(t, secondImage)
	defer clear(second.OriginalPacket)
	if !bytes.Equal(first.OriginalPacket, second.OriginalPacket) || first.OriginalPacketDigest != second.OriginalPacketDigest ||
		bytes.Equal(before.PairTrust.Recovery.Request, secondImage.PairTrust.Recovery.Request) || first.IssuedAt == second.IssuedAt {
		t.Fatal("fresh outer observation replaced/nested its original mutation instead of keeping one exact target")
	}
	nodePairAssertRetainedConsent(t, before, secondImage)
	outer.armed.Store(false)
	originalFault.armed.Store(false)
	settled := v.action(t, appcore.Action{Kind: appcore.ActionRecoverNodePairing})
	after := v.copiedAppState(t)
	defer after.clear()
	nodePairAssertRetainedConsent(t, before, after)
	canInspect := false
	for _, action := range settled.AvailableActions {
		canInspect = canInspect || action == appcore.ActionSessionInspect
	}
	t.Logf("NODE_PAIR_AGED_PUBLIC_STATE recovery_present=%t fenced_operation=%s stage=%s pending_operation=%s pending_applied=%t account=%s session_inspect_available=%t actions=%v",
		after.PairTrust.Recovery != nil, after.PairTrust.FencedOperation, after.PairTrust.Stage, after.PairTrust.Pending.Operation, after.PairTrust.Pending.Applied,
		settled.Account.State, canInspect, settled.AvailableActions)
	// Unlock explicitly requires a fresh authenticated session inspection.
	// An outer historical receipt can settle its original packet while that
	// current authorization check is still pending. Follow the public UI;
	// never convert the historical receipt itself into fresh permission.
	if after.PairTrust.Recovery == nil && after.PairTrust.FencedOperation != "" && canInspect {
		inspected := v.action(t, appcore.Action{Kind: appcore.ActionSessionInspect})
		canRecover := false
		for _, action := range inspected.AvailableActions {
			canRecover = canRecover || action == appcore.ActionRecoverNodePairing
		}
		if !canRecover {
			t.Fatal("authenticated session inspection did not expose recovery of the original known-no-effect request")
		}
		v.action(t, appcore.Action{Kind: appcore.ActionRecoverNodePairing})
		after = v.copiedAppState(t)
		defer after.clear()
		nodePairAssertRetainedConsent(t, before, after)
	}
	if after.PairTrust.Recovery != nil || after.PairTrust.FencedOperation != "" || after.PairTrust.Stage == wire.NodePairTrustFenced {
		t.Fatalf("fresh observation failed to settle its known no-effect packet independently of attempt state: recovery_present=%t fenced_operation=%s stage=%s pending_operation=%s pending_applied=%t",
			after.PairTrust.Recovery != nil, after.PairTrust.FencedOperation, after.PairTrust.Stage, after.PairTrust.Pending.Operation, after.PairTrust.Pending.Applied)
	}
	v.app.command(t, directIPAppCommand{Close: true})
	device := v.originalAppDevice(t)
	cached := must(nodePairCachedOriginal(v.hub, secondImage.PairTrust.Recovery.Request))
	defer clear(cached.response)
	outerResult := must(wire.OpenNodePairTrustResponse(device, v.hub.descriptor.Claims.Hub, secondImage.PairTrust.Recovery.Request, cached.response, second))
	if outerResult.State != wire.NodePairTrustRecovered {
		t.Fatal("fresh outer observation did not return its authenticated original receipt")
	}
	inner, receipt, err := wire.OpenNodePairTrustRecoveredResponse(device, v.hub.descriptor.Claims.Hub,
		secondImage.PairTrust.Recovery.Request, cached.response, second, nodePairOriginalBody(t, original))
	if err != nil || inner.State != wire.NodePairTrustFenced || inner.ErrorCode != "FENCED" || !bytes.Equal(receipt, fenced.response) {
		t.Fatal("fresh outer observation did not double-authenticate the exact original no-effect receipt")
	}
	if before.PairTrust.Approval != nil && !time.Now().UTC().Before(must(time.Parse(time.RFC3339Nano, before.PairTrust.Approval.AcceptBefore))) {
		confirmation := after.PairTrust.Confirmation
		if after.PairTrust.Stage != wire.NodePairTrustExpired || confirmation == nil || confirmation.GrantClaims == nil || !confirmation.Applied || len(confirmation.Response) == 0 {
			t.Fatal("expired original approval deadlocked instead of settling its exact negative Client receipt")
		}
		result := must(wire.OpenAppNodeConfirmationResponse(device, v.hub.descriptor.Claims.Hub, *confirmation.GrantClaims,
			confirmation.Request, confirmation.Response, confirmation.ExpectedResponseSequence))
		if result.OK || result.Binding != nil {
			t.Fatal("aged historical recovery renewed expired original admission rights")
		}
	}
	t.Logf("NODE_PAIR_RECOVERY aged_outer_actual_offline_seconds=%d original_target=%s old_outer=%s fresh_outer=%s", int64(time.Since(issued).Seconds()), first.OriginalPacketDigest,
		wire.NodePairTrustPacketDigest(before.PairTrust.Recovery.Request), wire.NodePairTrustPacketDigest(secondImage.PairTrust.Recovery.Request))
}
