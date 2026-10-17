package appcore

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func pairActionKind(kind ActionKind) bool {
	switch kind {
	case ActionPreparePair, ActionCompletePair, ActionRefreshPair, ActionPreparePairConsent, ActionApprovePairSlot, ActionRejectPairSlot, ActionRevokePair, ActionRecoverPair:
		return true
	}
	return false
}

func (c *nativeController) ensurePairLoaded() error {
	if c.pair.Format == "" || c.pairOriginal == nil && c.pair.View.PairID == "" &&
		(c.pair.DeviceID != c.state.DeviceID || c.pair.DeviceKeyID != c.state.DeviceKeyID || c.pair.OwnerKeyID != c.state.OwnerKeyID) {
		if err := c.loadPairState(); err != nil {
			return c.failPairStorage(err)
		}
	}
	return nil
}

func (c *nativeController) requirePairAdmin(ctx context.Context) error {
	if err := c.ensurePairLoaded(); err != nil {
		return err
	}
	if !c.pairCanStart() {
		return ErrInvalidAction
	}
	if !c.pairAvailable {
		if err := c.discoverPairAvailability(ctx); err != nil {
			return c.failPair("APP_PAIR_UNAVAILABLE", err)
		}
	}
	return nil
}

func (c *nativeController) preparePair(ctx context.Context, action PairAction) error {
	label := strings.TrimSpace(action.Label)
	if label == "" || len(label) > 128 || !utf8.ValidString(label) || strings.ContainsAny(label, "\x00\r\n") {
		return ErrInvalidAction
	}
	if err := c.requirePairAdmin(ctx); err != nil {
		return err
	}
	if c.pair.View.PairID != "" && c.pair.View.State != string(wire.NativePairExpired) && c.pair.View.State != string(wire.NativePairRevoked) {
		return ErrInvalidAction
	}
	scope, err := c.pairBootstrapScope(ctx)
	if err != nil {
		return err
	}
	claims, qctx, err := c.pairClaims(scope, e2ee.OwnerNativePairBootstrapPreview, time.Time{})
	if err != nil {
		return err
	}
	claims.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: label, Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	owner, _ := c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		return err
	}
	request := wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: qctx, SessionToken: c.session.SessionToken, OwnerProof: proof}
	return c.sendNewPair(ctx, scope, "", request)
}

func (c *nativeController) completePair(ctx context.Context, action PairAction) error {
	if err := c.requirePairAdmin(ctx); err != nil {
		return err
	}
	if !action.ConfirmBootstrap || action.PairID != c.pair.View.PairID || action.ReviewID != c.pair.View.ReviewID || !c.pair.View.AdministrativePermission {
		return ErrInvalidAction
	}
	review, err := c.pairReviewReceipt(true)
	if err != nil || review.Bootstrap == nil || !c.pairScopeCurrent(review.Bootstrap.Scope) {
		return c.failPair("APP_PAIR_TARGET_CHANGED", wire.ErrInvalid)
	}
	ch := review.Bootstrap
	claims, qctx, err := c.pairClaims(ch.Scope, e2ee.OwnerNativePairBootstrapCommit, parseExpiry(ch.ProofExpiresAt))
	if err != nil {
		return err
	}
	claims.Bootstrap = &ch.Bootstrap
	owner, _ := c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		return err
	}
	request := wire.NativePairBootstrapComplete{Format: wire.NativePairFormat, Context: qctx, SessionToken: c.session.SessionToken, OwnerProof: proof}
	return c.sendNewPair(ctx, ch.Scope, ch.Bootstrap.PairID, request)
}

func (c *nativeController) refreshPair(ctx context.Context) error {
	if err := c.ensurePairLoaded(); err != nil {
		return err
	}
	if c.pair.View.PairID == "" || c.hasPairPending() || c.hasNodePending() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return ErrInvalidAction
	}
	if !c.pairAvailable {
		if err := c.discoverPairAvailability(ctx); err != nil {
			return c.failPair("APP_PAIR_UNAVAILABLE", err)
		}
	}
	var scope e2ee.OwnerNativePairScope
	var token []byte
	if c.pairAccountReady() {
		var err error
		scope, err = c.pairFullScope(ctx)
		if err != nil {
			return err
		}
		token = c.session.SessionToken
	} else if c.pairOriginal != nil {
		scope = c.pairOriginal.Target.Scope
	} else {
		return ErrInvalidAction
	}
	qctx, err := c.pairRequestContext(scope, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	request := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: qctx, SessionToken: token, PairID: c.pair.View.PairID}
	return c.sendNewPair(ctx, scope, c.pair.View.PairID, request)
}

func (c *nativeController) preparePairConsent(ctx context.Context, action PairAction) error {
	if err := c.requirePairAdmin(ctx); err != nil {
		return err
	}
	v := c.pairCurrent
	if v == nil || !c.pair.View.Current || !c.pair.View.AdministrativePermission || action.PairID != v.PairID ||
		v.SlotA == nil || v.SlotB == nil || (v.State != wire.NativePairWaitingJoin && v.State != wire.NativePairWaitingConsent) ||
		v.SlotA.NativeSessionID == v.SlotB.NativeSessionID {
		return ErrInvalidAction
	}
	scope, err := c.pairFullScope(ctx)
	if err != nil || wire.ValidateNativePairSlot(*v.SlotA, scope, v.PeerExpiresAt) != nil || wire.ValidateNativePairSlot(*v.SlotB, scope, v.PeerExpiresAt) != nil {
		return c.failPair("APP_PAIR_TARGET_CHANGED", wire.ErrInvalid)
	}
	for _, state := range []wire.NativePairSlotState{v.SlotAState, v.SlotBState} {
		if state != wire.NativePairSlotCandidateReady && state != wire.NativePairSlotConsentRecorded {
			return ErrInvalidAction
		}
	}
	a, _ := wire.NativePairSlotDigest(*v.SlotA)
	b, _ := wire.NativePairSlotDigest(*v.SlotB)
	claims, qctx, err := c.pairClaims(scope, e2ee.OwnerNativePairConsentPreview, time.Time{})
	if err != nil {
		return err
	}
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: v.PairID, ExpectedRevision: v.ControlRevision, SlotADigest: a, SlotBDigest: b, PeerExpiresAt: v.PeerExpiresAt}
	owner, _ := c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		return err
	}
	request := wire.NativePairConsentPrepare{Format: wire.NativePairFormat, Context: qctx, SessionToken: c.session.SessionToken, OwnerProof: proof}
	return c.sendNewPair(ctx, scope, v.PairID, request)
}

func (c *nativeController) approvePairSlot(ctx context.Context, action PairAction) error {
	if err := c.requirePairAdmin(ctx); err != nil {
		return err
	}
	if !action.ConfirmSlot || action.PairID != c.pair.View.PairID || action.ReviewID != c.pair.View.ReviewID || !c.pair.View.AdministrativePermission || (action.Slot != "A" && action.Slot != "B") {
		return ErrInvalidAction
	}
	review, err := c.pairReviewReceipt(true)
	if err != nil || review.Plan == nil || !c.pairScopeCurrent(review.Plan.Plan.Scope) {
		return c.failPair("APP_PAIR_TARGET_CHANGED", wire.ErrInvalid)
	}
	p := review.Plan.Plan
	slot, peer, manifest, index := p.SlotA, p.SlotB, p.SlotAKeyManifest, 0
	if action.Slot == "B" {
		slot, peer, manifest, index = p.SlotB, p.SlotA, p.SlotBKeyManifest, 1
	}
	if c.pair.View.Slots[index].ConsentRecorded {
		return ErrInvalidAction
	}
	a, _ := wire.NativePairSlotDigest(p.SlotA)
	b, _ := wire.NativePairSlotDigest(p.SlotB)
	claims, qctx, err := c.pairClaims(p.Scope, e2ee.OwnerNativePairSlotConsent, parseExpiry(p.ExpiresAt))
	if err != nil {
		return err
	}
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: p.PairID, ExpectedRevision: p.ExpectedRevision, PlanID: p.PlanID, PlanDigest: p.Digest,
		SlotADigest: a, SlotBDigest: b, Slot: slot.Slot, SlotGeneration: slot.Generation, SlotAttemptID: slot.AttemptID,
		NativeSessionID: slot.NativeSessionID, PeerNativeSessionID: peer.NativeSessionID, ActivateWhenBoth: true, PlanExpiresAt: p.ExpiresAt, PeerExpiresAt: p.PeerExpiresAt}
	if wire.ValidateNativePairConsentTarget(claims, p) != nil {
		return wire.ErrInvalid
	}
	owner, _ := c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		return err
	}
	groupProof, err := owner.SignOwnerLinkKeyGrant(c.state.OwnerID, "group-endpoint-key-grant:v1", manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, c.cfg.Now().UTC(), parseExpiry(manifest.ExpiresAt))
	if err != nil {
		return err
	}
	request := wire.NativePairConsentComplete{Format: wire.NativePairFormat, Context: qctx, SessionToken: c.session.SessionToken, OwnerProof: proof, GroupKeyProof: groupProof}
	return c.sendNewPair(ctx, p.Scope, p.PairID, request)
}

func (c *nativeController) rejectPairSlot(ctx context.Context, action PairAction) error {
	if err := c.requirePairAdmin(ctx); err != nil {
		return err
	}
	v := c.pairCurrent
	if v == nil || !c.pair.View.Current || !c.pair.View.AdministrativePermission || action.PairID != v.PairID || action.ReviewID != c.pair.View.StateReviewID ||
		(v.State != wire.NativePairWaitingJoin && v.State != wire.NativePairWaitingConsent) || (action.Slot != "A" && action.Slot != "B") {
		return ErrInvalidAction
	}
	slot := v.SlotA
	if action.Slot == "B" {
		slot = v.SlotB
	}
	if slot == nil || slot.NativeSessionID == "" {
		return ErrInvalidAction
	}
	scope, err := c.pairFullScope(ctx)
	if err != nil {
		return err
	}
	digest, err := wire.NativePairSlotDigest(*slot)
	if err != nil {
		return err
	}
	claims, qctx, err := c.pairClaims(scope, e2ee.OwnerNativePairSlotReject, time.Time{})
	if err != nil {
		return err
	}
	claims.Reject = &e2ee.NativePairRejectClaims{PairID: v.PairID, ExpectedRevision: v.ControlRevision, Slot: slot.Slot,
		SlotGeneration: slot.Generation, SlotAttemptID: slot.AttemptID, SlotDigest: digest}
	owner, _ := c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		return err
	}
	return c.sendNewPair(ctx, scope, v.PairID, wire.NativePairSlotReject{Format: wire.NativePairFormat, Context: qctx, SessionToken: c.session.SessionToken, OwnerProof: proof})
}

func (c *nativeController) revokePair(ctx context.Context, action PairAction) error {
	if err := c.requirePairAdmin(ctx); err != nil {
		return err
	}
	v := c.pairCurrent
	if v == nil || !action.ConfirmRevoke || !c.pair.View.Current || !c.pair.View.AdministrativePermission || action.PairID != v.PairID || action.ReviewID != c.pair.View.StateReviewID {
		return ErrInvalidAction
	}
	scope, err := c.pairFullScope(ctx)
	if err != nil {
		return err
	}
	digest, err := wire.NativePairRevokeTargetDigest(scope, v.PairID, v.ControlRevision)
	if err != nil {
		return err
	}
	claims, qctx, err := c.pairClaims(scope, e2ee.OwnerNativePairRevoke, time.Time{})
	if err != nil {
		return err
	}
	claims.Revoke = &e2ee.NativePairRevokeClaims{PairID: v.PairID, ExpectedRevision: v.ControlRevision, PairTargetDigest: digest}
	if wire.ValidateNativePairRevokeTarget(claims) != nil {
		return wire.ErrInvalid
	}
	owner, _ := c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		return err
	}
	return c.sendNewPair(ctx, scope, v.PairID, wire.NativePairRevoke{Format: wire.NativePairFormat, Context: qctx, SessionToken: c.session.SessionToken, OwnerProof: proof})
}
