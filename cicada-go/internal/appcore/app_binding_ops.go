package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

const (
	appBindingRecordLimit    = 1 << 20
	appBindingChallengeLimit = 128 << 10
	appBindingResultLimit    = 64 << 10
)

func (c *nativeController) dispatchAppBinding(ctx context.Context, action Action) error {
	if c.storageFault || c.profileRecoveryRequired || !c.connected || c.vault == nil || c.owner == nil || c.device == nil || !c.localOwnerMatchesHub() {
		return ErrInvalidAction
	}
	if action.Kind == ActionRecoverAppBinding {
		record := c.appBindingActive()
		if record == nil {
			return ErrInvalidAction
		}
		return c.continueAppBinding(ctx, record)
	}
	if !action.AppBinding.Confirm || action.AppBinding.ReviewID == "" || action.AppBinding.ReviewID != c.appBindingReview() ||
		c.appBindingActive() != nil || c.appBindingHasOtherPending() {
		return ErrInvalidAction
	}
	if action.Kind == ActionUnbindApp {
		if c.appIsUnbound() || c.session == nil || !c.sessionInspected || c.sessionNeedsCheck ||
			!c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) || c.state.RootState != RootStateActive {
			return ErrInvalidAction
		}
	} else if action.Kind != ActionRebindApp || !c.appIsUnbound() {
		return ErrInvalidAction
	}
	// Project the entire lifecycle before even the first prepare. No capacity
	// failure may strand an already unbound user by silently deleting history.
	if err := c.checkAppBindingCapacity(); err != nil {
		return c.fail(PhaseUnavailable, "APP_BINDING_STORAGE_FULL", err)
	}
	if err := c.discoverAppBinding(ctx); err != nil {
		return c.fail(PhaseUnavailable, "APP_BINDING_UNAVAILABLE", err)
	}
	status, err := c.vault.AppDeviceStatus()
	if err != nil {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
	}
	record := &appBindingRecord{Format: appBindingRecordFormat, Scope: cardScope(c.connection), Generation: status.Generation}
	var prepare any
	if action.Kind == ActionUnbindApp {
		request, err := wire.NewAppUnbindPrepare(*c.session, c.owner.Public(), c.cfg.Now().UTC())
		if err != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_REVIEW_REQUIRED", err)
		}
		record.Unbind, prepare = &request, request
		record.DeviceKeyID = c.device.Public().ID
	} else {
		if err := c.prepareAppBindingCandidate(); err != nil {
			return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
		}
		challenge, _, err := c.openAppBindingRecord(c.appBinding.unbind)
		if err != nil {
			return c.failStorage("APP_BINDING_RECEIPT_INVALID", err)
		}
		suffix, err := wire.NewRequestID()
		if err != nil {
			return err
		}
		request, err := wire.NewAppRebindPrepare(c.hub, c.connection.Origin, c.connection.AccountID, c.connection.OwnerID,
			c.state.DeviceID, challenge.Binding.Digest(), wire.AccountDeviceIDPrefix+suffix, c.owner.Public(), c.cfg.Now().UTC())
		if err != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_REVIEW_REQUIRED", err)
		}
		record.Rebind, prepare = &request, request
		record.DeviceKeyID, record.Generation = c.appBinding.candidate.KeyID, c.appBinding.candidate.Generation
	}
	key, err := c.appBindingKey(record).E2EE()
	if err != nil {
		return err
	}
	record.PreparePacket, err = wire.SealClientRequest(key, c.hub, prepare)
	if err != nil || len(record.PreparePacket) > wire.MaxAppBindingOriginalBytes {
		return c.fail(PhaseUnavailable, "APP_BINDING_REQUEST_INVALID", err)
	}
	if err := c.checkAppBindingRecordFuture(record, false); err != nil {
		return c.fail(PhaseUnavailable, "APP_BINDING_STORAGE_FULL", err)
	}
	if err := c.persistAppBindingRecord(record); err != nil {
		return err
	}
	if record.Unbind != nil {
		c.appBinding.unbind, c.appBinding.unbindRejected = record, false
	} else {
		c.appBinding.rebind, c.appBinding.rebindRejected = record, false
	}
	c.publish()
	return c.continueAppBinding(ctx, record)
}

func (c *nativeController) discoverAppBinding(ctx context.Context) error {
	client := c.httpClient()
	if client == nil {
		return ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, wire.AppBindingCapabilitiesPath)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return ErrInvalidAction
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	defer clear(raw)
	var capability wire.AppBindingCapabilities
	if err != nil || len(raw) > maxMetadataBytes || decodeStateJSON(bytes.TrimSpace(raw), &capability) != nil ||
		!reflect.DeepEqual(capability, wire.AppBindingContractCapabilities()) {
		return ErrInvalidAction
	}
	return nil
}

func (c *nativeController) prepareAppBindingCandidate() error {
	raw, version, _, err := c.vault.LoadState(appUnbindNamespace)
	defer clear(raw)
	if err != nil || !c.appIsUnbound() || version != c.appBinding.unbindVersion {
		return appvault.ErrStateConflict
	}
	candidate, err := c.vault.PrepareAppDevice(c.state.DeviceKeyID, appvault.NewStateGuard(appUnbindNamespace, version, raw))
	if err != nil {
		return err
	}
	if c.appBinding.candidateKey != nil {
		if candidate != c.appBinding.candidate {
			return appvault.ErrScopeMismatch
		}
		return nil
	}
	c.appBinding.candidate = candidate
	c.appBinding.candidateKey, err = c.vault.OpenPendingAppDevice(candidate)
	return err
}

func (c *nativeController) continueAppBinding(ctx context.Context, record *appBindingRecord) error {
	challenge, result, err := c.openAppBindingRecord(record)
	if err != nil {
		return c.failStorage("APP_BINDING_RECEIPT_INVALID", err)
	}
	if len(record.ChallengePacket) == 0 {
		operation := wire.OperationAppUnbindPrepare
		if record.Rebind != nil {
			operation = wire.OperationAppRebindPrepare
		}
		response, _, err := postAccountPacket(ctx, c.httpClient(), c.connection.Origin, c.connection.Origin, operation, record.PreparePacket)
		if err != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_RESPONSE_UNKNOWN", err)
		}
		defer clear(response)
		key, err := c.appBindingKey(record).E2EE()
		if err != nil || len(response) > appBindingChallengeLimit || wire.OpenClientResponse(key, c.hub, record.PreparePacket, response, &challenge) != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_RESPONSE_INVALID", err)
		}
		var prepare any = record.Unbind
		if record.Rebind != nil {
			prepare = record.Rebind
		}
		if wire.ValidateAppBindingPreparedResponse(prepare, record.PreparePacket, challenge, c.hub, time.Time{}) != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_RESPONSE_INVALID", wire.ErrInvalid)
		}
		record.ChallengePacket = append([]byte(nil), response...)
		if err := c.persistAppBindingRecord(record); err != nil {
			return err
		}
	}
	if len(record.CompletePacket) == 0 {
		owner, err := c.owner.E2EE()
		if err != nil {
			return err
		}
		proof, err := ownerbootstrap.CreateProof(owner, challenge.Proof, c.cfg.Now().UTC())
		if err != nil {
			c.publish()
			return c.fail(PhaseConnected, "APP_BINDING_REVIEW_REQUIRED", err)
		}
		defer clear(proof)
		complete, err := wire.NewAppBindingComplete(record.PreparePacket, challenge, proof, c.cfg.Now().UTC())
		if err != nil {
			return c.fail(PhaseConnected, "APP_BINDING_REVIEW_REQUIRED", err)
		}
		key, err := c.appBindingKey(record).E2EE()
		if err != nil {
			return err
		}
		packet, err := wire.SealClientRequest(key, c.hub, complete)
		if err != nil || len(packet) > maxDurablePacketSize {
			return c.fail(PhaseUnavailable, "APP_BINDING_REQUEST_INVALID", err)
		}
		record.CompletePacket = packet
		if err := c.checkAppBindingRecordFuture(record, true); err != nil {
			record.CompletePacket = nil
			clear(packet)
			return c.fail(PhaseUnavailable, "APP_BINDING_STORAGE_FULL", err)
		}
		if err := c.persistAppBindingRecord(record); err != nil {
			return err
		}
		c.publish()
	}
	if result == nil {
		operation := wire.OperationAppUnbindComplete
		if record.Rebind != nil {
			operation = wire.OperationAppRebindComplete
		}
		response, _, err := postAccountPacket(ctx, c.httpClient(), c.connection.Origin, c.connection.Origin, operation, record.CompletePacket)
		if err != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_RESPONSE_UNKNOWN", err)
		}
		defer clear(response)
		key, err := c.appBindingKey(record).E2EE()
		var received wire.AppBindingResult
		if err != nil || len(response) > appBindingResultLimit || wire.OpenClientResponse(key, c.hub, record.CompletePacket, response, &received) != nil ||
			wire.ValidateAppBindingResultTarget(received, record.CompletePacket, challenge.Binding) != nil {
			return c.fail(PhaseUnavailable, "APP_BINDING_RESPONSE_INVALID", wire.ErrInvalid)
		}
		record.ResultPacket = append([]byte(nil), response...)
		// The authenticated completion receipt must be durable before clearing
		// live login or making the next atomic key/state generation transition.
		if err := c.persistAppBindingRecord(record); err != nil {
			return err
		}
		result = &received
	}
	if result.State == wire.AppBindingRejected {
		c.noteAppBindingRefusal(record)
		return c.fail(PhaseConnected, "APP_BINDING_REJECTED_"+result.ErrorCode, errors.New("authenticated App binding refusal"))
	}
	if record.Unbind != nil && result.State == wire.AppBindingUnbound {
		c.appBinding.unbound = true
		return c.applyAppUnbound()
	}
	if record.Rebind != nil && result.State == wire.AppBindingBoundZero {
		return c.promoteAppBinding(record, *result)
	}
	return c.failStorage("APP_BINDING_RECEIPT_INVALID", wire.ErrInvalid)
}

func (c *nativeController) noteAppBindingRefusal(record *appBindingRecord) {
	if record.Unbind != nil {
		c.appBinding.unbindRejected = true
		// A historical refusal is not a fresh account/management grant. Keep
		// the no-effect session receipt, but require an authenticated recheck.
		c.requireSessionRecheck()
		c.authorizationChecked, c.activationStatusRequestID = false, ""
		c.nodeChecked, c.nodeContextChecked = false, false
	} else {
		c.appBinding.rebindRejected = true
	}
}

func (c *nativeController) applyAppUnbound() error {
	c.clearSession()
	c.authorizationChecked, c.activationStatusRequestID = false, ""
	if !c.state.AppDeviceUnbound || c.state.AccountDeviceEnrolled || c.state.LoginChallenge != nil || c.state.AccountState != AccountStateLoginRequired {
		c.state.AppDeviceUnbound = true
		c.state.AccountDeviceEnrolled = false
		c.state.LoginChallenge = nil
		c.state.AccountState = AccountStateLoginRequired
		if err := c.persistState(); err != nil {
			return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
		}
	}
	c.publish()
	return nil
}

func (c *nativeController) freshAppBindingState(deviceID, keyID string) durableState {
	state := newDurableState(c.connection)
	state.Transport = cloneLocalTransport(c.state.Transport)
	state.AccountDeviceEnrolled = true
	state.DeviceID, state.DeviceKeyID = deviceID, keyID
	state.AccountID, state.OwnerID = c.connection.AccountID, c.connection.OwnerID
	state.Username, state.OwnerKeyID = c.state.Username, c.state.OwnerKeyID
	state.OwnerKeyIDAtHub, state.OwnerFingerprint = c.state.OwnerKeyIDAtHub, c.state.OwnerFingerprint
	state.RootState, state.AccountState = c.state.RootState, AccountStateLoginRequired
	return state
}

func (c *nativeController) promoteAppBinding(record *appBindingRecord, result wire.AppBindingResult) error {
	raw, version, _, err := c.vault.LoadState(appRebindNamespace)
	defer clear(raw)
	if err != nil || version != c.appBinding.rebindVersion {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", appvault.ErrStateConflict)
	}
	state := c.freshAppBindingState(result.DeviceID, record.DeviceKeyID)
	state.ObservedDeviceEpoch = result.DeviceEpoch
	stateData, err := encodeDurableState(state)
	if err != nil {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
	}
	defer clear(stateData)
	versions, err := c.vault.StateVersions()
	if err != nil {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
	}
	updates := map[string][]byte{appStateNamespace: stateData, appSessionNamespace: nil}
	if _, ok := versions[appSessionNamespace]; !ok {
		versions[appSessionNamespace] = 0
	}
	presence, _, _, err := c.vault.LoadState(profilePresenceNamespace)
	defer clear(presence)
	if err != nil {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
	}
	if len(presence) > 0 {
		updates[profilePresenceNamespace] = presence
	}
	newVersions, err := c.vault.PromoteAppDevice(appvault.AppDevicePromotion{CurrentKeyID: c.state.DeviceKeyID,
		Candidate: c.appBinding.candidate, Completion: appvault.NewStateGuard(appRebindNamespace, version, raw),
		ExpectedVersions: versions, Updates: updates, SessionNamespace: appSessionNamespace})
	if err != nil {
		return c.failStorage("APP_BINDING_PROMOTION_FAILED", err)
	}
	c.clearRuntimeSecrets()
	c.state, c.stateVer, c.sessionVer = state, newVersions[appStateNamespace], newVersions[appSessionNamespace]
	c.inspectionRequestID, c.authorizationChecked, c.activationStatusRequestID = "", false, ""
	if err := c.loadIdentities(false); err != nil {
		return c.failStorage("APP_IDENTITY_UNAVAILABLE", err)
	}
	if err := c.loadAppBinding(); err != nil {
		return c.failStorage("APP_BINDING_RECEIPT_INVALID", err)
	}
	if err := c.loadNodeState(); err != nil {
		return c.failStorage("APP_NODE_STATE_INVALID", err)
	}
	if err := c.loadPairState(); err != nil {
		return c.failStorage("APP_PAIR_STORAGE_FAILED", err)
	}
	if err := c.ensureThreadGroupsLoaded(); err != nil {
		return err
	}
	if err := c.restoreCurrentProfile(); err != nil {
		return c.failStorage("APP_PROFILE_UPDATE_FAILED", err)
	}
	c.publish()
	return nil
}

func (c *nativeController) checkAppBindingCapacity() error {
	fresh := c.freshAppBindingState(c.state.DeviceID, c.state.DeviceKeyID)
	fresh.ObservedDeviceEpoch = 1
	raw, err := encodeDurableState(fresh)
	if err != nil {
		return err
	}
	defer clear(raw)
	// Both full records are reserved together before the first unlink POST.
	// A subsequent step still checks its own exact record + possible response.
	oldState, err := encodeDurableState(c.state)
	if err != nil {
		return err
	}
	defer clear(oldState)
	padding := 128
	if c.state.AppDeviceUnbound {
		// The terminal flag/account change is already committed. Reserving
		// that growth again could falsely strand a transition at the ceiling.
		padding = 0
	}
	if len(oldState)+padding > appBindingRecordLimit {
		return appvault.ErrInvalidVault
	}
	retiring := map[string][]byte{appUnbindNamespace: make([]byte, appBindingRecordLimit), appRebindNamespace: make([]byte, appBindingRecordLimit),
		appStateNamespace: make([]byte, len(oldState)+padding), profilePresenceNamespace: make([]byte, 128)}
	defer clear(retiring[appUnbindNamespace])
	defer clear(retiring[appRebindNamespace])
	defer clear(retiring[appStateNamespace])
	defer clear(retiring[profilePresenceNamespace])
	// A local Remove/Restore is allowed while unbound. Reserve its namespace
	// and both boolean encodings even if this profile has no marker yet.
	current := map[string][]byte{appStateNamespace: raw, appSessionNamespace: nil, profilePresenceNamespace: retiring[profilePresenceNamespace]}
	return c.vault.CheckAppDeviceTransition(retiring, current)
}

func (c *nativeController) checkAppBindingRecordFuture(record *appBindingRecord, complete bool) error {
	projected := *record
	if complete {
		projected.ResultPacket = make([]byte, appBindingResultLimit)
	} else {
		projected.ChallengePacket = make([]byte, appBindingChallengeLimit)
		projected.CompletePacket = make([]byte, maxDurablePacketSize)
		projected.ResultPacket = make([]byte, appBindingResultLimit)
	}
	raw, err := json.Marshal(projected)
	defer clear(raw)
	if err != nil || len(raw) > appBindingRecordLimit {
		return appvault.ErrInvalidVault
	}
	return c.checkAppBindingCapacity()
}
