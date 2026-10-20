package appcore

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) loadIdentities(createDevice bool) error {
	ownerKeyID, deviceKeyID := c.state.OwnerKeyID, c.state.DeviceKeyID
	entries, err := c.vault.List()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Purpose {
		case appvault.PurposeAppDevice:
			if c.state.DeviceKeyID != "" && c.state.DeviceKeyID != entry.KeyID {
				return errors.New("stored App device identity mismatch")
			}
			identity, getErr := c.vault.Get(entry.Purpose, entry.KeyID)
			if getErr != nil {
				return getErr
			}
			c.device = identity
			c.state.DeviceKeyID = entry.KeyID
		case appvault.PurposeOwnerSigner:
			if c.state.OwnerKeyID != "" && c.state.OwnerKeyID != entry.KeyID {
				return errors.New("stored Owner identity mismatch")
			}
			identity, getErr := c.vault.Get(entry.Purpose, entry.KeyID)
			if getErr != nil {
				return getErr
			}
			c.owner = identity
			c.state.OwnerKeyID = entry.KeyID
		}
	}
	if c.device == nil && (c.state.DeviceID != "" || c.state.DeviceKeyID != "") {
		return errors.New("recorded App identity is missing")
	}
	if c.device == nil && createDevice {
		identity, err := appkeys.Generate()
		if err != nil {
			return err
		}
		if err := c.vault.Put(appvault.PurposeAppDevice, identity); err != nil {
			identity.Close()
			return err
		}
		c.device = identity
		c.state.DeviceKeyID = identity.Public().ID
	}
	if c.state.OwnerKeyID != ownerKeyID || c.state.DeviceKeyID != deviceKeyID {
		return c.persistState()
	}
	return nil
}

func (c *nativeController) persistState() error {
	if c.vault == nil {
		c.storageFault = true
		return errors.New("App vault is closed")
	}
	data, err := encodeDurableState(c.state)
	if err != nil {
		c.storageFault = true
		return err
	}
	defer clear(data)
	version, err := c.vault.CompareAndSwapState(appStateNamespace, c.stateVer, data)
	if err != nil {
		c.storageFault = true
		return err
	}
	c.stateVer = version
	return nil
}

func (c *nativeController) persistSession(request, response []byte) error {
	if len(request) == 0 || len(request) > maxDurablePacketSize || len(response) == 0 || len(response) > maxDurablePacketSize {
		c.storageFault = true
		return errors.New("session receipt exceeds local vault limit")
	}
	payload, err := encodeDurableSession(durableSession{Format: appSessionFormat, Version: 1,
		Request: append([]byte(nil), request...), Response: append([]byte(nil), response...)})
	if err != nil {
		c.storageFault = true
		return err
	}
	defer clear(payload)
	version, err := c.vault.CompareAndSwapState(appSessionNamespace, c.sessionVer, payload)
	if err != nil {
		c.storageFault = true
		return err
	}
	c.sessionVer = version
	c.sessionStored = true
	return nil
}

func (c *nativeController) clearPersistedSession() error {
	if !c.sessionStored {
		return nil
	}
	version, err := c.vault.CompareAndSwapState(appSessionNamespace, c.sessionVer, nil)
	if err != nil {
		c.storageFault = true
		return err
	}
	c.sessionVer = version
	c.sessionStored = false
	return nil
}

func (c *nativeController) restoreSession() error {
	payload, version, found, err := c.vault.LoadState(appSessionNamespace)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	defer clear(payload)
	c.sessionVer = version
	c.sessionStored = len(payload) != 0
	if len(payload) == 0 {
		return nil
	}
	saved, err := decodeDurableSession(payload)
	if err != nil || c.device == nil {
		return errors.New("saved App session is invalid")
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	var receipt wire.SessionReceipt
	if err := wire.OpenClientResponse(device, c.hub, saved.Request, saved.Response, &receipt); err != nil {
		return errors.New("saved App session receipt did not verify")
	}
	if receipt.Origin != c.connection.Origin || receipt.HubID != c.connection.HubID || receipt.AccountID != c.connection.AccountID || receipt.OwnerID != c.connection.OwnerID ||
		receipt.DeviceID != c.state.DeviceID || receipt.DeviceKeyID != c.state.DeviceKeyID {
		clear(receipt.SessionToken)
		return errors.New("saved App session scope mismatch")
	}
	c.state.AccountDeviceEnrolled = true
	if !c.cfg.Now().UTC().Before(parseExpiry(receipt.ExpiresAt)) || receipt.AccountEpoch < c.state.ObservedAccountEpoch || receipt.DeviceEpoch < c.state.ObservedDeviceEpoch {
		clear(receipt.SessionToken)
		c.state.AccountState = AccountStateLoginRequired
		return nil
	}
	context := receipt.Context()
	clear(receipt.SessionToken)
	c.session = &context
	c.sessionNeedsCheck = true
	c.sessionInspected = false
	c.state.AccountState = AccountStateSessionCheck
	return nil
}

func (c *nativeController) loadCurrentPendingResponse() error {
	if c.state.Pending == nil || len(c.state.Pending.Response) == 0 {
		return nil
	}
	response, err := c.openPendingResponse(c.state.Pending.Operation, c.state.Pending.Request, c.state.Pending.Response)
	if err != nil {
		return err
	}
	return c.applyResponse(c.state.Pending.Operation, response, c.state.Pending.Request, c.state.Pending.Response)
}

func (c *nativeController) openPendingResponse(operation string, request, response []byte) (any, error) {
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	var value any
	switch operation {
	case wire.OperationClaimPrepare:
		value = &wire.ClaimChallenge{}
	case wire.OperationClaimComplete:
		value = &wire.ClaimReceipt{}
	case wire.OperationLoginPrepare:
		value = &wire.LoginChallenge{}
	case wire.OperationLoginComplete:
		value = &wire.SessionReceipt{}
	case wire.OperationSessionInspect:
		value = &wire.SessionInspection{}
	case wire.OperationSessionLogout:
		value = &wire.LogoutReceipt{}
	case wire.OperationActivationPrepare:
		var challenge wire.ActivationChallenge
		if err := wire.OpenClientResponse(device, c.hub, request, response, &challenge); err == nil {
			return &challenge, nil
		}
		value = &wire.ActivationResult{}
	case wire.OperationActivationComplete, wire.OperationActivationStatus:
		value = &wire.ActivationResult{}
	case wire.OperationAccountReconcile:
		value = &wire.AccountReconcileResult{}
	default:
		return nil, ErrInvalidAction
	}
	if err := wire.OpenClientResponse(device, c.hub, request, response, value); err != nil {
		return nil, errors.New("Hub account response rejected")
	}
	if err := c.validateAccountResponseScope(value); err != nil {
		return nil, err
	}
	return value, nil
}

func (c *nativeController) validateAccountResponseScope(value any) error {
	var origin, hub, account, owner, device, key string
	switch r := value.(type) {
	case *wire.ClaimChallenge:
		origin, hub, account, owner, device = r.Origin, r.HubID, r.AccountID, r.OwnerID, r.DeviceID
	case *wire.ClaimReceipt:
		origin, hub, account, owner, device, key = r.Origin, r.HubID, r.AccountID, r.OwnerID, r.DeviceID, r.DeviceKeyID
	case *wire.LoginChallenge:
		origin, hub, account, owner, device, key = r.Origin, r.HubID, r.AccountID, r.OwnerID, r.DeviceID, r.DeviceKeyID
	case *wire.SessionReceipt:
		origin, hub, account, owner, device, key = r.Origin, r.HubID, r.AccountID, r.OwnerID, r.DeviceID, r.DeviceKeyID
	case *wire.SessionInspection:
		origin, hub, account, owner, device = r.Origin, r.HubID, r.AccountID, r.OwnerID, r.ActorDeviceID
	case *wire.LogoutReceipt:
		origin, hub, account, owner, device = r.Origin, r.HubID, r.AccountID, r.OwnerID, r.DeviceID
	default:
		return nil
	}
	if origin != c.connection.Origin || hub != c.connection.HubID || account != c.connection.AccountID || owner != c.connection.OwnerID || device != c.state.DeviceID ||
		(key != "" && (c.device == nil || key != c.device.Public().ID)) {
		if r, ok := value.(*wire.SessionReceipt); ok {
			clear(r.SessionToken)
		}
		return errors.New("Hub account response scope mismatch")
	}
	return nil
}

func (c *nativeController) applyResponse(operation string, value any, request, response []byte) error {
	switch response := value.(type) {
	case *wire.ClaimChallenge:
		c.state.ClaimChallenge = response
		c.state.AccountID, c.state.OwnerID, c.state.DeviceID = response.AccountID, response.OwnerID, response.DeviceID
		c.state.AccountState = AccountStateClaimPending
		c.activation = nil
	case *wire.ClaimReceipt:
		c.state.AccountDeviceEnrolled = true
		c.state.ClaimChallenge = nil
		c.state.AccountID, c.state.OwnerID, c.state.DeviceID = response.AccountID, response.OwnerID, response.DeviceID
		c.state.OwnerKeyIDAtHub, c.state.OwnerFingerprint = response.OwnerKeyID, response.OwnerFingerprint
		c.state.RootState = RootStatePending
		c.state.AccountState = AccountStateClaimPending
	case *wire.LoginChallenge:
		c.state.AccountDeviceEnrolled = true
		c.state.LoginChallenge = response
		c.state.AccountID, c.state.OwnerID, c.state.DeviceID = response.AccountID, response.OwnerID, response.DeviceID
		c.state.Username = response.Username
		c.state.AccountState = AccountStateLoginRequired
		if !c.cfg.Now().UTC().Before(parseExpiry(response.ExpiresAt)) || response.AccountEpoch < c.state.ObservedAccountEpoch || response.DeviceEpoch < c.state.ObservedDeviceEpoch {
			c.state.LoginChallenge = nil
		} else {
			c.observeEpochs(response.AccountEpoch, response.DeviceEpoch)
		}
	case *wire.SessionReceipt:
		if c.state.Pending == nil || len(c.state.Pending.Response) == 0 {
			return errors.New("session receipt packet is not durable")
		}
		if err := c.persistSession(request, c.state.Pending.Response); err != nil {
			return err
		}
		c.state.AccountDeviceEnrolled = true
		// An accepted receipt can be older than this process. Never resurrect
		// an expired session when replaying an already committed response.
		if !c.cfg.Now().UTC().Before(parseExpiry(response.ExpiresAt)) || response.AccountEpoch < c.state.ObservedAccountEpoch || response.DeviceEpoch < c.state.ObservedDeviceEpoch {
			clear(response.SessionToken)
			c.clearSession()
			c.state.LoginChallenge = nil
			c.state.AccountState = AccountStateLoginRequired
			break
		}
		// The exact encrypted receipt is retained; the token remains in RAM.
		context := response.Context()
		clear(response.SessionToken)
		c.clearSession()
		c.session = &context
		c.observeEpochs(response.AccountEpoch, response.DeviceEpoch)
		c.sessionNeedsCheck = true
		c.sessionInspected = false
		c.state.LoginChallenge = nil
		c.state.AccountID, c.state.OwnerID, c.state.DeviceID = response.AccountID, response.OwnerID, response.DeviceID
		c.state.AccountState = AccountStateSessionCheck
	case *wire.SessionInspection:
		if c.session == nil || !c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) {
			c.clearSession()
			c.state.AccountState = AccountStateLoginRequired
			break
		}
		if c.inspectionRequestID == "" || response.RequestID != c.inspectionRequestID ||
			c.cfg.Now().UTC().Sub(parseExpiry(response.InspectedAt)) > 30*time.Second ||
			parseExpiry(response.InspectedAt).After(c.cfg.Now().UTC().Add(30*time.Second)) {
			// An exact retry may return an authentic historical response.
			// The saved receipt cannot make a restored session current.
			c.requireSessionRecheck()
			break
		}
		if c.session == nil || !c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) || response.AccountID != c.connection.AccountID || response.OwnerID != c.connection.OwnerID ||
			response.ActorDeviceID != c.state.DeviceID || response.ActorDeviceEpoch != c.session.DeviceEpoch {
			return errors.New("Hub account inspection scope mismatch")
		}
		c.state.Username = response.Username
		c.state.AccountID, c.state.OwnerID = response.AccountID, response.OwnerID
		c.state.RootState = RootState(response.RootState)
		c.state.OwnerKeyIDAtHub, c.state.OwnerFingerprint = response.OwnerKeyID, response.OwnerFingerprint
		c.state.AccountState = AccountStateSessionActive
		c.sessionNeedsCheck = false
		c.sessionInspected = true
	case *wire.LogoutReceipt:
		if err := c.clearPersistedSession(); err != nil {
			return err
		}
		c.clearSession()
		c.state.AccountState = AccountStateLoginRequired
		c.state.LoginChallenge = nil
	case *wire.ActivationChallenge:
		if err := c.applyActivationChallenge(response, request); err != nil {
			return err
		}
	case *wire.ActivationResult:
		if err := c.applyActivationResult(response); err != nil {
			return err
		}
	default:
		return errors.New("unsupported Hub account response")
	}
	if err := c.persistState(); err != nil {
		return err
	}
	c.publish()
	return nil
}

func (c *nativeController) clearSession() {
	c.pair.View.Current, c.pair.View.AdministrativePermission = false, false
	c.pair.View.StateReviewID = ""
	c.pairCurrent = nil
	c.nodeChecked, c.nodeContextChecked, c.nodeReadRequestID = false, false, ""
	if c.session != nil {
		clear(c.session.SessionToken)
		c.session = nil
	}
	c.sessionNeedsCheck = false
	c.sessionInspected = false
}

func (c *nativeController) clearRuntimeSecrets() {
	c.clearPairRuntime()
	c.clearNodeRuntime()
	if c.state.Pending != nil {
		clear(c.state.Pending.Request)
		clear(c.state.Pending.Response)
	}
	if c.state.Recovery != nil {
		clear(c.state.Recovery.Request)
		clear(c.state.Recovery.Response)
	}
	if c.state.Enrollment != nil {
		c.state.Enrollment.Material.Code = ""
		if c.state.Enrollment.Prepare != nil {
			c.state.Enrollment.Prepare.Material.Code = ""
		}
	}
	c.clearSession()
	if c.device != nil {
		c.device.Close()
		c.device = nil
	}
	if c.owner != nil {
		c.owner.Close()
		c.owner = nil
	}
	if c.activation != nil {
		c.activation.card.Code = ""
		c.activation = nil
	}
	c.sessionStored = false
}

func (c *nativeController) setPhase(phase Phase, errorCode string) {
	c.snapshotMu.Lock()
	c.snapshot.Phase, c.snapshot.ErrorCode = phase, errorCode
	c.snapshotMu.Unlock()
}

func (c *nativeController) fail(phase Phase, code string, err error) error {
	c.snapshotMu.Lock()
	c.snapshot.ErrorCode = code
	c.snapshot.Management = ManagementUnavailable
	c.snapshot.Canvas = CanvasSnapshot{State: CanvasNoAuthorization}
	c.snapshotMu.Unlock()
	_ = err // Preserve only the stable code; raw errors may contain local details.
	c.publish()
	c.snapshotMu.Lock()
	c.snapshot.Phase = phase
	c.snapshot.ErrorCode = code
	c.snapshotMu.Unlock()
	return errors.New(code)
}

func (c *nativeController) failStorage(code string, err error) error {
	c.storageFault = true
	c.clearSession()
	if c.state.Pending != nil {
		clear(c.state.Pending.Request)
		clear(c.state.Pending.Response)
		c.state.Pending = nil
	}
	c.state.ClaimChallenge = nil
	c.state.LoginChallenge = nil
	if c.activation != nil {
		c.activation.card.Code = ""
		c.activation = nil
	}
	if c.vault != nil {
		_ = c.vault.Close()
		c.vault = nil
	}
	return c.fail(PhaseError, code, err)
}

func (c *nativeController) publish() {
	if c.suppressPublish {
		return
	}
	view := Snapshot{Phase: PhaseNeedConnection, Hub: HubSnapshot{Health: HubHealthUnknown},
		Account:    AccountSnapshot{State: AccountStateUnknown, RootState: RootStateUnknown},
		Management: ManagementUnavailable, Canvas: CanvasSnapshot{State: CanvasNoAuthorization}}
	for _, profile := range c.profiles {
		view.Profiles = append(view.Profiles, profile.view)
	}
	view.Storage.UserRoot = c.cfg.UserRoot
	if c.vault != nil && c.cfg.VaultLocation != nil {
		if root, ok := c.cfg.VaultLocation(cardScope(c.connection)); ok {
			view.Storage.VaultRoot = root
			view.Storage.Legacy = root != filepath.Join(c.cfg.UserRoot, "app", "vaults")
		}
	}
	if c.connected {
		view.Hub = HubSnapshot{Verified: true, Origin: c.connection.Origin, HubID: c.connection.HubID,
			Fingerprint: c.connection.HubFingerprint, Health: HubHealthHealthy, Service: c.service}
		view.Phase = PhaseConnected
		view.Account.State = AccountStateLoginRequired
		view.Account.AccountID, view.Account.OwnerID = c.connection.AccountID, c.connection.OwnerID
		view.Account.RootState = c.state.RootState
		view.Account.DeviceID = c.state.DeviceID
		view.Account.DeviceEnrolled = c.state.AccountDeviceEnrolled
		view.Account.OwnerFingerprint = c.state.OwnerFingerprint
		if c.session != nil {
			view.Account.SessionExpiresAt = c.session.ExpiresAt
		}
		view.Account.LocalOwnerKeyPresent = c.localOwnerMatchesHub()
		if view.Account.LocalOwnerKeyPresent {
			view.Account.LocalOwnerKeyID = c.owner.Public().ID
			view.Account.OwnerPeerFingerprint, _ = ownerPeerKeyFingerprint(c.owner.Public())
		}
		if c.state.Username != "" {
			view.Account.Username = c.state.Username
		}
		if c.vault == nil || c.device == nil {
			view.Phase = PhaseLocked
		} else if c.state.Pending != nil && len(c.state.Pending.Response) == 0 {
			view.Phase = PhaseUnavailable
			if c.session != nil {
				view.Account.State = AccountStateSessionCheck
			}
		} else if c.state.ClaimChallenge != nil {
			view.Phase = PhaseClaimChallenge
			view.Account.State = AccountStateClaimPending
		} else if c.state.LoginChallenge != nil {
			view.Phase = PhaseLoginChallenge
			view.Account.State = AccountStateLoginRequired
		} else if c.state.AccountState == AccountStateClaimPending {
			view.Phase = PhaseAccountPending
			view.Account.State = AccountStateClaimPending
		} else if c.session != nil && c.sessionNeedsCheck {
			view.Phase = PhaseSessionCheck
			view.Account.State = AccountStateSessionCheck
		} else if c.session != nil && c.sessionInspected {
			view.Phase = PhaseAccountSession
			view.Account.State = AccountStateSessionActive
			if c.state.RootState == RootStatePending || c.state.RootState == RootStateUnknown {
				view.Account.State = AccountStateOwnerProof
			}
			if c.state.RootState == RootStateActive && view.Account.LocalOwnerKeyPresent {
				view.Phase = PhaseOwnerReady
				view.Account.State = AccountStateOwnerReady
			}
		}
	}
	view.AvailableActions = c.availableActions()
	c.populateSetup(&view)
	c.populateNode(&view)
	c.populatePair(&view)
	if !c.profileRecoveryRequired {
		view.AvailableActions = append(view.AvailableActions, c.nodeActions()...)
		view.AvailableActions = append(view.AvailableActions, c.pairActions()...)
	}
	if c.storageFault {
		view.Phase = PhaseError
		view.Account = AccountSnapshot{State: AccountStateUnknown, RootState: RootStateUnknown}
	}
	c.snapshotMu.Lock()
	if !c.closed {
		view.ErrorCode = c.snapshot.ErrorCode
		c.snapshot = view
	}
	c.snapshotMu.Unlock()
}

func (c *nativeController) availableActions() []ActionKind {
	var actions []ActionKind
	if !c.profileRecoveryRequired {
		actions = append(actions, ActionConnect)
	}
	if c.cfg.DiscoverVaults != nil {
		actions = append(actions, ActionDiscoverProfiles)
	}
	if len(c.profiles) != 0 {
		actions = append(actions, ActionResumeProfile)
	}
	if c.profileRecoveryRequired {
		return actions
	}
	if c.storageFault {
		return actions
	}
	if !c.connected {
		return actions
	}
	if c.vault == nil {
		actions = append(actions, ActionImportOwner)
		return actions
	}
	if c.device == nil {
		return actions
	}
	if c.owner == nil {
		if c.state.OwnerKeyIDAtHub == "" {
			actions = append(actions, ActionGenerateOwner)
		}
		actions = append(actions, ActionImportOwner)
	}
	if c.canExportOwnerPublic() {
		actions = append(actions, ActionExportOwnerPublic)
	}
	if c.state.Pending != nil && len(c.state.Pending.Response) == 0 {
		if c.state.Recovery == nil {
			actions = append(actions, ActionRetry)
		}
		if wire.AccountReconcileOperationAllowed(c.state.Pending.Operation) || c.state.Pending.Operation == wire.OperationActivationPrepare || c.state.Pending.Operation == wire.OperationActivationComplete {
			actions = append(actions, ActionRecover)
		}
	}
	if c.state.Recovery != nil && (c.state.Pending == nil || len(c.state.Pending.Response) != 0) {
		actions = append(actions, ActionRecover)
	}
	if e := c.state.Enrollment; e != nil && c.canBeginOperation() {
		if e.Target != nil {
			actions = append(actions, ActionActivationStatus)
		}
		if c.owner != nil && c.canActivateEnrollment() {
			actions = append(actions, ActionActivateApp)
		}
	}
	if c.device != nil && c.activation != nil && c.state.ClaimChallenge == nil && c.state.AccountState != AccountStateClaimPending &&
		c.canBeginOperation() {
		actions = append(actions, ActionClaimPrepare)
	}
	if c.state.ClaimChallenge != nil && c.owner != nil && c.canBeginOperation() {
		actions = append(actions, ActionClaimComplete)
	}
	if c.owner != nil && c.canBeginOperation() && (c.activation != nil || c.state.ClaimChallenge != nil) {
		actions = append(actions, ActionSetupAccount)
	}
	if c.device != nil && c.state.AccountDeviceEnrolled && c.state.AccountID != "" && c.state.OwnerID != "" && c.session == nil && c.state.LoginChallenge == nil &&
		c.canBeginOperation() {
		actions = append(actions, ActionLoginPrepare)
	}
	if c.device != nil && c.state.AccountDeviceEnrolled && c.state.DeviceID != "" && c.session == nil && c.canBeginOperation() {
		actions = append(actions, ActionLogin)
	}
	if c.state.LoginChallenge != nil && c.canBeginOperation() {
		actions = append(actions, ActionLoginComplete)
	}
	if c.session != nil && c.canBeginOperation() {
		actions = append(actions, ActionSessionInspect, ActionLogout, ActionRefresh)
	}
	return actions
}

func canBeginOperation(pending *pendingOperation) bool {
	return pending == nil || len(pending.Response) != 0
}

func (c *nativeController) localOwnerMatchesHub() bool {
	if c.owner == nil || c.state.OwnerKeyIDAtHub == "" || c.owner.Public().ID != c.state.OwnerKeyIDAtHub ||
		c.state.OwnerFingerprint == "" {
		return false
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(c.owner.Public())
	return err == nil && fingerprint == c.state.OwnerFingerprint
}

func cloneSnapshot(source Snapshot) Snapshot {
	copy := source
	copy.AvailableActions = append([]ActionKind(nil), source.AvailableActions...)
	copy.Profiles = append([]ProfileSnapshot(nil), source.Profiles...)
	copy.Authorization.AllowedOperations = append([]string(nil), source.Authorization.AllowedOperations...)
	copy.Canvas.Objects = append([]CanvasObject(nil), source.Canvas.Objects...)
	copy.Node = cloneNodeSnapshot(source.Node)
	return copy
}

func parseExpiry(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}
	}
	return parsed.UTC()
}
