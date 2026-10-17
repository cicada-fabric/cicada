package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var (
	ErrControllerBusy = errors.New("native App is processing another action")
	ErrClosed         = errors.New("native App controller is closed")
	ErrInvalidAction  = errors.New("native App action is not available")
)

type Config struct {
	HTTP              HTTPDoer
	OpenVault         VaultOpener
	DiscoverVaults    func(context.Context) ([]appvault.Scope, error)
	AllowLoopbackHTTP bool
	Now               func() time.Time
}

type nativeController struct {
	cfg Config

	actionMu sync.Mutex
	lifetime context.Context
	cancel   context.CancelFunc

	snapshotMu sync.RWMutex
	snapshot   Snapshot
	closed     bool

	hub                       wire.HubIdentity
	connection                HubConnectionCard
	service                   string
	connected                 bool
	activation                *ActivationCode
	vault                     *appvault.Vault
	state                     durableState
	stateVer                  uint64
	sessionVer                uint64
	storageFault              bool
	device                    *appkeys.Identity
	owner                     *appkeys.Identity
	profiles                  []localProfile
	session                   *wire.SessionContext
	sessionNeedsCheck         bool
	sessionStored             bool
	sessionInspected          bool
	inspectionRequestID       string
	authorizationChecked      bool
	activationStatusRequestID string
	suppressPublish           bool
	node                      nodeAuthorityState
	nodeVer                   uint64
	nodeRecovery              *nodeOperation
	nodeRecoveryVer           uint64
	nodeConfirmation          *nodeConfirmationRecord
	nodeConfirmationVer       uint64
	nodeAvailable             bool
	nodeDiscoveryTried        bool
	nodeChecked               bool
	nodeContextChecked        bool
	nodeReadRequestID         string
	nodeError                 string
}

func NewController(config Config) (Controller, error) {
	if config.HTTP == nil {
		config.HTTP = NewHTTPClient()
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &nativeController{cfg: config, lifetime: lifetime, cancel: cancel}
	c.snapshot = Snapshot{Phase: PhaseNeedConnection, Hub: HubSnapshot{Health: HubHealthUnknown},
		Account:    AccountSnapshot{State: AccountStateUnknown, RootState: RootStateUnknown},
		Management: ManagementUnavailable, Canvas: CanvasSnapshot{State: CanvasNoAuthorization}}
	c.publish()
	return c, nil
}

func (c *nativeController) Snapshot() Snapshot {
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()
	view := cloneSnapshot(c.snapshot)
	if view.Account.SessionExpiresAt != "" && !c.cfg.Now().UTC().Before(parseExpiry(view.Account.SessionExpiresAt)) {
		blocked := false
		for _, action := range view.AvailableActions {
			if action == ActionRetry || action == ActionRecover {
				blocked = true
			}
		}
		view.Account.State = AccountStateLoginRequired
		if !blocked {
			view.Phase = PhaseConnected
		}
		view.Authorization.Confirmed = false
		if view.Authorization.State == "ACTIVE" {
			view.Authorization.State = "LOGIN_REQUIRED"
		}
		var actions []ActionKind
		for _, action := range view.AvailableActions {
			if action != ActionSessionInspect && action != ActionLogout && action != ActionRefresh {
				actions = append(actions, action)
			}
		}
		if !blocked && view.Account.DeviceID != "" && view.Account.DeviceEnrolled {
			actions = append(actions, ActionLogin)
		}
		view.AvailableActions = actions
	}
	if view.Authorization.State != "REVOKED" && view.Authorization.ExpiresAt != "" && !c.cfg.Now().UTC().Before(parseExpiry(view.Authorization.ExpiresAt)) {
		view.Authorization.State, view.Authorization.Confirmed = "EXPIRED", false
		if view.Setup.Purpose != "" && view.Phase == PhaseOwnerReady {
			view.Phase = PhaseAccountSession
		}
	}
	expireNodeView(&view, c.cfg.Now().UTC())
	return view
}

func (c *nativeController) Dispatch(ctx context.Context, action Action) (dispatchErr error) {
	if ctx == nil {
		return ErrInvalidAction
	}
	c.snapshotMu.RLock()
	closed := c.closed
	c.snapshotMu.RUnlock()
	if closed {
		return ErrClosed
	}
	if !c.actionMu.TryLock() {
		return ErrControllerBusy
	}
	defer c.actionMu.Unlock()

	c.snapshotMu.RLock()
	closed = c.closed
	c.snapshotMu.RUnlock()
	if closed {
		return ErrClosed
	}
	if action.AutoNodeStatus != nil && action.Kind != ActionRefreshNode {
		return ErrInvalidAction
	}
	if action.AutoNodeStatus != nil {
		// A skipped background read must not perform manual-session
		// housekeeping, discover context or change any vault version.
		operationCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(c.lifetime, cancel)
		defer func() { stop(); cancel() }()
		return c.refreshNodeAutomatically(operationCtx, *action.AutoNodeStatus)
	}
	if c.storageFault && action.Kind != ActionConnect && action.Kind != ActionResumeProfile && action.Kind != ActionDiscoverProfiles {
		return c.fail(PhaseError, "APP_STORAGE_RECOVERY_REQUIRED", errors.New("reconnect to recover encrypted App state"))
	}
	c.snapshotMu.Lock()
	c.snapshot.ErrorCode = ""
	c.snapshotMu.Unlock()
	operationCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifetime, cancel)
	defer func() { stop(); cancel() }()
	defer func() {
		if dispatchErr == nil && !nodeActionKind(action.Kind) {
			c.initializeNode(operationCtx)
		}
	}()
	if action.Kind == ActionRefresh {
		c.nodeDiscoveryTried = false
	}
	if action.Kind != ActionConnect && action.Kind != ActionDiscoverProfiles && action.Kind != ActionResumeProfile {
		if err := c.expireKnownSession(); err != nil {
			return c.failStorage("APP_STATE_COMMIT_FAILED", err)
		}
	}

	switch action.Kind {
	case ActionPreviewNode:
		return c.previewNode(operationCtx, action.NodeCode, false)
	case ActionReauthorizeNodeStatus:
		return c.previewNode(operationCtx, "", true)
	case ActionApproveNode:
		return c.approveNode(operationCtx, action)
	case ActionRefreshNode:
		if !c.nodeContextChecked && c.nodeAccountReady() {
			if !c.nodeAvailable {
				if err := c.discoverNodeAvailability(operationCtx); err != nil {
					return c.failNode("APP_NODE_UNAVAILABLE", err)
				}
			}
			if err := c.refreshNodeContext(operationCtx); err != nil {
				return err
			}
		}
		return c.refreshNode(operationCtx)
	case ActionRecoverNode:
		return c.recoverNode(operationCtx)
	case ActionCancelNodeAccess:
		return c.cancelNodeAccess(operationCtx, action.NodeReviewID)
	case ActionDiscoverProfiles:
		return c.discoverProfiles(operationCtx)
	case ActionResumeProfile:
		return c.resumeProfile(operationCtx, action.ProfileID)
	case ActionActivateApp:
		return c.activateApp(operationCtx, action)
	case ActionLogin:
		return c.login(operationCtx, action)
	case ActionRecover:
		return c.recoverOperation(operationCtx)
	case ActionActivationStatus:
		return c.refreshActivation(operationCtx)
	case ActionRefresh:
		if err := c.inspectSession(operationCtx); err != nil {
			return err
		}
		if c.state.Enrollment != nil {
			return c.refreshActivation(operationCtx)
		}
		return nil
	case ActionSetupAccount:
		if c.state.ClaimChallenge == nil {
			if err := c.claimPrepare(operationCtx); err != nil {
				return err
			}
		}
		return c.claimComplete(operationCtx, action)
	case ActionConnect:
		return c.connect(operationCtx, action)
	case ActionGenerateOwner:
		return c.generateOwner()
	case ActionImportOwner:
		return c.importOwner(operationCtx, action)
	case ActionClaimPrepare:
		return c.claimPrepare(operationCtx)
	case ActionClaimComplete:
		return c.claimComplete(operationCtx, action)
	case ActionLoginPrepare:
		return c.loginPrepare(operationCtx, action)
	case ActionLoginComplete:
		return c.loginComplete(operationCtx, action)
	case ActionSessionInspect:
		return c.inspectSession(operationCtx)
	case ActionLogout:
		return c.logout(operationCtx)
	case ActionRetry:
		return c.retry(operationCtx)
	case ActionSelectCanvas, ActionSetCanvasViewport:
		return ErrInvalidAction
	default:
		return ErrInvalidAction
	}
}

func (c *nativeController) Close() error {
	c.snapshotMu.Lock()
	if c.closed {
		c.snapshotMu.Unlock()
		return nil
	}
	c.closed = true
	c.snapshotMu.Unlock()
	c.cancel()
	c.actionMu.Lock()
	defer c.actionMu.Unlock()
	c.clearRuntimeSecrets()
	if c.vault != nil {
		err := c.vault.Close()
		c.vault = nil
		return err
	}
	return nil
}

func (c *nativeController) connect(ctx context.Context, action Action) error {
	if err := c.resetConnection(); err != nil {
		return c.fail(PhaseError, "APP_VAULT_CLOSE_FAILED", err)
	}
	if (action.ConnectionCard == "") == (action.ActivationCode == "") {
		return c.fail(PhaseError, "INVALID_CONNECTION_MATERIAL", ErrInvalidCard)
	}
	now := c.cfg.Now().UTC()
	var card HubConnectionCard
	var activation *ActivationCode
	var material *wire.ActivationMaterial
	if strings.HasPrefix(action.ActivationCode, wire.ActivationCodePrefix) {
		parsed, err := wire.DecodeActivationCode(action.ActivationCode)
		if err != nil || wire.ValidateActivationMaterial(parsed, now) != nil {
			return c.fail(PhaseError, "INVALID_ACTIVATION_CODE", ErrActivationExpired)
		}
		material = &parsed
		card = HubConnectionCard{Format: connectionCardFormat, Version: 1, Purpose: connectionCardPurpose,
			Origin: parsed.Origin, AllowLoopbackHTTP: parsed.AllowLoopbackHTTP, HubID: parsed.HubID,
			HubFingerprint: parsed.HubFingerprint, AccountID: parsed.AccountID, OwnerID: parsed.OwnerID,
			IssuedAt: parsed.IssuedAt, ExpiresAt: parsed.ExpiresAt}
	} else if action.ActivationCode != "" {
		parsed, err := ParseActivationCode(action.ActivationCode)
		if err != nil {
			return c.fail(PhaseError, "INVALID_ACTIVATION_CODE", ErrActivationExpired)
		}
		activation = &parsed
		claim := parsed.card
		card = HubConnectionCard{Format: connectionCardFormat, Version: 1, Purpose: connectionCardPurpose,
			Origin: claim.Origin, AllowLoopbackHTTP: claim.AllowLoopbackHTTP, HubID: claim.HubID,
			HubFingerprint: claim.HubFingerprint, AccountID: claim.AccountID, OwnerID: claim.OwnerID,
			IssuedAt: claim.IssuedAt, ExpiresAt: claim.ExpiresAt}
	} else {
		parsed, err := ParseHubConnectionCard(action.ConnectionCard, now)
		if err != nil {
			return c.fail(PhaseError, "INVALID_CONNECTION_CARD", ErrInvalidCard)
		}
		card = parsed
	}
	if validateConnectionCard(card, now) != nil {
		return c.fail(PhaseError, "EXPIRED_CONNECTION_MATERIAL", ErrInvalidCard)
	}
	if card.AllowLoopbackHTTP && !c.cfg.AllowLoopbackHTTP {
		if len(card.Origin) >= len("http://") && card.Origin[:len("http://")] == "http://" {
			return c.fail(PhaseError, "LOOPBACK_HTTP_DISABLED", ErrInvalidCard)
		}
	}
	c.setPhase(PhaseVerifyingHub, "")

	hub, service, err := c.verifyHub(ctx, card)
	if err != nil {
		return c.fail(PhaseUnavailable, err.Error(), err)
	}
	if activation != nil && wire.ValidateClaimCard(activation.card, hub, now) != nil {
		return c.fail(PhaseError, "INVALID_ACTIVATION_SCOPE", ErrActivationExpired)
	}
	if material != nil && wire.ValidateActivationHub(*material, hub, now) != nil {
		return c.fail(PhaseError, "INVALID_ACTIVATION_SCOPE", ErrActivationExpired)
	}
	if c.vault != nil {
		c.clearRuntimeSecrets()
		_ = c.vault.Close()
		c.vault = nil
	}
	c.setConnectedHub(hub, card, service, activation)
	c.state, c.stateVer, c.sessionVer = newDurableState(card), 0, 0

	scope := appvault.Scope{HubID: card.HubID, HubFingerprint: card.HubFingerprint, Origin: card.Origin,
		AccountID: card.AccountID, OwnerID: card.OwnerID}
	if c.cfg.OpenVault == nil {
		return c.fail(PhaseLocked, "APP_VAULT_UNAVAILABLE", errors.New("App vault is unavailable"))
	}
	create := activation != nil || material != nil
	vault, err := c.cfg.OpenVault(ctx, scope, create)
	if err != nil {
		return c.fail(PhaseLocked, "APP_DEVICE_NOT_ENROLLED", errors.New("this App has no enrolled device for the selected account"))
	}
	if vault.Scope() != scope {
		_ = vault.Close()
		return c.fail(PhaseError, "APP_VAULT_SCOPE_MISMATCH", errors.New("App vault scope mismatch"))
	}
	c.vault = vault
	c.hub, c.connection, c.connected = hub, card, true
	c.activation = activation
	c.snapshotMu.Lock()
	c.snapshot.Hub = HubSnapshot{Verified: true, Origin: card.Origin, HubID: card.HubID,
		Fingerprint: card.HubFingerprint, Health: HubHealthHealthy, Service: service}
	c.snapshotMu.Unlock()

	data, version, found, err := c.vault.LoadState(appStateNamespace)
	if err != nil {
		return c.failStorage("APP_STATE_UNAVAILABLE", errors.New("encrypted App state is unavailable"))
	}
	if found {
		state, decodeErr := decodeDurableState(data)
		clear(data)
		if decodeErr != nil || !sameScopeCard(state.Connection, card) {
			return c.failStorage("APP_STATE_SCOPE_MISMATCH", errors.New("encrypted App state scope mismatch"))
		}
		c.state, c.stateVer = state, version
		if c.state.Connection != card {
			c.state.Connection = card
			if err := c.persistState(); err != nil {
				return c.failStorage("APP_STATE_UNAVAILABLE", err)
			}
		}
	} else {
		entries, listErr := c.vault.List()
		if listErr != nil || len(entries) != 0 {
			return c.failStorage("APP_DEVICE_STATE_MISSING", errors.New("registered App device state is unavailable"))
		}
		if !create {
			return c.fail(PhaseLocked, "APP_DEVICE_NOT_ENROLLED", errors.New("this App has no enrolled device for the selected account"))
		}
		c.state, c.stateVer = newDurableState(card), version
		if err := c.persistState(); err != nil {
			return c.failStorage("APP_STATE_UNAVAILABLE", err)
		}
	}
	if material != nil && c.state.Enrollment == nil {
		c.state.Enrollment = &enrollmentState{Material: *material}
		if material.ExpectedOwnerPublic != nil {
			c.state.OwnerKeyIDAtHub = material.ExpectedOwnerPublic.ID
			c.state.OwnerFingerprint, _ = e2ee.OwnerDevicePublicKeyFingerprint(*material.ExpectedOwnerPublic)
			c.state.RootState = RootStatePending
		}
		if err := c.persistState(); err != nil {
			return c.failStorage("APP_STATE_UNAVAILABLE", err)
		}
	}
	if err := c.loadIdentities(create); err != nil {
		return c.failStorage("APP_IDENTITY_UNAVAILABLE", errors.New("App identity is unavailable"))
	}
	if err := c.loadNodeState(); err != nil {
		return c.failStorage("APP_NODE_STATE_INVALID", err)
	}
	if material != nil {
		if err := c.installActivationMaterial(*material); err != nil {
			return c.fail(PhaseError, "ACTIVATION_SCOPE_CHANGED", err)
		}
		if material.ExpectedOwnerPublic != nil {
			c.state.OwnerKeyIDAtHub = material.ExpectedOwnerPublic.ID
			c.state.OwnerFingerprint, _ = e2ee.OwnerDevicePublicKeyFingerprint(*material.ExpectedOwnerPublic)
			c.state.RootState = RootStatePending
		}
		if err := c.persistState(); err != nil {
			return c.failStorage("APP_STATE_UNAVAILABLE", err)
		}
	}
	if activation != nil && c.state.DeviceID == "" && c.device == nil {
		return c.fail(PhaseLocked, "APP_DEVICE_UNAVAILABLE", errors.New("App device identity is unavailable"))
	}
	if err := c.restoreSession(); err != nil {
		return c.failStorage("APP_SESSION_STATE_INVALID", err)
	}
	if err := c.loadCurrentPendingResponse(); err != nil {
		return c.failStorage("APP_PENDING_RESPONSE_INVALID", err)
	}
	c.requireSessionRecheck()
	c.publish()
	return nil
}

func (c *nativeController) resetConnection() error {
	c.clearRuntimeSecrets()
	if c.vault != nil {
		err := c.vault.Close()
		c.vault = nil
		if err != nil {
			c.connected = false
			c.state = durableState{}
			return err
		}
	}
	c.hub = wire.HubIdentity{}
	c.connection = HubConnectionCard{}
	c.service = ""
	c.connected = false
	c.activation = nil
	c.state = durableState{}
	c.stateVer, c.sessionVer = 0, 0
	c.inspectionRequestID = ""
	c.authorizationChecked, c.activationStatusRequestID = false, ""
	c.storageFault = false
	c.snapshotMu.Lock()
	c.snapshot = Snapshot{Phase: PhaseNeedConnection, Hub: HubSnapshot{Health: HubHealthUnknown},
		Account:    AccountSnapshot{State: AccountStateUnknown, RootState: RootStateUnknown},
		Management: ManagementUnavailable, Canvas: CanvasSnapshot{State: CanvasNoAuthorization}}
	c.snapshotMu.Unlock()
	return nil
}

func (c *nativeController) setConnectedHub(hub wire.HubIdentity, card HubConnectionCard, service string, activation *ActivationCode) {
	c.hub, c.connection, c.connected, c.activation = hub, card, true, activation
	c.service = service
	c.snapshotMu.Lock()
	c.snapshot.Hub = HubSnapshot{Verified: true, Origin: card.Origin, HubID: card.HubID,
		Fingerprint: card.HubFingerprint, Health: HubHealthHealthy, Service: service}
	c.snapshotMu.Unlock()
}

func decodeHubIdentity(data []byte) (wire.HubIdentity, error) {
	defer clear(data)
	var hub wire.HubIdentity
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&hub); err != nil || decoder.Decode(new(any)) != io.EOF {
		return wire.HubIdentity{}, errors.New("Hub identity is invalid")
	}
	if _, err := wire.HubFingerprint(hub); err != nil {
		return wire.HubIdentity{}, errors.New("Hub identity is invalid")
	}
	return hub, nil
}

func sameScopeCard(a, b HubConnectionCard) bool {
	return a.HubID == b.HubID && a.HubFingerprint == b.HubFingerprint && a.Origin == b.Origin &&
		a.AccountID == b.AccountID && a.OwnerID == b.OwnerID
}

func (c *nativeController) verifyHub(ctx context.Context, card HubConnectionCard) (wire.HubIdentity, string, error) {
	healthData, healthStatus, err := getHubMetadata(ctx, c.cfg.HTTP, card.Origin, "/healthz")
	if err != nil || healthStatus != http.StatusOK {
		return wire.HubIdentity{}, "", errors.New("HUB_UNAVAILABLE")
	}
	service, err := verifyHealth(healthData)
	if err != nil {
		return wire.HubIdentity{}, "", errors.New("HUB_HEALTH_INVALID")
	}
	identityData, identityStatus, err := getHubMetadata(ctx, c.cfg.HTTP, card.Origin, "/v2/client/identity")
	if err != nil || identityStatus != http.StatusOK {
		return wire.HubIdentity{}, "", errors.New("HUB_IDENTITY_UNAVAILABLE")
	}
	hub, err := decodeHubIdentity(identityData)
	if err != nil {
		return wire.HubIdentity{}, "", errors.New("HUB_IDENTITY_INVALID")
	}
	fingerprint, err := wire.HubFingerprint(hub)
	if err != nil || hub.HubID != card.HubID || fingerprint != card.HubFingerprint {
		return wire.HubIdentity{}, "", errors.New("HUB_PIN_MISMATCH")
	}
	return hub, service, nil
}
