package appcore

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) generateOwner() error {
	if c.vault == nil || c.owner != nil || c.state.OwnerKeyIDAtHub != "" {
		return ErrInvalidAction
	}
	identity, err := appkeys.Generate()
	if err != nil {
		return c.fail(PhaseError, "OWNER_IDENTITY_CREATE_FAILED", err)
	}
	if err := c.vault.Put(appvault.PurposeOwnerSigner, identity); err != nil {
		identity.Close()
		return c.failStorage("OWNER_IDENTITY_STORE_FAILED", err)
	}
	c.owner = identity
	c.state.OwnerKeyID = identity.Public().ID
	if err := c.persistState(); err != nil {
		return c.failStorage("APP_STATE_UNAVAILABLE", err)
	}
	c.publish()
	return nil
}

func (c *nativeController) importOwner(ctx context.Context, action Action) error {
	if !c.connected || c.owner != nil || action.OwnerImport == nil {
		return ErrInvalidAction
	}
	input := action.OwnerImport
	identity, err := appkeys.ImportOwner(appkeys.ImportOwnerPEM{
		KEMPrivatePKCS8: input.KEMPrivatePKCS8, SigningPrivatePKCS8: input.SigningPrivatePKCS8,
		KEMPublicSPKI: input.KEMPublicSPKI, SigningPublicSPKI: input.SigningPublicSPKI,
	})
	if err != nil {
		if errors.Is(err, appkeys.ErrEncryptedPEMUnsupported) {
			return c.fail(PhaseError, "ENCRYPTED_OWNER_PEM_UNSUPPORTED", err)
		}
		return c.fail(PhaseError, "OWNER_IDENTITY_IMPORT_REJECTED", errors.New("existing Owner identity import rejected"))
	}
	if c.state.OwnerKeyIDAtHub != "" {
		fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(identity.Public())
		if err != nil || identity.Public().ID != c.state.OwnerKeyIDAtHub || fingerprint != c.state.OwnerFingerprint {
			identity.Close()
			return c.fail(PhaseError, "OWNER_IDENTITY_SCOPE_MISMATCH", errors.New("import must preserve the known Owner identity"))
		}
	}
	if c.vault == nil {
		if err := c.openLocalVaultForOwnerImport(ctx); err != nil {
			identity.Close()
			if c.storageFault {
				return c.failStorage("APP_STATE_UNAVAILABLE", err)
			}
			return c.fail(PhaseLocked, "APP_VAULT_UNAVAILABLE", errors.New("encrypted local Owner identity storage is unavailable"))
		}
	}
	if err := c.vault.Put(appvault.PurposeOwnerSigner, identity); err != nil {
		identity.Close()
		return c.failStorage("OWNER_IDENTITY_STORE_FAILED", errors.New("Owner identity could not be stored"))
	}
	c.owner = identity
	c.state.OwnerKeyID = identity.Public().ID
	if err := c.persistState(); err != nil {
		return c.failStorage("APP_STATE_UNAVAILABLE", err)
	}
	c.publish()
	return nil
}

func (c *nativeController) openLocalVaultForOwnerImport(ctx context.Context) error {
	if c.vault != nil || c.cfg.OpenVault == nil || !c.connected {
		return errors.New("local Owner vault cannot be opened")
	}
	scope := appvault.Scope{HubID: c.connection.HubID, HubFingerprint: c.connection.HubFingerprint,
		Origin: c.connection.Origin, AccountID: c.connection.AccountID, OwnerID: c.connection.OwnerID}
	vault, err := c.cfg.OpenVault(ctx, scope, true)
	if err != nil {
		return err
	}
	if vault.Scope() != scope {
		_ = vault.Close()
		return errors.New("local Owner vault scope mismatch")
	}
	c.vault = vault
	data, version, found, err := vault.LoadState(appStateNamespace)
	if err != nil {
		c.storageFault = true
		return err
	}
	if found {
		state, decodeErr := decodeDurableState(data)
		clear(data)
		if decodeErr != nil || !sameScopeCard(state.Connection, c.connection) {
			c.storageFault = true
			return errors.New("existing encrypted Owner state is invalid")
		}
		c.state, c.stateVer = state, version
	} else {
		entries, listErr := vault.List()
		if listErr != nil || len(entries) != 0 {
			c.storageFault = true
			return errors.New("local Owner vault state is incomplete")
		}
		c.state, c.stateVer = newDurableState(c.connection), version
	}
	if err := c.loadIdentities(false); err != nil {
		c.storageFault = true
		return err
	}
	return nil
}

func (c *nativeController) claimPrepare(ctx context.Context) error {
	if c.activation == nil || c.device == nil || c.state.ClaimChallenge != nil ||
		c.state.AccountState == AccountStateClaimPending || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	now := c.cfg.Now().UTC()
	if wire.ValidateClaimCard(c.activation.card, c.hub, now) != nil {
		return c.fail(PhaseError, "ACTIVATION_CODE_EXPIRED", ErrActivationExpired)
	}
	device, err := c.device.E2EE()
	if err != nil {
		return c.fail(PhaseError, "APP_DEVICE_UNAVAILABLE", err)
	}
	request, err := wire.NewClaimPrepare(c.activation.card, c.hub, device.Public(), now)
	if err != nil {
		return c.fail(PhaseError, "CLAIM_PREPARE_INVALID", errors.New("claim request could not be created"))
	}
	c.state.AccountID, c.state.OwnerID, c.state.DeviceID = c.connection.AccountID, c.connection.OwnerID, request.DeviceID
	c.state.DeviceKeyID = device.Public().ID
	c.state.AccountState = AccountStateClaimPending
	if err := c.sendNew(ctx, wire.OperationClaimPrepare, request); err != nil {
		return err
	}
	c.activation = nil
	return nil
}

func (c *nativeController) claimComplete(ctx context.Context, action Action) error {
	if c.state.ClaimChallenge == nil || c.device == nil || c.owner == nil || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	if !validPasswordInput(action.Password) {
		return c.fail(PhaseError, "PASSWORD_POLICY_LOCAL", errors.New("password does not meet the minimum local policy"))
	}
	device, err := c.device.E2EE()
	if err != nil {
		return c.fail(PhaseError, "APP_DEVICE_UNAVAILABLE", err)
	}
	request, err := wire.NewClaimCompleteFromChallenge(c.hub, *c.state.ClaimChallenge, device.Public(),
		action.Username, action.Password, c.owner.Public(), c.cfg.Now().UTC())
	if err != nil {
		return c.fail(PhaseError, "CLAIM_CREDENTIALS_INVALID", errors.New("claim credentials or challenge are invalid"))
	}
	c.state.Username = action.Username
	return c.sendNew(ctx, wire.OperationClaimComplete, request)
}

func (c *nativeController) loginPrepare(ctx context.Context, action Action) error {
	if c.device == nil || !c.state.AccountDeviceEnrolled || c.state.AccountID == "" || c.state.OwnerID == "" || c.state.DeviceID == "" ||
		c.session != nil || c.state.LoginChallenge != nil || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	device, err := c.device.E2EE()
	if err != nil {
		return c.fail(PhaseError, "APP_DEVICE_UNAVAILABLE", err)
	}
	request, err := wire.NewLoginPrepare(c.hub, c.connection.Origin, c.state.AccountID, c.state.OwnerID,
		c.state.DeviceID, action.Username, device.Public(), c.cfg.Now().UTC())
	if err != nil {
		return c.fail(PhaseError, "LOGIN_USERNAME_INVALID", errors.New("login identity is invalid"))
	}
	c.state.Username = action.Username
	c.state.AccountState = AccountStateLoginRequired
	return c.sendNew(ctx, wire.OperationLoginPrepare, request)
}

func (c *nativeController) loginComplete(ctx context.Context, action Action) error {
	if c.device == nil || c.state.LoginChallenge == nil || c.session != nil || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	if !validPasswordInput(action.Password) {
		return c.fail(PhaseError, "PASSWORD_POLICY_LOCAL", errors.New("password does not meet the minimum local policy"))
	}
	request, err := wire.NewLoginComplete(c.hub, *c.state.LoginChallenge, action.Password, c.cfg.Now().UTC())
	if err != nil {
		return c.fail(PhaseError, "LOGIN_CREDENTIALS_INVALID", errors.New("login credentials or challenge are invalid"))
	}
	return c.sendNew(ctx, wire.OperationLoginComplete, request)
}

func validPasswordInput(value string) bool {
	return utf8.ValidString(value) && len(value) <= 1024 && utf8.RuneCountInString(value) >= 10
}

func (c *nativeController) inspectSession(ctx context.Context) error {
	if c.session == nil || c.device == nil || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	request, err := wire.NewSessionInspectRequest(*c.session, c.cfg.Now().UTC())
	if err != nil {
		return c.fail(PhaseError, "SESSION_EXPIRED", errors.New("account session must be renewed"))
	}
	c.inspectionRequestID = request.RequestID
	c.requireSessionRecheck()
	return c.sendNew(ctx, wire.OperationSessionInspect, request)
}

func (c *nativeController) logout(ctx context.Context) error {
	if c.session == nil || c.device == nil || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	request, err := wire.NewLogoutRequest(*c.session, c.cfg.Now().UTC())
	if err != nil {
		return c.fail(PhaseError, "SESSION_EXPIRED", errors.New("account session must be renewed"))
	}
	return c.sendNew(ctx, wire.OperationSessionLogout, request)
}

func (c *nativeController) retry(ctx context.Context) error {
	if c.state.Pending == nil || len(c.state.Pending.Response) != 0 || c.state.Recovery != nil {
		return ErrInvalidAction
	}
	inspection := c.state.Pending.Operation == wire.OperationSessionInspect
	if inspection {
		c.inspectionRequestID = ""
		c.requireSessionRecheck()
	}
	if err := c.sendPending(ctx); err != nil {
		return err
	}
	if inspection && c.session != nil {
		return c.inspectSession(ctx)
	}
	return nil
}

func (c *nativeController) canBeginOperation() bool {
	return (c.state.Pending == nil || len(c.state.Pending.Response) != 0) && c.state.Recovery == nil && !c.hasPairPending() && !c.hasLocalDomainPending()
}

func (c *nativeController) sendNew(ctx context.Context, operation string, body any) error {
	device, err := c.device.E2EE()
	if err != nil {
		return c.fail(PhaseError, "APP_DEVICE_UNAVAILABLE", err)
	}
	packet, err := wire.SealClientRequest(device, c.hub, body)
	if err != nil || len(packet) > maxDurablePacketSize {
		clear(packet)
		return c.fail(PhaseError, "ACCOUNT_REQUEST_INVALID", errors.New("account request could not be sealed"))
	}
	c.state.Pending = &pendingOperation{Operation: operation, Request: packet, CreatedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if c.state.Enrollment != nil {
		c.authorizationChecked = false
	}
	if operation == wire.OperationActivationPrepare || operation == wire.OperationActivationComplete {
		if c.state.Enrollment == nil {
			return ErrInvalidAction
		}
		c.state.Enrollment.Target = c.state.Pending
		if operation == wire.OperationActivationPrepare {
			c.state.Enrollment.PreparePacket = append([]byte(nil), packet...)
		}
	}
	if err := c.persistState(); err != nil {
		return c.failStorage("APP_STATE_COMMIT_FAILED", errors.New("exact account request was not safely committed"))
	}
	c.publish()
	return c.sendPending(ctx)
}

func (c *nativeController) sendPending(ctx context.Context) error {
	if c.state.Pending == nil || len(c.state.Pending.Request) == 0 {
		return ErrInvalidAction
	}
	response, status, err := postAccountPacket(ctx, c.httpClient(), c.connection.Origin, c.connection.Origin,
		c.state.Pending.Operation, c.state.Pending.Request)
	if err != nil {
		_ = status // HTTP status is not authenticated and cannot settle a request.
		return c.fail(PhaseUnavailable, "ACCOUNT_RESPONSE_UNKNOWN", errors.New("account response is unknown; exact recovery is available"))
	}
	defer clear(response)
	value, err := c.openPendingResponse(c.state.Pending.Operation, c.state.Pending.Request, response)
	if err != nil {
		return c.fail(PhaseUnavailable, "ACCOUNT_RESPONSE_INVALID", errors.New("Hub account response could not be authenticated"))
	}
	c.state.Pending.Response = append([]byte(nil), response...)
	if c.state.Pending.Operation == wire.OperationActivationPrepare || c.state.Pending.Operation == wire.OperationActivationComplete {
		c.state.Enrollment.Target = c.state.Pending
	}
	if err := c.persistState(); err != nil {
		return c.failStorage("APP_STATE_COMMIT_FAILED", errors.New("accepted account response could not be committed"))
	}
	if err := c.applyResponse(c.state.Pending.Operation, value, c.state.Pending.Request, c.state.Pending.Response); err != nil {
		return c.failStorage("APP_STATE_COMMIT_FAILED", errors.New("accepted account response could not be applied"))
	}
	return nil
}
