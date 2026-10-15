package appcore

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) activateApp(ctx context.Context, action Action) error {
	e := c.state.Enrollment
	if e == nil || c.owner == nil || c.device == nil || !c.canBeginOperation() || !action.ConfirmLimitedAuthorization ||
		!c.canActivateEnrollment() {
		return ErrInvalidAction
	}
	if e.Material.Purpose == wire.PurposeInitialActivation && (!validPasswordInput(action.Password) || action.Username == "") {
		return c.fail(PhaseError, "ACTIVATION_CREDENTIALS_REQUIRED", ErrInvalidAction)
	}
	if e.Material.Purpose == wire.PurposeLegacyContinuation && (action.Username != "" || action.Password != "") {
		return c.fail(PhaseError, "LEGACY_CREDENTIAL_CHANGE_FORBIDDEN", ErrInvalidAction)
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	if e.Material.ExpectedOwnerPublic != nil && !reflect.DeepEqual(*e.Material.ExpectedOwnerPublic, owner.Public()) {
		return c.fail(PhaseError, "OWNER_IDENTITY_SCOPE_MISMATCH", ErrInvalidAction)
	}
	if e.Challenge == nil {
		now := c.cfg.Now().UTC()
		if c.state.DeviceID == "" {
			id, err := wire.NewRequestID()
			if err != nil {
				return err
			}
			c.state.DeviceID = wire.AccountDeviceIDPrefix + id
		}
		grant, err := owner.SignOwnerDeviceGrant(c.connection.OwnerID, c.state.DeviceID, device.Public(),
			c.connection.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(wire.MaxActivationProofLifetime))
		if err != nil {
			return c.fail(PhaseError, "APP_GRANT_CREATE_FAILED", err)
		}
		defer clear(grant)
		prepare, err := wire.NewActivationPrepare(e.Material, c.hub, device.Public(), owner.Public(), c.state.DeviceID, grant, now)
		if err != nil {
			return c.fail(PhaseError, "ACTIVATION_PREPARE_INVALID", err)
		}
		e.Prepare = &prepare
		if err := c.sendNew(ctx, wire.OperationActivationPrepare, prepare); err != nil {
			return err
		}
	}
	if e.Challenge == nil {
		return c.fail(PhaseUnavailable, "ACTIVATION_CHALLENGE_UNCONFIRMED", ErrInvalidAction)
	}
	complete, err := wire.NewActivationComplete(*e.Challenge, c.hub, device.Public(), owner, action.Username, action.Password, c.cfg.Now().UTC())
	if err != nil {
		return c.fail(PhaseError, "ACTIVATION_PROOF_EXPIRED_OR_INVALID", err)
	}
	if action.Username != "" {
		c.state.Username = action.Username
	}
	if err := c.sendNew(ctx, wire.OperationActivationComplete, complete); err != nil {
		return err
	}
	return c.refreshActivation(ctx)
}

func (c *nativeController) canActivateEnrollment() bool {
	e := c.state.Enrollment
	if e == nil {
		return false
	}
	if e.Result == nil {
		return true
	}
	return e.Result.RootState == wire.RootPendingState && (e.Result.State == wire.ActivationPrepared || e.Result.State == wire.ActivationRejected)
}

func (c *nativeController) login(ctx context.Context, action Action) error {
	if e := c.state.Enrollment; e != nil && e.Result != nil && e.Result.LeaseState == wire.ActivationLeaseRevoked {
		return c.fail(PhaseUnavailable, "APP_DEVICE_REVOKED", ErrInvalidAction)
	}
	if !validPasswordInput(action.Password) || !c.canBeginOperation() {
		return ErrInvalidAction
	}
	if c.session != nil {
		return ErrInvalidAction
	}
	if c.state.LoginChallenge != nil && !c.cfg.Now().UTC().Before(parseExpiry(c.state.LoginChallenge.ExpiresAt)) {
		c.state.LoginChallenge = nil
	}
	if c.state.LoginChallenge != nil && action.Username != c.state.LoginChallenge.Username {
		return c.fail(PhaseError, "LOGIN_USERNAME_INVALID", ErrInvalidAction)
	}
	if c.state.LoginChallenge == nil {
		if err := c.loginPrepare(ctx, action); err != nil {
			return err
		}
	}
	if err := c.loginComplete(ctx, action); err != nil {
		return err
	}
	if err := c.inspectSession(ctx); err != nil {
		return err
	}
	if c.state.Enrollment != nil && c.state.Enrollment.Target != nil {
		return c.refreshActivation(ctx)
	}
	return nil
}

func (c *nativeController) applyActivationChallenge(challenge *wire.ActivationChallenge, packet []byte) error {
	e := c.state.Enrollment
	if e == nil || e.Prepare == nil || c.device == nil || c.owner == nil ||
		wire.ValidateActivationPreparedResponse(*challenge, *e.Prepare, packet, c.hub, c.device.Public(), time.Time{}) != nil ||
		!reflect.DeepEqual(challenge.Binding.OwnerPublic, c.owner.Public()) || cardScope(c.connection) !=
		cardScope(HubConnectionCard{HubID: challenge.Binding.HubID, HubFingerprint: challenge.Binding.HubFingerprint,
			Origin: challenge.Binding.Origin, AccountID: challenge.Binding.AccountID, OwnerID: challenge.Binding.OwnerID}) {
		return errors.New("activation challenge scope mismatch")
	}
	e.Challenge = challenge
	c.state.DeviceID = challenge.Binding.DeviceID
	c.state.OwnerKeyIDAtHub = challenge.Binding.OwnerPublic.ID
	c.state.OwnerFingerprint, _ = e2ee.OwnerDevicePublicKeyFingerprint(challenge.Binding.OwnerPublic)
	c.state.RootState = RootStatePending
	return nil
}

func (c *nativeController) applyActivationResult(result *wire.ActivationResult) error {
	e := c.state.Enrollment
	if e == nil || result.Origin != c.connection.Origin || result.HubID != c.connection.HubID ||
		result.AccountID != c.connection.AccountID || result.OwnerID != c.connection.OwnerID ||
		result.ActivationID != e.Material.ActivationID || result.DeviceID != c.state.DeviceID {
		return errors.New("activation result scope mismatch")
	}
	if result.Operation == wire.OperationActivationComplete && result.State != wire.ActivationCompleted &&
		result.State != wire.ActivationRejected && result.State != wire.ActivationCancelled {
		return errors.New("activation result is not terminal")
	}
	if result.Operation == wire.OperationActivationPrepare && result.State != wire.ActivationRejected && result.State != wire.ActivationCancelled {
		return errors.New("prepare result is not a refusal")
	}
	if result.LeaseState == wire.ActivationLeaseActive && (e.Challenge == nil || result.LeaseExpiresAt != e.Challenge.Binding.LeaseExpiresAt || !reflect.DeepEqual(result.AllowedOperations, wire.ActivationAllowedOperations())) {
		return errors.New("activation lease differs from confirmed proof scope")
	}
	if result.Operation != wire.OperationActivationStatus && result.State == wire.ActivationCompleted && e.Result != nil && e.Result.Operation == wire.OperationActivationStatus {
		// A historical completion cannot overwrite a current-state
		// observation, including known revocation. A fresh status follows.
		c.observeEpochs(result.AccountEpoch, result.DeviceEpoch)
		c.authorizationChecked = false
		return nil
	}
	e.Result = result
	c.observeEpochs(result.AccountEpoch, result.DeviceEpoch)
	c.state.RootState = RootState(result.RootState)
	c.authorizationChecked = result.Operation == wire.OperationActivationStatus &&
		result.RequestID == c.activationStatusRequestID && c.freshObservation(result.ObservedAt)
	if result.State == wire.ActivationCompleted && c.session == nil {
		c.state.AccountState = AccountStateLoginRequired
	}
	return nil
}

func (c *nativeController) observeEpochs(account, device uint64) {
	if account > c.state.ObservedAccountEpoch {
		c.state.ObservedAccountEpoch = account
	}
	if device > c.state.ObservedDeviceEpoch {
		c.state.ObservedDeviceEpoch = device
	}
}

func (c *nativeController) freshObservation(at string) bool {
	delta := c.cfg.Now().UTC().Sub(parseExpiry(at))
	return delta >= -30*time.Second && delta <= 30*time.Second
}

func (c *nativeController) expireKnownSession() error {
	if c.session == nil || c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) {
		return nil
	}
	if err := c.clearPersistedSession(); err != nil {
		return err
	}
	c.clearSession()
	c.state.AccountState = AccountStateLoginRequired
	if err := c.persistState(); err != nil {
		return err
	}
	c.publish()
	return nil
}
