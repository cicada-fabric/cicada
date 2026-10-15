package appcore

import (
	"reflect"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) populateSetup(view *Snapshot) {
	view.Authorization.State = "UNAVAILABLE"
	view.Setup.OwnerKeyStored = c.owner != nil
	e := c.state.Enrollment
	if e == nil {
		return
	}
	view.Setup.Purpose = e.Material.Purpose
	_, view.Setup.ReplacementAllowed = c.replacementDisposition()
	if e.Challenge != nil {
		view.Setup.AuthorizationDeadline = e.Challenge.Binding.LeaseExpiresAt
	}
	if view.Phase == PhaseOwnerReady {
		view.Phase = PhaseAccountSession
	}
	view.Setup.NeedsCredentials = e.Material.Purpose == wire.PurposeInitialActivation
	view.Setup.ActivationPending = c.canActivateEnrollment()
	if e.Material.ExpectedOwnerPublic != nil {
		view.Setup.ExpectedOwnerKeyID = e.Material.ExpectedOwnerPublic.ID
	}
	if view.Setup.ActivationPending && c.owner != nil && c.canBeginOperation() && c.connected {
		view.Phase = PhaseActivationPending
	}
	result := e.Result
	if result == nil {
		view.Authorization.State = "UNCONFIRMED"
		return
	}
	view.Authorization.ExpiresAt = result.LeaseExpiresAt
	view.Authorization.AllowedOperations = append([]string(nil), result.AllowedOperations...)
	view.Authorization.State = "RECHECK_REQUIRED"
	if c.authorizationChecked && result.LeaseState == wire.ActivationLeaseRevoked {
		view.Authorization.State = "REVOKED"
		return
	}
	if result.LeaseExpiresAt != "" && !c.cfg.Now().UTC().Before(parseExpiry(result.LeaseExpiresAt)) {
		view.Authorization.State = "EXPIRED"
		return
	}
	if !c.authorizationChecked || c.state.Recovery != nil || (c.state.Pending != nil && len(c.state.Pending.Response) == 0) {
		return
	}
	if result.RootState != wire.RootActiveState || result.LeaseState != wire.ActivationLeaseActive ||
		!reflect.DeepEqual(result.AllowedOperations, wire.ActivationAllowedOperations()) {
		view.Authorization.State = result.LeaseState
		return
	}
	if result.LoginRequired || c.session == nil || !c.sessionInspected || c.sessionNeedsCheck || !c.cfg.Now().UTC().Before(parseExpiry(c.session.ExpiresAt)) {
		view.Authorization.State = "LOGIN_REQUIRED"
		return
	}
	view.Authorization.State, view.Authorization.Confirmed = "ACTIVE", true
	view.Phase = PhaseOwnerReady
}
