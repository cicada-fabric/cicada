package appcore

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/appvault"
)

type localProfile struct {
	view  ProfileSnapshot
	scope appvault.Scope
}

func cardScope(card HubConnectionCard) appvault.Scope {
	return appvault.Scope{HubID: card.HubID, HubFingerprint: card.HubFingerprint,
		Origin: card.Origin, AccountID: card.AccountID, OwnerID: card.OwnerID}
}

func readProfile(vault *appvault.Vault, scope appvault.Scope) (durableState, uint64, error) {
	if vault == nil || vault.Scope() != scope {
		return durableState{}, 0, appvault.ErrScopeMismatch
	}
	data, version, found, err := vault.LoadState(appStateNamespace)
	defer clear(data)
	if err != nil || !found {
		return durableState{}, 0, appvault.ErrStateNotFound
	}
	state, err := decodeDurableState(data)
	if err != nil || cardScope(state.Connection) != scope || state.AccountID != scope.AccountID || state.OwnerID != scope.OwnerID {
		return durableState{}, 0, appvault.ErrScopeMismatch
	}
	return state, version, nil
}

func (c *nativeController) discoverProfiles(ctx context.Context) error {
	if err := c.resetConnection(); err != nil {
		return c.fail(PhaseError, "APP_VAULT_CLOSE_FAILED", err)
	}
	c.profiles = nil
	if c.cfg.DiscoverVaults == nil || c.cfg.OpenVault == nil {
		c.publish()
		return nil
	}
	scopes, err := c.cfg.DiscoverVaults(ctx)
	if err != nil || len(scopes) > 64 {
		return c.fail(PhaseLocked, "APP_PROFILE_DISCOVERY_FAILED", errors.New("local profile discovery unavailable"))
	}
	seen := make(map[appvault.Scope]bool)
	for _, scope := range scopes {
		if seen[scope] {
			return c.fail(PhaseLocked, "APP_PROFILE_DISCOVERY_FAILED", appvault.ErrScopeMismatch)
		}
		seen[scope] = true
		vault, err := c.cfg.OpenVault(ctx, scope, false)
		if err != nil {
			return c.fail(PhaseLocked, "APP_PROFILE_UNLOCK_FAILED", err)
		}
		_, _, readErr := readProfile(vault, scope)
		closeErr := vault.Close()
		if readErr != nil || closeErr != nil {
			return c.fail(PhaseLocked, "APP_PROFILE_INVALID", errors.New("local profile authentication failed"))
		}
		path, err := scopeVaultPath(string(filepath.Separator), scope)
		if err != nil {
			return c.fail(PhaseLocked, "APP_PROFILE_INVALID", err)
		}
		c.profiles = append(c.profiles, localProfile{scope: scope, view: ProfileSnapshot{
			ID: strings.TrimSuffix(filepath.Base(path), ".vault"), Origin: scope.Origin,
			AccountID: scope.AccountID, OwnerID: scope.OwnerID}})
	}
	sort.Slice(c.profiles, func(i, j int) bool { return c.profiles[i].view.ID < c.profiles[j].view.ID })
	c.publish()
	return nil
}

func (c *nativeController) resumeProfile(ctx context.Context, id string) error {
	var selected *localProfile
	for i := range c.profiles {
		if c.profiles[i].view.ID == id {
			selected = &c.profiles[i]
			break
		}
	}
	if selected == nil || c.cfg.OpenVault == nil {
		return ErrInvalidAction
	}
	scope := selected.scope
	if err := c.resetConnection(); err != nil {
		return c.fail(PhaseError, "APP_VAULT_CLOSE_FAILED", err)
	}
	// Authenticate the selected encrypted profile again before trusting its
	// origin. Discovery metadata and a filename alone never establish trust.
	vault, err := c.cfg.OpenVault(ctx, scope, false)
	if err != nil {
		return c.fail(PhaseLocked, "APP_PROFILE_UNLOCK_FAILED", err)
	}
	state, version, err := readProfile(vault, scope)
	if err != nil {
		_ = vault.Close()
		return c.fail(PhaseLocked, "APP_PROFILE_INVALID", err)
	}
	c.vault, c.state, c.stateVer = vault, state, version
	card := state.Connection
	// Expiry limits installer material, not an authenticated enrolled local
	// profile. HTTP remains an explicit fixture policy on every reopen.
	if strings.HasPrefix(card.Origin, "http://") && (!card.AllowLoopbackHTTP || !c.cfg.AllowLoopbackHTTP) {
		_ = c.resetConnection()
		return c.fail(PhaseLocked, "LOOPBACK_HTTP_DISABLED", ErrInvalidCard)
	}
	hub, service, err := c.verifyHub(ctx, card)
	if err != nil {
		_ = c.resetConnection()
		return c.fail(PhaseUnavailable, "APP_PROFILE_HUB_UNVERIFIED", err)
	}
	c.setConnectedHub(hub, card, service, nil)
	if err := c.loadIdentities(false); err != nil {
		return c.failStorage("APP_IDENTITY_UNAVAILABLE", err)
	}
	if err := c.loadNodeState(); err != nil {
		return c.failStorage("APP_NODE_STATE_INVALID", err)
	}
	if err := c.restoreSession(); err != nil {
		return c.failStorage("APP_SESSION_STATE_INVALID", err)
	}
	if err := c.loadCurrentPendingResponse(); err != nil {
		return c.failStorage("APP_PENDING_RESPONSE_INVALID", err)
	}
	// Cached inspections are receipts, not current authorization. Recover an
	// uncertain packet first, then ask for fresh authenticated session state.
	c.requireSessionRecheck()
	c.publish()
	if c.state.Recovery != nil {
		return c.recoverOperation(ctx)
	}
	if c.state.Pending != nil && len(c.state.Pending.Response) == 0 {
		if err := c.sendPending(ctx); err != nil {
			return err
		}
		c.requireSessionRecheck()
	}
	if c.session != nil {
		if err := c.inspectSession(ctx); err != nil {
			return err
		}
	}
	if c.state.Enrollment != nil && c.state.Enrollment.Target != nil && c.canBeginOperation() {
		return c.refreshActivation(ctx)
	}
	c.publish()
	return nil
}

func (c *nativeController) requireSessionRecheck() {
	if c.session != nil {
		c.sessionNeedsCheck, c.sessionInspected = true, false
		c.state.AccountState = AccountStateSessionCheck
	}
}
