package appcore

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/pqtls"
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
	c.profileRecoveryRequired = c.cfg.DiscoverVaults != nil
	if err := c.resetConnection(); err != nil {
		return c.fail(PhaseError, "APP_VAULT_CLOSE_FAILED", err)
	}
	if c.cfg.DiscoverVaults == nil {
		c.publish()
		return nil
	}
	scopes, err := c.cfg.DiscoverVaults(ctx)
	if err != nil || len(scopes) > 64 {
		return c.fail(PhaseLocked, "APP_PROFILE_DISCOVERY_FAILED", errors.New("local profile discovery unavailable"))
	}
	if len(scopes) != 0 && c.cfg.OpenVault == nil {
		return c.fail(PhaseLocked, "APP_PROFILE_UNLOCK_FAILED", errors.New("local profile storage unavailable"))
	}
	var profiles []localProfile
	seen := make(map[appvault.Scope]bool)
	for _, scope := range scopes {
		if seen[scope] {
			return c.fail(PhaseLocked, "APP_PROFILE_DISCOVERY_FAILED", appvault.ErrScopeMismatch)
		}
		seen[scope] = true
		vault, err := c.cfg.OpenVault(ctx, scope, false)
		if err != nil {
			return c.failProfileOpen(err)
		}
		state, _, readErr := readProfile(vault, scope)
		closeErr := vault.Close()
		if readErr != nil || closeErr != nil {
			return c.fail(PhaseLocked, "APP_PROFILE_INVALID", errors.New("local profile authentication failed"))
		}
		path, err := scopeVaultPath(string(filepath.Separator), scope)
		if err != nil {
			return c.fail(PhaseLocked, "APP_PROFILE_INVALID", err)
		}
		profiles = append(profiles, localProfile{scope: scope, view: ProfileSnapshot{
			ID: strings.TrimSuffix(filepath.Base(path), ".vault"), Origin: scope.Origin,
			AccountID: scope.AccountID, OwnerID: scope.OwnerID, Direct: state.Transport != nil}})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].view.ID < profiles[j].view.ID })
	c.profiles, c.profileRecoveryRequired = profiles, false
	c.publish()
	return nil
}

func (c *nativeController) resumeProfile(ctx context.Context, id string) error {
	return c.resumeProfileAt(ctx, id, "")
}

func (c *nativeController) resumeProfileAt(ctx context.Context, id, address string) error {
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
	c.profileRecoveryRequired = true
	if err := c.resetConnection(); err != nil {
		return c.fail(PhaseError, "APP_VAULT_CLOSE_FAILED", err)
	}
	// Authenticate the selected encrypted profile again before trusting its
	// origin. Discovery metadata and a filename alone never establish trust.
	vault, err := c.cfg.OpenVault(ctx, scope, false)
	if err != nil {
		return c.failProfileOpen(err)
	}
	state, version, err := readProfile(vault, scope)
	if err != nil {
		_ = vault.Close()
		return c.fail(PhaseLocked, "APP_PROFILE_INVALID", err)
	}
	c.vault, c.state, c.stateVer = vault, state, version
	card := state.Connection
	transport := cloneLocalTransport(state.Transport)
	c.directConnection = transport != nil
	if address != "" {
		if pqtls.ValidateIPDialAddress(address) != nil {
			return c.failConnectionTransport("HUB_ADDRESS_INVALID")
		}
		if transport == nil {
			return c.failConnectionTransport("HUB_TRANSPORT_SCOPE_MISMATCH")
		}
		transport.DialAddress = address
	}
	if err := c.useConnectionTransport(transport, card); err != nil {
		return c.failConnectionTransport("HUB_TLS_UNVERIFIED")
	}
	c.publish()
	// Expiry limits installer material, not an authenticated enrolled local
	// profile. HTTP remains an explicit fixture policy on every reopen.
	if strings.HasPrefix(card.Origin, "http://") && (!card.AllowLoopbackHTTP || !c.cfg.AllowLoopbackHTTP) {
		_ = c.resetConnection()
		return c.fail(PhaseLocked, "LOOPBACK_HTTP_DISABLED", ErrInvalidCard)
	}
	hub, service, err := c.verifyHub(ctx, card)
	if err != nil {
		if transport != nil {
			code := err.Error()
			if code == "HUB_UNAVAILABLE" {
				code = "HUB_TLS_UNVERIFIED"
			}
			return c.failConnectionTransport(code)
		}
		_ = c.resetConnection()
		return c.fail(PhaseUnavailable, "APP_PROFILE_HUB_UNVERIFIED", err)
	}
	if transport != nil {
		c.transportState = HubTransportVerified
		if transport.DialAddress != state.Transport.DialAddress {
			c.state.Transport = cloneLocalTransport(transport)
			if err := c.persistState(); err != nil {
				return c.failStorage("APP_STATE_UNAVAILABLE", err)
			}
		}
	}
	c.setConnectedHub(hub, card, service, nil)
	if err := c.loadIdentities(false); err != nil {
		return c.failStorage("APP_IDENTITY_UNAVAILABLE", err)
	}
	if err := c.loadNodeState(); err != nil {
		return c.failStorage("APP_NODE_STATE_INVALID", err)
	}
	if err := c.ensureThreadGroupsLoaded(); err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	if err := c.restoreSession(); err != nil {
		return c.failStorage("APP_SESSION_STATE_INVALID", err)
	}
	if err := c.loadCurrentPendingResponse(); err != nil {
		return c.failStorage("APP_PENDING_RESPONSE_INVALID", err)
	}
	if err := c.loadPairState(); err != nil {
		return c.failPairStorage(err)
	}
	if c.device != nil && c.owner != nil {
		if err := c.ensureLocalDomainLoaded(); err != nil {
			return err
		}
	}
	c.profileRecoveryRequired = false
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
	if c.nodePairTrustPending() {
		if err := c.recoverNodePairing(ctx); err != nil {
			return err
		}
	}
	if c.hasPairPending() {
		if err := c.recoverPair(ctx); err != nil {
			return err
		}
	}
	// Unlock may expose an uncertain domain packet without starting new work.
	// Keep the restored session uninspected until that original is recovered;
	// inspectSession correctly refuses fresh requests while it is pending.
	if c.hasLocalDomainPending() {
		c.publish()
		return nil
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

func (c *nativeController) failProfileOpen(err error) error {
	code := "APP_PROFILE_UNLOCK_FAILED"
	if errors.Is(err, appvault.ErrVaultBusy) {
		code = "APP_PROFILE_IN_USE"
	}
	return c.fail(PhaseLocked, code, err)
}

func (c *nativeController) requireSessionRecheck() {
	if c.session != nil {
		c.sessionNeedsCheck, c.sessionInspected = true, false
		c.state.AccountState = AccountStateSessionCheck
	}
}
