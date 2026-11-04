package appcore

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/appvault"
)

const profilePresenceNamespace = "appcore.profile-presence.v1"

// This authenticated vault record only controls the local connection list.
// Keys, original packets, receipts and CAS generations stay in the same vault.
type profilePresence struct {
	Format  string `json:"format"`
	Removed bool   `json:"removed"`
	Version uint64 `json:"-"`
}

func readProfilePresence(v *appvault.Vault) (profilePresence, error) {
	if v == nil {
		return profilePresence{}, appvault.ErrInvalidVault
	}
	raw, version, found, err := v.LoadState(profilePresenceNamespace)
	defer clear(raw)
	p := profilePresence{Version: version}
	if err != nil {
		return p, err
	}
	if !found {
		p.Format = profilePresenceNamespace
		return p, nil
	}
	if decodeStateJSON(raw, &p) != nil || p.Format != profilePresenceNamespace {
		return p, appvault.ErrScopeMismatch
	}
	p.Version = version
	return p, nil
}

func profilePresenceReview(scope appvault.Scope, version uint64) string {
	return localCollaborationReviewID(struct {
		Scope   appvault.Scope
		Version uint64
	}{scope, version})
}

func profileFromState(state durableState, scope appvault.Scope, p profilePresence) (localProfile, error) {
	path, err := scopeVaultPath(string(filepath.Separator), scope)
	if err != nil {
		return localProfile{}, err
	}
	view := ProfileSnapshot{ID: strings.TrimSuffix(filepath.Base(path), ".vault"), Origin: scope.Origin,
		HubID: scope.HubID, Fingerprint: scope.HubFingerprint, AccountID: scope.AccountID, OwnerID: scope.OwnerID,
		Direct: state.Transport != nil, Removed: p.Removed, ReviewID: profilePresenceReview(scope, p.Version)}
	if state.Transport != nil {
		view.Address = state.Transport.DialAddress
	} else {
		view.Address = scope.Origin
	}
	return localProfile{view: view, scope: scope}, nil
}

func (c *nativeController) rememberCurrentProfile(p profilePresence) error {
	profile, err := profileFromState(c.state, c.vault.Scope(), p)
	if err != nil {
		return err
	}
	for i := range c.profiles {
		if c.profiles[i].scope == profile.scope {
			c.profiles[i] = profile
			return nil
		}
	}
	c.profiles = append(c.profiles, profile)
	sort.Slice(c.profiles, func(i, j int) bool { return c.profiles[i].view.ID < c.profiles[j].view.ID })
	return nil
}

func (c *nativeController) restoreCurrentProfile() error {
	p, err := readProfilePresence(c.vault)
	if err != nil {
		return err
	}
	if p.Removed {
		p.Removed = false
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		defer clear(raw)
		p.Version, err = c.vault.CompareAndSwapState(profilePresenceNamespace, p.Version, raw)
		if err != nil {
			return err
		}
	}
	return c.rememberCurrentProfile(p)
}

func (c *nativeController) removeProfile(ctx context.Context, a Action) error {
	var selected *localProfile
	for i := range c.profiles {
		if c.profiles[i].view.ID == a.ProfileID {
			selected = &c.profiles[i]
			break
		}
	}
	if selected == nil || selected.view.Removed || !a.ConfirmProfileRemoval || a.ProfileReviewID != selected.view.ReviewID || c.cfg.OpenVault == nil {
		return ErrInvalidAction
	}
	scope := selected.scope
	if c.vault != nil && c.vault.Scope() == scope {
		if err := c.resetConnection(); err != nil {
			return c.fail(PhaseLocked, "APP_VAULT_CLOSE_FAILED", err)
		}
	}
	v, err := c.cfg.OpenVault(ctx, scope, false)
	if err != nil {
		return c.failProfileOpen(err)
	}
	state, _, err := readProfile(v, scope)
	p, presenceErr := readProfilePresence(v)
	if err != nil || presenceErr != nil || p.Removed || profilePresenceReview(scope, p.Version) != a.ProfileReviewID {
		_ = v.Close()
		return c.fail(PhaseLocked, "APP_PROFILE_UPDATE_FAILED", errors.New("saved connection changed"))
	}
	p.Removed = true
	raw, err := json.Marshal(p)
	if err == nil {
		p.Version, err = v.CompareAndSwapState(profilePresenceNamespace, p.Version, raw)
	}
	clear(raw)
	closeErr := v.Close()
	if err != nil || closeErr != nil {
		return c.fail(PhaseLocked, "APP_PROFILE_UPDATE_FAILED", errors.New("saved connection could not be updated"))
	}
	profile, err := profileFromState(state, scope, p)
	if err != nil {
		return c.fail(PhaseLocked, "APP_PROFILE_UPDATE_FAILED", err)
	}
	*selected = profile
	c.publish()
	return nil
}
