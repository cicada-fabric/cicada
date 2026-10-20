package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/apppaths"
	"github.com/cicada-ai/cicada/internal/appvault"
)

type VaultOpener func(context.Context, appvault.Scope, bool) (*appvault.Vault, error)

// OpenNativeController constructs the desktop App core with the platform
// vault protector and a no-proxy, redirect-rejecting HTTPS client. On Windows
// this uses current-user DPAPI. Other platforms compile for development but
// return an unsupported-platform vault error when a vault is opened.
func OpenNativeController() (Controller, error) {
	return OpenNativeControllerWithRoot("")
}

// OpenNativeControllerWithRoot selects new-profile storage while retaining the
// original published vault location for authenticated recovery. It never moves
// a vault or creates an identity merely because a selected directory is empty.
func OpenNativeControllerWithRoot(explicit string) (Controller, error) {
	root, err := apppaths.ResolveUserRoot(explicit)
	if err != nil {
		return nil, errors.New("native App configuration directory unavailable")
	}
	// N1 already published vaults at this nested path. Keep it stable: moving
	// local identities requires an explicit migration, never a silent rekey.
	legacy, err := nativeVaultRoot()
	if err != nil || legacy == "" {
		return nil, errors.New("original native App configuration directory unavailable")
	}
	primary := apppaths.AppVaultRoot(root)
	oldRoots := []string{filepath.Join(legacy, "CICADA", "vaults")}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
		oldRoots = append(oldRoots, apppaths.AppVaultRoot(filepath.Join(home, ".cicada")))
	}
	storage, err := newProfileStorage(primary, oldRoots, NewPlatformVaultOpener)
	if err != nil {
		return nil, err
	}
	return newController(Config{HTTP: NewHTTPClient(), OpenVault: storage.open, DiscoverVaults: storage.discover,
		UserRoot: root, VaultLocation: storage.location}, true)
}

// NewProfileDiscovery supplies untrusted scope locators only. The controller
// authenticates each vault before exposing profile metadata or sending traffic.
func NewProfileDiscovery(root string) func(context.Context) ([]appvault.Scope, error) {
	return func(ctx context.Context) ([]appvault.Scope, error) {
		candidates, err := appvault.DiscoverCandidates(root)
		if err != nil {
			return nil, err
		}
		var scopes []appvault.Scope
		for _, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			path, err := scopeVaultPath(root, candidate.Scope)
			if err != nil || filepath.Base(path) != candidate.Name {
				return nil, appvault.ErrScopeMismatch
			}
			scopes = append(scopes, candidate.Scope)
		}
		return scopes, nil
	}
}

// NewPlatformVaultOpener returns a scope-derived file path under root. The
// filename hashes all scope fields, preventing path injection and keeping
// different Hub/account/Owner pins in separate vaults.
func NewPlatformVaultOpener(root string) VaultOpener {
	return platformVaultOpener(root)
}

func scopeVaultPath(root string, scope appvault.Scope) (string, error) {
	if root == "" {
		return "", errors.New("invalid App vault location")
	}
	encoded, err := json.Marshal(scope)
	if err != nil {
		return "", errors.New("invalid App vault scope")
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return filepath.Join(root, hex.EncodeToString(digest[:])+".vault"), nil
}
