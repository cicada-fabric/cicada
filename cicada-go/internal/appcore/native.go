package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/appvault"
)

type VaultOpener func(context.Context, appvault.Scope, bool) (*appvault.Vault, error)

// OpenNativeController constructs the desktop App core with the platform
// vault protector and a no-proxy, redirect-rejecting HTTPS client. On Windows
// this uses current-user DPAPI. Other platforms compile for development but
// return an unsupported-platform vault error when a vault is opened.
func OpenNativeController() (Controller, error) {
	root, err := nativeVaultRoot()
	if err != nil || root == "" {
		return nil, errors.New("native App configuration directory unavailable")
	}
	// N1 already published vaults at this nested path. Keep it stable: moving
	// local identities requires an explicit migration, never a silent rekey.
	root = filepath.Join(root, "CICADA", "vaults")
	return newController(Config{HTTP: NewHTTPClient(), OpenVault: NewPlatformVaultOpener(root), DiscoverVaults: NewProfileDiscovery(root)}, true)
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
