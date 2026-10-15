//go:build windows

package appcore

import (
	"context"
	"errors"
	"os"

	"github.com/cicada-ai/cicada/internal/appvault"
)

func platformVaultOpener(root string) VaultOpener {
	return func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		path, err := scopeVaultPath(root, scope)
		if err != nil {
			return nil, err
		}
		_, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) && !create {
			return nil, appvault.ErrStateNotFound
		}
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, appvault.ErrInvalidVault
		}
		protector, err := appvault.NewPlatformProtector()
		if err != nil {
			return nil, err
		}
		if errors.Is(statErr, os.ErrNotExist) {
			return appvault.Create(path, scope, protector)
		}
		return appvault.Open(path, scope, protector)
	}
}
