//go:build !windows

package appcore

import (
	"context"

	"github.com/cicada-ai/cicada/internal/appvault"
)

func platformVaultOpener(string) VaultOpener {
	return func(context.Context, appvault.Scope, bool) (*appvault.Vault, error) {
		return nil, appvault.ErrUnsupportedOS
	}
}
