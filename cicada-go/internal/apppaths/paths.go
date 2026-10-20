// Package apppaths selects the installed per-user file root. It does not
// create, migrate, copy or remove files or identities.
package apppaths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidRoot = errors.New("Cicada user root must be an absolute canonical path in a protected directory")

const UserRootEnvironment = "CICADA_USER_ROOT"

// ResolveUserRoot applies an explicit installation choice, the dedicated
// environment override, then the per-user default. Existing component-specific
// state paths take precedence at their callers; this is never a migration.
func ResolveUserRoot(explicit string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil && explicit == "" && os.Getenv(UserRootEnvironment) == "" {
		return "", ErrInvalidRoot
	}
	return resolveUserRoot(explicit, os.Getenv(UserRootEnvironment), home)
}

func resolveUserRoot(explicit, environment, home string) (string, error) {
	selected := explicit
	if selected == "" {
		selected = environment
	}
	if selected == "" {
		selected = filepath.Join(home, ".cicada")
	}
	if selected == "" || !utf8.ValidString(selected) || strings.TrimSpace(selected) != selected ||
		!filepath.IsAbs(selected) || filepath.Clean(selected) != selected ||
		filepath.Dir(selected) == selected || strings.IndexFunc(selected, unicode.IsControl) >= 0 {
		return "", ErrInvalidRoot
	}
	if err := validatePlatformRoot(selected); err != nil {
		return "", ErrInvalidRoot
	}
	return selected, nil
}

func AppVaultRoot(root string) string   { return filepath.Join(root, "app", "vaults") }
func NodeStateRoot(root string) string  { return filepath.Join(root, "state") }
func MCPSessionFile(root string) string { return filepath.Join(root, "mcp", "sessions.json") }
