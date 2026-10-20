package appcore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/cicada-ai/cicada/internal/appvault"
)

// profileStorage keeps authenticated scope-to-location associations. Locations
// never come from the Hub, and a later failed scan cannot replace an association
// or silently turn a missing original identity into a new installation.
type profileStorage struct {
	primary    string
	roots      []string
	factory    func(string) VaultOpener
	mu         sync.RWMutex
	locations  map[appvault.Scope]string
	discovered bool
}

func newProfileStorage(primary string, legacy []string, factory func(string) VaultOpener) (*profileStorage, error) {
	if factory == nil {
		return nil, appvault.ErrInvalidVault
	}
	roots := []string{}
	for _, root := range append([]string{primary}, legacy...) {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return nil, appvault.ErrInvalidVault
		}
		duplicate := false
		for _, old := range roots {
			if sameStorageDirectory(root, old) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			roots = append(roots, root)
		}
	}
	return &profileStorage{primary: primary, roots: roots, factory: factory, locations: make(map[appvault.Scope]string)}, nil
}

func sameStorageDirectory(a, b string) bool {
	if a == b || (runtime.GOOS == "windows" && strings.EqualFold(a, b)) {
		return true
	}
	one, firstErr := os.Lstat(a)
	two, secondErr := os.Lstat(b)
	return firstErr == nil && secondErr == nil && one.IsDir() && two.IsDir() && one.Mode()&os.ModeSymlink == 0 && two.Mode()&os.ModeSymlink == 0 && os.SameFile(one, two)
}

func (s *profileStorage) discover(ctx context.Context) ([]appvault.Scope, error) {
	// Serialize scanning with creation. No I/O or authentication is done while
	// holding a controller snapshot lock or on the native frame loop.
	s.mu.Lock()
	defer s.mu.Unlock()
	found := make(map[appvault.Scope]string)
	var scopes []appvault.Scope
	for _, root := range s.roots {
		candidates, err := NewProfileDiscovery(root)(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectVaultFilenameAliases(root); err != nil {
			return nil, err
		}
		for _, scope := range candidates {
			if len(scopes) >= 64 {
				return nil, appvault.ErrInvalidVault
			}
			if _, duplicate := found[scope]; duplicate {
				return nil, appvault.ErrScopeMismatch
			}
			found[scope] = root
			scopes = append(scopes, scope)
		}
	}
	for scope, previous := range s.locations {
		if current, present := found[scope]; !present || current != previous {
			return nil, appvault.ErrScopeMismatch
		}
	}
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vault, err := s.factory(found[scope])(ctx, scope, false)
		if err != nil {
			return nil, err
		}
		if vault == nil {
			return nil, appvault.ErrInvalidVault
		}
		_, _, readErr := readProfile(vault, scope)
		closeErr := vault.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
	}
	// Publish only the complete authenticated scan. A busy, corrupt, duplicate,
	// renamed or missing source leaves every previous association unchanged.
	s.locations, s.discovered = found, true
	return scopes, nil
}

func rejectVaultFilenameAliases(root string) error {
	directory, err := os.Open(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return appvault.ErrInvalidVault
	}
	names, readErr := directory.Readdirnames(257)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(names) > 256 {
		return appvault.ErrInvalidVault
	}
	for _, name := range names {
		trimmed := strings.TrimRight(name, ". ")
		if strings.HasSuffix(strings.ToLower(trimmed), ".vault") &&
			(name != trimmed || name != strings.ToLower(name)) {
			return appvault.ErrInvalidVault
		}
	}
	return nil
}

func (s *profileStorage) open(ctx context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
	s.mu.RLock()
	root, known := s.locations[scope]
	complete := s.discovered
	s.mu.RUnlock()
	if known {
		return s.factory(root)(ctx, scope, false)
	}
	if !create {
		return nil, appvault.ErrStateNotFound
	}
	if !complete {
		return nil, appvault.ErrInvalidVault
	}
	// An explicit new-profile action still rechecks all known locations. An
	// empty selected custom root must not hide an identity in the old root.
	if _, err := s.discover(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if root, known := s.locations[scope]; known {
		return s.factory(root)(ctx, scope, false)
	}
	vault, err := s.factory(s.primary)(ctx, scope, true)
	if err != nil {
		return nil, err
	}
	if vault == nil || vault.Scope() != scope {
		if vault != nil {
			_ = vault.Close()
		}
		return nil, appvault.ErrScopeMismatch
	}
	s.locations[scope] = s.primary
	return vault, nil
}

func (s *profileStorage) location(scope appvault.Scope) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	root, ok := s.locations[scope]
	return root, ok
}
