package appvault

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Candidate is an UNAUTHENTICATED locator read from a vault header. Callers
// must Open the vault and authenticate its contents before displaying its
// scope as trusted, contacting its origin, or using any identity.
type Candidate struct {
	Name  string
	Scope Scope
}

// DiscoverCandidates reads only bounded regular vault files in a protected
// directory. It does not unlock anything, create a directory, or follow links.
func DiscoverCandidates(root string) ([]Candidate, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrInvalidVault
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if validatePrivateParent(root) != nil {
		return nil, ErrInvalidVault
	}
	dir, err := os.Open(root)
	if err != nil {
		return nil, ErrInvalidVault
	}
	defer dir.Close()
	// Includes lock files and incomplete atomic writes. An unexpected number
	// requires local inspection, not an unbounded scan at App startup.
	names, err := dir.Readdirnames(257)
	if (err != nil && !errors.Is(err, io.EOF)) || len(names) > 256 {
		return nil, ErrInvalidVault
	}
	var candidates []Candidate
	for _, name := range names {
		if !strings.HasSuffix(name, ".vault") {
			continue
		}
		data, _, err := readVaultFile(filepath.Join(root, name))
		if err != nil {
			return nil, ErrInvalidVault
		}
		header, scope, _, wrapped, nonce, ciphertext, err := decodeHeader(data)
		clear(data)
		clear(header)
		clear(wrapped)
		clear(nonce)
		clear(ciphertext)
		if err != nil || len(candidates) >= 64 {
			return nil, ErrInvalidVault
		}
		candidates = append(candidates, Candidate{Name: name, Scope: scope})
	}
	return candidates, nil
}
