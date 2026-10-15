//go:build linux || darwin

package appvault

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryRejectsLinksPermissionsAndOversize(t *testing.T) {
	for _, mode := range []string{"symlink-file", "symlink-directory", "unsafe-directory", "unsafe-file", "oversize", "entry-limit"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateTestDir(t)
			path := filepath.Join(dir, "synthetic.vault")
			vault, err := Create(path, testScope(), testProtector(t))
			if err != nil {
				t.Fatal(err)
			}
			vault.Close()
			if candidates, err := DiscoverCandidates(dir); err != nil || len(candidates) != 1 || candidates[0].Scope != testScope() {
				t.Fatal("valid vault locator not found")
			}
			switch mode {
			case "symlink-file":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "symlink-directory":
				link := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "unsafe-directory":
				if err := os.Chmod(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			case "unsafe-file":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(path, maxVaultFileBytes+1); err != nil {
					t.Fatal(err)
				}
			case "entry-limit":
				for i := 0; i < 257; i++ {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("unrelated-%d", i)), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := DiscoverCandidates(dir); err == nil {
				t.Fatal("unsafe discovery input was accepted")
			}
		})
	}
}

func TestDiscoveryDoesNotInitializeMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-initialized")
	if candidates, err := DiscoverCandidates(dir); err != nil || len(candidates) != 0 {
		t.Fatal("missing profile directory is not an empty discovery")
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("discovery created local state")
	}
}
