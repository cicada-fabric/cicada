package nodekeys

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func runtimeTrustTree(t *testing.T, root string) string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		entry := fmt.Sprintf("%s:%o", rel, info.Mode())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			clear(data)
			entry += fmt.Sprintf(":%x", sum)
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		t.Fatal("disposable tree read")
	}
	sort.Strings(entries)
	return strings.Join(entries, "\n")
}
func runtimeTrustFixture(t *testing.T) (string, e2ee.PublicIdentity, e2ee.PublicIdentity) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private disposable root")
	}
	s, err := OpenCryptoState(root)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := PeerKeyFingerprint(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	trust, err := s.TrustOwnerApprovalKeyLocal("synthetic-owner", owner.Public().ID, owner.Public(), fp)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, err = s.RevokeNodeOwnerKeyTrustLocal("synthetic-owner", owner.Public().ID, trust.Version); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	endpoint, err := LoadOrCreate(root, "synthetic-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	return root, owner.Public(), endpoint.Public()
}
func TestNodeTLSRuntimeTrustReadOnlyRetainsRevokedAndEndpointKeys(t *testing.T) {
	root, owner, endpoint := runtimeTrustFixture(t)
	before := runtimeTrustTree(t, root)
	reader, err := OpenExistingCryptoStateReadOnly(root)
	if err != nil {
		t.Fatal("existing checkpointed trust read", err)
	}
	keys, err := reader.RetainedSigningPublicKeys()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, key := range keys {
		found[string(key)] = true
	}
	if len(keys) != 2 || !found[string(owner.SigningPublic)] || !found[string(endpoint.SigningPublic)] {
		reader.Close()
		t.Fatal("retained inventory omitted revoked or Endpoint public")
	}
	trust, err := reader.State.GetNodeOwnerKeyTrustLocal("synthetic-owner", owner.ID)
	if err != nil || trust.State != NodeOwnerKeyTrustRevoked {
		reader.Close()
		t.Fatal("revoked local trust changed")
	}
	reader.Close()
	if runtimeTrustTree(t, root) != before {
		t.Fatal("read-only trust adapter changed bytes or modes")
	}
}
func TestNodeTLSRuntimeTrustRejectsWALAndUnstableSnapshotNoWrites(t *testing.T) {
	for _, kind := range []string{"wal", "journal", "symlink", "unstable"} {
		t.Run(kind, func(t *testing.T) {
			root, _, _ := runtimeTrustFixture(t)
			var reader *RuntimeTrustRead
			if kind == "unstable" {
				var err error
				reader, err = OpenExistingCryptoStateReadOnly(root)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
			}
			suffix := "-wal"
			if kind == "journal" {
				suffix = "-journal"
			}
			if kind == "unstable" {
				suffix = "-shm"
			}
			path := filepath.Join(root, cryptoStateDBName) + suffix
			if kind == "symlink" {
				if os.Symlink(filepath.Join(root, cryptoStateDBName), path) != nil {
					t.Fatal("synthetic symlink")
				}
			} else {
				if os.WriteFile(path, []byte("synthetic uncheckpointed sidecar"), 0600) != nil {
					t.Fatal("synthetic sidecar")
				}
			}
			before := runtimeTrustTree(t, root)
			var err error
			if reader != nil {
				err = reader.CheckStable()
			} else {
				opened, openErr := OpenExistingCryptoStateReadOnly(root)
				err = openErr
				if opened != nil {
					opened.Close()
				}
			}
			if !errors.Is(err, ErrRuntimeTrustUnavailable) {
				t.Fatal("unsafe or changed sidecar admitted", err)
			}
			if runtimeTrustTree(t, root) != before {
				t.Fatal("failed readonly inspection mutated sidecars")
			}
		})
	}
}
