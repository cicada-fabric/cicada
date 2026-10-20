//go:build linux

package appvault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func createDiscoveryFixture(t *testing.T, root string, scope PreRegistrationScope) (PreRegistrationInfo, string) {
	t.Helper()
	s, err := CreatePreRegistration(root, scope, testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CompareAndSwapState(0, []byte("SYNTHETIC_DISCOVERY_PRIVATE_S_AND_ORIGINAL_PACKET\x00")); err != nil {
		t.Fatal(err)
	}
	return PreRegistrationInfo{scope, preRegistrationIdentityID(t, s), 1}, s.path
}

func discoveryScope(index int) PreRegistrationScope {
	scope := preRegistrationTestScope()
	scope.InstallationID = fmt.Sprintf("%032x", index+1)
	return scope
}

type discoveryCountingProtector struct {
	*PasswordProtector
	closed *int
}

func (p *discoveryCountingProtector) Close() {
	*p.closed++
	p.PasswordProtector.Close()
}

func TestPreRegistrationDiscoveryAuthenticatesAllLocatorsAndClosesStores(t *testing.T) {
	root := privateTestDir(t)
	want := make(map[PreRegistrationScope]PreRegistrationInfo)
	original := make(map[string][]byte)
	for i := 0; i < 2; i++ {
		info, path := createDiscoveryFixture(t, root, discoveryScope(i))
		want[info.Scope] = info
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		original[path] = data
	}
	notes := filepath.Join(root, "pre-registration", "UNMANAGED-NOTES")
	if err := os.WriteFile(notes, []byte("SYNTHETIC_KEEP_UNMANAGED"), 0600); err != nil {
		t.Fatal(err)
	}
	closed := 0
	infos, err := DiscoverPreRegistrations(root, func() (Protector, error) {
		return &discoveryCountingProtector{testProtector(t), &closed}, nil
	})
	if err != nil || len(infos) != len(want) || closed != len(want) {
		t.Fatal("full authenticated discovery failed or leaked/double-closed a protector", err)
	}
	for _, info := range infos {
		if info != want[info.Scope] {
			t.Fatal("discovery altered an InstallationID, identity, scope or revision")
		}
		// A fresh open proves discovery released each exclusive process lock.
		s, err := OpenPreRegistration(root, info.Scope, testProtector(t))
		if err != nil {
			t.Fatal("discovery retained a private store handle", err)
		}
		_ = s.Close()
	}
	encoded, err := json.Marshal(infos)
	if err != nil || bytes.Contains(encoded, []byte("SYNTHETIC_DISCOVERY_PRIVATE")) || bytes.Contains(encoded, []byte("kem_private")) {
		t.Fatal("public locator metadata exposed private recovery state")
	}
	for path, before := range original {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("discovery rewrote an original protected payload")
		}
	}
	if data, err := os.ReadFile(notes); err != nil || string(data) != "SYNTHETIC_KEEP_UNMANAGED" {
		t.Fatal("discovery cleaned up an unrelated file")
	}
	if candidates, err := DiscoverCandidates(root); err != nil || len(candidates) != 0 {
		t.Fatal("pending locators became logged-in account profiles")
	}
}

func TestPreRegistrationDiscoveryMissingPathsStayMissing(t *testing.T) {
	for _, existingRoot := range []bool{false, true} {
		t.Run(fmt.Sprint(existingRoot), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "private-not-created")
			if existingRoot {
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			infos, err := DiscoverPreRegistrations(root, func() (Protector, error) { calls++; return testProtector(t), nil })
			if err != nil || len(infos) != 0 || calls != 0 {
				t.Fatal("missing paths should remain empty without opening a protector")
			}
			if _, err := os.Lstat(filepath.Join(root, "pre-registration")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("discovery created a pending namespace")
			}
			if !existingRoot {
				if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("discovery created the root directory")
				}
			}
		})
	}
}

func TestPreRegistrationDiscoveryLimitsAreExplicit(t *testing.T) {
	t.Run("sixteen-valid-records", func(t *testing.T) {
		root := privateTestDir(t)
		for i := 0; i < maxPreRegistrationCandidates; i++ {
			createDiscoveryFixture(t, root, discoveryScope(i))
		}
		infos, err := DiscoverPreRegistrations(root, func() (Protector, error) { return testProtector(t), nil })
		if err != nil || len(infos) != 16 {
			t.Fatal("the full permitted set was not returned for explicit selection", err)
		}
		createDiscoveryFixture(t, root, discoveryScope(16))
		calls := 0
		infos, err = DiscoverPreRegistrations(root, func() (Protector, error) { calls++; return testProtector(t), nil })
		if !errors.Is(err, ErrPreRegistrationLimit) || infos != nil || calls != 0 {
			t.Fatal("seventeenth record was silently ignored or treated as a new installation")
		}
	})
	t.Run("unrelated-directory-entry-bound", func(t *testing.T) {
		root := privateTestDir(t)
		directory := filepath.Join(root, "pre-registration")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= maxPreRegistrationDirectoryEntries; i++ {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprint(i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if infos, err := DiscoverPreRegistrations(root, func() (Protector, error) { return testProtector(t), nil }); infos != nil || !errors.Is(err, ErrPreRegistrationLimit) {
			t.Fatal("unrelated entries allowed an unbounded or falsely empty scan")
		}
	})
}

func TestPreRegistrationDiscoveryBusyOrCorruptReturnsNoPartialResults(t *testing.T) {
	for _, failure := range []string{"busy", "corrupt", "wrong-protector"} {
		t.Run(failure, func(t *testing.T) {
			root := privateTestDir(t)
			byPath := make(map[string]PreRegistrationScope)
			var paths []string
			for i := 0; i < 2; i++ {
				info, path := createDiscoveryFixture(t, root, discoveryScope(i))
				byPath[path] = info.Scope
				paths = append(paths, path)
			}
			slices.Sort(paths)
			last := paths[1]
			var busy *PreRegistrationStore
			if failure == "busy" {
				var err error
				busy, err = OpenPreRegistration(root, byPath[last], testProtector(t))
				if err != nil {
					t.Fatal(err)
				}
				defer busy.Close()
			} else if failure == "corrupt" {
				data, err := os.ReadFile(last)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err := os.WriteFile(last, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			infos, err := DiscoverPreRegistrations(root, func() (Protector, error) {
				if failure == "wrong-protector" {
					return NewPasswordProtector([]byte("synthetic different test-only password"))
				}
				return testProtector(t), nil
			})
			want := ErrInvalidVault
			if failure == "busy" {
				want = ErrVaultBusy
			}
			if infos != nil || !errors.Is(err, want) {
				t.Fatal("failed scan returned partial metadata or hid its failure", err)
			}
			first, err := OpenPreRegistration(root, byPath[paths[0]], testProtector(t))
			if err != nil {
				t.Fatal("a failed scan leaked an earlier record's process lock")
			}
			_ = first.Close()
		})
	}
}

func TestPreRegistrationDiscoveryRejectsUnsafeOrForgedLocators(t *testing.T) {
	for _, failure := range []string{"wrong-filename", "uppercase-extension", "trailing-dot", "trailing-space", "rewritten-scope", "truncated-header", "oversize-header-field", "legacy-magic", "file-symlink", "directory-symlink", "broad-directory", "broad-file"} {
		t.Run(failure, func(t *testing.T) {
			root := privateTestDir(t)
			_, path := createDiscoveryFixture(t, root, discoveryScope(0))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := ErrInvalidVault
			switch failure {
			case "wrong-filename":
				want = ErrScopeMismatch
				if err := os.Rename(path, filepath.Join(filepath.Dir(path), "wrong.pending")); err != nil {
					t.Fatal(err)
				}
			case "uppercase-extension", "trailing-dot", "trailing-space":
				want = ErrScopeMismatch
				other := strings.TrimSuffix(path, ".pending") + ".PENDING"
				if failure == "trailing-dot" {
					other = path + "."
				} else if failure == "trailing-space" {
					other = path + " "
				}
				if err := os.Rename(path, other); err != nil {
					t.Fatal(err)
				}
			case "rewritten-scope":
				other := discoveryScope(0)
				other.HubID = "hub_synthetic_b"
				otherPath, err := PreRegistrationPath(root, other)
				if err != nil {
					t.Fatal(err)
				}
				forged := bytes.Replace(data, []byte(discoveryScope(0).HubID), []byte(other.HubID), 1)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(otherPath, forged, 0600); err != nil {
					t.Fatal(err)
				}
			case "truncated-header", "oversize-header-field", "legacy-magic":
				if failure == "truncated-header" {
					data = data[:len(preRegistrationMagic)+1]
				} else if failure == "legacy-magic" {
					copy(data, vaultMagic)
				} else {
					binary.BigEndian.PutUint16(data[len(preRegistrationMagic)+2:], 65535)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "file-symlink":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".retained", path); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				directory := filepath.Dir(path)
				if err := os.Rename(directory, directory+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(directory+".retained", directory); err != nil {
					t.Fatal(err)
				}
			case "broad-directory", "broad-file":
				if failure == "broad-directory" {
					path = filepath.Dir(path)
				}
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if infos, err := DiscoverPreRegistrations(root, func() (Protector, error) { return testProtector(t), nil }); infos != nil || !errors.Is(err, want) {
				t.Fatal("unsafe or unauthenticated locator was accepted", err)
			}
		})
	}
	// A symlink root with a missing descendant is still an unsafe locator,
	// rather than a reason to create a fresh installation under another path.
	outside := privateTestDir(t)
	link := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if infos, err := DiscoverPreRegistrations(link, func() (Protector, error) { return testProtector(t), nil }); infos != nil || !errors.Is(err, ErrInvalidVault) {
		t.Fatal("symlink root with missing namespace looked like a fresh installation")
	}
}

func TestPreRegistrationDiscoveryRejectsChangesDuringAuthentication(t *testing.T) {
	for _, replacement := range []string{"same-bytes-new-inode", "new-bytes-same-inode", "directory", "added-record"} {
		t.Run(replacement, func(t *testing.T) {
			root := privateTestDir(t)
			_, path := createDiscoveryFixture(t, root, discoveryScope(0))
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var next []byte
			if replacement == "new-bytes-same-inode" {
				s, err := OpenPreRegistration(root, discoveryScope(0), testProtector(t))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.CompareAndSwapState(1, []byte("SYNTHETIC_DIFFERENT_ORIGINAL_PACKET")); err != nil {
					t.Fatal(err)
				}
				_ = s.Close()
				next, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			infos, err := DiscoverPreRegistrations(root, func() (Protector, error) {
				calls++
				switch replacement {
				case "same-bytes-new-inode":
					if err := os.WriteFile(path+".replacement", original, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".replacement", path); err != nil {
						t.Fatal(err)
					}
				case "new-bytes-same-inode":
					if err := os.WriteFile(path, next, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					directory := filepath.Dir(path)
					if err := os.Rename(directory, directory+".retained"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, original, 0600); err != nil {
						t.Fatal(err)
					}
				case "added-record":
					createDiscoveryFixture(t, root, discoveryScope(1))
				}
				return testProtector(t), nil
			})
			if calls != 1 || infos != nil || !errors.Is(err, ErrPreRegistrationChanged) {
				t.Fatal("changed discovery inputs were silently accepted", err)
			}
		})
	}
}

func TestPreRegistrationDiscoveryRechecksEarlierClosedRecords(t *testing.T) {
	root := privateTestDir(t)
	var paths []string
	for i := 0; i < 2; i++ {
		_, path := createDiscoveryFixture(t, root, discoveryScope(i))
		paths = append(paths, path)
	}
	slices.Sort(paths)
	calls := 0
	infos, err := DiscoverPreRegistrations(root, func() (Protector, error) {
		calls++
		if calls == 2 {
			if err := os.WriteFile(paths[0], []byte("SYNTHETIC_CHANGED_AFTER_CLOSE"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return testProtector(t), nil
	})
	if calls != 2 || infos != nil || !errors.Is(err, ErrPreRegistrationChanged) {
		t.Fatal("an earlier record changed unnoticed after its private handle closed", err)
	}
}

func TestPreRegistrationDiscoveryBackendErrorsAreExplicit(t *testing.T) {
	root := privateTestDir(t)
	createDiscoveryFixture(t, root, discoveryScope(0))
	for _, failure := range []string{"unsupported", "nil", "private-error"} {
		t.Run(failure, func(t *testing.T) {
			infos, err := DiscoverPreRegistrations(root, func() (Protector, error) {
				switch failure {
				case "unsupported":
					return nil, ErrUnsupportedOS
				case "nil":
					return nil, nil
				default:
					return nil, errors.New("SYNTHETIC_PRIVATE_BACKEND_DETAIL")
				}
			})
			want := ErrInvalidVault
			if failure == "unsupported" {
				want = ErrUnsupportedOS
			}
			if infos != nil || !errors.Is(err, want) || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_BACKEND_DETAIL") {
				t.Fatal("backend failure was hidden, exported details, or triggered fallback")
			}
		})
	}
}
