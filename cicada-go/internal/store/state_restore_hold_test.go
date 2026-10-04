package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestStateRestoreHoldPreservesArchivedWatermarkAfterSourceAdvances(t *testing.T) {
	root := t.TempDir()
	source, archive, target := filepath.Join(root, "source"), filepath.Join(root, "archive"), filepath.Join(root, "target")
	db, err := New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	contact, err := db.CreateContact(Contact{ID: "synthetic-restored-peer", Identity: remote.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := db.AllocateContactSequence(contact.ID); err != nil || n != 1 {
		t.Fatal("initial sequence")
	}
	session := PeerSession{ContactID: contact.ID, Epoch: 4, RootKey: bytesForBackupTest(32, 0x11), SendChainKey: bytesForBackupTest(32, 0x22), ReceiveChainKey: bytesForBackupTest(32, 0x33), SendCount: 8, ReceiveCount: 13}
	if err := db.SavePeerSession(session); err != nil {
		t.Fatal(err)
	}
	if err := db.AcceptContactSequence(contact.ID, 77); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := remote.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, "e2ee"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "e2ee", "identity.json"), identity, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BackupStateDir(source, archive)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Contacts.SendCountTotal != 8 || manifest.Contacts.ReceiveCountTotal != 13 || manifest.Contacts.ReplaySequences != 1 {
		t.Fatal("archive crypto watermark")
	}
	if manifest.Contacts.SendSequenceTotal != 1 {
		t.Fatal("archive watermark")
	}
	db, err = New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := db.AllocateContactSequence(contact.ID); err != nil || n != 2 {
		t.Fatal("source did not advance")
	}
	session.SendCount = 9
	if err := db.SavePeerSession(session); err != nil {
		t.Fatal(err)
	}
	if err := db.AcceptContactSequence(contact.ID, 88); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	sourceBefore, err := hashFile(context.Background(), filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	report, err := RestoreStateDir(archive, target)
	if err != nil || !report.Verified {
		t.Fatalf("restore integrity: %v", err)
	}
	if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
		t.Fatal("restored archive became startable")
	}
	_, restored, err := inspectSQLiteSnapshot(nil, filepath.Join(target, stateDatabaseName))
	if err != nil || restored.SendSequenceTotal != 1 || restored.SendCountTotal != 8 || restored.ReceiveCountTotal != 13 || restored.ReplaySequences != 1 {
		t.Fatalf("offline archived watermark: %v", err)
	}
	_, current, err := inspectSQLiteSnapshot(nil, filepath.Join(source, stateDatabaseName))
	if err != nil || current.SendSequenceTotal != 2 || current.SendCountTotal != 9 || current.ReplaySequences != 2 {
		t.Fatalf("original watermark changed: %v", err)
	}
	sourceAfter, err := hashFile(context.Background(), filepath.Join(source, stateDatabaseName))
	if err != nil || sourceBefore != sourceAfter {
		t.Fatal("restore modified original database")
	}
	for _, file := range manifest.Files {
		digest, err := hashFile(context.Background(), filepath.Join(target, filepath.FromSlash(file.Path)))
		if err != nil || digest != file.SHA256 {
			t.Fatal("archived payload bytes changed")
		}
	}
	if _, err := VerifyStateBackup(archive); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupStateDir(target, filepath.Join(root, "held-backup")); !errors.Is(err, ErrStateRestoreQuarantined) {
		t.Fatal("held backup was not rejected")
	}
}

func TestStateRestoreHoldPairedMarkersAndAliases(t *testing.T) {
	for _, mutation := range []string{"paired", "missing-marker", "missing-registration", "corrupt-marker", "corrupt-registration", "marker-symlink", "registration-symlink"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			staging := filepath.Join(root, "staging")
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := registerStateRestoreHold(staging, target, &StateBackupManifest{}); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(staging, target); err != nil {
				t.Fatal(err)
			}
			marker, registration := filepath.Join(target, stateRestoreMarker), stateRestoreRegistrationPath(target)
			switch mutation {
			case "missing-marker":
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			case "missing-registration":
				if err := os.Remove(registration); err != nil {
					t.Fatal(err)
				}
			case "corrupt-marker":
				if err := os.WriteFile(marker, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-registration":
				if err := os.WriteFile(registration, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "marker-symlink", "registration-symlink":
				path := marker
				if mutation == "registration-symlink" {
					path = registration
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "missing"), path); err != nil {
					t.Fatal(err)
				}
			}
			if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
				t.Fatal("damaged pair allowed startup")
			}
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			if err := RequireStateRestoreStartupAllowed(filepath.Join(alias, "target")); !errors.Is(err, ErrStateRestoreQuarantined) {
				t.Fatal("parent alias bypassed hold")
			}
			if err := RequireStateRestoreStartupAllowed(filepath.Join(root, "ordinary")); err != nil {
				t.Fatalf("foreign target held: %v", err)
			}
		})
	}
}

func TestStateRestoreHoldBeforePublicationAndInspectionFailures(t *testing.T) {
	root := t.TempDir()
	target, staging := filepath.Join(root, "target"), filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := registerStateRestoreHold(staging, target, &StateBackupManifest{}); err != nil {
		t.Fatal(err)
	}
	if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
		t.Fatal("pre-publication registration did not hold")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("registration published target data")
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("ordinary target"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetLease, err := acquireStateMaintenance(target, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer targetLease.Close()
	stagingLease, err := acquireStateMaintenance(staging, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stagingLease.Close()
	if err := installRestoreTarget(staging, target, targetLease, stagingLease); !errors.Is(err, ErrStateRestoreTargetNotEmpty) {
		t.Fatal("publication replaced nonempty target")
	}
	if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
		t.Fatal("failed publication removed hold")
	}
	for _, kind := range []string{"registry-file", "registry-symlink", "registry-public", "target-symlink", "parent-file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			registry := filepath.Join(root, stateRestoreRegistry)
			switch kind {
			case "registry-file":
				if err := os.WriteFile(registry, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "registry-symlink":
				if err := os.Symlink(t.TempDir(), registry); err != nil {
					t.Fatal(err)
				}
			case "registry-public":
				if err := os.Mkdir(registry, 0o755); err != nil {
					t.Fatal(err)
				}
			case "target-symlink":
				if err := os.Symlink(t.TempDir(), target); err != nil {
					t.Fatal(err)
				}
			case "parent-file":
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(target, "child")
			}
			if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
				t.Fatal("unsafe namespace allowed startup")
			}
		})
	}
}

func TestStateRestoreHoldRejectsReservedArchivePaths(t *testing.T) {
	for _, path := range []string{stateRestoreMarker, stateRestoreMarker + "/nested.json", stateRestoreRegistry, stateRestoreRegistry + "/registration.json"} {
		files := []StateBackupFile{{Path: stateDatabaseName, Mode: 0o600, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, {Path: path, Mode: 0o600, SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
		if err := validateManifestFiles(files); !errors.Is(err, ErrStateBackupPathUnsafe) {
			t.Fatalf("reserved path accepted: %s", path)
		}
	}
}
