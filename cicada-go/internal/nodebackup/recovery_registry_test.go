package nodebackup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryLineageRejectsChangedHoldsWithoutNormalization(t *testing.T) {
	for _, fault := range []string{"registry-content", "registry-parent-mode", "legacy-node", "legacy-digest", "missing-shared-hold"} {
		t.Run(fault, func(t *testing.T) {
			archive := createMinimalNodeBackup(t, "synthetic-lineage")
			root := filepath.Join(t.TempDir(), "restored")
			if _, err := RestoreWithWriterRoot(archive, root, root); err != nil {
				t.Fatal(err)
			}
			if err := VerifyRecoveryLineage(archive, root, root); err != nil {
				t.Fatal(err)
			}
			path := recoveryRegistrationPath(root, "synthetic-lineage")
			switch fault {
			case "registry-content":
				if err := os.WriteFile(path, []byte("synthetic transplanted registry"), 0600); err != nil {
					t.Fatal(err)
				}
			case "registry-parent-mode":
				path = filepath.Dir(path)
				if err := os.Chmod(path, 0500); err != nil {
					t.Fatal(err)
				}
				fixtureParent := path
				// Restore fixture cleanup permissions only after the rejection and
				// original raw-mode assertions; validation must not normalize it.
				t.Cleanup(func() {
					if err := os.Chmod(fixtureParent, 0700); err != nil {
						t.Errorf("restore disposable fixture cleanup permissions: %v", err)
					}
				})
			case "legacy-node", "legacy-digest":
				path = filepath.Join(root, sharedWriterRootMarkerName)
				marker, present, err := readSharedWriterRecoveryMarker(path)
				if err != nil || !present {
					t.Fatal(err)
				}
				if fault == "legacy-node" {
					marker.NodeID = "synthetic-other"
				} else {
					marker.BackupManifestSHA256 = strings.Repeat("a", 64)
				}
				data, _ := json.Marshal(marker)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-shared-hold":
				path = filepath.Join(root, sharedWriterRootMarkerName)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			before, statErr := os.Lstat(path)
			var raw []byte
			if statErr == nil && before.Mode().IsRegular() {
				raw, _ = os.ReadFile(path)
			}
			if err := VerifyRecoveryLineage(archive, root, root); err == nil {
				t.Fatal("changed recovery lineage accepted")
			}
			after, err := os.Lstat(path)
			if statErr != nil {
				if !os.IsNotExist(err) {
					t.Fatal("missing hold recreated")
				}
			} else if err != nil || before.Mode() != after.Mode() {
				t.Fatal("hold raw mode normalized")
			}
			if raw != nil {
				data, _ := os.ReadFile(path)
				if string(raw) != string(data) {
					t.Fatal("hold bytes rewritten")
				}
			}
		})
	}
}
