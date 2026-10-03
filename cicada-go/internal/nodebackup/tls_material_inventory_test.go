package nodebackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

// These are D1-shaped SYNTHETIC byte fixtures, not usable certificates/proofs.
// Tests verify inventory, publication, fencing and locks, never TLS validity.
func syntheticTLSFloor(t *testing.T, root, hub, node string, epoch uint64) []byte {
	t.Helper()
	makePrivateDir(t, filepath.Join(root, tlsFloorName))
	proof := []byte("synthetic-activation-not-a-signed-authority")
	hash := sha256.Sum256(proof)
	f := tlsFloorWitness{Version: 1, HubID: hub, NodeID: node, Epoch: epoch, GrantDigest: strings.Repeat("a", 64), ActivationDigest: hex.EncodeToString(hash[:]), ConfigDigest: strings.Repeat("b", 64), Activation: proof}
	b, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(root, tlsFloorName, tlsScopeBucket(hub, node)+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return b
}
func syntheticTLSMaterial(t *testing.T, state, hub, node string) string {
	t.Helper()
	bucket := tlsScopeBucket(hub, node)
	base := filepath.Join(state, tlsMaterialName, bucket)
	makePrivateDir(t, filepath.Join(base, "prepared", strings.Repeat("c", 64)))
	makePrivateDir(t, filepath.Join(base, "epochs", "1-"+strings.Repeat("a", 64)))
	// Use the exact production struct's JSON field spellings and scope anchor.
	preparation := []byte(`{"Version":1,"Binding":{"Control":{"hub_id":"` + hub + `","node_id":"` + node + `"}}}`)
	p := filepath.Join(base, "prepared", strings.Repeat("c", 64))
	for name, b := range map[string][]byte{"preparation.json": preparation, "key.pem": []byte("SYNTHETIC TLS PRIVATE KEY BYTES"), "csr.pem": []byte("synthetic-csr")} {
		if err := os.WriteFile(filepath.Join(p, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	active := []byte(`{"identity":{"hub_id":"` + hub + `","node_id":"` + node + `","tls_epoch":1}}`)
	if err := os.WriteFile(filepath.Join(base, "active.json"), active, 0600); err != nil {
		t.Fatal(err)
	}
	stage := []byte(`{"Claims":{"hub_id":"` + hub + `","node_id":"` + node + `"}}`)
	if err := os.WriteFile(filepath.Join(base, "epochs", "1-"+strings.Repeat("a", 64), "stage.json"), stage, 0600); err != nil {
		t.Fatal(err)
	}
	return base
}
func tlsBackupFixture(t *testing.T) (state, writer, archive string) {
	t.Helper()
	base := t.TempDir()
	state = filepath.Join(base, "state")
	writer = filepath.Join(base, "writer")
	archive = filepath.Join(base, "archive")
	makePrivateDir(t, state)
	makePrivateDir(t, writer)
	makeNodeSubtree(t, state, "synthetic-node")
	populateSharedWriterRoot(t, writer)
	syntheticTLSMaterial(t, state, "synthetic-hub", "synthetic-node")
	syntheticTLSFloor(t, writer, "synthetic-hub", "synthetic-node", 1)
	return
}
func TestTLSBackupCapturesPrivateScopesAndWitnesses(t *testing.T) {
	state, writer, archive := tlsBackupFixture(t)
	foreign := syntheticTLSMaterial(t, state, "synthetic-hub", "other-node")
	syntheticTLSFloor(t, writer, "synthetic-hub", "other-node", 9)
	syntheticTLSMaterial(t, state, "second-hub", "synthetic-node")
	syntheticTLSFloor(t, writer, "second-hub", "synthetic-node", 2)
	before, _ := os.ReadFile(filepath.Join(nodeStatePath(state, "synthetic-node"), "identity.json"))
	report, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive)
	if err != nil {
		t.Fatal(err)
	}
	if report.Manifest.FormatVersion != TLSFormatVersion || report.Manifest.TLSMaterial == nil || len(report.Manifest.TLSMaterial.Scopes) != 2 || len(report.Manifest.TLSMaterial.Floors) != 2 {
		t.Fatal("TLS scopes/floor witnesses missing")
	}
	if _, err := Verify(archive); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(archive, manifestName))
	if bytes.Contains(raw, []byte("SYNTHETIC TLS PRIVATE KEY")) || bytes.Contains(raw, []byte("synthetic-activation-not")) {
		t.Fatal("manifest disclosed private bytes")
	}
	if _, err := os.Lstat(filepath.Join(archive, tlsPayloadName, "material", filepath.Base(foreign))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign Node TLS captured")
	}
	if err := filepath.WalkDir(archive, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		s, e := os.Lstat(p)
		if e != nil {
			return e
		}
		want := os.FileMode(0600)
		if d.IsDir() {
			want = 0700
		}
		if s.Mode().Perm() != want {
			t.Fatalf("nonprivate archive path %s", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(nodeStatePath(state, "synthetic-node"), "identity.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("application identity changed")
	}
}
func TestTLSRestoreRetainsFloorsAndRemainsQuarantined(t *testing.T) {
	for _, epoch := range []uint64{1, 3} {
		t.Run(string(rune('0'+epoch)), func(t *testing.T) {
			state, writer, archive := tlsBackupFixture(t)
			if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "state")
			targetWriter := filepath.Join(t.TempDir(), "writer")
			makePrivateDir(t, targetWriter)
			retained := syntheticTLSFloor(t, targetWriter, "synthetic-hub", "synthetic-node", epoch)
			floorPath := filepath.Join(targetWriter, tlsFloorName, tlsScopeBucket("synthetic-hub", "synthetic-node")+".json")
			beforeInfo, _ := os.Lstat(floorPath)
			r, err := RestoreWithWriterRoot(archive, target, targetWriter)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Quarantined {
				t.Fatal("restore released quarantine")
			}
			after, _ := os.ReadFile(floorPath)
			afterInfo, _ := os.Lstat(floorPath)
			if !bytes.Equal(retained, after) || !os.SameFile(beforeInfo, afterInfo) || beforeInfo.Mode() != afterInfo.Mode() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
				t.Fatal("retained floor replaced or changed")
			}
			if held, err := RecoveryQuarantineActive(target, "synthetic-node"); err != nil || !held {
				t.Fatal("Node hold absent")
			}
			if err := VerifyRecoveryLineage(archive, target, targetWriter); err != nil {
				t.Fatal(err)
			}
			inspection, err := InspectWithWriterRoot(archive, target, targetWriter)
			if err != nil {
				t.Fatal(err)
			}
			if inspection.AgentMayStart || inspection.TLSMaterialCheck != "material_and_retained_floor_checked_hub_authority_not_checked" {
				t.Fatalf("misleading inspect: %#v", inspection)
			}
			material := filepath.Join(target, tlsMaterialName, tlsScopeBucket("synthetic-hub", "synthetic-node"), "prepared", strings.Repeat("c", 64), "key.pem")
			if err := os.Remove(material); err != nil {
				t.Fatal(err)
			}
			if err := VerifyRecoveryLineage(archive, target, targetWriter); err == nil {
				t.Fatal("missing restored key accepted")
			}
			inspection, err = InspectWithWriterRoot(archive, target, targetWriter)
			if err != nil || inspection.TLSMaterialCheck != "tls_material_missing_or_changed" {
				t.Fatal("missing key not held")
			}
		})
	}
}
func TestTLSRestoreRejectsMissingLowerAndConflictingFloors(t *testing.T) {
	for _, kind := range []string{"missing-directory", "missing-file", "lower", "same-epoch-different-proof", "foreign-node", "nonprivate", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			state, writer, archive := tlsBackupFixture(t)
			syntheticTLSFloor(t, writer, "synthetic-hub", "synthetic-node", 2)
			if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "state")
			tw := filepath.Join(t.TempDir(), "writer")
			makePrivateDir(t, tw)
			fp := filepath.Join(tw, tlsFloorName, tlsScopeBucket("synthetic-hub", "synthetic-node")+".json")
			switch kind {
			case "missing-directory":
			case "missing-file":
				makePrivateDir(t, filepath.Dir(fp))
			case "lower":
				syntheticTLSFloor(t, tw, "synthetic-hub", "synthetic-node", 1)
			case "same-epoch-different-proof":
				syntheticTLSFloor(t, tw, "synthetic-hub", "synthetic-node", 2)
				b, _ := os.ReadFile(fp)
				b = bytes.ReplaceAll(b, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("d", 64)))
				if err := os.WriteFile(fp, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-node":
				syntheticTLSFloor(t, tw, "synthetic-hub", "other-node", 2)
				b, _ := os.ReadFile(filepath.Join(tw, tlsFloorName, tlsScopeBucket("synthetic-hub", "other-node")+".json"))
				if err := os.WriteFile(fp, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "nonprivate":
				syntheticTLSFloor(t, tw, "synthetic-hub", "synthetic-node", 2)
				if err := os.Chmod(fp, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				makePrivateDir(t, outside)
				syntheticTLSFloor(t, outside, "synthetic-hub", "synthetic-node", 2)
				makePrivateDir(t, filepath.Dir(fp))
				if err := os.Symlink(filepath.Join(outside, tlsFloorName, filepath.Base(fp)), fp); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(fp)
			if _, err := RestoreWithWriterRoot(archive, target, tw); !errors.Is(err, ErrTLSFencesUnavailable) {
				t.Fatalf("restore error %v", err)
			}
			after, _ := os.ReadFile(fp)
			if !bytes.Equal(before, after) {
				t.Fatal("floor changed on rejection")
			}
			if _, err := os.Lstat(nodeStatePath(target, "synthetic-node")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Node published with untrusted floor")
			}
			if kind == "missing-file" {
				if _, err := os.Lstat(fp); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing floor recreated")
				}
			}
		})
	}
}
func TestTLSInventoryRejectsUnsafeLayouts(t *testing.T) {
	for _, kind := range []string{"public-key-mode", "public-directory", "symlink", "unknown-path", "anchor-mismatch", "missing-anchor", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			state, writer, archive := tlsBackupFixture(t)
			root := filepath.Join(state, tlsMaterialName, tlsScopeBucket("synthetic-hub", "synthetic-node"))
			prep := filepath.Join(root, "prepared", strings.Repeat("c", 64))
			key := filepath.Join(prep, "key.pem")
			switch kind {
			case "public-key-mode":
				_ = os.Chmod(key, 0644)
			case "public-directory":
				_ = os.Chmod(prep, 0755)
			case "symlink":
				_ = os.Remove(key)
				_ = os.Symlink(filepath.Join(nodeStatePath(state, "synthetic-node"), "identity.json"), key)
			case "unknown-path":
				_ = os.WriteFile(filepath.Join(root, "extra.json"), []byte("synthetic"), 0600)
			case "anchor-mismatch":
				_ = os.WriteFile(filepath.Join(prep, "preparation.json"), []byte(`{"Binding":{"Control":{"hub_id":"other-hub","node_id":"synthetic-node"}}}`), 0600)
			case "missing-anchor":
				_ = os.Remove(filepath.Join(prep, "preparation.json"))
				_ = os.Remove(filepath.Join(root, "active.json"))
				_ = os.Remove(filepath.Join(root, "epochs", "1-"+strings.Repeat("a", 64), "stage.json"))
			case "oversize":
				_ = os.WriteFile(key, bytes.Repeat([]byte("x"), int(maxTLSFileBytes+1)), 0600)
			}
			if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); err == nil {
				t.Fatal("unsafe TLS state archived")
			}
			if _, err := os.Lstat(archive); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid archive published")
			}
		})
	}
}
func TestTLSArchiveTamperingRejected(t *testing.T) {
	for _, kind := range []string{"key", "extra", "floor", "mode", "version-downgrade", "scope", "anchor-rehashed"} {
		t.Run(kind, func(t *testing.T) {
			state, writer, archive := tlsBackupFixture(t)
			if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); err != nil {
				t.Fatal(err)
			}
			manifest, err := Verify(archive)
			if err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(archive, tlsPayloadName, "material", tlsScopeBucket("synthetic-hub", "synthetic-node"), "prepared", strings.Repeat("c", 64), "key.pem")
			switch kind {
			case "key":
				_ = os.WriteFile(key, []byte("different-synthetic-key"), 0600)
			case "extra":
				_ = os.WriteFile(filepath.Join(archive, tlsPayloadName, "extra"), []byte("x"), 0600)
			case "floor":
				_ = os.WriteFile(filepath.Join(archive, tlsPayloadName, "floors", manifest.TLSMaterial.Floors[0].Path), []byte("{}"), 0600)
			case "mode":
				_ = os.Chmod(key, 0644)
			case "version-downgrade":
				manifest.FormatVersion = CurrentFormatVersion
				_ = os.Remove(filepath.Join(archive, manifestName))
				if err := writePrivateJSON(filepath.Join(archive, manifestName), manifest); err != nil {
					t.Fatal(err)
				}
			case "anchor-rehashed":
				anchor := manifest.TLSMaterial.Scopes[0].Bucket + "/active.json"
				path := filepath.Join(archive, tlsPayloadName, "material", anchor)
				if err := os.WriteFile(path, []byte(`{"identity":{"hub_id":"wrong-hub","node_id":"synthetic-node"}}`), 0600); err != nil {
					t.Fatal(err)
				}
				entry, err := tlsFileEntry(filepath.Join(archive, tlsPayloadName, "material"), anchor)
				if err != nil {
					t.Fatal(err)
				}
				for i := range manifest.TLSMaterial.Files {
					if manifest.TLSMaterial.Files[i].Path == anchor {
						manifest.TLSMaterial.Files[i] = entry
					}
				}
				_ = os.Remove(filepath.Join(archive, manifestName))
				if err := writePrivateJSON(filepath.Join(archive, manifestName), manifest); err != nil {
					t.Fatal(err)
				}
			case "scope":
				manifest.TLSMaterial.Scopes[0].NodeID = "other-node"
				_ = os.Remove(filepath.Join(archive, manifestName))
				if err := writePrivateJSON(filepath.Join(archive, manifestName), manifest); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Verify(archive); err == nil {
				t.Fatal("tampered archive verified")
			}
		})
	}
}
func TestTLSBackupWithoutWriterRootRejectsOmission(t *testing.T) {
	state, _, archive := tlsBackupFixture(t)
	if _, err := Backup(state, "synthetic-node", archive); !errors.Is(err, ErrTLSFencesUnavailable) {
		t.Fatalf("silent TLS floor omission: %v", err)
	}
}
func TestTLSRestoreFailedPublicationHoldsPartialState(t *testing.T) {
	state, writer, archive := tlsBackupFixture(t)
	if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "state")
	tw := filepath.Join(t.TempDir(), "writer")
	makePrivateDir(t, tw)
	floor := syntheticTLSFloor(t, tw, "synthetic-hub", "synthetic-node", 1)
	fail := errors.New("synthetic publication failure")
	if _, err := restoreWithWriterRootPublisher(archive, target, tw, func(string, string) (bool, error) { return false, fail }); !errors.Is(err, fail) {
		t.Fatal(err)
	}
	if held, err := RecoveryQuarantineActive(target, "synthetic-node"); err != nil || !held {
		t.Fatal("TLS material survived but recovery registration removed")
	}
	key := filepath.Join(target, tlsMaterialName, tlsScopeBucket("synthetic-hub", "synthetic-node"), "prepared", strings.Repeat("c", 64), "key.pem")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreWithWriterRoot(archive, target, tw); err == nil {
		t.Fatal("retry repaired missing forward TLS material")
	}
	if _, err := os.Lstat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing key recreated")
	}
	got, _ := os.ReadFile(filepath.Join(tw, tlsFloorName, tlsScopeBucket("synthetic-hub", "synthetic-node")+".json"))
	if !bytes.Equal(got, floor) {
		t.Fatal("floor changed on interrupted restore")
	}
}
func TestTLSBackupCompetingProcess(t *testing.T) {
	// Separate OS process owns the real WriterRoot shared flock, not a mock.
	if os.Getenv("CICADA_TLS_LOCK_HELPER") == "1" {
		lock, err := nodelock.AcquireWriterRoot(os.Getenv("CICADA_TLS_LOCK_ROOT"))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		_, _ = os.Stdout.Write([]byte("LOCKED\n"))
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	state, writer, archive := tlsBackupFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestTLSBackupCompetingProcess$")
	cmd.Env = append(os.Environ(), "CICADA_TLS_LOCK_HELPER=1", "CICADA_TLS_LOCK_ROOT="+writer)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make(chan error, 1)
	go func() {
		b := make([]byte, 7)
		_, e := io.ReadFull(stdout, b)
		if e == nil && string(b) != "LOCKED\n" {
			e = errors.New("wrong lock readiness")
		}
		ready <- e
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lock child readiness timeout")
	}
	if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); !errors.Is(err, ErrBusy) {
		t.Fatalf("backup bypassed process writer lock: %v", err)
	}
	if _, err := os.Lstat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("busy backup published")
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); err != nil {
		t.Fatal("released child lock not recovered:", err)
	}
}

func TestTLSBackupMissingFloorRejectsWitnessRecreation(t *testing.T) {
	state, writer, archive := tlsBackupFixture(t)
	path := filepath.Join(writer, tlsFloorName, tlsScopeBucket("synthetic-hub", "synthetic-node")+".json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupWithWriterRoot(state, "synthetic-node", writer, archive); !errors.Is(err, ErrTLSFencesUnavailable) {
		t.Fatalf("missing source floor error %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source floor recreated")
	}
}
