package store

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func nativeTLSStoreFixture(t *testing.T) (*Store, string, *HubOwnerSetup, *hubtransport.Profile) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "SYNTHETIC-native-Hub")
	s, err := New(filepath.Join(root, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	hub, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	origin, err := hubtransport.DefaultOrigin(hub)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := s.InitializeHubOwnerLocal("SYNTHETIC TLS owner", origin, false)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(root, "")
	if err != nil {
		t.Fatal(err)
	}
	identity := wire.HubIdentity{Contract: "android-hub-v1", HubID: hub, Public: ids.ClientControl.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	p, err := hubtransport.InitializeProfile(root, ids.ClientControl, identity, ids.NodeControl.Public(), origin, "")
	if err != nil {
		t.Fatal(err)
	}
	return s, root, setup, p
}

func TestHubNativeTLSPinIsPermanentAndDoesNotGrantOwnerAuthority(t *testing.T) {
	s, root, before, p := nativeTLSStoreFixture(t)
	if got, err := s.HubNativeTLSDescriptor(); err != nil || got != "" {
		t.Fatal("pin appeared before local commit")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.BindHubNativeTLSLocal(p.DescriptorText()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	after, err := s.GetHubOwnerSetup()
	if err != nil || !reflect.DeepEqual(before, after) || after.RootEverEstablished {
		t.Fatal("TLS changed Owner/account scope or Root")
	}
	for _, statement := range []string{`DELETE FROM hub_native_tls_v1`, `UPDATE hub_native_tls_v1 SET descriptor_text='wrong'`} {
		if _, err := s.db.Exec(statement); err == nil {
			t.Fatal("TLS pin history mutable")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(filepath.Join(root, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.HubNativeTLSDescriptor()
	if err != nil || got != p.DescriptorText() {
		t.Fatal("pin lost across restart")
	}
	if err = os.Remove(filepath.Join(root, "native-tls", "profile.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = hubtransport.LoadProfile(root, got); err == nil {
		t.Fatal("missing bundle loaded")
	}
	if still, err := reopened.HubNativeTLSDescriptor(); err != nil || still != got {
		t.Fatal("bundle loss reopened initialization")
	}
}

func TestHubNativeTLSBackupPreservesPinAndBundleButRestoreStaysHeld(t *testing.T) {
	s, source, _, p := nativeTLSStoreFixture(t)
	if err := s.BindHubNativeTLSLocal(p.DescriptorText()); err != nil {
		t.Fatal(err)
	}
	// Exercise the retained empty-v68 restore boundary with real historical
	// DDL. Current v70 coverage stays unsupported in its separate test.
	dropSyntheticAppNodeScopedMigration70(t, s)
	objects := endpointGroupsSchemaObjects()
	for i := len(objects) - 1; i >= 0; i-- {
		dropSyntheticMigrationObject(t, s.db, objects[i])
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations_v2 WHERE version=69`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(source, "native-tls", "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	backup := filepath.Join(filepath.Dir(source), "SYNTHETIC-native-backup")
	if _, err = BackupStateDir(source, backup); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(source), "SYNTHETIC-native-restored")
	if _, err = RestoreStateDir(backup, target); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(target, "native-tls", "profile.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("native private bundle omitted or changed")
	}
	clear(after)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(target, stateDatabaseName)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var pinned string
	if err = db.QueryRow(`SELECT descriptor_text FROM hub_native_tls_v1 WHERE id=1`).Scan(&pinned); err != nil || pinned != p.DescriptorText() {
		t.Fatal("native permanent pin lost")
	}
	if lease, err := AcquireStateStartup(target); !errors.Is(err, ErrStateRestoreQuarantined) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("unproved native restore gained startup authority")
	}
	if _, err = InspectHubRestoreCheckpointReadOnly(source); err != nil {
		t.Fatal("public pin with no Node pairing state failed legacy restore coverage", err)
	}
}
