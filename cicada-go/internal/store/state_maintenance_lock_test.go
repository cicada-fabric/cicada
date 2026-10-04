package store

import (
	"bufio"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gofrs/flock"
)

// The existing test executable is the only subprocess helper. Each phase is
// acknowledged through a pipe; no sleep, polling loop or product retry is used.
func TestStateMaintenanceProcessHelper(t *testing.T) {
	mode := os.Getenv("CICADA_MAINTENANCE_TEST_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("CICADA_MAINTENANCE_TEST_TARGET")
	wait := func(phase string) error {
		fmt.Println(phase)
		var b [1]byte
		_, err := io.ReadFull(os.Stdin, b[:])
		return err
	}
	switch mode {
	case "store":
		s, err := New(filepath.Join(path, stateDatabaseName))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := wait("store_locked"); err != nil {
			t.Fatal(err)
		}
	case "restore":
		_, err := RestoreStateDirWithContext(context.Background(), StateRestoreOptions{
			BackupDir: os.Getenv("CICADA_MAINTENANCE_TEST_ARCHIVE"), TargetStateDir: path,
			maintenanceHook: wait,
		})
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown synthetic helper mode")
	}
}

type maintenanceProcess struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
}

func startMaintenanceProcess(t *testing.T, mode, target, archive string) *maintenanceProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStateMaintenanceProcessHelper$")
	cmd.Env = append(os.Environ(), "CICADA_MAINTENANCE_TEST_MODE="+mode,
		"CICADA_MAINTENANCE_TEST_TARGET="+target, "CICADA_MAINTENANCE_TEST_ARCHIVE="+archive)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &maintenanceProcess{cmd: cmd, input: input, output: bufio.NewReader(output)}
	t.Cleanup(func() {
		_ = input.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return p
}

func (p *maintenanceProcess) phase(t *testing.T, expected string) {
	t.Helper()
	line, err := p.output.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != expected {
		t.Fatalf("subprocess barrier: got %q, %v; want %s", line, err, expected)
	}
}

func (p *maintenanceProcess) advance(t *testing.T) {
	t.Helper()
	if _, err := p.input.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
}

func maintenanceArchive(t *testing.T, root string) (string, string) {
	t.Helper()
	source, archive := filepath.Join(root, "source"), filepath.Join(root, "archive")
	s, err := New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupStateDir(source, archive); err != nil {
		t.Fatal(err)
	}
	return source, archive
}

func assertMaintenanceBusy(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrStateMaintenanceBusy) {
		t.Fatalf("want maintenance BUSY, got %v", err)
	}
}

func TestStateMaintenanceStoreLifetimeAndMultipleHandles(t *testing.T) {
	root := t.TempDir()
	source, _ := maintenanceArchive(t, root)
	a, err := New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	destination := filepath.Join(root, "must-not-create-parent", "backup")
	_, err = BackupStateDir(source, destination)
	assertMaintenanceBusy(t, err)
	if _, err := os.Lstat(filepath.Dir(destination)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("busy backup created destination parent")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = BackupStateDir(source, destination)
	assertMaintenanceBusy(t, err)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupStateDir(source, destination); err != nil {
		t.Fatal(err)
	}
}

func TestStateMaintenanceStartupBeforeRestoreAcrossProcesses(t *testing.T) {
	root := t.TempDir()
	source, archive := maintenanceArchive(t, root)
	p := startMaintenanceProcess(t, "store", source, "")
	p.phase(t, "store_locked")
	_, err := BackupStateDir(source, filepath.Join(root, "busy-backup"))
	assertMaintenanceBusy(t, err)
	_, err = RestoreStateDir(archive, source)
	assertMaintenanceBusy(t, err)
	p.advance(t)
	if err := p.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupStateDir(source, filepath.Join(root, "after-close-backup")); err != nil {
		t.Fatal(err)
	}

	// An absent target is first established by startup, without a database.
	target := filepath.Join(root, "new-parent", "empty-startup-target")
	lease, err := AcquireStateStartup(target)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RestoreStateDir(archive, target)
	assertMaintenanceBusy(t, err)
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("busy restore changed empty coordination target")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreStateDir(archive, target); err != nil {
		t.Fatal(err)
	}
}

func TestStateMaintenanceRestoreBeforeStartupAndInodeHandoff(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-%t", existing), func(t *testing.T) {
			root := t.TempDir()
			_, archive := maintenanceArchive(t, root)
			target := filepath.Join(root, "target")
			if existing {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			p := startMaintenanceProcess(t, "restore", target, archive)
			p.phase(t, "target_locked")
			old, err := os.Open(target)
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			oldInfo, err := old.Stat()
			if err != nil {
				t.Fatal(err)
			}
			_, err = AcquireStateStartup(target)
			assertMaintenanceBusy(t, err)
			_, err = New(filepath.Join(target, stateDatabaseName))
			assertMaintenanceBusy(t, err)
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatal("startup wrote before restore ownership")
			}
			p.advance(t)
			p.phase(t, "published_locked")
			live, err := os.Stat(target)
			if err != nil || os.SameFile(oldInfo, live) {
				t.Fatal("restore did not replace directory inode")
			}
			_, err = New(filepath.Join(target, stateDatabaseName))
			assertMaintenanceBusy(t, err)
			if _, err := AcquireStateStartup(target); !errors.Is(err, ErrStateRestoreQuarantined) {
				t.Fatalf("published startup bypassed holds: %v", err)
			}
			p.advance(t)
			if err := p.cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			// Model an opener that obtained the old descriptor before rename but
			// acquired its shared lock only after both restore leases released.
			delayed := &StateMaintenanceLease{lock: flock.New(fmt.Sprintf("/proc/self/fd/%d", old.Fd()), flock.SetFlag(os.O_RDONLY))}
			ok, err := delayed.lock.TryRLock()
			if err != nil || !ok {
				t.Fatalf("lock delayed old inode: %v", err)
			}
			defer delayed.Close()
			if err := delayed.validate(target); !errors.Is(err, ErrStateBackupPathUnsafe) {
				t.Fatalf("delayed old inode accepted: %v", err)
			}
			// Even an obsolete bind mount matching the held inode must reject
			// its zero link count, independent of pathname identity comparison.
			info, err := old.Stat()
			links, known := stateDirectoryLinks(info)
			if err != nil || !known || links != 0 {
				t.Fatal("replaced inode remains linked")
			}
			lease, err := acquireStateMaintenance(target, true, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStateMaintenanceProcessDeathRetainsBothHolds(t *testing.T) {
	root := t.TempDir()
	_, archive := maintenanceArchive(t, root)
	target := filepath.Join(root, "target")
	p := startMaintenanceProcess(t, "restore", target, archive)
	p.phase(t, "target_locked")
	p.advance(t)
	p.phase(t, "published_locked")
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Wait(); err == nil {
		t.Fatal("killed restore unexpectedly exited successfully")
	}
	lease, err := acquireStateMaintenance(target, true, false)
	if err != nil {
		t.Fatalf("dead process stranded kernel lock: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(target, stateRestoreMarker), stateRestoreRegistrationPath(target)} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("process death removed restore hold")
		}
	}
	if _, err := AcquireStateStartup(target); !errors.Is(err, ErrStateRestoreQuarantined) {
		t.Fatalf("death authorized activation: %v", err)
	}
	// The low-level Store remains available for explicit offline maintenance.
	s, err := New(filepath.Join(target, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
		t.Fatal("maintenance Store cleared quarantine")
	}
}

func TestStateMaintenanceDirectoryPolicyAndFailureCleanup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireStateMaintenance(target, true, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(filepath.Join(target, stateDatabaseName))
	assertMaintenanceBusy(t, err)
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatal("busy Store tightened directory before ownership")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(target, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("owned Store did not preserve private-directory policy")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "parent-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	lease, err = acquireStateMaintenance(target, true, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = AcquireStateStartup(filepath.Join(alias, "target"))
	assertMaintenanceBusy(t, err)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	targetAlias := filepath.Join(root, "target-alias")
	if err := os.Symlink(target, targetAlias); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(targetAlias, stateDatabaseName)); !errors.Is(err, ErrStateBackupPathUnsafe) {
		t.Fatalf("target symlink accepted: %v", err)
	}
	if err := os.Chmod(target, os.ModeSticky|0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireStateMaintenance(target, false, false); !errors.Is(err, ErrStateBackupPathUnsafe) {
		t.Fatalf("sticky directory repaired: %v", err)
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"database-directory", "invalid-database"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, stateDatabaseName)
			if kind == "database-directory" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("synthetic invalid SQLite"), 0o600); err != nil {
				t.Fatal(err)
			}
			if s, err := New(path); s != nil || err == nil {
				t.Fatal("invalid Store constructed")
			}
			lease, err := acquireStateMaintenance(dir, true, false)
			if err != nil {
				t.Fatalf("constructor failure stranded ownership: %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

var errMaintenanceTestClose = errors.New("synthetic database close failure")
var maintenanceCloseDriverOnce sync.Once

type maintenanceCloseDriver struct{}
type maintenanceCloseConnection struct{}

func (maintenanceCloseDriver) Open(string) (driver.Conn, error) {
	return maintenanceCloseConnection{}, nil
}
func (maintenanceCloseConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}
func (maintenanceCloseConnection) Begin() (driver.Tx, error) { return nil, errors.New("unused") }
func (maintenanceCloseConnection) Close() error              { return errMaintenanceTestClose }

func TestStateMaintenanceUncertainDatabaseCloseRetainsOwnership(t *testing.T) {
	maintenanceCloseDriverOnce.Do(func() { sql.Register("cicada-maintenance-close-error", maintenanceCloseDriver{}) })
	db, err := sql.Open("cicada-maintenance-close-error", "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lease, err := acquireStateMaintenance(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	s := &Store{db: db, maintenance: lease}
	for i := 0; i < 2; i++ {
		if err := s.Close(); !errors.Is(err, errMaintenanceTestClose) {
			t.Fatalf("close failure lost: %v", err)
		}
		_, err := acquireStateMaintenance(dir, true, false)
		assertMaintenanceBusy(t, err)
	}
}

func TestStateMaintenanceRestoreFailureCleanup(t *testing.T) {
	for _, phase := range []string{"target_locked", "published_locked"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			_, archive := maintenanceArchive(t, root)
			target := filepath.Join(root, "target")
			injected := errors.New("synthetic restore boundary failure")
			_, err := RestoreStateDirWithContext(context.Background(), StateRestoreOptions{
				BackupDir: archive, TargetStateDir: target,
				maintenanceHook: func(current string) error {
					if current == phase {
						return injected
					}
					return nil
				},
			})
			if !errors.Is(err, injected) {
				t.Fatalf("restore failure not observed: %v", err)
			}
			lease, err := acquireStateMaintenance(target, true, false)
			if err != nil {
				t.Fatalf("failed restore stranded ownership: %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			staging, err := filepath.Glob(target + ".restore-*")
			if err != nil || len(staging) != 0 {
				t.Fatal("failed restore retained unpublished staging payload")
			}
			if phase == "target_locked" {
				entries, err := os.ReadDir(target)
				if err != nil || len(entries) != 0 {
					t.Fatal("failed pre-copy restore changed empty target")
				}
			} else {
				for _, path := range []string{filepath.Join(target, stateRestoreMarker), stateRestoreRegistrationPath(target), filepath.Join(target, stateDatabaseName)} {
					if _, err := os.Stat(path); err != nil {
						t.Fatal("failed post-publication restore removed data or a hold")
					}
				}
				if err := RequireStateRestoreStartupAllowed(target); !errors.Is(err, ErrStateRestoreQuarantined) {
					t.Fatal("failed publication boundary activated target")
				}
			}
		})
	}
	if os.Geteuid() == 0 {
		t.Skip("permission failure test requires non-root execution")
	}
	root := t.TempDir()
	_, archive := maintenanceArchive(t, root)
	parent := filepath.Join(root, "unwritable-parent")
	target := filepath.Join(parent, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if _, err := RestoreStateDir(archive, target); err == nil {
		t.Fatal("restore published through unwritable parent")
	}
	lease, err := acquireStateMaintenance(target, true, false)
	if err != nil {
		t.Fatalf("staging creation failure stranded ownership: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed staging creation changed target")
	}
}

func TestStateMaintenanceNonrootBindMountAliases(t *testing.T) {
	a, b := os.Getenv("CICADA_MAINTENANCE_MOUNT_A"), os.Getenv("CICADA_MAINTENANCE_MOUNT_B")
	if a == "" || b == "" {
		t.Skip("two disposable bind mounts not supplied")
	}
	if os.Geteuid() == 0 {
		t.Fatal("bind-mount acceptance requires the non-root Hub UID")
	}
	ai, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := os.Stat(b)
	if err != nil || !os.SameFile(ai, bi) {
		t.Fatal("fixture paths do not mount the same backing directory")
	}
	if filepath.Dir(a) != "/" || filepath.Dir(b) != "/" {
		t.Fatal("fixture must use the default unwritable root parent")
	}
	lease, err := acquireStateMaintenance(a, true, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(filepath.Join(b, stateDatabaseName))
	assertMaintenanceBusy(t, err)
	if _, err := os.Stat(filepath.Join(b, stateDatabaseName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("busy alias created database")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(b, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t.Cleanup(func() {
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			_ = os.Remove(filepath.Join(b, stateDatabaseName) + suffix)
		}
	})
	_, err = acquireStateMaintenance(a, true, false)
	assertMaintenanceBusy(t, err)
	startup, err := AcquireStateStartup(a)
	if err != nil {
		t.Fatalf("ordinary non-root startup requires parent write: %v", err)
	}
	if err := startup.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	lease, err = acquireStateMaintenance(a, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}
