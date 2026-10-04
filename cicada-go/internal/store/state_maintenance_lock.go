package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/gofrs/flock"
)

var ErrStateMaintenanceBusy = errors.New("Hub StateDir is busy with startup, a writable Store or offline maintenance")

// StateMaintenanceLease owns a lock on the directory inode, rather than a
// sibling file. A non-root Hub needs access only to its StateDir, and bind
// mounts of the same directory contend on the same kernel lock. A lease is
// mutual exclusion, never permission to release restore quarantine.
type StateMaintenanceLease struct {
	lock *flock.Flock
}

// AcquireStateStartup checks both restore holds before creating anything, then
// checks again while sharing directory ownership. Callers must overlap this
// lease with Store.New, and retain ownership around all outside-Store writes.
func AcquireStateStartup(stateDir string) (*StateMaintenanceLease, error) {
	if err := RequireStateRestoreStartupAllowed(stateDir); err != nil {
		return nil, err
	}
	lease, err := acquireStateMaintenance(stateDir, false, true)
	if err != nil {
		return nil, err
	}
	if err := RequireStateRestoreStartupAllowed(stateDir); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	return lease, nil
}

func acquireStateMaintenance(stateDir string, exclusive, create bool) (*StateMaintenanceLease, error) {
	path, err := canonicalRestoreTarget(stateDir)
	if err != nil {
		return nil, err
	}
	if create {
		// Concurrent creators converge on one empty inode. Never remove this
		// directory on failure: another opener may already own it.
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create StateDir coordination directory: %w", err)
		}
	}
	lease := &StateMaintenanceLease{lock: flock.New(path, flock.SetFlag(os.O_RDONLY))}
	var acquired bool
	if exclusive {
		acquired, err = lease.lock.TryLock()
	} else {
		acquired, err = lease.lock.TryRLock()
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("lock Hub StateDir directory: %w", err), lease.Close())
	}
	if !acquired {
		return nil, errors.Join(ErrStateMaintenanceBusy, lease.Close())
	}
	if err := lease.validate(path); err != nil {
		return nil, errors.Join(err, lease.Close())
	}
	return lease, nil
}

// validate rejects a delayed opener of a replaced inode, including an obsolete
// bind-mounted empty target. Unknown ownership/link metadata fails closed.
func (l *StateMaintenanceLease) validate(path string) error {
	if l == nil || l.lock == nil || (!l.lock.Locked() && !l.lock.RLocked()) {
		return ErrStateBackupPathUnsafe
	}
	held, err := l.lock.Stat()
	if err != nil {
		return fmt.Errorf("inspect held StateDir directory: %w", err)
	}
	links, ok := stateDirectoryLinks(held)
	if !ok || links == 0 || !stateMaintenanceDirectory(held) {
		return ErrStateBackupPathUnsafe
	}
	canonical, err := canonicalRestoreTarget(path)
	if err != nil {
		return err
	}
	live, err := os.Lstat(canonical)
	if err != nil || !stateMaintenanceDirectory(live) || !os.SameFile(held, live) {
		return ErrStateBackupPathUnsafe
	}
	return nil
}

func stateMaintenanceDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSticky) != 0 {
		return false
	}
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	uid := v.Elem().FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(os.Geteuid())
}

func stateDirectoryLinks(info os.FileInfo) (uint64, bool) {
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return 0, false
	}
	links := v.Elem().FieldByName("Nlink")
	if !links.IsValid() || !links.CanUint() {
		return 0, false
	}
	return links.Uint(), true
}

func validateStateMaintenanceHandoff(old, replacement *StateMaintenanceLease, target string) error {
	if err := replacement.validate(target); err != nil {
		return err
	}
	oldInfo, err := old.lock.Stat()
	if err != nil {
		return err
	}
	newInfo, err := replacement.lock.Stat()
	if err != nil {
		return err
	}
	links, ok := stateDirectoryLinks(oldInfo)
	if !ok || links != 0 || os.SameFile(oldInfo, newInfo) {
		return ErrStateBackupPathUnsafe
	}
	return nil
}

// Close releases only ownership. It never removes a directory or either hold.
func (l *StateMaintenanceLease) Close() error {
	if l == nil || l.lock == nil {
		return nil
	}
	return l.lock.Close()
}

func stateMaintenanceSQLiteDir(path string) (string, error) {
	if path == "" || path == ":memory:" {
		return "", errors.New("SQLite state requires a private file path")
	}
	dir := filepath.Clean(filepath.Dir(path))
	if dir == "." || dir == ".." || dir == string(filepath.Separator) {
		return "", errors.New("SQLite state requires a dedicated directory")
	}
	return dir, nil
}
