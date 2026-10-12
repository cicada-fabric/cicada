package store

import (
	"errors"
	"os"
)

// NewForOfflineMaintenance opens only an existing Hub database while retaining
// the StateDir's exclusive inode lease until SQLite closes. Live Store and Hub
// startup readers cannot coexist with this operator. All normal migrations,
// authority Guard and restore quarantine checks still apply.
func NewForOfflineMaintenance(path string) (*Store, error) {
	dir, err := stateMaintenanceSQLiteDir(path)
	if err != nil {
		return nil, err
	}
	if err := RequireStateRestoreStartupAllowed(dir); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("offline maintenance requires an existing regular Hub database")
	}
	return newWithMaintenanceMode(path, true)
}
