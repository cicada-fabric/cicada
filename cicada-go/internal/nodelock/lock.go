// Package nodelock coordinates the Node Agent, Node-local writers, and offline
// maintenance tools across processes. Lock files live outside each Node state
// subtree so they are not part of a Node backup.
package nodelock

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gofrs/flock"
)

var (
	// ErrBusy means a live Agent or writer currently holds the shared
	// maintenance lock, so offline maintenance cannot safely proceed.
	ErrBusy = errors.New("Node state is busy")
	// ErrAgentRunning means another Agent already owns the Node singleton lock.
	ErrAgentRunning = errors.New("Node Agent is already running")
)

const (
	lockDirectoryName = ".locks"
	maintenanceSuffix = ".maintenance.lock"
	agentSuffix       = ".agent.lock"
)

// Lock represents one held Node maintenance lock. Close releases the shared
// lock returned to writers or the exclusive lock returned to offline tools.
type Lock struct {
	file *flock.Flock
	once sync.Once
	err  error
}

// AgentLock holds the shared maintenance lock for the Agent's full lifetime
// and an exclusive per-Node singleton lock. Close releases both locks.
type AgentLock struct {
	maintenance *Lock
	instance    *Lock
	once        sync.Once
	err         error
}

// AcquireAgent protects the Node subtree for the Agent lifetime and rejects a
// second Agent. It does not create the Node subtree or touch its credentials.
func AcquireAgent(stateDir, nodeID string) (*AgentLock, error) {
	maintenance, err := acquireShared(stateDir, nodeID)
	if err != nil {
		return nil, err
	}
	instance, err := acquireExclusiveLock(stateDir, nodeID, agentSuffix, ErrAgentRunning)
	if err != nil {
		_ = maintenance.Close()
		return nil, err
	}
	return &AgentLock{maintenance: maintenance, instance: instance}, nil
}

// AcquireMaintenance acquires a shared lock for a direct Node-subtree writer.
// It may coexist with the live Agent and other writers, but excludes offline
// maintenance.
func AcquireMaintenance(stateDir, nodeID string) (*Lock, error) {
	return acquireShared(stateDir, nodeID)
}

// AcquireMaintenanceExclusive attempts to exclude the Agent and every direct
// writer. It fails immediately with ErrBusy when any shared lock is held.
func AcquireMaintenanceExclusive(stateDir, nodeID string) (*Lock, error) {
	return acquireExclusiveLock(stateDir, nodeID, maintenanceSuffix, ErrBusy)
}

// Close releases the Agent singleton first and then its maintenance lock. Lock
// files remain in place: removing a locked file could let another process lock
// a different inode at the same path.
func (a *AgentLock) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		var instanceErr, maintenanceErr error
		if a.instance != nil {
			instanceErr = a.instance.Close()
		}
		if a.maintenance != nil {
			maintenanceErr = a.maintenance.Close()
		}
		a.err = errors.Join(instanceErr, maintenanceErr)
	})
	return a.err
}

// Close releases a maintenance lock. It is safe to call more than once.
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.once.Do(func() {
		l.err = l.file.Unlock()
	})
	return l.err
}

func acquireShared(stateDir, nodeID string) (*Lock, error) {
	path, err := lockPath(stateDir, nodeID, maintenanceSuffix)
	if err != nil {
		return nil, err
	}
	if err := prepareLockFile(path); err != nil {
		return nil, err
	}
	file := flock.New(path, flock.SetPermissions(0o600))
	if err := file.RLock(); err != nil {
		return nil, fmt.Errorf("lock Node maintenance state: %w", err)
	}
	if err := protectLockFile(path); err != nil {
		_ = file.Unlock()
		return nil, err
	}
	return &Lock{file: file}, nil
}

func acquireExclusiveLock(stateDir, nodeID, suffix string, busyErr error) (*Lock, error) {
	path, err := lockPath(stateDir, nodeID, suffix)
	if err != nil {
		return nil, err
	}
	if err := prepareLockFile(path); err != nil {
		return nil, err
	}
	file := flock.New(path, flock.SetPermissions(0o600))
	locked, err := file.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock Node state: %w", err)
	}
	if !locked {
		return nil, busyErr
	}
	if err := protectLockFile(path); err != nil {
		_ = file.Unlock()
		return nil, err
	}
	return &Lock{file: file}, nil
}

// lockPath places lock files beside, rather than inside, nodes/node-{id}. The
// URL escaping matches machineNodeStateDir's on-disk Node ID component.
func lockPath(stateDir, nodeID, suffix string) (string, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" || strings.TrimSpace(nodeID) == "" {
		return "", errors.New("Node state directory and Node ID are required for locking")
	}
	if strings.TrimSpace(nodeID) != nodeID {
		return "", errors.New("Node ID must be canonical when locking state")
	}
	root, err := filepath.Abs(filepath.Clean(stateDir))
	if err != nil {
		return "", fmt.Errorf("resolve Node state directory: %w", err)
	}
	nodesDir := filepath.Join(root, "nodes")
	if err := os.MkdirAll(nodesDir, 0o700); err != nil {
		return "", fmt.Errorf("create Node lock parent: %w", err)
	}
	nodesInfo, err := os.Lstat(nodesDir)
	if err != nil {
		return "", fmt.Errorf("inspect Node state parent: %w", err)
	}
	if nodesInfo.Mode()&os.ModeSymlink != 0 || !nodesInfo.IsDir() {
		return "", errors.New("Node state parent must be a real directory")
	}
	lockDir := filepath.Join(nodesDir, lockDirectoryName)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return "", fmt.Errorf("create Node lock directory: %w", err)
	}
	if err := protectDirectory(lockDir); err != nil {
		return "", err
	}
	// Resolve aliases through symlinked state roots so equivalent paths share
	// the same advisory lock. This does not resolve a Node subtree that restore
	// has not published yet because the lock directory lives beside it.
	canonicalLockDir, err := filepath.EvalSymlinks(lockDir)
	if err != nil {
		return "", fmt.Errorf("resolve Node lock directory: %w", err)
	}
	if err := protectDirectory(canonicalLockDir); err != nil {
		return "", err
	}
	name := "node-" + url.PathEscape(nodeID) + suffix
	return filepath.Join(canonicalLockDir, name), nil
}

func protectDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Node lock directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Node lock directory must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect Node lock directory: %w", err)
	}
	return nil
}

func protectLockFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Node lock file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("Node lock file must be a regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect Node lock file: %w", err)
	}
	return nil
}

func prepareLockFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("close Node lock file: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create Node lock file: %w", err)
	}
	return protectLockFile(path)
}

// AcquireMaintenanceExclusiveExisting excludes Node writers without creating or
// repairing lock state. Inspection requires the private lock namespace already
// established by a writer or restore, including through StateDir aliases.
func AcquireMaintenanceExclusiveExisting(stateDir, nodeID string) (*Lock, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" || strings.TrimSpace(nodeID) == "" || strings.TrimSpace(nodeID) != nodeID {
		return nil, errors.New("canonical Node state directory and Node ID are required for locking")
	}
	root, err := filepath.Abs(filepath.Clean(stateDir))
	if err != nil {
		return nil, fmt.Errorf("resolve Node state directory: %w", err)
	}
	nodesDir := filepath.Join(root, "nodes")
	if err := requireExistingPrivateDirectory(nodesDir); err != nil {
		return nil, err
	}
	lockDir := filepath.Join(nodesDir, lockDirectoryName)
	if err := requireExistingPrivateDirectory(lockDir); err != nil {
		return nil, err
	}
	canonicalLockDir, err := filepath.EvalSymlinks(lockDir)
	if err != nil {
		return nil, fmt.Errorf("resolve existing Node lock directory: %w", err)
	}
	if err := requireExistingPrivateDirectory(canonicalLockDir); err != nil {
		return nil, err
	}
	path := filepath.Join(canonicalLockDir, "node-"+url.PathEscape(nodeID)+maintenanceSuffix)
	before, err := existingPrivateLockInfo(path)
	if err != nil {
		return nil, err
	}
	return acquireExistingExclusiveLock(path, before)
}

func requireExistingPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect existing lock directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("existing lock directory must be real and private")
	}
	return nil
}

func existingPrivateLockInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect existing lock file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("existing lock file must be regular and private")
	}
	return info, nil
}

func acquireExistingExclusiveLock(path string, before os.FileInfo) (*Lock, error) {
	// SetFlag overrides flock's default O_CREATE. No inspection path repairs
	// permissions, truncates a file or creates a missing lock.
	file := flock.New(path, flock.SetFlag(os.O_RDWR))
	locked, err := file.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock existing maintenance state: %w", err)
	}
	if !locked {
		return nil, ErrBusy
	}
	if err := verifyExistingLockedFile(path, before, file); err != nil {
		return nil, errors.Join(err, file.Unlock())
	}
	return &Lock{file: file}, nil
}

func verifyExistingLockedFile(path string, before os.FileInfo, file *flock.Flock) error {
	// Stat uses the held descriptor, not a second open of the pathname. Both
	// the original observation and the current pathname must name that inode.
	held, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect held maintenance lock: %w", err)
	}
	current, err := existingPrivateLockInfo(path)
	if err != nil {
		return err
	}
	if !held.Mode().IsRegular() || held.Mode().Perm()&0o077 != 0 ||
		!os.SameFile(before, held) || !os.SameFile(held, current) {
		return errors.New("existing maintenance lock inode changed")
	}
	return nil
}
