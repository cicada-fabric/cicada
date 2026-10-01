//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

func machineAgentJoinSocketPlatformPathMaxBytes() int {
	// Linux sockaddr_un.sun_path has 108 bytes including the trailing NUL;
	// Darwin has 104. Keep the historical Linux path limit and use the stricter
	// platform limit where required.
	if runtime.GOOS == "linux" {
		return 107
	}
	return 103
}

func machineAgentJoinSocketTempRootPath() string {
	// On macOS /tmp is a symlink to /private/tmp. Use its canonical target so
	// the private socket directory itself can be checked with Lstat.
	if runtime.GOOS == "darwin" {
		return "/private/tmp"
	}
	return "/tmp"
}

func machineAgentJoinSocketCurrentUID() (uint32, error) {
	uid := os.Geteuid()
	if uid < 0 {
		return 0, errors.New("could not identify the local Node socket owner")
	}
	return uint32(uid), nil
}

func machineAgentJoinSocketRuntimeDirectory() (string, error) {
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return "", err
	}
	return machineAgentJoinSocketRuntimeDirectoryForUID(uid), nil
}

func machineAgentJoinSocketRuntimeDirectoryForUID(uid uint32) string {
	return filepath.Join(machineAgentJoinSocketTempRootPath(), machineAgentJoinSocketRuntimeDirPrefix+strconv.FormatUint(uint64(uid), 10))
}

func machineAgentJoinSocketOwner(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func validateMachineAgentJoinSocketPrivateDirectory(path string, expectedUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	uid, ok := machineAgentJoinSocketOwner(info)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !ok || uid != expectedUID ||
		info.Mode().Perm() != 0o700 {
		return errors.New("local Node Join socket directory is not private to this user")
	}
	return nil
}

func validateMachineAgentJoinSocketTempRoot() error {
	root := machineAgentJoinSocketTempRootPath()
	info, err := os.Lstat(root)
	if err != nil {
		return errors.New("private local Node Join runtime directory is unavailable")
	}
	uid, ok := machineAgentJoinSocketOwner(info)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !ok || uid != 0 || info.Mode()&os.ModeSticky == 0 {
		return errors.New("private local Node Join runtime directory is unsafe")
	}
	return nil
}

func prepareMachineAgentJoinSocketRuntimeDirectory(path string) error {
	runtimeDir, err := machineAgentJoinSocketRuntimeDirectory()
	if err != nil || filepath.Clean(filepath.Dir(path)) != runtimeDir ||
		len([]byte(path)) > machineAgentJoinSocketMaxPathBytes() {
		return errors.New("local Node Join socket path is invalid")
	}
	if err := validateMachineAgentJoinSocketTempRoot(); err != nil {
		return err
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return err
	}
	if err := os.Mkdir(runtimeDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create private local Node Join runtime directory: %w", err)
	}
	if err := validateMachineAgentJoinSocketPrivateDirectory(runtimeDir, uid); err != nil {
		return err
	}
	return nil
}

func prepareMachineAgentJoinSocketDirectory(path string) error {
	if machineAgentJoinSocketUsesPrivateRuntime(path) {
		return prepareMachineAgentJoinSocketRuntimeDirectory(path)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create local Node socket directory: %w", err)
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return err
	}
	if err := validateMachineAgentJoinSocketPrivateDirectory(directory, uid); err != nil {
		return err
	}
	return nil
}

func validateMachineAgentJoinSocketForDial(path string) error {
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return err
	}
	return validateMachineAgentJoinSocketForDialAs(path, uid)
}

func validateMachineAgentJoinSocketForDialAs(path string, expectedUID uint32) error {
	if len([]byte(path)) > machineAgentJoinSocketMaxPathBytes() {
		return errors.New("local Node Join socket path exceeds the platform limit")
	}
	if machineAgentJoinSocketUsesPrivateRuntime(path) {
		if err := validateMachineAgentJoinSocketTempRoot(); err != nil {
			return err
		}
	}
	if err := validateMachineAgentJoinSocketPrivateDirectory(filepath.Dir(path), expectedUID); err != nil {
		return err
	}
	_, err := machineAgentJoinSocketEntry(path, expectedUID, true)
	return err
}

// machineAgentJoinSocketEntry reads the exact socket entry without following
// symlinks. requirePrivate is used before dialing; stale cleanup accepts any
// mode but still insists on a same-owner Unix socket in a private directory.
func machineAgentJoinSocketEntry(path string, expectedUID uint32, requirePrivate bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	uid, ok := machineAgentJoinSocketOwner(info)
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || !ok || uid != expectedUID {
		return nil, errors.New("local Node Join path is not a socket owned by this user")
	}
	if requirePrivate && info.Mode().Perm() != 0o600 {
		return nil, errors.New("local Node Join socket is not private to this user")
	}
	return info, nil
}

func removeStaleMachineAgentJoinSocket(path string) error {
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return err
	}
	return removeStaleMachineAgentJoinSocketAs(path, uid)
}

func removeStaleMachineAgentJoinSocketAs(path string, expectedUID uint32) error {
	if err := validateMachineAgentJoinSocketPrivateDirectory(filepath.Dir(path), expectedUID); err != nil {
		return err
	}
	if _, err := machineAgentJoinSocketEntry(path, expectedUID, false); err != nil {
		return err
	}
	return os.Remove(path)
}

func removeOwnedMachineAgentJoinSocket(path string, created os.FileInfo) error {
	if created == nil {
		return errors.New("local Node Join socket ownership record is unavailable")
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return err
	}
	if err := validateMachineAgentJoinSocketPrivateDirectory(filepath.Dir(path), uid); err != nil {
		return err
	}
	current, err := machineAgentJoinSocketEntry(path, uid, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(created, current) {
		return errors.New("local Node Join socket path was replaced; refusing to remove it")
	}
	return os.Remove(path)
}
