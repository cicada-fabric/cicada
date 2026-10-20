package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The former implicit /state default must not disappear behind an empty new
// user root. Inspect only bounded names and metadata, never key/token contents.
// Operators select the original directory explicitly; no state is migrated.
func chooseMachineDefaultState(primary, legacy string) (string, error) {
	if filepath.Clean(primary) == filepath.Clean(legacy) {
		return primary, nil
	}
	for _, name := range []string{"node-native-context-history.sqlite3", "node-provider-admission.sqlite3", ".writer-root-recovery-pending.json"} {
		suffixes := []string{""}
		if strings.HasSuffix(name, ".sqlite3") {
			suffixes = append(suffixes, "-wal", "-shm", "-journal")
		}
		for _, suffix := range suffixes {
			if _, err := os.Lstat(filepath.Join(legacy, name+suffix)); err == nil {
				return "", errors.New("existing Node state requires its original explicit state directory")
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
	}
	directory := filepath.Join(legacy, "nodes")
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return primary, nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("original Node state directory is unavailable")
	}
	file, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	names, readErr := file.Readdirnames(257)
	closeErr := file.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(names) > 256 {
		return "", errors.New("original Node state inventory is unavailable")
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "node-") {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("original Node state entry is unavailable")
		}
		if !info.IsDir() {
			continue
		}
		for _, marker := range []string{"identity.json", "relay.token", "node-control-identity.bin", "node-control-state.json", "inbox.sqlite", "inbox.sqlite-wal", "inbox.sqlite-shm", "relay-journal.json", "recovery-pending.json"} {
			if _, err := os.Lstat(filepath.Join(directory, name, marker)); err == nil {
				return "", errors.New("existing Node state requires its original explicit state directory")
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
	}
	return primary, nil
}
