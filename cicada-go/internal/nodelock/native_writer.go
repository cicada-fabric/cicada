package nodelock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// NativeWriterLock serializes one physical native session across Hub contexts
// configured with the same state root. The caller holds it through the queue
// command and durable writer outcome; FinishNativeOperation fences a stale
// epoch. This does not fence later model consumption or application results.
type NativeWriterLock struct {
	mu    sync.Mutex
	file  *flock.Flock
	Epoch uint64
	path  string
}

func (l *NativeWriterLock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Unlock()
	l.file = nil
	return err
}

func AcquireNativeWriter(ctx context.Context, stateRoot, accountScope, harness, nativeID string) (*NativeWriterLock, error) {
	if ctx == nil || strings.TrimSpace(stateRoot) == "" || strings.TrimSpace(accountScope) == "" ||
		strings.TrimSpace(harness) == "" || strings.TrimSpace(nativeID) == "" {
		return nil, errors.New("native writer scope is incomplete")
	}
	root, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, ".native-writers")
	_, initialDirErr := os.Lstat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := protectDirectory(dir); err != nil {
		return nil, err
	}
	if errors.Is(initialDirErr, os.ErrNotExist) {
		parent, err := os.Open(filepath.Dir(dir))
		if err != nil {
			return nil, err
		}
		err = errors.Join(parent.Sync(), parent.Close())
		if err != nil {
			return nil, fmt.Errorf("sync native writer registry parent: %w", err)
		}
	} else if initialDirErr != nil {
		return nil, initialDirErr
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	scope := sha256.Sum256([]byte(accountScope + "\x00" + harness + "\x00" + nativeID))
	path := filepath.Join(dir, hex.EncodeToString(scope[:])+".lock")
	if err := prepareLockFile(path); err != nil {
		return nil, err
	}
	file := flock.New(path, flock.SetPermissions(0o600))
	for {
		locked, err := file.TryLock()
		if err != nil {
			return nil, err
		}
		if locked {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err := protectLockFile(path); err != nil {
		_ = file.Unlock()
		return nil, err
	}
	epochPath := path + ".epoch"
	if err := prepareLockFile(epochPath); err != nil {
		_ = file.Unlock()
		return nil, err
	}
	data, err := os.ReadFile(epochPath)
	if err != nil {
		_ = file.Unlock()
		return nil, err
	}
	var previous struct {
		Epoch uint64 `json:"epoch"`
	}
	if len(data) != 0 && json.Unmarshal(data, &previous) != nil {
		_ = file.Unlock()
		return nil, errors.New("native writer epoch is invalid")
	}
	if previous.Epoch == ^uint64(0) {
		_ = file.Unlock()
		return nil, errors.New("native writer epoch exhausted")
	}
	previous.Epoch++
	encoded, _ := json.Marshal(previous)
	output, err := os.CreateTemp(dir, ".native-epoch-*")
	if err != nil {
		_ = file.Unlock()
		return nil, err
	}
	tempPath := output.Name()
	defer os.Remove(tempPath)
	if err := output.Chmod(0o600); err != nil {
		_ = output.Close()
		_ = file.Unlock()
		return nil, err
	}
	if _, err = output.Write(append(encoded, '\n')); err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil || closeErr != nil {
		_ = file.Unlock()
		return nil, fmt.Errorf("persist native writer epoch: %w", errors.Join(err, closeErr))
	}
	if err := os.Rename(tempPath, epochPath); err != nil {
		_ = file.Unlock()
		return nil, fmt.Errorf("publish native writer epoch: %w", err)
	}
	directory, err := os.Open(dir)
	if err == nil {
		err = errors.Join(directory.Sync(), directory.Close())
	}
	if err != nil {
		_ = file.Unlock()
		return nil, fmt.Errorf("sync native writer epoch directory: %w", err)
	}
	if err := protectLockFile(epochPath); err != nil {
		_ = file.Unlock()
		return nil, err
	}
	return &NativeWriterLock{file: file, Epoch: previous.Epoch, path: path}, nil
}
