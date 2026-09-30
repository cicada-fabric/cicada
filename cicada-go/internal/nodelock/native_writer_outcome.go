package nodelock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NativeOperation is the immutable, Hub-scoped queue identity. AttemptID is
// current authorization evidence, not part of the deduplication key.
type NativeOperation struct {
	HubID, NodeID, EndpointID, BindingID, MessageID, Digest, AttemptID string
	BindingEpoch                                                       uint64
}

type NativeOutcomeState string

const (
	NativeInjecting     NativeOutcomeState = "INJECTING"
	NativeQueueAccepted NativeOutcomeState = "QUEUE_ACCEPTED"
	NativeUncertain     NativeOutcomeState = "INJECTION_UNCERTAIN"
	NativeNotStarted    NativeOutcomeState = "FAILED_BEFORE_START"
)

var ErrNativeOperationUncertain = errors.New("native queue outcome is uncertain; refusing reinjection")
var ErrNativeOperationConflict = errors.New("native queue operation identity changed")
var ErrNativeWriterStale = errors.New("native writer epoch is stale")

type nativeOutcome struct {
	Operation   NativeOperation    `json:"operation"`
	State       NativeOutcomeState `json:"state"`
	WriterEpoch uint64             `json:"writer_epoch"`
}

const maxNativeOperationsPerWriter = 4096

func (o NativeOperation) valid() bool {
	return o.HubID != "" && o.NodeID != "" && o.EndpointID != "" && o.BindingID != "" &&
		o.MessageID != "" && o.Digest != "" && o.AttemptID != "" && o.BindingEpoch != 0 &&
		len(o.HubID)+len(o.NodeID)+len(o.EndpointID)+len(o.BindingID)+len(o.MessageID)+len(o.Digest)+len(o.AttemptID) <= 4096 &&
		strings.TrimSpace(o.HubID) == o.HubID && strings.TrimSpace(o.MessageID) == o.MessageID
}

func (o NativeOperation) sameIdentity(other NativeOperation) bool {
	return o.HubID == other.HubID && o.NodeID == other.NodeID && o.EndpointID == other.EndpointID &&
		o.BindingID == other.BindingID && o.BindingEpoch == other.BindingEpoch &&
		o.MessageID == other.MessageID && o.Digest == other.Digest
}

func (l *NativeWriterLock) operationPath(o NativeOperation) string {
	key := sha256.Sum256([]byte(o.HubID + "\x00" + o.NodeID + "\x00" + o.EndpointID + "\x00" + o.MessageID))
	return filepath.Join(l.path+".operations", hex.EncodeToString(key[:])+".json")
}

func (l *NativeWriterLock) checkCurrent() error {
	if l == nil || l.file == nil || l.path == "" || l.Epoch == 0 {
		return ErrNativeWriterStale
	}
	if err := protectDirectory(filepath.Dir(l.path)); err != nil {
		return err
	}
	if err := protectLockFile(l.path + ".epoch"); err != nil {
		return err
	}
	data, err := os.ReadFile(l.path + ".epoch")
	if err != nil {
		return err
	}
	var current struct {
		Epoch uint64 `json:"epoch"`
	}
	if json.Unmarshal(data, &current) != nil || current.Epoch != l.Epoch {
		return ErrNativeWriterStale
	}
	return nil
}

func (l *NativeWriterLock) readOperation(o NativeOperation) (*nativeOutcome, error) {
	path := l.operationPath(o)
	if info, err := os.Lstat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("native outcome directory is unsafe")
	}
	if err := protectDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 8192 {
		return nil, errors.New("native outcome file is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var saved nativeOutcome
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}
	if !saved.Operation.sameIdentity(o) {
		return nil, ErrNativeOperationConflict
	}
	if saved.WriterEpoch == 0 {
		return nil, errors.New("native outcome lacks writer epoch")
	}
	switch saved.State {
	case NativeInjecting, NativeQueueAccepted, NativeUncertain, NativeNotStarted:
	default:
		return nil, errors.New("native outcome state is invalid")
	}
	return &saved, nil
}

func (l *NativeWriterLock) writeOperation(saved nativeOutcome) error {
	dir := l.path + ".operations"
	_, initialErr := os.Lstat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := protectDirectory(dir); err != nil {
		return err
	}
	if errors.Is(initialErr, os.ErrNotExist) {
		parent, err := os.Open(filepath.Dir(dir))
		if err != nil {
			return err
		}
		err = errors.Join(parent.Sync(), parent.Close())
		if err != nil {
			return err
		}
	} else if initialErr != nil {
		return initialErr
	}
	path := l.operationPath(saved.Operation)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) >= maxNativeOperationsPerWriter {
			return errors.New("native outcome ledger capacity reached; refusing injection")
		}
	} else if err != nil {
		return err
	}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".native-outcome-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	_, err = tmp.Write(append(data, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	return errors.Join(err, d.Close())
}

// BeginNativeOperation is called under the physical writer lease before
// starting the native command. A prior INJECTING record means a crash window,
// even when the Hub supplies a new Relay attempt.
func (l *NativeWriterLock) BeginNativeOperation(o NativeOperation) (NativeOutcomeState, error) {
	if !o.valid() {
		return "", errors.New("native operation scope is incomplete")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkCurrent(); err != nil {
		return "", err
	}
	saved, err := l.readOperation(o)
	if err != nil {
		return "", err
	}
	if saved != nil {
		switch saved.State {
		case NativeQueueAccepted:
			return NativeQueueAccepted, nil
		case NativeInjecting:
			if saved.WriterEpoch != l.Epoch {
				saved.State = NativeUncertain
				if err := l.writeOperation(*saved); err != nil {
					return "", err
				}
			}
			return NativeUncertain, ErrNativeOperationUncertain
		case NativeUncertain:
			return NativeUncertain, ErrNativeOperationUncertain
		}
	}
	if err := l.writeOperation(nativeOutcome{Operation: o, State: NativeInjecting, WriterEpoch: l.Epoch}); err != nil {
		return "", err
	}
	return NativeInjecting, nil
}

// FinishNativeOperation persists the queue result before the lease is released.
// A stale or released writer cannot turn an uncertain result into success.
func (l *NativeWriterLock) FinishNativeOperation(o NativeOperation, state NativeOutcomeState) error {
	if !o.valid() || (state != NativeQueueAccepted && state != NativeUncertain && state != NativeNotStarted) {
		return errors.New("invalid native outcome")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkCurrent(); err != nil {
		return err
	}
	saved, err := l.readOperation(o)
	if err != nil {
		return err
	}
	if saved == nil || saved.State != NativeInjecting || saved.WriterEpoch != l.Epoch || saved.Operation.AttemptID != o.AttemptID {
		return ErrNativeWriterStale
	}
	saved.State = state
	if err := l.writeOperation(*saved); err != nil {
		return fmt.Errorf("persist native outcome: %w", err)
	}
	return nil
}

// NativeOperationOutcome reads a durable result while holding the same writer
// lease. Only QUEUE_ACCEPTED can back a current, freshly authorized receipt.
func (l *NativeWriterLock) NativeOperationOutcome(o NativeOperation) (NativeOutcomeState, error) {
	if !o.valid() {
		return "", errors.New("native operation scope is incomplete")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkCurrent(); err != nil {
		return "", err
	}
	saved, err := l.readOperation(o)
	if err != nil {
		return "", err
	}
	if saved == nil {
		return "", nil
	}
	if saved.State == NativeInjecting && saved.WriterEpoch != l.Epoch {
		saved.State = NativeUncertain
		if err := l.writeOperation(*saved); err != nil {
			return "", err
		}
	}
	return saved.State, nil
}
