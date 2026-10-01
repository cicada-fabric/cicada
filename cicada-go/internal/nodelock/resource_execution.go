package nodelock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

const (
	ResourceExecutionStarting       = "STARTING"
	ResourceExecutionRunning        = "RUNNING"
	ResourceExecutionStopRequested  = "STOP_REQUESTED"
	ResourceExecutionStopConfirmed  = "STOP_CONFIRMED"
	ResourceExecutionQuarantined    = "RECONCILIATION_REQUIRED"
	ResourceExecutionStartFailed    = "START_FAILED"
	resourceExecutionMarkerVersion  = 1
	resourceExecutionMarkerFileMode = 0o600
)

var (
	ErrResourceExecutionInvalid = errors.New("resource execution identity is invalid")
	ErrResourceExecutionBusy    = errors.New("physical resource is executing or held")
	ErrResourceExecutionStale   = errors.New("resource execution fencing epoch is stale")
	ErrResourceExecutionUnknown = errors.New("resource execution record is unavailable")
	ErrResourceStopUnverified   = errors.New("physical resource stop is unverified")
)

// ResourceExecutionRequest uses a physical conflict identity, not a Hub,
// Group, Worker, or Node-local alias. Sharing stateDir across Hub contexts
// makes this lock common to those contexts on this host.
type ResourceExecutionRequest struct {
	ResourceID   string `json:"resource_id"`
	LeaseID      string `json:"lease_id"`
	FencingEpoch int64  `json:"fencing_epoch"`
	ExecutionID  string `json:"execution_id"`
}

// ResourceExecutionRecord is the durable local stop/start state visible to
// Node management. It contains no command line, prompt, provider response, or
// process output.
type ResourceExecutionRecord struct {
	Version      int    `json:"version"`
	ResourceID   string `json:"resource_id"`
	LeaseID      string `json:"lease_id"`
	FencingEpoch int64  `json:"fencing_epoch"`
	ExecutionID  string `json:"execution_id"`
	State        string `json:"state"`
	Outcome      string `json:"outcome,omitempty"`
	UpdatedAt    string `json:"updated_at"`
}

// ResourceStopReceipt is supplied only after a local executor/process probe
// observed termination for this exact execution. Active handles accept it via
// ConfirmStopped; crash recovery accepts it only from ResourceStopVerifier.
// Arbitrary model text is not a receipt.
type ResourceStopReceipt struct {
	ResourceID   string `json:"resource_id"`
	LeaseID      string `json:"lease_id"`
	FencingEpoch int64  `json:"fencing_epoch"`
	ExecutionID  string `json:"execution_id"`
	ObservedAt   string `json:"observed_at"`
}

// ResourceStopVerifier is implemented by the trusted Node executor or local
// operator integration. Returning a receipt means its own process/resource
// inspection verified stop; failures leave the authority quarantined.
type ResourceStopVerifier func(ResourceExecutionRecord) (ResourceStopReceipt, error)

type ResourceExecutionManager struct {
	stateDir string
}

type ResourceExecution struct {
	manager      *ResourceExecutionManager
	request      ResourceExecutionRequest
	cmd          *exec.Cmd
	lock         *flock.Flock
	mu           sync.Mutex
	waitOnce     sync.Once
	waitDone     chan struct{}
	waitErr      error
	waitObserved bool
	rootWaitAt   time.Time
	closed       bool
}

// OpenResourceExecutionManager binds execution records and OS locks to the
// common Node state root. It does not create or alter any Hub credential.
func OpenResourceExecutionManager(stateDir string) (*ResourceExecutionManager, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, errors.New("Node state root is required for resource execution")
	}
	if _, _, err := resourceExecutionPaths(stateDir, "gpu/0"); err != nil {
		return nil, err
	}
	return &ResourceExecutionManager{stateDir: stateDir}, nil
}

// Begin reserves the physical resource before a provider is started. The
// reservation and marker are independent of Hub-local lease storage and remain
// blocking after process restart until exact stop reconciliation succeeds.
func (m *ResourceExecutionManager) Begin(request ResourceExecutionRequest) (*ResourceExecution, error) {
	request, err := normalizeResourceExecutionRequest(request)
	if err != nil || m == nil || m.stateDir == "" {
		return nil, ErrResourceExecutionInvalid
	}
	lockPath, recordPath, err := resourceExecutionPaths(m.stateDir, request.ResourceID)
	if err != nil {
		return nil, err
	}
	if err := prepareLockFile(lockPath); err != nil {
		return nil, err
	}
	resourceLock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := resourceLock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock physical resource: %w", err)
	}
	if !locked {
		return nil, ErrResourceExecutionBusy
	}
	if err := protectLockFile(lockPath); err != nil {
		_ = resourceLock.Unlock()
		return nil, err
	}
	previous, err := readResourceExecutionRecord(recordPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = resourceLock.Unlock()
		return nil, err
	}
	if previous != nil {
		if previous.State != ResourceExecutionStopConfirmed && previous.State != ResourceExecutionStartFailed {
			_ = resourceLock.Unlock()
			return nil, ErrResourceExecutionBusy
		}
		if request.FencingEpoch <= previous.FencingEpoch || request.ExecutionID == previous.ExecutionID {
			_ = resourceLock.Unlock()
			return nil, ErrResourceExecutionStale
		}
	}
	entry := ResourceExecutionRecord{Version: resourceExecutionMarkerVersion,
		ResourceID: request.ResourceID, LeaseID: request.LeaseID, FencingEpoch: request.FencingEpoch,
		ExecutionID: request.ExecutionID, State: ResourceExecutionStarting,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := writeResourceExecutionRecord(recordPath, entry); err != nil {
		_ = resourceLock.Unlock()
		return nil, err
	}
	return &ResourceExecution{manager: m, request: request, lock: resourceLock,
		waitDone: make(chan struct{})}, nil
}

// StartCommand reserves the physical identity and starts one provider process.
// If Start fails, the record is safely terminal because no process was launched.
func (m *ResourceExecutionManager) StartCommand(request ResourceExecutionRequest,
	command *exec.Cmd) (*ResourceExecution, error) {
	if command == nil {
		return nil, ErrResourceExecutionInvalid
	}
	execution, err := m.Begin(request)
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = execution.finish(ResourceExecutionStartFailed, "process_start_failed")
		return nil, err
	}
	execution.cmd = command
	if err := execution.mark(ResourceExecutionRunning, "process_started"); err != nil {
		_ = execution.Quarantine()
		return nil, err
	}
	return execution, nil
}

// MarkStarted is for a non-command local executor which completed its own
// start operation. Such an executor must later provide a verified stop receipt.
func (e *ResourceExecution) MarkStarted() error {
	if e == nil || e.cmd != nil {
		return ErrResourceExecutionInvalid
	}
	return e.mark(ResourceExecutionRunning, "executor_started")
}

// RequestStop records stop intent before signaling a managed process. It does
// not release the physical lock; ConfirmStopped must follow process-tree cleanup.
func (e *ResourceExecution) RequestStop() error {
	if e == nil {
		return ErrResourceExecutionInvalid
	}
	if err := e.mark(ResourceExecutionStopRequested, "stop_requested"); err != nil {
		return err
	}
	if e.cmd != nil && e.cmd.Process != nil {
		if err := e.cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	return nil
}

// Wait reaps only the launched root process. It deliberately keeps the
// resource marker and OS lock; callers must stop/join the entire process tree
// and then provide an exact receipt to ConfirmStopped.
func (e *ResourceExecution) Wait() error {
	if e == nil || e.cmd == nil || e.cmd.Process == nil {
		return ErrResourceExecutionInvalid
	}
	e.waitOnce.Do(func() {
		defer close(e.waitDone)
		e.waitErr = e.cmd.Wait()
		e.mu.Lock()
		e.waitObserved = true
		e.rootWaitAt = time.Now().UTC()
		e.mu.Unlock()
	})
	<-e.waitDone
	return e.waitErr
}

// Stop asks the process to exit, escalates to Kill after the caller's grace
// period, and keeps an unresolved marker if process termination is unknown.
func (e *ResourceExecution) Stop(ctx context.Context, grace time.Duration) error {
	if e == nil || e.cmd == nil || e.cmd.Process == nil {
		return ErrResourceExecutionInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if grace <= 0 || grace > 5*time.Minute {
		grace = 10 * time.Second
	}
	if err := e.RequestStop(); err != nil {
		_ = e.Quarantine()
		return err
	}
	done := make(chan error, 1)
	go func() { done <- e.Wait() }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if err := e.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			_ = e.Quarantine()
			return errors.Join(ctx.Err(), err)
		}
	case <-timer.C:
		if err := e.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			_ = e.Quarantine()
			return err
		}
	}
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		_ = e.Quarantine()
		return ErrResourceExecutionBusy
	}
}

// ConfirmStopped releases the marker only when an injected trusted runtime or
// resource verifier supplies exact stop evidence. Process-group emptiness and
// Cmd.Wait are deliberately insufficient because a descendant can call setsid
// and escape the original group. A nil verifier leaves the resource held.
func (e *ResourceExecution) ConfirmStopped(verify ResourceStopVerifier) error {
	if e == nil {
		return ErrResourceExecutionInvalid
	}
	if verify == nil {
		return ErrResourceStopUnverified
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrResourceExecutionStale
	}
	_, recordPath, err := resourceExecutionPaths(e.manager.stateDir, e.request.ResourceID)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	entry, err := readResourceExecutionRecord(recordPath)
	if err != nil || entry == nil || !sameResourceExecution(*entry, e.request) ||
		(entry.State != ResourceExecutionRunning && entry.State != ResourceExecutionStopRequested) {
		e.mu.Unlock()
		return ErrResourceExecutionStale
	}
	rootWaitAt, waitObserved, commandManaged := e.rootWaitAt, e.waitObserved, e.cmd != nil
	e.mu.Unlock()
	if commandManaged && !waitObserved {
		return ErrResourceExecutionStale
	}
	receipt, err := verify(*entry)
	if err != nil {
		return err
	}
	if !sameResourceStopReceipt(receipt, e.request) {
		return ErrResourceExecutionStale
	}
	observedAt, err := validResourceStopTime(receipt.ObservedAt)
	if err != nil {
		return err
	}
	if commandManaged && observedAt.Before(rootWaitAt) {
		return ErrResourceExecutionStale
	}
	return e.finish(ResourceExecutionStopConfirmed, "trusted_runtime_stop_confirmed")
}

// QuarantineStopUnverified preserves the successful business result while
// preventing another execution from acquiring the same physical resource.
func (e *ResourceExecution) QuarantineStopUnverified() error {
	if e == nil {
		return ErrResourceExecutionInvalid
	}
	return e.finish(ResourceExecutionQuarantined, "resource_stop_unverified")
}

// Quarantine persists unresolved authority and releases only the OS mutex;
// subsequent callers still see the durable blocking marker.
func (e *ResourceExecution) Quarantine() error {
	if e == nil {
		return ErrResourceExecutionInvalid
	}
	return e.finish(ResourceExecutionQuarantined, "executor_outcome_uncertain")
}

func (e *ResourceExecution) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil
	}
	return e.Quarantine()
}

// Inspect returns only the bounded execution record. It does not clear or
// renew an expired Hub lease and does not infer that a process has stopped.
func (m *ResourceExecutionManager) Inspect(resourceID string) (*ResourceExecutionRecord, error) {
	lockPath, recordPath, err := resourceExecutionPaths(m.stateDir, resourceID)
	if err != nil {
		return nil, err
	}
	if err := prepareLockFile(lockPath); err != nil {
		return nil, err
	}
	resourceLock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := resourceLock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrResourceExecutionBusy
	}
	defer resourceLock.Unlock()
	if err := protectLockFile(lockPath); err != nil {
		return nil, err
	}
	return readResourceExecutionRecord(recordPath)
}

// ReconcileStopped is the only recovery path for a crashed/uncertain process.
// The trusted local verifier must inspect the current host and return a receipt
// that exactly matches the immutable resource, lease, epoch, and execution.
func (m *ResourceExecutionManager) ReconcileStopped(request ResourceExecutionRequest,
	verify ResourceStopVerifier) error {
	request, err := normalizeResourceExecutionRequest(request)
	if err != nil || verify == nil {
		return ErrResourceExecutionInvalid
	}
	lockPath, recordPath, err := resourceExecutionPaths(m.stateDir, request.ResourceID)
	if err != nil {
		return err
	}
	if err := prepareLockFile(lockPath); err != nil {
		return err
	}
	resourceLock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := resourceLock.TryLock()
	if err != nil {
		return err
	}
	if !locked {
		return ErrResourceExecutionBusy
	}
	defer resourceLock.Unlock()
	if err := protectLockFile(lockPath); err != nil {
		return err
	}
	current, err := readResourceExecutionRecord(recordPath)
	if err != nil || current == nil {
		return ErrResourceExecutionUnknown
	}
	if !sameResourceExecution(*current, request) ||
		(current.State != ResourceExecutionQuarantined && current.State != ResourceExecutionRunning && current.State != ResourceExecutionStopRequested && current.State != ResourceExecutionStarting) {
		return ErrResourceExecutionStale
	}
	receipt, err := verify(*current)
	if err != nil {
		return err
	}
	if !sameResourceStopReceipt(receipt, request) {
		return ErrResourceExecutionStale
	}
	observedAt, err := validResourceStopTime(receipt.ObservedAt)
	if err != nil {
		return err
	}
	current.State = ResourceExecutionStopConfirmed
	current.Outcome = "trusted_stop_probe"
	current.UpdatedAt = observedAt.UTC().Format(time.RFC3339Nano)
	return writeResourceExecutionRecord(recordPath, *current)
}

func sameResourceStopReceipt(receipt ResourceStopReceipt,
	request ResourceExecutionRequest) bool {
	return receipt.ResourceID == request.ResourceID && receipt.LeaseID == request.LeaseID &&
		receipt.FencingEpoch == request.FencingEpoch && receipt.ExecutionID == request.ExecutionID
}

func validResourceStopTime(raw string) (time.Time, error) {
	observedAt, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || observedAt.IsZero() || observedAt.After(time.Now().Add(time.Minute)) {
		return time.Time{}, ErrResourceExecutionInvalid
	}
	return observedAt, nil
}

func (e *ResourceExecution) mark(state, outcome string) error {
	if e == nil || (state != ResourceExecutionRunning && state != ResourceExecutionStopRequested) {
		return ErrResourceExecutionInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrResourceExecutionStale
	}
	_, recordPath, err := resourceExecutionPaths(e.manager.stateDir, e.request.ResourceID)
	if err != nil {
		return err
	}
	entry, err := readResourceExecutionRecord(recordPath)
	if err != nil || entry == nil || !sameResourceExecution(*entry, e.request) {
		return ErrResourceExecutionStale
	}
	if (state == ResourceExecutionRunning && entry.State != ResourceExecutionStarting) ||
		(state == ResourceExecutionStopRequested && entry.State != ResourceExecutionRunning && entry.State != ResourceExecutionStopRequested) {
		return ErrResourceExecutionStale
	}
	entry.State = state
	entry.Outcome = outcome
	entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeResourceExecutionRecord(recordPath, *entry)
}

func (e *ResourceExecution) finish(state, outcome string) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrResourceExecutionStale
	}
	_, recordPath, pathErr := resourceExecutionPaths(e.manager.stateDir, e.request.ResourceID)
	var persistErr error
	if pathErr != nil {
		persistErr = pathErr
	} else if entry, err := readResourceExecutionRecord(recordPath); err != nil || entry == nil || !sameResourceExecution(*entry, e.request) {
		persistErr = ErrResourceExecutionStale
	} else {
		validTransition := state == ResourceExecutionQuarantined && entry.State != ResourceExecutionStopConfirmed && entry.State != ResourceExecutionStartFailed ||
			state == ResourceExecutionStopConfirmed && (entry.State == ResourceExecutionRunning || entry.State == ResourceExecutionStopRequested) ||
			state == ResourceExecutionStartFailed && entry.State == ResourceExecutionStarting
		if !validTransition {
			persistErr = ErrResourceExecutionStale
		} else {
			entry.State = state
			entry.Outcome = outcome
			entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			persistErr = writeResourceExecutionRecord(recordPath, *entry)
		}
	}
	e.closed = true
	lock := e.lock
	e.lock = nil
	e.mu.Unlock()
	if lock != nil {
		persistErr = errors.Join(persistErr, lock.Unlock())
	}
	return persistErr
}

func normalizeResourceExecutionRequest(request ResourceExecutionRequest) (ResourceExecutionRequest, error) {
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	request.LeaseID = strings.TrimSpace(request.LeaseID)
	request.ExecutionID = strings.TrimSpace(request.ExecutionID)
	if !validPhysicalResourceID(request.ResourceID) || request.LeaseID == "" || len(request.LeaseID) > 256 ||
		request.ExecutionID == "" || len(request.ExecutionID) > 256 || request.FencingEpoch <= 0 ||
		strings.ContainsAny(request.LeaseID+request.ExecutionID, "\x00\r\n") {
		return ResourceExecutionRequest{}, ErrResourceExecutionInvalid
	}
	return request, nil
}

func validPhysicalResourceID(id string) bool {
	if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\\\x00\r\n") {
		return false
	}
	parts := strings.Split(id, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	if len(parts) == 2 && parts[0] == "gpu" {
		index, err := strconv.Atoi(parts[1])
		return err == nil && index >= 0 && strconv.Itoa(index) == parts[1]
	}
	if len(parts) == 2 && parts[0] == "physical" && len(parts[1]) == 64 {
		for _, character := range parts[1] {
			if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
				return false
			}
		}
		return true
	}
	return false
}

func resourceExecutionPaths(stateDir, resourceID string) (lockPath, recordPath string, err error) {
	if !validPhysicalResourceID(resourceID) {
		return "", "", ErrResourceExecutionInvalid
	}
	root, err := filepath.Abs(filepath.Clean(strings.TrimSpace(stateDir)))
	if err != nil || strings.TrimSpace(stateDir) == "" {
		return "", "", ErrResourceExecutionInvalid
	}
	nodesDir := filepath.Join(root, "nodes")
	if err := os.MkdirAll(nodesDir, 0o700); err != nil {
		return "", "", err
	}
	if err := protectDirectory(nodesDir); err != nil {
		return "", "", err
	}
	lockDir := filepath.Join(nodesDir, lockDirectoryName)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return "", "", err
	}
	if err := protectDirectory(lockDir); err != nil {
		return "", "", err
	}
	lockDir, err = filepath.EvalSymlinks(lockDir)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(resourceID))
	name := "resource-" + hex.EncodeToString(hash[:])
	return filepath.Join(lockDir, name+".execution.lock"), filepath.Join(lockDir, name+".execution.json"), nil
}

func readResourceExecutionRecord(path string) (*ResourceExecutionRecord, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("resource execution record must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record ResourceExecutionRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Version != resourceExecutionMarkerVersion ||
		!validPhysicalResourceID(record.ResourceID) || record.LeaseID == "" || record.ExecutionID == "" || record.FencingEpoch <= 0 {
		return nil, errors.New("resource execution record is invalid")
	}
	return &record, nil
}

func writeResourceExecutionRecord(path string, record ResourceExecutionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".resource-execution-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(resourceExecutionMarkerFileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if err := os.Chmod(path, resourceExecutionMarkerFileMode); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func sameResourceExecution(record ResourceExecutionRecord, request ResourceExecutionRequest) bool {
	return record.ResourceID == request.ResourceID && record.LeaseID == request.LeaseID &&
		record.FencingEpoch == request.FencingEpoch && record.ExecutionID == request.ExecutionID
}
