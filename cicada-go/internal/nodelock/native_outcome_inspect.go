package nodelock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// InspectNativeMessageOutcome reads the existing exact message outcome without
// taking a writer epoch, making directories, repairing modes or authorizing a
// retry. BindingID/AttemptID are supplied by the retained artifact, not guessed
// from a later registration. Callers must bind every lookup field below.
func InspectNativeMessageOutcome(root, scope, harness, nativeID string, lookup NativeOperation) (NativeOutcomeState, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.TrimSpace(scope) == "" || harness == "" || nativeID == "" || lookup.HubID == "" || lookup.NodeID == "" || lookup.EndpointID == "" || lookup.MessageID == "" || lookup.Digest == "" || lookup.BindingEpoch == 0 {
		return "", ErrNativeOperationConflict
	}
	if err := rejectWriterRootSymlinkComponents(root); err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(scope + "\x00" + harness + "\x00" + nativeID))
	l := NativeWriterLock{path: filepath.Join(root, ".native-writers", hex.EncodeToString(h[:])+".lock")}
	path := l.operationPath(lookup)
	for _, directory := range []string{root, filepath.Join(root, ".native-writers"), filepath.Dir(path)} {
		if err := requireExistingPrivateDirectory(directory); errors.Is(err, os.ErrNotExist) {
			return "", nil
		} else if err != nil {
			return "", err
		}
		if err := rejectWriterRootSymlinkComponents(directory); err != nil {
			return "", err
		}
	}
	before, err := existingPrivateLockInfo(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || before.Size() <= 0 || before.Size() > 8192 {
		return "", ErrNativeOperationConflict
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(before, held) {
		return "", ErrNativeOperationConflict
	}
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return "", err
	}
	after, err := existingPrivateLockInfo(path)
	if err != nil || !os.SameFile(before, after) || len(b) != int(before.Size()) || !before.ModTime().Equal(after.ModTime()) {
		return "", ErrNativeOperationConflict
	}
	var saved nativeOutcome
	if json.Unmarshal(b, &saved) != nil || !saved.Operation.valid() || saved.WriterEpoch == 0 {
		return "", ErrNativeOperationConflict
	}
	o := saved.Operation
	if o.HubID != lookup.HubID || o.NodeID != lookup.NodeID || o.EndpointID != lookup.EndpointID || o.MessageID != lookup.MessageID || o.Digest != lookup.Digest || o.BindingEpoch != lookup.BindingEpoch {
		return "", ErrNativeOperationConflict
	}
	switch saved.State {
	case NativeQueueAccepted, NativeInjecting, NativeUncertain, NativeNotStarted:
		return saved.State, nil
	}
	return "", ErrNativeOperationConflict
}
