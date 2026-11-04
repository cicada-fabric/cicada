package nodelock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// InspectResourceExecutionExisting observes a protected atomic marker without
// creating directories/locks, repairing modes or declaring a process stopped.
func InspectResourceExecutionExisting(root, resource string) (*ResourceExecutionRecord, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !validPhysicalResourceID(resource) {
		return nil, ErrResourceExecutionInvalid
	}
	if err := rejectWriterRootSymlinkComponents(root); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "nodes", lockDirectoryName)
	if err := requireExistingPrivateDirectory(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := rejectWriterRootSymlinkComponents(dir); err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(resource))
	path := filepath.Join(dir, "resource-"+hex.EncodeToString(h[:])+".execution.json")
	before, err := existingPrivateLockInfo(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || before.Size() <= 0 || before.Size() > 8192 {
		return nil, ErrResourceExecutionUnknown
	}
	record, err := readResourceExecutionRecord(path)
	if err != nil {
		return nil, err
	}
	after, err := existingPrivateLockInfo(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || record.ResourceID != resource {
		return nil, ErrResourceExecutionUnknown
	}
	return record, nil
}
