package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

// CheckBoundNodeWorkspaceSnapshotNodeControl repeats the encrypted channel's
// live Owner binding and Worker-attempt fence. Stream handlers call it for
// each chunk, with requireProcessing set on uploads until the atomic attach.
func (c *Control) CheckBoundNodeWorkspaceSnapshotNodeControl(input store.NodeControlRPCInput,
	workerID string, attempt int, workspaceID string, requireProcessing bool) (string, error) {
	if c == nil || c.store == nil {
		return "", errors.New("Node-Control workspace snapshot store is unavailable")
	}
	return c.store.CheckBoundNodeWorkerWorkspaceSnapshotNodeControl(input,
		workerID, attempt, workspaceID, requireProcessing)
}

// ReceiveBoundNodeWorkspaceSnapshotStream validates and stores a decrypted
// archive in the Control CAS without changing the Workspace pointer. Final
// attachment and the signed replay reply are committed atomically through
// AttachBoundNodeWorkspaceSnapshotNodeControl after the complete archive has
// passed digest and tar validation.
func (c *Control) ReceiveBoundNodeWorkspaceSnapshotStream(ctx context.Context,
	input store.NodeControlRPCInput, manifest nodewire.SnapshotManifest, body io.Reader) (snapshot.Snapshot, error) {
	if manifest.Validate(false) != nil || manifest.Direction != nodewire.SnapshotDirectionUpload ||
		input.Operation != nodewire.SnapshotUploadOperation ||
		manifest.Digest == "" || body == nil {
		return snapshot.Snapshot{}, ErrNodeWorkspaceSnapshotInvalidArchive
	}
	if _, err := c.CheckBoundNodeWorkspaceSnapshotNodeControl(input, manifest.WorkerID,
		manifest.Attempt, manifest.WorkspaceID, true); err != nil {
		return snapshot.Snapshot{}, err
	}
	result, err := c.snapshotStore.Put(ctx, body)
	if err != nil {
		var pathErr *os.PathError
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &pathErr) || errors.As(err, &maxBytesErr) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return snapshot.Snapshot{}, err
		}
		return snapshot.Snapshot{}, fmt.Errorf("%w: %v", ErrNodeWorkspaceSnapshotInvalidArchive, err)
	}
	if result.Digest != manifest.Digest || result.Size != manifest.Size || result.FileCount != manifest.FileCount {
		return snapshot.Snapshot{}, ErrNodeWorkspaceSnapshotDigestMismatch
	}
	return result, nil
}

func (c *Control) AttachBoundNodeWorkspaceSnapshotNodeControl(input store.NodeControlRPCInput,
	manifest nodewire.SnapshotManifest, result snapshot.Snapshot, responsePacket []byte) error {
	if c == nil || c.store == nil || manifest.Direction != nodewire.SnapshotDirectionUpload ||
		input.Operation != nodewire.SnapshotUploadOperation || result.Digest != manifest.Digest ||
		result.Size != manifest.Size || result.FileCount != manifest.FileCount {
		return ErrNodeWorkspaceSnapshotDigestMismatch
	}
	previousDigest, err := c.store.CheckBoundNodeWorkerWorkspaceSnapshotNodeControl(input,
		manifest.WorkerID, manifest.Attempt, manifest.WorkspaceID, true)
	if err != nil {
		return err
	}
	workspace, err := c.store.AttachBoundNodeWorkerWorkspaceSnapshotNodeControl(input,
		manifest.WorkerID, manifest.Attempt, manifest.WorkspaceID, previousDigest,
		result.Digest, responsePacket)
	if err != nil {
		return err
	}
	c.recordWorkspaceSnapshot(workspace, result)
	return nil
}

func (c *Control) OpenBoundNodeWorkspaceSnapshotNodeControl(input store.NodeControlRPCInput,
	manifest nodewire.SnapshotManifest, requireProcessing bool) (*os.File, snapshot.Snapshot, error) {
	if manifest.Validate(true) != nil || manifest.Direction != nodewire.SnapshotDirectionDownload ||
		input.Operation != nodewire.SnapshotDownloadOperation {
		return nil, snapshot.Snapshot{}, os.ErrNotExist
	}
	currentDigest, err := c.CheckBoundNodeWorkspaceSnapshotNodeControl(input,
		manifest.WorkerID, manifest.Attempt, manifest.WorkspaceID, requireProcessing)
	if err != nil {
		return nil, snapshot.Snapshot{}, err
	}
	if currentDigest == "" || currentDigest != manifest.Digest {
		return nil, snapshot.Snapshot{}, os.ErrNotExist
	}
	return c.snapshotStore.Open(currentDigest)
}

func (c *Control) CheckBoundNodeWorkspaceSnapshotDownloadChunk(input store.NodeControlRPCInput,
	manifest nodewire.SnapshotManifest) error {
	if manifest.Validate(false) != nil || manifest.Direction != nodewire.SnapshotDirectionDownload ||
		input.Operation != nodewire.SnapshotDownloadOperation {
		return store.ErrNodeWorkerNotAuthorized
	}
	currentDigest, err := c.CheckBoundNodeWorkspaceSnapshotNodeControl(input,
		manifest.WorkerID, manifest.Attempt, manifest.WorkspaceID, false)
	if err != nil {
		return err
	}
	if currentDigest != manifest.Digest {
		return store.ErrNodeWorkerNotAuthorized
	}
	return nil
}
