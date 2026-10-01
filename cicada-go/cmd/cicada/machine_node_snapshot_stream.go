package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

type machineNodeSnapshotReply struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   string          `json:"error_code,omitempty"`
	OperationID string          `json:"operation_id"`
	Sequence    uint64          `json:"sequence"`
}

const machineNodeSnapshotContentType = "application/x-cicada-node-snapshot-v1"

func machineNodeSnapshotOutboxDir(client *machineNodeControlClient) string {
	return filepath.Join(filepath.Dir(client.statePath), "snapshot-outbox")
}

func ensureMachineNodeSnapshotOutboxDir(client *machineNodeControlClient) (string, error) {
	directory := machineNodeSnapshotOutboxDir(client)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("Node snapshot outbox must be a private regular directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	return directory, nil
}

func validateMachineNodeSnapshotOutboxPath(client *machineNodeControlClient, operationID, path string) error {
	directory, err := ensureMachineNodeSnapshotOutboxDir(client)
	if err != nil {
		return err
	}
	base := filepath.Base(path)
	if filepath.Dir(filepath.Clean(path)) != directory ||
		(base != operationID+".tar" && base != operationID+".download.tar") {
		return errors.New("Node snapshot outbox path does not match the exact operation ID")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("Node snapshot outbox object must be a regular non-symlink file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}

func stageMachineNodeSnapshotUpload(ctx context.Context, client *machineNodeControlClient,
	workspace, operationID string) (string, snapshot.Snapshot, error) {
	directory, err := ensureMachineNodeSnapshotOutboxDir(client)
	if err != nil {
		return "", snapshot.Snapshot{}, err
	}
	temporary, err := os.CreateTemp(directory, ".upload-stage-*")
	if err != nil {
		return "", snapshot.Snapshot{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", snapshot.Snapshot{}, err
	}
	metadata, packErr := snapshot.Pack(ctx, workspace, temporary)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if packErr != nil {
		return "", snapshot.Snapshot{}, packErr
	}
	if syncErr != nil {
		return "", snapshot.Snapshot{}, syncErr
	}
	if closeErr != nil {
		return "", snapshot.Snapshot{}, closeErr
	}
	path := filepath.Join(directory, operationID+".tar")
	if _, err := os.Lstat(path); err == nil {
		return "", snapshot.Snapshot{}, errors.New("Node snapshot operation file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", snapshot.Snapshot{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", snapshot.Snapshot{}, err
	}
	if directoryFile, err := os.Open(directory); err == nil {
		_ = directoryFile.Sync()
		_ = directoryFile.Close()
	}
	return path, metadata, nil
}

func createMachineNodeSnapshotDownloadStage(client *machineNodeControlClient, operationID string) (string, error) {
	directory, err := ensureMachineNodeSnapshotOutboxDir(client)
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, operationID+".download.tar")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		_ = os.Remove(path)
		return "", syncErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", closeErr
	}
	return path, nil
}

func (client *machineNodeControlClient) prepareSnapshotOutbox(operation string,
	manifest nodewire.SnapshotManifest, path string, operationID string) error {
	plain, err := json.Marshal(manifest)
	if err != nil || len(plain) == 0 || len(plain) > nodewire.MaxRequestPlaintextBytes {
		return errors.New("Node workspace snapshot manifest exceeds the 64KiB management limit")
	}
	if operation != nodewire.SnapshotUploadOperation && operation != nodewire.SnapshotDownloadOperation {
		return errors.New("invalid Node workspace snapshot operation")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.state.PendingPacket) != 0 {
		return errors.New("another Node-Control operation is still awaiting its exact retry")
	}
	if client.state.BindingID == "" || client.state.BindingVersion == 0 || client.state.NodeKeyEpoch == 0 ||
		client.state.NodeKeyID != client.identity.Public().ID || client.state.HubKeyID != client.state.HubPublicIdentity.ID {
		return errors.New("Node-Control key binding is not Owner-approved")
	}
	if client.state.Sequence >= uint64(^uint64(0)>>1) {
		return errors.New("Node-Control sequence exhausted; require Owner-approved epoch upgrade")
	}
	if err := validateMachineNodeSnapshotOutboxPath(client, operationID, path); err != nil {
		return err
	}
	binding := machineNodeControlBindingFromState(client)
	sequence := client.state.Sequence + 1
	public := client.identity.Public()
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest,
		HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID,
		BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch,
		Sequence: sequence, OperationID: operationID, Operation: operation,
		SenderKeyID: public.ID, SenderKeyVersion: binding.NodeKeyVersion,
		ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	packet, err := nodewire.SealRequest(client.identity, binding.HubKey, binding, route, plain)
	if err != nil {
		return err
	}
	if len(packet) > nodewire.MaxRequestPacketBytes {
		return errors.New("Node workspace snapshot manifest packet exceeds its 256KiB transport limit")
	}
	plainDigest := sha256.Sum256(plain)
	previous := cloneMachineNodeControlState(client.state)
	client.state.Sequence = sequence
	client.state.PendingOperationID, client.state.PendingOperation = operationID, operation
	client.state.PendingSequence = sequence
	client.state.PendingPlaintextDigest = hex.EncodeToString(plainDigest[:])
	client.state.PendingPacket = packet
	client.state.PendingResponsePacket = nil
	client.state.PendingWorkerID, client.state.PendingWorkerAttempt = manifest.WorkerID, manifest.Attempt
	client.state.PendingSnapshotPath = path
	manifestCopy := manifest
	client.state.PendingSnapshotManifest = &manifestCopy
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func machineNodeSnapshotResponseRoute(requestRoute nodewire.Route) nodewire.Route {
	responseRoute := requestRoute
	responseRoute.Direction = nodewire.DirectionResponse
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	return responseRoute
}

// machineNodeSnapshotPendingRequestRoute verifies the durable route against
// the local Owner-approved pin. The Node sent this packet to the Hub, so it
// cannot decrypt it with its own identity; the exact packet bytes remain the
// retry payload and the bounded manifest metadata below drives stream recovery.
func machineNodeSnapshotPendingRequestRoute(client *machineNodeControlClient,
	state machineNodeControlState, binding nodewire.Binding) (nodewire.Route, error) {
	packet, err := nodewire.DecodePacket(state.PendingPacket)
	if err != nil {
		return nodewire.Route{}, errors.New("durable Node snapshot packet is invalid")
	}
	route := packet.Route
	if route.Version != nodewire.Version || route.Direction != nodewire.DirectionRequest ||
		route.HubID != binding.HubID || route.NodeID != binding.NodeID ||
		route.BindingID != binding.BindingID || route.BindingVersion != binding.BindingVersion ||
		route.NodeKeyEpoch != binding.NodeKeyEpoch || route.Sequence != state.PendingSequence ||
		route.OperationID != state.PendingOperationID || route.Operation != state.PendingOperation ||
		route.SenderKeyID != binding.NodeKey.ID || route.SenderKeyVersion != binding.NodeKeyVersion ||
		route.ReceiverKeyID != binding.HubKey.ID || route.ReceiverKeyVersion != binding.HubKeyVersion {
		return nodewire.Route{}, errors.New("durable Node snapshot route differs from its saved outbox")
	}
	if client == nil || client.identity == nil || client.identity.Public().ID != binding.NodeKey.ID {
		return nodewire.Route{}, errors.New("durable Node snapshot route does not match the local Node key")
	}
	return route, nil
}

func (client *machineNodeControlClient) uploadWorkspaceSnapshot(ctx context.Context, token string,
	job machineJob, workspace string) (string, error) {
	if err := client.recoverPending(ctx, token); err != nil {
		return "", err
	}
	operationID, err := newMachineNodeControlOperationID()
	if err != nil {
		return "", err
	}
	path, metadata, err := stageMachineNodeSnapshotUpload(ctx, client, workspace, operationID)
	if err != nil {
		return "", err
	}
	manifest := nodewire.SnapshotManifest{Version: nodewire.Version,
		Direction: nodewire.SnapshotDirectionUpload, WorkerID: job.WorkerID,
		Attempt: job.Attempt, WorkspaceID: job.WorkspaceID, Digest: metadata.Digest,
		Size: metadata.Size, FileCount: metadata.FileCount,
		ChunkSize:  nodewire.SnapshotChunkBytes,
		ChunkCount: int((metadata.Size + nodewire.SnapshotChunkBytes - 1) / nodewire.SnapshotChunkBytes)}
	if err := manifest.Validate(false); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	client.snapshotTransferMu.Lock()
	defer client.snapshotTransferMu.Unlock()
	if err := client.prepareSnapshotOutbox(nodewire.SnapshotUploadOperation, manifest, path, operationID); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	result, _, err := client.resumeNodeControlSnapshotLocked(ctx, token, true)
	if err != nil {
		return "", err
	}
	return result.Digest, nil
}

func (client *machineNodeControlClient) downloadWorkspaceSnapshot(ctx context.Context, token string,
	job machineJob, workspace string) error {
	if job.WorkspaceSnapshotDigest == "" {
		return nil
	}
	if err := client.recoverPending(ctx, token); err != nil {
		return err
	}
	operationID, err := newMachineNodeControlOperationID()
	if err != nil {
		return err
	}
	path, err := createMachineNodeSnapshotDownloadStage(client, operationID)
	if err != nil {
		return err
	}
	manifest := nodewire.SnapshotManifest{Version: nodewire.Version,
		Direction: nodewire.SnapshotDirectionDownload, WorkerID: job.WorkerID,
		Attempt: job.Attempt, WorkspaceID: job.WorkspaceID, Digest: job.WorkspaceSnapshotDigest}
	if err := manifest.Validate(true); err != nil {
		_ = os.Remove(path)
		return err
	}
	client.snapshotTransferMu.Lock()
	defer client.snapshotTransferMu.Unlock()
	if err := client.prepareSnapshotOutbox(nodewire.SnapshotDownloadOperation, manifest, path, operationID); err != nil {
		_ = os.Remove(path)
		return err
	}
	_, stage, err := client.resumeNodeControlSnapshotLocked(ctx, token, true)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	metadata, err := snapshot.Inspect(stage)
	if err != nil {
		return err
	}
	if metadata.Digest != job.WorkspaceSnapshotDigest {
		return errors.New("encrypted Hub Workspace snapshot did not match the requested digest")
	}
	_, err = snapshot.UnpackFile(ctx, stage, workspace)
	return err
}

// resumeNodeControlSnapshot recovers only the exact persisted operation and
// packet. Uploads reopen the durable staged archive; downloads restart from
// byte zero into the durable private stage file. No Worker runtime action is
// replayed by this path.
func (client *machineNodeControlClient) resumeNodeControlSnapshot(ctx context.Context,
	token string, keepDownloadStage bool) (snapshot.Snapshot, string, error) {
	client.snapshotTransferMu.Lock()
	defer client.snapshotTransferMu.Unlock()
	return client.resumeNodeControlSnapshotLocked(ctx, token, keepDownloadStage)
}

func (client *machineNodeControlClient) resumeNodeControlSnapshotLocked(ctx context.Context,
	token string, keepDownloadStage bool) (snapshot.Snapshot, string, error) {
	client.mu.Lock()
	state := client.state
	client.mu.Unlock()
	if len(state.PendingPacket) == 0 || state.PendingSnapshotPath == "" ||
		(state.PendingOperation != nodewire.SnapshotUploadOperation &&
			state.PendingOperation != nodewire.SnapshotDownloadOperation) {
		return snapshot.Snapshot{}, "", nil
	}
	if err := validateMachineNodeSnapshotOutboxPath(client, state.PendingOperationID,
		state.PendingSnapshotPath); err != nil {
		return snapshot.Snapshot{}, "", fmt.Errorf("recover Node snapshot outbox: %w", err)
	}
	binding := machineNodeControlBindingFromState(client)
	route, err := machineNodeSnapshotPendingRequestRoute(client, state, binding)
	if err != nil {
		return snapshot.Snapshot{}, "", err
	}
	if state.PendingSnapshotManifest == nil {
		return snapshot.Snapshot{}, "", errors.New("durable Node snapshot manifest metadata is unavailable")
	}
	manifest := *state.PendingSnapshotManifest
	if manifest.WorkerID != state.PendingWorkerID || manifest.Attempt != state.PendingWorkerAttempt {
		return snapshot.Snapshot{}, "", errors.New("durable Node snapshot manifest does not match its Worker fence")
	}
	isUpload := state.PendingOperation == nodewire.SnapshotUploadOperation
	if manifest.Validate(!isUpload) != nil || isUpload && manifest.Direction != nodewire.SnapshotDirectionUpload ||
		!isUpload && manifest.Direction != nodewire.SnapshotDirectionDownload {
		return snapshot.Snapshot{}, "", errors.New("durable Node snapshot manifest violates its operation direction")
	}
	if isUpload {
		metadata, inspectErr := snapshot.Inspect(state.PendingSnapshotPath)
		if inspectErr != nil || metadata.Digest != manifest.Digest || metadata.Size != manifest.Size ||
			metadata.FileCount != manifest.FileCount {
			return snapshot.Snapshot{}, "", errors.New("durable staged archive does not match the exact sealed manifest")
		}
	}
	endpointSuffix := "upload"
	if !isUpload {
		endpointSuffix = "download"
	}
	endpoint := strings.TrimRight(client.base, "/") + "/v2/relay/nodes/" + urlPath(client.nodeID) +
		"/jobs/" + urlPath(manifest.WorkerID) + "/snapshot/" + endpointSuffix
	if !machineHubOriginMatches(ctx, endpoint) {
		return snapshot.Snapshot{}, "", errors.New("Node snapshot stream escaped its pinned Hub origin")
	}
	reader, writer := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		writeErr := nodewire.WriteFrame(writer, state.PendingPacket)
		if writeErr == nil && isUpload {
			writeErr = writeMachineNodeSnapshotUploadFrames(ctx, writer, state.PendingSnapshotPath,
				client.identity, binding, route, manifest)
		}
		_ = writer.CloseWithError(writeErr)
		writeDone <- writeErr
	}()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, reader)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-writeDone
		return snapshot.Snapshot{}, "", err
	}
	request.Header.Set("Authorization", "CicadaNode "+strings.TrimSpace(token))
	request.Header.Set("Content-Type", machineNodeSnapshotContentType)
	request.Header.Set("Accept", machineNodeSnapshotContentType)
	response, err := (&http.Client{Timeout: 20 * time.Minute, CheckRedirect: rejectNodeRedirect}).Do(request)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-writeDone
		return snapshot.Snapshot{}, "", err
	}
	defer response.Body.Close()
	writeErr := <-writeDone
	if response.StatusCode != http.StatusOK {
		return snapshot.Snapshot{}, "", fmt.Errorf("Hub Node-Control snapshot HTTP status %d", response.StatusCode)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), machineNodeSnapshotContentType) {
		return snapshot.Snapshot{}, "", errors.New("Hub returned a non-Node-Control snapshot response")
	}
	responsePacket, err := nodewire.ReadFrame(response.Body, nodewire.MaxPacketBytes)
	if err != nil {
		return snapshot.Snapshot{}, "", fmt.Errorf("read sealed Node snapshot response: %w", err)
	}
	responseOpened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, responsePacket)
	if err != nil || responseOpened.Route != machineNodeSnapshotResponseRoute(route) {
		return snapshot.Snapshot{}, "", errors.New("Hub snapshot response did not authenticate for the exact operation")
	}
	var reply machineNodeSnapshotReply
	if err := decodeMachineNodeControlJSON(responseOpened.Plaintext, &reply); err != nil ||
		reply.OperationID != state.PendingOperationID || reply.Sequence != state.PendingSequence ||
		(reply.OK && (len(reply.Result) == 0 || reply.ErrorCode != "")) ||
		(!reply.OK && (len(reply.Result) != 0 || !machineNodeSnapshotReplyCodeAllowed(reply.ErrorCode))) {
		return snapshot.Snapshot{}, "", errors.New("Hub returned an invalid authenticated snapshot response")
	}
	if !reply.OK {
		if reply.ErrorCode == "IN_PROGRESS" || reply.ErrorCode == "OUTCOME_UNCERTAIN" {
			return snapshot.Snapshot{}, "", errors.New("Node snapshot operation remains pending; exact sealed packet and staged archive retained")
		}
		if isUpload && reply.ErrorCode == "RESULT_EXPIRED" {
			return snapshot.Snapshot{}, "", errors.New("Node snapshot attachment reply expired; exact staged action remains fenced")
		}
		if err := client.clearSnapshotPending(state, responsePacket, state.PendingSnapshotPath); err != nil {
			return snapshot.Snapshot{}, "", err
		}
		if isUpload || !keepDownloadStage {
			_ = os.Remove(state.PendingSnapshotPath)
		}
		return snapshot.Snapshot{}, "", fmt.Errorf("Hub rejected the encrypted workspace snapshot: %s", reply.ErrorCode)
	}
	if writeErr != nil && isUpload {
		// A completed server action can answer before a replayed, already-complete
		// upload body is consumed. Its authenticated cached reply is sufficient.
		_ = writeErr
	}
	var metadata snapshot.Snapshot
	if isUpload {
		if err := decodeMachineNodeControlJSON(reply.Result, &metadata); err != nil ||
			metadata.Digest != manifest.Digest || metadata.Size != manifest.Size || metadata.FileCount != manifest.FileCount {
			return snapshot.Snapshot{}, "", errors.New("Hub snapshot acknowledgement did not match the persisted upload manifest")
		}
		if err := client.clearSnapshotPending(state, responsePacket, state.PendingSnapshotPath); err != nil {
			return snapshot.Snapshot{}, "", err
		}
		_ = os.Remove(state.PendingSnapshotPath)
		return metadata, "", nil
	}
	var responseManifest nodewire.SnapshotManifest
	if err := decodeMachineNodeControlJSON(reply.Result, &responseManifest); err != nil ||
		responseManifest.Validate(false) != nil || responseManifest.Direction != nodewire.SnapshotDirectionDownload ||
		responseManifest.WorkerID != manifest.WorkerID || responseManifest.Attempt != manifest.Attempt ||
		responseManifest.WorkspaceID != manifest.WorkspaceID || responseManifest.Digest != manifest.Digest {
		return snapshot.Snapshot{}, "", errors.New("Hub snapshot manifest did not match the requested Worker/Workspace/digest")
	}
	metadata, err = receiveMachineNodeSnapshotDownloadFrames(ctx, response.Body, state.PendingSnapshotPath,
		client.identity, binding, responseOpened.Route, responseManifest)
	if err != nil {
		return snapshot.Snapshot{}, "", err
	}
	if err := client.clearSnapshotPending(state, responsePacket, state.PendingSnapshotPath); err != nil {
		return snapshot.Snapshot{}, "", err
	}
	if !keepDownloadStage {
		_ = os.Remove(state.PendingSnapshotPath)
		return metadata, "", nil
	}
	return metadata, state.PendingSnapshotPath, nil
}

func writeMachineNodeSnapshotUploadFrames(ctx context.Context, writer io.Writer, path string,
	identity *e2ee.Identity, binding nodewire.Binding,
	route nodewire.Route, manifest nodewire.SnapshotManifest) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	for index := 0; index < manifest.ChunkCount; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		length, err := nodewire.ExpectedSnapshotChunkLength(manifest, index)
		if err != nil {
			return err
		}
		plaintext := make([]byte, length)
		if _, err := io.ReadFull(file, plaintext); err != nil {
			return err
		}
		sealed, err := nodewire.SealSnapshotChunk(identity, binding.HubKey,
			route, manifest, index, plaintext)
		if err != nil {
			return err
		}
		if err := nodewire.WriteFrame(writer, sealed); err != nil {
			return err
		}
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("staged Node snapshot archive contains unexpected trailing bytes")
	}
	return nil
}

func receiveMachineNodeSnapshotDownloadFrames(ctx context.Context, reader io.Reader, path string,
	identity *e2ee.Identity, binding nodewire.Binding, route nodewire.Route,
	manifest nodewire.SnapshotManifest) (snapshot.Snapshot, error) {
	if err := manifest.Validate(false); err != nil {
		return snapshot.Snapshot{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	hasher := sha256.New()
	var total int64
	for index := 0; index < manifest.ChunkCount; index++ {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return snapshot.Snapshot{}, err
		}
		frame, err := nodewire.ReadFrame(reader, nodewire.SnapshotMaxChunkFrame)
		if err != nil {
			_ = file.Close()
			return snapshot.Snapshot{}, fmt.Errorf("read encrypted workspace snapshot chunk %d: %w", index, err)
		}
		plaintext, err := nodewire.OpenSnapshotChunk(identity, binding.HubKey, route, manifest, index, frame)
		if err != nil {
			_ = file.Close()
			return snapshot.Snapshot{}, err
		}
		if _, err := file.Write(plaintext); err != nil {
			_ = file.Close()
			return snapshot.Snapshot{}, err
		}
		_, _ = hasher.Write(plaintext)
		total += int64(len(plaintext))
	}
	var extra [1]byte
	if count, err := reader.Read(extra[:]); count != 0 || err != io.EOF {
		_ = file.Close()
		if count != 0 || err == nil {
			return snapshot.Snapshot{}, nodewire.ErrInvalidSnapshotFrame
		}
		return snapshot.Snapshot{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return snapshot.Snapshot{}, err
	}
	if err := file.Close(); err != nil {
		return snapshot.Snapshot{}, err
	}
	if total != manifest.Size || hex.EncodeToString(hasher.Sum(nil)) != manifest.Digest {
		return snapshot.Snapshot{}, errors.New("encrypted workspace snapshot size or digest mismatch")
	}
	metadata, err := snapshot.Inspect(path)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if metadata.Digest != manifest.Digest || metadata.Size != manifest.Size || metadata.FileCount != manifest.FileCount {
		return snapshot.Snapshot{}, errors.New("encrypted workspace snapshot archive does not match its authenticated manifest")
	}
	return metadata, nil
}

func machineNodeSnapshotReplyCodeAllowed(code string) bool {
	switch code {
	case "IN_PROGRESS", "OUTCOME_UNCERTAIN", "RESULT_EXPIRED", "SNAPSHOT_INVALID",
		"SNAPSHOT_DIGEST_MISMATCH", "SNAPSHOT_UNAVAILABLE":
		return true
	default:
		return false
	}
}

func machineNodeSnapshotFailureCause(message string) string {
	switch {
	case strings.Contains(message, "snapshot HTTP status"):
		return "hub_http_status"
	case strings.Contains(message, "non-Node-Control snapshot response"):
		return "content_type"
	case strings.Contains(message, "did not authenticate"):
		return "response_authentication"
	case strings.Contains(message, "invalid authenticated snapshot response"):
		return "response_decode"
	case strings.Contains(message, "Hub rejected the encrypted workspace snapshot"):
		return "signed_refusal"
	case strings.Contains(message, "manifest did not match"):
		return "manifest_mismatch"
	case strings.Contains(message, "snapshot size or digest mismatch"):
		return "archive_digest"
	case strings.Contains(message, "encrypted workspace snapshot chunk"):
		return "chunk_read_or_authentication"
	case strings.Contains(message, "workspace snapshot chunk"):
		return "chunk_authentication"
	case strings.Contains(message, "changed while its response was being verified"):
		return "snapshot_outbox_state_changed"
	case strings.Contains(message, "outbox path does not match"):
		return "snapshot_outbox_path_mismatch"
	case strings.Contains(message, "packet is invalid"):
		return "snapshot_outbox_packet_invalid"
	case strings.Contains(message, "route differs"):
		return "snapshot_outbox_route_mismatch"
	case strings.Contains(message, "local Node key"):
		return "snapshot_outbox_key_mismatch"
	case strings.Contains(message, "manifest metadata is unavailable"):
		return "snapshot_outbox_manifest_missing"
	case strings.Contains(message, "outbox object"):
		return "snapshot_outbox_object"
	case strings.Contains(message, "private regular directory"):
		return "snapshot_outbox_directory"
	case strings.Contains(message, "recover Node snapshot outbox"):
		return "snapshot_outbox_recovery"
	case strings.Contains(message, "outbox"):
		return "snapshot_outbox_other"
	case strings.Contains(message, "remains pending"):
		return "signed_pending_status"
	case strings.Contains(message, "snapshot frame"):
		return "stream_frame"
	case strings.Contains(message, "workspace snapshot archive"):
		return "archive_validation"
	case strings.Contains(message, "snapshot"):
		return "snapshot_protocol"
	default:
		return "snapshot_transfer"
	}
}

func (client *machineNodeControlClient) clearSnapshotPending(previous machineNodeControlState,
	responsePacket []byte, path string) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.PendingOperationID != previous.PendingOperationID ||
		client.state.PendingSequence != previous.PendingSequence ||
		client.state.PendingSnapshotPath != path {
		return errors.New("Node snapshot outbox changed while its response was being verified")
	}
	current := client.state
	client.state.PendingResponsePacket = append([]byte(nil), responsePacket...)
	client.clearPendingLocked()
	if err := client.persistLocked(); err != nil {
		client.state = current
		return err
	}
	return nil
}
