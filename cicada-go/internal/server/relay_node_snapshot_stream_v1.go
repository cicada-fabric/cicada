package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

const nodeControlSnapshotContentType = "application/x-cicada-node-snapshot-v1"

type nodeControlSnapshotReply struct {
	OK          bool   `json:"ok"`
	Result      any    `json:"result,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	OperationID string `json:"operation_id"`
	Sequence    uint64 `json:"sequence"`
}

type nodeControlSnapshotResult struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   string          `json:"error_code,omitempty"`
	OperationID string          `json:"operation_id"`
	Sequence    uint64          `json:"sequence"`
}

// relayNodeWorkerSnapshotStream handles only encrypted Node-Control snapshot
// transfers. The request packet is the first length-prefixed frame; upload
// data then arrives as independently authenticated 1MiB NIST envelopes.
func (h *Handler) relayNodeWorkerSnapshotStream(response http.ResponseWriter, request *http.Request,
	nodeID, workerID, direction, token string) {
	response.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Control workspace snapshots are unavailable"))
		return
	}
	if !h.relayNodeCredentialCurrent(nodeID, token) {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	if request.Header.Get("Content-Type") != nodeControlSnapshotContentType {
		writeError(response, http.StatusUnsupportedMediaType,
			errors.New("Node workspace snapshots require the encrypted Node-Control stream framing"))
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, int64(nodewire.SnapshotMaxWireBytes))
	packetBytes, err := nodewire.ReadFrame(request.Body, nodewire.MaxRequestPacketBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid encrypted workspace snapshot request frame"))
		return
	}
	keyBinding, err := h.control.NodeControlKeyForCredential(fabricpkg.HashSessionCredential(token), nodeID)
	if err != nil || keyBinding == nil {
		writeError(response, http.StatusUpgradeRequired, errors.New("MIGRATION_BLOCKED: Owner-approved Node-Control key is required"))
		return
	}
	opened, err := h.control.OpenNodeControlRequest(keyBinding, packetBytes)
	if err != nil {
		writeError(response, http.StatusUnauthorized, errors.New("workspace snapshot request did not authenticate under the current Node-Control pin"))
		return
	}
	expectedOperation := nodewire.SnapshotUploadOperation
	if direction == nodewire.SnapshotDirectionDownload {
		expectedOperation = nodewire.SnapshotDownloadOperation
	}
	if opened.Route.NodeID != nodeID || opened.Route.Operation != expectedOperation {
		writeError(response, http.StatusBadRequest, errors.New("workspace snapshot request route does not match this endpoint"))
		return
	}
	rpc := nodeControlSnapshotRPCInput(opened.Route, keyBinding, fabricpkg.HashSessionCredential(token), packetBytes)
	record, exactRetry, err := h.control.NodeControlRPCBegin(rpc)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNodeControlKeyUnauthorized):
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		case errors.Is(err, store.ErrNodeControlRPCUncertain), errors.Is(err, store.ErrNodeControlRPCConflict):
			writeError(response, http.StatusConflict, err)
		case errors.Is(err, store.ErrNodeControlRPCBackpressure):
			writeError(response, http.StatusTooManyRequests, errors.New("Node-Control snapshot action ledger is full"))
		default:
			writeError(response, http.StatusInternalServerError, errors.New("unable to admit Node-Control snapshot request"))
		}
		return
	}
	if record == nil {
		writeError(response, http.StatusInternalServerError, errors.New("Node-Control snapshot replay record is unavailable"))
		return
	}
	if record.State == store.NodeControlRPCUncertain {
		h.writeNodeControlSnapshotStatus(response, keyBinding, opened.Route, rpc, "OUTCOME_UNCERTAIN")
		return
	}
	if record.State == store.NodeControlRPCComplete && len(record.ResponsePacket) == 0 {
		h.writeNodeControlSnapshotStatus(response, keyBinding, opened.Route, rpc, "RESULT_EXPIRED")
		return
	}

	var manifest nodewire.SnapshotManifest
	manifestErr := decodeStrictClientJSON(bytes.NewReader(opened.Plaintext),
		nodewire.MaxRequestPlaintextBytes, &manifest)
	requestDirection := direction == nodewire.SnapshotDirectionDownload
	if manifestErr != nil || manifest.Validate(requestDirection) != nil || manifest.Direction != direction ||
		manifest.WorkerID != workerID {
		if record.State == store.NodeControlRPCComplete {
			if direction == nodewire.SnapshotDirectionDownload {
				h.replayNodeControlSnapshotRefusal(response, opened.Route, rpc, record.ResponsePacket)
			} else {
				_ = writeSnapshotFrame(response, record.ResponsePacket)
			}
			return
		}
		h.completeNodeControlSnapshotFailure(response, keyBinding, opened.Route, rpc, "SNAPSHOT_INVALID")
		return
	}
	if direction == nodewire.SnapshotDirectionUpload {
		h.receiveNodeControlSnapshotUpload(response, request, keyBinding, opened.Route, rpc, manifest,
			record, exactRetry)
		return
	}
	h.sendNodeControlSnapshotDownload(response, request, keyBinding, opened.Route, rpc, manifest,
		record, exactRetry)
}

func nodeControlSnapshotRPCInput(route nodewire.Route, binding *store.NodeControlKeyBinding,
	credentialDigest string, packet []byte) store.NodeControlRPCInput {
	requestDigest := sha256.Sum256(packet)
	return store.NodeControlRPCInput{BindingID: binding.OwnerBindingID, BindingVersion: binding.BindingVersion,
		NodeKeyEpoch: binding.NodeKeyEpoch, NodeID: binding.NodeID, NodeKeyID: binding.NodeKeyID,
		CredentialDigest: credentialDigest, Sequence: route.Sequence, OperationID: route.OperationID,
		Operation: route.Operation, RequestDigest: hex.EncodeToString(requestDigest[:])}
}

func (h *Handler) receiveNodeControlSnapshotUpload(response http.ResponseWriter, request *http.Request,
	binding *store.NodeControlKeyBinding, requestRoute nodewire.Route, rpc store.NodeControlRPCInput,
	manifest nodewire.SnapshotManifest, record *store.NodeControlRPCRecord, exactRetry bool) {
	if record.State == store.NodeControlRPCComplete {
		_ = writeSnapshotFrame(response, record.ResponsePacket)
		return
	}
	if _, err := h.control.CheckBoundNodeWorkspaceSnapshotNodeControl(rpc,
		manifest.WorkerID, manifest.Attempt, manifest.WorkspaceID, true); err != nil {
		h.nodeControlSnapshotGuardError(response, err)
		return
	}
	reader, writer := io.Pipe()
	type receiveResult struct {
		value snapshot.Snapshot
		err   error
	}
	resultChannel := make(chan receiveResult, 1)
	go func() {
		value, err := h.control.ReceiveBoundNodeWorkspaceSnapshotStream(request.Context(), rpc, manifest, reader)
		_ = reader.Close()
		resultChannel <- receiveResult{value: value, err: err}
	}()
	chunkHasher := sha256.New()
	var total int64
	for index := 0; index < manifest.ChunkCount; index++ {
		if _, err := h.control.CheckBoundNodeWorkspaceSnapshotNodeControl(rpc,
			manifest.WorkerID, manifest.Attempt, manifest.WorkspaceID, true); err != nil {
			_ = writer.CloseWithError(err)
			<-resultChannel
			h.nodeControlSnapshotGuardError(response, err)
			return
		}
		frame, err := nodewire.ReadFrame(request.Body, nodewire.SnapshotMaxChunkFrame)
		if err != nil {
			_ = writer.CloseWithError(err)
			<-resultChannel
			if errors.Is(err, nodewire.ErrInvalidSnapshotFrame) || errors.Is(err, http.ErrBodyReadAfterClose) {
				h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_INVALID")
				return
			}
			http.Error(response, "workspace snapshot stream interrupted; exact packet may be retried", http.StatusServiceUnavailable)
			return
		}
		plaintext, err := h.control.OpenNodeControlSnapshotChunk(binding, requestRoute, manifest, index, frame)
		if err != nil {
			_ = writer.CloseWithError(err)
			<-resultChannel
			h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_INVALID")
			return
		}
		if _, err := writer.Write(plaintext); err != nil {
			<-resultChannel
			http.Error(response, "workspace snapshot staging failed; exact packet may be retried", http.StatusServiceUnavailable)
			return
		}
		_, _ = chunkHasher.Write(plaintext)
		total += int64(len(plaintext))
	}
	var trailing [1]byte
	if count, err := request.Body.Read(trailing[:]); count != 0 || err != io.EOF {
		_ = writer.CloseWithError(nodewire.ErrInvalidSnapshotFrame)
		<-resultChannel
		if err == nil || count != 0 {
			h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_INVALID")
			return
		}
		http.Error(response, "workspace snapshot stream interrupted; exact packet may be retried", http.StatusServiceUnavailable)
		return
	}
	if closeErr := writer.Close(); closeErr != nil {
		<-resultChannel
		http.Error(response, "workspace snapshot staging failed; exact packet may be retried", http.StatusServiceUnavailable)
		return
	}
	result := <-resultChannel
	if result.err != nil {
		if errors.Is(result.err, control.ErrNodeWorkspaceSnapshotInvalidArchive) {
			h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_INVALID")
			return
		}
		if errors.Is(result.err, control.ErrNodeWorkspaceSnapshotDigestMismatch) ||
			!strings.EqualFold(hex.EncodeToString(chunkHasher.Sum(nil)), manifest.Digest) || total != manifest.Size {
			h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_DIGEST_MISMATCH")
			return
		}
		http.Error(response, "workspace snapshot storage is unavailable; exact packet may be retried", http.StatusServiceUnavailable)
		return
	}
	if !strings.EqualFold(hex.EncodeToString(chunkHasher.Sum(nil)), manifest.Digest) || total != manifest.Size ||
		result.value.Digest != manifest.Digest || result.value.Size != manifest.Size || result.value.FileCount != manifest.FileCount {
		h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_DIGEST_MISMATCH")
		return
	}
	body, err := nodeControlSnapshotResponseBody(rpc, result.value, "")
	if err != nil {
		http.Error(response, "unable to seal workspace snapshot acknowledgement", http.StatusInternalServerError)
		return
	}
	responsePacket, err := h.sealNodeControlSnapshotReply(binding, requestRoute, body)
	if err != nil {
		http.Error(response, "unable to seal workspace snapshot acknowledgement", http.StatusInternalServerError)
		return
	}
	if err := h.control.AttachBoundNodeWorkspaceSnapshotNodeControl(rpc, manifest, result.value, responsePacket); err != nil {
		h.nodeControlSnapshotGuardError(response, err)
		return
	}
	response.Header().Set("Content-Type", nodeControlSnapshotContentType)
	response.WriteHeader(http.StatusOK)
	_ = writeSnapshotFrame(response, responsePacket)
	_ = exactRetry // PROCESSING snapshot uploads are content-addressed and idempotent.
}

func (h *Handler) sendNodeControlSnapshotDownload(response http.ResponseWriter, request *http.Request,
	binding *store.NodeControlKeyBinding, requestRoute nodewire.Route, rpc store.NodeControlRPCInput,
	requestManifest nodewire.SnapshotManifest, record *store.NodeControlRPCRecord, exactRetry bool) {
	if record.State == store.NodeControlRPCUncertain {
		h.writeNodeControlSnapshotStatus(response, binding, requestRoute, rpc, "OUTCOME_UNCERTAIN")
		return
	}
	var responsePacket []byte
	var manifest nodewire.SnapshotManifest
	if record.State == store.NodeControlRPCComplete {
		responsePacket = append([]byte(nil), record.ResponsePacket...)
		packet, packetErr := nodewire.DecodePacket(responsePacket)
		if packetErr != nil || !sameNodeControlResponseRoute(packet.Route, requestRoute) {
			writeError(response, http.StatusConflict, errors.New("cached workspace snapshot response is invalid"))
			return
		}
		projection, projectionErr := h.control.NodeControlSnapshotRPCResponseProjection(rpc, requestRoute)
		if projectionErr != nil || projection == nil {
			writeError(response, http.StatusConflict, errors.New("MIGRATION_BLOCKED: cached workspace snapshot response projection is missing or invalid"))
			return
		}
		if projection.ErrorCode != "" {
			h.replayNodeControlSnapshotRefusal(response, requestRoute, rpc, responsePacket)
			return
		}
		if projection.Manifest == nil {
			writeError(response, http.StatusConflict, errors.New("cached workspace snapshot success projection is invalid"))
			return
		}
		manifest = *projection.Manifest
		if manifest.Validate(false) != nil ||
			manifest.Direction != nodewire.SnapshotDirectionDownload ||
			manifest.Digest != requestManifest.Digest || manifest.WorkerID != requestManifest.WorkerID ||
			manifest.Attempt != requestManifest.Attempt || manifest.WorkspaceID != requestManifest.WorkspaceID {
			writeError(response, http.StatusConflict, errors.New("cached workspace snapshot manifest does not match the request"))
			return
		}
	}
	file, metadata, err := h.control.OpenBoundNodeWorkspaceSnapshotNodeControl(rpc,
		requestManifest, record.State != store.NodeControlRPCComplete)
	if err != nil {
		if errors.Is(err, store.ErrNodeControlKeyUnauthorized) || errors.Is(err, store.ErrNodeWorkerNotAuthorized) {
			h.nodeControlSnapshotGuardError(response, err)
			return
		}
		if record.State != store.NodeControlRPCComplete {
			h.completeNodeControlSnapshotFailure(response, binding, requestRoute, rpc, "SNAPSHOT_UNAVAILABLE")
			return
		}
		writeError(response, http.StatusNotFound, errors.New("workspace snapshot is unavailable"))
		return
	}
	defer file.Close()
	if record.State != store.NodeControlRPCComplete {
		manifest = requestManifest
		manifest.Size, manifest.FileCount = metadata.Size, metadata.FileCount
		manifest.ChunkSize, manifest.ChunkCount = nodewire.SnapshotChunkBytes,
			int((metadata.Size+nodewire.SnapshotChunkBytes-1)/nodewire.SnapshotChunkBytes)
	}
	if manifest.Validate(false) != nil || manifest.Digest != metadata.Digest ||
		manifest.Size != metadata.Size || manifest.FileCount != metadata.FileCount {
		writeError(response, http.StatusConflict, errors.New("workspace snapshot metadata changed"))
		return
	}
	if record.State != store.NodeControlRPCComplete {
		body, bodyErr := nodeControlSnapshotResponseBody(rpc, manifest, "")
		if bodyErr != nil {
			writeError(response, http.StatusInternalServerError, errors.New("unable to encode workspace snapshot manifest"))
			return
		}
		responsePacket, err = h.sealNodeControlSnapshotReply(binding, requestRoute, body)
		if err != nil {
			writeError(response, http.StatusInternalServerError, errors.New("unable to seal workspace snapshot manifest"))
			return
		}
		if err := h.control.NodeControlRPCComplete(store.NodeControlRPCCompletion{
			NodeControlRPCInput: rpc, ResponsePacket: responsePacket,
			SnapshotRequestRoute: &requestRoute, SnapshotManifest: &manifest}); err != nil {
			h.nodeControlSnapshotGuardError(response, err)
			return
		}
	}
	response.Header().Set("Content-Type", nodeControlSnapshotContentType)
	response.WriteHeader(http.StatusOK)
	if err := writeSnapshotFrame(response, responsePacket); err != nil {
		return
	}
	// The manifest response is sealed Hub-to-Node. The Hub cannot decrypt its
	// own response; derive the authenticated direction-bound route from the
	// request we already opened and use it for each independently sealed chunk.
	chunkRoute := nodeControlSnapshotResponseRoute(requestRoute)
	for index := 0; index < manifest.ChunkCount; index++ {
		if err := h.control.CheckBoundNodeWorkspaceSnapshotDownloadChunk(rpc, manifest); err != nil {
			return
		}
		length, err := nodewire.ExpectedSnapshotChunkLength(manifest, index)
		if err != nil {
			return
		}
		chunk := make([]byte, length)
		if _, err := io.ReadFull(file, chunk); err != nil {
			return
		}
		sealed, err := h.control.SealNodeControlSnapshotChunk(binding, chunkRoute, manifest, index, chunk)
		if err != nil || writeSnapshotFrame(response, sealed) != nil {
			return
		}
	}
	_ = exactRetry // A repeated completed download is safe to stream again from the exact current CAS object.
}

func (h *Handler) sealNodeControlSnapshotReply(binding *store.NodeControlKeyBinding,
	requestRoute nodewire.Route, body []byte) ([]byte, error) {
	route := nodeControlSnapshotResponseRoute(requestRoute)
	return h.control.SealNodeControlResponse(binding, route, body)
}

func nodeControlSnapshotResponseRoute(requestRoute nodewire.Route) nodewire.Route {
	route := requestRoute
	route.Direction = nodewire.DirectionResponse
	route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	return route
}

func sameNodeControlResponseRoute(responseRoute, requestRoute nodewire.Route) bool {
	expected := nodeControlSnapshotResponseRoute(requestRoute)
	return responseRoute == expected
}

func nodeControlSnapshotResponseBody(rpc store.NodeControlRPCInput, result any, errorCode string) ([]byte, error) {
	reply := nodeControlSnapshotReply{OperationID: rpc.OperationID, Sequence: rpc.Sequence}
	if errorCode == "" {
		if result == nil {
			return nil, errors.New("workspace snapshot response result is required")
		}
		reply.OK, reply.Result = true, result
	} else {
		reply.ErrorCode = errorCode
	}
	encoded, err := json.Marshal(reply)
	if err != nil || len(encoded) == 0 || len(encoded) > nodewire.MaxPlaintextBytes {
		return nil, errors.New("workspace snapshot response exceeds the Node-Control plaintext limit")
	}
	return encoded, nil
}

func (h *Handler) completeNodeControlSnapshotFailure(response http.ResponseWriter,
	binding *store.NodeControlKeyBinding, requestRoute nodewire.Route,
	rpc store.NodeControlRPCInput, errorCode string) {
	body, err := nodeControlSnapshotResponseBody(rpc, nil, errorCode)
	if err != nil {
		writeError(response, http.StatusInternalServerError, errors.New("unable to encode Node-Control snapshot refusal"))
		return
	}
	packet, err := h.sealNodeControlSnapshotReply(binding, requestRoute, body)
	if err != nil {
		writeError(response, http.StatusInternalServerError, errors.New("unable to seal Node-Control snapshot refusal"))
		return
	}
	completion := store.NodeControlRPCCompletion{NodeControlRPCInput: rpc, ResponsePacket: packet}
	if rpc.Operation == nodewire.SnapshotDownloadOperation {
		completion.SnapshotRequestRoute = &requestRoute
		completion.SnapshotErrorCode = errorCode
	}
	if err := h.control.NodeControlRPCComplete(completion); err != nil {
		h.nodeControlSnapshotGuardError(response, err)
		return
	}
	response.Header().Set("Content-Type", nodeControlSnapshotContentType)
	response.WriteHeader(http.StatusOK)
	_ = writeSnapshotFrame(response, packet)
}

func (h *Handler) replayNodeControlSnapshotRefusal(response http.ResponseWriter, requestRoute nodewire.Route,
	rpc store.NodeControlRPCInput, responsePacket []byte) {
	packet, packetErr := nodewire.DecodePacket(responsePacket)
	if packetErr != nil || !sameNodeControlResponseRoute(packet.Route, requestRoute) {
		writeError(response, http.StatusConflict, errors.New("cached workspace snapshot refusal packet is invalid"))
		return
	}
	projection, projectionErr := h.control.NodeControlSnapshotRPCResponseProjection(rpc, requestRoute)
	if projectionErr != nil || projection == nil || projection.ErrorCode == "" || projection.Manifest != nil {
		writeError(response, http.StatusConflict, errors.New("cached workspace snapshot refusal projection is unavailable"))
		return
	}
	response.Header().Set("Content-Type", nodeControlSnapshotContentType)
	response.WriteHeader(http.StatusOK)
	_ = writeSnapshotFrame(response, responsePacket)
}

func (h *Handler) writeNodeControlSnapshotStatus(response http.ResponseWriter,
	binding *store.NodeControlKeyBinding, requestRoute nodewire.Route, rpc store.NodeControlRPCInput,
	errorCode string) {
	body, err := nodeControlSnapshotResponseBody(rpc, nil, errorCode)
	if err != nil {
		writeError(response, http.StatusInternalServerError, errors.New("unable to encode Node-Control snapshot status"))
		return
	}
	packet, err := h.sealNodeControlSnapshotReply(binding, requestRoute, body)
	if err != nil {
		writeError(response, http.StatusInternalServerError, errors.New("unable to seal Node-Control snapshot status"))
		return
	}
	response.Header().Set("Content-Type", nodeControlSnapshotContentType)
	response.WriteHeader(http.StatusOK)
	_ = writeSnapshotFrame(response, packet)
}

func (h *Handler) nodeControlSnapshotGuardError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNodeControlKeyUnauthorized), errors.Is(err, store.ErrNodeWorkerNotAuthorized):
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
	case errors.Is(err, store.ErrNodeWorkerUnavailable), errors.Is(err, control.ErrWorkerUnavailable):
		writeError(response, http.StatusConflict, errors.New("Node Worker attempt is no longer current"))
	case errors.Is(err, store.ErrNodeControlRPCUncertain), errors.Is(err, store.ErrNodeControlRPCConflict):
		writeError(response, http.StatusConflict, errors.New("Node-Control snapshot request is no longer current"))
	default:
		writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control snapshot guard is unavailable"))
	}
}

func writeSnapshotFrame(response http.ResponseWriter, frame []byte) error {
	return nodewire.WriteFrame(response, frame)
}
