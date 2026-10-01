package nodewire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

const (
	SnapshotUploadOperation   = "node.workspace.snapshot.upload"
	SnapshotDownloadOperation = "node.workspace.snapshot.download"
	SnapshotDirectionUpload   = "UPLOAD"
	SnapshotDirectionDownload = "DOWNLOAD"
	SnapshotChunkBytes        = 1 << 20
	SnapshotMaxChunkFrame     = 2 << 20
	SnapshotMaxWireBytes      = 512 << 20
	snapshotChunkAADDomain    = "cicada/node-control/workspace-snapshot/chunk/v1\x00"
)

var ErrInvalidSnapshotFrame = errors.New("invalid Node-Control workspace snapshot frame")

// SnapshotManifest is carried inside a Node-Control packet. The HTTP framing
// contains no plaintext worker, workspace, or content metadata.
type SnapshotManifest struct {
	Version     int    `json:"version"`
	Direction   string `json:"direction"`
	WorkerID    string `json:"worker_id"`
	Attempt     int    `json:"attempt"`
	WorkspaceID string `json:"workspace_id"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	FileCount   int    `json:"file_count"`
	ChunkSize   int    `json:"chunk_size"`
	ChunkCount  int    `json:"chunk_count"`
}

func (manifest SnapshotManifest) Validate(request bool) error {
	if manifest.Version != Version || manifest.Direction != SnapshotDirectionUpload &&
		manifest.Direction != SnapshotDirectionDownload || !validToken(manifest.WorkerID) ||
		manifest.Attempt <= 0 || !validToken(manifest.WorkspaceID) || !validSnapshotDigest(manifest.Digest) {
		return ErrInvalidSnapshotFrame
	}
	if manifest.Direction == SnapshotDirectionDownload && request {
		if manifest.Size != 0 || manifest.FileCount != 0 || manifest.ChunkSize != 0 || manifest.ChunkCount != 0 {
			return ErrInvalidSnapshotFrame
		}
		return nil
	}
	if manifest.Size <= 0 || manifest.Size > snapshot.MaxArchiveBytes || manifest.FileCount < 0 ||
		manifest.ChunkSize != SnapshotChunkBytes || manifest.ChunkCount != snapshotChunkCount(manifest.Size) {
		return ErrInvalidSnapshotFrame
	}
	return nil
}

func validSnapshotDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func snapshotChunkCount(size int64) int {
	return int((size + SnapshotChunkBytes - 1) / SnapshotChunkBytes)
}

func ExpectedSnapshotChunkLength(manifest SnapshotManifest, index int) (int, error) {
	if manifest.Validate(false) != nil || index < 0 || index >= manifest.ChunkCount {
		return 0, ErrInvalidSnapshotFrame
	}
	if index != manifest.ChunkCount-1 {
		return SnapshotChunkBytes, nil
	}
	last := int(manifest.Size - int64(index*SnapshotChunkBytes))
	if last <= 0 || last > SnapshotChunkBytes {
		return 0, ErrInvalidSnapshotFrame
	}
	return last, nil
}

func snapshotChunkAAD(route Route, manifest SnapshotManifest, direction string, index int) ([]byte, error) {
	if direction != SnapshotDirectionUpload && direction != SnapshotDirectionDownload || index < 0 {
		return nil, ErrInvalidSnapshotFrame
	}
	encodedRoute, err := json.Marshal(route)
	if err != nil {
		return nil, err
	}
	encodedManifest, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	manifestDigest := sha256.Sum256(encodedManifest)
	result := append([]byte(snapshotChunkAADDomain), encodedRoute...)
	result = append(result, 0)
	result = append(result, []byte(direction)...)
	result = append(result, 0)
	result = append(result, manifestDigest[:]...)
	var encodedIndex [8]byte
	binary.BigEndian.PutUint64(encodedIndex[:], uint64(index))
	result = append(result, encodedIndex[:]...)
	return result, nil
}

func SealSnapshotChunk(sender *e2ee.Identity, receiver e2ee.PublicIdentity, route Route,
	manifest SnapshotManifest, index int, plaintext []byte) ([]byte, error) {
	if sender == nil || route.Operation != snapshotOperation(manifest.Direction) ||
		!snapshotRouteDirectionMatches(route, manifest.Direction) {
		return nil, ErrInvalidSnapshotFrame
	}
	expected, err := ExpectedSnapshotChunkLength(manifest, index)
	if err != nil || len(plaintext) != expected || len(plaintext) > SnapshotChunkBytes {
		return nil, ErrInvalidSnapshotFrame
	}
	associatedData, err := snapshotChunkAAD(route, manifest, manifest.Direction, index)
	if err != nil {
		return nil, err
	}
	return e2ee.Seal(sender, receiver, plaintext, associatedData, uint64(index+1))
}

func OpenSnapshotChunk(recipient *e2ee.Identity, sender e2ee.PublicIdentity, route Route,
	manifest SnapshotManifest, index int, envelope []byte) ([]byte, error) {
	if recipient == nil || len(envelope) == 0 || len(envelope) > SnapshotMaxChunkFrame ||
		route.Operation != snapshotOperation(manifest.Direction) || !snapshotRouteDirectionMatches(route, manifest.Direction) {
		return nil, ErrInvalidSnapshotFrame
	}
	associatedData, err := snapshotChunkAAD(route, manifest, manifest.Direction, index)
	if err != nil {
		return nil, err
	}
	plaintext, sequence, err := e2ee.Open(recipient, sender, envelope, associatedData)
	if err != nil {
		return nil, fmt.Errorf("open workspace snapshot chunk: %w", err)
	}
	expected, err := ExpectedSnapshotChunkLength(manifest, index)
	if err != nil || sequence != uint64(index+1) || len(plaintext) != expected {
		return nil, ErrInvalidSnapshotFrame
	}
	return plaintext, nil
}

func snapshotOperation(direction string) string {
	if direction == SnapshotDirectionUpload {
		return SnapshotUploadOperation
	}
	return SnapshotDownloadOperation
}

func snapshotRouteDirectionMatches(route Route, direction string) bool {
	if direction == SnapshotDirectionUpload {
		return route.Direction == DirectionRequest
	}
	return route.Direction == DirectionResponse
}

func WriteFrame(writer io.Writer, frame []byte) error {
	if writer == nil || len(frame) == 0 || len(frame) > SnapshotMaxWireBytes {
		return ErrInvalidSnapshotFrame
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	if n, err := writer.Write(prefix[:]); err != nil {
		return err
	} else if n != len(prefix) {
		return io.ErrShortWrite
	}
	if n, err := writer.Write(frame); err != nil {
		return err
	} else if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

func ReadFrame(reader io.Reader, maxBytes int) ([]byte, error) {
	if reader == nil || maxBytes <= 0 || maxBytes > SnapshotMaxWireBytes {
		return nil, ErrInvalidSnapshotFrame
	}
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(prefix[:]))
	if length <= 0 || length > maxBytes {
		return nil, ErrInvalidSnapshotFrame
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, err
	}
	return frame, nil
}
