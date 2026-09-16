package cas

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

// Store keeps immutable workspace archives addressed by SHA-256.
type Store struct {
	root string
}

func New(root string) (*Store, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("workspace snapshot store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) Put(ctx context.Context, input io.Reader) (snapshot.Snapshot, error) {
	if s == nil || s.root == "" {
		return snapshot.Snapshot{}, errors.New("workspace snapshot store is not initialized")
	}
	if input == nil {
		return snapshot.Snapshot{}, errors.New("workspace snapshot input is required")
	}
	temporary, err := os.CreateTemp(s.root, ".upload-*")
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, &contextReader{ctx: ctx, reader: io.LimitReader(input, snapshot.MaxArchiveBytes+1)}); err != nil {
		_ = temporary.Close()
		return snapshot.Snapshot{}, err
	}
	if err := temporary.Close(); err != nil {
		return snapshot.Snapshot{}, err
	}
	result, err := snapshot.Inspect(temporaryPath)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if result.Size > snapshot.MaxArchiveBytes {
		return snapshot.Snapshot{}, errors.New("workspace snapshot exceeds size limit")
	}
	objectPath, err := s.objectPath(result.Digest)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		return snapshot.Snapshot{}, err
	}
	if _, err := os.Stat(objectPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(temporaryPath, objectPath); err != nil {
			return snapshot.Snapshot{}, fmt.Errorf("store workspace snapshot: %w", err)
		}
	} else if err != nil {
		return snapshot.Snapshot{}, err
	}
	return result, nil
}

func (s *Store) PutPath(ctx context.Context, root string) (snapshot.Snapshot, error) {
	temporary, err := os.CreateTemp(s.root, ".pack-*")
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	result, packErr := snapshot.Pack(ctx, root, temporary)
	closeErr := temporary.Close()
	if packErr != nil {
		return snapshot.Snapshot{}, packErr
	}
	if closeErr != nil {
		return snapshot.Snapshot{}, closeErr
	}
	objectPath, err := s.objectPath(result.Digest)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		return snapshot.Snapshot{}, err
	}
	if _, err := os.Stat(objectPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(temporaryPath, objectPath); err != nil {
			return snapshot.Snapshot{}, err
		}
	} else if err != nil {
		return snapshot.Snapshot{}, err
	}
	return result, nil
}

func (s *Store) Open(digest string) (*os.File, snapshot.Snapshot, error) {
	path, err := s.objectPath(digest)
	if err != nil {
		return nil, snapshot.Snapshot{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, snapshot.Snapshot{}, err
	}
	result, err := snapshot.Inspect(path)
	if err != nil {
		_ = file.Close()
		return nil, snapshot.Snapshot{}, err
	}
	if result.Digest != strings.TrimSpace(digest) {
		_ = file.Close()
		return nil, snapshot.Snapshot{}, errors.New("workspace snapshot object digest mismatch")
	}
	return file, result, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(data []byte) (int, error) {
	if r.ctx != nil {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(data)
}

func (s *Store) objectPath(digest string) (string, error) {
	if len(digest) != sha256HexLength || !isHex(digest) {
		return "", errors.New("workspace snapshot digest must be a SHA-256 hex value")
	}
	return filepath.Join(s.root, digest[:2], digest+".tar"), nil
}

const sha256HexLength = 64

func isHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}
