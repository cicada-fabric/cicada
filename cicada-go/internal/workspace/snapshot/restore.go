package snapshot

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Inspect validates an archive and computes the same digest returned by Pack.
func Inspect(path string) (Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()
	return readArchive(context.Background(), file, "", MaxArchiveBytes)
}

// UnpackFile validates and atomically replaces target with an archive.
func UnpackFile(ctx context.Context, archivePath, target string) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(target) == "" {
		return Snapshot{}, errors.New("snapshot target is required")
	}
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return Snapshot{}, errors.New("snapshot target cannot be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Snapshot{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".cicada-snapshot-")
	if err != nil {
		return Snapshot{}, err
	}
	defer os.RemoveAll(temporary)
	file, err := os.Open(archivePath)
	if err != nil {
		return Snapshot{}, err
	}
	result, err := readArchive(ctx, file, temporary, MaxArchiveBytes)
	closeErr := file.Close()
	if err != nil {
		return Snapshot{}, err
	}
	if closeErr != nil {
		return Snapshot{}, closeErr
	}
	backup := target + ".old"
	_ = os.RemoveAll(backup)
	if _, err := os.Lstat(target); err == nil {
		if err := os.Rename(target, backup); err != nil {
			return Snapshot{}, err
		}
	}
	if err := os.Rename(temporary, target); err != nil {
		_ = os.Rename(backup, target)
		return Snapshot{}, err
	}
	_ = os.RemoveAll(backup)
	return result, nil
}

func readArchive(ctx context.Context, input io.Reader, destination string, max int64) (Snapshot, error) {
	hasher := sha256.New()
	counted := &countingReader{reader: io.LimitReader(input, max+1)}
	reader := io.TeeReader(counted, hasher)
	tarReader := tar.NewReader(reader)
	seen := map[string]bool{}
	files := 0
	for {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Snapshot{}, fmt.Errorf("read workspace snapshot: %w", err)
		}
		name, err := safeEntryName(header.Name)
		if err != nil {
			return Snapshot{}, err
		}
		if seen[name] {
			return Snapshot{}, errors.New("workspace snapshot contains duplicate paths")
		}
		seen[name] = true
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg {
			return Snapshot{}, errors.New("workspace snapshot contains an unsupported entry type")
		}
		if header.Size < 0 || header.Size > max {
			return Snapshot{}, errors.New("workspace snapshot exceeds size limit")
		}
		if header.Typeflag == tar.TypeDir {
			if destination != "" {
				if err := os.MkdirAll(filepath.Join(destination, name), 0o755); err != nil {
					return Snapshot{}, err
				}
			}
			continue
		}
		if destination == "" {
			if _, err := io.Copy(io.Discard, &contextReader{ctx: ctx, reader: tarReader}); err != nil {
				return Snapshot{}, err
			}
		} else {
			path := filepath.Join(destination, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return Snapshot{}, err
			}
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return Snapshot{}, err
			}
			_, copyErr := io.Copy(file, &contextReader{ctx: ctx, reader: tarReader})
			closeErr := file.Close()
			if copyErr != nil {
				return Snapshot{}, copyErr
			}
			if closeErr != nil {
				return Snapshot{}, closeErr
			}
		}
		files++
	}
	// Drain the source so the digest includes tar padding and detect a stream
	// larger than the limit even when the tar reader already reached EOF.
	var tail [32 * 1024]byte
	for {
		count, err := reader.Read(tail[:])
		if counted.count > max {
			return Snapshot{}, errors.New("workspace snapshot exceeds size limit")
		}
		for _, value := range tail[:count] {
			if value != 0 {
				return Snapshot{}, errors.New("workspace snapshot has trailing data")
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Snapshot{}, err
		}
	}
	return Snapshot{Digest: hex.EncodeToString(hasher.Sum(nil)), Size: counted.count, FileCount: files}, nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(data []byte) (int, error) {
	count, err := r.reader.Read(data)
	r.count += int64(count)
	return count, err
}
