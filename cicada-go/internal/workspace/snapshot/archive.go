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
	"time"
)

// MaxArchiveBytes bounds both upload and restore work. A snapshot contains
// only workspace files; the control plane never stores model credentials.
const MaxArchiveBytes int64 = 256 << 20

type Snapshot struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	FileCount int    `json:"file_count"`
}

// Pack writes a deterministic tar stream and returns its content address.
func Pack(ctx context.Context, root string, output io.Writer) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	info, err := os.Stat(root)
	if err != nil {
		return Snapshot{}, err
	}
	if !info.IsDir() {
		return Snapshot{}, errors.New("workspace snapshot root must be a directory")
	}
	hasher := sha256.New()
	writer := &boundedWriter{writer: io.MultiWriter(output, hasher), max: MaxArchiveBytes}
	tarWriter := tar.NewWriter(writer)
	files := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace snapshot refuses symlink: %s", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("workspace snapshot refuses special file: %s", relative)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		header.ModTime = time.Unix(0, 0).UTC()
		header.AccessTime = time.Time{}
		header.ChangeTime = time.Time{}
		header.Uname, header.Gname, header.PAXRecords = "", "", nil
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tarWriter, &contextReader{ctx: ctx, reader: file})
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			files++
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	if err := tarWriter.Close(); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Digest: hex.EncodeToString(hasher.Sum(nil)), Size: writer.size, FileCount: files}, nil
}

type boundedWriter struct {
	writer io.Writer
	max    int64
	size   int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.max-w.size {
		return 0, errors.New("workspace snapshot exceeds size limit")
	}
	count, err := w.writer.Write(data)
	w.size += int64(count)
	return count, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func safeEntryName(name string) (string, error) {
	if strings.TrimSpace(name) == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") {
		return "", errors.New("workspace snapshot contains an invalid path")
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("workspace snapshot path escapes its root")
	}
	if filepath.ToSlash(clean) != name {
		return "", errors.New("workspace snapshot path is not canonical")
	}
	return clean, nil
}
