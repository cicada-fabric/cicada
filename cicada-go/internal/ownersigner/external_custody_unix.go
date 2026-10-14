//go:build !windows

package ownersigner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func validateExternalRegularPath(path string, max int64) error {
	if !filepath.IsAbs(path) || !safePathText(path) {
		return errors.New("path is not absolute and safe")
	}
	if err := rejectUnixSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (max > 0 && info.Size() > max) {
		return errors.New("path is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("file changed during open")
	}
	return nil
}

func validateExternalPrivateFile(path string, max int64) error {
	if err := validateExternalRegularPath(path, max); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		return errors.New("encrypted private PEM must have mode 0600")
	}
	return nil
}

func checkExternalPrivateFile(path string) error {
	if err := validateExternalRegularPath(path, 0); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		return errors.New("private file must have mode 0600")
	}
	return nil
}

func openExternalRegularFile(path string) (*os.File, error) {
	if err := validateExternalRegularPath(path, 0); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func checkExternalPrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || !safePathText(path) || rejectUnixSymlinkComponents(path) != nil {
		return errors.New("private directory path is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("private directory must have mode 0700")
	}
	return nil
}

func validateExternalParentDirectory(path string) error {
	if rejectUnixSymlinkComponents(path) != nil {
		return errors.New("Owner profile parent contains a symlink or unavailable component")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return errors.New("Owner profile parent must be an existing directory")
	}
	return nil
}

func createExternalPrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0700); err != nil {
		_ = os.Remove(path)
		return err
	}
	return checkExternalPrivateDirectory(path)
}

func createExternalPrivateTempDir(parent string) (string, error) {
	if err := checkExternalPrivateDirectory(parent); err != nil {
		return "", err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	path := filepath.Join(parent, "openssl-op-"+hex.EncodeToString(random[:]))
	if err := createExternalPrivateDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

func createExternalPrivateFile(dir, prefix string, data []byte) (string, error) {
	if err := checkExternalPrivateDirectory(dir); err != nil || strings.ContainsAny(prefix, `/\\`) {
		return "", errors.New("private temporary directory is unsafe")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	path := filepath.Join(dir, prefix+hex.EncodeToString(random[:]))
	if err := createExternalPrivateFileAt(path, data); err != nil {
		return "", err
	}
	return path, nil
}

func createExternalPrivateFileAt(path string, data []byte) error {
	if !filepath.IsAbs(path) || rejectUnixSymlinkComponents(filepath.Dir(path)) != nil || !safePathText(path) {
		return errors.New("private file path is unsafe")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = file.Chmod(0600); err == nil && len(data) != 0 {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func readExternalPrivateFile(path string, max int64) ([]byte, error) {
	if err := checkExternalPrivateFile(path); err != nil {
		return nil, err
	}
	file, err := openExternalRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("private profile file size is invalid")
	}
	return data, nil
}

func replaceExternalAtomic(path string, data []byte) error {
	if err := rejectUnixSymlinkComponents(filepath.Dir(path)); err != nil {
		return err
	}
	if err := checkExternalPrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := checkExternalPrivateFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), ".owner-signer-state-"+hex.EncodeToString(random[:]))
	if err := createExternalPrivateFileAt(temporary, data); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeExternalPublicExclusiveOrSame(path string, data []byte) error {
	return writePublicExclusiveOrSame(path, data)
}

func writeExternalPrivateExclusive(path string, data []byte) error {
	if len(data) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || validateExternalParentDirectory(filepath.Dir(path)) != nil {
		return errors.New("private grant output path is invalid")
	}
	return createExternalPrivateFileAt(path, data)
}

func writeExternalPublicExclusive(path string, data []byte) error {
	if len(data) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || validateExternalParentDirectory(filepath.Dir(path)) != nil {
		return errors.New("public summary output path is invalid")
	}
	return writeExclusive(path, data, 0644)
}

func readExternalOperationFile(path string, max int64) ([]byte, error) {
	if err := validateExternalPrivateFile(path, max); err != nil {
		return nil, err
	}
	file, err := openExternalRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("OpenSSL output size is invalid")
	}
	return data, nil
}

func rejectUnixSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	if clean != path {
		return errors.New("path is not canonical")
	}
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(rest, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symlink or unavailable component")
		}
	}
	return nil
}
