package componentinstall

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func checkManagedDirectory(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	return validateManagedDirectory(info)
}

// Pin every directory inode as it is traversed. Later operations use the
// returned handle, so replacing an ancestor pathname cannot redirect a write.
func openDirectory(name string, create bool) (*os.Root, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errors.New("component paths must be absolute and canonical")
	}
	start := filepath.VolumeName(name) + string(filepath.Separator)
	root, err := os.OpenRoot(start)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, start), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		next, err := openChildDirectory(root, part, create)
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		root = next
	}
	return root, nil
}

func openChildDirectory(root *os.Root, name string, create bool) (*os.Root, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := root.Mkdir(name, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		before, err = root.Lstat(name)
	}
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("component directory must not be a symlink or file")
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	after, afterErr := root.Lstat(name)
	if err != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		_ = child.Close()
		return nil, errors.New("component directory changed while opening")
	}
	return child, nil
}

func openRelativeParent(root *os.Root, name string, create bool) (*os.Root, string, error) {
	if !filepath.IsLocal(name) || filepath.Clean(name) != name {
		return nil, "", errors.New("unsafe component relative path")
	}
	parent, err := root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(name, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, err := openChildDirectory(parent, part, create)
		_ = parent.Close()
		if err != nil {
			return nil, "", err
		}
		parent = next
	}
	return parent, parts[len(parts)-1], nil
}

func readRegularAt(root *os.Root, name string, limit int64) ([]byte, error) {
	parent, base, err := openRelativeParent(root, name, false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	before, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("component input must be a bounded existing regular file")
	}
	f, err := parent.Open(base)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	after, afterErr := parent.Lstat(base)
	if err != nil || afterErr != nil || !after.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, errors.New("component input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > limit {
		return nil, errors.New("component input changed size while reading")
	}
	return data, nil
}

func writeNewFileAt(root *os.Root, name string, data []byte, mode fs.FileMode) error {
	parent, base, err := openRelativeParent(root, name, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	f, err := parent.OpenFile(base, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

func removeRegularAt(root *os.Root, name string) error {
	parent, base, err := openRelativeParent(root, name, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	info, err := parent.Lstat(base)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("component file changed before removal")
	}
	return parent.Remove(base)
}

func lockComponents(root *os.Root) (*os.File, error) {
	const name = ".component-files.lock"
	for attempt := 0; attempt < 2; attempt++ {
		before, err := root.Lstat(name)
		flags := os.O_RDWR
		if errors.Is(err, fs.ErrNotExist) {
			flags |= os.O_CREATE | os.O_EXCL
		} else if err != nil || !before.Mode().IsRegular() || runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 {
			return nil, errors.New("component operation lock is unsafe")
		}
		file, err := root.OpenFile(name, flags, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		opened, err := file.Stat()
		after, afterErr := root.Lstat(name)
		if err != nil || afterErr != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || before != nil && !os.SameFile(before, opened) {
			_ = file.Close()
			return nil, errors.New("component operation lock changed while opening")
		}
		if err := tryFileLock(file); err != nil {
			_ = file.Close()
			return nil, errors.New("component files are busy; no component was changed")
		}
		return file, nil // Closing the descriptor releases the OS lock.
	}
	return nil, errors.New("component operation lock changed repeatedly")
}
