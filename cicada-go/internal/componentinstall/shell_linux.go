package componentinstall

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const shellReceiptName = ".shell-command.json"
const shellBegin = "# >>> Cicada managed command >>>"
const shellEnd = "# <<< Cicada managed command <<<"

type shellReceipt struct {
	Format        string `json:"format"`
	Prefix        string `json:"prefix"`
	Separator     bool   `json:"separator"`
	BashrcCreated bool   `json:"bashrc_created"`
}

type shellFile struct {
	info fs.FileInfo
	data []byte
}

type shellPlan struct {
	home, root, bin               *os.Root
	lock                          *os.File
	prefix                        string
	receipt                       shellReceipt
	receiptFile, launcher, bashrc shellFile
	block                         []byte
	noop                          bool
	result                        shellIntegrationResult
}

func shellLauncher(prefix string) []byte {
	node := codexShellQuote(filepath.Join(prefix, "components", "node"))
	hub := codexShellQuote(filepath.Join(prefix, "components", "hub"))
	return []byte("#!/bin/sh\n# Cicada managed command v1\nif [ -f " + node + "/INSTALL-MANIFEST.json ] && [ -x " + node + "/bin/cicada ]; then\n  exec " + node + "/bin/cicada \"$@\"\nfi\nif [ -f " + hub + "/INSTALL-MANIFEST.json ] && [ -x " + hub + "/bin/cicada ]; then\n  exec " + hub + "/bin/cicada \"$@\"\nfi\nprintf '%s\\n' 'Cicada components are unavailable; reinstall the original component files.' >&2\nexit 127\n")
}

func shellBlock(home string, separator bool) []byte {
	prefix := ""
	if separator {
		prefix = "\n"
	}
	return []byte(prefix + shellBegin + "\n" + shellPathUpdate(filepath.Join(home, ".cicada", "bin")) + shellEnd + "\n")
}

// This owns only the stable command, its receipt and the exact managed Bash
// block. It never follows a bashrc symlink or changes a component/data root.
func prepareShellIntegration(home, prefix, action string) (shellIntegrationChange, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || strings.ContainsAny(home+prefix, "\x00\r\n") || strings.Contains(home, ":") {
		return nil, errors.New("shell paths must be absolute canonical paths without line breaks")
	}
	p := &shellPlan{prefix: prefix}
	ok := false
	defer func() {
		if !ok {
			p.close()
		}
	}()
	var err error
	p.home, err = openDirectory(home, false)
	if err != nil {
		return nil, err
	}
	if err = checkManagedDirectory(p.home); err != nil {
		return nil, err
	}
	p.root, err = openChildDirectory(p.home, ".cicada", action == "install")
	if errors.Is(err, fs.ErrNotExist) && action == "remove" {
		p.noop = true
		p.result.State = "absent"
		ok = true
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err = checkManagedDirectory(p.root); err != nil {
		return nil, err
	}
	// One shell-active prefix; serialize it before taking any per-prefix lock.
	p.lock, err = lockShellEntry(p.root)
	if err != nil {
		return nil, err
	}
	p.receiptFile, err = readShellFile(p.root, shellReceiptName, 8192, true)
	if err != nil {
		return nil, err
	}
	if p.receiptFile.info != nil {
		if json.Unmarshal(p.receiptFile.data, &p.receipt) != nil {
			return nil, errors.New("invalid managed shell receipt")
		}
		canonical, _ := json.Marshal(p.receipt)
		if p.receipt.Format != "cicada.shell-command.v1" || !bytes.Equal(p.receiptFile.data, append(canonical, '\n')) || !filepath.IsAbs(p.receipt.Prefix) || filepath.Clean(p.receipt.Prefix) != p.receipt.Prefix {
			return nil, errors.New("invalid managed shell receipt")
		}
		if p.receipt.Prefix != prefix {
			if action == "remove" {
				p.noop = true
				p.result.State = "other_prefix_preserved"
				ok = true
				return p, nil
			}
			return nil, errors.New("shell entry belongs to another installation prefix; use --shell-integration=off or remove its original components first")
		}
	} else if action == "remove" {
		p.noop = true
		p.result.State = "absent"
		ok = true
		return p, nil
	}
	p.bashrc, err = readShellFile(p.home, ".bashrc", 4<<20, false)
	if err != nil {
		return nil, err
	}
	if p.receiptFile.info == nil {
		p.receipt = shellReceipt{"cicada.shell-command.v1", prefix, len(p.bashrc.data) > 0 && p.bashrc.data[len(p.bashrc.data)-1] != '\n', p.bashrc.info == nil}
	}
	p.block = shellBlock(home, p.receipt.Separator)
	if err = validateShellBlock(p.bashrc.data, p.block, p.receiptFile.info != nil); err != nil {
		return nil, err
	}
	p.bin, err = openChildDirectory(p.root, "bin", action == "install")
	if errors.Is(err, fs.ErrNotExist) && action == "remove" {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if p.bin != nil {
		if err = checkManagedDirectory(p.bin); err != nil {
			return nil, err
		}
		p.launcher, err = readShellFile(p.bin, "cicada", 16384, false)
		if err != nil {
			return nil, err
		}
		if p.launcher.info != nil && (p.receiptFile.info == nil || !bytes.Equal(p.launcher.data, shellLauncher(prefix)) || p.launcher.info.Mode().Perm() != 0755) {
			return nil, errors.New("stable cicada entry is external or changed; refusing to overwrite it")
		}
	}
	p.result = shellIntegrationResult{State: "installed", Entry: filepath.Join(home, ".cicada", "bin", "cicada"), Bashrc: filepath.Join(home, ".bashrc"), Activation: "Open a new Bash shell or source " + codexShellQuote(filepath.Join(home, ".bashrc"))}
	ok = true
	return p, nil
}

func validateShellBlock(data, block []byte, owned bool) error {
	starts, ends := bytes.Count(data, []byte(shellBegin)), bytes.Count(data, []byte(shellEnd))
	if starts == 0 && ends == 0 {
		return nil
	}
	if !owned || starts != 1 || ends != 1 || bytes.Count(data, block) != 1 {
		return errors.New("bashrc contains an unknown, changed or duplicate Cicada block")
	}
	return nil
}

func (p *shellPlan) apply(remaining bool) error {
	if p.noop {
		return nil
	}
	if remaining {
		// Publish the exact intended ownership before the two public files.
		// Missing files after interruption are safe to complete on same retry;
		// present bytes must still match the preflight snapshots.
		if p.receiptFile.info == nil {
			data, _ := json.Marshal(p.receipt)
			if err := replaceShellFile(p.root, shellReceiptName, p.receiptFile, append(data, '\n'), 0600); err != nil {
				return err
			}
		}
		if p.bin == nil {
			return errors.New("managed shell bin directory is missing")
		}
		if err := replaceShellFile(p.bin, "cicada", p.launcher, shellLauncher(p.prefix), 0755); err != nil {
			return err
		}
		if !bytes.Contains(p.bashrc.data, p.block) {
			data := append(bytes.Clone(p.bashrc.data), p.block...)
			mode := fs.FileMode(0644)
			if p.bashrc.info != nil {
				mode = p.bashrc.info.Mode().Perm()
			}
			if err := replaceShellFile(p.home, ".bashrc", p.bashrc, data, mode); err != nil {
				return err
			}
		}
		return nil
	}
	if bytes.Contains(p.bashrc.data, p.block) {
		data := bytes.Replace(p.bashrc.data, p.block, nil, 1)
		if len(data) == 0 && p.receipt.BashrcCreated {
			if err := removeShellFile(p.home, ".bashrc", p.bashrc); err != nil {
				return err
			}
		} else {
			if err := replaceShellFile(p.home, ".bashrc", p.bashrc, data, p.bashrc.info.Mode().Perm()); err != nil {
				return err
			}
		}
	}
	if p.launcher.info != nil {
		if err := removeShellFile(p.bin, "cicada", p.launcher); err != nil {
			return err
		}
	}
	if p.receiptFile.info != nil {
		if err := removeShellFile(p.root, shellReceiptName, p.receiptFile); err != nil {
			return err
		}
	}
	p.result.State = "removed"
	p.result.Activation = ""
	return nil
}

func (p *shellPlan) status() shellIntegrationResult { return p.result }
func (p *shellPlan) close() {
	if p.lock != nil {
		p.lock.Close()
	}
	for _, r := range []*os.Root{p.bin, p.root, p.home} {
		if r != nil {
			r.Close()
		}
	}
}

func lockShellEntry(root *os.Root) (*os.File, error) {
	const name = ".shell-command.lock"
	before, err := readShellFile(root, name, 1, true)
	if err != nil {
		return nil, err
	}
	flags := os.O_RDWR
	if before.info == nil {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := root.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	info, se := f.Stat()
	after, ae := root.Lstat(name)
	if se != nil || ae != nil || !os.SameFile(info, after) || before.info != nil && !os.SameFile(before.info, info) || tryFileLock(f) != nil {
		f.Close()
		return nil, errors.New("managed shell command is busy or changed")
	}
	return f, nil
}

func readShellFile(root *os.Root, name string, limit int64, private bool) (shellFile, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return shellFile{}, nil
	}
	if err != nil {
		return shellFile{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm()&0077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > limit {
		return shellFile{}, errors.New("shell file must be bounded, same-user, regular, single-link and not writable by other users")
	}
	f, err := root.Open(name)
	if err != nil {
		return shellFile{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return shellFile{}, errors.New("shell file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, ae := root.Lstat(name)
	if err != nil || ae != nil || !os.SameFile(info, after) || int64(len(data)) != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return shellFile{}, errors.New("shell file changed while reading")
	}
	return shellFile{info, data}, nil
}

func checkShellSnapshot(root *os.Root, name string, expected shellFile) error {
	current, err := readShellFile(root, name, 4<<20, false)
	if err != nil {
		return err
	}
	if (current.info == nil) != (expected.info == nil) || !bytes.Equal(current.data, expected.data) || current.info != nil && (!os.SameFile(current.info, expected.info) || current.info.Mode() != expected.info.Mode()) {
		return errors.New("shell file changed since preflight; original bytes preserved")
	}
	return nil
}

func replaceShellFile(root *os.Root, name string, expected shellFile, data []byte, mode fs.FileMode) error {
	if err := checkShellSnapshot(root, name, expected); err != nil {
		return err
	}
	if expected.info != nil && bytes.Equal(expected.data, data) {
		return nil
	}
	temp := ".shell-command-" + rand.Text()
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	if expected.info != nil {
		if stat, ok := expected.info.Sys().(*syscall.Stat_t); ok {
			now, e := f.Stat()
			if e != nil {
				f.Close()
				return e
			}
			if actual, ok := now.Sys().(*syscall.Stat_t); ok && actual.Gid != stat.Gid {
				if err = f.Chown(-1, int(stat.Gid)); err != nil {
					f.Close()
					return err
				}
			}
		}
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = checkShellSnapshot(root, name, expected); err != nil {
		return err
	}
	if expected.info == nil {
		err = root.Link(temp, name)
	} else {
		err = root.Rename(temp, name)
	}
	if err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func removeShellFile(root *os.Root, name string, expected shellFile) error {
	if err := checkShellSnapshot(root, name, expected); err != nil {
		return err
	}
	return root.Remove(name)
}
