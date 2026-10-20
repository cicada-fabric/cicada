// Package componentinstall manages local component files. It never starts a
// service, enrolls a device, changes grants, or opens product state.
package componentinstall

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const manifestName = "INSTALL-MANIFEST.json"

type fileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type manifest struct {
	Format       string       `json:"format"`
	Component    string       `json:"component"`
	GOOS         string       `json:"goos"`
	GOARCH       string       `json:"goarch"`
	GoVersion    string       `json:"go_version"`
	BinarySHA256 string       `json:"binary_sha256"`
	Files        []fileRecord `json:"files"`
}

type platform struct{ os, arch string }

func supported(p platform, component string) bool {
	return p.os == "linux" && (p.arch == "amd64" || p.arch == "arm64") && (component == "hub" || component == "node") ||
		p.os == "windows" && p.arch == "amd64" && component == "app"
}

func binaryName(component string) string {
	if component == "app" {
		return "bin/cicada-app.exe"
	}
	return "bin/cicada"
}

func digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

// Preflight only. Actual reads and mutations use inode-pinned os.Root handles;
// a successful pathname check is never reused as permission to follow it later.
func checkPath(p string, missing bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("component paths must be absolute and canonical")
	}
	volume := filepath.VolumeName(p)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(p, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) && missing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || current != p && !info.IsDir() {
			return errors.New("component path contains a symlink or non-directory ancestor")
		}
	}
	return nil
}

func readRegular(p string, limit int64) ([]byte, error) {
	parent, err := openDirectory(filepath.Dir(p), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return readRegularAt(parent, filepath.Base(p), limit)
}

func validateBinary(data []byte, p platform, component, expected string) (*debug.BuildInfo, error) {
	if !validDigest(expected) || digest(data) != expected {
		return nil, errors.New("component binary SHA-256 does not match --sha256")
	}
	info, err := buildinfo.Read(bytes.NewReader(data))
	main := "github.com/cicada-ai/cicada/cmd/cicada"
	if component == "app" {
		main += "-app"
	}
	if err != nil || info.Path != main {
		return nil, errors.New("component binary has the wrong Go main package")
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != p.os || settings["GOARCH"] != p.arch {
		return nil, errors.New("component binary target does not match this platform")
	}
	if settings["CGO_ENABLED"] != "0" {
		return nil, errors.New("component file installation requires a standard CGO_ENABLED=0 build")
	}
	if p.os == "linux" {
		f, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("Linux component requires an ELF binary")
		}
		defer f.Close()
		machine := elf.EM_X86_64
		if p.arch == "arm64" {
			machine = elf.EM_AARCH64
		}
		if f.Machine != machine || f.Class != elf.ELFCLASS64 {
			return nil, errors.New("Linux component ELF architecture does not match")
		}
		if f.Type != elf.ET_EXEC {
			return nil, errors.New("Linux component requires a self-contained standard ELF executable")
		}
		for _, program := range f.Progs {
			if program.Type == elf.PT_INTERP || program.Type == elf.PT_DYNAMIC {
				return nil, errors.New("Linux component must not require an external loader or dynamic libraries")
			}
		}
		needed, err := f.DynString(elf.DT_NEEDED)
		if err != nil || len(needed) != 0 {
			return nil, errors.New("Linux component must not declare external dynamic libraries")
		}
	} else {
		f, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("Windows App requires a PE executable")
		}
		defer f.Close()
		header, ok := f.OptionalHeader.(*pe.OptionalHeader64)
		if !ok || f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || header.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_GUI {
			return nil, errors.New("Windows App requires an amd64 GUI executable")
		}
	}
	return info, nil
}

func licensePath(name string) bool {
	if name == "" || path.Clean(name) != name || strings.ContainsAny(name, "\\:\x00\r\n") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	base := strings.ToUpper(path.Base(name))
	return strings.HasPrefix(base, "LICENSE") || strings.HasPrefix(base, "COPYING") || strings.HasPrefix(base, "NOTICE") || base == "MODULES.JSON"
}

func readLicenses(root string, info *debug.BuildInfo) (map[string][]byte, error) {
	directory, err := openDirectory(root, false)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	files := make(map[string][]byte)
	var total int
	err = fs.WalkDir(directory.FS(), ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("component licenses must not contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		if !licensePath(p) || len(files) >= 1024 {
			return errors.New("unexpected file in component licenses")
		}
		data, err := readRegularAt(directory, filepath.FromSlash(p), 1<<20)
		if err != nil {
			return err
		}
		total += len(data)
		if total > 16<<20 {
			return errors.New("component license bundle is too large")
		}
		files[p] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, required := range []string{"cicada/LICENSE", "go/LICENSE", "go/MODULES.json"} {
		if len(files[required]) == 0 {
			return nil, fmt.Errorf("component licenses are missing %s", required)
		}
	}
	var notices struct {
		Modules []struct {
			Module, Version string
			Notices         map[string]string
		}
	}
	if json.Unmarshal(files["go/MODULES.json"], &notices) != nil {
		return nil, errors.New("invalid compiled module notice manifest")
	}
	for _, module := range info.Deps {
		if module.Replace != nil {
			return nil, errors.New("component has an unreviewed dependency replacement")
		}
		found := false
		for _, row := range notices.Modules {
			if row.Module != module.Path || row.Version != module.Version {
				continue
			}
			if len(row.Notices) == 0 {
				return nil, errors.New("compiled module has no license notices")
			}
			for relative, expected := range row.Notices {
				name := "modules/" + module.Path + "/" + module.Version + "/" + relative
				if !licensePath(name) || !validDigest(expected) || digest(files[name]) != expected {
					return nil, errors.New("compiled module license notice is missing or changed")
				}
			}
			found = true
		}
		if !found {
			return nil, fmt.Errorf("component licenses do not cover compiled module %s", module.Path)
		}
	}
	return files, nil
}
