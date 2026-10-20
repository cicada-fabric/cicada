//go:build linux

package componentinstall

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var fixtureCache = struct {
	sync.Mutex
	data map[string][]byte
}{data: make(map[string][]byte)}

// Compile tiny, visibly synthetic Go artifacts to exercise real Go/ELF/PE
// validation. These binaries are never executed and contain no product code.
func syntheticBinary(t *testing.T, target platform, component string) []byte {
	t.Helper()
	key := target.os + "/" + target.arch + "/" + component
	fixtureCache.Lock()
	defer fixtureCache.Unlock()
	if data := fixtureCache.data[key]; data != nil {
		return bytes.Clone(data)
	}
	root := t.TempDir()
	name := "cicada"
	if component == "app" {
		name += "-app"
	}
	dir := filepath.Join(root, "cmd", name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/cicada-ai/cicada\n\ngo 1.27.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := "package main\nfunc main(){panic(\"SYNTHETIC_ARTIFACT_MUST_NOT_RUN\")}\n"
	cgo := "0"
	if component == "dynamic" {
		source = "package main\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\nfunc main(){C.free(C.malloc(1));panic(\"SYNTHETIC_ARTIFACT_MUST_NOT_RUN\")}\n"
		cgo = "1"
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "synthetic-artifact")
	args := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", output}
	if component == "app" {
		args = append(args, "-ldflags=-H=windowsgui")
	}
	if component == "pie" {
		args = append(args, "-buildmode=pie")
	}
	args = append(args, "./cmd/"+name)
	command := exec.Command("go", args...)
	command.Dir = root
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOFLAGS":
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "GOOS="+target.os, "GOARCH="+target.arch, "CGO_ENABLED="+cgo, "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic artifact: %v\n%s", err, output)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	fixtureCache.data[key] = bytes.Clone(data)
	return data
}

type fixture struct {
	prefix, binary, licenses, sha string
	target                        platform
}

func newFixture(t *testing.T, target platform, component string) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{prefix: filepath.Join(root, "installation"), binary: filepath.Join(root, "artifact"), licenses: filepath.Join(root, "notices"), target: target}
	data := syntheticBinary(t, target, component)
	f.sha = digest(data)
	if err := os.WriteFile(f.binary, data, 0600); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		"cicada/LICENSE": "SYNTHETIC PROJECT NOTICE\n", "go/LICENSE": "SYNTHETIC TOOLCHAIN NOTICE\n", "go/MODULES.json": "{\"modules\":[]}\n",
	} {
		name := filepath.Join(f.licenses, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f fixture) installArgs(components string) []string {
	return []string{"install", "--prefix", f.prefix, "--components", components, "--binary", f.binary, "--sha256", f.sha, "--licenses", f.licenses}
}

func TestComponentSelfContainedVariantsOnly(t *testing.T) {
	for _, variant := range []string{"dynamic", "pie"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t, platform{"linux", "amd64"}, variant)
			data, err := os.ReadFile(f.binary)
			if err != nil {
				t.Fatal(err)
			}
			info, err := buildinfo.Read(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			settings := make(map[string]string)
			for _, setting := range info.Settings {
				settings[setting.Key] = setting.Value
			}
			wantCGO := "0"
			if variant == "dynamic" {
				wantCGO = "1"
			}
			if settings["CGO_ENABLED"] != wantCGO {
				t.Fatal("synthetic artifact does not have the requested CGO variant")
			}
			image, err := elf.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			interpreter := false
			for _, program := range image.Progs {
				interpreter = interpreter || program.Type == elf.PT_INTERP
			}
			needed, err := image.DynString(elf.DT_NEEDED)
			if err != nil || !interpreter && len(needed) == 0 {
				t.Fatal("synthetic artifact must require an external loader or shared library", err)
			}
			if err := command(f.installArgs("node"), io.Discard, f.target); err == nil {
				t.Error("installer accepted an artifact requiring an external loader or shared library")
			}
			if _, err := os.Lstat(f.prefix); !errors.Is(err, fs.ErrNotExist) {
				t.Error("rejected artifact created a destination")
			}
		})
	}
}

type managedDirectoryInfo struct {
	fs.FileInfo
	system any
	mode   fs.FileMode
}

func (i managedDirectoryInfo) Sys() any          { return i.system }
func (i managedDirectoryInfo) Mode() fs.FileMode { return i.mode }

func TestComponentManagedDirectoryOwnership(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("owned temporary directory must expose its actual current-user UID")
	}
	foreign := *stat
	foreign.Uid ^= 1 // Synthetic metadata only; never chown or touch another user.
	for _, test := range []struct {
		name string
		info fs.FileInfo
		pass bool
	}{
		{"current-user", info, true},
		{"foreign-owner", managedDirectoryInfo{info, &foreign, info.Mode()}, false},
		{"group-writable", managedDirectoryInfo{info, stat, info.Mode() | 0020}, false},
		{"unknown-owner", managedDirectoryInfo{info, nil, info.Mode()}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateManagedDirectory(test.info); (err == nil) != test.pass {
				t.Fatalf("directory ownership acceptance mismatch: %v", err)
			}
		})
	}
}

func mustWrite(t *testing.T, name, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func requireBytes(t *testing.T, name, expected string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil || string(data) != expected {
		t.Fatal("retained state or unrelated component changed")
	}
}

func TestComponentInstallRemovePreservesStateAndOtherComponents(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "hub")
	state := filepath.Join(f.prefix, "state", "identity-and-outbox")
	mustWrite(t, state, "SYNTHETIC_RETAINED_IDENTITY_AND_ORIGINAL_PACKET")
	var output bytes.Buffer
	for i := 0; i < 2; i++ {
		if err := command(f.installArgs("hub,node"), &output, f.target); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(f.prefix, "components")
	hub, err := readInstalled(base, "hub", f.target)
	if err != nil || hub.BinarySHA256 != f.sha {
		t.Fatal("installed Hub artifact was not validated")
	}
	localState := filepath.Join(base, "node", "state", "identity")
	localOutbox := filepath.Join(base, "node", "outbox", "original-packet")
	unknown := filepath.Join(base, "node", "licenses", "USER-NOTES.txt")
	mustWrite(t, localState, "SYNTHETIC_NODE_IDENTITY")
	mustWrite(t, localOutbox, "SYNTHETIC_UNCERTAIN_ORIGINAL")
	mustWrite(t, unknown, "UNMANAGED_FILE")
	if err := command([]string{"remove", "--prefix", f.prefix, "--components", "node"}, io.Discard, f.target); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]string{state: "SYNTHETIC_RETAINED_IDENTITY_AND_ORIGINAL_PACKET", localState: "SYNTHETIC_NODE_IDENTITY", localOutbox: "SYNTHETIC_UNCERTAIN_ORIGINAL", unknown: "UNMANAGED_FILE"} {
		requireBytes(t, name, expected)
	}
	if _, err := readInstalled(base, "hub", f.target); err != nil {
		t.Fatal("removing Node changed the independent Hub component", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "node", "bin", "cicada")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("removed Node executable remains")
	}
	output.Reset()
	if err := command([]string{"list", "--prefix", f.prefix}, &output, f.target); err != nil {
		t.Fatal(err)
	}
	var listed result
	if json.Unmarshal(output.Bytes(), &listed) != nil || len(listed.Components) != 1 || listed.Components[0].Component != "hub" || !listed.StatePreserved || listed.ServicesChanged {
		t.Fatal("file installer list implied a service or enrollment operation")
	}
}

func TestComponentInvalidInputCreatesNoDestination(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	for _, name := range []string{"digest", "platform", "mixed-platform", "duplicate", "missing-notice", "wrong-main", "wrong-architecture", "binary-symlink", "licenses-symlink", "license-file-symlink", "relative-prefix"} {
		t.Run(name, func(t *testing.T) {
			item := f
			item.prefix = filepath.Join(t.TempDir(), "destination")
			components, target := "node", f.target
			switch name {
			case "digest":
				item.sha = strings.Repeat("0", 64)
			case "platform":
				target = platform{"darwin", "amd64"}
			case "mixed-platform":
				components = "hub,app"
			case "duplicate":
				components = "node,node"
			case "missing-notice":
				item.licenses = t.TempDir()
			case "wrong-main":
				data := syntheticBinary(t, platform{"windows", "amd64"}, "app")
				item.binary = filepath.Join(t.TempDir(), "wrong-main")
				item.sha = digest(data)
				if err := os.WriteFile(item.binary, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-architecture":
				data := syntheticBinary(t, platform{"linux", "arm64"}, "node")
				item.binary = filepath.Join(t.TempDir(), "wrong-architecture")
				item.sha = digest(data)
				if err := os.WriteFile(item.binary, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "binary-symlink", "licenses-symlink":
				link := filepath.Join(t.TempDir(), "alias")
				source := item.binary
				if name == "licenses-symlink" {
					source = item.licenses
				}
				if err := os.Symlink(source, link); err != nil {
					t.Fatal(err)
				}
				if name == "binary-symlink" {
					item.binary = link
				} else {
					item.licenses = link
				}
			case "license-file-symlink":
				item.licenses = t.TempDir()
				if err := os.Symlink(f.binary, filepath.Join(item.licenses, "LICENSE")); err != nil {
					t.Fatal(err)
				}
			case "relative-prefix":
				item.prefix = "relative-installation"
			}
			if command(item.installArgs(components), io.Discard, target) == nil {
				t.Fatal("unsafe input was accepted")
			}
			if _, err := os.Lstat(item.prefix); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("input rejection wrote an installation prefix")
			}
		})
	}
}

func TestComponentRemoveValidatesAllBeforeDeleting(t *testing.T) {
	for _, mode := range []string{"changed-file", "traversal", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, platform{"linux", "amd64"}, "hub")
			if err := command(f.installArgs("hub,node"), io.Discard, f.target); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(f.prefix, "components")
			outside := filepath.Join(f.prefix, "state", "identity")
			mustWrite(t, outside, "SYNTHETIC_STATE_MUST_SURVIVE")
			switch mode {
			case "changed-file":
				mustWrite(t, filepath.Join(base, "node", "bin", "cicada"), "CHANGED_OWNED_BINARY")
			case "traversal":
				m, err := readInstalled(base, "node", f.target)
				if err != nil {
					t.Fatal(err)
				}
				m.Files = append(m.Files, fileRecord{"../../state/identity", digest([]byte("SYNTHETIC_STATE_MUST_SURVIVE")), 0644})
				data, _ := json.Marshal(m)
				if err := os.WriteFile(filepath.Join(base, "node", manifestName), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := filepath.Join(base, "node", "licenses")
				if err := os.Rename(path, path+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), path); err != nil {
					t.Fatal(err)
				}
			}
			if command([]string{"remove", "--prefix", f.prefix, "--components", "hub,node"}, io.Discard, f.target) == nil {
				t.Fatal("unsafe removal was accepted")
			}
			if _, err := readInstalled(base, "hub", f.target); err != nil {
				t.Fatal("earlier Hub component was removed before validating Node", err)
			}
			requireBytes(t, outside, "SYNTHETIC_STATE_MUST_SURVIVE")
		})
	}
}

func TestComponentWindowsAppArtifactValidation(t *testing.T) {
	f := newFixture(t, platform{"windows", "amd64"}, "app")
	data, err := readRegular(f.binary, 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateBinary(data, f.target, "app", f.sha); err != nil {
		t.Fatal("real cross-compiled synthetic GUI artifact rejected", err)
	}
}

func TestComponentBinaryHeaderMustMatchDeclaredTarget(t *testing.T) {
	for _, component := range []string{"node", "app"} {
		t.Run(component, func(t *testing.T) {
			target := platform{"linux", "amd64"}
			if component == "app" {
				target.os = "windows"
			}
			data := syntheticBinary(t, target, component)
			if component == "node" {
				binary.LittleEndian.PutUint16(data[18:20], 183) // ARM64 header, amd64 Go metadata.
			} else {
				pe := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
				binary.LittleEndian.PutUint16(data[pe+24+68:pe+24+70], 3) // Console instead of GUI.
			}
			if _, err := validateBinary(data, target, component, digest(data)); err == nil {
				t.Fatal("inconsistent native header was accepted")
			}
		})
	}
}

func TestComponentNoticesCoverActualModulesAndRejectOtherFiles(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	module := &debug.Module{Path: "example.invalid/synthetic", Version: "v0.0.0"}
	info := &debug.BuildInfo{Deps: []*debug.Module{module}}
	if _, err := readLicenses(f.licenses, info); err == nil {
		t.Fatal("missing actual module coverage was accepted")
	}
	notice := "SYNTHETIC_MODULE_NOTICE"
	mustWrite(t, filepath.Join(f.licenses, "modules", "example.invalid", "synthetic", "v0.0.0", "LICENSE"), notice)
	data, err := json.Marshal(map[string]any{"modules": []any{map[string]any{"module": module.Path, "version": module.Version, "notices": map[string]string{"LICENSE": digest([]byte(notice))}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.licenses, "go", "MODULES.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLicenses(f.licenses, info); err != nil {
		t.Fatal("matching actual module notice rejected", err)
	}
	mustWrite(t, filepath.Join(f.licenses, "modules", "example.invalid", "synthetic", "v0.0.0", "LICENSE"), "CHANGED_NOTICE")
	if _, err := readLicenses(f.licenses, info); err == nil {
		t.Fatal("changed module notice accepted")
	}
	mustWrite(t, filepath.Join(f.licenses, "private-identity.bin"), "SYNTHETIC_NOT_A_PRIVATE_KEY")
	if _, err := readLicenses(f.licenses, &debug.BuildInfo{}); err == nil {
		t.Fatal("unrelated file accepted as distributable license material")
	}
}

func TestComponentRootSurvivesParentReplacementAndLockRelease(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "hub")
	if err := command(f.installArgs("hub"), io.Discard, f.target); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(f.prefix, "components")
	m, err := readInstalled(base, "hub", f.target)
	if err != nil {
		t.Fatal(err)
	}
	p := plan{manifest: m, files: make(map[string][]byte)}
	p.manifest.Component = "node"
	for _, file := range m.Files {
		p.files[file.Path], err = os.ReadFile(filepath.Join(base, "hub", filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := openDirectory(base, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first, err := lockComponents(root)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockComponents(root); err == nil {
		_ = second.Close()
		t.Fatal("concurrent component mutation acquired the same OS lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := lockComponents(root)
	if err != nil {
		t.Fatal("lock did not release with its descriptor", err)
	}
	defer third.Close()
	moved := f.prefix + "-retained"
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "components", "node", "bin", "cicada"), "OUTSIDE_MUST_SURVIVE")
	if err := os.Rename(f.prefix, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, f.prefix); err != nil {
		t.Fatal(err)
	}
	if err := installOne(root, p); err != nil {
		t.Fatal(err)
	}
	if _, err := readInstalled(filepath.Join(moved, "components"), "node", f.target); err != nil {
		t.Fatal("install followed the replacement parent path", err)
	}
	if err := removeOne(root, p.manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := readInstalled(filepath.Join(moved, "components"), "hub", f.target); err != nil {
		t.Fatal("rooted removal changed the other component", err)
	}
	requireBytes(t, filepath.Join(outside, "components", "node", "bin", "cicada"), "OUTSIDE_MUST_SURVIVE")
}
