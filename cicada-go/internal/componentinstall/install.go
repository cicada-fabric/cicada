package componentinstall

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

const Usage = "usage: cicada components install [--prefix ABS] --components hub,node --binary FILE --sha256 HEX --licenses DIR [--codex-plugin-assets ABS --codex-plugin-sha256 HEX] | remove [--prefix ABS] --components hub,node | list [--prefix ABS]\nThe default user-file root is ~/.cicada (or CICADA_USER_ROOT); --prefix selects a custom absolute root. Linux Bash shell integration defaults to --shell-integration=auto: an owned ~/.cicada/bin/cicada launcher and managed ~/.bashrc PATH block; --shell-integration=off preserves file-only operations. Existing external commands retain PATH precedence. Open a new Bash shell or source ~/.bashrc after install. Only local component and explicitly managed shell files are installed or removed. Services, enrollment, grants and existing state are unchanged. Optional Codex assets accompany Linux node only: the five reviewed .agents/plugins files are checked and materialized under components/node/share/codex, without running Codex or Node. Linux amd64/arm64 supports hub,node; Windows amd64 supports app. Only self-contained standard CGO_ENABLED=0 builds are supported; Linux ELF must not require an external loader or dynamic libraries. Install supports a new component or an identical repeat; changed installations are refused. An I/O failure may leave earlier selected components completed; multi-component rollback is not promised."

type plan struct {
	manifest manifest
	files    map[string][]byte
	existing bool
}

type result struct {
	Action           string                  `json:"action"`
	Prefix           string                  `json:"prefix"`
	Components       []manifest              `json:"components"`
	StatePreserved   bool                    `json:"state_preserved"`
	ServicesChanged  bool                    `json:"services_changed"`
	PathExport       string                  `json:"path_export,omitempty"`
	ShellIntegration *shellIntegrationResult `json:"shell_integration,omitempty"`
}

func Command(args []string, output io.Writer) error {
	return command(args, output, platform{runtime.GOOS, runtime.GOARCH})
}

func command(args []string, output io.Writer, target platform) error {
	return commandWithHome(args, output, target, os.UserHomeDir)
}

func commandWithHome(args []string, output io.Writer, target platform, home func() (string, error)) error {
	if output == nil || len(args) == 0 {
		return errors.New(Usage)
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprintln(output, Usage)
		return err
	}
	action := args[0]
	if action != "install" && action != "remove" && action != "list" {
		return errors.New(Usage)
	}
	flags := flag.NewFlagSet("components "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	prefix := flags.String("prefix", "", "absolute user-file root (default ~/.cicada); existing state stays in its original location")
	selection := flags.String("components", "", "comma-separated components")
	binary := flags.String("binary", "", "existing local component executable")
	expected := flags.String("sha256", "", "independently checked executable SHA-256")
	licenses := flags.String("licenses", "", "matching compiled-dependency license directory")
	codexAssets := flags.String("codex-plugin-assets", "", "absolute package root containing the five reviewed .agents/plugins assets")
	codexDigest := flags.String("codex-plugin-sha256", "", "independently checked canonical five-asset manifest SHA-256")
	shellMode := flags.String("shell-integration", "auto", "auto installs the Linux Bash command entry; off keeps file-only installation")
	if flags.Parse(args[1:]) != nil || len(flags.Args()) != 0 {
		return errors.New(Usage)
	}
	if *shellMode != "auto" && *shellMode != "off" {
		return errors.New("--shell-integration must be auto or off")
	}
	resolved, err := apppaths.ResolveUserRoot(*prefix)
	if err != nil {
		return err
	}
	*prefix = resolved
	if err := checkPath(*prefix, action != "remove"); err != nil {
		return err
	}
	if target.os != "linux" && target.os != "windows" || target.os == "linux" && target.arch != "amd64" && target.arch != "arm64" || target.os == "windows" && target.arch != "amd64" {
		return errors.New("component file installation is unsupported on this platform")
	}
	components := []string{}
	if *selection != "" {
		seen := make(map[string]bool)
		for _, name := range strings.Split(*selection, ",") {
			if !supported(target, name) || seen[name] {
				return errors.New("unsupported or repeated component selection")
			}
			seen[name] = true
			components = append(components, name)
		}
	}
	if action != "list" && len(components) == 0 || action != "install" && (*binary != "" || *expected != "" || *licenses != "" || *codexAssets != "" || *codexDigest != "") {
		return errors.New(Usage)
	}
	if action == "install" && (*binary == "" || *licenses == "" || !validDigest(*expected)) {
		return errors.New(Usage)
	}
	if (*codexAssets == "") != (*codexDigest == "") {
		return errors.New("Codex plugin assets require both --codex-plugin-assets and --codex-plugin-sha256")
	}
	if *codexAssets != "" && (target.os != "linux" || !containsComponent(components, "node")) {
		return errors.New("Codex plugin material is available only with the Node component")
	}
	if action == "list" && len(components) == 0 {
		for _, name := range []string{"hub", "node", "app"} {
			if supported(target, name) {
				components = append(components, name)
			}
		}
	}
	base := filepath.Join(*prefix, "components")
	if err := checkPath(base, action != "remove"); err != nil {
		return err
	}
	plans := make([]plan, 0, len(components))
	if action == "install" {
		var codexFiles map[string][]byte
		var codexRecord *codexPluginRecord
		if *codexAssets != "" {
			codexFiles, codexRecord, err = prepareCodexPlugin(*codexAssets, *codexDigest, *prefix)
			if err != nil {
				return err
			}
		}
		binaryPath, err := filepath.Abs(*binary)
		if err != nil {
			return err
		}
		licensePath, err := filepath.Abs(*licenses)
		if err != nil {
			return err
		}
		data, err := readRegular(binaryPath, 256<<20)
		if err != nil {
			return err
		}
		// Platform, role, digest and complete notices are checked before making
		// any prefix, staging directory or operation lock.
		for _, name := range components {
			info, err := validateBinary(data, target, name, *expected)
			if err != nil {
				return err
			}
			notices, err := readLicenses(licensePath, info)
			if err != nil {
				return err
			}
			p := plan{manifest: manifest{Format: "cicada.component-files.v1", Component: name, GOOS: target.os,
				GOARCH: target.arch, GoVersion: info.GoVersion, BinarySHA256: *expected}, files: map[string][]byte{binaryName(name): data}}
			for relative, bytes := range notices {
				p.files["licenses/"+relative] = bytes
			}
			if name == "node" && codexRecord != nil {
				p.manifest.CodexPlugin = codexRecord
				for relative, bytes := range codexFiles {
					p.files[relative] = bytes
				}
			}
			for relative, bytes := range p.files {
				mode := uint32(0644)
				if relative == binaryName(name) {
					mode = 0755
				}
				p.manifest.Files = append(p.manifest.Files, fileRecord{relative, digest(bytes), mode})
			}
			sort.Slice(p.manifest.Files, func(i, j int) bool { return p.manifest.Files[i].Path < p.manifest.Files[j].Path })
			plans = append(plans, p)
		}
	}
	if action == "list" || action == "remove" {
		for _, name := range components {
			m, err := readInstalled(base, name, target)
			if errors.Is(err, fs.ErrNotExist) && action == "list" {
				continue
			}
			if err != nil {
				return err
			}
			plans = append(plans, plan{manifest: m, existing: true})
		}
	}
	if action == "install" {
		if err := checkInstallTargets(base, plans, target); err != nil {
			return err
		}
	}
	var shellResult *shellIntegrationResult
	if action != "list" {
		var shell shellIntegrationChange
		if *shellMode == "auto" && target.os == "linux" {
			selectedHome, err := home()
			if err != nil {
				return err
			}
			shell, err = prepareShellIntegration(selectedHome, *prefix, action)
			if err != nil {
				return fmt.Errorf("shell integration preflight; components unchanged: %w", err)
			}
			defer shell.close()
		}
		root, err := openDirectory(base, true)
		if err != nil {
			return err
		}
		defer root.Close()
		if err := checkManagedDirectory(root); err != nil {
			return err
		}
		lock, err := lockComponents(root)
		if err != nil {
			return err
		}
		defer lock.Close()
		remaining := action == "install"
		if shell != nil && shell.status().State == "installed" {
			// Validate an unselected fallback before changing the first byte.
			// The stable launcher must not quietly adopt an unknown component.
			for _, name := range []string{"hub", "node"} {
				if action == "remove" && containsComponent(components, name) {
					continue
				}
				if _, e := readInstalledAt(root, name, target); e == nil {
					remaining = true
				} else if !errors.Is(e, fs.ErrNotExist) {
					return fmt.Errorf("shell fallback preflight; components unchanged: %w", e)
				}
			}
		}
		if action == "install" {
			if err := checkInstallTargetsAt(root, plans, target); err != nil {
				return err
			}
			for _, p := range plans {
				if p.existing {
					continue
				}
				if err := installOne(root, p); err != nil {
					return err
				}
			}
		} else {
			// Verify every selected component again under the operation lock
			// before removing the first managed byte.
			for _, p := range plans {
				current, err := readInstalledAt(root, p.manifest.Component, target)
				if err != nil || !sameManifest(current, p.manifest) {
					return errors.New("installed component changed before removal")
				}
			}
			for _, p := range plans {
				if err := removeOne(root, p.manifest); err != nil {
					return err
				}
			}
		}
		if shell != nil {
			if err := shell.apply(remaining); err != nil {
				return fmt.Errorf("components %s completed; shell integration incomplete, rerun an identical install then remove if intended: %w", action, err)
			}
			status := shell.status()
			shellResult = &status
		}
	}
	r := result{Action: action, Prefix: *prefix, StatePreserved: true}
	if action != "list" {
		r.ShellIntegration = shellResult
		if r.ShellIntegration == nil {
			state := "off"
			if *shellMode == "auto" {
				state = "unsupported"
			}
			r.ShellIntegration = &shellIntegrationResult{State: state}
		}
	}
	if action == "install" && target.os == "linux" && containsComponent(components, "node") {
		r.PathExport = "export PATH=" + codexShellQuote(filepath.Join(*prefix, "components", "node", "bin")) + `:"$PATH"`
	}
	if action == "install" && target.os == "linux" && *shellMode == "auto" {
		r.PathExport = shellPathUpdate(filepath.Dir(r.ShellIntegration.Entry))
	}
	for _, p := range plans {
		r.Components = append(r.Components, p.manifest)
	}
	return json.NewEncoder(output).Encode(r)
}

func containsComponent(components []string, name string) bool {
	for _, component := range components {
		if component == name {
			return true
		}
	}
	return false
}

func sameManifest(a, b manifest) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func checkInstallTargets(base string, plans []plan, target platform) error {
	root, err := openDirectory(base, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return checkInstallTargetsAt(root, plans, target)
}

func checkInstallTargetsAt(root *os.Root, plans []plan, target platform) error {
	if err := checkManagedDirectory(root); err != nil {
		return err
	}
	for i := range plans {
		p := &plans[i]
		if _, err := root.Lstat(p.manifest.Component); errors.Is(err, fs.ErrNotExist) {
			p.existing = false
			continue
		}
		current, err := readInstalledAt(root, p.manifest.Component, target)
		if err != nil || !sameManifest(current, p.manifest) {
			return errors.New("component destination already exists; refusing an unknown or changed installation")
		}
		p.existing = true
	}
	return nil
}

func readInstalled(base, name string, target platform) (manifest, error) {
	root, err := openDirectory(base, false)
	if err != nil {
		return manifest{}, err
	}
	defer root.Close()
	return readInstalledAt(root, name, target)
}

func readInstalledAt(base *os.Root, name string, target platform) (manifest, error) {
	var m manifest
	if err := checkManagedDirectory(base); err != nil {
		return m, err
	}
	root, err := openChildDirectory(base, name, false)
	if err != nil {
		return m, err
	}
	defer root.Close()
	if err := checkManagedDirectory(root); err != nil {
		return m, err
	}
	data, err := readRegularAt(root, manifestName, 1<<20)
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Format != "cicada.component-files.v1" || m.Component != name ||
		m.GOOS != target.os || m.GOARCH != target.arch || !validDigest(m.BinarySHA256) || len(m.Files) < 4 || len(m.Files) > 1030 {
		return manifest{}, errors.New("invalid installed component manifest")
	}
	if err := validateCodexPluginRecord(m.CodexPlugin, m.Component, target, filepath.Dir(base.Name())); err != nil {
		return manifest{}, err
	}
	seen := make(map[string]bool)
	for _, file := range m.Files {
		binary := file.Path == binaryName(name)
		codexAsset := m.CodexPlugin != nil && installedCodexAssetPath(file.Path)
		if seen[file.Path] || !validDigest(file.SHA256) ||
			(!binary && !codexAsset && (!strings.HasPrefix(file.Path, "licenses/") || !licensePath(strings.TrimPrefix(file.Path, "licenses/")))) ||
			binary && (file.Mode != 0755 || file.SHA256 != m.BinarySHA256) || !binary && file.Mode != 0644 {
			return manifest{}, errors.New("installed component manifest contains an unsafe path or record")
		}
		seen[file.Path] = true
		limit := int64(1 << 20)
		if binary {
			limit = 256 << 20
		}
		actual, err := readRegularAt(root, filepath.FromSlash(file.Path), limit)
		if err != nil || digest(actual) != file.SHA256 {
			return manifest{}, errors.New("installed component file is missing, unsafe or changed")
		}
	}
	for _, required := range []string{binaryName(name), "licenses/cicada/LICENSE", "licenses/go/LICENSE", "licenses/go/MODULES.json"} {
		if !seen[required] {
			return manifest{}, errors.New("installed component manifest omits a required owned file")
		}
	}
	if m.CodexPlugin != nil {
		for _, source := range codexAssetPaths {
			if !seen[codexMaterialPath(source)] {
				return manifest{}, errors.New("installed component omits a Codex plugin asset")
			}
		}
	}
	return m, nil
}

func installOne(base *os.Root, p plan) error {
	stage := ".component-stage-" + rand.Text()
	if err := base.Mkdir(stage, 0700); err != nil {
		return err
	}
	root, err := openChildDirectory(base, stage, false)
	if err != nil {
		return err
	}
	defer root.Close()
	allocated, err := root.Stat(".")
	if err != nil {
		return err
	}
	defer func() {
		if current, err := base.Lstat(stage); err == nil && os.SameFile(allocated, current) {
			_ = base.RemoveAll(stage) // This invocation's new, private scratch only.
		}
	}()
	for _, file := range p.manifest.Files {
		if err := writeNewFileAt(root, filepath.FromSlash(file.Path), p.files[file.Path], fs.FileMode(file.Mode)); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(p.manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewFileAt(root, manifestName, append(data, '\n'), 0644); err != nil {
		return err
	}
	if _, err := base.Lstat(p.manifest.Component); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("component destination appeared before installation")
	}
	return base.Rename(stage, p.manifest.Component)
}

func removeOne(baseRoot *os.Root, m manifest) error {
	before, err := baseRoot.Lstat(m.Component)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return errors.New("component directory changed before removal")
	}
	root, err := openChildDirectory(baseRoot, m.Component, false)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return errors.New("component directory changed while opening")
	}
	dirs := make(map[string]bool)
	for _, file := range m.Files {
		if err := removeRegularAt(root, filepath.FromSlash(file.Path)); err != nil {
			return err
		}
		for parent := filepath.Dir(filepath.FromSlash(file.Path)); parent != "."; parent = filepath.Dir(parent) {
			dirs[parent] = true
		}
	}
	if err := removeRegularAt(root, manifestName); err != nil {
		return err
	}
	paths := make([]string, 0, len(dirs))
	for dir := range dirs {
		paths = append(paths, dir)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, path := range paths {
		_ = root.Remove(path) // rmdir succeeds only when empty; unknown files stay.
	}
	if current, err := baseRoot.Lstat(m.Component); err == nil && os.SameFile(before, current) {
		_ = baseRoot.Remove(m.Component)
	}
	return nil
}
