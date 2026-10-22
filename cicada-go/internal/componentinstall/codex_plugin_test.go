//go:build linux

package componentinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Copy the one authoritative bundle, rather than maintain a second embedded
// plugin fixture whose behavior can silently diverge from a shipped package.
func codexFixture(t *testing.T) (string, string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	root := t.TempDir()
	for _, path := range codexAssetPaths {
		data, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, codexFixtureDigest(t, root)
}

func codexFixtureDigest(t *testing.T, root string) string {
	t.Helper()
	var sources []codexSourceFile
	for _, path := range codexAssetPaths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, codexSourceFile{path, digest(data)})
	}
	return codexAssetsDigest(sources)
}

func TestCodexAssetDigestCanonicalVector(t *testing.T) {
	var sources []codexSourceFile
	for i, path := range codexAssetPaths {
		sources = append(sources, codexSourceFile{path, strings.Repeat(string(rune('0'+i)), 64)})
	}
	// Independently generated using Python json.dumps(sort_keys=True,
	// separators=(',', ':')) and hashlib.sha256; no trailing newline.
	const expected = "c8c0eae219781f15884db58739845530960dc8fe67493c514b2e66a6dcf51cbb"
	if got := codexAssetsDigest(sources); got != expected {
		t.Fatalf("digest = %s", got)
	}
	sources[0], sources[4] = sources[4], sources[0]
	if codexAssetsDigest(sources) != expected {
		t.Fatal("digest depends on caller inventory order")
	}
}

func TestCodexPluginInstallMaterializesOnlyFiles(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	f.prefix = filepath.Join(filepath.Dir(f.prefix), "selected root's $(must-not-run)")
	assets, expected := codexFixture(t)
	args := append(f.installArgs("hub,node"), "--codex-plugin-assets", assets, "--codex-plugin-sha256", expected)
	if err := command(args, io.Discard, f.target); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(f.prefix, "components")
	m, err := readInstalled(base, "node", f.target)
	if err != nil {
		t.Fatal(err)
	}
	if m.CodexPlugin == nil || m.CodexPlugin.AssetsSHA256 != expected || m.CodexPlugin.UserRoot != f.prefix {
		t.Fatal("source inventory or selected root missing")
	}
	hub, err := readInstalled(base, "hub", f.target)
	if err != nil || hub.CodexPlugin != nil {
		t.Fatal("Node assets leaked into Hub", err)
	}
	var mcp map[string]any
	data, err := os.ReadFile(filepath.Join(base, "node", codexMaterialPath(".agents/plugins/cicada/.mcp.json")))
	if err != nil || json.Unmarshal(data, &mcp) != nil {
		t.Fatal("invalid materialized MCP", err)
	}
	server := codexObject(codexObject(mcp["mcpServers"])["cicada"])
	if server["command"] != m.CodexPlugin.Executable || server["env_vars"] != nil {
		t.Fatal("MCP launch retains PATH or inherited-config dependency")
	}
	wantArgs := []string{"mcp", "--codex-context", "--user-root", f.prefix}
	gotArgs, _ := json.Marshal(server["args"])
	want, _ := json.Marshal(wantArgs)
	if !bytes.Equal(gotArgs, want) {
		t.Fatalf("args = %s", gotArgs)
	}
	var hooks map[string]any
	data, err = os.ReadFile(filepath.Join(base, "node", codexMaterialPath(".agents/plugins/cicada/hooks/hooks.json")))
	if err != nil || json.Unmarshal(data, &hooks) != nil {
		t.Fatal("invalid materialized hooks", err)
	}
	for _, event := range []string{"UserPromptSubmit", "PreToolUse"} {
		entries := codexObject(hooks["hooks"])[event].([]any)
		handler := codexObject(codexObject(entries[0])["hooks"].([]any)[0])
		// Parse words through the real POSIX shell without executing the
		// synthetic component binary, Codex, or a product operation.
		cmd := exec.Command("/bin/sh", "-c", "set -- "+handler["command"].(string)+"; printf '%s\\0' \"$@\"")
		out, err := cmd.Output()
		want := []byte(strings.Join([]string{m.CodexPlugin.Executable, "codex-hook", "--user-root", f.prefix, ""}, "\x00"))
		if err != nil || !bytes.Equal(out, want) {
			t.Fatal("Hook quoting changed argv", err)
		}
	}
	for _, source := range codexAssetPaths {
		original, err := os.ReadFile(filepath.Join(assets, source))
		if err != nil || digest(original) != m.CodexPlugin.SourceFiles[indexCodexSource(source)].SHA256 {
			t.Fatal("source asset changed", err)
		}
		if strings.HasSuffix(source, ".mcp.json") || strings.HasSuffix(source, "hooks.json") {
			continue
		}
		installed, err := os.ReadFile(filepath.Join(base, "node", codexMaterialPath(source)))
		if err != nil || !bytes.Equal(original, installed) {
			t.Fatal("non-launch asset was rewritten", err)
		}
	}
	before, err := os.ReadFile(filepath.Join(base, "node", manifestName))
	if err != nil {
		t.Fatal(err)
	}
	if err := command(args, io.Discard, f.target); err != nil {
		t.Fatal("identical repeat", err)
	}
	after, err := os.ReadFile(filepath.Join(base, "node", manifestName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeat changed installed manifest", err)
	}
	for _, path := range []string{"state", "run", ".codex"} {
		if _, err := os.Lstat(filepath.Join(f.prefix, path)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("file install created product state", path)
		}
	}
}

func indexCodexSource(path string) int {
	for i, source := range codexAssetPaths {
		if source == path {
			return i
		}
	}
	panic("unknown test source")
}

func TestCodexPluginInvalidInputsDoNotCreateDestination(t *testing.T) {
	for _, name := range []string{"missing-digest", "missing-assets", "wrong-digest", "relative-root", "hub-only", "missing-file", "symlink-file", "symlink-parent", "oversized", "extra-server", "extra-hook", "wrong-source"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, platform{"linux", "amd64"}, "node")
			assets, expected := codexFixture(t)
			components := "node"
			mutate := func(path, contents string) {
				if err := os.WriteFile(filepath.Join(assets, path), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				expected = codexFixtureDigest(t, assets)
			}
			switch name {
			case "wrong-digest":
				expected = strings.Repeat("0", 64)
			case "relative-root":
				assets = "."
			case "hub-only":
				components = "hub"
			case "missing-file":
				if err := os.Remove(filepath.Join(assets, codexAssetPaths[1])); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				file := filepath.Join(assets, codexAssetPaths[1])
				if err := os.Rename(file, file+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file+".original", file); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				parent := filepath.Join(assets, ".agents/plugins/cicada/hooks")
				if err := os.Rename(parent, parent+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+".original", parent); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				mutate(codexAssetPaths[3], strings.Repeat("x", (256<<10)+1))
			case "extra-server":
				mutate(codexAssetPaths[1], `{"mcpServers":{"cicada":{},"other":{"command":"unexpected"}}}`)
			case "extra-hook":
				mutate(codexAssetPaths[2], `{"hooks":{"UserPromptSubmit":[],"PreToolUse":[],"Stop":[]}}`)
			case "wrong-source":
				mutate(codexAssetPaths[4], `{"name":"cicada-repo","plugins":[{"name":"cicada","source":{"source":"local","path":"../../unexpected"}}]}`)
			}
			args := f.installArgs(components)
			if name != "missing-assets" {
				args = append(args, "--codex-plugin-assets", assets)
			}
			if name != "missing-digest" {
				args = append(args, "--codex-plugin-sha256", expected)
			}
			if err := command(args, io.Discard, f.target); err == nil {
				t.Fatal("accepted invalid asset installation")
			}
			if _, err := os.Lstat(f.prefix); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("invalid input created a destination")
			}
		})
	}
}

func TestCodexPluginChangedInstallRefusedAndRemovalPreservesState(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	assets, expected := codexFixture(t)
	args := append(f.installArgs("node"), "--codex-plugin-assets", assets, "--codex-plugin-sha256", expected)
	if err := command(args, io.Discard, f.target); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(f.prefix, "components", "node")
	manifestPath := filepath.Join(base, manifestName)
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(assets, codexAssetPaths[3])
	data, err := os.ReadFile(skill)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skill, append(data, []byte("\nReviewed new content\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = codexFixtureDigest(t, assets)
	if err := command(args, io.Discard, f.target); err == nil {
		t.Fatal("changed source replaced an existing installation")
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal changed manifest", err)
	}
	unknown := filepath.Join(base, "share/codex/keep-user-file")
	if err := os.WriteFile(unknown, []byte("USER FILE\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(f.prefix, "original-state")
	if err := os.WriteFile(state, []byte("ORIGINAL STATE\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := command([]string{"remove", "--prefix", f.prefix, "--components", "node"}, io.Discard, f.target); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{unknown, state} {
		if _, err := os.Stat(file); err != nil {
			t.Fatal("removal lost unowned state", err)
		}
	}
	for _, source := range codexAssetPaths {
		if _, err := os.Lstat(filepath.Join(base, codexMaterialPath(source))); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("owned plugin material remained")
		}
	}
}

func TestCodexPluginOldInstallDoesNotUpgradeInPlace(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	if err := command(f.installArgs("node"), io.Discard, f.target); err != nil {
		t.Fatal(err)
	}
	assets, expected := codexFixture(t)
	args := append(f.installArgs("node"), "--codex-plugin-assets", assets, "--codex-plugin-sha256", expected)
	if err := command(args, io.Discard, f.target); err == nil {
		t.Fatal("adding plugin material upgraded an old installation")
	}
	if _, err := os.Lstat(filepath.Join(f.prefix, "components/node/share")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("refusal added plugin material")
	}
}

func TestCodexPluginMaterialTamperRefused(t *testing.T) {
	for _, name := range []string{"material-bytes", "pin-root", "source-inventory", "missing-record"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, platform{"linux", "amd64"}, "node")
			assets, expected := codexFixture(t)
			args := append(f.installArgs("node"), "--codex-plugin-assets", assets, "--codex-plugin-sha256", expected)
			if err := command(args, io.Discard, f.target); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(f.prefix, "components/node")
			if name == "material-bytes" {
				if err := os.WriteFile(filepath.Join(base, codexMaterialPath(codexAssetPaths[1])), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				data, err := os.ReadFile(filepath.Join(base, manifestName))
				if err != nil {
					t.Fatal(err)
				}
				var m manifest
				if err := json.Unmarshal(data, &m); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "pin-root":
					m.CodexPlugin.UserRoot = filepath.Join(f.prefix, "other")
				case "source-inventory":
					m.CodexPlugin.SourceFiles[0].SHA256 = strings.Repeat("0", 64)
				case "missing-record":
					m.CodexPlugin = nil
				}
				data, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(base, manifestName), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, action := range []string{"list", "remove"} {
				if err := command([]string{action, "--prefix", f.prefix, "--components", "node"}, io.Discard, f.target); err == nil {
					t.Fatal("accepted tampered installation", action)
				}
			}
			if _, err := os.Stat(filepath.Join(base, binaryName("node"))); err != nil {
				t.Fatal("refused removal deleted executable", err)
			}
		})
	}
}
