package componentinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const codexAssetFormat = "cicada.codex-plugin-assets.v1"

// These files remain authored once, under the repository's .agents/plugins.
// Distribution packages supply their original bytes, not another Go copy.
var codexAssetPaths = []string{
	".agents/plugins/cicada/.codex-plugin/plugin.json",
	".agents/plugins/cicada/.mcp.json",
	".agents/plugins/cicada/hooks/hooks.json",
	".agents/plugins/cicada/skills/cicada-network/SKILL.md",
	".agents/plugins/marketplace.json",
}

type codexSourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type codexPluginRecord struct {
	AssetsSHA256 string            `json:"assets_sha256"`
	SourceFiles  []codexSourceFile `json:"source_files"`
	UserRoot     string            `json:"user_root"`
	Executable   string            `json:"executable"`
}

// Digest format: compact UTF-8 JSON, ASCII-sorted keys and paths, no newline.
// Each files row is [fixed relative path, lowercase SHA256(original bytes)].
func codexAssetsDigest(files []codexSourceFile) string {
	rows := make([][]string, 0, len(files))
	for _, file := range files {
		rows = append(rows, []string{file.Path, file.SHA256})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	data, _ := json.Marshal(map[string]any{"files": rows, "format": codexAssetFormat})
	return digest(data)
}

func codexMaterialPath(source string) string { return "share/codex/" + source }

func installedCodexAssetPath(name string) bool {
	for _, source := range codexAssetPaths {
		if name == codexMaterialPath(source) {
			return true
		}
	}
	return false
}

func validateCodexPluginRecord(record *codexPluginRecord, component string, target platform, prefix string) error {
	if record == nil {
		return nil
	}
	if component != "node" || target.os != "linux" || !validDigest(record.AssetsSHA256) ||
		len(record.SourceFiles) != len(codexAssetPaths) || record.UserRoot != prefix ||
		record.Executable != filepath.Join(prefix, "components", "node", binaryName("node")) {
		return errors.New("invalid installed Codex plugin material record")
	}
	for i, source := range record.SourceFiles {
		if source.Path != codexAssetPaths[i] || !validDigest(source.SHA256) {
			return errors.New("invalid Codex plugin source inventory")
		}
	}
	if codexAssetsDigest(record.SourceFiles) != record.AssetsSHA256 {
		return errors.New("Codex plugin source inventory digest differs")
	}
	return nil
}

func prepareCodexPlugin(source, expected, prefix string) (map[string][]byte, *codexPluginRecord, error) {
	if !validDigest(expected) {
		return nil, nil, errors.New("invalid --codex-plugin-sha256")
	}
	root, err := openDirectory(source, false)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	files := make(map[string][]byte, len(codexAssetPaths))
	record := &codexPluginRecord{AssetsSHA256: expected, UserRoot: prefix,
		Executable: filepath.Join(prefix, "components", "node", binaryName("node"))}
	total := 0
	for _, path := range codexAssetPaths {
		data, err := readRegularAt(root, filepath.FromSlash(path), 256<<10)
		if err != nil {
			return nil, nil, err
		}
		total += len(data)
		if total > 512<<10 {
			return nil, nil, errors.New("Codex plugin assets exceed the size limit")
		}
		files[codexMaterialPath(path)] = data
		record.SourceFiles = append(record.SourceFiles, codexSourceFile{path, digest(data)})
	}
	if codexAssetsDigest(record.SourceFiles) != expected {
		return nil, nil, errors.New("Codex plugin assets do not match --codex-plugin-sha256")
	}
	if err := materializeCodexPlugin(files, record); err != nil {
		return nil, nil, err
	}
	return files, record, nil
}

func codexJSONObject(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var object map[string]any
	if decoder.Decode(&object) != nil || object == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid Codex plugin JSON asset")
	}
	return object, nil
}

func codexObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func codexOnlyFields(object map[string]any, fields ...string) bool {
	if object == nil {
		return false
	}
	for name := range object {
		found := false
		for _, allowed := range fields {
			found = found || name == allowed
		}
		if !found {
			return false
		}
	}
	return true
}

func codexShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func materializeCodexPlugin(files map[string][]byte, record *codexPluginRecord) error {
	const bundle = ".agents/plugins/cicada/"
	invalid := errors.New("Codex assets do not describe the supported single Cicada plugin")
	read := func(source string) (map[string]any, error) { return codexJSONObject(files[codexMaterialPath(source)]) }
	manifest, err := read(bundle + ".codex-plugin/plugin.json")
	version, _ := manifest["version"].(string)
	if err != nil || !codexOnlyFields(manifest, "name", "version", "description", "author", "repository", "license", "keywords", "skills", "mcpServers", "interface", "hooks") ||
		manifest["name"] != "cicada" || strings.TrimSpace(version) == "" ||
		manifest["skills"] != "./skills/" || manifest["mcpServers"] != "./.mcp.json" || manifest["hooks"] != "./hooks/hooks.json" {
		return invalid
	}
	marketplace, err := read(".agents/plugins/marketplace.json")
	if err != nil || !codexOnlyFields(marketplace, "$schema", "name", "interface", "plugins") || marketplace["name"] != "cicada-repo" {
		return invalid
	}
	plugins, _ := marketplace["plugins"].([]any)
	if len(plugins) != 1 || !codexOnlyFields(codexObject(plugins[0]), "name", "source", "policy", "category") || codexObject(plugins[0])["name"] != "cicada" {
		return invalid
	}
	local := codexObject(codexObject(plugins[0])["source"])
	if !codexOnlyFields(local, "source", "path") || local["source"] != "local" || local["path"] != "./.agents/plugins/cicada" {
		return invalid
	}
	if !bytes.HasPrefix(files[codexMaterialPath(bundle+"skills/cicada-network/SKILL.md")], []byte("---\nname: cicada-network\n")) {
		return invalid
	}
	mcp, err := read(bundle + ".mcp.json")
	servers := codexObject(mcp["mcpServers"])
	if err != nil || len(mcp) != 1 || len(servers) != 1 {
		return invalid
	}
	server := codexObject(servers["cicada"])
	args, _ := server["args"].([]any)
	if !codexOnlyFields(server, "type", "command", "args", "env_vars") || server["type"] != "stdio" ||
		server["command"] != "cicada" || len(args) != 2 || args[0] != "mcp" || args[1] != "--codex-context" {
		return invalid
	}
	server["command"] = record.Executable
	server["args"] = []string{"mcp", "--codex-context", "--user-root", record.UserRoot}
	delete(server, "env_vars")
	hookFile, err := read(bundle + "hooks/hooks.json")
	hooks := codexObject(hookFile["hooks"])
	if err != nil || len(hookFile) != 1 || !codexOnlyFields(hooks, "PreToolUse", "UserPromptSubmit") {
		return invalid
	}
	events := []string{"PreToolUse"}
	if _, legacy := hooks["UserPromptSubmit"]; legacy {
		events = append(events, "UserPromptSubmit")
	}
	for _, event := range events {
		entries, _ := hooks[event].([]any)
		if len(entries) != 1 {
			return invalid
		}
		entry := codexObject(entries[0])
		if !codexOnlyFields(entry, "hooks", "matcher") || event == "UserPromptSubmit" && entry["matcher"] != nil ||
			event == "PreToolUse" && entry["matcher"] != "^mcp__(cicada|plugin_cicada_cicada)__" {
			return invalid
		}
		handlers, _ := entry["hooks"].([]any)
		if len(handlers) != 1 {
			return invalid
		}
		handler := codexObject(handlers[0])
		if !codexOnlyFields(handler, "type", "command", "timeout", "statusMessage") || handler["type"] != "command" || handler["command"] != "cicada codex-hook" {
			return invalid
		}
		handler["command"] = codexShellQuote(record.Executable) + " codex-hook --user-root " + codexShellQuote(record.UserRoot)
	}
	for source, object := range map[string]map[string]any{bundle + ".mcp.json": mcp, bundle + "hooks/hooks.json": hookFile} {
		data, err := json.MarshalIndent(object, "", "  ")
		if err != nil {
			return err
		}
		files[codexMaterialPath(source)] = append(data, '\n')
	}
	return nil
}
