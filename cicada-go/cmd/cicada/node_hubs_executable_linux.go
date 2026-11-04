package main

import (
	"os"
	"path/filepath"
	"strings"
)

func validateNodeHubExecutable(path string) error {
	if !localNodePath(path) {
		return ErrLocalNodeHubConfig
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrLocalNodeHubConfig
		}
		uid, ok := machineAgentJoinSocketOwner(info)
		if !ok || uid != 0 && uid != uint32(os.Geteuid()) {
			return ErrLocalNodeHubConfig
		}
		if i == len(parts)-1 {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
				return ErrLocalNodeHubConfig
			}
		} else if !info.IsDir() || info.Mode().Perm()&0022 != 0 && !(uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return ErrLocalNodeHubConfig
		}
	}
	return nil
}

// Codex is an externally installed executable. Preserve its configured wrapper
// path, including same-user installation symlinks and writable user bin dirs;
// only the resolved executable is authority here, not Cicada private storage.
func validateNodeHubCodexExecutable(path string) error {
	if !localNodePath(path) {
		return ErrLocalNodeHubConfig
	}
	link, err := os.Lstat(path)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	uid, ok := machineAgentJoinSocketOwner(link)
	if !ok || uid != 0 && uid != uint32(os.Geteuid()) {
		return ErrLocalNodeHubConfig
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	target, err := os.Stat(resolved)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	if !nodeHubExternalExecutableTargetSafe(target) {
		return ErrLocalNodeHubConfig
	}
	return nil
}

func nodeHubExternalExecutableTargetSafe(info os.FileInfo) bool {
	uid, ok := machineAgentJoinSocketOwner(info)
	return ok && (uid == 0 || uid == uint32(os.Geteuid())) && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 && info.Mode().Perm()&0022 == 0
}
