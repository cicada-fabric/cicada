package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

// New installations use the selected user root. A single retained legacy
// location remains authoritative until explicitly migrated; two populated
// locations require a deliberate component-specific choice, never newest-wins.
func defaultMCPSessionPath() (string, error) {
	root, err := apppaths.ResolveUserRoot("")
	if err != nil {
		return "", err
	}
	primary := apppaths.MCPSessionFile(root)
	candidates := []string{primary}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) || filepath.Clean(xdg) != xdg {
			return "", errors.New("existing MCP state location is invalid; select its original explicit state directory")
		}
		candidates = append(candidates, filepath.Join(xdg, "cicada", "mcp", "sessions.json"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".local", "state", "cicada", "mcp", "sessions.json"))
	}
	return chooseMCPSessionPath(primary, candidates)
}

func chooseMCPSessionPath(primary string, candidates []string) (string, error) {
	seen := make(map[string]bool)
	selected := ""
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		present, err := mcpStatePresent(candidate)
		if err != nil {
			return "", errors.New("existing MCP state is unavailable; refusing to initialize a replacement")
		}
		if present {
			if selected != "" {
				return "", errors.New("multiple MCP state locations exist; select the original explicit state directory")
			}
			selected = candidate
		}
	}
	if selected != "" {
		return selected, nil
	}
	return primary, nil
}

func mcpStatePresent(sessionFile string) (bool, error) {
	directory := filepath.Dir(sessionFile)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("invalid MCP directory")
	}
	present := false
	outboxPresent, sideFilePresent := false, false
	// SQLite side files can outlive a missing/unavailable main database. They
	// still mark the original location; never initialize a replacement outbox.
	for _, name := range []string{sessionFile, filepath.Join(directory, "outbox.sqlite3"),
		filepath.Join(directory, "outbox.sqlite3-wal"), filepath.Join(directory, "outbox.sqlite3-shm"),
		filepath.Join(directory, "outbox.sqlite3-journal")} {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("invalid MCP state file")
		}
		present = true
		if filepath.Base(name) == "outbox.sqlite3" {
			outboxPresent = true
		} else if name != sessionFile {
			sideFilePresent = true
		}
	}
	if sideFilePresent && !outboxPresent {
		return false, errors.New("original MCP outbox database is missing; retained SQLite side files require recovery")
	}
	scopes := filepath.Join(directory, "scopes")
	info, err = os.Lstat(scopes)
	if errors.Is(err, os.ErrNotExist) {
		return present, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("invalid MCP scope directory")
	}
	file, err := os.Open(scopes)
	if err != nil {
		return false, err
	}
	names, readErr := file.Readdirnames(1)
	closeErr := file.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return false, errors.Join(readErr, closeErr)
	}
	return present || len(names) != 0, nil
}
