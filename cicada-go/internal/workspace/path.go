package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ResolveWithin creates and resolves a workspace while enforcing containment
// after symlink evaluation.
func ResolveWithin(rootPath, workspacePath string) (string, error) {
	if strings.TrimSpace(rootPath) == "" || strings.TrimSpace(workspacePath) == "" {
		return "", errors.New("workspace root and path are required")
	}
	root, err := filepath.Abs(rootPath)
	if err != nil {
		return "", err
	}
	workspace, err := filepath.Abs(workspacePath)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, workspace)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("workspace is outside the configured root")
	}
	if _, err := os.Stat(workspace); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolvedWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return "", err
	}
	resolvedRelative, err := filepath.Rel(resolvedRoot, resolvedWorkspace)
	if err != nil || resolvedRelative == ".." || strings.HasPrefix(resolvedRelative, ".."+string(filepath.Separator)) {
		return "", errors.New("workspace resolves outside the configured root")
	}
	return resolvedWorkspace, nil
}
