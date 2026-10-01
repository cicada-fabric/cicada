package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
)

const (
	machineAgentJoinSocketRuntimeDirPrefix = "cicada-j-"
	machineAgentJoinSocketScopeDomain      = "cicada/node-agent-join-socket/v1"
)

// machineAgentJoinSocketPathChecked keeps the historical per-Node path when
// it fits the current platform's sockaddr_un. Long Multi-Hub state roots use a deterministic,
// private runtime socket name; the Hub database and Node identity paths remain
// under the original state root.
func machineAgentJoinSocketPathChecked(stateDir, nodeID string) (string, error) {
	stateDir = strings.TrimSpace(stateDir)
	nodeID = strings.TrimSpace(nodeID)
	if stateDir == "" || nodeID == "" {
		return "", errors.New("local Node Join socket scope is incomplete")
	}
	legacyPath := filepath.Join(machineNodeStateDir(stateDir, nodeID), "join.sock")
	pathMax := machineAgentJoinSocketPlatformPathMaxBytes()
	if pathMax > 0 && len([]byte(legacyPath)) <= pathMax {
		return legacyPath, nil
	}
	stateAbs, err := filepath.Abs(stateDir)
	if err != nil {
		return "", errors.New("could not resolve local Node Join socket scope")
	}
	stateAbs = filepath.Clean(stateAbs)
	runtimeDir, err := machineAgentJoinSocketRuntimeDirectory()
	if err != nil {
		return "", err
	}
	scope := machineAgentJoinSocketScopeDomain + "\x00" + stateAbs + "\x00" + nodeID
	digest := sha256.Sum256([]byte(scope))
	path := filepath.Join(runtimeDir, hex.EncodeToString(digest[:])+".sock")
	if pathMax <= 0 || len([]byte(path)) > pathMax {
		return "", errors.New("local Node Join socket path exceeds the platform limit")
	}
	return path, nil
}

func machineAgentJoinSocketMaxPathBytes() int {
	return machineAgentJoinSocketPlatformPathMaxBytes()
}

func machineAgentJoinSocketUsesPrivateRuntime(path string) bool {
	runtimeDir, err := machineAgentJoinSocketRuntimeDirectory()
	if err != nil || filepath.Clean(filepath.Dir(path)) != runtimeDir {
		return false
	}
	name := filepath.Base(path)
	if len(name) != 69 || !strings.HasSuffix(name, ".sock") {
		return false
	}
	_, err = hex.DecodeString(strings.TrimSuffix(name, ".sock"))
	return err == nil
}
