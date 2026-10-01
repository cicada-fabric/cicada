//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestMachineAgentJoinSocketPathKeepsShortAndHashesLongScopes(t *testing.T) {
	shortState := t.TempDir()
	legacy, err := machineAgentJoinSocketPathChecked(shortState, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	wantLegacy := filepath.Join(machineNodeStateDir(shortState, "node-a"), "join.sock")
	if legacy != wantLegacy {
		t.Fatalf("short legacy path changed: got %q, want %q", legacy, wantLegacy)
	}

	// Mirrors an installed Hub's state layout with a full Hub scope and a
	// multi-Hub Node ID. The socket itself remains a bounded per-scope path.
	longState := filepath.Join(t.TempDir(), "home", "cicada", ".local", "state", "cicada", "node", "hubs", strings.Repeat("a", 64))
	longNodeID := "node-0123456789"
	longPath, err := machineAgentJoinSocketPathChecked(longState, longNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !machineAgentJoinSocketUsesPrivateRuntime(longPath) {
		t.Fatalf("long path did not use the private runtime directory: %q", longPath)
	}
	if got, limit := len([]byte(longPath)), machineAgentJoinSocketMaxPathBytes(); got > limit {
		t.Fatalf("long socket path is %d bytes, platform limit is %d: %q", got, limit, longPath)
	}
	otherHub, err := machineAgentJoinSocketPathChecked(longState+"-other", longNodeID)
	if err != nil {
		t.Fatal(err)
	}
	otherNode, err := machineAgentJoinSocketPathChecked(longState, longNodeID+"-other")
	if err != nil {
		t.Fatal(err)
	}
	if otherHub == longPath || otherNode == longPath || otherHub == otherNode {
		t.Fatalf("independent Hub/Node scopes collided: base=%q hub=%q node=%q", longPath, otherHub, otherNode)
	}
}

func TestMachineAgentJoinSocketLongPathSupportsMCPRequestAndExactRestartCleanup(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	writeCodexSessionRecord(t, codexHome, "thread-long-socket", workspace)

	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/fabric/node/join" || request.Header.Get("Authorization") != "CicadaNode "+nodeToken {
			t.Errorf("unexpected Hub Join request: path=%q", request.URL.Path)
		}
		_ = json.NewEncoder(response).Encode(fabricpkg.JoinResult{
			Endpoint:     store.Endpoint{ID: "ep-long-socket", Harness: "codex", NativeSessionID: "thread-long-socket", MachineID: "node-0123456789"},
			SessionToken: "cicada_session_synthetic-long-socket", BindingID: "binding-long-socket", BindingEpoch: 1,
		})
	}))
	defer server.Close()

	stateDir := filepath.Join(t.TempDir(), "home", "cicada", ".local", "state", "cicada", "node", "hubs", strings.Repeat("b", 64))
	nodeID := "node-0123456789"
	path, err := machineAgentJoinSocketPathChecked(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !machineAgentJoinSocketUsesPrivateRuntime(path) {
		t.Fatalf("installer-long socket did not use runtime path: %q", path)
	}

	start := func() (*machineAgentJoinBridge, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, nodeID, nodeToken)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		return bridge, cancel
	}
	bridge, cancel := start()
	info, err := os.Lstat(path)
	if err != nil {
		cancel()
		_ = bridge.Close()
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		cancel()
		_ = bridge.Close()
		t.Fatalf("fallback socket mode=%v, want socket 0600", info.Mode())
	}
	directoryInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		cancel()
		_ = bridge.Close()
		t.Fatal(err)
	}
	uid, uidErr := machineAgentJoinSocketCurrentUID()
	directoryUID, directoryOwnerOK := machineAgentJoinSocketOwner(directoryInfo)
	socketUID, socketOwnerOK := machineAgentJoinSocketOwner(info)
	if uidErr != nil || directoryInfo.Mode()&os.ModeSymlink != 0 ||
		directoryInfo.Mode().Perm() != 0o700 || !directoryOwnerOK || directoryUID != uid ||
		!socketOwnerOK || socketUID != uid {
		cancel()
		_ = bridge.Close()
		t.Fatalf("fallback socket ownership/mode failed: dir=%v dir_uid=%d socket_uid=%d expected_uid=%d owner_checks=%t/%t uid_err=%v",
			directoryInfo, directoryUID, socketUID, uid, directoryOwnerOK, socketOwnerOK, uidErr)
	}

	joined, _, _, err := requestMachineAgentJoinWithScopeAndRecovery(path, localJoinRequest{
		Version: localJoinProtocolVersion, GroupID: "group-long-socket", Harness: "codex",
		NativeSessionID: "thread-long-socket", Workspace: workspace,
	})
	if err != nil {
		cancel()
		_ = bridge.Close()
		t.Fatal(err)
	}
	if joined.Endpoint.ID != "ep-long-socket" {
		cancel()
		_ = bridge.Close()
		t.Fatalf("MCP helper received unexpected Join: %#v", joined)
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bridge Close left its exact socket path behind: %v", err)
	}

	bridge2, cancel2 := start()
	defer cancel2()
	defer bridge2.Close()
	if bridge2.path != path {
		t.Fatalf("same Hub/Node restart changed socket path: got %q, want %q", bridge2.path, path)
	}
	if err := validateMachineAgentJoinSocketForDial(path); err != nil {
		t.Fatalf("restarted socket failed dial validation: %v", err)
	}
}

func TestMachineAgentJoinSocketDialGuardRejectsUnsafeDirectoryAndEntry(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "join.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unixListener := listener.(*net.UnixListener)
	unixListener.SetUnlinkOnClose(false)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMachineAgentJoinSocketForDial(path); err != nil {
		directoryInfo, _ := os.Lstat(directory)
		owner, ownerOK := machineAgentJoinSocketOwner(directoryInfo)
		t.Fatalf("valid private socket rejected: %v (dir=%q dir_mode=%v owner=%d owner_ok=%t expected_uid=%d)", err,
			directory, directoryInfo.Mode(), owner, ownerOK, uid)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineAgentJoinSocketForDial(path); err == nil {
		t.Fatal("group/world-readable socket was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongUID := uid ^ 1
	if err := validateMachineAgentJoinSocketPrivateDirectory(directory, wrongUID); err == nil {
		t.Fatal("directory owned by another UID was accepted")
	}
	if _, err := machineAgentJoinSocketEntry(path, wrongUID, false); err == nil {
		t.Fatal("socket owned by another UID was accepted")
	}
	if err := validateMachineAgentJoinSocketForDialAs(path, wrongUID); err == nil {
		t.Fatal("dial validation accepted a mismatched owner UID")
	}

	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineAgentJoinSocketForDial(path); err == nil {
		t.Fatal("world-readable socket directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	symlinkDirectory := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(directory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineAgentJoinSocketForDial(filepath.Join(symlinkDirectory, "join.sock")); err == nil {
		t.Fatal("symlink socket directory was accepted")
	}

	symlinkPath := filepath.Join(directory, "linked.sock")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineAgentJoinSocketForDial(symlinkPath); err == nil {
		t.Fatal("symlink socket entry was accepted")
	}

	regularPath := filepath.Join(directory, "regular.sock")
	if err := os.WriteFile(regularPath, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineAgentJoinSocketForDial(regularPath); err == nil {
		t.Fatal("regular file was accepted as a Unix socket")
	}
}

func TestMachineAgentJoinSocketStaleCleanupRequiresOwnedSocket(t *testing.T) {
	stateDir := shortLocalJoinStateDir(t)
	path, err := machineAgentJoinSocketPathChecked(stateDir, "node-stale")
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareMachineAgentJoinSocketDirectory(path); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		t.Fatal(err)
	}
	staleInfo, err := machineAgentJoinSocketEntry(path, uid, false)
	if err != nil {
		t.Fatalf("same-user stale socket was not present: %v", err)
	}
	if err := removeStaleMachineAgentJoinSocketAs(path, uid^1); err == nil {
		t.Fatal("stale cleanup accepted a mismatched directory/socket owner")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(staleInfo, current) {
		t.Fatalf("failed owner check changed stale socket: info=%v err=%v", current, err)
	}
	if err := prepareLocalJoinSocket(path); err != nil {
		t.Fatalf("same-user stale socket was not safely replaced: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket cleanup left path behind: %v", err)
	}

	regularTarget := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(regularTarget, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regularTarget, path); err != nil {
		t.Fatal(err)
	}
	if err := prepareLocalJoinSocket(path); err == nil {
		t.Fatal("stale cleanup accepted a symlink entry")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rejected symlink was removed or followed: info=%v err=%v", info, err)
	}
}

func TestMachineAgentJoinSocketCloseDoesNotUnlinkReplacementInode(t *testing.T) {
	nodeToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	stateDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := startMachineAgentJoinBridge(ctx, stateDir, server.URL, "node-close-safe", nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	path := bridge.path
	if err := os.Remove(path); err != nil {
		_ = bridge.Close()
		t.Fatal(err)
	}
	replacement, err := net.Listen("unix", path)
	if err != nil {
		_ = bridge.Close()
		t.Fatal(err)
	}
	replacementUnix := replacement.(*net.UnixListener)
	replacementUnix.SetUnlinkOnClose(false)
	replacementInfo, err := os.Lstat(path)
	if err != nil {
		_ = replacement.Close()
		_ = bridge.Close()
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = replacement.Close()
		_ = bridge.Close()
		t.Fatal(err)
	}
	if err := bridge.Close(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("Close did not report a replaced socket inode: %v", err)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(replacementInfo, currentInfo) {
		t.Fatalf("Close removed or changed the replacement socket: info=%v err=%v", currentInfo, err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("replacement socket was not left usable: %v", err)
	}
	_ = connection.Close()
	_ = replacement.Close()
	if current, err := os.Lstat(path); err == nil && os.SameFile(replacementInfo, current) {
		_ = os.Remove(path)
	}
}
