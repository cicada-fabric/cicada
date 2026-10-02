package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

const localJoinProtocolVersion = 1

var errLocalJoinBridgeUnavailable = errors.New("trusted local Node join bridge is unavailable; start the Cicada machine agent")

// localJoinRequest is intentionally smaller than JoinInput. The Node ID and
// owner are derived by the agent from its own authenticated configuration and
// Node credential; they cannot be supplied by the MCP process or model.
type localJoinRequest struct {
	Version         int    `json:"version"`
	GroupID         string `json:"group_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace,omitempty"`
}

// Network Join is separate from Group Join. The native Thread record is
// checked by this Node before its credential is used at the Hub.
type localNetworkJoinRequest struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	NetworkID       string `json:"network_id"`
	InvitationToken string `json:"invitation_token"`
	OwnerJoinProof  string `json:"owner_join_proof"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace"`
	EndpointName    string `json:"endpoint_name,omitempty"`
}

type localNetworkRenewRequest struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	NetworkID       string `json:"network_id"`
	EndpointID      string `json:"endpoint_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace"`
}

type localJoinResponse struct {
	Version            int                                   `json:"version"`
	Join               *fabricpkg.JoinResult                 `json:"join,omitempty"`
	NetworkJoin        *fabricpkg.NetworkJoinResult          `json:"network_join,omitempty"`
	NativeContextScope *nodeinbox.NativeContextScopeDecision `json:"native_context_scope,omitempty"`
	JoinRecovery       *localJoinRecoveryStatus              `json:"join_recovery,omitempty"`
	NetworkDirect      *localNetworkDirectResult             `json:"network_direct,omitempty"`
	SealedSend         *localSealedSendResult                `json:"sealed_send,omitempty"`
	SealedRPC          *localSealedRPCResult                 `json:"sealed_rpc,omitempty"`
	LocalGroup         *localGroupResult                     `json:"local_group,omitempty"`
	CrossNodeGroup     *crossNodeGroupResult                 `json:"cross_node_group,omitempty"`
	GroupBroadcast     *groupBroadcastResult                 `json:"group_broadcast,omitempty"`
	GroupSpace         *groupSpaceLocalResult                `json:"group_space,omitempty"`
	MonitorBroadcast   *monitorBroadcastResult               `json:"monitor_broadcast,omitempty"`
	Retryable          bool                                  `json:"retryable,omitempty"`
	Error              string                                `json:"error,omitempty"`
}

// localJoinRecoveryStatus describes a partial commit. The Hub membership and
// Node binding exist, but this Node withheld the session credential because
// the local native-scope registry did not authorize delivery into this native
// context. It intentionally contains no native session ID, workspace, token,
// or proof material.
type localJoinRecoveryStatus struct {
	Status                string `json:"status"`
	RecoveryState         string `json:"recovery_state"`
	Message               string `json:"message"`
	ScopeType             string `json:"scope_type"`
	HubID                 string `json:"hub_id"`
	GroupID               string `json:"group_id,omitempty"`
	NetworkID             string `json:"network_id,omitempty"`
	EndpointID            string `json:"endpoint_id"`
	BindingID             string `json:"binding_id"`
	BindingEpoch          uint64 `json:"binding_epoch"`
	LeaseExpiresAt        string `json:"lease_expires_at,omitempty"`
	ReasonCode            string `json:"reason_code"`
	NativeHistoryCoverage string `json:"native_history_coverage"`
	CoverageExplanation   string `json:"coverage_explanation"`
	RecoveryRecordSaved   bool   `json:"recovery_record_saved"`
	RecoveryID            string `json:"recovery_id"`
	UpdatedAt             string `json:"updated_at"`
}

type localJoinCommittedScopeBlockedError struct {
	Status localJoinRecoveryStatus
}

func (e *localJoinCommittedScopeBlockedError) Error() string {
	if e == nil || e.Status.Message == "" {
		return "HUB_COMMITTED_LOCAL_SCOPE_BLOCKED: Hub Join committed; local scope check blocked session activation"
	}
	return e.Status.Message
}

func localJoinRecoveryFromError(err error) (*localJoinRecoveryStatus, bool) {
	var blocked *localJoinCommittedScopeBlockedError
	if !errors.As(err, &blocked) || blocked == nil {
		return nil, false
	}
	status := blocked.Status
	return &status, true
}

type machineAgentJoinBridge struct {
	listener      net.Listener
	path          string
	socketFile    os.FileInfo
	baseURL       string
	stateDir      string
	nodeID        string
	nodeToken     string
	ctx           context.Context
	localWake     chan struct{}
	wg            sync.WaitGroup
	closeOnce     sync.Once
	spaceSyncMu   sync.Mutex
	spaceSyncNext int
}

func machineAgentJoinSocketPath(stateDir, nodeID string) string {
	path, err := machineAgentJoinSocketPathChecked(stateDir, nodeID)
	if err != nil {
		return ""
	}
	return path
}

func defaultMCPJoinSocketPath(context harness.SessionContext) string {
	return machineAgentJoinSocketPath(machineAgentStateDir(), context.MachineID)
}

// detectCodexMCPJoinSession accepts the native identity only from Codex's
// process environment and checks it against Codex's local session metadata.
// This confirms the record/workspace association, not a Hub-verifiable
// cryptographic identity: a process running as the same OS user remains inside
// this local trust boundary.
func detectCodexMCPJoinSession() (harness.SessionContext, error) {
	current, err := harness.DetectCurrentSession()
	if err != nil {
		return harness.SessionContext{}, err
	}
	if harness.Canonical(current.Harness) != "codex" {
		return harness.SessionContext{}, errors.New("trusted Node Join is available only inside a Codex native session")
	}
	nativeSessionID := firstNonEmptyEnvironment("CODEX_THREAD_ID", "CODEX_SESSION_ID")
	if nativeSessionID == "" {
		return harness.SessionContext{}, errors.New("Codex did not expose its current native Thread ID; refusing to guess or create a replacement session")
	}
	workspace, err := os.Getwd()
	if err != nil {
		return harness.SessionContext{}, errors.New("could not identify the current Codex workspace")
	}
	workspace = filepath.Clean(workspace)
	if configured := strings.TrimSpace(current.Workspace); configured != "" && filepath.Clean(configured) != workspace {
		return harness.SessionContext{}, errors.New("configured Cicada workspace does not match the current Codex working directory")
	}
	if err := verifyCodexSessionRecord(nativeSessionID, workspace); err != nil {
		return harness.SessionContext{}, err
	}
	current.Harness = "codex"
	current.NativeSessionID = nativeSessionID
	current.Workspace = workspace
	return current, nil
}

type codexSessionRecordMeta struct {
	Type    string `json:"type"`
	Payload struct {
		ID        string `json:"id"`
		SessionID string `json:"session_id"`
		CWD       string `json:"cwd"`
	} `json:"payload"`
}

func verifyCodexSessionRecord(nativeSessionID, workspace string) error {
	root := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return errors.New("could not locate Codex's local session records")
		}
		root = filepath.Join(home, ".codex")
	}
	root = filepath.Join(root, "sessions")
	expectedWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return errors.New("current workspace cannot be verified against the Codex session record")
	}
	if expectedWorkspace, err = filepath.Abs(expectedWorkspace); err != nil {
		return errors.New("current workspace cannot be verified against the Codex session record")
	}
	matchedID := false
	matchedWorkspace := false
	filesSeen := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(filepath.Base(path), "rollout-") || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		filesSeen++
		if filesSeen > 20000 {
			return errors.New("Codex session directory exceeds the local verification limit")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		reader := bufio.NewReader(io.LimitReader(file, 1024*1024))
		var record codexSessionRecordMeta
		foundMeta := false
		for lines := 0; lines < 8; lines++ {
			line, readErr := reader.ReadBytes('\n')
			if len(line) == 0 && readErr != nil {
				break
			}
			var candidate codexSessionRecordMeta
			if json.Unmarshal(bytes.TrimSpace(line), &candidate) == nil && candidate.Type == "session_meta" {
				record, foundMeta = candidate, true
				break
			}
			if readErr != nil {
				break
			}
		}
		_ = file.Close()
		if !foundMeta || (record.Payload.ID != nativeSessionID && record.Payload.SessionID != nativeSessionID) {
			return nil
		}
		matchedID = true
		recordWorkspace := strings.TrimSpace(record.Payload.CWD)
		if recordWorkspace == "" {
			return nil
		}
		realWorkspace, err := filepath.EvalSymlinks(recordWorkspace)
		if err != nil {
			return nil
		}
		if realWorkspace, err = filepath.Abs(realWorkspace); err == nil && filepath.Clean(realWorkspace) == filepath.Clean(expectedWorkspace) {
			matchedWorkspace = true
			return fs.SkipAll
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.SkipAll) {
		return errors.New("could not safely inspect Codex's local session records")
	}
	if matchedID && matchedWorkspace {
		return nil
	}
	if matchedID {
		return errors.New("Codex's native session record does not match the current workspace")
	}
	return errors.New("Codex's current native Thread has no verifiable local session record; refusing to guess or create a replacement session")
}

func startMachineAgentJoinBridge(ctx context.Context, stateDir, baseURL, nodeID, nodeToken string) (*machineAgentJoinBridge, error) {
	if hub, ok := machineHubFrom(ctx); ok &&
		(hub.Origin != strings.TrimRight(baseURL, "/") || hub.NodeID != nodeID ||
			hub.StateDir != stateDir || hub.Token != nodeToken) {
		return nil, errors.New("local Node bridge does not match its pinned Hub context")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || strings.TrimSpace(nodeToken) == "" {
		return nil, errors.New("Node identity is required to start the local Join bridge")
	}
	if _, err := fabricpkg.NodeCredentialFromAuthorization("CicadaNode " + nodeToken); err != nil {
		return nil, errors.New("local Join bridge requires a valid Node credential")
	}
	if err := requireSecureNodeEnrollmentTransport(baseURL); err != nil {
		return nil, err
	}
	path, err := machineAgentJoinSocketPathChecked(stateDir, nodeID)
	if err != nil {
		return nil, err
	}
	if err := prepareLocalJoinSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on local Node Join socket: %w", err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("local Node Join listener is not a Unix socket")
	}
	unixListener.SetUnlinkOnClose(false)
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	socketFile, err := machineAgentJoinSocketEntry(path, uid, false)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("inspect local Node Join socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeOwnedMachineAgentJoinSocket(path, socketFile)
		return nil, fmt.Errorf("protect local Node Join socket: %w", err)
	}
	info, err := machineAgentJoinSocketEntry(path, uid, true)
	if err != nil || !os.SameFile(socketFile, info) {
		_ = listener.Close()
		_ = removeOwnedMachineAgentJoinSocket(path, socketFile)
		if err != nil {
			return nil, fmt.Errorf("inspect local Node Join socket: %w", err)
		}
		return nil, errors.New("local Node Join socket path was replaced during startup")
	}
	bridge := &machineAgentJoinBridge{
		listener: listener, path: path, socketFile: info, baseURL: strings.TrimRight(baseURL, "/"),
		stateDir: stateDir, nodeID: nodeID, nodeToken: nodeToken, ctx: ctx,
		localWake: make(chan struct{}, 1),
	}
	bridge.wg.Add(1)
	go bridge.serve()
	go func() {
		<-ctx.Done()
		_ = bridge.Close()
	}()
	return bridge, nil
}

func prepareLocalJoinSocket(path string) error {
	if len([]byte(path)) > machineAgentJoinSocketMaxPathBytes() {
		return errors.New("local Node Join socket path exceeds the platform limit")
	}
	if err := prepareMachineAgentJoinSocketDirectory(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := removeStaleMachineAgentJoinSocket(path); err != nil {
			return fmt.Errorf("remove stale local Node Join socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect local Node Join path: %w", err)
	}
	return nil
}

func (b *machineAgentJoinBridge) Close() error {
	if b == nil {
		return nil
	}
	var closeErr error
	b.closeOnce.Do(func() {
		closeErr = b.listener.Close()
		b.wg.Wait()
		if err := removeOwnedMachineAgentJoinSocket(b.path, b.socketFile); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (b *machineAgentJoinBridge) serve() {
	defer b.wg.Done()
	for {
		connection, err := b.listener.Accept()
		if err != nil {
			if b.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
			b.serveConnection(connection)
		}()
	}
}

func (b *machineAgentJoinBridge) serveConnection(connection net.Conn) {
	// The local protocol is newline-delimited JSON. Keep reading one bounded
	// record so older Join clients that leave the socket open after Encode still
	// work; requiring EOF here would break that protocol.
	requestBytes, err := bufio.NewReader(io.LimitReader(connection, 256*1024+1)).ReadBytes('\n')
	if err != nil || len(requestBytes) == 0 || len(requestBytes) > 256*1024 {
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local Node request"})
		return
	}
	requestBytes = bytes.TrimSpace(requestBytes)
	var header struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(requestBytes, &header); err != nil {
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local Node request"})
		return
	}
	if header.Operation == "network_join" {
		var request localNetworkJoinRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local Network Join request"})
			return
		}
		joined, decision, err := b.joinNetworkWithScope(request)
		if err != nil {
			response := localJoinErrorResponse(err)
			response.NetworkJoin, response.NativeContextScope = joined, decision
			_ = json.NewEncoder(connection).Encode(response)
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, NetworkJoin: joined,
			NativeContextScope: decision, JoinRecovery: b.readLocalJoinRecoveryStatus("NETWORK", joined.NativeContextScope.HubID, "", joined.NetworkID, joined.Endpoint.ID)})
		return
	}
	if header.Operation == "network_renew" {
		var request localNetworkRenewRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local Network Renew request"})
			return
		}
		joined, err := b.renewNetwork(request)
		if err != nil {
			response := localJoinErrorResponse(err)
			response.NetworkJoin = joined
			_ = json.NewEncoder(connection).Encode(response)
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, NetworkJoin: joined})
		return
	}
	if strings.HasPrefix(header.Operation, "network_direct_") {
		var request localNetworkDirectRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local Network direct request"})
			return
		}
		result, err := b.networkDirect(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, NetworkDirect: result})
		return
	}
	if header.Operation == "sealed_send" {
		var request localSealedSendRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local sealed-send request"})
			return
		}
		result, err := b.sealedSend(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, SealedSend: result})
		return
	}
	if header.Operation == "sealed_ask" || header.Operation == "sealed_reply" ||
		header.Operation == "sealed_status" || header.Operation == "sealed_cancel" {
		var request localSealedRPCRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: "invalid local sealed RPC request"})
			return
		}
		result, err := b.sealedRPC(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, SealedRPC: result})
		return
	}
	if header.Operation == "monitor_broadcast_info" || header.Operation == "monitor_broadcast_execute" || header.Operation == "monitor_broadcast_preview" {
		var request monitorBroadcastRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: "invalid Monitor broadcast request"})
			return
		}
		result, err := b.monitorBroadcast(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
			MonitorBroadcast: result})
		return
	}
	if header.Operation == "group_broadcast" {
		var request groupBroadcastRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: "invalid same-Group broadcast request"})
			return
		}
		result, err := b.groupBroadcast(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
			GroupBroadcast: result})
		return
	}
	if strings.HasPrefix(header.Operation, "space_") {
		var request groupSpaceLocalRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: "invalid local Group Space request"})
			return
		}
		result, err := b.groupSpace(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
			GroupSpace: result})
		return
	}
	if strings.HasPrefix(header.Operation, "cross_node_group_") || header.Operation == "cross_node_task_handoff" {
		var request crossNodeGroupRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: "invalid cross-Node same-Group request"})
			return
		}
		result, err := b.crossNodeGroup(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
			CrossNodeGroup: result})
		return
	}
	if strings.HasPrefix(header.Operation, "local_") {
		var request localGroupRequest
		if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: "invalid local Group request"})
			return
		}
		result, err := b.localGroup(request)
		if err != nil {
			_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion,
				Error: safeLocalJoinError(err), Retryable: localSealedSendRetryable(err)})
			return
		}
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, LocalGroup: result})
		return
	}
	var request localJoinRequest
	if err := decodeLocalBridgeRequest(requestBytes, &request); err != nil {
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: "invalid local Join request"})
		return
	}
	joined, decision, err := b.joinWithScope(request)
	if err != nil {
		_ = json.NewEncoder(connection).Encode(localJoinErrorResponse(err))
		return
	}
	// The session token crosses only this owner-only local socket. MCP persists
	// it in its mode-0600 cache and exposes only the public join result.
	_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Join: joined,
		NativeContextScope: decision, JoinRecovery: b.readLocalJoinRecoveryStatus("GROUP", joined.NativeContextScope.HubID, request.GroupID, "", joined.Endpoint.ID)})
}

func localJoinErrorResponse(err error) localJoinResponse {
	if status, ok := localJoinRecoveryFromError(err); ok {
		return localJoinResponse{Version: localJoinProtocolVersion, Error: status.Message, JoinRecovery: status}
	}
	return localJoinResponse{Version: localJoinProtocolVersion, Error: safeLocalJoinError(err)}
}

func decodeLocalBridgeRequest(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("local Node request has trailing data")
	}
	return nil
}

func (b *machineAgentJoinBridge) join(request localJoinRequest) (*fabricpkg.JoinResult, error) {
	joined, _, err := b.joinWithScope(request)
	return joined, err
}

func (b *machineAgentJoinBridge) joinWithScope(request localJoinRequest) (*fabricpkg.JoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	if request.Version != localJoinProtocolVersion || strings.TrimSpace(request.GroupID) == "" {
		return nil, nil, errors.New("invalid local Join request")
	}
	if strings.TrimSpace(request.Harness) != "codex" || harness.Canonical(request.Harness) != "codex" {
		return nil, nil, errors.New("local Node Join currently supports a verified Codex session only")
	}
	if strings.TrimSpace(request.NativeSessionID) == "" || len(request.NativeSessionID) > 512 {
		return nil, nil, errors.New("native Codex session identity is unavailable")
	}
	if len(request.Workspace) > 4096 {
		return nil, nil, errors.New("Codex workspace path is too long")
	}
	if !filepath.IsAbs(request.Workspace) {
		return nil, nil, errors.New("Codex workspace must be an absolute path")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, nil, err
	}
	input := struct {
		GroupID         string         `json:"group_id"`
		Harness         string         `json:"harness"`
		NativeSessionID string         `json:"native_session_id"`
		Workspace       string         `json:"workspace,omitempty"`
		Capabilities    map[string]any `json:"capabilities,omitempty"`
	}{
		GroupID: strings.TrimSpace(request.GroupID), Harness: "codex",
		NativeSessionID: strings.TrimSpace(request.NativeSessionID),
		Workspace:       strings.TrimSpace(request.Workspace),
		Capabilities: map[string]any{
			"fabric_tools": true, "wake": "codex_queue",
			"local_peer_delivery": "sealed_v1",
		},
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/v2/fabric/node/join", bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	client, err := machineNodeHTTPClient(ctx, 30*time.Second)
	if err != nil {
		return nil, nil, err
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, nil, errors.New("could not reach the Hub for local Thread Join")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("Hub rejected local Thread Join with HTTP %d", response.StatusCode)
	}
	var joined fabricpkg.JoinResult
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(&joined); err != nil {
		return nil, nil, errors.New("Hub returned an invalid local Thread Join result")
	}
	if strings.TrimSpace(joined.SessionToken) == "" || strings.TrimSpace(joined.Endpoint.ID) == "" {
		return nil, nil, errors.New("Hub returned an incomplete local Thread Join result")
	}
	decision := &nodeinbox.NativeContextScopeDecision{Accepted: true, ContextPolicy: joined.NativeContextScope.GroupContextPolicy,
		NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}
	if _, managed := machineHubFrom(b.ctx); managed {
		decision, err = recordMachineNativeContextMetadata(b.ctx, request.Harness, request.NativeSessionID,
			joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch, joined.NativeContextScope)
		if err != nil {
			return nil, nil, b.blockCommittedLocalJoin("GROUP", joined.NativeContextScope.HubID,
				request.GroupID, "", joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch,
				joined.LeaseExpiresAt, err)
		}
	}
	if decision == nil || !decision.Accepted {
		return nil, nil, b.blockCommittedLocalJoin("GROUP", joined.NativeContextScope.HubID,
			request.GroupID, "", joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch,
			joined.LeaseExpiresAt, errors.New("native context scope was not accepted"))
	}
	b.markLocalJoinRecoveryResolved("GROUP", joined.NativeContextScope.HubID, request.GroupID, "", joined.Endpoint.ID,
		joined.BindingID, joined.BindingEpoch, joined.LeaseExpiresAt, decision.NativeHistoryCoverage)
	if joined.Endpoint.Capabilities["local_peer_delivery"] == "sealed_v1" {
		if err := b.publishJoinedLocalEndpointKey(&joined); err != nil {
			return nil, nil, fmt.Errorf("joined native Thread, but could not publish its local Endpoint key: %w", err)
		}
	}
	// The current Join is the trusted source for a bounded local sync watch.
	// It does not assert space.read; every later page still passes Hub Guard.
	if err := b.rememberGroupSpaceSubscription(groupSpaceLocalRequest{
		localSealedSendRequest: localSealedSendRequest{
			GroupID: request.GroupID, SessionToken: joined.SessionToken,
			BindingEpoch: joined.BindingEpoch,
		},
	}, store.GroupSpaceEndpointEvidence{EndpointID: joined.Endpoint.ID}, nil); err != nil {
		return nil, nil, fmt.Errorf("joined native Thread, but could not persist its Group Space sync watch: %w", err)
	}
	return &joined, decision, nil
}

func firstNonEmptyEnvironment(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func safeLocalJoinError(err error) string {
	if err == nil {
		return "local Thread Join failed"
	}
	message := err.Error()
	if strings.Contains(message, "cicada_session_") || strings.Contains(message, "cicada_node_") {
		return "local Thread Join failed"
	}
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}

const (
	localJoinBlockedStatus          = "HUB_COMMITTED_LOCAL_SCOPE_BLOCKED"
	localJoinRecoveryNeeded         = "RECONCILIATION_REQUIRED"
	localJoinRecoveryDone           = "RECOVERED_BY_EXACT_SCOPE_RETRY"
	localJoinRecoveryMaxFiles       = 128
	localJoinRecoveryMaxBytes       = 256 * 1024
	localJoinRecoveryMaxRecordBytes = 4096
)

func localJoinCoverageExplanation(coverage string) string {
	if coverage == nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly {
		return "Only previously observed Cicada native scopes were checked; unobserved Runtime history is unknown."
	}
	return "Native scope history was not checked; isolation from prior Runtime context is unknown."
}

func localJoinRecoveryKey(scopeType, hubID, groupID, networkID, endpointID string) string {
	canonical := strings.Join([]string{"cicada/local-join-recovery/v1", scopeType, hubID, groupID, networkID, endpointID}, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func (b *machineAgentJoinBridge) localJoinRecoveryPath(scopeType, hubID, groupID, networkID, endpointID string) string {
	if b == nil || strings.TrimSpace(b.stateDir) == "" || strings.TrimSpace(b.nodeID) == "" {
		return ""
	}
	id := localJoinRecoveryKey(scopeType, hubID, groupID, networkID, endpointID)
	return filepath.Join(machineNodeStateDir(b.stateDir, b.nodeID), "native-context-join-recovery", id+".json")
}

func localJoinBlockedReason(err error) (code, coverage string) {
	coverage = nodeinbox.NativeContextHistoryCoverageNotChecked
	switch {
	case errors.Is(err, nodeinbox.ErrNativeContextScopeConflict):
		return "KNOWN_SCOPE_CONFLICT", nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly
	case errors.Is(err, nodeinbox.ErrNativeContextHistoryAtLimit):
		return "KNOWN_SCOPE_HISTORY_LIMIT", nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly
	case errors.Is(err, nodeinbox.ErrNativeContextScopeInvalid):
		return "SCOPE_METADATA_INVALID", coverage
	default:
		return "SCOPE_CHECK_UNAVAILABLE", coverage
	}
}

func (b *machineAgentJoinBridge) blockCommittedLocalJoin(scopeType, hubID, groupID, networkID,
	endpointID, bindingID string, bindingEpoch uint64, leaseExpiresAt string, cause error) error {
	reason, coverage := localJoinBlockedReason(cause)
	status := localJoinRecoveryStatus{
		Status: localJoinBlockedStatus, RecoveryState: localJoinRecoveryNeeded,
		Message:   "HUB_COMMITTED_LOCAL_SCOPE_BLOCKED: Hub membership is committed, but local native-scope policy blocked session activation. No session credential was released; reconcile with the Hub Owner or retry the exact scope after resolving the local policy block.",
		ScopeType: scopeType, HubID: hubID, GroupID: groupID, NetworkID: networkID,
		EndpointID: endpointID, BindingID: bindingID, BindingEpoch: bindingEpoch,
		LeaseExpiresAt: leaseExpiresAt, ReasonCode: reason,
		NativeHistoryCoverage: coverage, CoverageExplanation: localJoinCoverageExplanation(coverage),
		RecoveryID: localJoinRecoveryKey(scopeType, hubID, groupID, networkID, endpointID),
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if path := b.localJoinRecoveryPath(scopeType, hubID, groupID, networkID, endpointID); path != "" {
		status.RecoveryRecordSaved = true
		if persistLocalJoinRecoveryStatus(path, status) == nil {
			status.RecoveryRecordSaved = true
		} else {
			status.RecoveryRecordSaved = false
		}
	}
	return &localJoinCommittedScopeBlockedError{Status: status}
}

func persistLocalJoinRecoveryStatus(path string, status localJoinRecoveryStatus) error {
	data, err := json.Marshal(status)
	if err != nil || len(data)+1 > localJoinRecoveryMaxRecordBytes {
		return errors.New("local Join recovery record is invalid or too large")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("local Join recovery directory is not a private directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	count, total, targetExists, targetSize := 0, int64(0), false, int64(0)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return errors.New("local Join recovery directory contains an unsafe entry")
		}
		entryInfo, err := entry.Info()
		if err != nil || !entryInfo.Mode().IsRegular() || entryInfo.Mode().Perm() != 0o600 {
			return errors.New("local Join recovery directory contains an unprotected record")
		}
		count++
		total += entryInfo.Size()
		if filepath.Join(directory, entry.Name()) == path {
			targetExists = true
			targetSize = entryInfo.Size()
		}
	}
	if targetExists {
		total -= targetSize
	}
	if (!targetExists && count >= localJoinRecoveryMaxFiles) || total+int64(len(data)+1) > localJoinRecoveryMaxBytes {
		return errors.New("local Join recovery record bound reached")
	}
	return persistNodeSecretFile(path, append(data, '\n'), ".native-join-recovery-*")
}

func (b *machineAgentJoinBridge) markLocalJoinRecoveryResolved(scopeType, hubID, groupID, networkID,
	endpointID, bindingID string, bindingEpoch uint64, leaseExpiresAt, coverage string) {
	path := b.localJoinRecoveryPath(scopeType, hubID, groupID, networkID, endpointID)
	if path == "" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var status localJoinRecoveryStatus
	if json.Unmarshal(data, &status) != nil || status.RecoveryID != localJoinRecoveryKey(scopeType, hubID, groupID, networkID, endpointID) ||
		status.Status != localJoinBlockedStatus || status.RecoveryState != localJoinRecoveryNeeded {
		return
	}
	status.Status = "JOIN_RECOVERED"
	status.RecoveryState = localJoinRecoveryDone
	status.Message = "A later exact-scope Join passed the local native-scope registry; this records local recovery and does not prove unobserved Runtime history was empty."
	status.BindingID, status.BindingEpoch, status.LeaseExpiresAt = bindingID, bindingEpoch, leaseExpiresAt
	if coverage == "" {
		coverage = nodeinbox.NativeContextHistoryCoverageNotChecked
	}
	status.NativeHistoryCoverage = coverage
	status.CoverageExplanation = localJoinCoverageExplanation(coverage)
	status.RecoveryRecordSaved = true
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	_ = persistLocalJoinRecoveryStatus(path, status)
}

func (b *machineAgentJoinBridge) readLocalJoinRecoveryStatus(scopeType, hubID, groupID, networkID, endpointID string) *localJoinRecoveryStatus {
	path := b.localJoinRecoveryPath(scopeType, hubID, groupID, networkID, endpointID)
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var status localJoinRecoveryStatus
	if json.Unmarshal(data, &status) != nil || status.RecoveryID != localJoinRecoveryKey(scopeType, hubID, groupID, networkID, endpointID) ||
		status.RecoveryState != localJoinRecoveryDone {
		return nil
	}
	return &status
}

func requestMachineAgentJoin(socketPath string, request localJoinRequest) (*fabricpkg.JoinResult, error) {
	joined, _, err := requestMachineAgentJoinWithScope(socketPath, request)
	return joined, err
}

func requestMachineAgentJoinWithScope(socketPath string, request localJoinRequest) (*fabricpkg.JoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	joined, scope, _, err := requestMachineAgentJoinWithScopeAndRecovery(socketPath, request)
	return joined, scope, err
}

func requestMachineAgentJoinWithScopeAndRecovery(socketPath string, request localJoinRequest) (*fabricpkg.JoinResult, *nodeinbox.NativeContextScopeDecision, *localJoinRecoveryStatus, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, nil, nil, errLocalJoinBridgeUnavailable
	}
	if err := validateMachineAgentJoinSocketForDial(socketPath); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return nil, nil, nil, errLocalJoinBridgeUnavailable
		}
		return nil, nil, nil, errors.New("local Node Join bridge path is not trusted")
	}
	connection, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil, nil, errLocalJoinBridgeUnavailable
		}
		return nil, nil, nil, errors.New("could not connect to the trusted local Node Join bridge")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	if request.Version == 0 {
		request.Version = localJoinProtocolVersion
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, nil, nil, errors.New("could not send Join request to the trusted local Node agent")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, nil, nil, errors.New("could not finish the local Node Join request")
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil {
		return nil, nil, nil, errors.New("trusted local Node agent returned an invalid Join response")
	}
	if response.Version != localJoinProtocolVersion {
		return nil, nil, nil, errors.New("trusted local Node Join protocol version is unsupported")
	}
	if response.JoinRecovery != nil && response.JoinRecovery.Status == localJoinBlockedStatus {
		return nil, nil, nil, &localJoinCommittedScopeBlockedError{Status: *response.JoinRecovery}
	}
	if response.Error != "" {
		return nil, nil, nil, errors.New(response.Error)
	}
	if response.Join == nil || strings.TrimSpace(response.Join.SessionToken) == "" || strings.TrimSpace(response.Join.Endpoint.ID) == "" {
		return nil, nil, nil, errors.New("trusted local Node agent returned an incomplete Join result")
	}
	return response.Join, response.NativeContextScope, response.JoinRecovery, nil
}
