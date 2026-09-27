package main

import (
	"bufio"
	"bytes"
	"context"
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

type localJoinResponse struct {
	Version          int                     `json:"version"`
	Join             *fabricpkg.JoinResult   `json:"join,omitempty"`
	SealedSend       *localSealedSendResult  `json:"sealed_send,omitempty"`
	SealedRPC        *localSealedRPCResult   `json:"sealed_rpc,omitempty"`
	LocalGroup       *localGroupResult       `json:"local_group,omitempty"`
	CrossNodeGroup   *crossNodeGroupResult   `json:"cross_node_group,omitempty"`
	GroupBroadcast   *groupBroadcastResult   `json:"group_broadcast,omitempty"`
	MonitorBroadcast *monitorBroadcastResult `json:"monitor_broadcast,omitempty"`
	Retryable        bool                    `json:"retryable,omitempty"`
	Error            string                  `json:"error,omitempty"`
}

type machineAgentJoinBridge struct {
	listener  net.Listener
	path      string
	baseURL   string
	stateDir  string
	nodeID    string
	nodeToken string
	ctx       context.Context
	localWake chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func machineAgentJoinSocketPath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "join.sock")
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
	path := machineAgentJoinSocketPath(stateDir, nodeID)
	if err := prepareLocalJoinSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on local Node Join socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("protect local Node Join socket: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		_ = os.Remove(path)
		if err != nil {
			return nil, fmt.Errorf("inspect local Node Join socket: %w", err)
		}
		return nil, errors.New("local Node Join path is not a Unix socket")
	}
	bridge := &machineAgentJoinBridge{
		listener: listener, path: path, baseURL: strings.TrimRight(baseURL, "/"),
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
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create local Node socket directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect local Node socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace a non-socket local Node Join path")
		}
		if err := os.Remove(path); err != nil {
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
		if err := os.Remove(b.path); err != nil && !errors.Is(err, os.ErrNotExist) && closeErr == nil {
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
	if strings.HasPrefix(header.Operation, "cross_node_group_") {
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
	joined, err := b.join(request)
	if err != nil {
		_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Error: safeLocalJoinError(err)})
		return
	}
	// The session token crosses only this owner-only local socket. MCP persists
	// it in its mode-0600 cache and exposes only the public join result.
	_ = json.NewEncoder(connection).Encode(localJoinResponse{Version: localJoinProtocolVersion, Join: joined})
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
	if request.Version != localJoinProtocolVersion || strings.TrimSpace(request.GroupID) == "" {
		return nil, errors.New("invalid local Join request")
	}
	if strings.TrimSpace(request.Harness) != "codex" || harness.Canonical(request.Harness) != "codex" {
		return nil, errors.New("local Node Join currently supports a verified Codex session only")
	}
	if strings.TrimSpace(request.NativeSessionID) == "" || len(request.NativeSessionID) > 512 {
		return nil, errors.New("native Codex session identity is unavailable")
	}
	if len(request.Workspace) > 4096 {
		return nil, errors.New("Codex workspace path is too long")
	}
	if !filepath.IsAbs(request.Workspace) {
		return nil, errors.New("Codex workspace must be an absolute path")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, err
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
		return nil, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/v2/fabric/node/join", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, errors.New("could not reach the Hub for local Thread Join")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Hub rejected local Thread Join with HTTP %d", response.StatusCode)
	}
	var joined fabricpkg.JoinResult
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(&joined); err != nil {
		return nil, errors.New("Hub returned an invalid local Thread Join result")
	}
	if strings.TrimSpace(joined.SessionToken) == "" || strings.TrimSpace(joined.Endpoint.ID) == "" {
		return nil, errors.New("Hub returned an incomplete local Thread Join result")
	}
	if joined.Endpoint.Capabilities["local_peer_delivery"] == "sealed_v1" {
		if err := b.publishJoinedLocalEndpointKey(&joined); err != nil {
			return nil, fmt.Errorf("joined native Thread, but could not publish its local Endpoint key: %w", err)
		}
	}
	return &joined, nil
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

func requestMachineAgentJoin(socketPath string, request localJoinRequest) (*fabricpkg.JoinResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	connection, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, errLocalJoinBridgeUnavailable
		}
		return nil, errors.New("could not connect to the trusted local Node Join bridge")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	if request.Version == 0 {
		request.Version = localJoinProtocolVersion
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, errors.New("could not send Join request to the trusted local Node agent")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return nil, errors.New("could not finish the local Node Join request")
		}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var response localJoinResponse
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("trusted local Node agent returned an invalid Join response")
	}
	if response.Version != localJoinProtocolVersion {
		return nil, errors.New("trusted local Node Join protocol version is unsupported")
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	if response.Join == nil || strings.TrimSpace(response.Join.SessionToken) == "" || strings.TrimSpace(response.Join.Endpoint.ID) == "" {
		return nil, errors.New("trusted local Node agent returned an incomplete Join result")
	}
	return response.Join, nil
}
