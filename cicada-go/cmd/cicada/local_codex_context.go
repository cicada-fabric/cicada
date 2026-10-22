package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const localCodexContextTTL = 30 * time.Second
const maxLocalCodexContexts = 512

const LocalCodexContextProfileLegacy = "LEGACY_STRICT"
const LocalCodexContextProfileDomain = "LOCAL_DOMAIN"

var errLocalCodexContext = errors.New("CODEX_CONTEXT_UNSUPPORTED: current local Codex context could not be verified")

// LocalCodexContextError describes a local verification stage without including
// native identifiers, paths or record contents. The public error stays generic.
type LocalCodexContextError struct {
	Stage string
}

func (e *LocalCodexContextError) Error() string { return errLocalCodexContext.Error() }
func (e *LocalCodexContextError) Unwrap() error { return errLocalCodexContext }

func localCodexContextFailure(stage string) error {
	return &LocalCodexContextError{Stage: stage}
}

type localCodexContextIssue struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	APIOrigin       string `json:"api_origin"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace"`
	TranscriptPath  string `json:"transcript_path"`
	ConnectionNonce string `json:"connection_nonce"`
	ToolName        string `json:"tool_name"`
	ArgumentsDigest string `json:"arguments_digest"`
	TurnID          string `json:"turn_id"`
	ToolUseID       string `json:"tool_use_id"`
}

type localCodexContextIssueResult struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expires_at"`
}

type localCodexContextConsume struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	APIOrigin       string `json:"api_origin"`
	ConnectionNonce string `json:"connection_nonce"`
	ToolName        string `json:"tool_name"`
	ArgumentsDigest string `json:"arguments_digest"`
	Ticket          string `json:"ticket"`
}

type localCodexContext struct {
	Harness             string                    `json:"harness"`
	NativeSessionID     string                    `json:"native_session_id"`
	Workspace           string                    `json:"workspace"`
	TurnID              string                    `json:"turn_id"`
	ToolUseID           string                    `json:"tool_use_id"`
	VerificationProfile string                    `json:"verification_profile,omitempty"`
	LocalDomainVersion  int                       `json:"local_domain_version,omitempty"`
	LocalDomain         wire.LocalDomainSelection `json:"local_domain,omitzero"`
}

type localCodexContextConsumeResult struct {
	Context   localCodexContext `json:"context"`
	ExpiresAt string            `json:"expires_at"`
}

// This key and its bounded live set belong to one Node process. Tickets carry
// no readable SID/path and never grant Hub rights or prove human intent.
type localCodexContextAuthority struct {
	mu     sync.Mutex
	key    []byte
	live   map[string]localCodexContextRecord
	native map[string]localCodexContextRecord
}

type localCodexContextRecord struct {
	Context                                 localCodexContext
	Origin, Binding, Nonce, Tool, Arguments string
	Expires                                 time.Time
	TranscriptPath                          string
}

func localContextText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

func localContextHex(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (a *localCodexContextAuthority) sign(id string, r localCodexContextRecord) string {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte("cicada/local-codex-context/v1\x00" + id + "\x00"))
	data, _ := json.Marshal(r)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *localCodexContextAuthority) issue(q localCodexContextIssue, binding string, now time.Time) (*localCodexContextIssueResult, error) {
	return a.issueVerified(q, binding, now, localCodexContext{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, TurnID: q.TurnID, ToolUseID: q.ToolUseID})
}

func (a *localCodexContextAuthority) issueVerified(q localCodexContextIssue, binding string, now time.Time, verified localCodexContext) (*localCodexContextIssueResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, r := range a.live {
		if !now.Before(r.Expires) {
			delete(a.live, id)
		}
	}
	if len(a.live) >= maxLocalCodexContexts {
		return nil, errors.New("CODEX_CONTEXT_BUSY: live context capacity is full")
	}
	if len(a.key) == 0 {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, errLocalCodexContext
		}
		a.key, a.live = key, make(map[string]localCodexContextRecord)
	}
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, errLocalCodexContext
	}
	id := hex.EncodeToString(idBytes)
	r := localCodexContextRecord{Context: verified, TranscriptPath: q.TranscriptPath, Origin: q.APIOrigin, Binding: binding, Nonce: q.ConnectionNonce, Tool: q.ToolName, Arguments: q.ArgumentsDigest, Expires: now.Add(localCodexContextTTL)}
	a.live[id] = r
	if a.native == nil {
		a.native = make(map[string]localCodexContextRecord)
	}
	for id, v := range a.native {
		if !now.Before(v.Expires) {
			delete(a.native, id)
		}
	}
	if len(a.native) < maxLocalCodexContexts {
		a.native[q.NativeSessionID+"\x00"+q.Workspace] = r
	}
	return &localCodexContextIssueResult{Ticket: id + "." + a.sign(id, r), ExpiresAt: r.Expires.UTC().Format(time.RFC3339Nano)}, nil
}

func (a *localCodexContextAuthority) consume(q localCodexContextConsume, binding string, now time.Time) (*localCodexContextConsumeResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	parts := strings.Split(q.Ticket, ".")
	if len(parts) != 2 || !localContextHex(parts[0], 64) || !localContextHex(parts[1], 64) {
		return nil, errLocalCodexContext
	}
	r, ok := a.live[parts[0]]
	if !ok {
		return nil, errLocalCodexContext
	}
	if !now.Before(r.Expires) {
		delete(a.live, parts[0])
		return nil, errLocalCodexContext
	}
	if r.Origin != q.APIOrigin || r.Binding != binding || r.Nonce != q.ConnectionNonce || r.Tool != q.ToolName || r.Arguments != q.ArgumentsDigest || !hmac.Equal([]byte(parts[1]), []byte(a.sign(parts[0], r))) {
		return nil, errLocalCodexContext
	}
	delete(a.live, parts[0]) // Check and consume happen under the same lock.
	return &localCodexContextConsumeResult{Context: r.Context, ExpiresAt: r.Expires.UTC().Format(time.RFC3339Nano)}, nil
}

func (b *machineAgentJoinBridge) localContextBinding(origin string) (string, error) {
	actual, err := normalizeMCPAPIOrigin(origin)
	expected, expectedErr := normalizeMCPAPIOrigin(b.baseURL)
	if err != nil || expectedErr != nil || actual != expected || actual != origin {
		return "", errLocalCodexContext
	}
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return "", errLocalCodexContext
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.BindingID == "" || c.state.NodeKeyEpoch == 0 {
		return "", errLocalCodexContext
	}
	data, _ := json.Marshal(machineNodeControlBindingFromState(c))
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (b *machineAgentJoinBridge) codexContextIssue(q localCodexContextIssue) (*localCodexContextIssueResult, error) {
	if q.Version != localJoinProtocolVersion || q.Operation != "codex_context_issue" || q.Harness != "codex" || !localContextText(q.NativeSessionID, 128) || strings.ContainsAny(q.NativeSessionID, "/\\") || !localContextHex(q.ConnectionNonce, 64) || !localContextHex(q.ArgumentsDigest, 64) || !localContextText(q.ToolName, 256) || !localCodexContextEventIDs(q) {
		return nil, errLocalCodexContext
	}
	binding, err := b.localContextBinding(q.APIOrigin)
	if err != nil {
		return nil, err
	}
	verified, err := b.localCodexVerificationProfile(q)
	if err != nil {
		return nil, err
	}
	if err := verifyCodexContextTranscriptProfile(q.TranscriptPath, q.NativeSessionID, q.Workspace, verified.VerificationProfile == LocalCodexContextProfileDomain); err != nil {
		return nil, err
	}
	return b.codexContexts.issueVerified(q, binding, time.Now(), verified)
}

func (b *machineAgentJoinBridge) codexContextConsume(q localCodexContextConsume) (*localCodexContextConsumeResult, error) {
	if q.Version != localJoinProtocolVersion || q.Operation != "codex_context_consume" || !localContextHex(q.ConnectionNonce, 64) || !localContextHex(q.ArgumentsDigest, 64) || !localContextText(q.ToolName, 256) {
		return nil, errLocalCodexContext
	}
	binding, err := b.localContextBinding(q.APIOrigin)
	if err != nil {
		return nil, err
	}
	return b.codexContexts.consume(q, binding, time.Now())
}

// The path locates one native record; only the open record's metadata supplies
// identity. This deliberately avoids a per-tool walk through session history.
func verifyCodexContextTranscript(path, sid, workspace string) error {
	return verifyCodexContextTranscriptProfile(path, sid, workspace, false)
}

func verifyCodexContextTranscriptProfile(path, sid, workspace string, domain bool) error {
	root := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return localCodexContextFailure("ROOT")
		}
		root = filepath.Join(home, ".codex")
	}
	root, err := filepath.Abs(filepath.Join(root, "sessions"))
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return localCodexContextFailure("PATH")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return localCodexContextFailure("PATH")
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return localCodexContextFailure("OWNERSHIP")
	}
	for ancestor := filepath.Dir(root); ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return localCodexContextFailure("ROOT")
		}
		if filepath.Dir(ancestor) == ancestor {
			break
		}
	}
	// Reject symlinks in the configured record tree, including its root.
	current := root
	for _, part := range append([]string{""}, strings.Split(rel, string(filepath.Separator))...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return localCodexContextFailure("PATH")
		}
		owner, ok := machineAgentJoinSocketOwnerOrZero(info)
		if !ok || owner != uid {
			return localCodexContextFailure("OWNERSHIP")
		}
		if !domain && info.Mode().Perm()&0o022 != 0 {
			return localCodexContextFailure("PERMISSION")
		}
		if current != path && !info.IsDir() {
			return localCodexContextFailure("PATH")
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return localCodexContextFailure("PATH")
	}
	f, err := os.Open(path)
	if err != nil {
		return localCodexContextFailure("PERMISSION")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return localCodexContextFailure("INODE")
	}
	actualCWD, err := filepath.EvalSymlinks(workspace)
	if err != nil || actualCWD != workspace {
		return localCodexContextFailure("WORKSPACE")
	}
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for line := 0; line < 8 && scanner.Scan(); line++ {
		var meta struct {
			Type    string `json:"type"`
			Payload struct {
				ID         string          `json:"id"`
				SessionID  string          `json:"session_id"`
				CWD        string          `json:"cwd"`
				Source     json.RawMessage `json:"source"`
				Originator string          `json:"originator"`
			} `json:"payload"`
		}
		if json.Unmarshal(scanner.Bytes(), &meta) != nil || meta.Type != "session_meta" {
			continue
		}
		var source string
		// A real TUI on a --remote-initialized shared daemon records the exact
		// vscode/codex-tui tuple. Other vscode origins remain unsupported.
		// A fork's ancestry never supplies its ID; structured subagent and
		// missing/unknown sources remain unsupported.
		if json.Unmarshal(meta.Payload.Source, &source) != nil || (source != "cli" && (source != "exec" || meta.Payload.Originator != "codex_exec") && (source != "vscode" || meta.Payload.Originator != "codex-tui")) {
			return localCodexContextFailure("SOURCE")
		}
		if meta.Payload.ID != sid || (meta.Payload.SessionID != "" && meta.Payload.SessionID != sid) {
			return localCodexContextFailure("SESSION")
		}
		cwd, err := filepath.EvalSymlinks(meta.Payload.CWD)
		if err != nil || cwd != workspace {
			return localCodexContextFailure("WORKSPACE")
		}
		return nil
	}
	return localCodexContextFailure("METADATA")
}

func machineAgentJoinSocketOwnerOrZero(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	return machineAgentJoinSocketOwner(info)
}

func requestLocalNodeOperation(socketPath string, q any) (*localJoinResponse, error) {
	if err := validateMachineAgentJoinSocketForDial(socketPath); err != nil {
		return nil, errLocalJoinBridgeUnavailable
	}
	c, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, errLocalJoinBridgeUnavailable
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(35 * time.Second))
	if err := json.NewEncoder(c).Encode(q); err != nil {
		return nil, errLocalJoinBridgeUnavailable
	}
	if u, ok := c.(*net.UnixConn); ok {
		if err := u.CloseWrite(); err != nil {
			return nil, errLocalJoinBridgeUnavailable
		}
	}
	d := json.NewDecoder(io.LimitReader(c, 2<<20))
	d.DisallowUnknownFields()
	var r localJoinResponse
	if d.Decode(&r) != nil || r.Version != localJoinProtocolVersion {
		return nil, errors.New("invalid local Node response")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid local Node response framing")
	}
	if r.Error != "" {
		return &r, errors.New(r.Error)
	}
	return &r, nil
}

func requestMachineAgentCodexContextIssue(socketPath string, q localCodexContextIssue) (*localCodexContextIssueResult, error) {
	r, err := requestLocalNodeOperation(socketPath, q)
	if err != nil {
		return nil, err
	}
	if r.CodexContextIssue == nil {
		return nil, errLocalCodexContext
	}
	return r.CodexContextIssue, nil
}

func requestMachineAgentCodexContextConsume(socketPath string, q localCodexContextConsume) (*localCodexContextConsumeResult, error) {
	r, err := requestLocalNodeOperation(socketPath, q)
	if err != nil {
		return nil, err
	}
	if r.CodexContextConsume == nil {
		return nil, errLocalCodexContext
	}
	return r.CodexContextConsume, nil
}
