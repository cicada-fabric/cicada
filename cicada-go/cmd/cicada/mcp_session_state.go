package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cicada-ai/cicada/internal/harness"
)

const mcpSessionStateVersion = 1

// mcpTrustedContext is the identity boundary used for local session state.
// These values come from the harness environment, never from MCP arguments.
type mcpTrustedContext struct {
	Harness         string
	NativeSessionID string
	NodeID          string
	Workspace       string
}

// mcpCachedSession is deliberately a local-only object. It is never returned
// through an MCP tool result. The plaintext session credential is needed to
// authenticate after a process restart, so the containing file is protected
// with a private directory and a 0600 file mode.
type mcpCachedSession struct {
	Scope           string `json:"scope"`
	APIOrigin       string `json:"api_origin"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
	Workspace       string `json:"workspace,omitempty"`
	GroupID         string `json:"group_id"`
	EndpointID      string `json:"endpoint_id"`
	BindingID       string `json:"binding_id,omitempty"`
	BindingEpoch    uint64 `json:"binding_epoch,omitempty"`
	LeaseExpiresAt  string `json:"lease_expires_at,omitempty"`
	SessionToken    string `json:"session_token"`
}

type mcpSessionStateDisk struct {
	Version  int                `json:"version"`
	Sessions []mcpCachedSession `json:"sessions"`
}

// mcpSessionStateStore stores one file per trusted session scope. Separate
// native sessions therefore cannot overwrite each other's state even when
// they run as separate MCP processes.
type mcpSessionStateStore struct {
	path string
	mu   sync.Mutex
}

func newMCPSessionStateStore(path string) *mcpSessionStateStore {
	return &mcpSessionStateStore{path: strings.TrimSpace(path)}
}

// mcpSessionStatePath returns the process-wide default used by runMCP. Direct
// mcpServer test fixtures leave sessionStatePath empty and therefore never
// touch a user's home directory.
func mcpSessionStatePath() string {
	for _, name := range []string{"CICADA_MCP_SESSION_STATE_FILE", "CICADA_MCP_STATE_FILE"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return filepath.Clean(value)
		}
	}
	for _, name := range []string{"CICADA_SESSION_STATE_DIR", "CICADA_MCP_STATE_DIR", "CICADA_STATE_DIR"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return filepath.Join(value, "mcp", "sessions.json")
		}
	}
	if value := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); value != "" {
		return filepath.Join(value, "cicada", "mcp", "sessions.json")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".local", "state", "cicada", "mcp", "sessions.json")
	}
	return ""
}

// normalizeMCPAPIOrigin strips the root path, queries, fragments, credentials, and
// default ports so equivalent API URLs use the same local-state scope.
func normalizeMCPAPIOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("Cicada API origin is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("Cicada API URL must have a scheme and host without credentials")
	}
	if (parsed.Path != "" && parsed.Path != "/") || (parsed.RawPath != "" && parsed.RawPath != "/") {
		return "", errors.New("Cicada API URL must not contain a base path")
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported Cicada API URL scheme %q", parsed.Scheme)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", errors.New("Cicada API URL host is required")
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	hostPort := host
	if strings.Contains(host, ":") {
		if port != "" {
			hostPort = net.JoinHostPort(host, port)
		} else {
			hostPort = "[" + host + "]"
		}
	} else if port != "" {
		hostPort = net.JoinHostPort(host, port)
	}
	return scheme + "://" + hostPort, nil
}

func normalizeMCPTrustedContext(context harness.SessionContext) (mcpTrustedContext, error) {
	trusted := mcpTrustedContext{
		Harness:         harness.Canonical(context.Harness),
		NativeSessionID: strings.TrimSpace(context.NativeSessionID),
		NodeID:          strings.TrimSpace(context.MachineID),
		Workspace:       strings.TrimSpace(context.Workspace),
	}
	if trusted.Workspace != "" {
		trusted.Workspace = filepath.Clean(trusted.Workspace)
	}
	if trusted.Harness == "" || trusted.NativeSessionID == "" || trusted.NodeID == "" {
		return mcpTrustedContext{}, errors.New("trusted harness, native session, and node are required")
	}
	return trusted, nil
}

func mcpSessionScope(origin string, context harness.SessionContext) (string, mcpTrustedContext, error) {
	normalizedOrigin, err := normalizeMCPAPIOrigin(origin)
	if err != nil {
		return "", mcpTrustedContext{}, err
	}
	trusted, err := normalizeMCPTrustedContext(context)
	if err != nil {
		return "", mcpTrustedContext{}, err
	}
	identity := normalizedOrigin + "\x00" + trusted.Harness + "\x00" + trusted.NativeSessionID + "\x00" + trusted.NodeID
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:]), trusted, nil
}

func (s mcpCachedSession) trustedContext() mcpTrustedContext {
	workspace := strings.TrimSpace(s.Workspace)
	if workspace != "" {
		workspace = filepath.Clean(workspace)
	}
	return mcpTrustedContext{
		Harness:         harness.Canonical(s.Harness),
		NativeSessionID: strings.TrimSpace(s.NativeSessionID),
		NodeID:          strings.TrimSpace(s.NodeID),
		Workspace:       workspace,
	}
}

func (s mcpCachedSession) matches(origin, scope string, trusted mcpTrustedContext) bool {
	if s.Scope != scope || s.APIOrigin != origin {
		return false
	}
	stored := s.trustedContext()
	return stored.Harness == trusted.Harness &&
		stored.NativeSessionID == trusted.NativeSessionID &&
		stored.NodeID == trusted.NodeID &&
		stored.Workspace == trusted.Workspace
}

func (s *mcpSessionStateStore) load(origin string, context harness.SessionContext) (*mcpCachedSession, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil, nil
	}
	scope, trusted, err := mcpSessionScope(origin, context)
	if err != nil {
		return nil, err
	}
	normalizedOrigin, err := normalizeMCPAPIOrigin(origin)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	disk, exists, err := s.readScopeLocked(scope)
	if err != nil || !exists {
		return nil, err
	}
	for index := range disk.Sessions {
		entry := disk.Sessions[index]
		if entry.matches(normalizedOrigin, scope, trusted) {
			if strings.TrimSpace(entry.SessionToken) == "" || strings.TrimSpace(entry.EndpointID) == "" || strings.TrimSpace(entry.GroupID) == "" {
				return nil, errors.New("cached Cicada session is incomplete")
			}
			return &entry, nil
		}
	}
	return nil, nil
}

func (s *mcpSessionStateStore) save(entry mcpCachedSession) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	var err error
	entry.APIOrigin, err = normalizeMCPAPIOrigin(entry.APIOrigin)
	if err != nil {
		return err
	}
	if entry.APIOrigin == "" || strings.TrimSpace(entry.Scope) == "" || strings.TrimSpace(entry.Harness) == "" ||
		strings.TrimSpace(entry.NativeSessionID) == "" || strings.TrimSpace(entry.NodeID) == "" ||
		strings.TrimSpace(entry.GroupID) == "" || strings.TrimSpace(entry.EndpointID) == "" || strings.TrimSpace(entry.SessionToken) == "" {
		return errors.New("incomplete Cicada session state")
	}
	if entry.Workspace != "" {
		entry.Workspace = filepath.Clean(entry.Workspace)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ensureMCPPrivateDir(filepath.Dir(s.scopeDirectory())); err != nil {
		return err
	}
	if err := ensureMCPPrivateDir(s.scopeDirectory()); err != nil {
		return err
	}
	disk, _, err := s.readScopeLocked(entry.Scope)
	if err != nil {
		return err
	}
	disk.Sessions = []mcpCachedSession{entry}
	disk.Version = mcpSessionStateVersion
	return s.writeScopeLocked(entry.Scope, disk)
}

func (s *mcpSessionStateStore) remove(scope string) error {
	if s == nil || strings.TrimSpace(s.path) == "" || strings.TrimSpace(scope) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists, err := s.readScopeLocked(scope)
	if err != nil || !exists {
		return err
	}
	if err := os.Remove(s.scopePath(scope)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *mcpSessionStateStore) scopeDirectory() string {
	return filepath.Join(filepath.Dir(s.path), "scopes")
}

func (s *mcpSessionStateStore) scopePath(scope string) string {
	return filepath.Join(s.scopeDirectory(), scope+".json")
}

func (s *mcpSessionStateStore) readScopeLocked(scope string) (mcpSessionStateDisk, bool, error) {
	var disk mcpSessionStateDisk
	if strings.TrimSpace(s.path) == "" || strings.TrimSpace(scope) == "" {
		return disk, false, nil
	}
	path := s.scopePath(scope)
	if directoryInfo, directoryErr := os.Lstat(s.scopeDirectory()); directoryErr == nil {
		if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
			return disk, false, errors.New("Cicada MCP session scope directory is not private")
		}
	} else if !errors.Is(directoryErr, os.ErrNotExist) {
		return disk, false, directoryErr
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return mcpSessionStateDisk{Version: mcpSessionStateVersion, Sessions: []mcpCachedSession{}}, false, nil
	}
	if err != nil {
		return disk, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return disk, false, errors.New("Cicada MCP session state must not be a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return disk, false, errors.New("Cicada MCP session state is not private")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return disk, false, err
	}
	if err := json.Unmarshal(data, &disk); err != nil {
		return disk, false, fmt.Errorf("decode Cicada MCP session state: %w", err)
	}
	if disk.Version != mcpSessionStateVersion {
		return disk, false, fmt.Errorf("unsupported Cicada MCP session state version %d", disk.Version)
	}
	return disk, true, nil
}

func ensureMCPPrivateDir(path string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || path == "." {
		return errors.New("Cicada MCP session state directory is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create Cicada MCP session state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Cicada MCP session state path is not a directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect Cicada MCP session state directory: %w", err)
	}
	return nil
}

func (s *mcpSessionStateStore) writeScopeLocked(scope string, disk mcpSessionStateDisk) error {
	if err := ensureMCPPrivateDir(filepath.Dir(s.scopeDirectory())); err != nil {
		return err
	}
	if err := ensureMCPPrivateDir(s.scopeDirectory()); err != nil {
		return err
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Cicada MCP session state: %w", err)
	}
	temporary, err := os.CreateTemp(s.scopeDirectory(), ".sessions-*")
	if err != nil {
		return fmt.Errorf("create Cicada MCP session state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write Cicada MCP session state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	path := s.scopePath(scope)
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace Cicada MCP session state: %w", err)
	}
	keep = true
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}
