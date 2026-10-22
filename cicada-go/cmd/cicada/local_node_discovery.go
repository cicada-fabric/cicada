package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

const (
	localNodeLocatorFormat   = "cicada.local-node-locator.v1"
	localNodeDiscoveryBudget = 3 * time.Second
	localNodeMaxLocators     = 64
	localNodeMaxLocatorBytes = 4 << 10
	localNodeMaxRequestBytes = 1 << 10
	localNodeMaxReplyBytes   = 32 << 10
)

var (
	ErrLocalNodeNotRunning           = errors.New("NODE_NOT_RUNNING")
	ErrLocalNodeNotReady             = errors.New("NODE_NOT_READY")
	ErrLocalNodeSelectionAmbiguous   = errors.New("NODE_SELECTION_AMBIGUOUS")
	ErrLocalNodeDiscoveryInvalid     = errors.New("LOCAL_NODE_DISCOVERY_INVALID")
	ErrLocalNodeDiscoveryUnavailable = errors.New("LOCAL_NODE_DISCOVERY_UNAVAILABLE")
	ErrLocalNodeDiscoveryLimit       = errors.New("LOCAL_NODE_DISCOVERY_LIMIT")
	ErrLocalNodeBindingChanged       = errors.New("LOCAL_NODE_BINDING_CHANGED")
	ErrLocalNodeConfigRequired       = errors.New("LOCAL_NODE_CONFIG_REQUIRED")
)

type LocalNodeSelection struct{ UserRoot, HubID, NodeID string }
type LocalNodeBinding struct {
	BindingID          string `json:"binding_id"`
	BindingVersion     uint64 `json:"binding_version"`
	NodeKeyEpoch       uint64 `json:"node_key_epoch"`
	NodeKeyVersion     uint64 `json:"node_key_version"`
	HubKeyVersion      uint64 `json:"hub_key_version"`
	NodeKeyID          string `json:"node_key_id"`
	NodeKeyFingerprint string `json:"node_key_fingerprint"`
	HubKeyID           string `json:"hub_key_id"`
	HubFingerprint     string `json:"hub_fingerprint"`
}
type LocalNodeConnectionPin struct {
	UserRoot            string           `json:"user_root"`
	HubID               string           `json:"hub_id"`
	APIOrigin           string           `json:"api_origin"`
	NodeID              string           `json:"node_id"`
	SocketPath          string           `json:"socket_path"`
	StateDir            string           `json:"state_dir"`
	WriterRoot          string           `json:"writer_root"`
	MCPSessionStateFile string           `json:"mcp_session_state_file"`
	MCPOutboxStateFile  string           `json:"mcp_outbox_state_file"`
	Binding             LocalNodeBinding `json:"binding"`
}
type LocalNodeConnection struct {
	Pin                       LocalNodeConnectionPin
	InstanceID, LocatorDigest string
}
type localNodeLocator struct {
	Format     string `json:"format"`
	InstanceID string `json:"instance_id"`
	SocketPath string `json:"socket_path"`
}
type localNodeDescribeRequest struct {
	Version       int    `json:"version"`
	Operation     string `json:"operation"`
	Nonce         string `json:"nonce"`
	InstanceID    string `json:"instance_id"`
	LocatorDigest string `json:"locator_digest"`
}
type localNodeDescription struct {
	Nonce         string                 `json:"nonce"`
	InstanceID    string                 `json:"instance_id"`
	LocatorDigest string                 `json:"locator_digest"`
	Connection    LocalNodeConnectionPin `json:"connection"`
}
type localNodeDescribeResponse struct {
	Version     int                   `json:"version"`
	Description *localNodeDescription `json:"node_description,omitempty"`
	Error       string                `json:"error,omitempty"`
}

func localNodeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func localNodeLocatorName(state, node string) string {
	return localNodeDigest([]byte("cicada/local-node-locator/v1\x00"+state+"\x00"+node)) + ".json"
}
func localNodePath(path string) bool {
	return path != "" && len(path) <= 4096 && utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}
func validateLocalNodePin(p LocalNodeConnectionPin) error {
	for _, path := range []string{p.UserRoot, p.SocketPath, p.StateDir, p.WriterRoot, p.MCPSessionStateFile, p.MCPOutboxStateFile} {
		if !localNodePath(path) {
			return ErrLocalNodeDiscoveryInvalid
		}
	}
	for _, directory := range []string{p.UserRoot, p.StateDir, p.WriterRoot, filepath.Dir(p.SocketPath), filepath.Dir(p.MCPSessionStateFile), filepath.Dir(p.MCPOutboxStateFile)} {
		if _, err := apppaths.ResolveUserRoot(directory); err != nil {
			return ErrLocalNodeDiscoveryInvalid
		}
	}
	origin, err := normalizeMCPAPIOrigin(p.APIOrigin)
	if err != nil || origin != p.APIOrigin || requireSecureNodeEnrollmentTransport(origin) != nil {
		return ErrLocalNodeDiscoveryInvalid
	}
	b := p.Binding
	for _, id := range []string{p.HubID, p.NodeID, b.BindingID, b.NodeKeyID, b.HubKeyID} {
		if !localContextText(id, 256) {
			return ErrLocalNodeDiscoveryInvalid
		}
	}
	if b.BindingVersion == 0 || b.NodeKeyEpoch == 0 || b.NodeKeyVersion == 0 || b.HubKeyVersion == 0 || !localContextHex(b.NodeKeyFingerprint, 64) || !localContextHex(b.HubFingerprint, 64) {
		return ErrLocalNodeDiscoveryInvalid
	}
	socket, err := machineAgentJoinSocketPathChecked(p.StateDir, p.NodeID)
	if err != nil || socket != p.SocketPath {
		return ErrLocalNodeDiscoveryInvalid
	}
	return nil
}

// Strict shape plus duplicate-key detection at every object level. No canonical
// re-encoding requirement is imposed on otherwise valid local JSON whitespace.
func decodeLocalNodeJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return ErrLocalNodeDiscoveryInvalid
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrLocalNodeDiscoveryInvalid
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrLocalNodeDiscoveryInvalid
		}
		_, err = d.Token()
		return err
	}
	if value(0) != nil {
		return ErrLocalNodeDiscoveryInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrLocalNodeDiscoveryInvalid
	}
	if decodeLocalBridgeRequest(data, target) != nil {
		return ErrLocalNodeDiscoveryInvalid
	}
	return nil
}

// ResolveLocalNodeConnection reads one selected installation only. All file
// checks and all socket probes share one deadline; failures never select a
// different original binding or initialize a replacement state directory.
func ResolveLocalNodeConnection(parent context.Context, s LocalNodeSelection, pin *LocalNodeConnectionPin) (LocalNodeConnection, error) {
	var zero LocalNodeConnection
	if parent == nil {
		return zero, ErrLocalNodeDiscoveryInvalid
	}
	ctx, cancel := context.WithTimeout(parent, localNodeDiscoveryBudget)
	defer cancel()
	if !localNodePath(s.UserRoot) {
		return zero, ErrLocalNodeConfigRequired
	}
	if pin != nil {
		if validateLocalNodePin(*pin) != nil {
			return zero, ErrLocalNodeDiscoveryInvalid
		}
		if s.UserRoot != pin.UserRoot || (s.HubID != "" && s.HubID != pin.HubID) || (s.NodeID != "" && s.NodeID != pin.NodeID) {
			return zero, ErrLocalNodeBindingChanged
		}
	}
	root, err := openLocalNodeDirectory(ctx, s.UserRoot, false)
	if err != nil {
		return zero, localNodeReadError(err)
	}
	defer root.Close()
	run, err := localNodeChildDirectory(root, "run", false)
	if err != nil {
		return zero, localNodeReadError(err)
	}
	defer run.Close()
	nodes, err := localNodeChildDirectory(run, "nodes", false)
	if err != nil {
		return zero, localNodeReadError(err)
	}
	defer nodes.Close()
	var names []string
	if pin != nil {
		names = []string{localNodeLocatorName(pin.StateDir, pin.NodeID)}
	} else {
		dir, err := nodes.Open(".")
		if err != nil {
			return zero, ErrLocalNodeDiscoveryUnavailable
		}
		entries, err := dir.ReadDir(localNodeMaxLocators + 1)
		closeErr := dir.Close()
		if err != nil && err != io.EOF || closeErr != nil {
			return zero, ErrLocalNodeDiscoveryUnavailable
		}
		if len(entries) > localNodeMaxLocators {
			return zero, ErrLocalNodeDiscoveryLimit
		}
		for _, entry := range entries {
			name := entry.Name()
			if len(name) != 69 || !strings.HasSuffix(name, ".json") || !localContextHex(strings.TrimSuffix(name, ".json"), 64) {
				return zero, ErrLocalNodeDiscoveryInvalid
			}
			names = append(names, name)
		}
	}
	var found []LocalNodeConnection
	for _, name := range names {
		if ctx.Err() != nil {
			return zero, ErrLocalNodeDiscoveryUnavailable
		}
		data, _, err := readLocalNodeFile(nodes, name, localNodeMaxLocatorBytes)
		if err != nil {
			if pin != nil && errors.Is(err, os.ErrNotExist) {
				return zero, ErrLocalNodeNotRunning
			}
			return zero, localNodeReadError(err)
		}
		var locator localNodeLocator
		if decodeLocalNodeJSON(data, &locator) != nil || locator.Format != localNodeLocatorFormat || !localContextHex(locator.InstanceID, 32) || !localNodePath(locator.SocketPath) {
			return zero, ErrLocalNodeDiscoveryInvalid
		}
		desc, err := probeLocalNode(ctx, locator, localNodeDigest(data))
		if err != nil {
			if errors.Is(err, ErrLocalNodeNotRunning) {
				continue
			}
			return zero, err
		}
		p := desc.Connection
		if p.UserRoot != s.UserRoot || localNodeLocatorName(p.StateDir, p.NodeID) != name || p.SocketPath != locator.SocketPath || validateLocalNodePin(p) != nil {
			return zero, ErrLocalNodeDiscoveryInvalid
		}
		// Re-read after live verification: replacement cannot turn a stale reply
		// into confirmation for a newly published locator.
		after, _, err := readLocalNodeFile(nodes, name, localNodeMaxLocatorBytes)
		if err != nil || !bytes.Equal(data, after) {
			return zero, ErrLocalNodeDiscoveryUnavailable
		}
		if pin != nil && *pin != p {
			return zero, ErrLocalNodeBindingChanged
		}
		if s.HubID != "" && s.HubID != p.HubID || s.NodeID != "" && s.NodeID != p.NodeID {
			continue
		}
		found = append(found, LocalNodeConnection{Pin: p, InstanceID: desc.InstanceID, LocatorDigest: desc.LocatorDigest})
	}
	if ctx.Err() != nil {
		return zero, ErrLocalNodeDiscoveryUnavailable
	}
	if len(found) == 0 {
		return zero, ErrLocalNodeNotRunning
	}
	if len(found) > 1 {
		return zero, ErrLocalNodeSelectionAmbiguous
	}
	return found[0], nil
}
func localNodeReadError(err error) error {
	if errors.Is(err, ErrLocalNodeDiscoveryInvalid) {
		return ErrLocalNodeDiscoveryInvalid
	}
	if errors.Is(err, ErrLocalNodeDiscoveryLimit) {
		return ErrLocalNodeDiscoveryLimit
	}
	if errors.Is(err, os.ErrNotExist) {
		return ErrLocalNodeNotRunning
	}
	return ErrLocalNodeDiscoveryUnavailable
}
func probeLocalNode(ctx context.Context, l localNodeLocator, digest string) (*localNodeDescription, error) {
	if _, err := apppaths.ResolveUserRoot(filepath.Dir(l.SocketPath)); err != nil {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	if err := validateMachineAgentJoinSocketForDial(l.SocketPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLocalNodeNotRunning
		}
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", l.SocketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrLocalNodeNotRunning
		}
		return nil, ErrLocalNodeDiscoveryUnavailable
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrLocalNodeDiscoveryUnavailable
	}
	q := localNodeDescribeRequest{1, "local_node_describe", hex.EncodeToString(random[:]), l.InstanceID, digest}
	data, _ := json.Marshal(q)
	if len(data)+1 > localNodeMaxRequestBytes {
		return nil, ErrLocalNodeDiscoveryLimit
	}
	if _, err := c.Write(append(data, '\n')); err != nil {
		return nil, ErrLocalNodeDiscoveryUnavailable
	}
	if u, ok := c.(*net.UnixConn); ok {
		_ = u.CloseWrite()
	}
	raw, err := io.ReadAll(io.LimitReader(c, localNodeMaxReplyBytes+1))
	if err != nil {
		return nil, ErrLocalNodeDiscoveryUnavailable
	}
	if len(raw) > localNodeMaxReplyBytes {
		return nil, ErrLocalNodeDiscoveryLimit
	}
	var r localNodeDescribeResponse
	if decodeLocalNodeJSON(raw, &r) != nil || r.Version != 1 {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	if r.Error != "" {
		if r.Description != nil {
			return nil, ErrLocalNodeDiscoveryInvalid
		}
		if r.Error == ErrLocalNodeNotReady.Error() {
			return nil, ErrLocalNodeNotReady
		}
		if r.Error == ErrLocalNodeConfigRequired.Error() {
			return nil, ErrLocalNodeConfigRequired
		}
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	d := r.Description
	if d == nil || d.Nonce != q.Nonce || d.InstanceID != q.InstanceID || d.LocatorDigest != q.LocatorDigest {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	return d, nil
}

func localNodePrivate(info os.FileInfo, directory bool) bool {
	uid, err := machineAgentJoinSocketCurrentUID()
	owner, ok := machineAgentJoinSocketOwner(info)
	if err != nil || !ok || uid != owner || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600
}
func openLocalNodeDirectory(ctx context.Context, path string, create bool) (*os.Root, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !localNodePath(path) {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	if _, err := apppaths.ResolveUserRoot(path); err != nil {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	// Pin every ancestor handle, and never follow a path component's link.
	start := filepath.VolumeName(path) + string(filepath.Separator)
	root, err := os.OpenRoot(start)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, start), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		if ctx.Err() != nil {
			root.Close()
			return nil, ctx.Err()
		}
		next, err := localNodeOpenChild(root, part, false, false)
		root.Close()
		if err != nil {
			return nil, err
		}
		root = next
	}
	info, err := root.Stat(".")
	uid, uidErr := machineAgentJoinSocketCurrentUID()
	owner, ownerOK := uint32(0), false
	if err == nil {
		owner, ownerOK = machineAgentJoinSocketOwner(info)
	}
	if err != nil || uidErr != nil || !ownerOK || owner != uid || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		root.Close()
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	return root, nil
}
func localNodeChildDirectory(root *os.Root, name string, create bool) (*os.Root, error) {
	return localNodeOpenChild(root, name, create, true)
}
func localNodeOpenChild(root *os.Root, name string, create, private bool) (*os.Root, error) {
	before, err := root.Lstat(name)
	if create && errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		before, err = root.Lstat(name)
	}
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || private && !localNodePrivate(before, true) {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, e := child.Stat(".")
	after, e2 := root.Lstat(name)
	if e != nil || e2 != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		child.Close()
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	return child, nil
}
func readLocalNodeFile(root *os.Root, name string, limit int) ([]byte, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !localNodePrivate(before, false) || before.Size() < 1 {
		return nil, nil, ErrLocalNodeDiscoveryInvalid
	}
	if before.Size() > int64(limit) {
		return nil, nil, ErrLocalNodeDiscoveryLimit
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, nil, ErrLocalNodeDiscoveryInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	after, statErr := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if statErr != nil || !localNodePrivate(after, false) || !os.SameFile(before, after) || before.Size() != int64(len(data)) || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, ErrLocalNodeDiscoveryInvalid
	}
	return data, after, nil
}

// Error detail intentionally contains no remote payloads or credentials.
func localNodeConfigError(reason string) error {
	return fmt.Errorf("%w: %s", ErrLocalNodeConfigRequired, reason)
}
