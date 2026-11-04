package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

const nodeHubRegistryName = "node-hubs.json"

var errNodeHubNotFound = errors.New("NODE_HUB_NOT_FOUND")
var errNodeHubConflict = errors.New("NODE_HUB_CONFLICT")
var errNodeHubLimit = errors.New("NODE_HUB_LIMIT")
var errNodeHubPending = errors.New("NODE_HUB_PENDING")
var errNodeHubUnavailable = errors.New("NODE_HUB_UNAVAILABLE")
var errNodeHubNotReady = errors.New("NODE_HUB_NOT_READY")

func nodeHubID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func nodeHubRoot(ctx context.Context, selected string, create bool) (*os.Root, string, error) {
	path, err := apppaths.ResolveUserRoot(selected)
	if err != nil {
		return nil, "", ErrLocalNodeHubConfig
	}
	r, err := openNodeHubDirectory(ctx, path, create)
	if err != nil {
		return nil, "", ErrLocalNodeHubConfig
	}
	return r, path, nil
}

// The discovery reader intentionally never initializes storage. The manager's
// explicit create operations use pinned no-symlink ancestor handles instead.
func openNodeHubDirectory(ctx context.Context, path string, create bool) (*os.Root, error) {
	if !create {
		return openLocalNodeDirectory(ctx, path, false)
	}
	if ctx.Err() != nil || !localNodePath(path) {
		return nil, ErrLocalNodeHubConfig
	}
	if _, err := apppaths.ResolveUserRoot(path); err != nil {
		return nil, ErrLocalNodeHubConfig
	}
	start := filepath.VolumeName(path) + string(filepath.Separator)
	r, err := os.OpenRoot(start)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, start), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		if ctx.Err() != nil {
			r.Close()
			return nil, ctx.Err()
		}
		next, e := localNodeOpenChild(r, part, true, false)
		r.Close()
		if e != nil {
			return nil, e
		}
		r = next
	}
	info, err := r.Stat(".")
	uid, ok := uint32(0), false
	if err == nil {
		uid, ok = machineAgentJoinSocketOwner(info)
	}
	if err != nil || !ok || uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		r.Close()
		return nil, ErrLocalNodeHubConfig
	}
	return r, nil
}

func lockNodeHubs(root *os.Root) (*os.File, error) {
	const name = "node-hubs.lock"
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, e := root.Lstat(name)
		if e != nil || !localNodePrivate(info, false) {
			return nil, ErrLocalNodeHubConfig
		}
		f, err = root.OpenFile(name, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, ErrLocalNodeHubConfig
	}
	before, e := root.Lstat(name)
	opened, se := f.Stat()
	if e != nil || se != nil || !localNodePrivate(before, false) || !os.SameFile(before, opened) {
		f.Close()
		return nil, ErrLocalNodeHubConfig
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errNodeHubConflict
	}
	after, e := root.Lstat(name)
	if e != nil || !os.SameFile(after, opened) {
		f.Close()
		return nil, ErrLocalNodeHubConfig
	}
	return f, nil
}

// All callers changing these records hold the same registry lock. Expected
// bytes make adoption/configuration changes explicit CAS operations as well.
func writeNodeHubAtomic(root *os.Root, name string, data, expected []byte) error {
	if len(data) == 0 || len(data) > MaxLocalNodeHubRegistryBytes || strings.ContainsAny(name, "/\\") {
		return ErrLocalNodeHubConfig
	}
	old, _, err := readLocalNodeFile(root, name, MaxLocalNodeHubRegistryBytes)
	if expected == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errNodeHubConflict
		}
	} else if err != nil || !bytes.Equal(old, expected) {
		return errNodeHubConflict
	}
	id, err := nodeHubID()
	if err != nil {
		return err
	}
	temp := ".node-hubs-" + id
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	defer root.Remove(temp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	// Recheck the exact protected target immediately before replacement. An
	// unsafe or externally changed record is never repaired or overwritten.
	current, _, err := readLocalNodeFile(root, name, MaxLocalNodeHubRegistryBytes)
	if expected == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errNodeHubConflict
		}
		if err = root.Link(temp, name); err != nil {
			return errNodeHubConflict
		}
	} else {
		if err != nil || !bytes.Equal(current, expected) {
			return errNodeHubConflict
		}
		if err = root.Rename(temp, name); err != nil {
			return ErrLocalNodeHubConfig
		}
	}
	dir, err := root.Open(".")
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func readNodeHubRegistry(root *os.Root) (nodeHubRegistry, []byte, error) {
	b, _, err := readLocalNodeFile(root, nodeHubRegistryName, MaxLocalNodeHubRegistryBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nodeHubRegistry{}, nil, errNodeHubNotFound
	}
	if err != nil {
		return nodeHubRegistry{}, nil, ErrLocalNodeHubConfig
	}
	r, err := decodeNodeHubRegistry(b)
	return r, b, err
}

func saveNodeHubRegistry(root *os.Root, r nodeHubRegistry, expected []byte) error {
	b, err := json.Marshal(r)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	if _, err = decodeNodeHubRegistry(b); err != nil {
		return err
	}
	return writeNodeHubAtomic(root, nodeHubRegistryName, append(b, '\n'), expected)
}

func initializeNodeHubRegistry(ctx context.Context, userRoot string) error {
	root, path, err := nodeHubRoot(ctx, userRoot, true)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockNodeHubs(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, _, err = readNodeHubRegistry(root); err == nil {
		return nil
	} else if !errors.Is(err, errNodeHubNotFound) {
		return err
	}
	id, err := nodeHubID()
	if err != nil {
		return err
	}
	name, err := os.Hostname()
	if err != nil || !localNodeHubText(name, 128) {
		name = "Cicada Node"
	}
	return saveNodeHubRegistry(root, nodeHubRegistry{Format: LocalNodeHubRegistryFormat, Revision: 1, NodeID: "node-" + id, NodeName: name, WriterRoot: apppaths.NodeStateRoot(path), Connections: []nodeHubRegistryEntry{}}, nil)
}

func mutateNodeHubRegistry(ctx context.Context, userRoot string, fn func(*os.Root, *nodeHubRegistry) error) (nodeHubRegistry, error) {
	root, _, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return nodeHubRegistry{}, err
	}
	defer root.Close()
	lock, err := lockNodeHubs(root)
	if err != nil {
		return nodeHubRegistry{}, err
	}
	defer lock.Close()
	r, raw, err := readNodeHubRegistry(root)
	if err != nil {
		return r, err
	}
	if r.Revision >= 1<<63-1 {
		return r, ErrLocalNodeHubConfig
	}
	if err = fn(root, &r); err != nil {
		return r, err
	}
	r.Revision++
	err = saveNodeHubRegistry(root, r, raw)
	return r, err
}

func selectNodeHubEntry(r nodeHubRegistry, s LocalNodeHubSelection) (int, error) {
	if s.ConnectionID == "" && s.Alias == "" && s.HubAddress == "" && s.HubID == "" {
		return -1, errNodeHubNotFound
	}
	for i, e := range r.Connections {
		if s.ConnectionID != "" && s.ConnectionID != e.ConnectionID || s.Alias != "" && !strings.EqualFold(s.Alias, e.Alias) || s.HubAddress != "" && s.HubAddress != e.HubAddress || s.HubID != "" && s.HubID != e.HubID || s.NodeID != "" && s.NodeID != e.NodeID {
			continue
		}
		return i, nil
	}
	return -1, errNodeHubNotFound
}

type nodeHubRetired struct {
	Format  string               `json:"format"`
	Entry   nodeHubRegistryEntry `json:"entry"`
	Removal LocalNodeHubRemoval  `json:"removal"`
}

func nodeHubRetiredName(alias string) string {
	h := sha256.Sum256([]byte(strings.ToLower(alias)))
	return "node-hub-retired-" + hex.EncodeToString(h[:]) + ".json"
}

func nodeHubEntryView(e nodeHubRegistryEntry) LocalNodeHubView {
	return LocalNodeHubView{ConnectionID: e.ConnectionID, HubID: e.HubID, NodeID: e.NodeID, Alias: e.Alias, HubAddress: e.HubAddress, NodeName: e.NodeName, DesiredState: e.DesiredState, PairingState: "UNKNOWN", RuntimeState: "UNKNOWN", HubOnline: "UNKNOWN", LocalFence: e.LocalFence}
}

type nodeHubStateReference struct {
	Format       string `json:"format"`
	UserRoot     string `json:"user_root"`
	ConnectionID string `json:"connection_id"`
	NodeID       string `json:"node_id"`
}

const nodeHubStateReferenceName = "node-hub-manager-ref.json"

func writeNodeHubStateReference(ctx context.Context, userRoot string, e nodeHubRegistryEntry) error {
	directory := machineNodeStateDir(e.StateDir, e.NodeID)
	root, err := openNodeHubDirectory(ctx, directory, true)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	defer root.Close()
	ref := nodeHubStateReference{"cicada.node-hub-state-reference.v1", userRoot, e.ConnectionID, e.NodeID}
	b, _ := json.Marshal(ref)
	old, _, err := readLocalNodeFile(root, nodeHubStateReferenceName, 4096)
	if err == nil {
		if bytes.Equal(bytes.TrimSpace(old), b) {
			return nil
		}
		return errNodeHubConflict
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrLocalNodeHubConfig
	}
	return writeNodeHubAtomic(root, nodeHubStateReferenceName, append(b, '\n'), nil)
}

func readNodeHubStateReference(ctx context.Context, state, node string) (*nodeHubStateReference, error) {
	if _, err := os.Lstat(machineNodeStateDir(state, node)); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, ErrLocalNodeHubConfig
	}
	root, err := openLocalNodeDirectory(ctx, machineNodeStateDir(state, node), false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	b, _, err := readLocalNodeFile(root, nodeHubStateReferenceName, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var ref nodeHubStateReference
	if err != nil || decodeLocalNodeJSON(b, &ref) != nil || ref.Format != "cicada.node-hub-state-reference.v1" || !localNodePath(ref.UserRoot) || !localContextHex(ref.ConnectionID, 32) || ref.NodeID != node {
		return nil, ErrLocalNodeHubConfig
	}
	return &ref, nil
}

func nodeHubDefaultEntry(r nodeHubRegistry, root, id, alias, address string) nodeHubRegistryEntry {
	state := filepath.Join(r.WriterRoot, "hubs", id)
	return nodeHubRegistryEntry{ConnectionID: id, Alias: alias, NodeID: r.NodeID, NodeName: r.NodeName, HubAddress: address, StateDir: state, WriterRoot: r.WriterRoot, MCPSessionStateFile: filepath.Join(state, "mcp", "sessions.json"), MCPOutboxStateFile: filepath.Join(state, "mcp", "outbox.sqlite3"), DesiredState: "ENABLED", LocalFence: 1}
}
