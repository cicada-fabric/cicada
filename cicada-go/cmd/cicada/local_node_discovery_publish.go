package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localNodePublishConfig struct{ UserRoot, MCPSessionStateFile, MCPOutboxStateFile string }
type localNodeDiscoveryPublication struct {
	config                         localNodePublishConfig
	instance, digest, socket, name string
	nodes                          *os.Root
	inode                          os.FileInfo
}

func startLocalNodeDiscovery(b *machineAgentJoinBridge, config localNodePublishConfig) error {
	if config.UserRoot == "" {
		return nil
	}
	b.discoveryMu.Lock()
	defer b.discoveryMu.Unlock()
	if b.ctx.Err() != nil {
		return b.ctx.Err()
	}
	if b.discovery.Load() != nil {
		return ErrLocalNodeDiscoveryInvalid
	}
	for _, path := range []string{config.UserRoot, config.MCPSessionStateFile, config.MCPOutboxStateFile, b.stateDir} {
		if !localNodePath(path) {
			return ErrLocalNodeConfigRequired
		}
	}
	hub, ok := machineHubFrom(b.ctx)
	if !ok || !localNodePath(hub.WriterRoot) {
		return ErrLocalNodeConfigRequired
	}
	ctx, cancel := context.WithTimeout(b.ctx, localNodeDiscoveryBudget)
	defer cancel()
	root, err := openLocalNodeDirectory(ctx, config.UserRoot, false)
	if err != nil {
		return err
	}
	defer root.Close()
	run, err := localNodeChildDirectory(root, "run", true)
	if err != nil {
		return err
	}
	defer run.Close()
	nodes, err := localNodeChildDirectory(run, "nodes", true)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			nodes.Close()
		}
	}()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	instance := hex.EncodeToString(random[:])
	l := localNodeLocator{localNodeLocatorFormat, instance, b.path}
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > localNodeMaxLocatorBytes {
		return ErrLocalNodeDiscoveryLimit
	}
	name := localNodeLocatorName(b.stateDir, b.nodeID)
	// Refuse an unsafe existing target. Never repair its permission or owner.
	oldData, _, oldErr := readLocalNodeFile(nodes, name, localNodeMaxLocatorBytes)
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return oldErr
	}
	if oldErr == nil {
		var old localNodeLocator
		if decodeLocalNodeJSON(oldData, &old) != nil || old.Format != localNodeLocatorFormat || !localContextHex(old.InstanceID, 32) || old.SocketPath != b.path {
			return ErrLocalNodeDiscoveryInvalid
		}
	}
	temporary := ".local-node-" + instance
	f, err := run.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer run.Remove(temporary)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := run.Rename(temporary, filepath.Join("nodes", name)); err != nil {
		return err
	}
	_, inode, err := readLocalNodeFile(nodes, name, localNodeMaxLocatorBytes)
	if err != nil {
		return err
	}
	dir, err := nodes.Open(".")
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	publication := &localNodeDiscoveryPublication{config: config, instance: instance, digest: localNodeDigest(data), socket: b.path, name: name, nodes: nodes, inode: inode}
	b.discovery.Store(publication)
	success = true
	return nil
}
func (p *localNodeDiscoveryPublication) close() {
	defer p.nodes.Close()
	data, info, err := readLocalNodeFile(p.nodes, p.name, localNodeMaxLocatorBytes)
	if err != nil || !os.SameFile(p.inode, info) || localNodeDigest(data) != p.digest {
		return
	}
	_ = p.nodes.Remove(p.name)
	if directory, err := p.nodes.Open("."); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
}
func (b *machineAgentJoinBridge) localNodeDescribe(q localNodeDescribeRequest) (*localNodeDescription, error) {
	if q.Version != 1 || q.Operation != "local_node_describe" || !localContextHex(q.Nonce, 64) || !localContextHex(q.InstanceID, 32) || !localContextHex(q.LocatorDigest, 64) {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	p := b.discovery.Load()
	if p == nil {
		return nil, ErrLocalNodeNotReady
	}
	if p.instance != q.InstanceID || p.digest != q.LocatorDigest {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	hub, ok := machineHubFrom(b.ctx)
	if !ok || hub.StateDir != b.stateDir || hub.NodeID != b.nodeID || hub.Origin != b.baseURL || hub.HubID == "" {
		return nil, ErrLocalNodeNotReady
	}
	if hub.TLSRuntime != nil || hub.NodeTransport != nil {
		return nil, ErrLocalNodeConfigRequired
	}
	_, statePath := machineNodeControlPaths(b.stateDir, b.nodeID)
	cached, ok := machineNodeControlClients.Load(statePath)
	if !ok {
		return nil, ErrLocalNodeNotReady
	}
	client := cached.(*machineNodeControlClient)
	client.mu.Lock()
	s := client.state
	public := client.identity.Public()
	binding := LocalNodeBinding{BindingID: s.BindingID, BindingVersion: s.BindingVersion, NodeKeyEpoch: s.NodeKeyEpoch, NodeKeyVersion: s.NodeKeyVersion, HubKeyVersion: s.HubKeyVersion, NodeKeyID: s.NodeKeyID, NodeKeyFingerprint: s.NodeKeyFingerprint, HubKeyID: s.HubKeyID, HubFingerprint: s.HubFingerprint}
	ready := s.HubID == hub.HubID && s.NodeID == hub.NodeID && s.HubOrigin == hub.Origin && s.NodeKeyID == public.ID && s.NodeKeyFingerprint == nodewire.IdentityFingerprint(public) && s.HubKeyID == s.HubPublicIdentity.ID && s.HubFingerprint == nodewire.IdentityFingerprint(s.HubPublicIdentity)
	if s.HubTransportDescriptor != hub.HubTransportDescriptor || s.HubDialAddress != hub.HubDialAddress || (s.HubTransportDescriptor != "" && hub.NativeTransport == nil) {
		ready = false
	}
	client.mu.Unlock()
	pin := LocalNodeConnectionPin{UserRoot: p.config.UserRoot, HubID: hub.HubID, APIOrigin: hub.Origin, NodeID: hub.NodeID, SocketPath: p.socket, StateDir: hub.StateDir, WriterRoot: hub.WriterRoot, MCPSessionStateFile: p.config.MCPSessionStateFile, MCPOutboxStateFile: p.config.MCPOutboxStateFile, Binding: binding}
	pin.HubTransportDescriptor, pin.HubDialAddress = s.HubTransportDescriptor, s.HubDialAddress
	if !ready || validateLocalNodePin(pin) != nil {
		return nil, ErrLocalNodeNotReady
	}
	return &localNodeDescription{Nonce: q.Nonce, InstanceID: p.instance, LocatorDigest: p.digest, Connection: pin}, nil
}
func (b *machineAgentJoinBridge) serveLocalNodeDescribe(raw []byte, output io.Writer) {
	response := localNodeDescribeResponse{Version: 1}
	var q localNodeDescribeRequest
	if len(raw) > localNodeMaxRequestBytes || decodeLocalNodeJSON(raw, &q) != nil {
		response.Error = ErrLocalNodeDiscoveryInvalid.Error()
	} else {
		desc, err := b.localNodeDescribe(q)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Description = desc
		}
	}
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > localNodeMaxReplyBytes {
		return
	}
	_, _ = output.Write(append(data, '\n'))
}
