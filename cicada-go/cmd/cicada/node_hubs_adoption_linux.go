package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

type nodeHubAdoptionReceipt struct {
	Format               string                 `json:"format"`
	OriginalConfigDigest string                 `json:"original_config_digest"`
	OriginalUnit         string                 `json:"original_unit"`
	OriginalPID          int                    `json:"original_pid"`
	OldPin               LocalNodeConnectionPin `json:"old_pin"`
	NewPin               LocalNodeConnectionPin `json:"new_pin"`
}

func nodeHubAdoptionName(id string) string { return "node-hub-adoption-" + id + ".json" }
func nodeHubOriginalPin(c nodeServiceConfig, s nodeServiceSelection) (LocalNodeConnectionPin, error) {
	client, _, err := loadMachineRecoveryClient(s.state, s.id)
	if err != nil {
		return LocalNodeConnectionPin{}, errNodeHubNotReady
	}
	if err = requireExistingNodeServiceState(c, s); err != nil {
		return LocalNodeConnectionPin{}, err
	}
	state := client.state
	socket, err := machineAgentJoinSocketPathChecked(s.state, s.id)
	if err != nil {
		return LocalNodeConnectionPin{}, err
	}
	p := LocalNodeConnectionPin{UserRoot: c.UserRoot, HubID: state.HubID, APIOrigin: state.HubOrigin, NodeID: state.NodeID, SocketPath: socket, StateDir: s.state, WriterRoot: s.state, MCPSessionStateFile: s.session, MCPOutboxStateFile: s.outbox, HubTransportDescriptor: state.HubTransportDescriptor, HubDialAddress: state.HubDialAddress, Binding: LocalNodeBinding{BindingID: state.BindingID, BindingVersion: state.BindingVersion, NodeKeyEpoch: state.NodeKeyEpoch, NodeKeyVersion: state.NodeKeyVersion, HubKeyVersion: state.HubKeyVersion, NodeKeyID: state.NodeKeyID, NodeKeyFingerprint: state.NodeKeyFingerprint, HubKeyID: state.HubKeyID, HubFingerprint: state.HubFingerprint}}
	if validateLocalNodePin(p) != nil {
		return LocalNodeConnectionPin{}, errNodeHubNotReady
	}
	return p, nil
}

func adoptNodeHubFromService(ctx context.Context, in LocalNodeHubAddInput) (LocalNodeHubView, error) {
	if in.ConnectionID != "" || in.HubAddress != "" || in.RetryPairing || in.NodeID != "" || in.NodeName != "" {
		return LocalNodeHubView{}, ErrLocalNodeHubConfig
	}
	root, path, err := nodeHubRoot(ctx, in.UserRoot, false)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	defer root.Close()
	serviceLock, err := lockNodeService(root)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	defer serviceLock.Close()
	raw, _, err := readLocalNodeFile(root, nodeServiceConfigName, 64<<10)
	if err != nil {
		return LocalNodeHubView{}, ErrLocalNodeHubConfig
	}
	var old nodeServiceConfig
	var manager nodeHubServiceConfig
	var originalDigest string
	alreadyManager := decodeLocalNodeJSON(raw, &manager) == nil && manager.Format == nodeHubServiceFormat
	if alreadyManager {
		if validateNodeHubService(manager, path) != nil || manager.OriginalService == nil {
			return LocalNodeHubView{}, errNodeHubNotFound
		}
		old = *manager.OriginalService
		originalDigest = manager.OriginalServiceDigest
	} else {
		if decodeLocalNodeJSON(raw, &old) != nil || old.Format != nodeServiceFormat {
			return LocalNodeHubView{}, ErrLocalNodeHubConfig
		}
		h := sha256.Sum256(raw)
		originalDigest = hex.EncodeToString(h[:])
	}
	selection, err := validateNodeServiceConfig(old, path, "")
	if err != nil {
		return LocalNodeHubView{}, err
	}
	oldPin, err := nodeHubOriginalPin(old, selection)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	hooks := nodeHubHooks(ctx)
	unit := nodeServiceUnit(old, selection)
	state, err := inspectNodeService(ctx, hooks.ServiceRunner, unit, "Cicada managed Node "+originalDigest)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	if state["LoadState"] != "not-found" && (state["MainPID"] != "0" || state["ActiveState"] != "inactive" && state["ActiveState"] != "failed") {
		return LocalNodeHubView{}, errNodeHubConflict
	}
	// A response-loss replay may arrive while the adopted manager owns the
	// original Agent lock. Verify the durable exact mapping without stopping it.
	if alreadyManager {
		r, _, re := readNodeHubRegistry(root)
		if re != nil {
			return LocalNodeHubView{}, re
		}
		for _, e := range r.Connections {
			if e.StateDir != selection.state || e.NodeID != selection.id {
				continue
			}
			if in.Alias != "" && !strings.EqualFold(in.Alias, e.Alias) {
				return LocalNodeHubView{}, errNodeHubConflict
			}
			if re = verifyNodeHubAdoptionReceipt(root, originalDigest, unit, oldPin, e); re != nil {
				return LocalNodeHubView{}, re
			}
			serviceLock.Close()
			if re = controlNodeHubService(ctx, "on", manager, raw, hooks.ServiceRunner, io.Discard); re != nil {
				return nodeHubEntryView(e), re
			}
			if list, le := ListLocalNodeHubConnections(ctx, path); le == nil {
				for _, v := range list.Connections {
					if v.ConnectionID == e.ConnectionID {
						return v, nil
					}
				}
			}
			return nodeHubEntryView(e), nil
		}
		return LocalNodeHubView{}, errNodeHubNotFound
	}
	agent, err := nodelock.AcquireAgent(selection.state, selection.id)
	if err != nil {
		return LocalNodeHubView{}, errNodeHubConflict
	}
	defer agent.Close()
	release, err := acquireNodeHubAdmission(ctx, selection.state, selection.id, true)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	defer release()
	if err = rejectMachineRecoveryMutation(selection.state, selection.state, selection.id); err != nil {
		return LocalNodeHubView{}, err
	}
	if err = initializeNodeHubRegistry(ctx, path); err != nil {
		return LocalNodeHubView{}, err
	}
	registryLock, err := lockNodeHubs(root)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	defer registryLock.Close()
	r, registryRaw, err := readNodeHubRegistry(root)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	for _, e := range r.Connections {
		if e.StateDir != selection.state || e.NodeID != selection.id {
			continue
		}
		if e.LocalFence != 1 || e.DesiredState != "ENABLED" || in.Alias != "" && !strings.EqualFold(in.Alias, e.Alias) {
			return LocalNodeHubView{}, errNodeHubConflict
		}
		re := verifyNodeHubAdoptionReceipt(root, originalDigest, unit, oldPin, e)
		if re != nil {
			return LocalNodeHubView{}, re
		}
		manager, raw, re = ensureNodeHubAdoptionService(root, path, old, originalDigest, manager, raw, alreadyManager)
		if re != nil {
			return LocalNodeHubView{}, re
		}
		registryLock.Close()
		release()
		agent.Close()
		serviceLock.Close()
		if re = controlNodeHubService(ctx, "on", manager, raw, hooks.ServiceRunner, io.Discard); re != nil {
			return nodeHubEntryView(e), re
		}
		if list, le := ListLocalNodeHubConnections(ctx, path); le == nil {
			for _, v := range list.Connections {
				if v.ConnectionID == e.ConnectionID {
					return v, nil
				}
			}
		}
		return nodeHubEntryView(e), nil
	}
	if len(r.Connections) != 0 || r.WriterRoot != selection.state && len(r.Connections) > 0 {
		return LocalNodeHubView{}, errNodeHubConflict
	}
	alias := in.Alias
	if alias == "" {
		alias = "original"
	}
	if !localNodeHubText(alias, 128) {
		return LocalNodeHubView{}, ErrLocalNodeHubConfig
	}
	id, err := nodeHubID()
	if err != nil {
		return LocalNodeHubView{}, err
	}
	if ref, e := readNodeHubStateReference(ctx, selection.state, selection.id); e != nil {
		return LocalNodeHubView{}, e
	} else if ref != nil {
		if ref.UserRoot != path {
			return LocalNodeHubView{}, errNodeHubConflict
		}
		id = ref.ConnectionID
	}
	entry := nodeHubRegistryEntry{ConnectionID: id, Alias: alias, HubID: oldPin.HubID, NodeID: oldPin.NodeID, NodeName: nodeServiceOriginalName(old), HubAddress: oldPin.HubDialAddress, Origin: oldPin.APIOrigin, StateDir: oldPin.StateDir, WriterRoot: oldPin.WriterRoot, MCPSessionStateFile: oldPin.MCPSessionStateFile, MCPOutboxStateFile: oldPin.MCPOutboxStateFile, DesiredState: "ENABLED", LocalFence: 1}
	newPin := oldPin
	newPin.ConnectionID, newPin.ConnectionEpoch = id, 1
	receipt := nodeHubAdoptionReceipt{"cicada.node-hub-adoption.v1", originalDigest, unit, 0, oldPin, newPin}
	b, _ := json.Marshal(receipt)
	existing, _, e := readLocalNodeFile(root, nodeHubAdoptionName(id), MaxLocalNodeHubRegistryBytes)
	if e == nil {
		var previous nodeHubAdoptionReceipt
		if decodeLocalNodeJSON(existing, &previous) != nil || previous != receipt {
			return LocalNodeHubView{}, errNodeHubConflict
		}
	} else if errors.Is(e, os.ErrNotExist) {
		if e = writeNodeHubAtomic(root, nodeHubAdoptionName(id), append(b, '\n'), nil); e != nil {
			return LocalNodeHubView{}, e
		}
	} else {
		return LocalNodeHubView{}, ErrLocalNodeHubConfig
	}
	if err = writeNodeHubStateReference(ctx, path, entry); err != nil {
		return LocalNodeHubView{}, err
	}
	r.WriterRoot, r.NodeID, r.NodeName = entry.WriterRoot, entry.NodeID, entry.NodeName
	r.Connections = append(r.Connections, entry)
	r.Revision++
	if err = saveNodeHubRegistry(root, r, registryRaw); err != nil {
		return LocalNodeHubView{}, err
	}
	manager, raw, err = ensureNodeHubAdoptionService(root, path, old, originalDigest, manager, raw, alreadyManager)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	registryLock.Close()
	release()
	agent.Close()
	serviceLock.Close()
	if err = controlNodeHubService(ctx, "on", manager, raw, hooks.ServiceRunner, io.Discard); err != nil {
		return nodeHubEntryView(entry), err
	}
	// Adoption itself needs no old-server roundtrip. Report the actual local
	// worker state; do not require an offline retired Hub to return a response.
	if list, e := ListLocalNodeHubConnections(ctx, path); e == nil {
		for _, v := range list.Connections {
			if v.ConnectionID == entry.ConnectionID {
				return v, nil
			}
		}
	}
	return nodeHubEntryView(entry), nil
}

func verifyNodeHubAdoptionReceipt(root *os.Root, digest, unit string, old LocalNodeConnectionPin, e nodeHubRegistryEntry) error {
	if e.LocalFence != 1 || e.DesiredState != "ENABLED" || e.HubID != old.HubID || e.Origin != old.APIOrigin || e.NodeID != old.NodeID || e.StateDir != old.StateDir || e.WriterRoot != old.WriterRoot || e.MCPSessionStateFile != old.MCPSessionStateFile || e.MCPOutboxStateFile != old.MCPOutboxStateFile || e.HubAddress != old.HubDialAddress {
		return errNodeHubConflict
	}
	b, _, err := readLocalNodeFile(root, nodeHubAdoptionName(e.ConnectionID), MaxLocalNodeHubRegistryBytes)
	var proof nodeHubAdoptionReceipt
	expected := old
	expected.ConnectionID = e.ConnectionID
	expected.ConnectionEpoch = 1
	if err != nil || decodeLocalNodeJSON(b, &proof) != nil || proof.Format != "cicada.node-hub-adoption.v1" || proof.OriginalConfigDigest != digest || proof.OriginalUnit != unit || proof.OriginalPID != 0 || proof.OldPin != old || proof.NewPin != expected {
		return errNodeHubConflict
	}
	return nil
}

func nodeServiceOriginalName(c nodeServiceConfig) string {
	for i, arg := range c.AgentArgs {
		if arg == "--name" && i+1 < len(c.AgentArgs) {
			return c.AgentArgs[i+1]
		}
	}
	return "Cicada Node"
}

func nodeHubAdoptLegacyArguments(ctx context.Context, root, binary, codex string, args []string, run nodeServiceRunner, out io.Writer) error {
	canonical, _, err := canonicalNodeServiceArgs(root, args)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	c := nodeServiceConfig{Format: nodeServiceFormat, UserRoot: root, Binary: binary, CodexBin: codex, Home: home, Path: os.Getenv("PATH"), CodexHome: os.Getenv("CODEX_HOME"), AgentArgs: canonical}
	selection, err := validateNodeServiceConfig(c, root, binary)
	if err != nil {
		return err
	}
	if err = requireExistingNodeServiceState(c, selection); err != nil {
		return err
	}
	r, _, err := nodeHubRoot(ctx, root, false)
	if err != nil {
		return err
	}
	defer r.Close()
	b, _ := json.Marshal(c)
	if err = writeNodeHubAtomic(r, nodeServiceConfigName, append(b, '\n'), nil); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, nodeHubOperationHooksKey{}, nodeHubOperationHooks{ServiceRunner: run, Binary: binary, Output: out})
	v, err := adoptNodeHubFromService(ctx, LocalNodeHubAddInput{UserRoot: root, FromService: true})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(v)
}

// Explicit compatibility only: exact legacy Pin0 may map to its protected
// adopted epoch1, while the current entry and complete live pin still match.
func ResolveAdoptedLocalNodeConnection(ctx context.Context, oldPin LocalNodeConnectionPin) (LocalNodeConnection, error) {
	if oldPin.ConnectionID != "" || oldPin.ConnectionEpoch != 0 || validateLocalNodePin(oldPin) != nil {
		return LocalNodeConnection{}, ErrLocalNodeBindingChanged
	}
	root, _, err := nodeHubRoot(ctx, oldPin.UserRoot, false)
	if err != nil {
		return LocalNodeConnection{}, err
	}
	defer root.Close()
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return LocalNodeConnection{}, err
	}
	i, err := selectNodeHubEntry(r, LocalNodeHubSelection{HubID: oldPin.HubID, NodeID: oldPin.NodeID})
	if err != nil {
		return LocalNodeConnection{}, err
	}
	e := r.Connections[i]
	if e.LocalFence != 1 || e.DesiredState != "ENABLED" {
		return LocalNodeConnection{}, ErrLocalNodeBindingChanged
	}
	b, _, err := readLocalNodeFile(root, nodeHubAdoptionName(e.ConnectionID), MaxLocalNodeHubRegistryBytes)
	var proof nodeHubAdoptionReceipt
	if err != nil || decodeLocalNodeJSON(b, &proof) != nil || proof.Format != "cicada.node-hub-adoption.v1" || proof.OriginalPID != 0 || !localContextHex(proof.OriginalConfigDigest, 64) || proof.OldPin != oldPin || proof.NewPin.ConnectionID != e.ConnectionID || proof.NewPin.ConnectionEpoch != 1 {
		return LocalNodeConnection{}, ErrLocalNodeBindingChanged
	}
	expected := oldPin
	expected.ConnectionID, expected.ConnectionEpoch = e.ConnectionID, 1
	if expected != proof.NewPin {
		return LocalNodeConnection{}, ErrLocalNodeBindingChanged
	}
	c, _, err := readNodeHubService(root, oldPin.UserRoot)
	if err != nil || c.OriginalService == nil || c.OriginalServiceDigest != proof.OriginalConfigDigest {
		return LocalNodeConnection{}, ErrLocalNodeBindingChanged
	}
	selection, err := validateNodeServiceConfig(*c.OriginalService, oldPin.UserRoot, "")
	if err != nil {
		return LocalNodeConnection{}, err
	}
	retained, err := nodeHubOriginalPin(*c.OriginalService, selection)
	if err != nil || retained != oldPin {
		return LocalNodeConnection{}, ErrLocalNodeBindingChanged
	}
	return ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: oldPin.UserRoot, HubID: e.HubID, NodeID: e.NodeID}, &proof.NewPin)
}

func ensureNodeHubAdoptionService(root *os.Root, path string, old nodeServiceConfig, digest string, manager nodeHubServiceConfig, raw []byte, already bool) (nodeHubServiceConfig, []byte, error) {
	if already {
		return manager, raw, nil
	}
	manager = nodeHubServiceConfig{Format: nodeHubServiceFormat, UserRoot: path, Binary: old.Binary, CodexBin: old.CodexBin, Home: old.Home, Path: old.Path, CodexHome: old.CodexHome, OriginalService: &old, OriginalServiceDigest: digest}
	if validateNodeHubService(manager, path) != nil {
		return manager, nil, ErrLocalNodeHubConfig
	}
	b, _ := json.Marshal(manager)
	b = append(b, '\n')
	if err := writeNodeHubAtomic(root, nodeServiceConfigName, b, raw); err != nil {
		return manager, nil, err
	}
	return manager, b, nil
}
