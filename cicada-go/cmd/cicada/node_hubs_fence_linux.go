package main

import (
	"context"
	"os"
)

func currentNodeHubFence(ctx context.Context, userRoot, id string, epoch uint64) (nodeHubRegistryEntry, error) {
	root, _, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return nodeHubRegistryEntry{}, err
	}
	defer root.Close()
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return nodeHubRegistryEntry{}, err
	}
	i, err := selectNodeHubEntry(r, LocalNodeHubSelection{ConnectionID: id})
	if err != nil {
		return nodeHubRegistryEntry{}, err
	}
	e := r.Connections[i]
	if e.DesiredState != "ENABLED" || e.LocalFence != epoch {
		return e, errNodeHubNotReady
	}
	return e, nil
}

func checkManagedMachineHubFence(ctx context.Context) error {
	h, ok := machineHubFrom(ctx)
	if !ok || h.ManagedConnectionID == "" {
		return nil
	}
	e, err := currentNodeHubFence(ctx, h.ManagedUserRoot, h.ManagedConnectionID, h.ManagedConnectionEpoch)
	if err != nil {
		return err
	}
	if e.HubID != h.HubID || e.Origin != h.Origin || e.NodeID != h.NodeID || e.StateDir != h.StateDir || e.WriterRoot != h.WriterRoot {
		return errNodeHubConflict
	}
	return nil
}

func checkManagedLocalNodePin(ctx context.Context, p LocalNodeConnectionPin) error {
	if p.ConnectionID == "" {
		ref, err := readNodeHubStateReference(ctx, p.StateDir, p.NodeID)
		if err != nil {
			return err
		}
		if ref != nil {
			return errNodeHubNotReady
		}
		return nil
	}
	e, err := currentNodeHubFence(ctx, p.UserRoot, p.ConnectionID, p.ConnectionEpoch)
	if err != nil {
		return err
	}
	if e.HubID != p.HubID || e.Origin != p.APIOrigin || e.NodeID != p.NodeID || e.StateDir != p.StateDir || e.WriterRoot != p.WriterRoot || e.MCPSessionStateFile != p.MCPSessionStateFile || e.MCPOutboxStateFile != p.MCPOutboxStateFile {
		return errNodeHubConflict
	}
	return nil
}

func installNodeHubStateReference(ctx context.Context, h *machineHubContext) error {
	ref, err := readNodeHubStateReference(ctx, h.StateDir, h.NodeID)
	if err != nil {
		return err
	}
	if ref == nil {
		return nil
	}
	if h.ManagedConnectionID != "" && (h.ManagedConnectionID != ref.ConnectionID || h.ManagedUserRoot != ref.UserRoot) {
		return errNodeHubConflict
	}
	root, _, err := nodeHubRoot(ctx, ref.UserRoot, false)
	if err != nil {
		return err
	}
	defer root.Close()
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return err
	}
	i, err := selectNodeHubEntry(r, LocalNodeHubSelection{ConnectionID: ref.ConnectionID, NodeID: h.NodeID})
	if err != nil {
		return err
	}
	e := r.Connections[i]
	if h.ManagedConnectionID != "" && h.ManagedConnectionEpoch != e.LocalFence {
		return errNodeHubNotReady
	}
	if e.DesiredState != "ENABLED" || e.StateDir != h.StateDir || e.WriterRoot != h.WriterRoot || h.HubID != "" && h.HubID != e.HubID || h.Origin != e.Origin {
		return errNodeHubNotReady
	}
	h.ManagedUserRoot, h.ManagedConnectionID, h.ManagedConnectionEpoch = ref.UserRoot, ref.ConnectionID, e.LocalFence
	return nil
}

func nodeHubStateDirectoryExists(state, node string) bool {
	_, err := os.Lstat(machineNodeStateDir(state, node))
	return err == nil
}
