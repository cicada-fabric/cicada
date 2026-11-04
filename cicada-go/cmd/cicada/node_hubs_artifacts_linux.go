package main

import (
	"context"
	"os"
)

// ValidateRetainedLocalNodeArtifacts proves only that a fresh, independently
// authorized child may retain the original storage pin. It never upgrades a
// live pin, context, credential or packet, nor initializes or rewrites storage.
// Every later operation still needs its current Host/Hub/Group authority and
// final admission fence. In particular, this is not an intent-resume resolver.
func ValidateRetainedLocalNodeArtifacts(ctx context.Context, historical, current LocalNodeConnectionPin) error {
	if ctx == nil || ctx.Err() != nil || validateLocalNodePin(historical) != nil || validateLocalNodePin(current) != nil || current.ConnectionID == "" {
		return ErrLocalNodeBindingChanged
	}
	legacy := historical.ConnectionID == ""
	if !legacy && (historical.ConnectionID != current.ConnectionID || historical.ConnectionEpoch >= current.ConnectionEpoch) {
		return ErrLocalNodeBindingChanged
	}
	// Reachability changes are intentionally not folded into an epoch change.
	// This purpose seam permits only the explicit local generation difference.
	immutable := historical
	immutable.ConnectionID, immutable.ConnectionEpoch = current.ConnectionID, current.ConnectionEpoch
	if immutable != current {
		return ErrLocalNodeBindingChanged
	}
	root, _, err := nodeHubRoot(ctx, current.UserRoot, false)
	if err != nil {
		return ErrLocalNodeBindingChanged
	}
	defer root.Close()
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return ErrLocalNodeBindingChanged
	}
	i, err := selectNodeHubEntry(r, LocalNodeHubSelection{ConnectionID: current.ConnectionID, HubID: current.HubID, NodeID: current.NodeID})
	if err != nil {
		return ErrLocalNodeBindingChanged
	}
	e := r.Connections[i]
	if e.DesiredState != "ENABLED" || e.LocalFence != current.ConnectionEpoch || checkManagedLocalNodePin(ctx, current) != nil {
		return ErrLocalNodeBindingChanged
	}
	ref, err := readNodeHubStateReference(ctx, current.StateDir, current.NodeID)
	if err != nil || ref == nil || ref.UserRoot != current.UserRoot || ref.ConnectionID != current.ConnectionID {
		return ErrLocalNodeBindingChanged
	}
	if legacy && validateRetainedNodeAdoptionOrigin(root, current.UserRoot, historical, e) != nil {
		return ErrLocalNodeBindingChanged
	}
	if current.ConnectionEpoch != 1 {
		retired, err := readNodeHubRetired(root, LocalNodeHubSelection{ConnectionID: e.ConnectionID, HubID: e.HubID, NodeID: e.NodeID, HubAddress: e.HubAddress})
		if err != nil || retired.Removal.State != "LOCAL_STOPPED" || retired.Removal.RemoteRevocation != "NOT_REQUESTED" || retired.Entry.LocalFence+1 != e.LocalFence || historical.ConnectionEpoch >= retired.Entry.LocalFence {
			return ErrLocalNodeBindingChanged
		}
		previous := e
		previous.DesiredState, previous.LocalFence = "REMOVING", retired.Entry.LocalFence
		if previous != retired.Entry {
			return ErrLocalNodeBindingChanged
		}
	} else if !legacy {
		return ErrLocalNodeBindingChanged
	}
	// Do not trust a caller-supplied "live" label or merely configured metadata.
	// The returned observation is not exposed as a replacement historical pin.
	live, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: current.UserRoot, HubID: current.HubID, NodeID: current.NodeID}, &current)
	if err != nil || live.Pin != current {
		return ErrLocalNodeBindingChanged
	}
	return nil
}

func validateRetainedNodeAdoptionOrigin(root *os.Root, userRoot string, historical LocalNodeConnectionPin, current nodeHubRegistryEntry) error {
	c, _, err := readNodeHubService(root, userRoot)
	if err != nil || c.OriginalService == nil || !localContextHex(c.OriginalServiceDigest, 64) {
		return ErrLocalNodeBindingChanged
	}
	s, err := validateNodeServiceConfig(*c.OriginalService, userRoot, "")
	if err != nil {
		return ErrLocalNodeBindingChanged
	}
	retained, err := nodeHubOriginalPin(*c.OriginalService, s)
	if err != nil || retained != historical {
		return ErrLocalNodeBindingChanged
	}
	adopted := current
	adopted.LocalFence = 1
	return verifyNodeHubAdoptionReceipt(root, c.OriginalServiceDigest, nodeServiceUnit(*c.OriginalService, s), historical, adopted)
}
