package main

import (
	"errors"
	"path/filepath"
)

var (
	errMCPGroupRouteRequired    = errors.New("GROUP_SELECTION_REQUIRED: select an exact authorized Group")
	errMCPGroupRouteAmbiguous   = errors.New("GROUP_SELECTION_AMBIGUOUS: qualify the authorized Hub and Network")
	errMCPGroupRouteUnavailable = errors.New("GROUP_ROUTE_UNAVAILABLE: refresh this Thread's authorized Groups")
	errMCPOriginalGroupRoute    = errors.New("ORIGINAL_ROUTE_UNAVAILABLE: the original operation remains in its original scope")
)

// mcpGroupRoute is routing metadata from a child's verified current self-view,
// never a grant or model-supplied connection configuration. The caller must
// verify each pin, registration and current Group authority before constructing
// this value, and must repeat the child Guard before any business operation.
type mcpGroupRoute struct {
	Pin                            LocalNodeConnectionPin
	Native                         mcpTrustedContext
	NetworkID, GroupID, EndpointID string
	OwnerID, PrincipalID           string
	RegistrationDigest             string
	RegistrationRevision           uint64
}

type mcpGroupRouteChoice struct {
	HubID, NetworkID, GroupID string
}

func validMCPSenderRoute(route mcpGroupRoute) bool {
	origin, err := normalizeMCPAPIOrigin(route.Pin.APIOrigin)
	if err != nil || origin != route.Pin.APIOrigin || route.Native.NodeID != route.Pin.NodeID || route.RegistrationRevision == 0 ||
		route.Native.Harness != "codex" || !localContextText(route.Native.NativeSessionID, 128) || !localNodePath(route.Native.Workspace) ||
		!localContextHex(route.RegistrationDigest, 64) {
		return false
	}
	if !localContextText(route.Pin.Binding.HubKeyID, 256) || !localContextHex(route.Pin.Binding.HubFingerprint, 64) || route.Pin.Binding.HubKeyVersion == 0 {
		return false
	}
	for _, id := range []string{route.Pin.HubID, route.Pin.NodeID, route.NetworkID, route.EndpointID, route.OwnerID, route.PrincipalID} {
		if !localContextText(id, 256) {
			return false
		}
	}
	return true
}

func validMCPGroupRoute(route mcpGroupRoute) bool {
	return validMCPSenderRoute(route) && localContextText(route.GroupID, 256)
}

// A Thread can register a different Node/Endpoint identity at each Hub. NodeID
// remains immutable within each sender route, not in the cross-Hub Thread key.
func sameMCPRouteThread(a, b mcpTrustedContext) bool {
	return a.Harness == b.Harness && a.NativeSessionID == b.NativeSessionID && a.Workspace == b.Workspace &&
		a.Harness == "codex" && localContextText(a.NativeSessionID, 128) && filepath.IsAbs(a.Workspace) && filepath.Clean(a.Workspace) == a.Workspace
}

// resolveMCPGroupRoute has no default Hub, file access, cache write or network
// action. Missing and duplicate names cannot borrow a previously selected Hub.
func resolveMCPGroupRoute(routes []mcpGroupRoute, native mcpTrustedContext, choice mcpGroupRouteChoice) (mcpGroupRoute, error) {
	var zero mcpGroupRoute
	if choice.GroupID == "" {
		return zero, errMCPGroupRouteRequired
	}
	for _, id := range []string{choice.HubID, choice.NetworkID, choice.GroupID} {
		if id != "" && !localContextText(id, 256) {
			return zero, errMCPGroupRouteUnavailable
		}
	}
	var found *mcpGroupRoute
	for _, route := range routes {
		if !validMCPGroupRoute(route) {
			return zero, errMCPGroupRouteUnavailable
		}
		if !sameMCPRouteThread(route.Native, native) || route.GroupID != choice.GroupID || choice.HubID != "" && route.Pin.HubID != choice.HubID ||
			choice.NetworkID != "" && route.NetworkID != choice.NetworkID {
			continue
		}
		if found != nil && *found != route {
			return zero, errMCPGroupRouteAmbiguous
		}
		copy := route
		found = &copy
	}
	if found == nil {
		return zero, errMCPGroupRouteUnavailable
	}
	return *found, nil
}

// resolveMCPOriginalGroupRoute is the stricter dispatch fence. It is not used
// for historical read-only lookup: a changed grant cannot dispatch an old
// operation by borrowing another currently usable Group or registration.
func resolveMCPOriginalGroupRoute(routes []mcpGroupRoute, original mcpGroupRoute) (mcpGroupRoute, error) {
	var zero mcpGroupRoute
	if !validMCPGroupRoute(original) {
		return zero, errMCPOriginalGroupRoute
	}
	for _, route := range routes {
		if !validMCPGroupRoute(route) {
			return zero, errMCPOriginalGroupRoute
		}
		if route == original {
			return route, nil
		}
		// Only freshly verified numeric reachability may change. All stored
		// identity, transport descriptor and binding coordinates stay exact.
		if route.Pin.HubTransportDescriptor != "" && route.Pin.HubTransportDescriptor == original.Pin.HubTransportDescriptor {
			copy := route
			copy.Pin.HubDialAddress = original.Pin.HubDialAddress
			if copy == original {
				return route, nil
			}
		}
	}
	return zero, errMCPOriginalGroupRoute
}

type mcpOriginalSender struct {
	HubID, APIOrigin, NetworkID, EndpointID, OwnerID, PrincipalID string
	HubKeyID, HubFingerprint                                      string
	HubKeyVersion                                                 uint64
	Native                                                        mcpTrustedContext
	RegistrationDigest                                            string
}

func (route mcpGroupRoute) originalSender() mcpOriginalSender {
	return mcpOriginalSender{HubID: route.Pin.HubID, APIOrigin: route.Pin.APIOrigin, NetworkID: route.NetworkID, EndpointID: route.EndpointID,
		OwnerID: route.OwnerID, PrincipalID: route.PrincipalID, Native: route.Native, RegistrationDigest: route.RegistrationDigest,
		HubKeyID: route.Pin.Binding.HubKeyID, HubFingerprint: route.Pin.Binding.HubFingerprint, HubKeyVersion: route.Pin.Binding.HubKeyVersion}
}

// This locates the original sender for read-only local history/reconciliation,
// including after its last Group was removed. It confers no dispatch authority.
// The fresh pin/epoch and registration generation may differ, but the original
// Hub, Network, Node, Owner, Principal, Endpoint and native identity cannot.
// Callers retain the saved Group and original packet bytes for any lookup; they
// must never use the returned current Group or grant to reconstruct a packet.
func resolveMCPOriginalSenderRoute(senders []mcpGroupRoute, original mcpGroupRoute) (mcpGroupRoute, error) {
	var zero mcpGroupRoute
	if !validMCPSenderRoute(original) {
		return zero, errMCPOriginalGroupRoute
	}
	var found *mcpGroupRoute
	for _, route := range senders {
		if !validMCPSenderRoute(route) {
			return zero, errMCPOriginalGroupRoute
		}
		if route.originalSender() != original.originalSender() {
			continue
		}
		if found != nil && *found != route {
			return zero, errMCPGroupRouteAmbiguous
		}
		copy := route
		found = &copy
	}
	if found == nil {
		return zero, errMCPOriginalGroupRoute
	}
	return *found, nil
}
