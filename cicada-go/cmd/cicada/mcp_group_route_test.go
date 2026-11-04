package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func syntheticMCPGroupRoute(hub, network, group string) mcpGroupRoute {
	return mcpGroupRoute{Pin: LocalNodeConnectionPin{HubID: hub, APIOrigin: "https://" + hub + ".synthetic.invalid", NodeID: "SYNTHETIC-node",
		StateDir: "/SYNTHETIC/" + hub, MCPSessionStateFile: "/SYNTHETIC/" + hub + "/sessions", MCPOutboxStateFile: "/SYNTHETIC/" + hub + "/outbox"},
		Native:    mcpTrustedContext{Harness: "codex", NativeSessionID: "SYNTHETIC-original-thread", NodeID: "SYNTHETIC-node", Workspace: "/SYNTHETIC/workspace"},
		NetworkID: network, GroupID: group, EndpointID: "SYNTHETIC-" + hub + "-endpoint", OwnerID: "SYNTHETIC-owner", PrincipalID: "SYNTHETIC-" + hub + "-principal", RegistrationDigest: strings.Repeat("a", 64), RegistrationRevision: 1}
}

func TestMCPGroupRouteSelectsHubOnlyFromExplicitGroupAndPreservesOriginalThread(t *testing.T) {
	a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-net-a", "SYNTHETIC-group-a")
	b := syntheticMCPGroupRoute("hub-b", "SYNTHETIC-net-b", "SYNTHETIC-group-b")
	b.Pin.NodeID, b.Native.NodeID = "SYNTHETIC-hub-b-node", "SYNTHETIC-hub-b-node"
	routes := []mcpGroupRoute{a, b}
	before := append([]mcpGroupRoute(nil), routes...)
	for _, target := range []mcpGroupRoute{b, a, b} {
		got, err := resolveMCPGroupRoute(routes, a.Native, mcpGroupRouteChoice{GroupID: target.GroupID})
		if err != nil || got != target || got.Native.NativeSessionID != a.Native.NativeSessionID || got.EndpointID != target.EndpointID {
			t.Fatal("explicit Group changed native identity or selected another Hub", err)
		}
	}
	if !reflect.DeepEqual(before, routes) {
		t.Fatal("selection mutated a connection or saved route")
	}
	for _, available := range [][]mcpGroupRoute{routes, {a}} {
		if _, err := resolveMCPGroupRoute(available, a.Native, mcpGroupRouteChoice{}); !errors.Is(err, errMCPGroupRouteRequired) {
			t.Fatal("missing Group selected a default Hub", err)
		}
	}
}

func TestMCPGroupRouteRejectsAmbiguityAndForeignNativeContext(t *testing.T) {
	a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-net-a", "SYNTHETIC-shared-group")
	b := syntheticMCPGroupRoute("hub-b", "SYNTHETIC-net-b", a.GroupID)
	routes := []mcpGroupRoute{a, b}
	if _, err := resolveMCPGroupRoute(routes, a.Native, mcpGroupRouteChoice{GroupID: a.GroupID}); !errors.Is(err, errMCPGroupRouteAmbiguous) {
		t.Fatal("duplicate Group guessed a Hub", err)
	}
	got, err := resolveMCPGroupRoute(routes, a.Native, mcpGroupRouteChoice{HubID: b.Pin.HubID, NetworkID: b.NetworkID, GroupID: b.GroupID})
	if err != nil || got != b {
		t.Fatal("qualified Group did not select its exact authority", err)
	}
	for _, native := range []mcpTrustedContext{
		{Harness: a.Native.Harness, NativeSessionID: "SYNTHETIC-other-thread", NodeID: a.Native.NodeID, Workspace: a.Native.Workspace},
		{Harness: "SYNTHETIC-other-harness", NativeSessionID: a.Native.NativeSessionID, NodeID: a.Native.NodeID, Workspace: a.Native.Workspace},
		{Harness: a.Native.Harness, NativeSessionID: a.Native.NativeSessionID, NodeID: a.Native.NodeID, Workspace: "/SYNTHETIC/other-workspace"},
	} {
		if _, err := resolveMCPGroupRoute(routes, native, mcpGroupRouteChoice{GroupID: a.GroupID}); !errors.Is(err, errMCPGroupRouteUnavailable) {
			t.Fatal("another native context borrowed the Group", err)
		}
	}
	if got, err := resolveMCPGroupRoute([]mcpGroupRoute{a, a}, a.Native, mcpGroupRouteChoice{GroupID: a.GroupID}); err != nil || got != a {
		t.Fatal("overlapping identical page rows became different routes", err)
	}
}

func TestMCPOriginalSenderReadOnlyLookupSurvivesGrantAndLocalEpochChange(t *testing.T) {
	original := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-network", "SYNTHETIC-original-group")
	current := original
	current.GroupID = "" // A registered sender survives its last Group removal.
	current.RegistrationRevision++
	current.Pin.ConnectionID, current.Pin.ConnectionEpoch = "SYNTHETIC-connection", 7
	current.Pin.Binding.BindingVersion++
	got, err := resolveMCPOriginalSenderRoute([]mcpGroupRoute{current}, original)
	if err != nil || got != current {
		t.Fatal("fresh sender context could not locate original read-only history", err)
	}
	if _, err := resolveMCPOriginalGroupRoute([]mcpGroupRoute{current}, original); !errors.Is(err, errMCPOriginalGroupRoute) {
		t.Fatal("read-only sender match authorized a redispatch", err)
	}
	for _, mutate := range []func(*mcpGroupRoute){
		func(r *mcpGroupRoute) { r.OwnerID = "SYNTHETIC-other-owner" },
		func(r *mcpGroupRoute) { r.PrincipalID = "SYNTHETIC-other-principal" },
		func(r *mcpGroupRoute) { r.EndpointID = "SYNTHETIC-other-endpoint" },
		func(r *mcpGroupRoute) { r.NetworkID = "SYNTHETIC-other-network" },
		func(r *mcpGroupRoute) { r.Pin.NodeID = "SYNTHETIC-other-node"; r.Native.NodeID = r.Pin.NodeID },
		func(r *mcpGroupRoute) { r.Native.NativeSessionID = "SYNTHETIC-other-thread" },
	} {
		changed := current
		mutate(&changed)
		if _, err := resolveMCPOriginalSenderRoute([]mcpGroupRoute{changed}, original); !errors.Is(err, errMCPOriginalGroupRoute) {
			t.Fatal("foreign sender borrowed original history", err)
		}
	}
	duplicate := current
	duplicate.Pin.ConnectionEpoch++
	if _, err := resolveMCPOriginalSenderRoute([]mcpGroupRoute{current, duplicate}, original); !errors.Is(err, errMCPGroupRouteAmbiguous) {
		t.Fatal("ambiguous original sender guessed a current connection", err)
	}
}

func TestMCPOriginalGroupRouteCannotFollowLaterSelectionOrBindingChange(t *testing.T) {
	a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-network", "SYNTHETIC-group")
	b := syntheticMCPGroupRoute("hub-b", a.NetworkID, a.GroupID)
	if _, err := resolveMCPOriginalGroupRoute([]mcpGroupRoute{b}, a); !errors.Is(err, errMCPOriginalGroupRoute) {
		t.Fatal("removed original Hub was replaced by another Hub", err)
	}
	for _, mutate := range []func(*mcpGroupRoute){
		func(r *mcpGroupRoute) { r.Pin.Binding.BindingVersion++ }, func(r *mcpGroupRoute) { r.Pin.APIOrigin = "https://foreign.synthetic.invalid" },
		func(r *mcpGroupRoute) { r.EndpointID = "SYNTHETIC-replacement-endpoint" }, func(r *mcpGroupRoute) { r.RegistrationRevision++ },
		func(r *mcpGroupRoute) { r.GroupID = "SYNTHETIC-other-group" }, func(r *mcpGroupRoute) { r.Native.NativeSessionID = "SYNTHETIC-other-thread" },
	} {
		changed := a
		mutate(&changed)
		if _, err := resolveMCPOriginalGroupRoute([]mcpGroupRoute{changed, b}, a); !errors.Is(err, errMCPOriginalGroupRoute) {
			t.Fatal("original recovery borrowed changed authority", err)
		}
	}
	a.Pin.HubTransportDescriptor = "SYNTHETIC-verified-identical-descriptor"
	a.Pin.HubDialAddress = "192.0.2.1:8787"
	moved := a
	moved.Pin.HubDialAddress = "192.0.2.2:8787"
	if got, err := resolveMCPOriginalGroupRoute([]mcpGroupRoute{moved}, a); err != nil || got.Pin.HubDialAddress != moved.Pin.HubDialAddress {
		t.Fatal("verified same-authority reachability could not resume original route", err)
	}
}
