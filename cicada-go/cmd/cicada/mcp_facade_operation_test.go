package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
)

// Public synthetic local records test routing and storage guards only. They do
// not initialize a deployment or claim actual Hub/Node/Runtime acceptance.
func syntheticFacadeOperation(t *testing.T, root, node, reserved string) (LocalNodeConnection, mcpTrustedContext, *mcpOutboxStore, mcpOutboxScope, mcpOutboxOperation, localCodexContext) {
	t.Helper()
	pin := syntheticLocalNodePin(t, root, node)
	pin.WriterRoot = filepath.Join(root, "original-shared-writer")
	pin.MCPSessionStateFile = filepath.Join(pin.StateDir, "mcp", "sessions.json")
	pin.MCPOutboxStateFile = filepath.Join(pin.StateDir, "mcp", "outbox.sqlite3")
	native := mcpTrustedContext{Harness: "codex", NativeSessionID: "synthetic-original-thread", NodeID: node, Workspace: root}
	registration := e2ee.EndpointGroupRegistration{HubID: pin.HubID, OwnerID: "synthetic-owner", NodeID: node, Harness: native.Harness, NativeSessionID: native.NativeSessionID, Workspace: native.Workspace, EndpointID: "synthetic-" + node + "-endpoint", PrincipalID: "synthetic-" + node + "-principal"}
	digest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	if err != nil {
		t.Fatal(err)
	}
	verified := syntheticEndpointGroupsContext()
	verified.RegistrationDigest = digest
	verified.Harness, verified.NativeSessionID, verified.Workspace = native.Harness, native.NativeSessionID, native.Workspace
	binding, err := codexContextBinding(verified)
	if err != nil {
		t.Fatal(err)
	}
	authority := syntheticEndpointGroupsAuthority(binding)
	authority.Relation.HubID, authority.Relation.OwnerID, authority.Relation.NodeID = pin.HubID, registration.OwnerID, node
	authority.Relation.EndpointID, authority.Relation.PrincipalID, authority.Relation.NetworkID = registration.EndpointID, registration.PrincipalID, "synthetic-"+node+"-network"
	scopeID, _, err := mcpSessionScope(pin.APIOrigin, harness.SessionContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, MachineID: node, Workspace: root})
	if err != nil {
		t.Fatal(err)
	}
	scope := mcpOutboxScope{APIOrigin: pin.APIOrigin, Scope: scopeID, Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: node, Workspace: root, EndpointID: registration.EndpointID, GroupID: authority.Relation.GroupID,
		codexOutboxBinding: codexOutboxBinding{codexDomainBinding: binding, NativeBindingID: verified.BindingID, NativeBindingEpoch: verified.BindingEpoch, EndpointGroupAuthority: authority}}
	store := newMCPOutbox(pin.MCPOutboxStateFile)
	store.connectionPin = &pin
	t.Cleanup(func() { _ = store.close() })
	op, _, err := store.prepareOperation(scope, "send", "SYNTHETIC-original-key", mcpOutboxInput{Target: "SYNTHETIC-target", Body: "SYNTHETIC-original-bytes"}, reserved)
	if err != nil {
		t.Fatal(err)
	}
	return LocalNodeConnection{Pin: pin}, native, store, scope, op, verified
}

func TestMCPFacadeReadOnlyOperationSeesLiveWALAndRetainsOriginalScope(t *testing.T) {
	root := privateLocalNodeRoot(t)
	connection, native, store, scope, original, verified := syntheticFacadeOperation(t, root, "synthetic-node-a", "")
	unknown, err := store.markError(scope, original.OperationID, mcpOutboxStatusUnknown, errors.New("SYNTHETIC-lost-response"))
	if err != nil {
		t.Fatal(err)
	}
	current := connection.Pin
	current.ConnectionID, current.ConnectionEpoch = strings.Repeat("d", 32), 7 // synthetic managed ID
	current.Binding.BindingVersion++
	op, pin, err := readMCPFacadeOperation(current, native, original.OperationID)
	if err != nil || op != unknown || pin != connection.Pin {
		t.Fatal("fresh local metadata could not read original WAL operation", err)
	}
	m := newMCPServerWithPaths(current.APIOrigin, "", current.MCPSessionStateFile, current.MCPOutboxStateFile)
	m.localNode = &LocalNodeConnection{Pin: current}
	verified.RegistrationRevision++ // Read-only history does not borrow a grant.
	value, err := m.facadeOperationStatus(harness.SessionContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, MachineID: native.NodeID, Workspace: native.Workspace}, verified, map[string]any{"operation_id": original.OperationID})
	if err != nil || value.(map[string]any)["status"] != mcpOutboxStatusUnknown {
		t.Fatal("fresh authenticated sender could not read original status", err)
	}
	after, err := store.load(scope, original.OperationID)
	if err != nil || after != unknown {
		t.Fatal("read-only lookup modified original packet or attempt", err)
	}
	clone := current
	clone.Binding.HubFingerprint = strings.Repeat("c", 64)
	if _, _, err := readMCPFacadeOperation(clone, native, original.OperationID); err == nil {
		t.Fatal("same-ID Hub with another key borrowed old result")
	}
}

func TestMCPFacadeOperationIDCollisionAcrossHubsRefusesAndNeverUsesSelection(t *testing.T) {
	root := privateLocalNodeRoot(t)
	a, native, _, _, op, _ := syntheticFacadeOperation(t, root, "synthetic-node-a", "")
	b, _, _, _, _, _ := syntheticFacadeOperation(t, root, "synthetic-node-b", op.OperationID)
	if _, err := locateMCPFacadeOperation([]LocalNodeConnection{a, b}, native, op.OperationID); !errors.Is(err, errMCPGroupRouteAmbiguous) {
		t.Fatal("cross-Hub ID collision guessed a Hub", err)
	}
	chosen, err := locateMCPFacadeOperation([]LocalNodeConnection{a}, native, op.OperationID)
	if err != nil || len(chosen) != 1 || chosen[0].Pin != a.Pin {
		t.Fatal("unique operation left original Hub", err)
	}
	native.NativeSessionID = "SYNTHETIC-other-thread"
	if _, err := locateMCPFacadeOperation([]LocalNodeConnection{a, b}, native, op.OperationID); !errors.Is(err, errMCPOutboxNotFound) {
		t.Fatal("another Thread borrowed operation ID", err)
	}
}

func TestCodexMCPFacadeKeepsChildPinsSessionsOutboxesAndNoncesIndependent(t *testing.T) {
	root := privateLocalNodeRoot(t)
	a, _, _, _, _, _ := syntheticFacadeOperation(t, root, "synthetic-node-a", "")
	b, _, _, _, _, _ := syntheticFacadeOperation(t, root, "synthetic-node-b", "")
	connections := []LocalNodeConnection{a, b}
	var listed int
	f, err := newCodexMCPFacade(root, func(_ context.Context, selected string) ([]LocalNodeConnection, error) {
		listed++
		if selected != root {
			t.Fatal("enumerated another installation")
		}
		return connections, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if err := f.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.children) != 2 || listed != 1 {
		t.Fatal("facade failed verified enumeration")
	}
	aID, _ := codexChildRouteID(a.Pin)
	bID, _ := codexChildRouteID(b.Pin)
	aChild, bChild := f.children[aID], f.children[bID]
	if aChild.localNode.Pin != a.Pin || bChild.localNode.Pin != b.Pin || aChild.sessionStatePath == bChild.sessionStatePath || aChild.outbox.path == bChild.outbox.path || aChild.codexContext.nonce == bChild.codexContext.nonce || aChild.selectedNodeHTTPPool() == bChild.selectedNodeHTTPPool() {
		t.Fatal("children shared mutable authority or transport")
	}
	connections = []LocalNodeConnection{b}
	if err := f.refresh(context.Background()); err != nil || f.children[aID] != nil || f.children[bID] != bChild || listed != 2 {
		t.Fatal("removing A restarted B or retained A", err)
	}
	connections = []LocalNodeConnection{a, b}
	a.Pin.MCPOutboxStateFile = b.Pin.MCPOutboxStateFile
	connections[0] = a
	if err := f.refresh(context.Background()); err == nil {
		t.Fatal("different Hubs shared outbox path")
	}
}
