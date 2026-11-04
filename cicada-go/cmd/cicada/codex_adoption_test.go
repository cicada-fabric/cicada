package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/harness"
)

func syntheticManagedAdoption(original LocalNodeConnection) LocalNodeConnection {
	current := original
	current.Pin.ConnectionID, current.Pin.ConnectionEpoch = strings.Repeat("d", 32), 1 // synthetic
	current.InstanceID, current.LocatorDigest = strings.Repeat("a", 32), strings.Repeat("b", 64)
	return current
}

func TestCodexAdoptionRequiresExactVerifiedEpochOneRelationship(t *testing.T) {
	root := privateLocalNodeRoot(t)
	original := LocalNodeConnection{Pin: syntheticLocalNodePin(t, root, "synthetic-node")}
	current := syntheticManagedAdoption(original)
	var resolved int
	resolver := func(_ context.Context, pin LocalNodeConnectionPin) (LocalNodeConnection, error) {
		resolved++
		if pin != original.Pin {
			t.Fatal("proof asked about another original")
		}
		return current, nil
	}
	if validateCodexAdoption(context.Background(), original.Pin, current.Pin, nil) == nil {
		t.Fatal("missing adoption proof accepted")
	}
	if err := validateCodexAdoption(context.Background(), original.Pin, current.Pin, resolver); err != nil || resolved != 1 {
		t.Fatal("exact proof rejected", err)
	}
	if sameLocalNodeAuthority(original.Pin, current.Pin) {
		t.Fatal("private adapter widened shared authority equality")
	}
	for _, mutate := range []func(*LocalNodeConnectionPin){
		func(p *LocalNodeConnectionPin) { p.ConnectionEpoch = 2 },
		func(p *LocalNodeConnectionPin) { p.ConnectionID = strings.Repeat("e", 32) },
		func(p *LocalNodeConnectionPin) { p.Binding.HubFingerprint = strings.Repeat("c", 64) },
		func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyEpoch++ },
		func(p *LocalNodeConnectionPin) {
			p.MCPSessionStateFile = filepath.Join(root, "SYNTHETIC-replacement", "sessions.json")
		},
	} {
		changed := current.Pin
		mutate(&changed)
		if validateCodexAdoption(context.Background(), original.Pin, changed, resolver) == nil {
			t.Fatal("changed/re-added authority borrowed adoption")
		}
	}
	removed := func(context.Context, LocalNodeConnectionPin) (LocalNodeConnection, error) {
		return LocalNodeConnection{}, ErrLocalNodeNotRunning
	}
	if validateCodexAdoption(context.Background(), original.Pin, current.Pin, removed) == nil {
		t.Fatal("removed connection borrowed an old proof")
	}
}

func TestCodexAdoptionRetainsOriginalSessionPinAndOutboxBytes(t *testing.T) {
	root := privateLocalNodeRoot(t)
	original, native, store, scope, op, verified := syntheticFacadeOperation(t, root, "synthetic-node", "")
	current := syntheticManagedAdoption(original)
	proofs := 0
	resolver := func(_ context.Context, pin LocalNodeConnectionPin) (LocalNodeConnection, error) {
		proofs++
		if pin != original.Pin {
			t.Fatal("substituted original")
		}
		return current, nil
	}
	m, err := newLocalNodeChildMCPServer(current)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCodexMCPChild(m)
	m.adoptConnection = resolver
	entry := mcpCachedSession{ConnectionPin: &original.Pin, Scope: scope.Scope, APIOrigin: scope.APIOrigin, Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.NodeID, Workspace: native.Workspace,
		GroupID: scope.GroupID, EndpointID: scope.EndpointID, OwnerID: scope.EndpointGroupAuthority.Relation.OwnerID, BindingID: verified.BindingID, BindingEpoch: verified.BindingEpoch, SessionToken: "SYNTHETIC_ORIGINAL_LOCAL_TOKEN",
		codexDomainBinding: scope.codexDomainBinding, EndpointGroupAuthority: scope.EndpointGroupAuthority, EndpointGroupsLocalAccessRevision: 1}
	state := newMCPSessionStateStore(original.Pin.MCPSessionStateFile)
	if err := state.saveEndpointGroupsAuthenticated(entry); err != nil {
		t.Fatal(err)
	}
	if err := m.validateCachedConnection(&entry); err != nil {
		t.Fatal("original credential cache refused verified adoption", err)
	}
	m.setSession(entry.SessionToken, entry.EndpointID, entry.GroupID, native, entry.Scope, mcpPublicJoinResult{BindingID: entry.BindingID, BindingEpoch: entry.BindingEpoch})
	m.sessionMu.Lock()
	m.sessionDomain = entry.codexDomainBinding
	m.sessionPublic.Endpoint.Owner = entry.OwnerID
	m.sessionEndpointGroupAuthority = entry.EndpointGroupAuthority
	m.sessionEndpointGroupsLocalAccessRevision = 1
	m.sessionMu.Unlock()
	if err := m.persistEndpointGroupsSession(); err != nil {
		t.Fatal(err)
	}
	cached, err := state.load(scope.APIOrigin, harness.SessionContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, MachineID: native.NodeID, Workspace: native.Workspace})
	if err != nil || cached.ConnectionPin == nil || *cached.ConnectionPin != original.Pin || cached.NativeSessionID != native.NativeSessionID || cached.EndpointID != entry.EndpointID || cached.SessionToken != entry.SessionToken || cached.OwnerID != entry.OwnerID {
		t.Fatal("adoption replaced original sender or credential pin", err)
	}
	before, err := os.ReadFile(original.Pin.MCPOutboxStateFile)
	if err != nil {
		t.Fatal(err)
	}
	walBefore, _ := os.ReadFile(original.Pin.MCPOutboxStateFile + "-wal")
	if _, err := m.ensureMCPOutbox(); err != nil {
		t.Fatal("original outbox refused verified adoption", err)
	}
	if m.outbox.connectionPin == nil || *m.outbox.connectionPin != original.Pin || m.localNode.Pin != current.Pin {
		t.Fatal("storage bridge replaced original fence or actual managed child")
	}
	after, _ := os.ReadFile(original.Pin.MCPOutboxStateFile)
	walAfter, _ := os.ReadFile(original.Pin.MCPOutboxStateFile + "-wal")
	if !bytes.Equal(before, after) || !bytes.Equal(walBefore, walAfter) {
		t.Fatal("adoption rewrote old database or original WAL bytes")
	}
	retained, err := store.load(scope, op.OperationID)
	if err != nil || retained != op {
		t.Fatal("adoption changed original operation", err)
	}
	if proofs < 2 {
		t.Fatal("cache and outbox did not each verify common adoption")
	}
	m.localNode.Pin.ConnectionEpoch = 2
	if m.validateCachedConnection(&entry) == nil {
		t.Fatal("later epoch borrowed old session")
	}
	if _, err := m.ensureMCPOutbox(); err == nil {
		t.Fatal("later epoch borrowed old outbox")
	}
}

func TestCodexAdoptionUncertainIntentKeepsExactOriginalAndRejectsReadd(t *testing.T) {
	root := privateLocalNodeRoot(t)
	original := LocalNodeConnection{Pin: syntheticLocalNodePin(t, root, "synthetic-node"), InstanceID: strings.Repeat("a", 32), LocatorDigest: strings.Repeat("b", 64)}
	current := syntheticManagedAdoption(original)
	q := syntheticCodexOperatorTemplate()
	q.APIOrigin = original.Pin.APIOrigin
	path := filepath.Join(filepath.Dir(original.Pin.MCPSessionStateFile), "scopes", strings.Repeat("c", 64), "operator-intent.json")
	c, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	request, err := c.prepareForConnection(q, original)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	c.adoptConnection = func(_ context.Context, pin LocalNodeConnectionPin) (LocalNodeConnection, error) {
		if pin != original.Pin {
			t.Fatal("intent proof changed original pin")
		}
		return current, nil
	}
	var received localEndpointRequest
	c.exchange = func(_ string, req localEndpointRequest) (*localEndpointResult, error) {
		received = req
		return nil, errors.New("SYNTHETIC lost response")
	}
	_, err = c.callForConnection(request, current)
	if err == nil || received != request {
		t.Fatal("uncertain intent sent a replacement request", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("lost response rewrote original intent bytes")
	}
	readded := current
	readded.Pin.ConnectionEpoch = 2
	if _, err := c.prepareForConnection(q, readded); err == nil {
		t.Fatal("re-added connection borrowed uncertain intent")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refused later epoch changed uncertain original")
	}
}
