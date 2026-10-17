package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type nodeAutoHTTPFunc func(*http.Request) (*http.Response, error)

func (f nodeAutoHTTPFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func readyNodeAutoFixture(t *testing.T) (*nodeActorFixture, NodeStatusTarget) {
	t.Helper()
	f := newNodeActorFixture(t)
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	target, ok := AutomaticNodeStatusTarget(f.c.Snapshot(), f.n2.now)
	if !ok {
		t.Fatal("confirmed Node without an initial heartbeat was not eligible")
	}
	return f, target
}

func nodeVaultDigest(t *testing.T, f *nodeActorFixture) [32]byte {
	t.Helper()
	path, err := scopeVaultPath(f.root, cardScope(f.c.connection))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	return sha256.Sum256(raw)
}

func nodeAutoPacketCount(f *nodeActorFixture) int {
	count := 0
	for _, packets := range f.posts {
		count += len(packets)
	}
	return count
}

func TestAutomaticNodeStatusReadsKeepGrantBindingCountersAndKeys(t *testing.T) {
	f, target := readyNodeAutoFixture(t)
	before, _ := json.Marshal(f.c.node.Grant)
	confirmation, _ := json.Marshal(f.c.nodeConfirmation)
	n2, _ := json.Marshal(f.c.state.Enrollment)
	counters := f.c.node.Client
	owner, device := f.c.owner.Public(), f.c.device.Public()
	statusBefore := len(f.posts[wire.OperationAppNodeStatus])
	for i := range 3 {
		f.n2.now = f.n2.now.Add(30 * time.Second)
		if i == 1 {
			f.heartbeat = f.stamp(f.n2.now)
		}
		if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); err != nil {
			t.Fatal(err)
		}
		if _, ok := AutomaticNodeStatusTarget(f.c.Snapshot(), f.n2.now); !ok {
			t.Fatal("status read consumed the existing finite authority")
		}
	}
	after, _ := json.Marshal(f.c.node.Grant)
	confirmationAfter, _ := json.Marshal(f.c.nodeConfirmation)
	n2After, _ := json.Marshal(f.c.state.Enrollment)
	if len(f.posts[wire.OperationAppNodeStatus]) != statusBefore+3 || len(f.posts["nodes.confirm"]) != 1 ||
		!bytes.Equal(before, after) || !bytes.Equal(confirmation, confirmationAfter) || !bytes.Equal(n2, n2After) || f.c.node.Client != counters ||
		owner.ID != f.c.owner.Public().ID || device.ID != f.c.device.Public().ID || f.c.Snapshot().Node.ConnectionState() != NodeOnline {
		t.Fatal("automatic status altered binding, grant, keys, confirmation budget or Client counters")
	}
}

func TestAutomaticNodeStatusGuardsSkipWithoutPacketOrVaultCAS(t *testing.T) {
	f, target := readyNodeAutoFixture(t)
	for _, tt := range []struct {
		name string
		edit func(*NodeStatusTarget) func()
	}{
		{"origin", func(v *NodeStatusTarget) func() { v.Origin += "/foreign"; return func() {} }},
		{"hub", func(v *NodeStatusTarget) func() { v.HubID += "foreign"; return func() {} }},
		{"account", func(v *NodeStatusTarget) func() { v.AccountID += "foreign"; return func() {} }},
		{"owner", func(v *NodeStatusTarget) func() { v.OwnerID += "foreign"; return func() {} }},
		{"device", func(v *NodeStatusTarget) func() { v.DeviceID += "foreign"; return func() {} }},
		{"binding", func(v *NodeStatusTarget) func() { v.BindingID += "foreign"; return func() {} }},
		{"node", func(v *NodeStatusTarget) func() { v.NodeID += "foreign"; return func() {} }},
		{"version", func(v *NodeStatusTarget) func() { v.BindingVersion++; return func() {} }},
		{"review", func(v *NodeStatusTarget) func() { v.ReviewID += "foreign"; return func() {} }},
		{"expired-before-dispatch", func(*NodeStatusTarget) func() {
			old := f.n2.now
			f.n2.now = parseExpiry(f.c.session.ExpiresAt)
			return func() { f.n2.now = old }
		}},
		{"proposal-before-challenge", func(*NodeStatusTarget) func() {
			f.c.node.Proposal = &nodeProposal{}
			return func() { f.c.node.Proposal = nil }
		}},
		{"context-not-current", func(*NodeStatusTarget) func() {
			f.c.nodeContextChecked = false
			return func() { f.c.nodeContextChecked = true }
		}},
		{"missing-current-node", func(*NodeStatusTarget) func() {
			old := f.c.node.Current.Node
			f.c.node.Current.Node = nil
			return func() { f.c.node.Current.Node = old }
		}},
		{"storage-fault", func(*NodeStatusTarget) func() {
			f.c.storageFault = true
			return func() { f.c.storageFault = false }
		}},
		{"unknown-node-request", func(*NodeStatusTarget) func() {
			old := f.c.node.Pending
			f.c.node.Pending = &nodeOperation{}
			return func() { f.c.node.Pending = old }
		}},
		{"node-recovery", func(*NodeStatusTarget) func() {
			f.c.nodeRecovery = &nodeOperation{}
			return func() { f.c.nodeRecovery = nil }
		}},
		{"unknown-account-request", func(*NodeStatusTarget) func() {
			old := f.c.state.Pending
			f.c.state.Pending = &pendingOperation{}
			return func() { f.c.state.Pending = old }
		}},
		{"client-not-initialized", func(*NodeStatusTarget) func() {
			f.c.node.Client.Initialized = false
			return func() { f.c.node.Client.Initialized = true }
		}},
		{"account-recovery", func(*NodeStatusTarget) func() {
			f.c.state.Recovery = &pendingOperation{}
			return func() { f.c.state.Recovery = nil }
		}},
		{"global-error", func(*NodeStatusTarget) func() {
			f.c.snapshotMu.Lock()
			old := f.c.snapshot.ErrorCode
			f.c.snapshot.ErrorCode = "SYNTHETIC_FOREGROUND_ERROR"
			f.c.snapshotMu.Unlock()
			return func() {
				f.c.snapshotMu.Lock()
				f.c.snapshot.ErrorCode = old
				f.c.snapshotMu.Unlock()
			}
		}},
		{"provenance", func(*NodeStatusTarget) func() {
			old := f.c.node.Current.Authority.ConfirmationProvenanceID
			f.c.node.Current.Authority.ConfirmationProvenanceID = "synthetic-foreign"
			return func() { f.c.node.Current.Authority.ConfirmationProvenanceID = old }
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			candidate := target
			restore := tt.edit(&candidate)
			defer restore()
			digest, packets := nodeVaultDigest(t, f), nodeAutoPacketCount(f)
			pending, recovery := f.c.node.Pending, f.c.nodeRecovery
			if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &candidate}); !errors.Is(err, ErrInvalidAction) {
				t.Fatalf("stale automatic target returned %v", err)
			}
			if nodeVaultDigest(t, f) != digest || nodeAutoPacketCount(f) != packets || f.c.node.Pending != pending || f.c.nodeRecovery != recovery {
				t.Fatal("skipped automatic target changed encrypted state or sent a packet")
			}
		})
	}
	for _, edit := range []func(*wire.AppNodeObservation){
		func(n *wire.AppNodeObservation) { n.Authorized = false },
		func(n *wire.AppNodeObservation) { n.BindingState = "REVOKED" },
		func(n *wire.AppNodeObservation) { n.BindingID += "foreign" },
		func(n *wire.AppNodeObservation) { n.BindingVersion++ },
		func(n *wire.AppNodeObservation) { n.CredentialVersion++ },
		func(n *wire.AppNodeObservation) { n.NodeKeyID += "foreign" },
		func(n *wire.AppNodeObservation) { n.NodeKeyFingerprint = "foreign" },
		func(n *wire.AppNodeObservation) { n.NodeKeyEpoch++ },
	} {
		old := *f.c.node.Current.Node
		edit(f.c.node.Current.Node)
		digest, packets := nodeVaultDigest(t, f), nodeAutoPacketCount(f)
		if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); !errors.Is(err, ErrInvalidAction) || nodeVaultDigest(t, f) != digest || nodeAutoPacketCount(f) != packets {
			t.Fatal("changed authenticated binding tuple bypassed core automatic guard")
		}
		*f.c.node.Current.Node = old
	}
}

func TestAutomaticNodeStatusTagCannotRunOtherActionsOrCancelledContext(t *testing.T) {
	f, target := readyNodeAutoFixture(t)
	digest, packets := nodeVaultDigest(t, f), nodeAutoPacketCount(f)
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionLogout, AutoNodeStatus: &target}); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("automatic status tag admitted another operation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("cancelled automatic context was admitted")
	}
	if nodeVaultDigest(t, f) != digest || nodeAutoPacketCount(f) != packets || f.c.hasNodePending() {
		t.Fatal("rejected automatic intent changed durable state or sent a packet")
	}
}

func TestAutomaticNodeStatusUnsignedOrCorruptResponseFreezesOriginal(t *testing.T) {
	for _, fault := range []string{"unsigned-403", "corrupt-packet"} {
		t.Run(fault, func(t *testing.T) {
			f, target := readyNodeAutoFixture(t)
			if fault == "unsigned-403" {
				f.deny = wire.OperationAppNodeStatus
			} else {
				f.c.cfg.HTTP = nodeAutoHTTPFunc(func(r *http.Request) (*http.Response, error) {
					response, err := f.Do(r)
					if response != nil {
						response.Body.Close()
						response.Body = io.NopCloser(bytes.NewBufferString("synthetic corrupt response"))
					}
					return response, err
				})
			}
			if f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}) == nil || !f.c.hasNodePending() {
				t.Fatal("unauthenticated automatic error settled the request")
			}
			original := bytes.Clone(f.c.node.Pending.Request)
			digest, packets := nodeVaultDigest(t, f), nodeAutoPacketCount(f)
			for range 3 {
				if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); !errors.Is(err, ErrInvalidAction) {
					t.Fatal(err)
				}
			}
			if nodeVaultDigest(t, f) != digest || nodeAutoPacketCount(f) != packets || !bytes.Equal(original, f.c.node.Pending.Request) {
				t.Fatal("automatic ticks replaced the exact unconfirmed request")
			}
		})
	}
}

func TestAutomaticNodeStatusLossFreezesExactReadUntilManualRecovery(t *testing.T) {
	f, target := readyNodeAutoFixture(t)
	f.drop = wire.OperationAppNodeStatus
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}) == nil || !f.c.hasNodePending() {
		t.Fatal("lost automatic response did not retain its request")
	}
	original := bytes.Clone(f.c.node.Pending.Request)
	digest, packets := nodeVaultDigest(t, f), nodeAutoPacketCount(f)
	for range 3 {
		f.n2.now = f.n2.now.Add(30 * time.Second)
		if _, ok := AutomaticNodeStatusTarget(f.c.Snapshot(), f.n2.now); ok {
			t.Fatal("uncertain read remained eligible")
		}
		if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); !errors.Is(err, ErrInvalidAction) {
			t.Fatal(err)
		}
	}
	if nodeVaultDigest(t, f) != digest || nodeAutoPacketCount(f) != packets || !bytes.Equal(original, f.c.node.Pending.Request) {
		t.Fatal("later ticks replaced or modified the uncertain original")
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverNode}); err != nil {
		t.Fatal(err)
	}
	if _, ok := AutomaticNodeStatusTarget(f.c.Snapshot(), f.n2.now); !ok {
		t.Fatal("explicit exact recovery did not allow a new current observation")
	}
}

func TestAutomaticNodeStatusCancelledLateResponseCannotBecomeFresh(t *testing.T) {
	f, target := readyNodeAutoFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.c.cfg.HTTP = nodeAutoHTTPFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Fatal("automatic HTTP read has no ten-second bound")
		}
		response, err := f.Do(r)
		cancel() // A noncompliant transport returns its sealed response late.
		return response, err
	})
	if f.c.Dispatch(ctx, Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}) == nil ||
		f.c.hasNodePending() || f.c.node.Pending == nil || !f.c.node.Pending.Applied || f.c.Snapshot().Node.Access.Confirmed || f.c.nodeChecked {
		t.Fatal("cancelled authenticated response became fresh or its settlement was lost")
	}
	f.c.cfg.HTTP = f
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode}); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticNodeStatusSettlesAuthenticatedTerminalOutcomes(t *testing.T) {
	for _, state := range []string{wire.AppNodeRevoked, wire.AppNodeExpired, wire.AppNodeCancelled, wire.AppNodeSessionEnded} {
		t.Run(state, func(t *testing.T) {
			f, target := readyNodeAutoFixture(t)
			f.state = state
			if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); err != nil {
				t.Fatal(err)
			}
			if f.c.hasNodePending() || f.c.node.Pending == nil || !f.c.node.Pending.Applied || f.c.Snapshot().Node.Access.State != state {
				t.Fatal("known terminal outcome was turned into uncertain recovery")
			}
			if _, ok := AutomaticNodeStatusTarget(f.c.Snapshot(), f.n2.now); ok {
				t.Fatal("terminal read allowed more automatic packets")
			}
		})
	}
}

func TestAutomaticNodeStatusExpiryDuringReadSettlesWithoutFreshness(t *testing.T) {
	f, target := readyNodeAutoFixture(t)
	expires := parseExpiry(f.c.node.Grant.Claims.Scope.AccountSessionExpiresAt)
	f.n2.now = expires.Add(-100 * time.Millisecond)
	f.c.cfg.HTTP = nodeAutoHTTPFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 110*time.Millisecond {
			t.Fatal("automatic HTTP timeout crossed the effective authorization deadline")
		}
		f.n2.now = expires
		return f.Do(r)
	})
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired in-flight read returned %v", err)
	}
	if f.c.hasNodePending() || !f.c.node.Pending.Applied || f.c.Snapshot().Node.Access.State != wire.AppNodeSessionEnded ||
		f.c.Snapshot().Node.Access.Confirmed || f.c.nodeChecked || f.c.nodeError == "APP_NODE_REQUEST_UNKNOWN" {
		t.Fatal("authenticated expiry was made uncertain or retained fresh authority")
	}
	digest, packets := nodeVaultDigest(t, f), nodeAutoPacketCount(f)
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}); !errors.Is(err, ErrInvalidAction) ||
		nodeVaultDigest(t, f) != digest || nodeAutoPacketCount(f) != packets {
		t.Fatal("expired automatic retry wrote state or sent another packet")
	}
}
