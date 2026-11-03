//go:build cicada_scoped_app_integration

package appcore

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Reuse the producer's real TLS Hub, SDK request/receipt verification and
// persistent App vault. Only this signed Node's requested lifetime is shorter;
// neither a stored state nor either side's clock is changed to expire pairing.
func v01ShortScopedNode(t *testing.T, f *scopedAppHTTPFixture, id string) *scopedAppNodeActor {
	t.Helper()
	n := new(scopedAppNodeActor)
	var err error
	n.key, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	n.token, digest, err = fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	n.attempt, err = wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := wire.NodePairTrustScopedStart{
		ScopeVersion: 2, Format: wire.NodePairTrustScopedFormat, Hub: f.hub,
		Origin: f.origin, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(f.descriptorText),
		NodeID: id, NodeName: "SYNTHETIC QA finite pairing", CredentialDigest: digest,
		RequestNonce: nonce, HubNodeControlPublic: f.descriptor.Claims.NodeControl,
		HubNodeControlKeyVersion: 1, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(75 * time.Second).Format(time.RFC3339Nano),
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{
		HubID: f.hub.HubID, NodeID: id, RequestNonce: nonce, CredentialDigest: digest,
		NodePublicIdentity: n.key.Public(), HubPublicIdentity: start.HubNodeControlPublic, HubKeyVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	start.PairingProof, err = e2ee.Seal(n.key, start.HubNodeControlPublic, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	started, _, _ := f.nodeRequest(n, wire.OperationNodePairTrustScopedStart, start)
	if started.Context == nil || started.Context.AuthorityNodeID != id {
		t.Fatal("QA signed finite Node start lacked its authenticated original context")
	}
	n.context = *started.Context
	n.secret, err = wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(n.secret) })
	n.code, err = wire.EncodeNodePairTrustScopedCode(n.context, started.Selector, n.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, err := wire.DecodeNodePairTrustScopedCode(n.code, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(code.OOBSecret)
	n.oob, err = wire.MatchNodePairTrustScopedCode(code, n.context, f.hub, start.HubNodeControlPublic, f.origin, start.DescriptorDigest, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.nodeRequest(n, wire.OperationNodePairTrustScopedCommit, wire.NodePairTrustScopedCommit{
		Format: wire.NodePairTrustScopedFormat, Context: n.context, OOBCommitment: n.oob,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return n
}

func v01OriginalCleanupReceipt(t *testing.T, f *scopedAppHTTPFixture, original *scopedOriginal) []byte {
	t.Helper()
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(f.root, "SYNTHETIC-hub.sqlite3"), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := f.c.Snapshot()
	var count int
	var operation, digest, state string
	var receipt []byte
	err = db.QueryRow(`SELECT count(*),operation,request_digest,state,response_packet FROM hub_app_node_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`,
		s.Account.OwnerID, s.Account.DeviceID, original.RequestID).Scan(&count, &operation, &digest, &state, &receipt)
	if err != nil || count != 1 || operation != original.Operation || digest != wire.AppNodeScopedPacketDigest(original.Packet) || state != wire.AppNodeScopedCompleted || len(receipt) == 0 {
		t.Fatal("owned persistent Hub lacks one exact completed cleanup receipt")
	}
	device, err := f.c.device.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wire.OpenAppNodeScopedResponse(device, f.hub, original.Packet, receipt); err != nil {
		t.Fatal("original device could not authenticate its exact durable cleanup receipt")
	}
	var grantState, nodeID string
	err = db.QueryRow(`SELECT state,authority_node_id FROM hub_app_node_grants_v1 WHERE grant_id=? AND owner_id=? AND device_id=?`,
		original.GrantID, s.Account.OwnerID, s.Account.DeviceID).Scan(&grantState, &nodeID)
	if err != nil || grantState != "CANCELLED" || nodeID != original.NodeID {
		t.Fatal("durable cleanup affected a different grant or Node")
	}
	return receipt
}

func TestV01ScopedNaturalExpiryReloginRetainsSelectedNodeAndNewCode(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	a := f.startNode("SYNTHETIC-QA-retained-A")
	f.approveNode(a)
	f.ackNode(a)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if !reflect.DeepEqual(f.c.selectedNodeBinding(), a.binding) {
		t.Fatal("QA lacks the independently ACKed original selected A")
	}
	owner, device := f.c.owner.Public().ID, f.c.device.Public().ID
	counters := f.c.node.Client
	f.dispatch(Action{Kind: ActionBeginAddNode})
	b := v01ShortScopedNode(t, f, "SYNTHETIC-QA-expiring-B")
	f.approveNode(b) // Deliberately do not ACK B.
	deadline := parseExpiry(f.c.scoped.flow.Approval.AcceptBefore)
	if deadline.IsZero() || !deadline.After(time.Now()) || deadline.After(time.Now().Add(2*time.Minute)) {
		t.Fatal("QA finite approval did not retain a bounded authenticated deadline")
	}
	waitStarted := time.Now()
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	s := f.c.Snapshot()
	if s.Node.Pairing == nil || s.Node.Pairing.State != wire.NodePairTrustScopedExpired ||
		!s.Targets.Locked || !containsAction(s.AvailableActions, ActionCancelNodePairing) ||
		containsAction(s.AvailableActions, ActionReviewNodePairing) || s.Targets.SelectedNodeID != a.binding.NodeID {
		t.Fatal("actual Hub expiry did not expose original cleanup while retaining selected A")
	}
	t.Logf("V01_PAIRING_QA natural_pair_deadline_elapsed_ms=%d authenticated_state=EXPIRED", time.Since(waitStarted).Milliseconds())

	// Model account display expiry only; never send a future-dated packet or
	// claim the real fifteen-minute account deadline elapsed in this fixture.
	now := f.c.cfg.Now
	accountEnd := parseExpiry(s.Account.SessionExpiresAt)
	if accountEnd.IsZero() {
		t.Fatal("current account has no explicit finite deadline")
	}
	f.c.cfg.Now = func() time.Time { return accountEnd.Add(time.Nanosecond) }
	expired := f.c.Snapshot()
	f.c.cfg.Now = now
	if expired.Account.State != AccountStateLoginRequired ||
		containsAction(expired.AvailableActions, ActionApproveNodePairing) ||
		containsAction(expired.AvailableActions, ActionReviewNodePairing) {
		t.Fatal("local account expiry retained approval or new-code authority")
	}

	f.dropOperation = wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedCancel)
	f.dropHTTPStatus = http.StatusForbidden
	if f.c.Dispatch(context.Background(), Action{Kind: ActionCancelNodePairing, NodePairingReviewID: s.Node.Pairing.ReviewID}) == nil || !f.c.scopedPending() {
		t.Fatal("lost cleanup response did not retain the original uncertain packet")
	}
	original := cloneScopedOriginal(f.c.scoped.original)
	defer func() { clear(original.Packet); clear(original.Body); clear(original.Response) }()
	grantID := f.c.scoped.flow.Approval.GrantID
	if grantID == "" || original.GrantID != grantID || !bytes.Equal(original.Packet, f.droppedPacket) || !f.c.Snapshot().Targets.Locked ||
		!containsAction(f.c.Snapshot().AvailableActions, ActionRecoverNodePairing) {
		t.Fatal("original cleanup packet or reachable recovery was lost")
	}
	receipt := v01OriginalCleanupReceipt(t, f, original)
	defer clear(receipt)
	oldSession := bytes.Clone(f.c.session.SessionToken)
	defer clear(oldSession)
	f.dispatch(Action{Kind: ActionLogout})
	f.dispatch(Action{Kind: ActionLogin, Username: "synthetic-scoped-app", Password: n2SyntheticPassword})
	f.restart()
	pending := f.c.scoped.original
	if !f.c.scopedPending() || pending == nil ||
		!bytes.Equal(original.Packet, pending.Packet) || !bytes.Equal(original.Body, pending.Body) ||
		original.RequestID != pending.RequestID || original.Operation != pending.Operation ||
		original.AttemptID != pending.AttemptID || original.GrantID != pending.GrantID ||
		original.NodeID != pending.NodeID || len(pending.Response) != 0 || pending.Applied ||
		f.c.scoped.flow == nil || f.c.scoped.flow.Approval.GrantID != grantID {
		t.Fatal("relogin or vault reopen replaced the original cleanup")
	}
	f.dispatch(Action{Kind: ActionRecoverNodePairing})
	if f.c.scopedPending() || f.c.scoped.flow != nil && !f.c.scoped.flow.CleanupComplete ||
		f.posts[wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedCancel)] != 1 ||
		f.c.owner.Public().ID != owner || f.c.device.Public().ID != device || f.c.node.Client != counters ||
		!reflect.DeepEqual(f.c.selectedNodeBinding(), a.binding) {
		t.Fatal("original cleanup did not settle once while preserving identity, counters and selected A")
	}
	afterReceipt := v01OriginalCleanupReceipt(t, f, original)
	defer clear(afterReceipt)
	if !bytes.Equal(receipt, afterReceipt) {
		t.Fatal("recovery replaced the original persisted cleanup ciphertext")
	}
	s = f.c.Snapshot()
	if s.Targets.Locked || s.Targets.SelectedNodeID != a.binding.NodeID || !s.Targets.CanAdd ||
		s.Node.Pairing == nil || s.Node.Pairing.NodeID != a.binding.NodeID ||
		s.Node.Pairing.State != wire.NodePairTrustScopedACKed || s.Node.Pairing.ErrorCode == "APP_NODE_PAIRING_UNKNOWN" ||
		s.ErrorCode == "APP_NODE_PAIRING_UNKNOWN" || bytes.Equal(f.c.session.SessionToken, oldSession) {
		t.Fatal("expired B or stale uncertainty hid A after fresh-session cleanup")
	}
	f.dispatch(Action{Kind: ActionBeginAddNode})
	c := f.startNode("SYNTHETIC-QA-explicit-new-code")
	f.dispatch(Action{Kind: ActionReviewNodePairing, DevicePairingCode: c.code})
	if f.c.scoped.flow == nil || f.c.scoped.flow.NodeID != c.context.AuthorityNodeID ||
		f.c.scopedNode(c.context.AuthorityNodeID) != nil && f.c.scopedNode(c.context.AuthorityNodeID).Binding != nil ||
		!reflect.DeepEqual(f.c.selectedNodeBinding(), a.binding) || f.c.Snapshot().Management != ManagementUnavailable {
		t.Fatal("explicit new-code review granted admission/business authority or replaced A")
	}
}
