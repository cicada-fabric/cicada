package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// A scripted crypto actor isolates App persistence/interaction from the new
// Store service. It uses real shared PQ packets, proofs and the frozen Store
// binding DTO. It is not Hub Guard, process, Windows or HTTPS acceptance.
type nodeActorFixture struct {
	candidateOverride         *e2ee.OwnerAppNodeCandidate
	t                         *testing.T
	n2                        *activationActorFixture
	c                         *nativeController
	root                      string
	scope                     e2ee.OwnerAppNodeScope
	token                     []byte
	code                      string
	nodeKey, controlKey       *e2ee.Identity
	proposal, grant           *wire.AppNodeChallenge
	state                     string
	head                      uint64
	latest, provenance        string
	binding                   *store.NodeControlKeyBinding
	heartbeat                 string
	lastRequest, nextResponse uint64
	receipts                  map[string][]byte
	requests                  map[string][]byte
	fenced                    map[string]bool
	posts                     map[string][][]byte
	drop, deny                string
	available                 bool
	readExpired               bool
}

func newNodeActorFixture(t *testing.T) *nodeActorFixture {
	return newNodeActorAvailabilityFixture(t, true)
}

func newNodeActorAvailabilityFixture(t *testing.T, available bool) *nodeActorFixture {
	t.Helper()
	f := newActivationActorFixture(t)
	root := filepath.Join(t.TempDir(), "vaults")
	c := f.controller(t, root).(*nativeController)
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	for _, action := range []Action{{Kind: ActionConnect, ActivationCode: code}, {Kind: ActionGenerateOwner},
		{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}} {
		if err := c.Dispatch(ctx, action); err != nil {
			t.Fatal(err)
		}
	}
	// The previous N2 lease expires by the actor's logical clock. This setup
	// supplies an independently authenticated synthetic account-session actor;
	// real password/device login and Store coupling belong to the process gate.
	f.now = f.now.Add(16 * time.Minute)
	c.session = &wire.SessionContext{Origin: c.connection.Origin, HubID: c.hub.HubID, AccountID: c.connection.AccountID, OwnerID: c.connection.OwnerID,
		DeviceID: c.state.DeviceID, DeviceKeyID: c.state.DeviceKeyID, SessionToken: bytes.Repeat([]byte{0x35}, 32), AccountEpoch: 1, DeviceEpoch: 1, ExpiresAt: f.now.Add(15 * time.Minute).Format(time.RFC3339Nano)}
	c.sessionInspected, c.sessionNeedsCheck = true, false
	c.state.AccountState = AccountStateSessionActive
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	controlKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := &nodeActorFixture{t: t, n2: f, c: c, root: root, token: bytes.Clone(c.session.SessionToken), code: "23456789ABCD", nodeKey: nodeKey, controlKey: controlKey,
		available: available, nextResponse: 1, receipts: map[string][]byte{}, requests: map[string][]byte{}, fenced: map[string]bool{}, posts: map[string][][]byte{}}
	n.scope = e2ee.OwnerAppNodeScope{Version: 1, Origin: c.connection.Origin, HubID: c.hub.HubID, HubFingerprint: c.connection.HubFingerprint, AccountID: c.connection.AccountID,
		AccountSessionID: "synthetic-node-session", AccountSessionExpiresAt: c.session.ExpiresAt, OwnerID: c.connection.OwnerID, OwnerPublic: c.owner.Public(), OwnerKeyVersion: 1,
		DeviceID: c.state.DeviceID, DevicePublic: c.device.Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, TransportPolicy: wire.AppNodeTransportHTTPS}
	c.cfg.HTTP, c.nodeDiscoveryTried = n, false
	c.node = c.newNodeState()
	c.initializeNode(ctx)
	if available && (!c.nodeAvailable || !c.nodeContextChecked) {
		t.Fatal("synthetic Node context did not initialize")
	}
	t.Cleanup(func() { _ = n.c.Close() })
	return n
}

func (f *nodeActorFixture) stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (f *nodeActorFixture) Do(req *http.Request) (*http.Response, error) {
	reply := func(data []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: req}, nil
	}
	if req.URL.Path == wire.AppNodeCapabilitiesPath {
		if !f.available {
			return reply(nil, 404)
		}
		cap := wire.AppNodeCapabilities{Format: wire.AppNodeCapabilitiesFormat, ContractRevision: wire.AppNodeContractRevision, ServeMode: "--hub-nodes-only", Available: true,
			HTTPOperations: []string{wire.OperationAppNodePrepare, wire.OperationAppNodeComplete, wire.OperationAppNodeStatus, wire.OperationAppNodeCancel, wire.OperationAppNodeReconcile},
			Profiles:       []string{wire.AppNodeProfileInitial, wire.AppNodeProfileStatus}, RuntimeLeaseSeconds: 900, MaxOriginalBytes: wire.MaxAppNodeOriginalBytes, TransportPolicy: wire.AppNodeTransportHTTPS}
		raw, _ := json.Marshal(cap)
		return reply(raw, 200)
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/owner/app-node/") && req.URL.Path != "/v2/client/rpc" {
		return f.n2.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	op := "nodes.confirm"
	if req.URL.Path != "/v2/client/rpc" {
		p, e := wire.DecodePacket(raw)
		if e != nil {
			f.t.Fatal(e)
		}
		op = p.Packet.Route.Operation
	}
	f.posts[op] = append(f.posts[op], bytes.Clone(raw))
	// Observe the real encrypted vault before even the actor accepts a packet.
	ns := nodeStateNamespace
	if op == wire.OperationAppNodeReconcile {
		ns = nodeRecoveryNamespace
	}
	saved, _, found, e := f.c.vault.LoadState(ns)
	if e != nil || !found {
		f.t.Fatal("Node POST preceded vault persistence")
	}
	var durable []byte
	if ns == nodeStateNamespace {
		var s nodeAuthorityState
		e = decodeStateJSON(saved, &s)
		if s.Pending != nil {
			durable = s.Pending.Request
		}
	} else {
		var p nodeOperation
		e = decodeStateJSON(saved, &p)
		durable = p.Request
	}
	clear(saved)
	if e != nil || !bytes.Equal(durable, raw) {
		f.t.Fatal("Node POST differs from durable original")
	}
	if f.deny == op {
		return reply(nil, 403)
	}
	digest := wire.AppNodePacketDigest(raw)
	if prior := f.receipts[digest]; prior != nil {
		return reply(bytes.Clone(prior), 200)
	}
	var response []byte
	if op == "nodes.confirm" {
		response = f.confirm(raw)
	} else {
		p, e := wire.DecodePacket(raw)
		if e != nil {
			f.t.Fatal(e)
		}
		b := clientwire.Binding{HubID: f.scope.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
		var body any
		switch op {
		case wire.OperationAppNodeStatus:
			var request wire.AppNodeStatusRequest
			f.open(b, p, raw, &request)
			result := f.result(op, p.Packet.Route.OperationID, digest, request.GrantID)
			if f.readExpired {
				result.State, result.ErrorCode, result.Node = wire.AppNodeReadExpired, wire.AppNodeReadExpired, nil
				result.Authority.AllowedOperations = []string{}
				result.Authority.RemainingConfirmations = 0
			}
			body = result
		case wire.OperationAppNodePrepare:
			var request wire.AppNodePrepare
			f.open(b, p, raw, &request)
			intent, e := e2ee.VerifyOwnerAppNodePreview(f.scope.OwnerPublic, request.OwnerIntent, f.n2.now)
			if e != nil {
				f.t.Fatal(e)
			}
			claims := e2ee.OwnerAppNodeGrantClaims{Purpose: e2ee.OwnerAppNodeGrantPurpose, Scope: intent.Scope, GrantID: intent.GrantID, ExpectedHeadVersion: f.head, Profile: wire.AppNodeProfileInitial,
				PrepareRequestID: intent.RequestID, PreparePacketDigest: digest, PreviewProofDigest: wire.AppNodeProofDigest(request.OwnerIntent), ServerNonce: strings.Repeat("1", 64),
				ReadNodeStatus: true, AllowedOperations: wire.AppNodeAllowedOperations(), ConfirmationLimit: 1, PreparedAt: f.stamp(f.n2.now), ProofExpiresAt: f.stamp(f.n2.now.Add(5 * time.Minute)), LeaseExpiresAt: f.stamp(f.n2.now.Add(15 * time.Minute))}
			claims.Scope.HeadVersion = f.head + 1
			if end := parseExpiry(claims.Scope.AccountSessionExpiresAt); end.Before(parseExpiry(claims.ProofExpiresAt)) {
				claims.ProofExpiresAt = f.stamp(end)
			}
			if request.Target.Kind == wire.AppNodeTargetPrevious {
				claims.Profile, claims.Purpose, claims.PreviousGrantID, claims.ConfirmationProvenanceID = wire.AppNodeProfileStatus, e2ee.OwnerAppNodeStatusGrantPurpose, request.Target.PreviousGrantID, f.provenance
				claims.AllowedOperations, claims.ConfirmationLimit = []string{}, 0
				binding := f.bindingDTO()
				claims.Binding = &binding
			} else {
				codeDigest, _ := wire.AppNodeCodeDigest(f.scope.HubID, request.Target.Code)
				claims.Candidate = &e2ee.OwnerAppNodeCandidate{RequestID: "nctrlreq_synthetic", Version: 1, Mode: "INITIAL", State: "PENDING", HubID: f.scope.HubID, NodeID: "synthetic-node", NodeName: "Synthetic Ubuntu Node",
					NodePublic: f.nodeKey.Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(f.nodeKey.Public()), NodeKeyEpoch: 1, HubNodeControlPublic: f.controlKey.Public(), HubNodeControlKeyVersion: 1,
					HubNodeControlFingerprint: nodewire.IdentityFingerprint(f.controlKey.Public()), CandidateDigest: strings.Repeat("c", 64), CodeDigest: codeDigest, ExpiresAt: f.stamp(f.n2.now.Add(10 * time.Minute))}
				if f.candidateOverride != nil {
					candidate := *f.candidateOverride
					claims.Candidate = &candidate
				}
			}
			ch := wire.AppNodeChallenge{Format: wire.AppNodeChallengeFormat, RequestID: intent.RequestID, RequestPacketDigest: digest, Claims: claims, ObservedAt: f.stamp(f.n2.now)}
			f.proposal = &ch
			body = ch
		case wire.OperationAppNodeComplete:
			var request wire.AppNodeComplete
			f.open(b, p, raw, &request)
			claims, e := e2ee.VerifyOwnerAppNodeGrant(f.scope.OwnerPublic, request.OwnerGrant, f.n2.now)
			if e != nil {
				f.t.Fatal(e)
			}
			if f.proposal == nil || !reflect.DeepEqual(claims, f.proposal.Claims) {
				f.t.Fatal("changed explicit grant")
			}
			f.grant, f.head, f.latest, f.state = f.proposal, claims.Scope.HeadVersion, claims.GrantID, wire.AppNodeActive
			body = f.result(op, p.Packet.Route.OperationID, digest, claims.GrantID)
		case wire.OperationAppNodeCancel:
			var request wire.AppNodeCancel
			f.open(b, p, raw, &request)
			if f.grant != nil && request.GrantID == f.grant.Claims.GrantID {
				f.head++
				f.state = wire.AppNodeCancelled
			}
			body = f.result(op, p.Packet.Route.OperationID, digest, request.GrantID)
			if f.grant == nil || request.GrantID != f.grant.Claims.GrantID {
				r := body.(wire.AppNodeResult)
				r.Authority.State = wire.AppNodeCancelled
				body = r
			}
		case wire.OperationAppNodeReconcile:
			var request wire.AppNodeReconcileRequest
			f.open(b, p, raw, &request)
			body = f.reconcile(request, p.Packet.Route.OperationID, digest)
		default:
			f.t.Fatal("unexpected synthetic Node operation")
		}
		response, err = wire.SealResponse(f.n2.hubKey, f.scope.DevicePublic, p.Packet.Route, body)
		if err != nil {
			f.t.Fatalf("synthetic %s response invalid: %v", op, err)
		}
	}
	f.receipts[digest], f.requests[digest] = bytes.Clone(response), bytes.Clone(raw)
	if f.drop == op {
		f.drop = ""
		return nil, errors.New("synthetic response lost after commit")
	}
	return reply(response, 200)
}

func (f *nodeActorFixture) open(b clientwire.Binding, p wire.Packet, raw []byte, out any) {
	f.t.Helper()
	pub := f.scope.DevicePublic
	if err := wire.OpenRequestAt(f.n2.hubKey, &pub, b, p.Packet.Route, raw, out, time.Time{}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *nodeActorFixture) result(op, id, digest, grantID string) wire.AppNodeResult {
	scope := f.scope
	scope.HeadVersion = f.head
	a := wire.AppNodeAuthoritySnapshot{Scope: scope, GrantID: grantID, State: wire.AppNodeAbsent, CurrentHeadVersion: f.head, LatestGrantID: f.latest, ConfirmationProvenanceID: f.provenance,
		RootState: wire.RootActiveState, AllowedOperations: []string{}, Counters: wire.AppNodeClientCounters{SessionEpoch: 1, LastRequestSequence: f.lastRequest, NextResponseSequence: f.nextResponse}}
	var g *wire.AppNodeChallenge
	if f.grant != nil && grantID == f.grant.Claims.GrantID {
		g = f.grant
		a.State = f.state
	} else if f.proposal != nil && grantID == f.proposal.Claims.GrantID {
		g = f.proposal
		a.State = wire.AppNodePrepared
	}
	if g != nil {
		a.Scope, a.Profile, a.LeaseExpiresAt = g.Claims.Scope, g.Claims.Profile, g.Claims.LeaseExpiresAt
		if a.State == wire.AppNodePrepared && !f.n2.now.Before(parseExpiry(g.Claims.ProofExpiresAt)) {
			a.State = wire.AppNodeExpired
		}
		if a.State == wire.AppNodeActive && !f.n2.now.Before(parseExpiry(g.Claims.LeaseExpiresAt)) {
			a.State = wire.AppNodeExpired
		}
		if !f.n2.now.Before(parseExpiry(g.Claims.Scope.AccountSessionExpiresAt)) || g.Claims.Scope.AccountSessionID != f.scope.AccountSessionID {
			a.State = wire.AppNodeSessionEnded
			a.LoginRequired = true
		}
		if a.State == wire.AppNodeActive && g.Claims.Profile == wire.AppNodeProfileInitial && f.binding == nil {
			a.AllowedOperations = wire.AppNodeAllowedOperations()
			a.RemainingConfirmations = 1
		}
	}
	r := wire.AppNodeResult{Format: wire.AppNodeResultFormat, Operation: op, RequestID: id, RequestPacketDigest: digest, State: wire.AppNodeCompleted, Authority: a, ObservedAt: f.stamp(f.n2.now)}
	if op == wire.OperationAppNodeStatus && a.State == wire.AppNodeActive && f.binding != nil {
		b := f.binding
		n := &wire.AppNodeObservation{NodeID: b.NodeID, NodeName: b.NodeName, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, CredentialVersion: b.NodeCredentialVersion,
			NodeKeyID: b.NodeKeyID, NodeKeyFingerprint: b.NodeKeyFingerprint, NodeKeyEpoch: b.NodeKeyEpoch, BindingState: "ACTIVE", Authorized: true, Connectivity: "UNKNOWN", Stale: true,
			Source: "store.machines.last_seen", ObservedAt: r.ObservedAt, LastHeartbeatAt: f.heartbeat}
		if h := parseExpiry(f.heartbeat); !h.IsZero() {
			n.Known = true
			n.FreshUntil = f.stamp(h.Add(wire.AppNodeObservationStaleAfter))
			n.Stale = !f.n2.now.Before(parseExpiry(n.FreshUntil))
			n.Connectivity = "CONNECTED"
			if n.Stale {
				n.Connectivity = "STALE"
			}
		}
		r.Node = n
	}
	return r
}

func (f *nodeActorFixture) confirm(raw []byte) []byte {
	var packet clientwire.Packet
	if json.Unmarshal(raw, &packet) != nil || f.grant == nil {
		f.t.Fatal("bad synthetic confirm")
	}
	b := clientwire.Binding{HubID: f.scope.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	if _, err := clientwire.OpenRequest(f.n2.hubKey, f.scope.DevicePublic, b, raw); err != nil {
		f.t.Fatal(err)
	}
	n := f.grant.Claims.Candidate
	if n == nil || packet.Route.Sequence != f.lastRequest+1 {
		f.t.Fatal("confirm skipped scripted counters")
	}
	f.binding = &store.NodeControlKeyBinding{OwnerBindingID: "binding_synthetic", OwnerID: f.scope.OwnerID, HubID: f.scope.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: f.scope.DeviceID, OwnerKeyID: f.scope.OwnerPublic.ID,
		NodeCredentialVersion: 1, BindingVersion: 1, NodeKeyID: n.NodePublic.ID, NodePublicIdentity: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch,
		HubKeyID: n.HubNodeControlPublic.ID, HubPublicIdentity: n.HubNodeControlPublic, HubKeyFingerprint: n.HubNodeControlFingerprint, HubKeyVersion: n.HubNodeControlKeyVersion,
		ApprovedRequestID: n.RequestID, ApprovedRequestVersion: int64(n.Version), ApprovedCandidateDigest: n.CandidateDigest, ApprovedOwnerDeviceID: f.scope.DeviceID, ApprovedOwnerKeyID: f.scope.OwnerPublic.ID,
		ApprovedAt: f.stamp(f.n2.now), State: "ACTIVE", Version: 1}
	body, _ := json.Marshal(map[string]any{"ok": true, "operation_id": packet.Route.OperationID, "request_id": "clientreq_synthetic_n3", "result": f.binding})
	route := packet.Route
	route.Direction = clientwire.DirectionResponse
	route.Sequence = f.nextResponse
	route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	response, err := clientwire.SealResponse(f.n2.hubKey, f.scope.DevicePublic, b, route, body)
	if err != nil {
		f.t.Fatal(err)
	}
	f.lastRequest++
	f.nextResponse++
	f.provenance = strings.Repeat("4", 32)
	return response
}

func (f *nodeActorFixture) bindingDTO() e2ee.OwnerAppNodeBinding {
	b := f.binding
	if b == nil {
		f.t.Fatal("missing synthetic confirmed binding")
	}
	return e2ee.OwnerAppNodeBinding{OwnerBindingID: b.OwnerBindingID, OwnerID: b.OwnerID, HubID: b.HubID, NodeID: b.NodeID, NodeName: b.NodeName, ClientDeviceID: b.ClientDeviceID, OwnerKeyID: b.OwnerKeyID,
		CredentialVersion: b.NodeCredentialVersion, BindingVersion: b.BindingVersion, NodePublic: b.NodePublicIdentity, NodeKeyFingerprint: b.NodeKeyFingerprint, NodeKeyVersion: b.NodeKeyVersion, NodeKeyEpoch: b.NodeKeyEpoch,
		HubNodeControlPublic: b.HubPublicIdentity, HubNodeControlFingerprint: b.HubKeyFingerprint, HubNodeControlKeyVersion: b.HubKeyVersion,
		ApprovedRequestID: b.ApprovedRequestID, ApprovedRequestVersion: uint64(b.ApprovedRequestVersion), ApprovedCandidateDigest: b.ApprovedCandidateDigest, ApprovedAt: b.ApprovedAt, State: b.State}
}

func (f *nodeActorFixture) reconcile(request wire.AppNodeReconcileRequest, id, digest string) wire.AppNodeReconcileResult {
	target := wire.AppNodePacketDigest(request.OriginalPacket)
	p, err := wire.DecodePacket(request.OriginalPacket)
	if err != nil {
		f.t.Fatal(err)
	}
	r := wire.AppNodeReconcileResult{Format: wire.AppNodeReconciledFormat, Origin: f.scope.Origin, HubID: f.scope.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID,
		RequestID: id, RequestPacketDigest: digest, GrantID: request.GrantID, OriginalKind: request.OriginalKind, OriginalOperation: p.Packet.Route.Operation, OriginalRequestID: p.Packet.Route.OperationID,
		OriginalPacketDigest: target, State: wire.AppNodeCompleted, ReceiptPacket: f.receipts[target], AccountEpoch: 1, DeviceEpoch: 1, CurrentHeadVersion: f.head, CurrentGrantState: f.state, ObservedAt: f.stamp(f.n2.now)}
	if len(r.ReceiptPacket) == 0 {
		if p.Packet.Route.Operation == wire.OperationAppNodeStatus {
			r.State = wire.AppNodeReadExpired
		} else {
			fenced := f.result(p.Packet.Route.Operation, p.Packet.Route.OperationID, target, request.GrantID)
			fenced.State, fenced.ErrorCode = wire.AppNodeRejectedFenced, "INVALID_REQUEST"
			fenced.Authority.AllowedOperations = []string{}
			fenced.Authority.RemainingConfirmations = 0
			raw, e := wire.SealResponse(f.n2.hubKey, f.scope.DevicePublic, p.Packet.Route, fenced)
			if e != nil {
				f.t.Fatal(e)
			}
			f.receipts[target], f.fenced[target] = raw, true
			r.State, r.ReceiptPacket = wire.AppNodeRejectedFenced, raw
		}
	} else if f.fenced[target] {
		r.State = wire.AppNodeRejectedFenced
	}
	return r
}

func (f *nodeActorFixture) approve(t *testing.T) {
	t.Helper()
	s := f.c.Snapshot()
	if s.Node.Candidate == nil {
		t.Fatal("missing Node review")
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionApproveNode, NodeReviewID: s.Node.Candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true}); err != nil {
		t.Fatal(err)
	}
}

func (f *nodeActorFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	f.c = f.n2.controller(t, f.root).(*nativeController)
	f.c.cfg.HTTP = f
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := f.c.Snapshot().Profiles
	if len(profiles) != 1 {
		t.Fatal("saved profile lost")
	}
	if err := f.c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
}

func TestNodeControllerFiniteFlowKeepsN2AndKeysAndUsesHeartbeatDeadline(t *testing.T) {
	f := newNodeActorFixture(t)
	c := f.c
	ctx := context.Background()
	owner, device := c.owner.Public(), c.device.Public()
	n2Before, _ := json.Marshal(c.state.Enrollment)
	if c.Snapshot().Authorization.State != "EXPIRED" {
		t.Fatal("test did not start after logical N2 expiry")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.Node.Candidate == nil || s.Node.Access.Confirmed {
		t.Fatal("preview granted authority")
	}
	before := len(f.posts[wire.OperationAppNodeComplete])
	if c.Dispatch(ctx, Action{Kind: ActionApproveNode, NodeReviewID: s.Node.Candidate.ReviewID, ConfirmNodeAccess: true}) == nil || len(f.posts[wire.OperationAppNodeComplete]) != before {
		t.Fatal("approval bypassed exact key consent")
	}
	f.approve(t)
	s = c.Snapshot()
	if s.Node.Binding == nil || !s.Node.Access.Confirmed || s.Node.ConnectionState() != NodeUnknown || s.Management != ManagementUnavailable {
		t.Fatal("binding became heartbeat or generic management authority")
	}
	f.heartbeat = f.stamp(f.n2.now)
	if err := c.Dispatch(ctx, Action{Kind: ActionRefreshNode}); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Node.ConnectionState() != NodeOnline {
		t.Fatal("current authenticated heartbeat not shown")
	}
	f.n2.now = f.n2.now.Add(wire.AppNodeObservationStaleAfter + time.Second)
	if c.Snapshot().Node.ConnectionState() != NodeStale {
		t.Fatal("idle desktop kept a permanent online label")
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionRefreshNode}); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Node.ConnectionState() != NodeStale {
		t.Fatal("new poll refreshed an old heartbeat")
	}
	f.deny = wire.OperationAppNodeStatus
	if c.Dispatch(ctx, Action{Kind: ActionRefreshNode}) == nil || !c.Snapshot().Node.Pending || c.Snapshot().Node.ConnectionState() == NodeOnline {
		t.Fatal("failed read retained live state or discarded its packet")
	}
	n2After, _ := json.Marshal(c.state.Enrollment)
	if !bytes.Equal(n2Before, n2After) || !reflect.DeepEqual(owner, c.owner.Public()) || !reflect.DeepEqual(device, c.device.Public()) {
		t.Fatal("Node flow changed N2 or original identities")
	}
}

func TestNodeControllerOldHubNeverPostsSecretsOrCreatesPending(t *testing.T) {
	f := newNodeActorAvailabilityFixture(t, false)
	if f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: f.code}) == nil {
		t.Fatal("unsupported Hub accepted Node preview")
	}
	if len(f.posts) != 0 || f.c.node.Pending != nil || f.c.Snapshot().Node.Available {
		t.Fatal("old Hub received N3 secret traffic or gained pending state")
	}
	_, _, found, err := f.c.vault.LoadState(nodeStateNamespace)
	if err != nil || found {
		t.Fatal("old Hub created a first N3 vault record")
	}
}

func TestNodeControllerHeartbeatClockBoundaryWithoutTraffic(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	f.heartbeat = f.stamp(f.n2.now)
	if err := f.c.Dispatch(ctx, Action{Kind: ActionRefreshNode}); err != nil {
		t.Fatal(err)
	}
	deadline := parseExpiry(f.c.Snapshot().Node.Connectivity.FreshUntil)
	if !deadline.Equal(parseExpiry(f.heartbeat).Add(wire.AppNodeObservationStaleAfter)) {
		t.Fatal("test did not use the authenticated heartbeat deadline")
	}
	version, requests := f.c.nodeVer, len(f.requests)
	for _, tt := range []struct {
		at   time.Time
		want NodeConnectionState
	}{{deadline.Add(-time.Nanosecond), NodeOnline}, {deadline, NodeStale}, {deadline.Add(time.Nanosecond), NodeStale}} {
		f.n2.now = tt.at
		if got := f.c.Snapshot().Node.ConnectionState(); got != tt.want {
			t.Fatalf("snapshot at heartbeat boundary %v: got %s, want %s", tt.at, got, tt.want)
		}
	}
	if f.c.nodeVer != version || len(f.requests) != requests || f.c.hasNodePending() {
		t.Fatal("clock-only redraw sent traffic, changed durable state or renewed observation")
	}
}

func TestNodeControllerLegacyOrChangedEpochCannotStartAuthority(t *testing.T) {
	f := newNodeActorFixture(t)
	before := len(f.posts[wire.OperationAppNodePrepare])
	old := f.c.state.Enrollment
	f.c.state.Enrollment = nil
	if f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: f.code}) == nil || len(f.posts[wire.OperationAppNodePrepare]) != before {
		t.Fatal("legacy account bypassed completed N2 history")
	}
	f.c.state.Enrollment = old
	f.c.session.AccountEpoch++
	if f.c.nodeAccountReady() {
		t.Fatal("changed account epoch adopted immutable old N2 authority")
	}
}

func TestNodeControllerReadExpiredCannotInitializeCountersOrPermission(t *testing.T) {
	f := newNodeActorFixture(t)
	f.c.node.Client = nodeClientState{}
	f.c.node.Context = nil
	f.c.nodeContextChecked = false
	f.readExpired = true
	if err := f.c.refreshNodeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.c.node.Client.Initialized || f.c.nodeContextChecked || f.c.nodeChecked || f.c.hasNodePending() {
		t.Fatal("READ_EXPIRED adopted counters/context or failed to close the exact read")
	}
	if f.c.node.Pending == nil || !f.c.node.Pending.Applied {
		t.Fatal("pure read settlement was not durable")
	}
}

func TestNodeControllerStatusOnlyReauthorizationKeepsExactConfirmation(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	original := f.c.nodeConfirmation.Binding
	old := f.c.node.Grant.Claims
	count := len(f.posts["nodes.confirm"])
	f.c.clearSession()
	f.scope.AccountSessionID = "synthetic-node-session-2"
	f.scope.AccountSessionExpiresAt = f.stamp(f.n2.now.Add(15 * time.Minute))
	f.token = bytes.Repeat([]byte{0x47}, 32)
	f.c.session = &wire.SessionContext{Origin: f.scope.Origin, HubID: f.scope.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, DeviceKeyID: f.scope.DevicePublic.ID,
		SessionToken: bytes.Clone(f.token), AccountEpoch: 1, DeviceEpoch: 1, ExpiresAt: f.scope.AccountSessionExpiresAt}
	f.c.sessionInspected = true
	f.c.state.AccountState = AccountStateSessionActive
	f.c.initializeNode(ctx)
	if f.c.Snapshot().Node.Access.Confirmed {
		t.Fatal("new login adopted old Node permission")
	}
	if err := f.c.Dispatch(ctx, Action{Kind: ActionReauthorizeNodeStatus}); err != nil {
		t.Fatal(err)
	}
	if !f.c.Snapshot().Node.Candidate.StatusOnly {
		t.Fatal("existing Node required a new pairing code")
	}
	f.approve(t)
	if len(f.posts["nodes.confirm"]) != count || !reflect.DeepEqual(original, f.c.nodeConfirmation.Binding) || f.c.node.Grant.Claims.Profile != wire.AppNodeProfileStatus ||
		f.c.node.Grant.Claims.PreviousGrantID != old.GrantID || f.c.node.Grant.Claims.GrantID == old.GrantID || !f.c.Snapshot().Node.Access.Confirmed {
		t.Fatal("status authorization changed binding, renewed old grant or consumed confirmation")
	}
}

func TestNodeControllerStoredUnappliedCompleteReplaysBeforeNewPost(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.drop = wire.OperationAppNodeComplete
	s := f.c.Snapshot()
	if f.c.Dispatch(ctx, Action{Kind: ActionApproveNode, NodeReviewID: s.Node.Candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true}) == nil {
		t.Fatal("lost complete reported success")
	}
	p := f.c.node.Pending
	p.Response = bytes.Clone(f.receipts[wire.AppNodePacketDigest(p.Request)])
	p.Applied = false
	if len(p.Response) == 0 {
		t.Fatal("synthetic committed receipt missing")
	}
	if err := f.c.persistNode(); err != nil {
		t.Fatal(err)
	}
	if !f.c.hasNodePending() {
		t.Fatal("stored but unapplied receipt escaped recovery gate")
	}
	owner, device := f.c.owner.Public(), f.c.device.Public()
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	f.c = f.n2.controller(t, f.root).(*nativeController)
	f.c.cfg.HTTP = f
	count := len(f.posts[wire.OperationAppNodeStatus])
	if err := f.c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := f.c.Snapshot().Profiles
	if len(profiles) != 1 {
		t.Fatal("saved profile lost")
	}
	if err := f.c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	if f.c.node.Grant == nil || f.c.node.Pending == nil || !f.c.node.Pending.Applied || f.c.hasNodePending() || len(f.posts[wire.OperationAppNodeStatus]) != count || f.c.Snapshot().Node.Access.Confirmed {
		t.Fatal("startup replaced unapplied receipt or revived its authority")
	}
	if !reflect.DeepEqual(owner, f.c.owner.Public()) || !reflect.DeepEqual(device, f.c.device.Public()) {
		t.Fatal("restart replaced original identities")
	}
}

func TestNodeControllerConfirmationReceiptAndSeparateProofCrashBoundaries(t *testing.T) {
	for _, proofWritten := range []bool{false, true} {
		name := "receipt-before-apply"
		if proofWritten {
			name = "proof-before-counter-commit"
		}
		t.Run(name, func(t *testing.T) {
			f := newNodeActorFixture(t)
			ctx := context.Background()
			if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
				t.Fatal(err)
			}
			f.drop = "nodes.confirm"
			s := f.c.Snapshot()
			if f.c.Dispatch(ctx, Action{Kind: ActionApproveNode, NodeReviewID: s.Node.Candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true}) == nil {
				t.Fatal("lost confirmation was not pending")
			}
			p := f.c.node.Pending
			p.Response = bytes.Clone(f.receipts[wire.AppNodePacketDigest(p.Request)])
			p.Applied = false
			if err := f.c.persistNode(); err != nil {
				t.Fatal(err)
			}
			if proofWritten {
				device, _ := f.c.device.E2EE()
				verified, err := wire.OpenAppNodeConfirmationResponse(device, f.n2.hub, *p.GrantClaims, p.Request, p.Response, p.ExpectedResponseSequence)
				if err != nil || verified.Binding == nil {
					t.Fatal("synthetic confirmation receipt rejected")
				}
				f.c.nodeConfirmation = &nodeConfirmationRecord{Scope: f.c.node.Scope, Operation: *p, Binding: *verified.Binding}
				if err := f.c.persistNodeConfirmation(); err != nil {
					t.Fatal(err)
				}
			}
			request := bytes.Clone(p.Request)
			f.reopen(t)
			if f.c.node.Client.NextRequest != 2 || f.c.node.Client.NextResponse != 2 || f.c.nodeConfirmation == nil || !bytes.Equal(request, f.c.nodeConfirmation.Operation.Request) || f.c.hasNodePending() {
				t.Fatal("startup lost the exact confirmation or skipped/doubled its counters")
			}
			f.reopen(t)
			if f.c.node.Client.NextRequest != 2 || f.c.node.Client.NextResponse != 2 || len(f.posts["nodes.confirm"]) != 1 {
				t.Fatal("second reopen advanced or dispatched confirmation twice")
			}
		})
	}
}

func TestNodeControllerStoredReconcileReceiptCompletesAcrossNamespaces(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	f.drop = wire.OperationAppNodePrepare
	if f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}) == nil {
		t.Fatal("prepare loss missing")
	}
	f.deny, f.drop = wire.OperationAppNodePrepare, wire.OperationAppNodeReconcile
	if f.c.Dispatch(ctx, Action{Kind: ActionRecoverNode}) == nil || f.c.nodeRecovery == nil {
		t.Fatal("reconcile loss missing")
	}
	f.c.nodeRecovery.Response = bytes.Clone(f.receipts[wire.AppNodePacketDigest(f.c.nodeRecovery.Request)])
	if len(f.c.nodeRecovery.Response) == 0 {
		t.Fatal("missing synthetic diagnostic receipt")
	}
	if err := f.c.persistNodeRecovery(); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(f.c.node.Pending.Request)
	f.reopen(t)
	if f.c.hasNodePending() || f.c.nodeRecovery != nil || f.c.node.Proposal == nil || f.c.node.Proposal.Challenge == nil || !bytes.Equal(original, f.c.node.Proposal.PreparePacket) {
		t.Fatal("restart lost target or failed to finish the committed reconciliation")
	}
}

func TestNodeControllerExpiredPrepareReceiptSettlesButCannotApprove(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	f.drop = wire.OperationAppNodePrepare
	if f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}) == nil {
		t.Fatal("prepare loss missing")
	}
	f.n2.now = f.n2.now.Add(6 * time.Minute)
	if err := f.c.Dispatch(ctx, Action{Kind: ActionRecoverNode}); err != nil {
		t.Fatal(err)
	}
	if f.c.hasNodePending() || f.c.node.Proposal != nil || f.c.Snapshot().Node.Access.Confirmed {
		t.Fatal("expired historical challenge revived approval")
	}
	if len(f.posts[wire.OperationAppNodePrepare]) != 2 || !bytes.Equal(f.posts[wire.OperationAppNodePrepare][0], f.posts[wire.OperationAppNodePrepare][1]) {
		t.Fatal("expiry resealed original prepare")
	}
	if !f.c.nodeCanStartInitial() {
		t.Fatal("authenticated expired unconfirmed proposal stranded a new code")
	}
}

func TestNodeControllerObsoletePreparedSessionCanBeDiagnosedWithoutLogin(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	prepareCount := len(f.posts[wire.OperationAppNodePrepare])
	f.c.clearSession()
	f.c.state.AccountState = AccountStateLoginRequired
	f.scope.AccountSessionID = "synthetic-new-session"
	f.c.publish()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionRefreshNode}); err != nil {
		t.Fatal(err)
	}
	if f.c.node.Proposal != nil || f.c.hasNodePending() || f.c.nodeContextChecked || f.c.nodeChecked || len(f.posts[wire.OperationAppNodePrepare]) != prepareCount {
		t.Fatal("diagnostic session-end observation retained obsolete consent or created new authority")
	}
}

func TestNodeControllerIdleReviewExpiryRetainsDiagnosticRefresh(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	before := f.c.Snapshot()
	if before.Node.Candidate == nil || !containsAction(before.AvailableActions, ActionApproveNode) {
		t.Fatal("test did not begin with a reviewable proposal")
	}
	version, requests := f.c.nodeVer, len(f.requests)
	// Only time passes: no publish or request can add a missing action to the
	// frozen renderer snapshot. The diagnostic action must already exist.
	f.n2.now = parseExpiry(before.Node.Candidate.ExpiresAt).Add(time.Nanosecond)
	after := f.c.Snapshot()
	if containsAction(after.AvailableActions, ActionApproveNode) || !containsAction(after.AvailableActions, ActionRefreshNode) ||
		after.Node.Candidate == nil || after.Node.Candidate.ReviewID != before.Node.Candidate.ReviewID || after.Node.Access.Confirmed ||
		f.c.nodeVer != version || len(f.requests) != requests {
		t.Fatal("idle expiry stranded diagnostics, retained approval or changed durable state")
	}
	if err := f.c.Dispatch(ctx, Action{Kind: ActionRefreshNode}); err != nil {
		t.Fatal(err)
	}
	if f.c.node.Proposal != nil || f.c.hasNodePending() || !containsAction(f.c.Snapshot().AvailableActions, ActionPreviewNode) ||
		len(f.posts[wire.OperationAppNodePrepare]) != 1 || len(f.posts[wire.OperationAppNodeComplete]) != 0 || len(f.posts["nodes.confirm"]) != 0 {
		t.Fatal("terminal diagnostic did not safely return to a new explicit code")
	}
}

func TestNodeControllerSelfCancelAllowsStatusOnlyWithoutStoppingNode(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	before := f.bindingDTO()
	oldGrant := f.c.node.Grant.Claims.GrantID
	if err := f.c.Dispatch(ctx, Action{Kind: ActionCancelNodeAccess, NodeReviewID: f.c.Snapshot().Node.Access.ReviewID}); err != nil {
		t.Fatal(err)
	}
	if f.c.Snapshot().Node.Access.Confirmed || !reflect.DeepEqual(before, f.bindingDTO()) || f.binding.State != "ACTIVE" {
		t.Fatal("ending App access changed the Node binding")
	}
	if err := f.c.Dispatch(ctx, Action{Kind: ActionReauthorizeNodeStatus}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	if f.c.node.Grant.Claims.GrantID == oldGrant || f.c.node.Grant.Claims.Profile != wire.AppNodeProfileStatus || len(f.posts["nodes.confirm"]) != 1 {
		t.Fatal("self-cancel resumed or re-paired instead of new status-only consent")
	}
}

func TestNodeControllerReadExistingRejectsSubstitutedFullBinding(t *testing.T) {
	f := newNodeActorFixture(t)
	ctx := context.Background()
	if err := f.c.Dispatch(ctx, Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	if err := f.c.Dispatch(ctx, Action{Kind: ActionCancelNodeAccess, NodeReviewID: f.c.Snapshot().Node.Access.ReviewID}); err != nil {
		t.Fatal(err)
	}
	f.binding.HubKeyVersion++
	if f.c.Dispatch(ctx, Action{Kind: ActionReauthorizeNodeStatus}) == nil || !f.c.hasNodePending() {
		t.Fatal("different full binding was offered for consent")
	}
	for _, a := range f.c.Snapshot().AvailableActions {
		if a == ActionApproveNode {
			t.Fatal("substituted target enabled explicit consent")
		}
	}
}
