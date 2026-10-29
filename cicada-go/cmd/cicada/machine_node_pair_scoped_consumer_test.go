package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// The transport and all cryptographic codecs are real. This scripted scoped
// responder has no scoped Store/Guard transactions and is never carrier PASS.
type nodePairScopedConsumerFixture struct {
	f              nodePairLocalFixture
	t              *testing.T
	mu             sync.Mutex
	ids            hubidentity.Set
	owner, device  *e2ee.Identity
	context        *wire.NodePairTrustScopedContext
	oob            string
	proof, capsule []byte
	approval       wire.NodePairTrustScopedApproval
	binding        e2ee.OwnerAppNodeBinding
	cache          map[string][]byte
	requests       map[string][][]byte
	drop           map[string]int
	available      bool
}

func newNodePairScopedConsumerFixture(t *testing.T) *nodePairScopedConsumerFixture {
	t.Helper()
	f := newNodePairLocalFixture(t)
	ids, err := hubidentity.LoadOrCreate(filepath.Dir(f.native.file), "")
	if err != nil || !reflect.DeepEqual(ids.ClientControl.Public(), f.native.d.Claims.Hub.Public) {
		t.Fatal("synthetic Hub keys unavailable", err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	x := &nodePairScopedConsumerFixture{f: f, t: t, ids: ids, owner: owner, device: device, cache: map[string][]byte{}, requests: map[string][][]byte{}, drop: map[string]int{}, available: true}
	actual := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wire.NodePairTrustScopedCapabilitiesPath {
			x.mu.Lock()
			c := wire.NodePairTrustScopedContractCapabilities()
			c.Available = x.available
			x.mu.Unlock()
			raw, _ := json.Marshal(c)
			_, _ = w.Write(raw)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v2/node/pair-trust-scoped/") {
			actual.ServeHTTP(w, r)
			return
		}
		x.serve(w, r)
	})
	return x
}

func (f *nodePairScopedConsumerFixture) serve(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		f.t.Error("scoped preproof sent bearer")
		w.WriteHeader(400)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, wire.MaxNodePairTrustScopedReconcilePacketBytes+1))
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(400)
		return
	}
	var header wire.NodePairTrustScopedPacket
	if json.Unmarshal(raw, &header) != nil || wire.NodePairTrustScopedHTTPPath(header.Operation) != req.URL.Path {
		f.t.Error("scoped route mismatch")
		w.WriteHeader(400)
		return
	}
	body := wire.NewNodePairTrustScopedRequestBody(header.Operation)
	header, err = wire.OpenNodePairTrustScopedRequest(f.ids.ClientControl, f.f.native.d.Claims.Hub, raw, header.Operation, body, time.Now().UTC())
	if err != nil {
		f.t.Error("scoped request codec", err)
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests[header.Operation] = append(f.requests[header.Operation], bytes.Clone(raw))
	digest := wire.NodePairTrustScopedPacketDigest(raw)
	response := f.cache[digest]
	if response == nil {
		r := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: header.Operation, RequestID: header.RequestID, AttemptID: header.AttemptID, RequestPacketDigest: digest, State: wire.NodePairTrustScopedPending, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		switch q := body.(type) {
		case *wire.NodePairTrustScopedStart:
			if wire.ValidateNodePairTrustScopedStartProof(f.ids.NodeControl, header.SenderPublic, *q) != nil {
				f.t.Error("actual original Node proof failed")
				w.WriteHeader(400)
				return
			}
			selector := "23456789ABCD"
			codeDigest, _ := wire.AppNodeCodeDigest(q.Hub.HubID, selector)
			n := e2ee.OwnerAppNodeCandidate{RequestID: "synthetic-scoped-candidate", Version: 1, Mode: "INITIAL", State: "PENDING", HubID: q.Hub.HubID, NodeID: q.NodeID, NodeName: q.NodeName, NodePublic: header.SenderPublic, NodeKeyFingerprint: nodewire.IdentityFingerprint(header.SenderPublic), NodeKeyEpoch: 1, HubNodeControlPublic: q.HubNodeControlPublic, HubNodeControlKeyVersion: q.HubNodeControlKeyVersion, HubNodeControlFingerprint: nodewire.IdentityFingerprint(q.HubNodeControlPublic), CodeDigest: codeDigest, ExpiresAt: q.ExpiresAt}
			n.CandidateDigest, err = nodewire.PairingCandidateDigest(nodewire.PairingCandidateBasis{RequestID: n.RequestID, Version: 1, Mode: n.Mode, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, CredentialDigest: q.CredentialDigest, CodeDigest: codeDigest, NodePublicIdentity: n.NodePublic, NodeFingerprint: n.NodeKeyFingerprint, HubPublicIdentity: n.HubNodeControlPublic, HubKeyVersion: 1, HubFingerprint: n.HubNodeControlFingerprint, NodeKeyEpoch: 1, ExpiresAt: n.ExpiresAt})
			if err != nil {
				f.t.Error(err)
				w.WriteHeader(500)
				return
			}
			c := wire.NodePairTrustScopedContext{ScopeVersion: 2, AuthorityNodeID: q.NodeID, Format: wire.NodePairTrustScopedFormat, AttemptID: header.AttemptID, Hub: q.Hub, Origin: q.Origin, DescriptorDigest: q.DescriptorDigest, NodeNonce: hex.EncodeToString(q.RequestNonce), Mode: wire.NodePairTrustScopedInitial, Candidate: &n, IssuedAt: r.ObservedAt, ExpiresAt: q.ExpiresAt}
			f.context = &c
			r.Context, r.Selector = &c, selector
		case *wire.NodePairTrustScopedExistingStart:
			c := q.Context
			c.Binding = &f.binding
			f.context = &c
			r.Context = &c
		case *wire.NodePairTrustScopedCommit:
			if header.Operation == wire.OperationNodePairTrustScopedCommit {
				f.oob = q.OOBCommitment
			}
			r.Context, r.OOBCommitment = f.context, f.oob
			if header.Operation == wire.OperationNodePairTrustScopedPoll && f.proof != nil {
				r.State, r.OwnerProof, r.TrustCapsule = wire.NodePairTrustScopedOwnerApproved, f.proof, f.capsule
			}
		case *wire.NodePairTrustScopedACK:
			if wire.VerifyNodePairTrustScopedACK(*f.context, f.oob, f.proof, f.capsule, *q, time.Now().UTC()) != nil {
				f.t.Error("private ACK proof failed")
				w.WriteHeader(400)
				return
			}
			keyPath, _ := machineNodeControlPaths(f.f.state, f.f.node)
			keyRaw, _ := machineNodePairPrivateRead(keyPath, machineNodePairLocalMax)
			key, _ := e2ee.UnmarshalIdentity(keyRaw)
			clear(keyRaw)
			local, err := loadMachineNodePairScopedState(f.f.state, f.f.node, key)
			if err != nil || local.TrustAcceptedAt == "" || !bytes.Equal(local.ACKPacket, raw) || local.PendingOperation != wire.OperationNodePairTrustScopedACK || machineNodePairScopedCurrentTrust(f.f.state, local) != nil {
				f.t.Error("ACK preceded durable S verification/current pin/original packet", err)
				w.WriteHeader(400)
				return
			}
			clear(local.Secret)
			r.Context, r.OOBCommitment, r.State, r.Binding = f.context, f.oob, wire.NodePairTrustScopedACKed, &f.binding
		case *wire.NodePairTrustScopedReconcile:
			original := f.cache[q.OriginalPacketDigest]
			if original == nil {
				r.State, r.ErrorCode = wire.NodePairTrustScopedFenced, "FENCED"
			} else {
				r.State, r.OriginalPacketDigest, r.OriginalReceipt = wire.NodePairTrustScopedRecovered, q.OriginalPacketDigest, original
			}
		default:
			f.t.Error("unexpected scoped test operation")
			w.WriteHeader(400)
			return
		}
		response, err = wire.SealNodePairTrustScopedResponse(f.ids.ClientControl, f.f.native.d.Claims.Hub, raw, body, r)
		if err != nil {
			f.t.Error("scoped result codec", err)
			w.WriteHeader(500)
			return
		}
		f.cache[digest] = response
	}
	if f.drop[header.Operation] > 0 {
		f.drop[header.Operation]--
		w.WriteHeader(503)
		return
	}
	_, _ = w.Write(response)
}

func (f *nodePairScopedConsumerFixture) load(t *testing.T) (*machineNodeControlClient, *machineNodePairScopedState) {
	t.Helper()
	c, err := openMachineNodeControlClientMode(f.f.state, f.f.native.d.Claims.Origin, f.f.node, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := loadMachineNodePairScopedState(f.f.state, f.f.node, c.identity)
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func (f *nodePairScopedConsumerFixture) run(t *testing.T) error {
	t.Helper()
	return prepareMachineNodePairTrust(context.Background(), f.f.state, f.f.node, f.f.node, f.f.address, "", false, true, false, io.Discard, nil, "auto")
}

func (f *nodePairScopedConsumerFixture) approve(t *testing.T, s *machineNodePairScopedState, observed ...time.Time) {
	t.Helper()
	now := time.Now().UTC()
	if len(observed) > 0 {
		now = observed[0]
	}
	codeText, err := wire.EncodeNodePairTrustScopedCode(*s.Context, s.Selector, s.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code, err := wire.DecodeNodePairTrustScopedCode(codeText, now)
	if err != nil || code.AuthorityNodeID != f.f.node || len(codeText) > 1536 {
		t.Fatal("compact v2 exact Node", err)
	}
	defer clear(code.OOBSecret)
	oob, err := wire.MatchNodePairTrustScopedCode(code, *s.Context, f.f.native.d.Claims.Hub, f.f.native.d.Claims.NodeControl, f.f.native.d.Claims.Origin, wire.NodePairTrustScopedDescriptorDigest(f.f.native.text), now)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := wire.HubFingerprint(f.f.native.d.Claims.Hub)

	scope := e2ee.OwnerAppNodeScopedScope{AuthorityNodeID: f.f.node, Version: 2, Origin: f.f.native.d.Claims.Origin, HubID: f.f.native.d.Claims.Hub.HubID, HubFingerprint: fp, AccountID: "synthetic-account", AccountSessionID: "synthetic-account-session", AccountSessionExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), OwnerID: "synthetic-owner", OwnerPublic: f.owner.Public(), OwnerKeyVersion: 1, DeviceID: wire.AccountDeviceIDPrefix + strings.Repeat("a", 32), DevicePublic: f.device.Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, HeadVersion: 1, TransportPolicy: wire.AppNodeScopedTransportHTTPS}
	digest, _ := wire.NodePairTrustScopedContextDigest(*s.Context)
	a := wire.NodePairTrustScopedApproval{Format: wire.NodePairTrustScopedFormat, ContextDigest: digest, OOBCommitment: oob, Scope: scope, GrantID: strings.Repeat("a", 32), GrantProofDigest: strings.Repeat("b", 64), ConfirmationPacketDigest: strings.Repeat("c", 64), PrepareRequestID: strings.Repeat("d", 32), PreparePacketDigest: strings.Repeat("e", 64), ServerNonce: strings.Repeat("f", 64), PreparedAt: now.Format(time.RFC3339Nano), AcceptBefore: now.Add(2 * time.Minute).Format(time.RFC3339Nano)}
	if s.Context.Mode == wire.NodePairTrustScopedExisting {
		a.GrantID, a.GrantProofDigest, a.ConfirmationPacketDigest = "", "", ""
	}
	proof, capsule, err := wire.SealNodePairTrustScopedApproval(f.owner, *s.Context, oob, a, code.OOBSecret, bytes.Repeat([]byte{0x58}, 32), now)
	if err != nil {
		t.Fatal("synthetic original Owner approval", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approval, f.proof, f.capsule = a, proof, capsule
	if s.Context.Mode == wire.NodePairTrustScopedInitial {
		n := s.Context.Candidate
		f.binding = e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-scoped-binding", OwnerID: scope.OwnerID, HubID: scope.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: scope.DeviceID, OwnerKeyID: scope.OwnerPublic.ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch, HubNodeControlPublic: n.HubNodeControlPublic, HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: n.HubNodeControlKeyVersion, ApprovedRequestID: n.RequestID, ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: now.Format(time.RFC3339Nano), State: "ACTIVE"}
	}
}

func TestNodePairScopedConsumerOriginalACKLossColdReopen(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("scoped Node did not wait", err)
	}
	c, s := f.load(t)
	defer clear(s.Secret)
	if s.Context.ScopeVersion != 2 || c.state.BindingID != "" {
		t.Fatal("scoped candidate granted a binding")
	}
	keyBefore, _ := c.identity.MarshalBinary()
	defer clear(keyBefore)
	f.approve(t, s)
	f.mu.Lock()
	f.drop[wire.OperationNodePairTrustScopedACK] = 1
	f.mu.Unlock()
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("lost ACK did not remain pending", err)
	}
	c, pending := f.load(t)
	defer clear(pending.Secret)
	if pending.PendingOperation != wire.OperationNodePairTrustScopedACK || pending.TrustAcceptedAt == "" || c.state.BindingID != "" {
		t.Fatal("Owner approval/unknown ACK installed binding")
	}
	original := bytes.Clone(pending.PendingPacket)
	machineNodeControlClients.Delete(c.statePath)
	if err := f.run(t); err != nil {
		t.Fatal("cold original ACK recovery failed", err)
	}
	c, settled := f.load(t)
	defer clear(settled.Secret)
	keyAfter, _ := c.identity.MarshalBinary()
	defer clear(keyAfter)
	if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(settled.ACKPacket, original) || c.state.BindingID != f.binding.OwnerBindingID || settled.Stage != wire.NodePairTrustScopedACKed || !bytes.Equal(s.Secret, settled.Secret) {
		t.Fatal("ACK recovery replaced original identity/secret/packet")
	}
	f.mu.Lock()
	requests := f.requests[wire.OperationNodePairTrustScopedACK]
	f.available = false
	f.mu.Unlock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatal("ACK retry changed operation/request bytes")
	}
	before, _ := recoveryTreeDigest(machineNodeStateDir(f.f.state, f.f.node))
	if err := machineNodePairACKMarker(f.f.state, f.f.node, c); err != nil {
		t.Fatal("read-only ACK marker rejected", err)
	}
	if err := f.run(t); err != nil {
		t.Fatal("ACKED startup retried enrollment/capability", err)
	}
	after, _ := recoveryTreeDigest(machineNodeStateDir(f.f.state, f.f.node))
	if before != after {
		t.Fatal("ACKED startup rewrote enrollment state")
	}
	t.Log("CLOSED_SCOPED_NODE consumer=PASS scripted_codec_transport=true scoped_carrier=NOT_RUN original_ACK_byte_identical=true cold_reopen=true Owner_approval_only_pending=true")
}

func TestNodePairScopedCapsuleWrongSecretAndLateFirstTrustRetainOriginal(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, s := f.load(t)
	defer clear(s.Secret)
	f.approve(t, s)
	q := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := newMachineNodePairScopedRequest(f.f.state, c.identity, s, f.f.native.d.Claims.Hub, wire.OperationNodePairTrustScopedPoll, q); err != nil {
		t.Fatal(err)
	}
	raw, receipt, err := sendMachineNodePairScopedPending(context.Background(), f.f.state, c.identity, s, f.f.native.d, f.f.http)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(s.PendingPacket)
	correct := bytes.Clone(s.Secret)
	defer clear(correct)
	s.Secret = bytes.Repeat([]byte{0x99}, 32)
	if err := applyMachineNodePairScopedResult(f.f.state, c, s, f.f.native.d, raw, receipt); !errors.Is(err, errMachineNodePairIndependentTrust) || !bytes.Equal(original, s.PendingPacket) || s.TrustAcceptedAt != "" {
		t.Fatal("wrong S cleared original or installed trust", err)
	}
	s.Secret = correct
	end, _ := time.Parse(time.RFC3339Nano, f.approval.AcceptBefore)
	if err := acceptMachineNodePairScopedCapsule(f.f.state, c, s, raw, end.Add(time.Second)); !errors.Is(err, errMachineNodePairIndependentTrust) || s.TrustAcceptedAt != "" {
		t.Fatal("late first trust accepted historical receipt", err)
	}
	if _, err := nodekeys.OpenExistingCryptoState(context.Background(), machineNodeStateDir(f.f.state, f.f.node)); err == nil {
		t.Fatal("failed S/TTL initialized Owner trust database")
	}
}
