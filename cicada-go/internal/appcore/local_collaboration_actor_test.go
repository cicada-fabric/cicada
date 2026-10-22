package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This actor uses the actual Core, local Owner key, encrypted vault and PQ
// packets. It deliberately makes no claim about Hub Store/Guard or Node IPC.
type localCollaborationActor struct {
	t            *testing.T
	n            *nodeActorFixture
	c            *nativeController
	next         HTTPDoer
	available    bool
	capStatus    int
	malformed    bool
	pageSize     int
	deny, drop   string
	posts        map[string][][]byte
	receipts     map[string][]byte
	challenge    wire.LocalDomainChallenge
	descriptions []wire.LocalDomainDescription
}

func newLocalCollaborationActor(t *testing.T) *localCollaborationActor {
	t.Helper()
	n := newNodeActorFixture(t)
	f := &localCollaborationActor{t: t, n: n, c: n.c, next: n, available: true, capStatus: 200, pageSize: 1, posts: map[string][][]byte{}, receipts: map[string][]byte{}}
	f.c.cfg.HTTP = f
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: n.code}); err != nil {
		t.Fatal(err)
	}
	n.approve(t)
	if !f.c.Snapshot().LocalCollaboration.Current || !slices.Contains(f.c.Snapshot().AvailableActions, ActionPrepareLocalCollaboration) {
		t.Fatal("fresh authenticated Node read did not enable setup")
	}
	return f
}

func (f *localCollaborationActor) Do(req *http.Request) (*http.Response, error) {
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), Request: req}, nil
	}
	if req.URL.Path == wire.LocalDomainCapabilitiesPath {
		if f.malformed {
			return reply([]byte(`{"available":true}`), 200)
		}
		cap := wire.LocalDomainCapabilities{Format: wire.LocalDomainFormat, ContractRevision: wire.LocalDomainContractRevision, Available: f.available, ServeMode: "--hub-nodes-only", TransportPolicy: wire.AppNodeTransportHTTPS, HTTPOperations: wire.LocalDomainHTTPOperations(), NodeOperations: wire.LocalDomainNodeOperations(), Rights: e2ee.LocalDomainRights(), MaxActivePoliciesPerNodeUser: 1, OptionalPolicyExpiry: true}
		raw, _ := json.Marshal(cap)
		return reply(raw, f.capStatus)
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/owner/local-domains/") {
		return f.next.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	p, err := wire.DecodeLocalDomainPacket(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	r := p.Packet.Route
	if req.URL.Path != wire.LocalDomainHTTPPath(r.Operation) {
		f.t.Fatal("incorrect local-domain HTTP route")
	}
	index := localDomainOriginal
	if r.Operation == wire.OperationLocalDomainReconcile {
		index = localDomainRecovery
	}
	saved, _, found, err := f.c.vault.LoadState(localDomainNamespaces[index])
	defer clear(saved)
	durable, decodeErr := decodeLocalDomainRecord(saved)
	if err != nil || !found || decodeErr != nil || !bytes.Equal(durable.Packet, raw) {
		f.t.Fatal("local-domain POST preceded exact vault persistence")
	}
	f.posts[r.Operation] = append(f.posts[r.Operation], bytes.Clone(raw))
	if f.deny == r.Operation {
		return reply([]byte("synthetic unsigned HTTP refusal"), 403)
	}
	digest := wire.LocalDomainPacketDigest(raw)
	response := f.receipts[digest]
	if response == nil {
		binding := clientwire.Binding{HubID: r.HubID, OwnerID: r.OwnerID, DeviceID: r.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
		device := f.c.device.Public()
		open := func(out any) {
			if err := wire.OpenRequestAt(f.n.n2.hubKey, &device, binding, r, raw, out, f.n.n2.now); err != nil {
				f.t.Fatal("open actual Core packet", err)
			}
		}
		verify := func(proof []byte) e2ee.OwnerLocalDomainRequestClaims {
			claims, err := e2ee.VerifyOwnerLocalDomainRequest(f.c.owner.Public(), proof, wire.LocalDomainOwnerPurpose(r.Operation), f.n.n2.now)
			if err != nil {
				f.t.Fatal("actual local Owner signature", err)
			}
			return claims
		}
		base := wire.LocalDomainResult{Format: wire.LocalDomainFormat, Operation: r.Operation, RequestID: r.OperationID, RequestPacketDigest: digest, HubID: r.HubID, OwnerID: r.OwnerID, DeviceID: r.DeviceID, State: wire.AppNodeCompleted, ObservedAt: f.n.stamp(f.n.n2.now)}
		var body any
		switch r.Operation {
		case wire.OperationLocalDomainPrepare:
			var q wire.LocalDomainPrepare
			open(&q)
			claims := verify(q.OwnerProof)
			if claims.Target == nil || claims.Target.LocalUserScope != "" {
				f.t.Fatal("App supplied OS user")
			}
			target := claims.Target
			report, err := e2ee.SignLocalDomainUserReport(f.n.nodeKey, e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: r.HubID, OwnerID: r.OwnerID, NodeID: target.Node.NodeID, OwnerBindingID: target.Node.OwnerBindingID, NodeKeyEpoch: target.Node.NodeKeyEpoch, LocalUserScope: "uid:4242", IssuedAt: f.n.stamp(f.n.n2.now), ExpiresAt: f.n.stamp(f.n.n2.now.Add(5 * time.Minute)), Nonce: strings.Repeat("a", 64)})
			if err != nil {
				f.t.Fatal(err)
			}
			policy := e2ee.LocalDomainPolicy{Version: 1, PolicyID: strings.Repeat("b", 32), Epoch: 1, Origin: claims.Scope.Origin, HubID: r.HubID, HubFingerprint: claims.Scope.HubFingerprint, OwnerID: r.OwnerID, OwnerPublic: f.c.owner.Public(), OwnerKeyVersion: claims.Scope.OwnerKeyVersion, Node: target.Node, NodeControlBindingVersion: 1, CredentialCommitment: strings.Repeat("c", 64), LocalUserScope: "uid:4242", NetworkID: "synthetic-domain-network", NetworkName: target.NewNetworkName, CreateNetwork: true, GroupID: "synthetic-domain-group", GroupName: target.GroupName, Rights: e2ee.LocalDomainRights(), IssuedAt: f.n.stamp(f.n.n2.now), ExpiresAt: target.ExpiresAt, PrepareRequestID: r.OperationID, PreparePacketDigest: digest, ServerNonce: strings.Repeat("d", 64)}
			f.challenge = wire.LocalDomainChallenge{Format: wire.LocalDomainFormat, RequestID: r.OperationID, RequestPacketDigest: digest, PrepareProofDigest: wire.LocalDomainProofDigest(q.OwnerProof), Policy: policy, Revision: 1, ProofExpiresAt: f.n.stamp(f.n.n2.now.Add(5 * time.Minute)), ObservedAt: base.ObservedAt, LocalUserReport: report}
			f.descriptions = append(f.descriptions, wire.LocalDomainDescription{ContractRevision: wire.LocalDomainContractRevision, Policy: policy, State: wire.LocalDomainPrepared, Revision: 1, ObservedAt: base.ObservedAt})
			body = f.challenge
		case wire.OperationLocalDomainActivate:
			var q wire.LocalDomainActivate
			open(&q)
			verify(q.OwnerProof)
			policy, err := e2ee.VerifyOwnerLocalDomainPolicy(f.c.owner.Public(), q.PolicyProof, f.n.n2.now)
			if err != nil || !reflect.DeepEqual(policy, f.challenge.Policy) {
				f.t.Fatal("Core did not sign complete reviewed policy", err)
			}
			for i := range f.descriptions {
				if f.descriptions[i].Policy.PolicyID == policy.PolicyID {
					f.descriptions[i].PolicyProof = bytes.Clone(q.PolicyProof)
					f.descriptions[i].State = wire.LocalDomainActive
					f.descriptions[i].Revision = 2
					d := f.descriptions[i]
					base.Description = &d
				}
			}
			base.PolicyID, base.PolicyEpoch = policy.PolicyID, policy.Epoch
			body = base
		case wire.OperationLocalDomainRevoke:
			var q wire.LocalDomainRevoke
			open(&q)
			claims := verify(q.OwnerProof)
			for i := range f.descriptions {
				if f.descriptions[i].Policy.PolicyID == claims.PolicyID {
					f.descriptions[i].State = wire.LocalDomainRevoked
					f.descriptions[i].Revision++
					d := f.descriptions[i]
					base.Description = &d
					base.PolicyID, base.PolicyEpoch = d.Policy.PolicyID, d.Policy.Epoch
				}
			}
			body = base
		case wire.OperationLocalDomainStatus:
			var q wire.LocalDomainStatusRequest
			open(&q)
			claims := verify(q.OwnerProof)
			if claims.NodeID != f.c.nodeConfirmation.Binding.NodeID || claims.PolicyID != "" {
				f.t.Fatal("status did not select authenticated Node")
			}
			base.NodeID = claims.NodeID
			var rows []wire.LocalDomainDescription
			for _, d := range f.descriptions {
				if d.Policy.PolicyID > claims.Cursor {
					rows = append(rows, d)
				}
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Policy.PolicyID < rows[j].Policy.PolicyID })
			more := f.pageSize > 0 && len(rows) > f.pageSize
			if more {
				rows = rows[:f.pageSize]
			}
			body, err = wire.BuildLocalDomainStatusPage(base, rows, more)
			if err != nil {
				f.t.Fatal("status page", err)
			}
		case wire.OperationLocalDomainReconcile:
			var q wire.LocalDomainReconcileRequest
			open(&q)
			original, err := wire.DecodeLocalDomainPacket(q.OriginalPacket)
			if err != nil {
				f.t.Fatal(err)
			}
			digest := wire.LocalDomainPacketDigest(q.OriginalPacket)
			receipt := f.receipts[digest]
			if receipt == nil {
				or := original.Packet.Route
				fence := wire.LocalDomainResult{Format: wire.LocalDomainFormat, Operation: or.Operation, RequestID: or.OperationID, RequestPacketDigest: digest, HubID: or.HubID, OwnerID: or.OwnerID, DeviceID: or.DeviceID, State: wire.AppNodeRejectedFenced, NoEffect: true, ErrorCode: "SYNTHETIC_FENCE", ObservedAt: base.ObservedAt}
				receipt, err = wire.SealResponse(f.n.n2.hubKey, device, or, fence)
				if err != nil {
					f.t.Fatal(err)
				}
			}
			body = wire.LocalDomainReconciled{Format: wire.LocalDomainFormat, RequestID: r.OperationID, RequestPacketDigest: base.RequestPacketDigest, HubID: r.HubID, OwnerID: r.OwnerID, DeviceID: r.DeviceID, OriginalOperation: original.Packet.Route.Operation, OriginalRequestID: original.Packet.Route.OperationID, OriginalPacketDigest: digest, State: wire.AppNodeCompleted, ReceiptPacket: receipt, ObservedAt: base.ObservedAt}
		default:
			f.t.Fatal("unexpected domain operation")
		}
		response, err = wire.SealResponse(f.n.n2.hubKey, device, r, body)
		if err != nil {
			f.t.Fatal("seal PQ response", err)
		}
		f.receipts[digest] = response
	}
	if f.drop == r.Operation {
		f.drop = ""
		return nil, errors.New("synthetic response lost after acceptance")
	}
	return reply(response, 200)
}

func (f *localCollaborationActor) prepare() {
	f.t.Helper()
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: "Synthetic private Network", GroupName: "Synthetic local Group"}}); err != nil {
		f.t.Fatal(err)
	}
}
func (f *localCollaborationActor) activate() {
	f.t.Helper()
	s := f.c.Snapshot()
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionActivateLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ReviewID: s.LocalCollaboration.ReviewID, ConfirmActivation: true}}); err != nil {
		f.t.Fatal(err)
	}
}
func (f *localCollaborationActor) reopen() {
	f.t.Helper()
	if err := f.c.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.c = f.n.n2.controller(f.t, f.n.root).(*nativeController)
	f.n.c = f.c
	if pair, ok := f.next.(*pairActorFixture); ok {
		pair.c = f.c
	}
	f.c.cfg.HTTP = f
	for _, a := range []Action{{Kind: ActionDiscoverProfiles}} {
		if err := f.c.Dispatch(context.Background(), a); err != nil {
			f.t.Fatal(err)
		}
	}
	profiles := f.c.Snapshot().Profiles
	if len(profiles) != 1 {
		f.t.Fatal("profile lost")
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		f.t.Fatal(err)
	}
}

func TestLocalCollaborationRevokeRequiresExactCurrentState(t *testing.T) {
	f := newLocalCollaborationActor(t)
	f.prepare()
	f.activate()
	view := f.c.Snapshot().LocalCollaboration
	for _, input := range []LocalCollaborationAction{{ReviewID: view.StateReviewID}, {ConfirmRevoke: true, ReviewID: "other-state"}} {
		if f.c.Dispatch(context.Background(), Action{Kind: ActionRevokeLocalCollaboration, LocalCollaboration: input}) == nil || len(f.posts[wire.OperationLocalDomainRevoke]) != 0 {
			t.Fatal("revoke bypassed exact state consent")
		}
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRevokeLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ReviewID: view.StateReviewID, ConfirmRevoke: true}}); err != nil {
		t.Fatal(err)
	}
	if s := f.c.Snapshot(); s.LocalCollaboration.State != wire.LocalDomainRevoked || !s.LocalCollaboration.Current || !slices.Contains(s.AvailableActions, ActionPrepareLocalCollaboration) {
		t.Fatal("authenticated revoke/status did not restore setup")
	}
}

func TestLocalCollaborationFreshCoreWithoutCacheReadsExistingNodePolicies(t *testing.T) {
	f := newLocalCollaborationActor(t)
	f.prepare()
	f.activate()
	for i := 1; i <= 2; i++ {
		d := f.descriptions[0]
		d.Policy.PolicyID = fmt.Sprintf("%032x", i)
		d.State = wire.LocalDomainExpired
		d.PolicyProof = nil
		f.descriptions = append(f.descriptions, d)
	}
	for i, ns := range localDomainNamespaces {
		version, err := f.c.vault.CompareAndSwapState(ns, f.c.localDomain.versions[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		f.c.localDomain.versions[i] = version
	}
	f.reopen()
	if slices.Contains(f.c.Snapshot().AvailableActions, ActionPrepareLocalCollaboration) || f.c.Snapshot().LocalCollaboration.State == "UNCONFIGURED" {
		t.Fatal("missing local cache was treated as unconfigured")
	}
	f.c.session = &wire.SessionContext{Origin: f.n.scope.Origin, HubID: f.n.scope.HubID, AccountID: f.n.scope.AccountID, OwnerID: f.n.scope.OwnerID, DeviceID: f.n.scope.DeviceID, DeviceKeyID: f.c.state.DeviceKeyID, SessionToken: bytes.Clone(f.n.token), AccountEpoch: f.n.scope.AccountEpoch, DeviceEpoch: f.n.scope.DeviceEpoch, ExpiresAt: f.n.scope.AccountSessionExpiresAt}
	f.c.sessionInspected, f.c.sessionNeedsCheck = true, false
	f.c.state.AccountState = AccountStateSessionActive
	before := len(f.posts[wire.OperationLocalDomainStatus])
	f.c.initializeLocalCollaboration(context.Background())
	s := f.c.Snapshot()
	if len(f.posts[wire.OperationLocalDomainStatus])-before != 3 || s.LocalCollaboration.State != wire.LocalDomainActive || !s.LocalCollaboration.Current || slices.Contains(s.AvailableActions, ActionPrepareLocalCollaboration) {
		t.Fatal("fresh Core did not read all Node pages before offering setup")
	}
}

func TestLocalCollaborationFullPQRecoveryCoexistsWithPairVaultRecords(t *testing.T) {
	p := newPairActorFixture(t)
	p.prepareSlots()
	p.drop = wire.OperationNativePairConsentComplete
	if p.approve("A") == nil {
		t.Fatal("missing synthetic Pair loss")
	}
	p.deny = wire.OperationNativePairConsentComplete
	if err := p.dispatch(Action{Kind: ActionRecoverPair}); err != nil {
		t.Fatal(err)
	}
	// Reserve the existing Node recovery namespace through its own API too.
	if err := p.c.persistNodeRecovery(); err != nil {
		t.Fatal(err)
	}
	f := &localCollaborationActor{t: t, n: p.n, c: p.c, next: p, available: true, capStatus: 200, posts: map[string][][]byte{}, receipts: map[string][]byte{}}
	f.c.cfg.HTTP = f
	// A logged-out profile retains a versioned session tombstone. The actor's
	// injected session is deliberately not represented as a fabricated receipt.
	version, err := f.c.vault.CompareAndSwapState(appSessionNamespace, f.c.sessionVer, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.c.sessionVer = version
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: strings.Repeat("<", 128), GroupName: strings.Repeat("<", 128)}}); err != nil {
		t.Fatal(err)
	}
	f.activate()
	owner, err := f.c.owner.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		d := f.descriptions[0]
		d.Policy.PolicyID = fmt.Sprintf("%032x", i)
		d.State = wire.LocalDomainRevoked
		d.PolicyProof, err = e2ee.SignOwnerLocalDomainPolicy(owner, d.Policy)
		if err != nil {
			t.Fatal(err)
		}
		f.descriptions = append(f.descriptions, d)
	}
	f.drop = wire.OperationLocalDomainStatus
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}) == nil {
		t.Fatal("missing synthetic full page loss")
	}
	original := bytes.Clone(f.c.localDomain.original.Packet)
	packet, _ := wire.DecodeLocalDomainPacket(original)
	var page wire.LocalDomainResult
	device, _ := f.c.device.E2EE()
	response := f.receipts[wire.LocalDomainPacketDigest(original)]
	if err := wire.OpenLocalDomainResponse(device, f.c.hub, original, response, &page); err != nil {
		t.Fatal(err)
	}
	pageJSON, _ := json.Marshal(page)
	if len(page.Policies) == 0 || len(page.Policies) >= len(f.descriptions) || page.NextCursor == "" || len(pageJSON) > wire.MaxLocalDomainPageBytes {
		t.Fatal("fixture did not produce an actual byte-bounded PQ page")
	}
	f.drop = wire.OperationLocalDomainReconcile
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverLocalCollaboration}) == nil {
		t.Fatal("missing synthetic full recovery loss")
	}
	recovery := bytes.Clone(f.c.localDomain.recovery.Packet)
	f.n.n2.now = f.n.n2.now.Add(2 * time.Hour)
	f.reopen()
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverLocalCollaboration}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, f.c.localDomain.original.Packet) || !bytes.Equal(recovery, f.c.localDomain.recovery.Packet) || f.c.hasLocalDomainPending() {
		t.Fatal("full recovery did not preserve exact packets")
	}
	var total, count int
	names := append([]string{appStateNamespace, appSessionNamespace, nodeStateNamespace, nodeRecoveryNamespace, nodeConfirmationNamespace}, pairNamespaces[:]...)
	names = append(names, localDomainNamespaces[:]...)
	for _, ns := range names {
		raw, _, found, err := f.c.vault.LoadState(ns)
		if err != nil || !found {
			t.Fatalf("missing coexisting namespace %s: %v", ns, err)
		}
		count++
		total += len(raw)
		clear(raw)
	}
	if count != 16 {
		t.Fatal("fixture no longer covers full existing namespace ceiling")
	}
	// File size is a conservative bound including encrypted/base64 payload,
	// identity records and metadata; a fresh reopen verifies the actual vault.
	path, err := scopeVaultPath(f.n.root, cardScope(f.c.connection))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if f.c.storageFault || f.c.localDomain.original == nil {
		t.Fatal("full vault could not reopen")
	}
	t.Logf("namespaces=%d opaque_payload=%d vault_file=%d page_json=%d rows=%d sealed_page=%d reconcile_request=%d reconcile_response=%d operation=%s", count, total, info.Size(), len(pageJSON), len(page.Policies), len(response), len(recovery), len(f.c.localDomain.recoveryResponse.Packet), packet.Packet.Route.Operation)
}

func TestLocalCollaborationActualCoreOwnerPolicyAndIndependentLifetime(t *testing.T) {
	f := newLocalCollaborationActor(t)
	owner, device := f.c.owner.Public(), f.c.device.Public()
	f.prepare()
	s := f.c.Snapshot()
	if s.LocalCollaboration.State != wire.LocalDomainPrepared || s.LocalCollaboration.LocalUserScope != "uid:4242" || s.LocalCollaboration.ReviewID == "" {
		t.Fatal("missing Node-derived review")
	}
	if f.c.Dispatch(context.Background(), Action{Kind: ActionActivateLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ConfirmActivation: true, ReviewID: "changed"}}) == nil || len(f.posts[wire.OperationLocalDomainActivate]) != 0 {
		t.Fatal("activation bypassed exact review")
	}
	f.activate()
	s = f.c.Snapshot()
	if s.LocalCollaboration.State != wire.LocalDomainActive || !s.LocalCollaboration.Current || s.LocalCollaboration.ExpiresAt != "" {
		t.Fatal("policy not independently persistent")
	}
	f.n.n2.now = f.n.n2.now.Add(2 * time.Hour)
	s = f.c.Snapshot()
	if s.LocalCollaboration.State != wire.LocalDomainActive || s.LocalCollaboration.Current || slices.Contains(s.AvailableActions, ActionRevokeLocalCollaboration) {
		t.Fatal("account expiry changed policy or retained admin action")
	}
	f.reopen()
	if !reflect.DeepEqual(owner, f.c.owner.Public()) || !reflect.DeepEqual(device, f.c.device.Public()) || f.c.Snapshot().LocalCollaboration.State != wire.LocalDomainActive || f.c.Snapshot().LocalCollaboration.Current {
		t.Fatal("restart replaced identities or restored stale authority")
	}
}

func TestLocalCollaborationPrepareRefreshRestartRetainsReviewAndReadsAllPages(t *testing.T) {
	f := newLocalCollaborationActor(t)
	f.prepare()
	// A terminal policy sorts before PREPARED. A short continuation page is
	// valid; only consuming all pages can establish the selected Node state.
	history := f.descriptions[0]
	history.Policy.PolicyID = strings.Repeat("1", 32)
	history.State = wire.LocalDomainExpired
	f.descriptions = append(f.descriptions, history)
	original := bytes.Clone(f.c.localDomain.reviewOriginal.Packet)
	review := f.c.Snapshot().LocalCollaboration.ReviewID
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, f.c.localDomain.reviewOriginal.Packet) || f.c.Snapshot().LocalCollaboration.ReviewID != review || !slices.Contains(f.c.Snapshot().AvailableActions, ActionActivateLocalCollaboration) {
		t.Fatal("status replacement cleared original prepare review")
	}
	f.reopen()
	if !bytes.Equal(original, f.c.localDomain.reviewOriginal.Packet) {
		t.Fatal("restart lost exact prepare packet")
	}
	// The account has to be independently logged in again; the cache itself
	// supplies neither a session nor authorization to activate.
	f.c.session = &wire.SessionContext{Origin: f.n.scope.Origin, HubID: f.n.scope.HubID, AccountID: f.n.scope.AccountID, OwnerID: f.n.scope.OwnerID, DeviceID: f.n.scope.DeviceID, DeviceKeyID: f.c.state.DeviceKeyID, SessionToken: bytes.Clone(f.n.token), AccountEpoch: f.n.scope.AccountEpoch, DeviceEpoch: f.n.scope.DeviceEpoch, ExpiresAt: f.n.scope.AccountSessionExpiresAt}
	f.c.sessionInspected, f.c.sessionNeedsCheck = true, false
	f.c.state.AccountState = AccountStateSessionActive
	f.c.nodeContextChecked = false
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}); err != nil {
		t.Fatal(err)
	}
	if f.c.Snapshot().LocalCollaboration.ReviewID != review {
		t.Fatal("fresh status selected terminal history instead of matching preparation")
	}
	f.activate()
}

func TestLocalCollaborationUnsignedRefusalAndLostRecoveryKeepOriginalPackets(t *testing.T) {
	for _, mode := range []string{"unsigned", "lost"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalCollaborationActor(t)
			if mode == "unsigned" {
				f.deny = wire.OperationLocalDomainPrepare
			} else {
				f.drop = wire.OperationLocalDomainPrepare
			}
			a := Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: "Synthetic private Network", GroupName: "Synthetic local Group"}}
			if f.c.Dispatch(context.Background(), a) == nil || !f.c.Snapshot().LocalCollaboration.Pending {
				t.Fatal("uncertain request discarded")
			}
			original := bytes.Clone(f.c.localDomain.original.Packet)
			f.reopen()
			if !bytes.Equal(original, f.c.localDomain.original.Packet) || !f.c.Snapshot().LocalCollaboration.Pending {
				t.Fatal("restart replaced original")
			}
			f.deny = ""
			f.drop = wire.OperationLocalDomainReconcile
			if f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverLocalCollaboration}) == nil {
				t.Fatal("synthetic lost recovery response reported complete")
			}
			recovery := bytes.Clone(f.c.localDomain.recovery.Packet)
			f.reopen()
			if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverLocalCollaboration}); err != nil {
				t.Fatal(err)
			}
			if f.c.Snapshot().LocalCollaboration.Pending || len(f.posts[wire.OperationLocalDomainPrepare]) != 1 || !bytes.Equal(recovery, f.posts[wire.OperationLocalDomainReconcile][1]) {
				t.Fatal("recovery regenerated uncertain request")
			}
			if mode == "unsigned" && f.c.Snapshot().LocalCollaboration.State == wire.LocalDomainPrepared {
				t.Fatal("unsigned refusal became success")
			}
		})
	}
}

func TestLocalCollaborationPublicAvailabilityNeverAuthorizesSigning(t *testing.T) {
	for _, mode := range []string{"false", "404", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalCollaborationActor(t)
			f.posts = map[string][][]byte{}
			f.c.localDomain.discoveryTried = false
			switch mode {
			case "false":
				f.available = false
			case "404":
				f.capStatus = 404
			case "malformed":
				f.malformed = true
			}
			_ = f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration})
			if f.c.Dispatch(context.Background(), Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: "Synthetic", GroupName: "Synthetic"}}) == nil || len(f.posts) != 0 || f.c.Snapshot().LocalCollaboration.Available {
				t.Fatal("unavailable Hub allowed Owner request")
			}
			f.available, f.capStatus, f.malformed = true, 200, false
			if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}); err != nil {
				t.Fatal("explicit refresh did not rediscover recovered Hub", err)
			}
			if !slices.Contains(f.c.Snapshot().AvailableActions, ActionPrepareLocalCollaboration) || len(f.posts[wire.OperationLocalDomainStatus]) != 1 || len(f.posts[wire.OperationLocalDomainPrepare]) != 0 {
				t.Fatal("rediscovery did not require authenticated read before setup")
			}
		})
	}
}
