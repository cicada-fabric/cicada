package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localDomainFixture struct {
	f         appNodeCryptoFixture
	node      *e2ee.Identity
	target    e2ee.LocalDomainTarget
	prepare   LocalDomainPrepare
	original  []byte
	challenge LocalDomainChallenge
}

func TestLocalDomainNodePacketProfileBoundsAreIndependent(t *testing.T) {
	for _, test := range []struct {
		name, operation, direction string
		limit                      int
	}{
		{"original", OperationLocalDomainNodeKeyComplete, nodewire.DirectionRequest, MaxLocalDomainNodeOriginalBytes},
		{"receipt", OperationLocalDomainNodeKeyComplete, nodewire.DirectionResponse, MaxLocalDomainNodeReceiptBytes},
		{"reconciliation", OperationLocalDomainNodeReconcile, nodewire.DirectionResponse, MaxLocalDomainNodeReconcilePacketBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := nodewire.Packet{Route: nodewire.Route{Operation: test.operation, Direction: test.direction}, Envelope: json.RawMessage(`"SYNTHETIC"`)}
			base, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			// Envelope is a byte slice, so packet JSON base64-encodes it. Use
			// the closest representable size below the cap, then add one block.
			p.Envelope = bytes.Repeat([]byte("S"), (test.limit-len(base)+16)/4*3)
			raw, err := json.Marshal(p)
			if err != nil || len(raw) > test.limit || test.limit-len(raw) > 3 {
				t.Fatal("incorrect size fixture", err, len(raw))
			}
			if _, err := DecodeLocalDomainNodePacket(raw); err != nil {
				t.Fatal("exact profile boundary rejected", err)
			}
			p.Envelope = append(p.Envelope, 'S', 'S', 'S')
			raw, err = json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeLocalDomainNodePacket(raw); err == nil {
				t.Fatal("profile accepted packet above its bound")
			}
		})
	}
}

func localDomainCrypto(t *testing.T) localDomainFixture {
	return localDomainSizedCrypto(t, false)
}

func localDomainSizedCrypto(t *testing.T, maximum bool) localDomainFixture {
	t.Helper()
	pair := nativePairSizedFixture(t, maximum)
	if maximum {
		pair.f.session = AppNodeSession{Hub: pair.f.hub, Origin: pair.f.scope.Origin, AccountID: pair.f.scope.AccountID, OwnerID: pair.f.scope.OwnerID, DeviceID: pair.f.scope.DeviceID, AccountEpoch: pair.f.scope.AccountEpoch, DeviceEpoch: pair.f.scope.DeviceEpoch, Token: pair.f.session.Token}
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	target := e2ee.LocalDomainTarget{Node: pair.scope.Node, NewNetworkName: "Synthetic private local Network", GroupName: "Synthetic local Group"}
	if maximum {
		target.NewNetworkName = strings.Repeat("<", 128)
		target.GroupName = strings.Repeat("<", 128)
	}
	target.Node.NodePublic = node.Public()
	target.Node.NodeKeyFingerprint = nodewire.IdentityFingerprint(node.Public())
	f := localDomainFixture{f: pair.f, node: node, target: target}
	f.prepare, err = NewLocalDomainPrepare(f.f.session, f.f.scope, target, f.f.owner, f.f.now)
	if err != nil {
		t.Fatal("prepare", err)
	}
	f.original, err = SealClientRequest(f.f.device, f.f.hub, f.prepare)
	if err != nil {
		t.Fatal("seal prepare", err)
	}
	r := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: f.f.hub.HubID, OwnerID: f.f.scope.OwnerID, NodeID: target.Node.NodeID, OwnerBindingID: target.Node.OwnerBindingID, NodeKeyEpoch: target.Node.NodeKeyEpoch, LocalUserScope: "uid:1000", IssuedAt: formatUTC(f.f.now), ExpiresAt: formatUTC(f.f.now.Add(5 * time.Minute)), Nonce: strings.Repeat("a", 64)}
	report, err := e2ee.SignLocalDomainUserReport(node, r)
	if err != nil {
		t.Fatal(err)
	}
	preparedAt := f.f.now.Add(time.Second)
	policy := e2ee.LocalDomainPolicy{Version: 1, PolicyID: strings.Repeat("1", 32), Epoch: 1, Origin: f.f.scope.Origin, HubID: f.f.hub.HubID, HubFingerprint: f.f.scope.HubFingerprint, OwnerID: f.f.scope.OwnerID, OwnerPublic: f.f.owner.Public(), OwnerKeyVersion: f.f.scope.OwnerKeyVersion, Node: target.Node, NodeControlBindingVersion: 1, CredentialCommitment: strings.Repeat("b", 64), LocalUserScope: "uid:1000", NetworkID: "synthetic-domain-network", NetworkName: target.NewNetworkName, CreateNetwork: true, GroupID: "synthetic-domain-group", GroupName: target.GroupName, Rights: e2ee.LocalDomainRights(), IssuedAt: formatUTC(preparedAt), PrepareRequestID: f.prepare.Context.RequestID, PreparePacketDigest: LocalDomainPacketDigest(f.original), ServerNonce: strings.Repeat("c", 64)}
	if maximum {
		policy.NetworkID = strings.Repeat("n", 128)
		policy.GroupID = strings.Repeat("g", 128)
		policy.Epoch = 1<<63 - 2
		policy.NodeControlBindingVersion = 1<<63 - 2
	}
	f.challenge = LocalDomainChallenge{Format: LocalDomainFormat, RequestID: f.prepare.Context.RequestID, RequestPacketDigest: LocalDomainPacketDigest(f.original), PrepareProofDigest: LocalDomainProofDigest(f.prepare.OwnerProof), LocalUserReport: report, Policy: policy, Revision: 1, ProofExpiresAt: formatUTC(f.f.now.Add(5 * time.Minute)), ObservedAt: formatUTC(preparedAt)}
	return f
}

func localDomainRequestRoundTrip(t *testing.T, f localDomainFixture, body, out any) []byte {
	t.Helper()
	raw, err := SealClientRequest(f.f.device, f.f.hub, body)
	if err != nil {
		t.Fatal("seal request", err)
	}
	b, r, err := NewClientRoute(f.f.hub, body, f.f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := f.f.device.Public()
	if err = OpenRequestAt(f.f.hubPrivate, &pub, b, r, raw, out, f.f.now.Add(2*time.Second)); err != nil {
		t.Fatal("open request", err)
	}
	if !reflect.DeepEqual(dereference(body), dereference(out)) {
		t.Fatal("request changed across PQ envelope")
	}
	return raw
}

func TestLocalDomainOwnerChallengeAcceptsOnlyExactBindingWithEmptyReportOwnerHint(t *testing.T) {
	f := localDomainCrypto(t)
	var original e2ee.LocalDomainUserReportProof
	if json.Unmarshal(f.challenge.LocalUserReport, &original) != nil {
		t.Fatal("synthetic report")
	}
	good := original.Report
	good.OwnerID = ""
	for name, change := range map[string]func(*e2ee.LocalDomainUserReport){"empty-correct": func(*e2ee.LocalDomainUserReport) {}, "wrong-owner": func(r *e2ee.LocalDomainUserReport) { r.OwnerID = "synthetic-other-owner" }, "wrong-binding": func(r *e2ee.LocalDomainUserReport) { r.OwnerBindingID += "-other" }, "wrong-node": func(r *e2ee.LocalDomainUserReport) { r.NodeID += "-other" }, "wrong-epoch": func(r *e2ee.LocalDomainUserReport) { r.NodeKeyEpoch++ }} {
		t.Run(name, func(t *testing.T) {
			r := good
			change(&r)
			raw, err := e2ee.SignLocalDomainUserReport(f.node, r)
			if err != nil {
				t.Fatal(err)
			}
			ch := f.challenge
			ch.LocalUserReport = raw
			err = ValidateLocalDomainChallenge(f.prepare, f.original, ch, f.f.hub, f.f.now.Add(2*time.Second))
			if (name == "empty-correct") != (err == nil) {
				t.Fatal("Owner challenge confused report hint with exact Node binding", err)
			}
		})
	}
}

func TestLocalDomainOwnerConstructorsAndActualPQEnvelope(t *testing.T) {
	f := localDomainCrypto(t)
	var prepare LocalDomainPrepare
	raw := localDomainRequestRoundTrip(t, f, f.prepare, &prepare)
	// Use the original packet: encryption randomness changes the packet digest.
	if LocalDomainPacketDigest(raw) == LocalDomainPacketDigest(f.original) {
		t.Fatal("fixture expected a fresh encryption")
	}
	_, route, _ := NewClientRoute(f.f.hub, f.prepare, f.f.device.Public())
	sealed, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, f.challenge)
	if err != nil {
		t.Fatal("seal challenge", err)
	}
	var challenge LocalDomainChallenge
	if err = OpenLocalDomainResponse(f.f.device, f.f.hub, f.original, sealed, &challenge); err != nil {
		t.Fatal("open challenge", err)
	}
	activate, err := NewLocalDomainActivate(f.f.session, f.f.scope, f.prepare, f.original, challenge, f.f.owner, f.f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal("activate", err)
	}
	var opened LocalDomainActivate
	activationPacket := localDomainRequestRoundTrip(t, f, activate, &opened)
	policy, err := e2ee.VerifyOwnerLocalDomainPolicy(f.f.owner.Public(), opened.PolicyProof, f.f.now.AddDate(5, 0, 0))
	if err != nil || policy.ExpiresAt != "" {
		t.Fatal("policy unexpectedly depended on the account session", err)
	}
	if _, err = e2ee.VerifyOwnerLocalDomainRequest(f.f.owner.Public(), opened.OwnerProof, e2ee.OwnerLocalDomainActivatePurpose, f.f.now.Add(time.Hour)); err == nil {
		t.Fatal("activation request proof did not expire")
	}
	description := LocalDomainDescription{ContractRevision: LocalDomainContractRevision, Policy: policy, PolicyProof: activate.PolicyProof, State: LocalDomainActive, Revision: 2, ObservedAt: formatUTC(f.f.now.Add(2 * time.Second))}
	result := LocalDomainResult{Format: LocalDomainFormat, Operation: OperationLocalDomainActivate, RequestID: activate.Context.RequestID, RequestPacketDigest: LocalDomainPacketDigest(activationPacket), HubID: f.f.hub.HubID, OwnerID: f.f.scope.OwnerID, DeviceID: f.f.scope.DeviceID, PolicyID: policy.PolicyID, PolicyEpoch: policy.Epoch, State: AppNodeCompleted, Description: &description, ObservedAt: description.ObservedAt}
	_, route, _ = NewClientRoute(f.f.hub, activate, f.f.device.Public())
	receipt, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, result)
	if err != nil {
		t.Fatal("seal result", err)
	}
	var recovered LocalDomainResult
	if OpenLocalDomainResponse(f.f.device, f.f.hub, activationPacket, receipt, &recovered) != nil {
		t.Fatal("activation result failed pinned response verification")
	}
	if ValidateLocalDomainResultTarget(activate, activationPacket, recovered, f.f.hub) != nil {
		t.Fatal("activation result target mismatch")
	}
	status, err := NewLocalDomainStatus(f.f.session, f.f.scope, policy.PolicyID, f.f.owner, f.f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	localDomainRequestRoundTrip(t, f, status, &LocalDomainStatusRequest{})
	revoke, err := NewLocalDomainRevoke(f.f.session, f.f.scope, description, f.f.owner, f.f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	localDomainRequestRoundTrip(t, f, revoke, &LocalDomainRevoke{})
	reconcile, err := NewLocalDomainReconcile(f.f.session, activationPacket, f.f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	reconcilePacket := localDomainRequestRoundTrip(t, f, reconcile, &LocalDomainReconcileRequest{})
	_, route, _ = NewClientRoute(f.f.hub, reconcile, f.f.device.Public())
	rr := LocalDomainReconciled{Format: LocalDomainFormat, RequestID: reconcile.Context.RequestID, RequestPacketDigest: LocalDomainPacketDigest(reconcilePacket), HubID: policy.HubID, OwnerID: policy.OwnerID, DeviceID: f.f.scope.DeviceID, OriginalOperation: OperationLocalDomainActivate, OriginalRequestID: activate.Context.RequestID, OriginalPacketDigest: LocalDomainPacketDigest(activationPacket), State: AppNodeCompleted, ReceiptPacket: receipt, ObservedAt: description.ObservedAt}
	response, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, rr)
	if err != nil {
		t.Fatal("seal reconcile", err)
	}
	var out LocalDomainReconciled
	if OpenLocalDomainResponse(f.f.device, f.f.hub, reconcilePacket, response, &out) != nil || !bytes.Equal(out.ReceiptPacket, receipt) {
		t.Fatal("exact receipt recovery changed the original receipt")
	}
}

func TestLocalDomainMaximumPQPageAndRecoveryBudgets(t *testing.T) {
	f := localDomainSizedCrypto(t, true)
	activate, err := NewLocalDomainActivate(f.f.session, f.f.scope, f.prepare, f.original, f.challenge, f.f.owner, f.f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal("maximum legal activation", err)
	}
	activationPacket := localDomainRequestRoundTrip(t, f, activate, &LocalDomainActivate{})
	status, err := NewLocalDomainStatusForNode(f.f.session, f.f.scope, f.target.Node.NodeID, "", f.f.owner, f.f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	statusPacket := localDomainRequestRoundTrip(t, f, status, &LocalDomainStatusRequest{})
	base := LocalDomainResult{Format: LocalDomainFormat, Operation: OperationLocalDomainStatus, RequestID: status.Context.RequestID, RequestPacketDigest: LocalDomainPacketDigest(statusPacket), HubID: f.f.hub.HubID, OwnerID: f.f.scope.OwnerID, DeviceID: f.f.scope.DeviceID, State: AppNodeCompleted, NodeID: f.target.Node.NodeID, ObservedAt: formatUTC(f.f.now.Add(2 * time.Second))}
	var candidates []LocalDomainDescription
	for i := 1; i <= 6; i++ {
		p := f.challenge.Policy
		p.PolicyID = fmt.Sprintf("%032x", i)
		proof, err := e2ee.SignOwnerLocalDomainPolicy(f.f.owner, p)
		if err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, LocalDomainDescription{ContractRevision: LocalDomainContractRevision, Policy: p, PolicyProof: proof, State: LocalDomainActive, Revision: 2, ObservedAt: base.ObservedAt})
	}
	page, err := BuildLocalDomainStatusPage(base, candidates, false)
	if err != nil {
		t.Fatal("actual PQ page", err)
	}
	pageJSON, _ := json.Marshal(page)
	if len(page.Policies) == 0 || len(page.Policies) >= len(candidates) || len(pageJSON) > MaxLocalDomainPageBytes || page.NextCursor != page.Policies[len(page.Policies)-1].Policy.PolicyID {
		t.Fatal("byte-bounded page skipped or hid rows")
	}
	_, route, _ := NewClientRoute(f.f.hub, status, f.f.device.Public())
	receipt, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, page)
	if err != nil {
		t.Fatal("seal maximum actual PQ page", err)
	}
	var opened LocalDomainResult
	if OpenLocalDomainResponse(f.f.device, f.f.hub, statusPacket, receipt, &opened) != nil || ValidateLocalDomainResultTarget(status, statusPacket, opened, f.f.hub) != nil {
		t.Fatal("actual page did not survive authenticated round trip")
	}
	remaining := candidates[len(page.Policies):]
	next, err := BuildLocalDomainStatusPage(base, remaining, false)
	if err != nil || len(next.Policies) == 0 || next.Policies[0].Policy.PolicyID <= page.NextCursor {
		t.Fatal("page cursor did not preserve the first unreturned policy", err)
	}
	one, err := BuildLocalDomainStatusPage(base, candidates[:1], false)
	if err != nil {
		t.Fatal(err)
	}
	one.NextCursor = candidates[0].Policy.PolicyID
	oneJSON, _ := json.Marshal(one)
	if _, err = buildLocalDomainStatusPage(base, candidates[:1], true, len(oneJSON)-1); err == nil {
		t.Fatal("single oversized PQ row was silently omitted")
	}
	if len(page.Policies) > 1 {
		changed := page
		changed.NodeID = "synthetic-other-node"
		if ValidateLocalDomainResultTarget(status, statusPacket, changed, f.f.hub) == nil {
			t.Fatal("restored Node page was substituted")
		}
	}
	// Both the largest legal mutation fixture and a real full PQ page receipt
	// are nested as exact packets, rather than represented by invented sizes.
	for _, original := range [][]byte{activationPacket, statusPacket} {
		q, err := NewLocalDomainReconcile(f.f.session, original, f.f.now.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		packet := localDomainRequestRoundTrip(t, f, q, &LocalDomainReconcileRequest{})
		_, rr, _ := NewClientRoute(f.f.hub, q, f.f.device.Public())
		// The page receipt corresponds to status; use its exact request here.
		if !bytes.Equal(original, statusPacket) {
			continue
		}
		body := LocalDomainReconciled{Format: LocalDomainFormat, RequestID: q.Context.RequestID, RequestPacketDigest: LocalDomainPacketDigest(packet), HubID: base.HubID, OwnerID: base.OwnerID, DeviceID: base.DeviceID, OriginalOperation: OperationLocalDomainStatus, OriginalRequestID: status.Context.RequestID, OriginalPacketDigest: LocalDomainPacketDigest(statusPacket), State: AppNodeCompleted, ReceiptPacket: receipt, ObservedAt: base.ObservedAt}
		response, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), rr, body)
		if err != nil {
			t.Fatal("nested full PQ page receipt", err)
		}
		var out LocalDomainReconciled
		if OpenLocalDomainResponse(f.f.device, f.f.hub, packet, response, &out) != nil || !bytes.Equal(out.ReceiptPacket, receipt) {
			t.Fatal("nested receipt changed")
		}
		t.Logf("canonical page bytes=%d rows=%d sealed page=%d activation original=%d reconcile request=%d response=%d", len(pageJSON), len(page.Policies), len(receipt), len(activationPacket), len(packet), len(response))
	}
	if MaxLocalDomainReconcileBodyBytes != clientwire.LocalDomainReconcileBodyBytes || MaxLocalDomainReconcileInnerPacketBytes != clientwire.LocalDomainReconcilePacketBytes {
		t.Fatal("profile/crypto frame budgets diverged")
	}
}

func TestLocalDomainPreviewCannotSubstituteAuthorityOrExpiredReport(t *testing.T) {
	f := localDomainCrypto(t)
	for _, tc := range []struct {
		name   string
		change func(*LocalDomainChallenge)
	}{
		{"node", func(c *LocalDomainChallenge) { c.Policy.Node.NodeID = "synthetic-other-node" }},
		{"user", func(c *LocalDomainChallenge) { c.Policy.LocalUserScope = "uid:1001" }},
		{"network", func(c *LocalDomainChallenge) { c.Policy.NetworkName = "Different Network" }},
		{"group", func(c *LocalDomainChallenge) { c.Policy.GroupName = "Different Group" }},
		{"prepare", func(c *LocalDomainChallenge) { c.RequestPacketDigest = strings.Repeat("f", 64) }},
		{"report", func(c *LocalDomainChallenge) { c.LocalUserReport = nil }},
		{"rights", func(c *LocalDomainChallenge) { c.Policy.Rights = append(c.Policy.Rights, "ROOT") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(f.challenge)
			var changed LocalDomainChallenge
			_ = json.Unmarshal(data, &changed)
			tc.change(&changed)
			if _, err := NewLocalDomainActivate(f.f.session, f.f.scope, f.prepare, f.original, changed, f.f.owner, f.f.now.Add(2*time.Second)); err == nil {
				t.Fatal("substituted preview was signed")
			}
		})
	}
	if _, err := NewLocalDomainActivate(f.f.session, f.f.scope, f.prepare, f.original, f.challenge, f.f.owner, f.f.now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired preview/report was signed")
	}
	if _, err := NewLocalDomainPrepare(f.f.session, f.f.scope, e2ee.LocalDomainTarget{Node: f.target.Node, NetworkID: "synthetic-existing", NewNetworkName: "also create", GroupName: f.target.GroupName}, f.f.owner, f.f.now); err == nil {
		t.Fatal("ambiguous Network choice was accepted")
	}
	if _, err := NewLocalDomainPrepare(f.f.session, f.f.scope, f.target, f.node, f.f.now); err == nil {
		t.Fatal("Node key acted as Owner")
	}
	if _, err := DecodeNativePairPacket(f.original); err == nil {
		t.Fatal("domain request entered Pair profile")
	}
	badRoute := clientwire.Route{Operation: OperationNativePairStatus}
	if validateLocalDomainResponse(f.challenge, badRoute) == nil {
		t.Fatal("domain response accepted on Pair route")
	}
}

func TestLocalDomainSignedChallengeCannotExtendOriginalPrepareIntent(t *testing.T) {
	f := localDomainCrypto(t)
	var report e2ee.LocalDomainUserReportProof
	if json.Unmarshal(f.challenge.LocalUserReport, &report) != nil {
		t.Fatal("report fixture")
	}
	report.Report.IssuedAt = formatUTC(f.f.now.Add(time.Minute))
	report.Report.ExpiresAt = formatUTC(f.f.now.Add(6 * time.Minute))
	proof, err := e2ee.SignLocalDomainUserReport(f.node, report.Report)
	if err != nil {
		t.Fatal(err)
	}
	challenge := f.challenge
	challenge.LocalUserReport = proof
	challenge.ObservedAt = formatUTC(f.f.now.Add(61 * time.Second))
	challenge.Policy.IssuedAt = challenge.ObservedAt
	challenge.ProofExpiresAt = formatUTC(f.f.now.Add(5*time.Minute + time.Second))
	_, route, _ := NewClientRoute(f.f.hub, f.prepare, f.f.device.Public())
	packet, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, challenge)
	if err != nil {
		t.Fatal("Hub-signed response", err)
	}
	var opened LocalDomainChallenge
	if OpenLocalDomainResponse(f.f.device, f.f.hub, f.original, packet, &opened) != nil {
		t.Fatal("valid PQ response fixture")
	}
	if _, err = NewLocalDomainActivate(f.f.session, f.f.scope, f.prepare, f.original, opened, f.f.owner, f.f.now.Add(62*time.Second)); err == nil {
		t.Fatal("Hub extended the original Owner prepare intent despite a later valid report/session")
	}
}

func TestLocalDomainPrepareNoEffectFenceHasExactRecoverableTarget(t *testing.T) {
	f := localDomainCrypto(t)
	result := LocalDomainResult{Format: LocalDomainFormat, Operation: OperationLocalDomainPrepare, RequestID: f.prepare.Context.RequestID, RequestPacketDigest: LocalDomainPacketDigest(f.original), HubID: f.f.hub.HubID, OwnerID: f.f.scope.OwnerID, DeviceID: f.f.scope.DeviceID, State: AppNodeRejectedFenced, NoEffect: true, ErrorCode: "NODE_REPORT_REQUIRED", ObservedAt: formatUTC(f.f.now)}
	_, route, _ := NewClientRoute(f.f.hub, f.prepare, f.f.device.Public())
	packet, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, result)
	if err != nil {
		t.Fatal(err)
	}
	var opened LocalDomainResult
	if OpenLocalDomainResponse(f.f.device, f.f.hub, f.original, packet, &opened) != nil || ValidateLocalDomainResultTarget(f.prepare, f.original, opened, f.f.hub) != nil {
		t.Fatal("authenticated no-effect prepare fence could not settle its original pending operation")
	}
	opened.NoEffect = false
	if ValidateLocalDomainResultTarget(f.prepare, f.original, opened, f.f.hub) == nil {
		t.Fatal("prepare result acquired business effect")
	}
	opened = result
	opened.RequestPacketDigest = strings.Repeat("f", 64)
	if ValidateLocalDomainResultTarget(f.prepare, f.original, opened, f.f.hub) == nil {
		t.Fatal("prepare fence settled a different original packet")
	}
	for _, operation := range []string{OperationLocalDomainActivate, OperationLocalDomainRevoke} {
		opened = result
		opened.Operation = operation
		if ValidateLocalDomainResultTarget(f.prepare, f.original, opened, f.f.hub) == nil {
			t.Fatal("prepare fence was reused for another Owner purpose")
		}
	}
}

func TestLocalDomainCapabilitiesAndNodeUserReportCodec(t *testing.T) {
	f := localDomainCrypto(t)
	c := LocalDomainCapabilities{Format: LocalDomainFormat, ContractRevision: LocalDomainContractRevision, Available: false, ServeMode: "--hub-nodes-only", TransportPolicy: AppNodeTransportHTTPS, HTTPOperations: LocalDomainHTTPOperations(), NodeOperations: LocalDomainNodeOperations(), Rights: e2ee.LocalDomainRights(), MaxActivePoliciesPerNodeUser: 1, OptionalPolicyExpiry: true}
	raw, _ := json.Marshal(c)
	if _, err := DecodeLocalDomainCapabilities(raw); err != nil {
		t.Fatal("availability=false must parse without granting authority", err)
	}
	c.Rights = append(c.Rights, "NETWORK_ADMIN")
	raw, _ = json.Marshal(c)
	if _, err := DecodeLocalDomainCapabilities(raw); err == nil {
		t.Fatal("capability widened fixed rights")
	}
	q := LocalDomainNodeAvailable{ContractRevision: LocalDomainContractRevision, LocalUserScope: "uid:1000", LocalUserReport: f.challenge.LocalUserReport}
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeAvailable, q); err != nil {
		t.Fatal(err)
	}
	q.LocalUserScope = "uid:1001"
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeAvailable, q); err == nil {
		t.Fatal("report/user mismatch accepted")
	}
	selection, err := LocalDomainSelectionForPolicy(f.challenge.Policy)
	if err != nil {
		t.Fatal(err)
	}
	join := LocalDomainNodeJoin{ContractRevision: LocalDomainContractRevision, Selection: selection, LocalUserScope: "uid:1000", AttemptID: strings.Repeat("d", 32), Runtime: "codex", NativeSessionID: "synthetic-domain-thread", Workspace: "/synthetic/workspace", EndpointName: "Synthetic local Thread"}
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeJoin, join); err != nil {
		t.Fatal(err)
	}
	join.Selection.PolicyDigest = ""
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeJoin, join); err == nil {
		t.Fatal("unselected domain join accepted")
	}
	prepare := LocalDomainNodeKeyPrepare{ContractRevision: LocalDomainContractRevision, Selection: selection, MemberID: "synthetic-member", ExpectedRevision: 1}
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeKeyPrepare, prepare); err != nil {
		t.Fatal("explicit key preparation", err)
	}
	claims := e2ee.LocalDomainEndpointKeyClaims{Version: 1, Purpose: e2ee.LocalDomainEndpointKeyPurpose, PolicyID: selection.PolicyID, PolicyEpoch: selection.PolicyEpoch, PolicyDigest: selection.PolicyDigest, MemberID: prepare.MemberID, MemberRevision: 2, MemberDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("e", 64), CandidateBindingDigest: strings.Repeat("f", 64), IssuedAt: f.challenge.Policy.IssuedAt}
	proof, err := e2ee.SignLocalDomainEndpointKey(f.node, f.challenge.Policy, claims)
	if err != nil {
		t.Fatal(err)
	}
	complete := LocalDomainNodeKeyComplete{ContractRevision: LocalDomainContractRevision, Selection: selection, ChallengeID: strings.Repeat("a", 32), MemberID: prepare.MemberID, ExpectedRevision: 1, NodeProof: proof}
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeKeyComplete, complete); err != nil {
		t.Fatal("projected member revision", err)
	}
	complete.ExpectedRevision = 2
	if _, err := CanonicalLocalDomainNodeRequest(OperationLocalDomainNodeKeyComplete, complete); err == nil {
		t.Fatal("unrelated current revision accepted a projected proof")
	}
}
