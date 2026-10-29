package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// These fixtures are disposable synthetic identities. JSON adaptation below
// is test setup only; production has no grant/namespace conversion operation.
func scopedFixtureValue[T any](t *testing.T, source any, edits map[string]any) T {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for k, v := range edits {
		fields[k] = v
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func scopedScopeFixture(t *testing.T, scope e2ee.OwnerAppNodeScope, nodeID string) e2ee.OwnerAppNodeScopedScope {
	return scopedFixtureValue[e2ee.OwnerAppNodeScopedScope](t, scope, map[string]any{"version": 2, "authority_node_id": nodeID})
}

func scopedPreparedFixture(t *testing.T) (appNodeCryptoFixture, AppNodeScopedPrepare, []byte, AppNodeScopedChallenge) {
	t.Helper()
	f := appNodeCrypto(t)
	scope := scopedScopeFixture(t, f.scope, f.claims.Candidate.NodeID)
	p, err := NewAppNodeScopedPrepare(f.session, scope, AppNodeScopedPrepareTarget{Kind: AppNodeScopedTargetInitial, Code: "2345-6789-ABCD"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealClientRequest(f.device, f.hub, p)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, p, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened AppNodeScopedPrepare
	pub := f.device.Public()
	if err := OpenRequestAt(f.hubPrivate, &pub, b, r, raw, &opened, f.now); err != nil || !reflect.DeepEqual(opened, p) {
		t.Fatal("scoped request round trip", err)
	}
	intent, err := e2ee.VerifyOwnerAppNodeScopedPreview(f.owner.Public(), p.OwnerIntent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope.HeadVersion++
	c := scopedFixtureValue[e2ee.OwnerAppNodeScopedGrantClaims](t, f.claims, map[string]any{
		"purpose": e2ee.OwnerAppNodeScopedGrantPurpose, "scope": scope, "grant_id": intent.GrantID,
		"prepare_request_id": p.Context.RequestID, "prepare_packet_digest": AppNodeScopedPacketDigest(raw), "preview_proof_digest": AppNodeScopedProofDigest(p.OwnerIntent),
	})
	ch := AppNodeScopedChallenge{Format: AppNodeScopedChallengeFormat, RequestID: p.Context.RequestID, RequestPacketDigest: AppNodeScopedPacketDigest(raw), Claims: c, ObservedAt: formatUTC(f.now)}
	response, err := SealResponse(f.hubPrivate, pub, r, ch)
	if err != nil {
		t.Fatal(err)
	}
	var result AppNodeScopedChallenge
	if err := OpenClientResponse(f.device, f.hub, raw, response, &result); err != nil || !reflect.DeepEqual(result, ch) {
		t.Fatal("scoped challenge round trip", err)
	}
	return f, p, raw, result
}

func TestAppNodeScopedProofAndEncryptedRoundTrip(t *testing.T) {
	f, prepare, raw, ch := scopedPreparedFixture(t)
	complete, err := NewAppNodeScopedComplete(f.session, prepare, raw, ch, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e2ee.VerifyOwnerAppNodeScopedGrant(f.owner.Public(), complete.OwnerGrant, f.now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(grant, ch.Claims) {
		t.Fatal("exact scoped grant", err)
	}
	packet, err := SealClientRequest(f.device, f.hub, complete)
	if err != nil {
		t.Fatal(err)
	}
	b, r, _ := NewClientRoute(f.hub, complete, f.device.Public())
	var opened AppNodeScopedComplete
	pub := f.device.Public()
	if err := OpenRequestAt(f.hubPrivate, &pub, b, r, packet, &opened, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	confirm, err := SealAppNodeScopedConfirmation(f.device, f.hub, grant, "2345-6789-ABCD", 1, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	route, _, err := appNodeScopedOriginalRoute(AppNodeScopedOriginalClient, confirm)
	if err != nil || !strings.HasPrefix(route.OperationID, "n3s.") || route.Sequence != 1 {
		t.Fatal("scoped confirmation must retain global Client counter", err)
	}
	if _, _, err := appNodeOriginalRoute(AppNodeOriginalClient, confirm); err == nil {
		t.Fatal("legacy confirmation parser accepted scoped original")
	}
}

func TestAppNodeScopedRejectsNamespaceAndNodeSubstitution(t *testing.T) {
	f, prepare, _, ch := scopedPreparedFixture(t)
	if _, err := e2ee.VerifyOwnerAppNodePreview(f.owner.Public(), prepare.OwnerIntent, f.now); err == nil {
		t.Fatal("legacy parser accepted scope2")
	}
	var intent e2ee.OwnerAppNodeScopedPreview
	if decodeCanonical(prepare.OwnerIntent, MaxAppNodeScopedProofBytes, &intent) != nil {
		t.Fatal("fixture")
	}
	intent.Claims.Scope.AuthorityNodeID = "synthetic-other-node"
	raw, _ := json.Marshal(intent)
	if _, err := e2ee.VerifyOwnerAppNodeScopedPreview(f.owner.Public(), raw, f.now); err == nil {
		t.Fatal("signature did not bind authority Node")
	}
	for _, node := range []string{"", "control-local", "worker-local", "synthetic-other-node"} {
		x := ch.Claims
		x.Scope.AuthorityNodeID = node
		if ValidateAppNodeScopedGrantClaims(x, f.hub, f.now) == nil {
			t.Fatal("candidate borrowed another Node scope")
		}
		if _, err := e2ee.SignOwnerAppNodeScopedGrant(f.owner, x); err == nil {
			t.Fatal("proof signer accepted mismatched Node")
		}
	}
	x := ch.Claims
	x.Scope.Version = 1
	if _, err := e2ee.SignOwnerAppNodeScopedGrant(f.owner, x); err == nil {
		t.Fatal("proof signer accepted legacy scope")
	}
	// Even an empty new field cannot be smuggled into the frozen strict v1 DTO.
	old, err := NewAppNodePrepare(f.session, f.scope, AppNodePrepareTarget{Kind: AppNodeTargetInitial, Code: "23456789ABCD"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(old.OwnerIntent, &fields) != nil {
		t.Fatal("fixture")
	}
	fields["claims"].(map[string]any)["scope"].(map[string]any)["authority_node_id"] = ""
	raw, _ = json.Marshal(fields)
	if _, err := e2ee.VerifyOwnerAppNodePreview(f.owner.Public(), raw, f.now); err == nil {
		t.Fatal("v1 silently ignored a scope2 field")
	}
}

func TestAppNodeScopedStatusTargetAndOwnerActor(t *testing.T) {
	f, _, _, ch := scopedPreparedFixture(t)
	for _, target := range []AppNodeScopedStatusTarget{{}, {NodeID: ch.Claims.Scope.AuthorityNodeID, CandidateCode: "23456789ABCD"}, {NodeID: "control-local"}, {CandidateCode: "invalid"}} {
		if _, err := NewAppNodeScopedStatus(f.session, target, "", f.now); err == nil {
			t.Fatal("invalid XOR target accepted")
		}
	}
	for _, target := range []AppNodeScopedStatusTarget{{NodeID: ch.Claims.Scope.AuthorityNodeID}, {CandidateCode: "23456789ABCD"}} {
		status, err := NewAppNodeScopedStatus(f.session, target, "", f.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SealClientRequest(f.device, f.hub, status); err != nil {
			t.Fatal(err)
		}
	}
	noLogin := f.session
	noLogin.Token = nil
	if _, err := NewAppNodeScopedStatus(noLogin, AppNodeScopedStatusTarget{CandidateCode: "23456789ABCD"}, "", f.now); err == nil {
		t.Fatal("anonymous code resolution accepted")
	}
	a, err := AppNodeScopedOwnerActor(ch.Claims.Scope, f.hub)
	if err != nil || a.HeadVersion != 0 || !reflect.DeepEqual(a, f.scope) {
		t.Fatal("Owner actor identity changed", err)
	}
	// Projection alone is no Owner signature and cannot pass as a legacy grant.
	if _, err := e2ee.SignOwnerAppNodeGrant(f.owner, e2ee.OwnerAppNodeGrantClaims{Scope: a}); err == nil {
		t.Fatal("identity projection became a confirmation grant")
	}
}

func TestAppNodeScopedCapabilitiesAvailableAndStrict(t *testing.T) {
	c := AppNodeScopedContractCapabilities(AppNodeTransportHTTPS)
	n := NodePairTrustScopedContractCapabilities()
	if !c.Available || !n.Available {
		t.Fatal("qualified Hub Nodes carrier unavailable")
	}
	c.Available = false
	raw, _ := json.Marshal(c)
	if _, err := DecodeAppNodeScopedCapabilities(raw); err == nil {
		t.Fatal("consumer accepted unavailable carrier")
	}
	c.Available = true
	raw, _ = json.Marshal(c)
	if _, err := DecodeAppNodeScopedCapabilities(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"scope_version":2`), []byte(`"scope_version":1`), 1), bytes.Replace(raw, []byte(`"NODE_V1"`), []byte(`"LEGACY_V1"`), 1)} {
		if _, err := DecodeAppNodeScopedCapabilities(bad); err == nil {
			t.Fatal("capability scope downgrade accepted")
		}
	}
	n.Available = true
	raw, _ = json.Marshal(n)
	if _, err := DecodeNodePairTrustScopedCapabilities(raw); err != nil {
		t.Fatal(err)
	}
	n.Available = false
	raw, _ = json.Marshal(n)
	if _, err := DecodeNodePairTrustScopedCapabilities(raw); err == nil {
		t.Fatal("consumer accepted unavailable pairing carrier")
	}
	if AppNodeScopedPacketDigest([]byte("synthetic")) == AppNodePacketDigest([]byte("synthetic")) {
		t.Fatal("authority packet domains overlap")
	}
}

func TestAppNodeScopedCancelAndOriginalReconcileRemainExact(t *testing.T) {
	f, _, original, ch := scopedPreparedFixture(t)
	node := ch.Claims.Scope.AuthorityNodeID
	cancel, err := NewAppNodeScopedCancel(f.session, node, ch.Claims.GrantID, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealClientRequest(f.device, f.hub, cancel); err != nil {
		t.Fatal(err)
	}
	query, err := NewAppNodeScopedReconcile(f.session, node, AppNodeScopedOriginalAuthority, ch.Claims.GrantID, original, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealClientRequest(f.device, f.hub, query); err != nil {
		t.Fatal(err)
	}
	result := AppNodeScopedReconciled{AuthorityNodeID: node, OriginalKind: query.OriginalKind, OriginalOperation: OperationAppNodeScopedPrepare, OriginalRequestID: ch.RequestID, OriginalPacketDigest: AppNodeScopedPacketDigest(original), HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID}
	if ValidateAppNodeScopedReconcileTarget(result, node, query.OriginalKind, original) != nil {
		t.Fatal("exact original rejected")
	}
	if ValidateAppNodeScopedReconcileTarget(result, "synthetic-other-node", query.OriginalKind, original) == nil {
		t.Fatal("reconcile changed Node")
	}
	old, err := NewAppNodePrepare(f.session, f.scope, AppNodePrepareTarget{Kind: AppNodeTargetInitial, Code: "23456789ABCD"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := SealClientRequest(f.device, f.hub, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAppNodeScopedReconcile(f.session, node, AppNodeScopedOriginalAuthority, "", legacy, f.now); err == nil {
		t.Fatal("scoped recovery accepted legacy original")
	}
}
