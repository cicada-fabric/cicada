package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// These are contract/data-only tests. Their proof placeholder is deliberately
// not a cryptographic signature and never used with a server or deployment.
func appNodeDraftFixture(t *testing.T) (HubIdentity, e2ee.OwnerAppNodePreviewClaims, []byte, []byte, AppNodeChallenge, time.Time) {
	t.Helper()
	identities := make([]*e2ee.Identity, 5)
	for i := range identities {
		var err error
		identities[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: "synthetic-n3-hub", Public: identities[0].Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	fp, err := HubFingerprint(hub)
	if err != nil {
		t.Fatal(err)
	}
	scope := e2ee.OwnerAppNodeScope{Version: 1, Origin: "https://synthetic-n3.invalid", HubID: hub.HubID, HubFingerprint: fp,
		AccountID: "synthetic-account", AccountSessionID: "synthetic-session", AccountSessionExpiresAt: formatUTC(now.Add(14 * time.Minute)),
		OwnerID: "synthetic-owner", OwnerPublic: identities[1].Public(), OwnerKeyVersion: 1,
		DeviceID: AccountDeviceIDPrefix + strings.Repeat("a", 32), DevicePublic: identities[2].Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1,
		HeadVersion: 0, TransportPolicy: AppNodeTransportHTTPS}
	codeDigest, err := AppNodeCodeDigest(hub.HubID, "2345-6789-ABCD")
	if err != nil {
		t.Fatal(err)
	}
	intent := e2ee.OwnerAppNodePreviewClaims{Purpose: e2ee.OwnerAppNodePreviewPurpose, Scope: scope, GrantID: strings.Repeat("b", 32), CodeDigest: codeDigest,
		RequestID: strings.Repeat("c", 32), Nonce: strings.Repeat("d", 64), IssuedAt: formatUTC(now), ExpiresAt: formatUTC(now.Add(time.Minute))}
	proof, err := json.Marshal(e2ee.OwnerAppNodePreview{Claims: intent, Signature: []byte("synthetic-contract-placeholder-not-a-signature")})
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("synthetic-contract-original-not-a-network-packet")
	scope.HeadVersion = 1
	candidate := e2ee.OwnerAppNodeCandidate{RequestID: "nctrlreq_synthetic", Version: 1, Mode: "INITIAL", State: "PENDING", HubID: hub.HubID,
		NodeID: "synthetic-node", NodeName: "Synthetic relay Node", NodePublic: identities[3].Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(identities[3].Public()), NodeKeyEpoch: 1,
		HubNodeControlPublic: identities[4].Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: nodewire.IdentityFingerprint(identities[4].Public()),
		CandidateDigest: strings.Repeat("e", 64), CodeDigest: codeDigest, ExpiresAt: formatUTC(now.Add(10 * time.Minute))}
	claims := e2ee.OwnerAppNodeGrantClaims{Purpose: e2ee.OwnerAppNodeGrantPurpose, Scope: scope, GrantID: intent.GrantID, ExpectedHeadVersion: 0, Profile: AppNodeProfileInitial,
		PrepareRequestID: intent.RequestID, PreparePacketDigest: AppNodePacketDigest(original), PreviewProofDigest: AppNodeProofDigest(proof), ServerNonce: strings.Repeat("f", 64),
		Candidate: &candidate, AllowedOperations: AppNodeAllowedOperations(), ReadNodeStatus: true, ConfirmationLimit: 1,
		PreparedAt: formatUTC(now), ProofExpiresAt: formatUTC(now.Add(5 * time.Minute)), LeaseExpiresAt: formatUTC(now.Add(15 * time.Minute))}
	return hub, intent, proof, original, AppNodeChallenge{Format: AppNodeChallengeFormat, RequestID: intent.RequestID, RequestPacketDigest: AppNodePacketDigest(original), Claims: claims, ObservedAt: formatUTC(now)}, now
}

func TestAppNodeDraftManifestAndBounds(t *testing.T) {
	raw, err := os.ReadFile("app-node-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Revision    string                             `json:"contract_revision"`
		Lease       int                                `json:"runtime_lease_seconds"`
		Intent      int                                `json:"intent_max_seconds"`
		Proof       int                                `json:"proof_max_seconds"`
		MaxBody     int                                `json:"max_body_bytes"`
		MaxOriginal int                                `json:"max_original_bytes"`
		MaxMutation int                                `json:"max_mutation_packet_bytes"`
		MaxReceipt  int                                `json:"max_receipt_bytes"`
		MaxProof    int                                `json:"max_proof_bytes"`
		Allowed     []string                           `json:"allowed_operations"`
		ReadAllowed []string                           `json:"status_only_operations"`
		Operations  []struct{ Operation, Path string } `json:"operations"`
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Revision != AppNodeContractRevision || time.Duration(m.Lease)*time.Second != AppNodeLeaseLifetime || time.Duration(m.Intent)*time.Second != MaxAppNodeIntentLifetime || time.Duration(m.Proof)*time.Second != MaxAppNodeProofLifetime ||
		m.MaxBody != MaxAppNodeBodyBytes || m.MaxOriginal != MaxAppNodeOriginalBytes || m.MaxMutation != MaxAppNodeMutationPacketBytes || m.MaxReceipt != MaxAppNodeReceiptBytes || m.MaxProof != MaxAppNodeProofBytes ||
		!reflect.DeepEqual(m.Allowed, AppNodeAllowedOperations()) || !reflect.DeepEqual(m.ReadAllowed, AppNodeStatusAllowedOperations()) || len(m.Operations) != 5 {
		t.Fatal("draft manifest differs from typed contract")
	}
	for _, op := range m.Operations {
		if AppNodeHTTPPath(op.Operation) != op.Path {
			t.Fatal("endpoint mapping differs")
		}
	}
	if AppNodeHTTPPath("nodes.confirm") != "" {
		t.Fatal("catalog RPC confused with new HTTP operation")
	}
	if !AppNodeReconcileOriginalAllowed(AppNodeOriginalAuthority, OperationAppNodeStatus) || AppNodeReconcileOriginalAllowed(AppNodeOriginalAuthority, OperationAppNodeReconcile) || AppNodeReconcileOriginalAllowed(AppNodeOriginalClient, "session.capabilities") {
		t.Fatal("read settlement missing or unnecessary counter-consuming RPC admitted")
	}
	result := AppNodeReconcileResult{Format: AppNodeReconciledFormat, ReceiptPacket: make([]byte, MaxAppNodeReceiptBytes)}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxAppNodeBodyBytes || len(result.ReceiptPacket) <= 96*1024 {
		t.Fatal("legal nested receipt exceeds extension body budget")
	}
}

func TestAppNodeDraftExactPreviewAndConsent(t *testing.T) {
	hub, intent, proof, original, ch, now := appNodeDraftFixture(t)
	if err := ValidateAppNodePreviewClaims(intent, hub, now); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAppNodePreparedResponse(ch, intent, proof, original, hub, now); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*e2ee.OwnerAppNodeGrantClaims){
		"scope-epoch":          func(c *e2ee.OwnerAppNodeGrantClaims) { c.Scope.DeviceEpoch++ },
		"session-binding":      func(c *e2ee.OwnerAppNodeGrantClaims) { c.Scope.AccountSessionID = "other-session" },
		"wrong-head":           func(c *e2ee.OwnerAppNodeGrantClaims) { c.ExpectedHeadVersion++ },
		"missing-read-consent": func(c *e2ee.OwnerAppNodeGrantClaims) { c.ReadNodeStatus = false },
		"extra-rpc": func(c *e2ee.OwnerAppNodeGrantClaims) {
			c.AllowedOperations = append(c.AllowedOperations, "intent.submit")
		},
		"renewed-expiry":      func(c *e2ee.OwnerAppNodeGrantClaims) { c.LeaseExpiresAt = formatUTC(now.Add(16 * time.Minute)) },
		"extra-confirmation":  func(c *e2ee.OwnerAppNodeGrantClaims) { c.ConfirmationLimit = 2 },
		"wrong-preview-proof": func(c *e2ee.OwnerAppNodeGrantClaims) { c.PreviewProofDigest = strings.Repeat("0", 64) },
		"upgrade":             func(c *e2ee.OwnerAppNodeGrantClaims) { c.Candidate.Mode = "UPGRADE" },
		"wrong-node-key":      func(c *e2ee.OwnerAppNodeGrantClaims) { c.Candidate.NodeKeyFingerprint = strings.Repeat("0", 64) },
		"expired-candidate":   func(c *e2ee.OwnerAppNodeGrantClaims) { c.Candidate.ExpiresAt = formatUTC(now.Add(4 * time.Minute)) },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(ch)
			var altered AppNodeChallenge
			if err := json.Unmarshal(raw, &altered); err != nil {
				t.Fatal(err)
			}
			change(&altered.Claims)
			if ValidateAppNodePreparedResponse(altered, intent, proof, original, hub, now) == nil {
				t.Fatal("substituted consent accepted")
			}
		})
	}
	if ValidateAppNodePreparedResponse(ch, intent, proof, append(original, '!'), hub, now) == nil || ValidateAppNodePreparedResponse(ch, intent, proof, original, hub, now.Add(5*time.Minute)) == nil {
		t.Fatal("wrong packet or expired proof accepted")
	}
	if ValidateAppNodePreviewClaims(intent, hub, now.Add(time.Minute)) == nil {
		t.Fatal("expired preview intent accepted")
	}
}

func TestAppNodeDraftReadExistingCannotConfirm(t *testing.T) {
	hub, _, _, _, ch, now := appNodeDraftFixture(t)
	c := ch.Claims
	n := c.Candidate
	c.Purpose, c.Profile, c.PreviousGrantID = e2ee.OwnerAppNodeStatusGrantPurpose, AppNodeProfileStatus, strings.Repeat("1", 32)
	c.ConfirmationProvenanceID = c.PreviousGrantID
	c.Candidate, c.AllowedOperations, c.ConfirmationLimit = nil, AppNodeStatusAllowedOperations(), 0
	c.Binding = &e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-binding", OwnerID: c.Scope.OwnerID, HubID: c.Scope.HubID, NodeID: n.NodeID, NodeName: n.NodeName,
		ClientDeviceID: c.Scope.DeviceID, OwnerKeyID: c.Scope.OwnerPublic.ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint,
		NodeKeyVersion: 1, NodeKeyEpoch: 1, HubNodeControlPublic: n.HubNodeControlPublic, HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: 1,
		ApprovedRequestID: n.RequestID, ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: formatUTC(now.Add(-time.Minute)), State: "ACTIVE"}
	if err := ValidateAppNodeGrantClaims(c, hub, now); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	var altered e2ee.OwnerAppNodeGrantClaims
	_ = json.Unmarshal(raw, &altered)
	altered.AllowedOperations = AppNodeAllowedOperations()
	if ValidateAppNodeGrantClaims(altered, hub, now) == nil {
		t.Fatal("status-only authority granted confirm")
	}
	_ = json.Unmarshal(raw, &altered)
	altered.ConfirmationLimit = 1
	if ValidateAppNodeGrantClaims(altered, hub, now) == nil {
		t.Fatal("status-only confirmation budget accepted")
	}
	_ = json.Unmarshal(raw, &altered)
	altered.Candidate = n
	if ValidateAppNodeGrantClaims(altered, hub, now) == nil {
		t.Fatal("ambiguous initial/read-existing target accepted")
	}
}

func TestAppNodeDraftGrantInstanceAndCanonicalProof(t *testing.T) {
	grant := strings.Repeat("a", 32)
	nonce := strings.Repeat("b", 32)
	id, err := AppNodeBusinessOperationID(grant, nonce)
	if err != nil || len(id) > 128 {
		t.Fatal("instance binding does not fit old route")
	}
	g, n, err := ParseAppNodeBusinessOperationID(id)
	if err != nil || g != grant || n != nonce {
		t.Fatal("grant instance lost")
	}
	for _, bad := range []string{strings.ToUpper(id), id + ".extra", "n3." + grant, "old." + grant + "." + nonce} {
		if _, _, err := ParseAppNodeBusinessOperationID(bad); err == nil {
			t.Fatal("noncanonical instance accepted")
		}
	}
	_, _, proof, _, _, _ := appNodeDraftFixture(t)
	var out e2ee.OwnerAppNodePreview
	if decodeCanonical(append(proof, '\n'), MaxAppNodeProofBytes, &out) == nil {
		t.Fatal("noncanonical proof accepted")
	}
	unknown := bytes.Replace(proof, []byte(`"claims":{`), []byte(`"extra":true,"claims":{`), 1)
	if decodeCanonical(unknown, MaxAppNodeProofBytes, &out) == nil {
		t.Fatal("unknown proof field accepted")
	}
	a, err := AppNodeCodeDigest("synthetic-hub", "2345-6789-abcd")
	b, other := AppNodeCodeDigest("synthetic-hub", "23456789ABCD")
	if err != nil || other != nil || a != b {
		t.Fatal("old code normalization changed")
	}
	if _, err := NormalizeAppNodeCode("2345\t6789ABCD"); err == nil {
		t.Fatal("non-alphabet selector accepted")
	}
}
