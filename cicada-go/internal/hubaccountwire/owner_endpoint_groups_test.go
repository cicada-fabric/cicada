package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type endpointGroupsFixture struct {
	f        appNodeCryptoFixture
	prepare  OwnerEndpointGroupsPrepareRequest
	original []byte
	review   OwnerEndpointGroupsReview
}

func syntheticEndpointGroupsReview(t *testing.T, action string) endpointGroupsFixture {
	t.Helper()
	domain := localDomainCrypto(t)
	f := domain.f
	b := OwnerEndpointGroupsPrepareBody{Action: action, NodeID: domain.target.Node.NodeID, NetworkID: "synthetic-network"}
	if action == OwnerEndpointGroupsCreateGroup {
		b.Name = "Synthetic G2"
	} else {
		b.GroupID = "synthetic-G2"
		b.EndpointID = "synthetic-original-D"
	}
	if action == OwnerEndpointGroupsAddEndpoint {
		b.Duration = "until_revoked"
	}
	q, err := NewOwnerEndpointGroupsPrepare(f.session, f.scope, b, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealClientRequest(f.device, f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	c := OwnerEndpointGroupsCAS{OwnerKeyVersion: f.scope.OwnerKeyVersion, NodeOwnerBindingID: domain.target.Node.OwnerBindingID, NodeOwnerBindingVersion: domain.target.Node.BindingVersion, NodeKeyEpoch: domain.target.Node.NodeKeyEpoch, NetworkVersion: 1}
	r := OwnerEndpointGroupsReview{ReviewID: strings.Repeat("a", 32), RequestID: q.Context.RequestID, RequestPacketDigest: OwnerEndpointGroupsPacketDigest(raw), Action: action, Target: OwnerEndpointGroupsTarget{HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, NodeID: b.NodeID, NetworkID: b.NetworkID, GroupID: "synthetic-G2"}, Expected: c, ObservedAt: formatUTC(f.now.Add(time.Second)), ExpiresAt: formatUTC(f.now.Add(5 * time.Minute))}
	yes := true
	if action == OwnerEndpointGroupsCreateGroup {
		r.Target.Name = b.Name
		r.Target.ContextPolicy = "group_scoped"
		r.Projection = OwnerEndpointGroupsProjection{GroupID: r.Target.GroupID, Name: b.Name, ContextPolicy: "group_scoped", OwnerManagementOnly: &yes}
	} else {
		endpoint, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := endpoint.SignEndpointKeyAttestation(b.EndpointID, "synthetic-agent", b.NodeID, "synthetic-original-binding", 1)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(attestation)
		r.Target.LocalUserScope = "uid:1000"
		r.Target.EndpointID = b.EndpointID
		r.Target.PrincipalID = "synthetic-agent"
		r.Target.RegistrationDigest = strings.Repeat("b", 64)
		c := &r.Expected
		c.GroupVersion = 1
		c.RegistrationDigest = r.Target.RegistrationDigest
		c.RegistrationRevision = 1
		c.BindingID = "synthetic-original-binding"
		c.BindingEpoch = 1
		c.CandidateVersion = 1
		c.CandidateProofDigest = hex.EncodeToString(hash[:])
		c.CandidateFingerprint = nativePairPeerFingerprint(endpoint.Public())
		c.OwnerControlDigest = strings.Repeat("c", 64)
		if action == OwnerEndpointGroupsRemoveEndpoint {
			r.Projection = OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", RelationState: "REMOVED", ManualDeny: &yes, WithdrawScope: "EXACT_ENDPOINT_GROUP"}
		} else {
			p := e2ee.EndpointGroupPolicy{Version: 1, Purpose: e2ee.OwnerEndpointGroupsPolicyPurpose, PolicyID: strings.Repeat("d", 32), Epoch: 1, Origin: f.scope.Origin, HubID: f.hub.HubID, HubFingerprint: f.scope.HubFingerprint, OwnerID: f.scope.OwnerID, OwnerPublic: f.owner.Public(), OwnerKeyVersion: c.OwnerKeyVersion, Node: domain.target.Node, LocalUserScope: r.Target.LocalUserScope, NetworkID: b.NetworkID, GroupID: b.GroupID, EndpointID: b.EndpointID, PrincipalID: r.Target.PrincipalID, RegistrationDigest: c.RegistrationDigest, RegistrationRevision: c.RegistrationRevision, BindingID: c.BindingID, BindingEpoch: c.BindingEpoch, EndpointKeyID: endpoint.Public().ID, EndpointPublic: endpoint.Public(), EndpointFingerprint: c.CandidateFingerprint, CandidateVersion: c.CandidateVersion, CandidateProofDigest: c.CandidateProofDigest, ExpectedOwnerControlDigest: c.OwnerControlDigest, Rights: e2ee.EndpointGroupRights(), IssuedAt: r.ObservedAt, ReviewID: r.ReviewID, ServerNonce: strings.Repeat("e", 64)}
			core := p.Core()
			empty := []string{}
			r.Projection = OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", ContributionState: "PENDING_KEY", EffectiveRelationState: "PENDING_KEY", Grants: &empty, ProjectedRights: e2ee.EndpointGroupRights(), Duration: b.Duration, ExpectedOwnerControl: &e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, CompletionOwnerControl: &e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "NONE", PolicyID: p.PolicyID, PolicyEpoch: 1}, PolicyCore: &core}
			m := LocalDomainKeyManifest{Version: 1, Operation: "group-endpoint-key-grant:v1", HubID: p.HubID, OwnerID: p.OwnerID, PrincipalID: p.PrincipalID, GroupID: p.GroupID, GroupRevision: 1, EndpointID: p.EndpointID, NodeID: p.Node.NodeID, BindingID: p.BindingID, BindingEpoch: p.BindingEpoch, CandidateVersion: 1, CandidateKeyID: p.EndpointKeyID, CandidateFingerprint: p.EndpointFingerprint, CandidateProofDigest: p.CandidateProofDigest, CandidatePublicIdentity: p.EndpointPublic, OwnerKeyID: p.OwnerPublic.ID, IssuedAt: r.ObservedAt, CandidateAttestation: attestation}
			m.CandidateBindingDigest, _ = LocalDomainGroupBindingDigest(m)
			m.Digest, _ = LocalDomainGroupManifestDigest(m)
			r.KeyManifest = &m
			r.Policy = &p
		}
	}
	r.ReviewDigest, err = OwnerEndpointGroupsReviewDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy != nil {
		r.Policy.ReviewDigest = r.ReviewDigest
	}
	if err := ValidateOwnerEndpointGroupsReview(q, raw, r, f.hub, f.now.Add(2*time.Second)); err != nil {
		t.Fatal("synthetic review", err)
	}
	return endpointGroupsFixture{f, q, raw, r}
}

func TestOwnerEndpointGroupsRequestReviewAndOriginalRecoveryPQ(t *testing.T) {
	for _, action := range []string{OwnerEndpointGroupsCreateGroup, OwnerEndpointGroupsAddEndpoint, OwnerEndpointGroupsRemoveEndpoint} {
		t.Run(action, func(t *testing.T) {
			g := syntheticEndpointGroupsReview(t, action)
			f := g.f
			apply, err := NewOwnerEndpointGroupsApply(f.session, f.scope, g.prepare, g.original, g.review, f.owner, f.now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			original, err := SealClientRequest(f.device, f.hub, apply)
			if err != nil {
				t.Fatal(err)
			}
			status, err := NewOwnerEndpointGroupsStatus(f.session, f.scope, original, f.owner, f.now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if status.Body.OperationID != apply.Context.RequestID || status.Body.OriginalPacketDigest != OwnerEndpointGroupsPacketDigest(original) {
				t.Fatal("status used a response/prepare ID or digest")
			}
			reconcile, err := NewOwnerEndpointGroupsReconcile(f.session, f.scope, original, f.owner, f.now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []any{g.prepare, apply, status, reconcile} {
				var out any
				switch q.(type) {
				case OwnerEndpointGroupsPrepareRequest:
					out = &OwnerEndpointGroupsPrepareRequest{}
				case OwnerEndpointGroupsApplyRequest:
					out = &OwnerEndpointGroupsApplyRequest{}
				case OwnerEndpointGroupsStatusRequest:
					out = &OwnerEndpointGroupsStatusRequest{}
				case OwnerEndpointGroupsReconcileRequest:
					out = &OwnerEndpointGroupsReconcileRequest{}
				}
				raw, err := SealClientRequest(f.device, f.hub, q)
				if err != nil {
					t.Fatal("seal", err)
				}
				binding, route, err := NewClientRoute(f.hub, q, f.device.Public())
				if err != nil {
					t.Fatal(err)
				}
				pub := f.device.Public()
				if err := OpenRequestAt(f.hubPrivate, &pub, binding, route, raw, out, f.now.Add(4*time.Second)); err != nil || !reflect.DeepEqual(dereference(q), dereference(out)) {
					t.Fatalf("actual PQ request roundtrip %T: %v", q, err)
				}
			}
			if (len(apply.Body.PolicyProof) != 0) != (action == OwnerEndpointGroupsAddEndpoint) {
				t.Fatal("non-add signed policy")
			}
			outer, err := SealClientRequest(f.device, f.hub, reconcile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewOwnerEndpointGroupsReconcile(f.session, f.scope, outer, f.owner, f.now.Add(4*time.Second)); err == nil {
				t.Fatal("recursive reconciliation accepted")
			}
			reviewResult := OwnerEndpointGroupsResult{Format: OwnerEndpointGroupsResultFormat, ContractRevision: OwnerEndpointGroupsContractRevision, RequestID: g.prepare.Context.RequestID, RequestPacketDigest: OwnerEndpointGroupsPacketDigest(g.original), HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, NodeID: g.prepare.Body.NodeID, State: "PREPARED", CapturedAt: g.review.ObservedAt, Freshness: "SNAPSHOT_ONLY", Review: &g.review}
			_, route, _ := NewClientRoute(f.hub, g.prepare, f.device.Public())
			response, err := SealResponse(f.hubPrivate, f.device.Public(), route, reviewResult)
			if err != nil {
				t.Fatal("seal review response", err)
			}
			var result OwnerEndpointGroupsResult
			if err := OpenOwnerEndpointGroupsResponse(f.device, f.hub, g.original, response, &result); err != nil || VerifyOwnerEndpointGroupsResult(g.prepare, g.original, result, f.hub) != nil {
				t.Fatal("authenticated review result", err)
			}
		})
	}
}

func TestOwnerEndpointGroupsReviewRejectsSubstitutionAndEarlyTakeover(t *testing.T) {
	g := syntheticEndpointGroupsReview(t, OwnerEndpointGroupsAddEndpoint)
	changes := []func(*OwnerEndpointGroupsReview){
		func(r *OwnerEndpointGroupsReview) { r.Target.EndpointID = "synthetic-other-D" },
		func(r *OwnerEndpointGroupsReview) { r.Expected.BindingEpoch++ },
		func(r *OwnerEndpointGroupsReview) { r.Expected.DecisionRevision++ },
		func(r *OwnerEndpointGroupsReview) { r.Projection.ExpectedOwnerControl.Mode = "OWNER" },
		func(r *OwnerEndpointGroupsReview) { r.Projection.CompletionOwnerControl.Revision++ },
		func(r *OwnerEndpointGroupsReview) {
			r.Projection.ProjectedRights = append(r.Projection.ProjectedRights, "task.create")
		},
		func(r *OwnerEndpointGroupsReview) { r.Policy.BindingEpoch++ },
		func(r *OwnerEndpointGroupsReview) { r.Policy.EndpointKeyID = "synthetic-replacement-key" },
		func(r *OwnerEndpointGroupsReview) { r.Policy.Node.NodeKeyEpoch++ },
		func(r *OwnerEndpointGroupsReview) { r.Policy.ExpectedOwnerControlDigest = strings.Repeat("0", 64) },
		func(r *OwnerEndpointGroupsReview) { r.ExpiresAt = formatUTC(g.f.now.Add(6 * time.Minute)) },
		func(r *OwnerEndpointGroupsReview) { r.KeyManifest.CandidateAttestation[0] ^= 1 },
		func(r *OwnerEndpointGroupsReview) { r.Projection.Grants = nil },
	}
	for i, change := range changes {
		raw, _ := json.Marshal(g.review)
		var r OwnerEndpointGroupsReview
		json.Unmarshal(raw, &r)
		change(&r)
		// Recompute outer review binding: these negatives must fail the semantic
		// comparison even if an authenticated server labels the altered review.
		r.ReviewDigest, _ = OwnerEndpointGroupsReviewDigest(r)
		if r.Policy != nil {
			r.Policy.ReviewDigest = r.ReviewDigest
		}
		if _, err := NewOwnerEndpointGroupsApply(g.f.session, g.f.scope, g.prepare, g.original, r, g.f.owner, g.f.now.Add(2*time.Second)); err == nil {
			t.Fatalf("review substitution %d accepted", i)
		}
	}
	if _, err := NewOwnerEndpointGroupsApply(g.f.session, g.f.scope, g.prepare, g.original, g.review, g.f.owner, g.f.now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired review extended by new apply")
	}
	// A pending re-add cannot clear or mask an existing Owner removal.
	raw, _ := json.Marshal(g.review)
	var r OwnerEndpointGroupsReview
	json.Unmarshal(raw, &r)
	r.Expected.DecisionRevision = 2
	r.Projection.ExpectedOwnerControl = &e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 2, DenyReason: "REMOVED"}
	r.Projection.CompletionOwnerControl.Revision = 3
	r.Policy.ExpectedDecisionRevision = 2
	core := r.Policy.Core()
	r.Projection.PolicyCore = &core
	r.Projection.EffectiveRelationState = "ACTIVE"
	r.ReviewDigest, _ = OwnerEndpointGroupsReviewDigest(r)
	r.Policy.ReviewDigest = r.ReviewDigest
	if ValidateOwnerEndpointGroupsReview(g.prepare, g.original, r, g.f.hub, g.f.now.Add(2*time.Second)) == nil {
		t.Fatal("pending cleared durable deny")
	}
}

func TestOwnerEndpointGroupsStrictBodiesAndDeviceIsolation(t *testing.T) {
	g := syntheticEndpointGroupsReview(t, OwnerEndpointGroupsCreateGroup)
	f := g.f
	for _, body := range []OwnerEndpointGroupsPrepareBody{
		{Action: OwnerEndpointGroupsCreateGroup, NodeID: g.prepare.Body.NodeID, NetworkID: "synthetic-network", Name: " valid"},
		{Action: OwnerEndpointGroupsCreateGroup, NodeID: g.prepare.Body.NodeID, NetworkID: "synthetic-network", Name: "valid", EndpointID: "synthetic-D"},
		{Action: OwnerEndpointGroupsAddEndpoint, NodeID: g.prepare.Body.NodeID, NetworkID: "synthetic-network", GroupID: "synthetic-G2", EndpointID: "synthetic-D", Duration: "forever"},
		{Action: OwnerEndpointGroupsRemoveEndpoint, NodeID: g.prepare.Body.NodeID, NetworkID: "synthetic-network", GroupID: "synthetic-G2", EndpointID: "synthetic-D", Duration: "1d"},
	} {
		if _, err := NewOwnerEndpointGroupsPrepare(f.session, f.scope, body, f.owner, f.now); err == nil {
			t.Fatal("mixed/invalid action union accepted")
		}
	}
	q := g.prepare
	q.Body.Name = "changed after signing"
	if _, err := SealClientRequest(f.device, f.hub, q); err == nil {
		t.Fatal("body digest not verified")
	}
	for _, bad := range []string{strings.Replace(string(mustEndpointGroupsJSON(t, g.prepare)), `"action":`, `"native_session_id":"invented","action":`, 1), strings.Replace(string(mustEndpointGroupsJSON(t, g.prepare)), `"action":`, `"action":"CREATE_GROUP","action":`, 1)} {
		var q OwnerEndpointGroupsPrepareRequest
		if decodeCanonical([]byte(bad), MaxOwnerEndpointGroupsBodyBytes, &q) == nil {
			t.Fatal("unknown identity selector/duplicate accepted")
		}
	}
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealClientRequest(other, f.hub, g.prepare); err == nil {
		t.Fatal("another device borrowed Owner proof")
	}
	apply, err := NewOwnerEndpointGroupsApply(f.session, f.scope, g.prepare, g.original, g.review, f.owner, f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, apply)
	if err != nil {
		t.Fatal(err)
	}
	otherScope := f.scope
	otherScope.DevicePublic = other.Public()
	if _, err := NewOwnerEndpointGroupsStatus(f.session, otherScope, original, f.owner, f.now.Add(3*time.Second)); err == nil {
		t.Fatal("other device read original status")
	}
	if _, err := NewOwnerEndpointGroupsReconcile(f.session, otherScope, original, f.owner, f.now.Add(3*time.Second)); err == nil {
		t.Fatal("other device recovered original receipt")
	}
}

func mustEndpointGroupsJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOwnerEndpointGroupsReadScopeActionsAndSnapshotRules(t *testing.T) {
	f := appNodeCrypto(t)
	q, err := NewOwnerEndpointGroupsRead(f.session, f.scope, OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: "synthetic-node", NetworkID: "synthetic-network"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if q.Body.Limit != 64 {
		t.Fatal("default page bound changed")
	}
	original, err := SealClientRequest(f.device, f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	r := OwnerEndpointGroupsResult{Format: OwnerEndpointGroupsResultFormat, ContractRevision: OwnerEndpointGroupsContractRevision, RequestID: q.Context.RequestID, RequestPacketDigest: OwnerEndpointGroupsPacketDigest(original), HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, NodeID: q.Body.NodeID, State: "COMPLETED", CapturedAt: formatUTC(f.now), Freshness: "SNAPSHOT_ONLY", ScopeActions: &OwnerEndpointGroupsScopeActions{NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID, AllowedActions: []string{OwnerEndpointGroupsCreateGroup}}}
	if err := VerifyOwnerEndpointGroupsResult(q, original, r, f.hub); err != nil {
		t.Fatal("empty group list lost independent create action", err)
	}
	r.ScopeActions = nil
	if VerifyOwnerEndpointGroupsResult(q, original, r, f.hub) == nil {
		t.Fatal("unscoped create/read result accepted")
	}
	fp, _ := HubFingerprint(f.hub)
	caps := OwnerEndpointGroupsCapabilities{Format: OwnerEndpointGroupsCapabilitiesFormat, ContractRevision: OwnerEndpointGroupsContractRevision, HubID: f.hub.HubID, HubFingerprint: fp, MaxPageRows: 64, MaxPageCanonicalBytes: MaxOwnerEndpointGroupsPageBytes, MaxActiveGroupsPerEndpoint: 32, DurationValues: EndpointGroupDurationValues()}
	if _, err := DecodeOwnerEndpointGroupsCapabilities(mustEndpointGroupsJSON(t, caps), f.hub); err != nil {
		t.Fatal(err)
	}
	caps.NativeSelfGroups = true
	if _, err := DecodeOwnerEndpointGroupsCapabilities(mustEndpointGroupsJSON(t, caps), f.hub); err == nil {
		t.Fatal("self capability exceeded overall availability")
	}
	if OwnerEndpointGroupsHTTPPath("owner.endpoint_groups.apply.extra") != "" || OwnerEndpointGroupsOwnerPurpose("owner.endpoint_groups.legacy") != "" {
		t.Fatal("prefix enabled unknown operation")
	}
}

func TestOwnerEndpointGroupsReceiptRemainsOriginalAndUncertainNeverCompletes(t *testing.T) {
	g := syntheticEndpointGroupsReview(t, OwnerEndpointGroupsCreateGroup)
	f := g.f
	apply, err := NewOwnerEndpointGroupsApply(f.session, f.scope, g.prepare, g.original, g.review, f.owner, f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, apply)
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	o := OwnerEndpointGroupsOperation{OperationID: apply.Context.RequestID, OriginalPacketDigest: OwnerEndpointGroupsPacketDigest(original), Action: g.review.Action, State: "COMPLETED", ReviewID: g.review.ReviewID, Target: g.review.Target, CommittedAt: formatUTC(f.now.Add(3 * time.Second)), Effect: &OwnerEndpointGroupsEffect{GroupID: g.review.Target.GroupID, Created: &yes}}
	r := OwnerEndpointGroupsResult{Format: OwnerEndpointGroupsResultFormat, ContractRevision: OwnerEndpointGroupsContractRevision, RequestID: apply.Context.RequestID, RequestPacketDigest: OwnerEndpointGroupsPacketDigest(original), HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, NodeID: g.prepare.Body.NodeID, State: "COMPLETED", CapturedAt: o.CommittedAt, Freshness: "SNAPSHOT_ONLY", Operation: &o}
	if VerifyOwnerEndpointGroupsResult(apply, original, r, f.hub) != nil || VerifyOwnerEndpointGroupsOperation(g.review, original, o) != nil {
		t.Fatal("original create receipt rejected")
	}
	_, route, _ := NewClientRoute(f.hub, apply, f.device.Public())
	receipt, err := SealResponse(f.hubPrivate, f.device.Public(), route, r)
	if err != nil {
		t.Fatal(err)
	}
	status, err := NewOwnerEndpointGroupsStatus(f.session, f.scope, original, f.owner, f.now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	statusPacket, err := SealClientRequest(f.device, f.hub, status)
	if err != nil {
		t.Fatal(err)
	}
	r.RequestID = status.Context.RequestID
	r.RequestPacketDigest = OwnerEndpointGroupsPacketDigest(statusPacket)
	r.ReceiptPacket = receipt
	if VerifyOwnerEndpointGroupsResult(status, statusPacket, r, f.hub) != nil {
		t.Fatal("status lost original receipt binding")
	}
	// Both layers authenticate independently: the fresh status envelope and
	// its unchanged original receipt using the retained original apply route.
	_, statusRoute, _ := NewClientRoute(f.hub, status, f.device.Public())
	response, err := SealResponse(f.hubPrivate, f.device.Public(), statusRoute, r)
	if err != nil {
		t.Fatal(err)
	}
	var opened OwnerEndpointGroupsResult
	if OpenOwnerEndpointGroupsResponse(f.device, f.hub, statusPacket, response, &opened) != nil || OpenOwnerEndpointGroupsResponse(f.device, f.hub, original, opened.ReceiptPacket, &opened) != nil {
		t.Fatal("nested original response authentication failed")
	}
	wrong := o
	wrong.OriginalPacketDigest = OwnerEndpointGroupsPacketDigest(g.original)
	if VerifyOwnerEndpointGroupsOperation(g.review, original, wrong) == nil {
		t.Fatal("prepare digest substituted for original apply digest")
	}
	unknown := r
	unknown.State = "PREPARED"
	unknown.ErrorCode = "OUTCOME_UNCERTAIN"
	unknown.Operation = nil
	unknown.ReceiptPacket = nil
	if VerifyOwnerEndpointGroupsResult(status, statusPacket, unknown, f.hub) != nil {
		t.Fatal("uncertain observation must remain representable")
	}
	unknown.State = "REJECTED_FENCED"
	if VerifyOwnerEndpointGroupsResult(status, statusPacket, unknown, f.hub) == nil {
		t.Fatal("uncertainty became permanent no-effect fence")
	}
	unknown = r
	unknown.Operation = nil
	unknown.RequestID = apply.Context.RequestID
	unknown.RequestPacketDigest = OwnerEndpointGroupsPacketDigest(original)
	unknown.ReceiptPacket = nil
	if VerifyOwnerEndpointGroupsResult(apply, original, unknown, f.hub) == nil {
		t.Fatal("success inferred without terminal original operation")
	}
}

func TestOwnerEndpointGroupsCardsCannotFallBackAfterOwnerDecision(t *testing.T) {
	ref := EndpointGroupSourceReference{Source: "DEFAULT_POLICY", AuthorityID: strings.Repeat("a", 32), AuthorityEpoch: 1, ContributionRevision: 1}
	c := OwnerEndpointGroupsRelationCard{GroupID: "synthetic-G1", GroupName: "Synthetic G1", NetworkID: "synthetic-network", State: "ACTIVE", RelationRevision: 1, OwnerControl: e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, Contributions: []OwnerEndpointGroupsContributionCard{{Source: ref.Source, AuthorityID: ref.AuthorityID, AuthorityEpoch: 1, ContributionRevision: 1, State: "ACTIVE", KeyState: "CURRENT", Effective: true}}, SelectedSource: &ref, KeyState: "CURRENT"}
	if !endpointGroupsRelationCard(c) {
		t.Fatal("untouched current default relation rejected")
	}
	c.OwnerControl = e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "EXPIRED", PolicyID: strings.Repeat("b", 32), PolicyEpoch: 1}
	c.DecisionRevision = 1
	c.ManualDeny = true
	if endpointGroupsRelationCard(c) {
		t.Fatal("default proof survived finite Owner expiry")
	}
	c.State = "EXPIRED"
	c.SelectedSource = nil
	c.Contributions[0].Effective = false
	c.KeyState = "EXPIRED"
	if !endpointGroupsRelationCard(c) {
		t.Fatal("blocked default provenance must remain visible")
	}
	c.Contributions[0].Source = "LEGACY_UNKNOWN"
	if endpointGroupsRelationCard(c) {
		t.Fatal("unknown source admitted")
	}
}
