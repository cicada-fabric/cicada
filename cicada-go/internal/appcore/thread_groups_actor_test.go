package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// Actual Controller/vault/Owner/PQ packets with a synthetic response actor.
// This is not evidence of Hub Store/Guard, a real Node or native Runtime.
type threadGroupActor struct {
	t           *testing.T
	local       *localCollaborationActor
	c           *nativeController
	card        wire.OwnerEndpointGroupsThreadCard
	groups      []wire.OwnerEndpointGroupsGroupCard
	reviews     map[string]wire.OwnerEndpointGroupsReview
	receipts    map[string][]byte
	results     map[string]wire.OwnerEndpointGroupsResult
	posts       map[string][][]byte
	available   bool
	deny, drop  string
	wrongHead   bool
	badNested   bool
	applyCount  int
	queryResult func(*wire.OwnerEndpointGroupsResult)
}

func newThreadGroupActor(t *testing.T) *threadGroupActor {
	t.Helper()
	l := newLocalCollaborationActor(t)
	a := &threadGroupActor{t: t, local: l, c: l.c, reviews: map[string]wire.OwnerEndpointGroupsReview{}, receipts: map[string][]byte{}, results: map[string]wire.OwnerEndpointGroupsResult{}, posts: map[string][][]byte{}, available: true}
	a.c.cfg.HTTP = a
	l.prepare()
	l.activate()
	p := l.challenge.Policy
	source := wire.EndpointGroupSourceReference{Source: "DEFAULT_POLICY", AuthorityID: p.PolicyID, AuthorityEpoch: 1, ContributionRevision: 1}
	r := wire.OwnerEndpointGroupsRelationCard{GroupID: p.GroupID, GroupName: p.GroupName, NetworkID: p.NetworkID, State: "ACTIVE", RelationRevision: 1,
		OwnerControl: e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, KeyState: "CURRENT", AllowedActions: []string{"REMOVE_ENDPOINT"}, SelectedSource: &source,
		Contributions: []wire.OwnerEndpointGroupsContributionCard{{Source: source.Source, AuthorityID: source.AuthorityID, AuthorityEpoch: 1, ContributionRevision: 1, State: "ACTIVE", KeyState: "CURRENT", Effective: true}}}
	a.card = wire.OwnerEndpointGroupsThreadCard{EndpointID: "synthetic-original-D", PrincipalID: "synthetic-agent-D", NodeID: p.Node.NodeID, NetworkID: p.NetworkID,
		Name: "Synthetic Thread D", Workspace: "/synthetic/original/workspace", Harness: "codex", RegistrationDigest: strings.Repeat("b", 64), RegistrationRevision: 1, Presence: "UNKNOWN",
		Relations: []wire.OwnerEndpointGroupsRelationCard{r}, RelationStates: []string{"NONE", "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}, RelationsRevision: 1, RelationsComplete: true}
	return a
}

func (a *threadGroupActor) Do(req *http.Request) (*http.Response, error) {
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: req}, nil
	}
	if req.URL.Path == wire.OwnerEndpointGroupsCapabilitiesPath {
		capability, err := wire.NewOwnerEndpointGroupsCapabilities(a.c.hub)
		if err != nil {
			a.t.Fatal(err)
		}
		capability.Available = a.available
		raw, _ := json.Marshal(capability)
		return reply(raw, 200)
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/owner/endpoint-groups/") {
		return a.local.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	defer clear(raw)
	packet, err := wire.DecodeOwnerEndpointGroupsPacket(raw)
	if err != nil {
		a.t.Fatal(err)
	}
	route := packet.Packet.Route
	if req.URL.Path != wire.OwnerEndpointGroupsHTTPPath(route.Operation) {
		a.t.Fatal("wrong Group route")
	}
	index := threadGroupOriginal
	if route.Operation == wire.OperationOwnerEndpointGroupsReconcile {
		index = threadGroupRecovery
	}
	saved, _, found, err := a.c.vault.LoadState(threadGroupNamespaces[index])
	defer clear(saved)
	record, decodeErr := decodeThreadGroupRecord(saved)
	if err != nil || !found || decodeErr != nil || !bytes.Equal(record.Packet, raw) {
		a.t.Fatal("Group POST preceded exact vault persistence")
	}
	if route.Operation == wire.OperationOwnerEndpointGroupsApply {
		rawReview, _, _, err := a.c.vault.LoadState(threadGroupNamespaces[threadGroupState])
		defer clear(rawReview)
		var review threadGroupSavedReview
		_, decodeErr := decodeThreadGroupFrame(rawReview, "CEGS", &review)
		if err != nil || decodeErr != nil || review.Original != nil || review.Response != nil || a.c.threadGroups.reviewOriginal != nil || a.c.threadGroups.reviewResponse != nil {
			a.t.Fatal("apply POST preceded durable retirement of the prior review")
		}
	}
	a.posts[route.Operation] = append(a.posts[route.Operation], bytes.Clone(raw))
	if a.deny == route.Operation {
		return reply([]byte("synthetic unsigned denial"), 403)
	}
	digest := wire.OwnerEndpointGroupsPacketDigest(raw)
	response := a.receipts[digest]
	if response == nil {
		binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
		device := a.c.device.Public()
		open := func(out any) {
			if err := wire.OpenRequestAt(a.local.n.n2.hubKey, &device, binding, route, raw, out, time.Time{}); err != nil {
				a.t.Fatal("actual Group PQ request", err)
			}
		}
		result := wire.OwnerEndpointGroupsResult{Format: wire.OwnerEndpointGroupsResultFormat, ContractRevision: wire.OwnerEndpointGroupsContractRevision,
			RequestID: route.OperationID, RequestPacketDigest: digest, HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID,
			NodeID: a.local.challenge.Policy.Node.NodeID, State: "COMPLETED", CapturedAt: a.local.n.stamp(a.local.n.n2.now), Freshness: "SNAPSHOT_ONLY"}
		switch route.Operation {
		case wire.OperationOwnerEndpointGroupsRead:
			var q wire.OwnerEndpointGroupsReadRequest
			open(&q)
			result.ScopeActions = &wire.OwnerEndpointGroupsScopeActions{NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID, AllowedActions: []string{"CREATE_GROUP"}}
			switch q.Body.View {
			case "THREADS":
				result.Threads = []wire.OwnerEndpointGroupsThreadCard{a.card}
			case "RELATIONS":
				result.Relations = a.card.Relations
				result.RelationPage = &wire.OwnerEndpointGroupsRelationPage{EndpointID: q.Body.EndpointID, NetworkID: q.Body.NetworkID, States: a.card.RelationStates, RelationsRevision: a.card.RelationsRevision, Complete: true}
			case "CANDIDATE_GROUPS":
				result.Groups = slices.Clone(a.groups)
				sort.Slice(result.Groups, func(i, j int) bool { return result.Groups[i].GroupID < result.Groups[j].GroupID })
			}
		case wire.OperationOwnerEndpointGroupsPrepare:
			var q wire.OwnerEndpointGroupsPrepareRequest
			open(&q)
			review := a.makeReview(q, raw)
			a.reviews[review.ReviewID] = review
			result.State, result.Review = "PREPARED", &review
		case wire.OperationOwnerEndpointGroupsApply:
			var q wire.OwnerEndpointGroupsApplyRequest
			open(&q)
			review := a.reviews[q.Body.ReviewID]
			a.applyCount++
			operation := wire.OwnerEndpointGroupsOperation{OperationID: route.OperationID, OriginalPacketDigest: digest, Action: review.Action, State: "COMPLETED", ReviewID: review.ReviewID, Target: review.Target, CommittedAt: result.CapturedAt}
			yes, revision := true, review.Expected.RelationRevision+1
			switch review.Action {
			case "CREATE_GROUP":
				operation.Effect = &wire.OwnerEndpointGroupsEffect{GroupID: review.Target.GroupID, Created: &yes}
				a.groups = append(a.groups, wire.OwnerEndpointGroupsGroupCard{GroupID: review.Target.GroupID, Name: review.Target.Name, NetworkID: review.Target.NetworkID, GroupVersion: 1, ContextPolicy: "group_scoped", AllowedActions: []string{"ADD_ENDPOINT"}})
			case "ADD_ENDPOINT":
				policy, err := e2ee.VerifyOwnerEndpointGroupPolicy(a.c.owner.Public(), q.Body.PolicyProof, time.Time{})
				if err != nil {
					a.t.Fatal(err)
				}
				decision := review.Expected.DecisionRevision
				operation.Effect = &wire.OwnerEndpointGroupsEffect{GroupID: review.Target.GroupID, EndpointID: review.Target.EndpointID, RelationRevision: &revision, DecisionRevision: &decision, PolicyID: policy.PolicyID, PolicyEpoch: policy.Epoch, ContributionRevision: 1, ContributionState: "PENDING_KEY", EffectiveRelationState: review.Projection.EffectiveRelationState, OwnerControl: review.Projection.ExpectedOwnerControl}
				a.card.Relations = append(a.card.Relations, wire.OwnerEndpointGroupsRelationCard{GroupID: policy.GroupID, GroupName: "Synthetic G2", NetworkID: policy.NetworkID, State: "PENDING_KEY", RelationRevision: revision, OwnerControl: *review.Projection.ExpectedOwnerControl, KeyState: "PENDING", AllowedActions: []string{"REMOVE_ENDPOINT"}, Contributions: []wire.OwnerEndpointGroupsContributionCard{{Source: "OWNER_EXPLICIT", AuthorityID: policy.PolicyID, AuthorityEpoch: policy.Epoch, ContributionRevision: 1, State: "PENDING_KEY", KeyState: "PENDING"}}})
				a.card.RelationsRevision++
			case "REMOVE_ENDPOINT":
				head := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: review.Expected.DecisionRevision + 1, DenyReason: "REMOVED"}
				if a.wrongHead {
					head.Revision++
				}
				decision := head.Revision
				withdrawn := []wire.EndpointGroupSourceReference{{Source: "DEFAULT_POLICY", AuthorityID: a.local.challenge.Policy.PolicyID, AuthorityEpoch: 1, ContributionRevision: 1}}
				operation.Effect = &wire.OwnerEndpointGroupsEffect{GroupID: review.Target.GroupID, EndpointID: review.Target.EndpointID, RelationRevision: &revision, DecisionRevision: &decision, WithdrawnContributions: &withdrawn, ManualDeny: &yes, RelationState: "REMOVED", OwnerControl: &head}
				for i := range a.card.Relations {
					if a.card.Relations[i].GroupID == review.Target.GroupID {
						r := &a.card.Relations[i]
						r.State, r.KeyState, r.RelationRevision, r.DecisionRevision, r.ManualDeny, r.OwnerControl, r.SelectedSource = "REMOVED", "REVOKED", revision, decision, true, head, nil
						for j := range r.Contributions {
							r.Contributions[j].Effective = false
							r.Contributions[j].State = "REVOKED"
							r.Contributions[j].KeyState = "REVOKED"
						}
					}
				}
				a.card.RelationsRevision++
			}
			result.Operation = &operation
		case wire.OperationOwnerEndpointGroupsReconcile:
			var q wire.OwnerEndpointGroupsReconcileRequest
			open(&q)
			originalDigest := wire.OwnerEndpointGroupsPacketDigest(q.Body.OriginalPacket)
			result.ReceiptPacket = a.receipts[originalDigest]
			originalResult, ok := a.results[originalDigest]
			if !ok {
				original, err := wire.DecodeOwnerEndpointGroupsPacket(q.Body.OriginalPacket)
				if err != nil || original.Packet.Route.Operation != wire.OperationOwnerEndpointGroupsApply {
					a.t.Fatal("synthetic unseen original was not an apply", err)
				}
				originalResult = wire.OwnerEndpointGroupsResult{Format: wire.OwnerEndpointGroupsResultFormat, ContractRevision: wire.OwnerEndpointGroupsContractRevision,
					RequestID: original.Packet.Route.OperationID, RequestPacketDigest: originalDigest, HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID,
					State: "REJECTED_FENCED", ErrorCode: wire.OwnerEndpointGroupsOriginalNotAdmitted, CapturedAt: result.CapturedAt, Freshness: "SNAPSHOT_ONLY"}
				fence, err := wire.SealResponse(a.local.n.n2.hubKey, device, original.Packet.Route, originalResult)
				if err != nil {
					a.t.Fatal(err)
				}
				a.receipts[originalDigest], a.results[originalDigest] = bytes.Clone(fence), originalResult
				result.ReceiptPacket, result.NodeID = fence, ""
			}
			result.Operation = originalResult.Operation
			if a.queryResult != nil {
				a.queryResult(&result)
			}
		default:
			a.t.Fatal("unexpected Group operation")
		}
		sort.Slice(a.card.Relations, func(i, j int) bool { return a.card.Relations[i].GroupID < a.card.Relations[j].GroupID })
		response, err = wire.SealResponse(a.local.n.n2.hubKey, device, route, result)
		if err != nil {
			a.t.Fatal("synthetic Group response shape", err)
		}
		a.receipts[digest], a.results[digest] = bytes.Clone(response), result
	}
	if a.drop == route.Operation {
		a.drop = ""
		return nil, errors.New("synthetic response loss after commit")
	}
	if route.Operation == wire.OperationOwnerEndpointGroupsReconcile && a.badNested {
		a.badNested = false
		// Inject a transient Hub-signed outer response whose nested receipt
		// has the exact original route but a different reviewed Group. The
		// durable synthetic ledger still retains its correct exact response.
		bad := a.results[record.ParentDigest]
		op := *bad.Operation
		effect := *op.Effect
		op.Target.GroupID, effect.GroupID = "synthetic-wrong-group", "synthetic-wrong-group"
		op.Effect, bad.Operation = &effect, &op
		original, err := wire.DecodeOwnerEndpointGroupsPacket(a.c.threadGroups.original.Packet)
		if err != nil {
			a.t.Fatal(err)
		}
		nested, err := wire.SealResponse(a.local.n.n2.hubKey, a.c.device.Public(), original.Packet.Route, bad)
		if err != nil {
			a.t.Fatal(err)
		}
		outer := a.results[digest]
		outer.ReceiptPacket = nested
		response, err = wire.SealResponse(a.local.n.n2.hubKey, a.c.device.Public(), route, outer)
		if err != nil {
			a.t.Fatal(err)
		}
	}
	return reply(response, 200)
}

func (a *threadGroupActor) makeReview(q wire.OwnerEndpointGroupsPrepareRequest, raw []byte) wire.OwnerEndpointGroupsReview {
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(a.c.owner.Public(), q.OwnerProof, wire.OwnerEndpointGroupsOwnerPurpose(wire.OperationOwnerEndpointGroupsPrepare), time.Time{})
	if err != nil {
		a.t.Fatal(err)
	}
	b := a.c.nodeConfirmation.Binding
	reviewID, err := wire.NewRequestID()
	if err != nil {
		a.t.Fatal(err)
	}
	r := wire.OwnerEndpointGroupsReview{ReviewID: reviewID, RequestID: q.Context.RequestID, RequestPacketDigest: wire.OwnerEndpointGroupsPacketDigest(raw), Action: q.Body.Action,
		Target:   wire.OwnerEndpointGroupsTarget{HubID: q.Context.HubID, OwnerID: q.Context.OwnerID, NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID, GroupID: "synthetic-G2"},
		Expected: wire.OwnerEndpointGroupsCAS{OwnerKeyVersion: claims.Scope.OwnerKeyVersion, NodeOwnerBindingID: b.OwnerBindingID, NodeOwnerBindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, NetworkVersion: 1}, ObservedAt: a.local.n.stamp(a.local.n.n2.now), ExpiresAt: claims.ExpiresAt}
	yes := true
	if q.Body.Action == "CREATE_GROUP" {
		r.Target.GroupID = "synthetic-G2-" + reviewID
		r.Target.Name, r.Target.ContextPolicy = q.Body.Name, "group_scoped"
		r.Projection = wire.OwnerEndpointGroupsProjection{GroupID: r.Target.GroupID, Name: q.Body.Name, ContextPolicy: "group_scoped", OwnerManagementOnly: &yes}
	} else {
		r.Target.GroupID, r.Target.EndpointID, r.Target.PrincipalID, r.Target.RegistrationDigest, r.Target.LocalUserScope = q.Body.GroupID, q.Body.EndpointID, a.card.PrincipalID, a.card.RegistrationDigest, "uid:4242"
		c := &r.Expected
		c.GroupVersion, c.RegistrationDigest, c.RegistrationRevision = 1, a.card.RegistrationDigest, 1
		c.BindingID, c.BindingEpoch = "synthetic-original-binding", 1
		c.CandidateVersion = 1
		c.OwnerControlDigest = strings.Repeat("c", 64)
		if q.Body.Action == "REMOVE_ENDPOINT" {
			for _, relation := range a.card.Relations {
				if relation.GroupID == q.Body.GroupID {
					c.RelationRevision, c.DecisionRevision = relation.RelationRevision, relation.DecisionRevision
				}
			}
			c.CandidateProofDigest, c.CandidateFingerprint = strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)
			r.Projection = wire.OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", RelationState: "REMOVED", ManualDeny: &yes, WithdrawScope: "EXACT_ENDPOINT_GROUP"}
		} else {
			endpoint, err := e2ee.NewIdentity()
			if err != nil {
				a.t.Fatal(err)
			}
			attestation, err := endpoint.SignEndpointKeyAttestation(q.Body.EndpointID, a.card.PrincipalID, b.NodeID, c.BindingID, 1)
			if err != nil {
				a.t.Fatal(err)
			}
			hash := sha256.Sum256(attestation)
			c.CandidateProofDigest = hex.EncodeToString(hash[:])
			c.CandidateFingerprint, err = nodekeys.PeerKeyFingerprint(endpoint.Public())
			if err != nil {
				a.t.Fatal(err)
			}
			expires, _ := wire.EndpointGroupDurationExpiry(q.Body.Duration, a.local.n.n2.now)
			p := e2ee.EndpointGroupPolicy{Version: 1, Purpose: e2ee.OwnerEndpointGroupsPolicyPurpose, PolicyID: strings.Repeat("d", 32), Epoch: 1, Origin: claims.Scope.Origin, HubID: q.Context.HubID, HubFingerprint: claims.Scope.HubFingerprint, OwnerID: q.Context.OwnerID, OwnerPublic: a.c.owner.Public(), OwnerKeyVersion: c.OwnerKeyVersion, Node: b, LocalUserScope: r.Target.LocalUserScope, NetworkID: q.Body.NetworkID, GroupID: q.Body.GroupID, EndpointID: q.Body.EndpointID, PrincipalID: a.card.PrincipalID, RegistrationDigest: c.RegistrationDigest, RegistrationRevision: 1, BindingID: c.BindingID, BindingEpoch: 1, EndpointKeyID: endpoint.Public().ID, EndpointPublic: endpoint.Public(), EndpointFingerprint: c.CandidateFingerprint, CandidateVersion: 1, CandidateProofDigest: c.CandidateProofDigest, ExpectedOwnerControlDigest: c.OwnerControlDigest, Rights: e2ee.EndpointGroupRights(), IssuedAt: r.ObservedAt, ExpiresAt: expires, ReviewID: r.ReviewID, ServerNonce: strings.Repeat("e", 64)}
			core, empty := p.Core(), []string{}
			r.Projection = wire.OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", ContributionState: "PENDING_KEY", EffectiveRelationState: "PENDING_KEY", Grants: &empty, ProjectedRights: e2ee.EndpointGroupRights(), Duration: q.Body.Duration, ExpectedOwnerControl: &e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, CompletionOwnerControl: &e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "NONE", PolicyID: p.PolicyID, PolicyEpoch: 1}, PolicyCore: &core}
			m := wire.LocalDomainKeyManifest{Version: 1, Operation: "group-endpoint-key-grant:v1", HubID: p.HubID, OwnerID: p.OwnerID, PrincipalID: p.PrincipalID, GroupID: p.GroupID, GroupRevision: 1, EndpointID: p.EndpointID, NodeID: b.NodeID, BindingID: p.BindingID, BindingEpoch: 1, CandidateVersion: 1, CandidateKeyID: p.EndpointKeyID, CandidateFingerprint: p.EndpointFingerprint, CandidateProofDigest: p.CandidateProofDigest, CandidatePublicIdentity: p.EndpointPublic, OwnerKeyID: p.OwnerPublic.ID, IssuedAt: r.ObservedAt, ExpiresAt: expires, CandidateAttestation: attestation}
			m.CandidateBindingDigest, _ = wire.LocalDomainGroupBindingDigest(m)
			m.Digest, _ = wire.LocalDomainGroupManifestDigest(m)
			r.KeyManifest, r.Policy = &m, &p
		}
	}
	r.ReviewDigest, err = wire.OwnerEndpointGroupsReviewDigest(r)
	if err != nil {
		a.t.Fatal(err)
	}
	if r.Policy != nil {
		r.Policy.ReviewDigest = r.ReviewDigest
	}
	if err := wire.ValidateOwnerEndpointGroupsReview(q, raw, r, a.c.hub, a.local.n.n2.now); err != nil {
		a.t.Fatal("synthetic reviewed scope", err)
	}
	return r
}

func (a *threadGroupActor) readAndSelect() {
	a.t.Helper()
	s := a.c.Snapshot()
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionReadThreadGroups, ThreadGroups: ThreadGroupAction{GestureID: s.ThreadGroups.GestureID}}); err != nil {
		a.t.Fatal(err)
	}
	s = a.c.Snapshot()
	if len(s.ThreadGroups.Threads) != 1 || !s.ThreadGroups.Current {
		a.t.Fatal("fresh signed Thread card absent")
	}
	t := s.ThreadGroups.Threads[0]
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionReadThreadRelations, ThreadGroups: ThreadGroupAction{EndpointID: t.EndpointID, GestureID: t.GestureID}}); err != nil {
		a.t.Fatal(err)
	}
}

func (a *threadGroupActor) candidates() {
	a.t.Helper()
	t := a.c.Snapshot().ThreadGroups.Selected
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionReadGroupCandidates, ThreadGroups: ThreadGroupAction{EndpointID: t.EndpointID, GestureID: t.GestureID}}); err != nil {
		a.t.Fatal(err)
	}
}

func (a *threadGroupActor) prepareCreate() {
	a.t.Helper()
	a.readAndSelect()
	a.candidates()
	s := a.c.Snapshot()
	if !s.ThreadGroups.CanCreate || len(s.ThreadGroups.Candidates) != 0 {
		a.t.Fatal("empty candidates lost authenticated create")
	}
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: s.ThreadGroups.GestureID, Change: "CREATE_GROUP", Name: "Synthetic G2"}}); err != nil {
		a.t.Fatal(err)
	}
}

func (a *threadGroupActor) apply() error {
	a.t.Helper()
	r := a.c.Snapshot().ThreadGroups.Review
	if r == nil {
		a.t.Fatal("no reviewed exact change")
	}
	return a.c.Dispatch(context.Background(), Action{Kind: ActionApplyThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID, Confirm: true}})
}

func TestThreadGroupActorCreatesThenAddsWithoutAutomaticMembership(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	if a.c.Snapshot().ThreadGroups.Outcome != "GROUP_CREATED" || len(a.card.Relations) != 1 {
		t.Fatal("creating G2 claimed an Agent membership")
	}
	a.readAndSelect()
	a.candidates()
	s := a.c.Snapshot()
	candidate := s.ThreadGroups.Candidates[0]
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: candidate.GestureID, EndpointID: s.ThreadGroups.Selected.EndpointID, GroupID: candidate.GroupID, Change: "ADD_ENDPOINT", Duration: "until_revoked"}}); err != nil {
		t.Fatal(err)
	}
	if r := a.c.Snapshot().ThreadGroups.Review; r.PolicyExpiresAt != "" || r.Duration != "until_revoked" {
		t.Fatal("default policy acquired request expiry")
	}
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	a.readAndSelect()
	s = a.c.Snapshot()
	if len(s.ThreadGroups.Selected.Relations) != 2 {
		t.Fatal("same original Thread did not retain both relations")
	}
	for _, r := range s.ThreadGroups.Selected.Relations {
		if r.GroupID == candidate.GroupID && r.State != "PENDING_KEY" {
			t.Fatal("submitted grant became active without real key completion")
		}
	}
}

func TestThreadGroupActorLostApplyAndRecoveryResponseRetainExactPackets(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil || !a.c.hasThreadGroupPending() {
		t.Fatal("lost apply response did not remain unknown")
	}
	original := bytes.Clone(a.c.threadGroups.original.Packet)
	owner, device := a.c.owner.Public().ID, a.c.device.Public().ID
	a.drop = wire.OperationOwnerEndpointGroupsReconcile
	recoveryErr := a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup})
	if recoveryErr == nil || !a.c.hasThreadGroupPending() {
		t.Fatal("lost recovery response settled pending")
	}
	if a.c.threadGroups.recovery == nil {
		t.Fatal("recovery did not stage its wrapper", recoveryErr)
	}
	wrapper := bytes.Clone(a.c.threadGroups.recovery.Packet)
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}); err != nil {
		t.Fatal(err)
	}
	if a.applyCount != 1 || !bytes.Equal(original, a.c.threadGroups.original.Packet) || !bytes.Equal(wrapper, a.posts[wire.OperationOwnerEndpointGroupsReconcile][1]) || a.c.owner.Public().ID != owner || a.c.device.Public().ID != device {
		t.Fatal("recovery replaced original/sender or re-applied mutation")
	}
	if a.c.Snapshot().ThreadGroups.Current || a.c.hasThreadGroupPending() {
		t.Fatal("historical receipt restored current authority or failed to settle")
	}
}

func TestThreadGroupActorRejectsWrongRemovalHeadAndKeepsOriginal(t *testing.T) {
	a := newThreadGroupActor(t)
	a.readAndSelect()
	s := a.c.Snapshot()
	r := s.ThreadGroups.Selected.Relations[0]
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID, EndpointID: s.ThreadGroups.Selected.EndpointID, GroupID: r.GroupID, Change: "REMOVE_ENDPOINT"}}); err != nil {
		t.Fatal(err)
	}
	a.wrongHead = true
	if a.apply() == nil || !a.c.hasThreadGroupPending() {
		t.Fatal("wrong but Hub-authenticated head settled exact removal")
	}
}

func TestThreadGroupActorBadNestedReceiptDoesNotPoisonRecoveryCache(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil {
		t.Fatal("lost apply response reported success")
	}
	a.badNested = true
	if a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil || !a.c.hasThreadGroupPending() || a.c.threadGroups.recoveryResponse != nil {
		t.Fatal("invalid nested receipt was cached or settled the original")
	}
	wrapper := bytes.Clone(a.c.threadGroups.recovery.Packet)
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}); err != nil {
		t.Fatal(err)
	}
	if a.applyCount != 1 || a.c.hasThreadGroupPending() || !bytes.Equal(wrapper, a.posts[wire.OperationOwnerEndpointGroupsReconcile][1]) {
		t.Fatal("bad nested response prevented retry of the exact original wrapper")
	}
}

func TestThreadGroupActorRestartKeepsOriginalAndRequiresLogin(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	owner, device := a.c.owner.Public().ID, a.c.device.Public().ID
	session := *a.c.session
	session.SessionToken = bytes.Clone(session.SessionToken)
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil {
		t.Fatal("lost response reported success")
	}
	original := bytes.Clone(a.c.threadGroups.original.Packet)
	a.local.reopen()
	a.c = a.local.c
	a.c.cfg.HTTP = a
	if a.c.owner.Public().ID != owner || a.c.device.Public().ID != device || !a.c.hasThreadGroupPending() || !bytes.Equal(original, a.c.threadGroups.original.Packet) {
		t.Fatalf("reopening changed state: owner=%v device=%v pending=%v packet=%v phase=%s error=%s", a.c.owner.Public().ID == owner, a.c.device.Public().ID == device, a.c.hasThreadGroupPending(), a.c.threadGroups.original != nil && bytes.Equal(original, a.c.threadGroups.original.Packet), a.c.Snapshot().Phase, a.c.Snapshot().ErrorCode)
	}
	if s := a.c.Snapshot(); s.Account.State != AccountStateLoginRequired || slices.Contains(s.AvailableActions, ActionRecoverThreadGroup) || len(s.ThreadGroups.Threads) != 0 {
		t.Fatal("a saved original packet bypassed account login or exposed private cards")
	}
	// The base Node actor deliberately uses a RAM-only synthetic account
	// session. Supply its fresh independent account observation, as in that
	// fixture; password/device login belongs to the actual process gate.
	a.c.session = &session
	a.c.sessionInspected, a.c.sessionNeedsCheck = true, false
	a.c.state.AccountState = AccountStateSessionActive
	a.c.publish()
	if !slices.Contains(a.c.Snapshot().AvailableActions, ActionRecoverThreadGroup) {
		t.Fatal("fresh account observation did not expose original recovery")
	}
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}); err != nil {
		t.Fatal(err)
	}
	if a.applyCount != 1 || a.c.hasThreadGroupPending() || a.c.Snapshot().ThreadGroups.Current {
		t.Fatal("restart recovery redispatched or claimed current authorization")
	}
}

func TestThreadGroupActorUnsignedDenialRetainsOriginal(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	a.deny = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil || !a.c.hasThreadGroupPending() {
		t.Fatal("an unsigned HTTP refusal discarded an uncertain apply")
	}
	original := bytes.Clone(a.c.threadGroups.original.Packet)
	if a.applyCount != 0 || a.c.Snapshot().ThreadGroups.Outcome == "GROUP_CREATED" {
		t.Fatal("unsigned refusal reported a management effect")
	}
	s := a.c.Snapshot()
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: s.ThreadGroups.GestureID, Change: "CREATE_GROUP", Name: "replacement must not be sent"}}); err == nil || !bytes.Equal(original, a.c.threadGroups.original.Packet) {
		t.Fatal("a replacement intent displaced the unknown original")
	}
	a.deny = ""
	// The actor now permanently fences the truly unseen apply. The outer
	// response cannot identify its target; only the original nested receipt
	// authenticated against those exact bytes may settle it.
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}); err == nil || a.c.hasThreadGroupPending() {
		t.Fatal("authenticated no-effect fence was mistaken for success or left pending", err)
	}
	if s := a.c.Snapshot(); s.ThreadGroups.ErrorCode != wire.OwnerEndpointGroupsOriginalNotAdmitted || s.ThreadGroups.Review != nil || a.applyCount != 0 || len(a.groups) != 0 {
		t.Fatal("no-effect recovery retained reusable consent or reported a created Group")
	}
}

func TestThreadGroupActorSDKMaximumFieldsFitRecoveryAndSixteenOldSlots(t *testing.T) {
	a := newThreadGroupActor(t)
	a.card.Name, a.card.Workspace = strings.Repeat("<", 256), strings.Repeat("<", 1024)
	legacy := append([]string{appStateNamespace, appSessionNamespace, nodeStateNamespace, nodeRecoveryNamespace, nodeConfirmationNamespace}, pairNamespaces[:]...)
	legacy = append(legacy, localDomainNamespaces[:]...)
	for _, name := range legacy {
		_, version, found, err := a.c.vault.LoadState(name)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			if _, err := a.c.vault.CompareAndSwapState(name, version, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	a.readAndSelect()
	a.candidates()
	s := a.c.Snapshot()
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: s.ThreadGroups.GestureID, Change: "CREATE_GROUP", Name: strings.Repeat("<", 128)}}); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	a.readAndSelect()
	a.candidates()
	s = a.c.Snapshot()
	candidate := s.ThreadGroups.Candidates[0]
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: candidate.GestureID, EndpointID: s.ThreadGroups.Selected.EndpointID, GroupID: candidate.GroupID, Change: "ADD_ENDPOINT", Duration: "30d"}}); err != nil {
		t.Fatal(err)
	}
	if got := a.c.Snapshot().ThreadGroups.Review.PolicyExpiresAt; got != a.local.n.stamp(a.local.n.n2.now.Add(30*24*time.Hour)) {
		t.Fatal("finite business duration changed", got)
	}
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil {
		t.Fatal("lost response reported success")
	}
	original := a.c.threadGroups.original
	request, err := a.c.threadGroupDTO(original, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, proof := threadGroupRequestParts(request)
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(a.c.owner.Public(), proof, wire.OwnerEndpointGroupsOwnerPurpose(original.Route.Operation), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	scope := claims.Scope
	scope.OwnerKeyVersion, scope.AccountEpoch, scope.DeviceEpoch, scope.ClientSessionEpoch = math.MaxInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64
	scope.AccountSessionID = strings.Repeat("s", 128)
	now := a.local.n.n2.now.Add(time.Second).Truncate(time.Second).Add(999999999 * time.Nanosecond)
	scope.AccountSessionExpiresAt = a.local.n.stamp(now.Add(15 * time.Minute))
	actor := a.c.nodeSession()
	actor.AccountEpoch, actor.DeviceEpoch = scope.AccountEpoch, scope.DeviceEpoch
	owner, _ := a.c.owner.E2EE()
	maximum, err := wire.NewOwnerEndpointGroupsReconcile(actor, scope, original.Packet, owner, now)
	if err != nil {
		t.Fatal("SDK maximum coordinate fixture", err)
	}
	maxRecord, err := a.c.newThreadGroupRecord(maximum, original)
	if err != nil {
		t.Fatal(err)
	}
	current, err := a.c.makeThreadGroupRecovery(original, claims.Scope)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := encodeThreadGroupRecord(current)
	if err != nil {
		t.Fatal(err)
	}
	upper, err := encodeThreadGroupRecord(maxRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(upper) > len(actual)+4096 || len(maxRecord.DTO) > 256<<10 {
		t.Fatal("fixed-coordinate reserve or deduplicated header exceeded")
	}
	t.Logf("actual_PQ original_packet=%d maximum_reconcile_packet=%d maximum_reconcile_header=%d maximum_reconcile_record=%d baseline_reconcile_record=%d sixteen_old_slots=true", len(original.Packet), len(maxRecord.Packet), len(maxRecord.DTO), len(upper), len(actual))
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}); err != nil {
		t.Fatal(err)
	}
	if a.c.hasThreadGroupPending() {
		t.Fatal("maximum-field lost response could not recover")
	}
}

func TestThreadGroupActorFutureBudgetRefusesBeforePOSTAndKeepsOpaqueOldState(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepare", true: "apply"}[apply], func(t *testing.T) {
			a := newThreadGroupActor(t)
			if apply {
				a.prepareCreate()
			} else {
				a.readAndSelect()
				a.candidates()
			}
			saved := make(map[string][]byte)
			versions := make(map[string]uint64)
			for _, name := range threadGroupNamespaces {
				raw, version, _, err := a.c.vault.LoadState(name)
				if err != nil {
					t.Fatal(err)
				}
				saved[name], versions[name] = raw, version
				defer clear(raw)
			}
			name := pairNamespaces[pairOriginalResponseRecord]
			_, version, _, err := a.c.vault.LoadState(name)
			if err != nil {
				t.Fatal(err)
			}
			occupied := bytes.Repeat([]byte("synthetic opaque budget occupancy; never a protocol proof"), (1<<20)/56)
			if len(occupied) > 1<<20 {
				occupied = occupied[:1<<20]
			}
			if _, err := a.c.vault.CompareAndSwapState(name, version, occupied); err != nil {
				t.Fatal(err)
			}
			second := pairNamespaces[pairRecoveryResponseRecord]
			_, secondVersion, _, err := a.c.vault.LoadState(second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.c.vault.CompareAndSwapState(second, secondVersion, occupied); err != nil {
				t.Fatal(err)
			}
			s := a.c.Snapshot()
			before := len(a.posts[wire.OperationOwnerEndpointGroupsPrepare]) + len(a.posts[wire.OperationOwnerEndpointGroupsApply])
			if apply {
				err = a.apply()
			} else {
				err = a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: s.ThreadGroups.GestureID, Change: "CREATE_GROUP", Name: "Must not leave this App"}})
			}
			if err == nil || len(a.posts[wire.OperationOwnerEndpointGroupsPrepare])+len(a.posts[wire.OperationOwnerEndpointGroupsApply]) != before || a.c.hasThreadGroupPending() || a.c.Snapshot().ThreadGroups.ErrorCode != "APP_THREAD_GROUP_STORAGE_BUDGET" {
				t.Fatal("full future budget was checked after POST or invented a pending request")
			}
			raw, gotVersion, found, err := a.c.vault.LoadState(name)
			if err != nil || !found || gotVersion != version+1 || !bytes.Equal(raw, occupied) {
				t.Fatal("budget failure evicted old opaque state or changed CAS")
			}
			clear(raw)
			for name, want := range saved {
				raw, version, _, err := a.c.vault.LoadState(name)
				if err != nil || version != versions[name] || !bytes.Equal(raw, want) {
					t.Fatal("pre-POST refusal changed a Group original, receipt, recovery or prior review")
				}
				clear(raw)
			}
		})
	}
}

func TestThreadGroupActorFalseCapabilityAndCancelledReviewCreateNoApply(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		a := newThreadGroupActor(t)
		a.available = false
		a.c.threadGroups.discoveryTried = false
		s := a.c.Snapshot()
		if err := a.c.Dispatch(context.Background(), Action{Kind: ActionReadThreadGroups, ThreadGroups: ThreadGroupAction{GestureID: s.ThreadGroups.GestureID}}); err == nil {
			t.Fatal("false capability permitted a Group read")
		}
		if len(a.posts) != 0 || a.c.hasThreadGroupPending() || a.c.Snapshot().ThreadGroups.Available {
			t.Fatal("availability supplied authority or created an unknown original")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		a := newThreadGroupActor(t)
		a.prepareCreate()
		r := a.c.Snapshot().ThreadGroups.Review
		if err := a.c.Dispatch(context.Background(), Action{Kind: ActionDismissThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID}}); err != nil {
			t.Fatal(err)
		}
		if a.c.Snapshot().ThreadGroups.Review != nil || a.c.hasThreadGroupPending() || len(a.posts[wire.OperationOwnerEndpointGroupsApply]) != 0 {
			t.Fatal("cancelling local consent sent or retained an apply")
		}
	})
}

func TestThreadGroupActorChangedRelationBeforePrepareRequiresFreshRead(t *testing.T) {
	a := newThreadGroupActor(t)
	a.readAndSelect()
	s := a.c.Snapshot()
	r := s.ThreadGroups.Selected.Relations[0]
	a.card.Relations[0].RelationRevision++
	a.card.RelationsRevision++
	err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID, EndpointID: s.ThreadGroups.Selected.EndpointID, GroupID: r.GroupID, Change: "REMOVE_ENDPOINT"}})
	if err == nil || a.c.hasThreadGroupPending() || a.c.Snapshot().ThreadGroups.Review != nil || a.c.Snapshot().ThreadGroups.ErrorCode != "CAS_CONFLICT" || a.applyCount != 0 {
		t.Fatal("a known zero-right preview race trapped pending or reused stale consent")
	}
	a.readAndSelect()
	s = a.c.Snapshot()
	r = s.ThreadGroups.Selected.Relations[0]
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID, EndpointID: s.ThreadGroups.Selected.EndpointID, GroupID: r.GroupID, Change: "REMOVE_ENDPOINT"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
}

func TestThreadGroupActorNetworkChangeHidesPriorCardsAndRequiresFreshRead(t *testing.T) {
	a := newThreadGroupActor(t)
	a.readAndSelect()
	oldView := a.c.Snapshot().ThreadGroups
	// Simulate a different current authenticated local-policy projection.
	// This is an App isolation check, not evidence of a server scope change.
	prior := a.c.localDomain.state.Description
	replacement := *prior
	replacement.Policy.NetworkID, replacement.Policy.NetworkName = "synthetic-other-network", "Synthetic Other Network"
	a.c.localDomain.state.Description = &replacement
	a.c.publish()
	s := a.c.Snapshot()
	if s.ThreadGroups.Current || len(s.ThreadGroups.Threads) != 0 || s.ThreadGroups.Selected != nil || s.ThreadGroups.CanCreate || slices.Contains(s.AvailableActions, ActionPrepareThreadGroup) {
		t.Fatal("prior Network cards were relabeled as current in a different scope")
	}
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: oldView.GestureID, Change: "CREATE_GROUP", Name: "Must not leave the App"}}); err == nil || len(a.posts[wire.OperationOwnerEndpointGroupsPrepare]) != 0 {
		t.Fatal("stale Network gesture sent a prepare")
	}
	a.c.localDomain.state.Description = prior
	a.c.publish()
	a.readAndSelect()
	if !a.c.Snapshot().ThreadGroups.Current {
		t.Fatal("fresh read did not restore the original authenticated scope")
	}
}

func TestThreadGroupActorDifferentLoginWithSameExpiryCannotApplyOldReview(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	before := a.c.Snapshot().ThreadGroups.Review
	if before == nil {
		t.Fatal("synthetic review missing")
	}
	// Epochs and deadline deliberately stay equal; only the current opaque
	// synthetic login token changes. A deadline alone is not a session ID.
	a.c.session.SessionToken = bytes.Repeat([]byte{0x59}, len(a.c.session.SessionToken))
	a.c.publish()
	s := a.c.Snapshot()
	if s.ThreadGroups.Current || len(s.ThreadGroups.Threads) != 0 || slices.Contains(s.AvailableActions, ActionApplyThreadGroup) {
		t.Fatal("a new login inherited the old review or cards")
	}
	if err := a.c.Dispatch(context.Background(), Action{Kind: ActionApplyThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: before.GestureID, Confirm: true}}); err == nil || len(a.posts[wire.OperationOwnerEndpointGroupsApply]) != 0 || a.c.hasThreadGroupPending() {
		t.Fatal("a review was signed under a different account login")
	}
}
