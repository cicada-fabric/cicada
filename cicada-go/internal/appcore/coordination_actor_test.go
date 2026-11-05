package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Actual Controller, encrypted vault and PQC packets with a synthetic Hub actor.
// These tests do not claim a real Hub Store/Guard, Runtime or physical Windows.
type coordinationActor struct {
	t                 *testing.T
	base              *threadGroupActor
	thread            wire.ThreadScopeView
	policy            *wire.GroupCoordinationPolicy
	slots             *wire.GroupSlotView
	reviews           map[string]wire.ThreadCollaborationOwnerReview
	receipts          map[string][]byte
	results           map[string]wire.ThreadCollaborationOwnerResult
	posts             map[string][][]byte
	drop, deny        string
	replayUnavailable bool
	effects           int
	observedSkew      time.Duration
}

func newCoordinationActor(t *testing.T) *coordinationActor {
	// Arrange the retained legacy binding through its private fixture path, then
	// explicitly initialize the current Owner collaboration view. The historical
	// helper assumes enrollment still initializes this view automatically.
	n := newNodeActorFixture(t)
	l := &localCollaborationActor{t: t, n: n, c: n.c, next: n, available: true, capStatus: 200, pageSize: 1, posts: map[string][][]byte{}, receipts: map[string][]byte{}}
	l.c.cfg.HTTP = l
	if err := legacyFixtureDispatch(l.c, context.Background(), Action{Kind: ActionPreviewNode, NodeCode: n.code}); err != nil {
		t.Fatal(err)
	}
	n.approve(t)
	l.c.initializeLocalCollaboration(context.Background())
	l.prepare()
	l.activate()
	b := &threadGroupActor{t: t, local: l, c: l.c, reviews: map[string]wire.OwnerEndpointGroupsReview{}, receipts: map[string][]byte{}, results: map[string]wire.OwnerEndpointGroupsResult{}, posts: map[string][][]byte{}, available: true}
	p := l.challenge.Policy
	source := wire.EndpointGroupSourceReference{Source: "DEFAULT_POLICY", AuthorityID: p.PolicyID, AuthorityEpoch: 1, ContributionRevision: 1}
	r := wire.OwnerEndpointGroupsRelationCard{GroupID: p.GroupID, GroupName: p.GroupName, NetworkID: p.NetworkID, State: "ACTIVE", RelationRevision: 1, OwnerControl: e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, KeyState: "CURRENT", AllowedActions: []string{"REMOVE_ENDPOINT"}, SelectedSource: &source, Contributions: []wire.OwnerEndpointGroupsContributionCard{{Source: source.Source, AuthorityID: source.AuthorityID, AuthorityEpoch: 1, ContributionRevision: 1, State: "ACTIVE", KeyState: "CURRENT", Effective: true}}}
	b.card = wire.OwnerEndpointGroupsThreadCard{EndpointID: "SYNTHETIC-original-thread", PrincipalID: "SYNTHETIC-original-principal", NodeID: p.Node.NodeID, NetworkID: p.NetworkID, Name: "SYNTHETIC Thread", Workspace: "/SYNTHETIC/workspace", Harness: "codex", RegistrationDigest: strings.Repeat("b", 64), RegistrationRevision: 1, Presence: "UNKNOWN", Relations: []wire.OwnerEndpointGroupsRelationCard{r}, RelationStates: []string{"NONE", "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}, RelationsRevision: 1, RelationsComplete: true}
	a := &coordinationActor{t: t, base: b, reviews: map[string]wire.ThreadCollaborationOwnerReview{}, receipts: map[string][]byte{}, results: map[string]wire.ThreadCollaborationOwnerResult{}, posts: map[string][][]byte{}}
	b.c.cfg.HTTP = a
	b.c.threadGroups.discoveryTried = false
	b.c.initializeThreadGroups(context.Background())
	if b.c.threadGroupGesture("read") == "" {
		t.Fatalf("fixture scope not ready: owner=%v node=%v binding=%v description=%v storage=%v", b.c.ownerAccountReady(), b.c.nodeAccountReady(), b.c.selectedNodeBinding() != nil, b.c.localDomain.state.Description != nil, b.c.storageFault)
	}
	b.readAndSelect()
	a.thread = wire.ThreadScopeView{Format: wire.ThreadScopeFormat, HubID: b.c.hub.HubID, NetworkID: b.card.NetworkID, NodeID: b.card.NodeID, EndpointID: b.card.EndpointID, Source: wire.ThreadRegistrationSource{RegistrationID: "SYNTHETIC-original-source", SourceEpoch: 1}, ScopeRevision: 1, State: "CURRENT", Classification: wire.ThreadClassificationWorker, ClassificationRevision: 1, RelationsRevision: 1, ActiveGroupIDs: []string{b.card.Relations[0].GroupID}, ActiveGroupCount: 1, HistoryCoverage: "CICADA_KNOWN_ONLY", RegistrationDigest: b.card.RegistrationDigest}
	return a
}

func (a *coordinationActor) Do(req *http.Request) (*http.Response, error) {
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: req}, nil
	}
	c := a.base.c
	if req.URL.Path == wire.ThreadCollaborationCapabilitiesPath {
		capability, err := wire.NewThreadCollaborationCapabilities(c.hub, "--hub-nodes-only")
		if err != nil {
			a.t.Fatal(err)
		}
		capability.ThreadScopeRoleAvailable, capability.GroupLocksAvailable = true, true
		raw, _ := json.Marshal(capability)
		return reply(raw, 200)
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/owner/thread-collaboration/") {
		return a.base.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	defer clear(raw)
	p, err := wire.DecodeThreadCollaborationOwnerPacket(raw)
	if err != nil {
		a.t.Fatal(err)
	}
	route := p.Packet.Route
	if req.URL.Path != wire.ThreadCollaborationHTTPPath(route.Operation) {
		a.t.Fatal("wrong common route")
	}
	index := coordinationOriginal
	if route.Operation == wire.OperationThreadCollaborationOwnerReconcile {
		index = coordinationQuery
	}
	saved, _, found, err := c.vault.LoadState(coordinationNamespaces[index])
	record, de := decodeCoordinationRecord(saved)
	clear(saved)
	if err != nil || !found || de != nil || !bytes.Equal(record.Packet, raw) {
		a.t.Fatal("Owner POST preceded exact encrypted-vault persistence")
	}
	a.posts[route.Operation] = append(a.posts[route.Operation], bytes.Clone(raw))
	if a.deny == route.Operation {
		return reply([]byte("SYNTHETIC unsigned denial"), 403)
	}
	digest := wire.ThreadCollaborationOwnerPacketDigest(raw)
	if a.replayUnavailable && route.Operation == wire.OperationThreadCollaborationOwnerApply && a.receipts[digest] != nil {
		return reply(nil, 503)
	}
	response := a.receipts[digest]
	if response == nil {
		binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
		open := func(out any) {
			public := c.device.Public()
			if err := wire.OpenRequestAt(a.base.local.n.n2.hubKey, &public, binding, route, raw, out, time.Time{}); err != nil {
				a.t.Fatal("actual PQC open", err)
			}
		}
		now := c.cfg.Now().UTC().Add(a.observedSkew).Format(time.RFC3339Nano)
		result := wire.ThreadCollaborationOwnerResult{Format: wire.ThreadCollaborationOwnerResultFormat, ContractRevision: wire.ThreadCollaborationContractRevision, RequestID: route.OperationID, RequestPacketDigest: digest, HubID: c.hub.HubID, OwnerID: c.state.OwnerID, DeviceID: c.state.DeviceID, ObservedAt: now, OperationID: route.OperationID, OriginalPacketDigest: digest, State: "COMPLETED"}
		switch route.Operation {
		case wire.OperationThreadCollaborationOwnerRead:
			var q wire.ThreadCollaborationOwnerReadRequest
			open(&q)
			read := &wire.ThreadCollaborationOwnerReadResult{HubID: c.hub.HubID, NetworkID: q.Body.NetworkID, View: q.Body.View, ObservedAt: now}
			if q.Body.View == "THREAD_SCOPE" {
				read.Threads = []wire.ThreadScopeView{a.thread}
			} else {
				read.Group = &wire.ThreadCollaborationGroupCard{GroupID: q.Body.GroupID, NetworkID: q.Body.NetworkID, Name: "SYNTHETIC Group", GroupVersion: 1}
				read.GroupPolicy, read.GroupSlots = a.policy, a.slots
				if a.slots != nil {
					a.slots.ObservedAt = now
				}
			}
			result.Read = read
		case wire.OperationThreadCollaborationOwnerPrepare:
			var q wire.ThreadCollaborationOwnerPrepareRequest
			open(&q)
			d, err := wire.ThreadCollaborationOwnerBodyDigest(q.Body)
			if err != nil {
				a.t.Fatal(err)
			}
			id, err := wire.NewRequestID()
			if err != nil {
				a.t.Fatal(err)
			}
			review := wire.ThreadCollaborationOwnerReview{HubID: c.hub.HubID, OwnerID: c.state.OwnerID, DeviceID: c.state.DeviceID, PrepareRequestID: q.Context.RequestID, PreparePacketDigest: digest, ObservedAt: now, ReviewID: id, Action: q.Body.Action, BodyDigest: d, ExpiresAt: c.cfg.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Prepared: q.Body}
			if q.Body.Policy != nil {
				review.TargetGroupID = q.Body.Policy.GroupID
				if review.TargetGroupID == "" {
					review.TargetGroupID = "SYNTHETIC-new-group"
				}
			}
			if q.Body.Clear != nil {
				review.TargetGroupID = q.Body.Clear.Scope.GroupID
			}
			a.reviews[id] = review
			result.Review = &review
		case wire.OperationThreadCollaborationOwnerApply:
			var q wire.ThreadCollaborationOwnerApplyRequest
			open(&q)
			review, ok := a.reviews[q.Body.ReviewID]
			if !ok {
				a.t.Fatal("unknown exact review")
			}
			if c.coordination.review != nil {
				a.t.Fatal("reusable review survived before apply POST")
			}
			if review.Prepared.Role != nil {
				a.thread.Classification = review.Prepared.Role.Classification
				a.thread.ClassificationRevision++
				result.Thread = &a.thread
			} else if change := review.Prepared.Policy; change != nil {
				state := "ENABLED"
				if review.Action == wire.ThreadCollaborationRevokeGroupPolicy {
					state = "REVOKED"
				}
				a.policy = &wire.GroupCoordinationPolicy{Format: wire.GroupCoordinationPolicyFormat, HubID: c.hub.HubID, NetworkID: change.NetworkID, GroupID: review.TargetGroupID, PolicyID: "SYNTHETIC-policy", Revision: change.ExpectedPolicyRevision + 1, State: state, SlotCount: 8, Rights: wire.GroupCoordinationRights(), OwnerConsentDigest: digest}
				result.Policy = a.policy
				a.slots = &wire.GroupSlotView{Format: wire.GroupSlotViewFormat, Scope: wire.GroupLockScope{HubID: c.hub.HubID, NetworkID: change.NetworkID, GroupID: review.TargetGroupID}, PolicyRevision: a.policy.Revision, PolicyState: state, ObservedAt: now}
				for i := 0; i < 8; i++ {
					a.slots.Slots = append(a.slots.Slots, wire.GroupLockSlot{Slot: uint8(i + 1), State: "FREE", Version: 1})
				}
				a.slots.Slots[7] = wire.GroupLockSlot{Slot: 8, State: "HELD", Version: 3, Generation: 2, Holder: &wire.GroupLockHolder{NodeID: "SYNTHETIC-other-node", EndpointID: "SYNTHETIC-other-thread", PrincipalID: "SYNTHETIC-other-principal", Source: wire.ThreadRegistrationSource{RegistrationID: "SYNTHETIC-holder-source", SourceEpoch: 1}}, HolderName: "SYNTHETIC holder", HolderNameState: "VISIBLE", Note: "SYNTHETIC coordination note", ExpiresAt: c.cfg.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)}
			} else if change := review.Prepared.Clear; change != nil {
				slot := &a.slots.Slots[int(change.Slot)-1]
				if slot.Version != change.ExpectedVersion || slot.Generation != change.Generation {
					result.State, result.ErrorCode = "REJECTED", wire.ThreadCollaborationErrorVersionConflict
				} else {
					result.Lock = &wire.GroupLockReceipt{Format: wire.GroupLockReceiptFormat, Scope: change.Scope, Slot: change.Slot, OperationID: q.Context.RequestID, RequestDigest: digest, AppliedVersion: change.ExpectedVersion + 1, Generation: change.Generation, Outcome: "OWNER_CLEARED", ObservedAt: now}
					*slot = wire.GroupLockSlot{Slot: change.Slot, State: "FREE", Version: change.ExpectedVersion + 1, Generation: change.Generation}
				}
			}
			if result.State == "COMPLETED" {
				a.effects++
			}
		case wire.OperationThreadCollaborationOwnerReconcile:
			var q wire.ThreadCollaborationOwnerReconcileRequest
			open(&q)
			d := wire.ThreadCollaborationOwnerPacketDigest(q.Body.OriginalPacket)
			original, e := wire.DecodeThreadCollaborationOwnerPacket(q.Body.OriginalPacket)
			if e != nil {
				a.t.Fatal(e)
			}
			result.OperationID, result.OriginalPacketDigest = original.Packet.Route.OperationID, d
			if a.receipts[d] == nil {
				a.t.Fatal("fixture expected an original receipt")
			}
			result.State, result.ReceiptPacket = "ORIGINAL_RECEIPT", a.receipts[d]
		default:
			a.t.Fatal("unexpected shared operation")
		}
		response, err = wire.SealResponse(a.base.local.n.n2.hubKey, c.device.Public(), route, result)
		if err != nil {
			a.t.Fatal("actual PQC response", route.Operation, result.State, err)
		}
		a.receipts[digest], a.results[digest] = bytes.Clone(response), result
	}
	if a.drop == route.Operation {
		a.drop = ""
		return nil, errors.New("SYNTHETIC loss after effect")
	}
	return reply(response, 200)
}

func (a *coordinationActor) readRole() {
	a.t.Helper()
	s := a.base.c.Snapshot()
	t := s.ThreadGroups.Selected
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionReadThreadCoordination, Coordination: CoordinationAction{EndpointID: t.EndpointID, GestureID: t.CoordinationGestureID}}); err != nil {
		a.t.Fatal(err)
	}
}
func (a *coordinationActor) readLocks() {
	a.t.Helper()
	s := a.base.c.Snapshot()
	r := s.ThreadGroups.Selected.Relations[0]
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionReadGroupCoordination, Coordination: CoordinationAction{GroupID: r.GroupID, GestureID: r.CoordinationGestureID}}); err != nil {
		a.t.Fatal(err)
	}
}
func (a *coordinationActor) preparePolicy() {
	a.t.Helper()
	a.readLocks()
	r := a.base.c.Snapshot().ThreadGroups.Selected.Relations[0]
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionPrepareCoordination, Coordination: CoordinationAction{Change: wire.ThreadCollaborationEnableGroupPolicy, GroupID: r.GroupID, GestureID: r.Locks.GestureID}}); err != nil {
		a.t.Fatal(err)
	}
}
func (a *coordinationActor) apply() error {
	a.t.Helper()
	review := a.base.c.Snapshot().Coordination.Review
	if review == nil {
		a.t.Fatal("missing authenticated review")
	}
	return a.base.c.Dispatch(context.Background(), Action{Kind: ActionApplyCoordination, Coordination: CoordinationAction{GestureID: review.GestureID, Confirm: true}})
}

func TestCoordinationOwnerRolePolicyClearRequiresExactConfirmation(t *testing.T) {
	a := newCoordinationActor(t)
	a.readRole()
	s := a.base.c.Snapshot()
	thread := s.ThreadGroups.Selected
	if thread.Classification == nil || thread.Classification.Classification != "worker" {
		t.Fatal("authenticated role absent")
	}
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionPrepareCoordination, Coordination: CoordinationAction{Change: wire.ThreadCollaborationSetClassification, EndpointID: thread.EndpointID, GestureID: thread.Classification.GestureID, Classification: "advisor"}}); err != nil {
		t.Fatal(err)
	}
	review := a.base.c.Snapshot().Coordination.Review
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionApplyCoordination, Coordination: CoordinationAction{GestureID: review.GestureID}}); err == nil || a.effects != 0 {
		t.Fatal("no consent became management success")
	}
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	if a.thread.Classification != "advisor" || a.effects != 1 {
		t.Fatal("exact role change absent")
	}
	a.preparePolicy()
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	a.readLocks()
	r := a.base.c.Snapshot().ThreadGroups.Selected.Relations[0]
	slot := r.Locks.Slots[7]
	if slot.State != GroupLockHeld || slot.HolderName != "SYNTHETIC holder" || slot.ExpiresAt == "" || !slot.CanClear {
		t.Fatal("authenticated slot eight absent")
	}
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionPrepareCoordination, Coordination: CoordinationAction{Change: wire.ThreadCollaborationClearOneSlot, GroupID: r.GroupID, Slot: 8, GestureID: slot.GestureID}}); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	if a.effects != 3 || a.slots.Slots[7].State != "FREE" {
		t.Fatal("clear changed another slot or was not confirmed")
	}
}

func TestCoordinationOriginalAndQuerySurviveLossAndRestart(t *testing.T) {
	a := newCoordinationActor(t)
	a.preparePolicy()
	a.drop = wire.OperationThreadCollaborationOwnerApply
	session := *a.base.c.session
	session.SessionToken = bytes.Clone(session.SessionToken)
	owner, device := a.base.c.owner.Public().ID, a.base.c.device.Public().ID
	if a.apply() == nil {
		t.Fatal("lost apply response reported success")
	}
	original := bytes.Clone(a.base.c.coordination.original.Packet)
	a.base.local.reopen()
	a.base.c = a.base.local.c
	a.base.c.cfg.HTTP = a
	if a.base.c.owner.Public().ID != owner || a.base.c.device.Public().ID != device || !a.base.c.hasCoordinationPending() || !bytes.Equal(original, a.base.c.coordination.original.Packet) {
		t.Fatal("restart changed identity or original")
	}
	if s := a.base.c.Snapshot(); s.Coordination.Review != nil || s.ThreadGroups.Selected != nil {
		t.Fatal("restart exposed private management state before login")
	}
	// Independent synthetic account observation, as in the existing actor base.
	a.base.c.session = &session
	a.base.c.sessionInspected, a.base.c.sessionNeedsCheck = true, false
	a.base.c.state.AccountState = AccountStateSessionActive
	a.base.c.publish()
	a.replayUnavailable = true
	a.drop = wire.OperationThreadCollaborationOwnerReconcile
	if a.base.c.Dispatch(context.Background(), Action{Kind: ActionRecoverCoordination}) == nil || !a.base.c.hasCoordinationPending() {
		t.Fatal("lost reconcile discarded unknown original")
	}
	query := bytes.Clone(a.base.c.coordination.query.Packet)
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionRecoverCoordination}); err != nil {
		t.Fatal(err)
	}
	posts := a.posts[wire.OperationThreadCollaborationOwnerReconcile]
	if a.effects != 1 || a.base.c.hasCoordinationPending() || len(posts) != 2 || !bytes.Equal(query, posts[0]) || !bytes.Equal(posts[0], posts[1]) || !bytes.Equal(original, a.base.c.coordination.original.Packet) {
		t.Fatal("recovery resealed originals, repeated effects or claimed unconfirmed success")
	}
}

func TestCoordinationUnsignedHTTPDenialCannotDiscardOrReplaceOriginal(t *testing.T) {
	a := newCoordinationActor(t)
	a.preparePolicy()
	a.deny = wire.OperationThreadCollaborationOwnerApply
	if a.apply() == nil || !a.base.c.hasCoordinationPending() {
		t.Fatal("unsigned denial discarded original")
	}
	original := bytes.Clone(a.base.c.coordination.original.Packet)
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionPrepareCoordination, Coordination: CoordinationAction{Change: wire.ThreadCollaborationCreateGroupWithPolicy, Name: "SYNTHETIC replacement"}}); err == nil {
		t.Fatal("unknown original was replaced")
	}
	if a.effects != 0 || a.base.c.Snapshot().Coordination.Outcome != "" || !bytes.Equal(original, a.base.c.coordination.original.Packet) {
		t.Fatal("unsigned HTTP became success or changed original bytes")
	}
}

func TestCoordinationAuthenticatedReadsKeepIndependentFreshness(t *testing.T) {
	a := newCoordinationActor(t)
	a.readRole()
	start := a.base.c.cfg.Now().UTC()
	a.base.c.cfg.Now = func() time.Time { return start.Add(20 * time.Second) }
	a.readLocks()
	s := a.base.c.Snapshot()
	thread := s.ThreadGroups.Selected
	if thread.Classification == nil || !thread.Classification.Current || thread.Relations[0].Locks == nil || !thread.Relations[0].Locks.Current {
		t.Fatal("one authenticated read erased the other")
	}
	a.base.c.cfg.Now = func() time.Time { return start.Add(31 * time.Second) }
	s = a.base.c.Snapshot()
	thread = s.ThreadGroups.Selected
	if thread.Classification.Current || thread.Classification.CanChange || !thread.Relations[0].Locks.Current || !thread.Relations[0].Locks.CanEnable || s.Coordination.FreshUntil != start.Add(50*time.Second).Format(time.RFC3339Nano) {
		t.Fatal("one deadline expired another independent observation or kept stale role authority")
	}
}

func TestCoordinationOwnerCanClearRevokedPolicyAndRejectsChangedGeneration(t *testing.T) {
	a := newCoordinationActor(t)
	a.preparePolicy()
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	a.readLocks()
	r := a.base.c.Snapshot().ThreadGroups.Selected.Relations[0]
	if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionPrepareCoordination, Coordination: CoordinationAction{Change: wire.ThreadCollaborationRevokeGroupPolicy, GroupID: r.GroupID, GestureID: r.Locks.GestureID}}); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	a.readLocks()
	r = a.base.c.Snapshot().ThreadGroups.Selected.Relations[0]
	slot := r.Locks.Slots[7]
	if r.Locks.PolicyState != "REVOKED" || r.Locks.CanRevoke || !slot.CanClear {
		t.Fatal("Owner clear incorrectly requires enabling policy again")
	}
	prepare := func() {
		t.Helper()
		if err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionPrepareCoordination, Coordination: CoordinationAction{Change: wire.ThreadCollaborationClearOneSlot, GroupID: r.GroupID, Slot: 8, GestureID: slot.GestureID}}); err != nil {
			t.Fatal(err)
		}
	}
	prepare()
	a.slots.Slots[7].Generation++
	a.slots.Slots[7].Version++
	if a.apply() == nil || a.effects != 2 || a.base.c.Snapshot().Coordination.Outcome != "" || a.base.c.hasCoordinationPending() {
		t.Fatal("changed holder generation became success or lost a known refusal")
	}
	a.readLocks()
	r = a.base.c.Snapshot().ThreadGroups.Selected.Relations[0]
	slot = r.Locks.Slots[7]
	prepare()
	if err := a.apply(); err != nil {
		t.Fatal(err)
	}
	if a.effects != 3 || a.slots.Slots[7].State != "FREE" {
		t.Fatal("exact Owner clear of revoked policy failed")
	}
}

func TestCoordinationReadClockSkewUsesUTCInstantAndThirtySecondWindow(t *testing.T) {
	for _, skew := range []time.Duration{-31 * time.Second, -10 * time.Millisecond, 10 * time.Millisecond, 31 * time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			a := newCoordinationActor(t)
			a.observedSkew = skew
			instant := a.base.c.cfg.Now()
			a.base.c.cfg.Now = func() time.Time { return instant.In(time.FixedZone("SYNTHETIC-UTC+8", 8*3600)) }
			thread := a.base.c.Snapshot().ThreadGroups.Selected
			err := a.base.c.Dispatch(context.Background(), Action{Kind: ActionReadThreadCoordination, Coordination: CoordinationAction{EndpointID: thread.EndpointID, GestureID: thread.CoordinationGestureID}})
			fresh := a.base.c.Snapshot().ThreadGroups.Selected.Classification
			if skew < -30*time.Second || skew > 30*time.Second {
				if err == nil || fresh != nil && fresh.Current {
					t.Fatal("out-of-window server time became a current role")
				}
			} else if err != nil || fresh == nil || !fresh.Current {
				t.Fatal("small clock skew or a timezone label rejected the same UTC instant", err)
			}
		})
	}
}
