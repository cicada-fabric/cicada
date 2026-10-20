package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Synthetic crypto actor around production Core/vault/wire. Store/real TCP,
// Windows and native Codex runtime acceptance belong to their own gates.
type ownerEndpointActor struct {
	node               *nodeActorFixture
	capMode, fault     string
	posts              [][]byte
	receipts           map[string][]byte
	wrongNode, expired bool
}

func newOwnerEndpointActor(t *testing.T) *ownerEndpointActor {
	t.Helper()
	f := newNodeActorFixture(t)
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: f.code}); err != nil {
		t.Fatal(err)
	}
	f.approve(t)
	a := &ownerEndpointActor{node: f, receipts: map[string][]byte{}}
	f.c.cfg.HTTP = a
	f.c.publish()
	if f.c.Snapshot().OwnerEndpoints.ReviewID == "" {
		t.Fatal("confirmed original Node did not expose a read gesture")
	}
	return a
}

func (a *ownerEndpointActor) Do(request *http.Request) (*http.Response, error) {
	if request.URL.Path != wire.OwnerEndpointReadPath {
		return a.node.Do(request)
	}
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), Request: request}, nil
	}
	f := a.node
	if request.Method == http.MethodGet {
		if a.capMode == "404" {
			return reply(nil, 404)
		}
		fp, _ := wire.HubFingerprint(f.c.hub)
		cap := wire.OwnerEndpointReadCapabilities{Format: wire.OwnerEndpointReadCapabilitiesFormat, ContractRevision: wire.OwnerEndpointReadContractRevision,
			Available: a.capMode != "disabled", HubID: f.c.hub.HubID, HubFingerprint: fp, MaxPageRows: 64, MaxPageBytes: wire.MaxOwnerEndpointPageBytes, MaxProofSeconds: 60}
		if a.capMode == "wrong-hub" {
			cap.HubID = "synthetic_other_hub"
		}
		if a.capMode == "old-format" {
			cap.Format = "synthetic.unsupported.v0"
		}
		raw, _ := json.Marshal(cap)
		if a.capMode == "oversized" {
			raw = bytes.Repeat([]byte("x"), wire.MaxOwnerEndpointCapabilitiesBytes+1)
		}
		return reply(raw, 200)
	}
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	a.posts = append(a.posts, bytes.Clone(raw))
	saved, _, found, err := f.c.vault.LoadState(nodeStateNamespace)
	if err != nil || !found {
		f.t.Fatal("directory POST preceded persistence")
	}
	var durable nodeAuthorityState
	if decodeStateJSON(saved, &durable) != nil || durable.Pending == nil || durable.Pending.OwnerEndpointRead == nil || !bytes.Equal(durable.Pending.Request, raw) {
		f.t.Fatal("directory packet differs from durable original")
	}
	clear(saved)
	if a.fault == "403" {
		return reply(nil, 403)
	}
	digest := wire.AppNodePacketDigest(raw)
	if response := a.receipts[digest]; response != nil {
		return reply(bytes.Clone(response), 200)
	}
	packet, err := wire.PreflightRequest(raw, wire.OperationOwnerEndpointRead)
	if err != nil {
		f.t.Fatal(err)
	}
	binding := clientwire.Binding{HubID: f.scope.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
	var q wire.OwnerEndpointReadRequest
	pub := f.scope.DevicePublic
	if err := wire.OpenRequestAt(f.n2.hubKey, &pub, binding, packet.Packet.Route, raw, &q, time.Time{}); err != nil {
		f.t.Fatal(err)
	}
	claims, err := e2ee.VerifyOwnerEndpointRead(f.c.owner.Public(), q.OwnerProof, time.Time{})
	if err != nil || !reflect.DeepEqual(claims.Node, f.bindingDTO()) || !bytes.Equal(q.SessionToken, f.token) {
		f.t.Fatal("directory did not use the original Owner/Node and independent proof", err)
	}
	card := wire.OwnerEndpointCard{EndpointID: "synthetic_endpoint_a", Name: "合成 Thread A", Workspace: "/synthetic/workspace/" + strings.Repeat("long-path/", 48), Harness: "codex", Presence: "offline"}
	if claims.Cursor != "" {
		card.EndpointID, card.Name = "synthetic_endpoint_b", "Synthetic Thread B"
	}
	result := wire.OwnerEndpointReadResult{Format: wire.OwnerEndpointReadResultFormat, RequestID: q.Context.RequestID, RequestPacketDigest: digest,
		HubID: f.scope.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, NodeID: claims.Node.NodeID, State: wire.AppNodeCompleted,
		CapturedAt: f.stamp(f.n2.now), Freshness: "SNAPSHOT_ONLY", Endpoints: []wire.OwnerEndpointCard{card}}
	if claims.Cursor == "" {
		result.NextCursor = card.EndpointID
	}
	if a.wrongNode {
		result.NodeID = "synthetic_foreign_node"
	}
	if a.expired {
		result.State, result.Endpoints, result.NextCursor = wire.AppNodeReadExpired, []wire.OwnerEndpointCard{}, ""
	}
	response, err := wire.SealResponse(f.n2.hubKey, f.scope.DevicePublic, packet.Packet.Route, result)
	if err != nil {
		f.t.Fatal(err)
	}
	if !a.wrongNode {
		a.receipts[digest] = bytes.Clone(response)
	}
	if a.fault == "drop" {
		a.fault = ""
		return nil, errors.New("synthetic committed directory response lost")
	}
	return reply(response, 200)
}

func (a *ownerEndpointActor) readAction(next bool) Action {
	s := a.node.c.Snapshot().OwnerEndpoints
	q := OwnerEndpointReadAction{ReviewID: s.ReviewID, Limit: 64, ConfirmRead: true}
	if next {
		q.ReviewID, q.Cursor = s.NextReviewID, s.NextCursor
	}
	return Action{Kind: ActionReadOwnerEndpoints, OwnerEndpoints: q}
}

func TestOwnerEndpointsRequiresExactGestureAndNeverGrantsManagement(t *testing.T) {
	a := newOwnerEndpointActor(t)
	c := a.node.c
	ownerID, deviceID := c.owner.Public().ID, c.device.Public().ID
	version := c.nodeVer
	for _, mutate := range []func(*Action){func(q *Action) { q.OwnerEndpoints.ConfirmRead = false }, func(q *Action) { q.OwnerEndpoints.ReviewID = "synthetic-wrong-target" }, func(q *Action) { q.OwnerEndpoints.Limit = 65 }} {
		q := a.readAction(false)
		mutate(&q)
		if c.Dispatch(context.Background(), q) == nil || len(a.posts) != 0 || c.nodeVer != version {
			t.Fatal("unconfirmed/changed read signed or wrote state")
		}
	}
	if err := c.Dispatch(context.Background(), a.readAction(false)); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.OwnerEndpoints.State != "SNAPSHOT_ONLY" || len(s.OwnerEndpoints.Endpoints) != 1 || s.Management == ManagementAuthorized || s.Canvas.State != CanvasNoAuthorization {
		t.Fatal("directory became live/management/canvas authority", s.OwnerEndpoints.State)
	}
	if c.owner.Public().ID != ownerID || c.device.Public().ID != deviceID || !s.OwnerEndpoints.Available || s.OwnerEndpoints.NextReviewID == "" {
		t.Fatal("directory changed keys or lost page review")
	}
	if c.state.Enrollment == nil || c.cfg.Now().Before(parseExpiry(c.state.Enrollment.Challenge.Binding.LeaseExpiresAt)) {
		t.Fatal("fixture failed to use expired old N2 operation TTL")
	}
	s.OwnerEndpoints.Endpoints[0].Name = "MUTATED_SNAPSHOT"
	if c.Snapshot().OwnerEndpoints.Endpoints[0].Name == "MUTATED_SNAPSHOT" {
		t.Fatal("snapshot aliases controller state")
	}
	if err := c.Dispatch(context.Background(), a.readAction(true)); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().OwnerEndpoints.Endpoints[0].EndpointID != "synthetic_endpoint_b" || len(a.posts) != 2 || bytes.Equal(a.posts[0], a.posts[1]) {
		t.Fatal("next page reused a signature or wrong page")
	}
}

func TestOwnerEndpointsUnsupportedCapabilityMakesNoPendingOrSecretPost(t *testing.T) {
	for _, mode := range []string{"404", "wrong-hub", "old-format", "oversized", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			a := newOwnerEndpointActor(t)
			a.capMode = mode
			c := a.node.c
			version, pending := c.nodeVer, c.node.Pending
			if c.Dispatch(context.Background(), a.readAction(false)) == nil || len(a.posts) != 0 || c.nodeVer != version || c.node.Pending != pending || c.hasOwnerEndpointPending() {
				t.Fatal("unavailable capability created a new request/state")
			}
		})
	}
}

func TestOwnerEndpointsUnsignedErrorWrongTargetAndRestartRetainOriginalPacket(t *testing.T) {
	a := newOwnerEndpointActor(t)
	c := a.node.c
	ownerID, deviceID := c.owner.Public().ID, c.device.Public().ID
	a.fault = "drop"
	if c.Dispatch(context.Background(), a.readAction(false)) == nil || !c.hasOwnerEndpointPending() {
		t.Fatal("lost response was settled")
	}
	if c.Snapshot().Node.Pending || c.Snapshot().Node.ErrorCode != "" || !c.Snapshot().OwnerEndpoints.Pending || containsAction(c.Snapshot().AvailableActions, ActionRefreshNode) {
		t.Fatal("directory uncertainty was attributed to another operation or allowed a new Node read")
	}
	original := bytes.Clone(c.node.Pending.Request)
	a.fault, a.capMode = "403", "404"
	if c.Dispatch(context.Background(), Action{Kind: ActionRecoverOwnerEndpoints}) == nil || !bytes.Equal(original, c.node.Pending.Request) || len(c.node.Pending.Response) != 0 {
		t.Fatal("unsigned 403 settled/replaced uncertain read")
	}
	if c.Dispatch(context.Background(), a.readAction(false)) == nil || len(a.posts) != 2 {
		t.Fatal("uncertain read allowed another original")
	}
	a.fault = ""
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	a.node.c = a.node.n2.controller(t, a.node.root).(*nativeController)
	a.node.c.cfg.HTTP = a
	c = a.node.c
	if err := c.Dispatch(context.Background(), Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := c.Snapshot().Profiles
	if len(profiles) != 1 {
		t.Fatal("original profile lost")
	}
	if err := c.Dispatch(context.Background(), Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	if c.hasOwnerEndpointPending() {
		if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverOwnerEndpoints}); err != nil {
			t.Fatal(err)
		}
	}
	if c.hasOwnerEndpointPending() || len(a.posts) < 3 || !bytes.Equal(a.posts[len(a.posts)-1], original) || c.owner.Public().ID != ownerID || c.device.Public().ID != deviceID {
		t.Fatal("restart changed original packet or identity")
	}
	if c.ownerEndpointResult == nil || c.ownerEndpointResult.State != wire.AppNodeCompleted || c.node.OwnerDirectory == nil || !c.node.OwnerDirectory.Applied || c.Snapshot().Management == ManagementAuthorized {
		t.Fatal("authenticated original directory receipt was not restored")
	}
	// The existing Node actor's manually installed account session is not a
	// persisted login receipt. Recovery must not manufacture a fresh login.
	if !c.nodeAccountReady() && (len(c.Snapshot().OwnerEndpoints.Endpoints) != 0 || c.Snapshot().OwnerEndpoints.NodeID != "") {
		t.Fatal("restored historical directory bypassed current account login")
	}
}

func TestOwnerEndpointsAuthenticatedForeignTargetCannotSettle(t *testing.T) {
	a := newOwnerEndpointActor(t)
	a.wrongNode = true
	c := a.node.c
	if c.Dispatch(context.Background(), a.readAction(false)) == nil || !c.hasOwnerEndpointPending() || len(c.node.Pending.Response) != 0 || len(c.Snapshot().OwnerEndpoints.Endpoints) != 0 {
		t.Fatal("foreign target receipt was adopted")
	}
	original := bytes.Clone(c.node.Pending.Request)
	a.wrongNode = false
	if err := c.Dispatch(context.Background(), Action{Kind: ActionRecoverOwnerEndpoints}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.posts[len(a.posts)-1], original) {
		t.Fatal("wrong target replaced original request")
	}
}

func TestOwnerEndpointsExpiredReadAndAccountDecayCannotShowPermission(t *testing.T) {
	a := newOwnerEndpointActor(t)
	a.expired = true
	c := a.node.c
	if err := c.Dispatch(context.Background(), a.readAction(false)); err != nil {
		t.Fatal(err)
	}
	if c.hasOwnerEndpointPending() || c.Snapshot().OwnerEndpoints.State != "READ_EXPIRED" || len(c.Snapshot().OwnerEndpoints.Endpoints) != 0 {
		t.Fatal("expired signed read was shown as usable rows")
	}
	a.expired = false
	if err := c.Dispatch(context.Background(), a.readAction(false)); err != nil {
		t.Fatal(err)
	}
	version, posts := c.nodeVer, len(a.posts)
	a.node.n2.now = parseExpiry(c.session.ExpiresAt)
	s := c.Snapshot()
	if len(s.OwnerEndpoints.Endpoints) != 0 || s.OwnerEndpoints.ReviewID != "" || containsAction(s.AvailableActions, ActionReadOwnerEndpoints) || s.Management == ManagementAuthorized || c.nodeVer != version || len(a.posts) != posts {
		t.Fatal("clock expiry retained directory or performed network/state work")
	}
}
