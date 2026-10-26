package n3_test

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The scenario's restarted App outlives its subtest and is cleaned by the
// parent fixture. Assertions still belong to the current measured case.
func restartOwnerGroupsApp(t *testing.T, v *codexProductFixture) ownerGroupsPanel {
	t.Helper()
	marker := filepath.Join(v.f.dir, "owner-groups-resume-"+must(wire.NewRequestID())+".json")
	v.app = startAppProcess(v.f.parent, v.f, "resume-node", marker)
	v.sequence = 0
	awaitMarker(t, v.app.process, marker)
	var checkpoint appActorCheckpoint
	readJSON(t, marker, &checkpoint)
	assertOwnerDirectoryIdentity(t, v.endpointSecurityFixture, checkpoint.Current)
	return actualOwnerGroupsPanel(t, checkpoint.Current)
}

func oneOwnerGroupsExchange(t *testing.T, trace []exchange, operation string) exchange {
	t.Helper()
	var matched []exchange
	for _, ex := range trace {
		if ex.Path == wire.OwnerEndpointGroupsHTTPPath(operation) {
			matched = append(matched, ex)
		}
	}
	if len(matched) != 1 {
		t.Fatal("actual App did not dispatch exactly one packet for the expected Group operation")
	}
	return matched[0]
}

// A real App action, actual TCP fault and process crash. Recovery is performed
// by the restarted Controller using its protected original. The parent only
// opens evidence after stopping that App; it never signs a positive mutation.
func exerciseOwnerGroupsLostApply(t *testing.T, v *codexProductFixture, review ownerGroupsPanel, fault string, wantFence bool) wire.OwnerEndpointGroupsResult {
	t.Helper()
	_, release := armOwnerGroupsFault(t, v.f.proxy, fault)
	reply, pending, trace := applyOwnerGroupsReview(t, v, review)
	release()
	if !reply.ActionFailed || !pending.Pending || pending.Current || pending.NodeID != review.NodeID || pending.NetworkID != review.NetworkID {
		t.Fatal("unconfirmed actual APPLY was cleared or exposed as current authority")
	}
	originalExchange := oneOwnerGroupsExchange(t, trace, wire.OperationOwnerEndpointGroupsApply)
	if (wantFence && originalExchange.Forwarded) || (!wantFence && (!originalExchange.Forwarded || originalExchange.Status != http.StatusOK || len(originalExchange.response) == 0)) {
		t.Fatal("actual TCP fault did not reach the intended original admission boundary")
	}
	// A new mutation must not replace this immutable unresolved original.
	blocked, blockedView, blockedTrace := ownerGroupsAppGesture(t, v, appcore.ActionApplyThreadGroup, ownerGroupsGesture{
		GestureID: review.Review.GestureID, Confirm: true})
	if !blocked.ActionFailed || !blockedView.Pending || len(blockedTrace) != 0 {
		t.Fatal("uncertain original allowed another App mutation or redispatch")
	}
	v.app.kill(t)
	original, request := ownerGroupsOriginalApply(t, v, originalExchange)
	v.f.hub.kill(t)
	v.f.start(t)
	from := len(v.f.proxy.snapshot())
	current := restartOwnerGroupsApp(t, v)
	if current.Pending {
		_, current, _ = ownerGroupsAppGesture(t, v, appcore.ActionRecoverThreadGroup, ownerGroupsGesture{})
	}
	if current.Pending || current.Current || (wantFence && current.ErrorCode != wire.OwnerEndpointGroupsOriginalNotAdmitted) ||
		(!wantFence && current.ErrorCode != "") {
		t.Fatal("actual restarted App did not settle the exact original receipt safely")
	}
	recoveryTrace := ownerGroupsTrace(v.f, from)
	for _, ex := range recoveryTrace {
		if ex.Path == wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply) {
			t.Fatal("original recovery redispatched a business APPLY")
		}
	}
	wrapper := oneOwnerGroupsExchange(t, recoveryTrace, wire.OperationOwnerEndpointGroupsReconcile)
	if !wrapper.Forwarded || wrapper.Status != http.StatusOK || len(wrapper.response) == 0 {
		t.Fatal("actual recovery lacks an authenticated sealed response")
	}
	closeLocalDomainApp(t, v)
	result := ownerGroupsOriginalReceipt(t, v, original, request, wrapper, wantFence)
	if wantFence {
		// Exact direct APPLY after the fence must return the same no-effect
		// original receipt. Fresh proof/review at the first recovery cannot
		// authorize late execution of this sealed old intent.
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		httpRequest := must(http.NewRequest(http.MethodPost, v.f.cfg.Origin+wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply), bytes.NewReader(original.packet)))
		httpRequest.Header.Set("Content-Type", "application/json")
		response := must(client.Do(httpRequest))
		raw := must(io.ReadAll(io.LimitReader(response.Body, wire.MaxOwnerEndpointGroupsPacketBytes+1)))
		response.Body.Close()
		defer clear(raw)
		if response.StatusCode != http.StatusOK || len(raw) > wire.MaxOwnerEndpointGroupsPacketBytes {
			t.Fatal("direct original APPLY did not return its permanent sealed fence")
		}
		device := ownedAppIdentity(t, v.f, appvault.PurposeAppDevice)
		accepted := ownerGroupsStoredPacketAt(t, v, "appcore.endpoint-groups-response.v1")
		replayed := openOwnerGroupsCapturedResponse(t, v, device, request, original.packet, raw)
		if wire.VerifyOwnerEndpointGroupsOriginalFence(request, original.packet, replayed, v.f.cfg.Hub) != nil ||
			!bytes.Equal(raw, accepted.packet) || replayed.RequestID != result.RequestID || replayed.RequestPacketDigest != result.RequestPacketDigest || replayed.CapturedAt != result.CapturedAt {
			t.Fatal("late original APPLY escaped or replaced its immutable no-effect fence")
		}
	}
	_ = restartOwnerGroupsApp(t, v)
	return result
}

func ownerGroupsCandidateNamed(t *testing.T, panel ownerGroupsPanel, name string) ownerGroupsCandidateCard {
	t.Helper()
	var found []ownerGroupsCandidateCard
	for _, candidate := range panel.Candidates {
		if candidate.Name == name {
			found = append(found, candidate)
		}
	}
	if !panel.CandidatesLoaded || len(found) != 1 || found[0].GroupID == "" {
		t.Fatal("actual fresh candidate list lacks one exact named Group")
	}
	return found[0]
}

func awaitOwnerGroupsRelation(t *testing.T, v *codexProductFixture, network string, identity ownerGroupsIdentity, group, state, mode string) ownerGroupsRelationCard {
	t.Helper()
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) {
		panel := selectOwnerGroupsThread(t, v, network, identity)
		var found []ownerGroupsRelationCard
		for _, relation := range panel.Selected.Relations {
			if relation.GroupID == group {
				found = append(found, relation)
			}
		}
		if len(found) > 1 {
			t.Fatal("actual private relation list repeated an exact Endpoint/Group")
		}
		if len(found) == 1 && found[0].State == state && found[0].OwnerMode == mode {
			if state == "ACTIVE" && found[0].KeyState != "CURRENT" {
				t.Fatal("actual ACTIVE relation lacks its exact completed key projection")
			}
			return found[0]
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("actual Endpoint Group relation did not reach the required current state")
	return ownerGroupsRelationCard{}
}

// CREATE is separate from ADD. An unseen original is permanently fenced first;
// a later explicit Owner review/new ID creates exactly one G2. Lost committed
// response is then recovered without replaying business or adding D implicitly.
func exerciseOwnerGroupsCreateRecovery(t *testing.T, v *codexProductFixture, actors nativePeerActors, identity ownerGroupsIdentity) string {
	t.Helper()
	const name = "Synthetic Owner Group G2"
	network := actors.active.NetworkID
	if ownerGroupsNamedGroupCount(t, v, network, name) != 0 {
		t.Fatal("isolated G2 create started with an existing named Group")
	}
	panel := selectOwnerGroupsThread(t, v, network, identity)
	panel = ownerGroupsCandidates(t, v, panel)
	panel = prepareOwnerGroupsChange(t, v, panel, wire.OwnerEndpointGroupsCreateGroup, "", name, "")
	fenced := exerciseOwnerGroupsLostApply(t, v, panel, "apply-before-forward", true)
	if ownerGroupsNamedGroupCount(t, v, network, name) != 0 || fenced.Operation != nil {
		t.Fatal("reconciling an unseen original created business state")
	}
	panel = selectOwnerGroupsThread(t, v, network, identity)
	panel = ownerGroupsCandidates(t, v, panel)
	panel = prepareOwnerGroupsChange(t, v, panel, wire.OwnerEndpointGroupsCreateGroup, "", name, "")
	created := exerciseOwnerGroupsLostApply(t, v, panel, "apply-lost-response", false)
	if created.Operation == nil || created.Operation.Action != wire.OwnerEndpointGroupsCreateGroup || created.Operation.OperationID == fenced.RequestID ||
		ownerGroupsNamedGroupCount(t, v, network, name) != 1 {
		t.Fatal("new explicit Owner create did not produce exactly one distinct G2 intent")
	}
	panel = selectOwnerGroupsThread(t, v, network, identity)
	panel = ownerGroupsCandidates(t, v, panel)
	g2 := ownerGroupsCandidateNamed(t, panel, name)
	if !g2.CanAdd || g2.GroupID != created.Operation.Target.GroupID || ownerGroupsRelationCount(t, v, identity.Endpoint, g2.GroupID) != 0 {
		t.Fatal("creating G2 silently added the selected Endpoint or changed the returned Group")
	}
	for _, relation := range panel.Selected.Relations {
		if relation.GroupID == g2.GroupID {
			t.Fatal("CREATE manufactured an Endpoint/Group relation before its separate ADD review")
		}
	}
	return g2.GroupID
}
