package n3_test

import (
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Verify captured actual App packets using the formally delivered SDK. Caller
// obtains the device only from the stopped fixture App's own protected vault;
// this helper never signs a positive mutation in place of the App Controller.
// faultProxy.response is upstream evidence, not bytes the App necessarily got:
// corrupted/lost-response cases must separately check the actual App's pending
// record/state before attributing any response as accepted by that App.
func openOwnerGroupsCapturedResponse(t *testing.T, v *codexProductFixture, device *e2ee.Identity, request any, original, response []byte) wire.OwnerEndpointGroupsResult {
	t.Helper()
	var result wire.OwnerEndpointGroupsResult
	if wire.OpenOwnerEndpointGroupsResponse(device, v.f.cfg.Hub, original, response, &result) != nil {
		t.Fatal("actual Owner Group response did not authenticate against the exact original App packet")
	}
	if wire.VerifyOwnerEndpointGroupsResult(request, original, result, v.f.cfg.Hub) != nil {
		t.Fatal("actual Owner Group response changed its original actor/target/operation coordinates")
	}
	return result
}

func performOwnerGroupsAppAction(t *testing.T, v *codexProductFixture, action appcore.Action) (appActorReply, []exchange) {
	t.Helper()
	from := len(v.f.proxy.snapshot())
	result := v.command(t, appActorCommand{Action: &action})
	trace := ownerGroupsTrace(v.f, from)
	for _, ex := range trace {
		packet, err := wire.DecodeOwnerEndpointGroupsPacket(ex.request)
		if err != nil || ex.Method != "POST" || wire.OwnerEndpointGroupsHTTPPath(packet.Packet.Route.Operation) != ex.Path ||
			packet.Packet.Route.HubID != v.f.cfg.Material.HubID || packet.Packet.Route.OwnerID != v.f.cfg.Material.OwnerID ||
			ex.RequestSHA256 != hash(ex.request) {
			t.Fatal("actual App dispatched an unbound or substituted Owner Group packet")
		}
	}
	// A failed action, a cached card and an upstream 200 are not success. The
	// individual case must inspect this actual Controller snapshot, immutable
	// originals and independently authenticated Hub state before emitting facts.
	return result, trace
}

func requireOwnerGroupsCapturedOperation(t *testing.T, review wire.OwnerEndpointGroupsReview, originalApply []byte, result wire.OwnerEndpointGroupsResult, authenticatedHead *e2ee.EndpointGroupOwnerControl) {
	t.Helper()
	if review.Action == wire.OwnerEndpointGroupsRemoveEndpoint && authenticatedHead == nil {
		t.Fatal("REMOVE audit requires the original authenticated exact-target Owner-control head")
	}
	if result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(review, originalApply, *result.Operation, authenticatedHead) != nil {
		t.Fatal("actual Owner Group receipt did not retain its precise reviewed effect and original head")
	}
	// Historical completion is an immutable receipt; the caller separately reads
	// and checks current relation/head before treating anything as usable authority.
}
