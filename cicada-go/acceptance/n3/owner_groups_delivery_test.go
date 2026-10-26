package n3_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

type ownerGroupsDeniedDelivery struct {
	RequestID string
	Body      string
	Path      string
	Group     string
}

// Hold the actual OS writer used by the production Node, never a substitute
// native queue. The UID determines a local serialization scope, not authority.
func holdOwnerGroupsNativeWriter(t *testing.T, v *codexProductFixture, identity ownerGroupsIdentity) func() {
	t.Helper()
	var approved bool
	for _, scenario := range readOwnerGroupsInputs(t).Cases {
		if scenario.ID == "M3_RemoveOnlyD" && len(scenario.NativeFaults) == 1 && scenario.NativeFaults[0] == "hold_original_native_writer" {
			approved = true
		}
	}
	if !approved || identity.NodeID != v.actualNode.id || !ownerGroupsSIDPattern.MatchString(identity.SID) {
		t.Fatal("native writer fault targeted another original actor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writer := must(nodelock.AcquireNativeWriter(ctx, v.actualNode.state, "uid:"+strconv.Itoa(os.Getuid()), "codex", identity.SID))
	closed := false
	release := func() {
		if closed {
			return
		}
		closed = true
		if writer.Close() != nil {
			t.Error("owned native writer fault did not release cleanly")
		}
	}
	t.Cleanup(release)
	return release
}

func awaitOwnerGroupsDeliveryBeforeRemove(t *testing.T, v *codexProductFixture, from int, request string, source, target ownerGroupsIdentity, group string) string {
	t.Helper()
	prefix := "/v2/relay/nodes/" + url.PathEscape(v.actualNode.id) + "/group/sealed/deliveries/"
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range v.f.proxy.snapshot()[from:] {
			if ex.Method != http.MethodGet || !strings.HasPrefix(ex.Path, prefix) || !strings.HasSuffix(ex.Path, "/authorization") || !ex.Forwarded || ex.Status != http.StatusOK {
				continue
			}
			var authorization struct {
				EndpointID      string `json:"endpoint_id"`
				NativeSessionID string `json:"native_session_id"`
				Sender          struct {
					EndpointID string `json:"endpoint_id"`
					GroupID    string `json:"group_id"`
				} `json:"sender"`
				Receiver struct {
					EndpointID string `json:"endpoint_id"`
					GroupID    string `json:"group_id"`
				} `json:"receiver"`
				Route struct {
					RequestID string `json:"request_id"`
					Kind      string `json:"kind"`
				} `json:"route"`
			}
			if json.Unmarshal(ex.response, &authorization) != nil || authorization.Route.RequestID != request {
				continue
			}
			if authorization.Route.Kind != "ask" || authorization.EndpointID != target.Endpoint || authorization.NativeSessionID != target.SID ||
				authorization.Sender.EndpointID != source.Endpoint || authorization.Receiver.EndpointID != target.Endpoint ||
				authorization.Sender.GroupID != group || authorization.Receiver.GroupID != group {
				t.Fatal("actual pre-writer delivery authorization changed original request, Group or native actor")
			}
			return ex.Path
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual queued request did not reach positive delivery authorization before the writer wait")
	return ""
}

func awaitOwnerGroupsFinalDeliveryDenied(t *testing.T, v *codexProductFixture, from int, path string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range v.f.proxy.snapshot()[from:] {
			if ex.Path == path && ex.Method == http.MethodGet && ex.Forwarded &&
				(ex.Status == http.StatusUnauthorized || ex.Status == http.StatusForbidden || ex.Status == http.StatusNotFound) {
				// This exact production route authenticated the same queued request
				// before removal. Its post-writer rejection is not an absent route.
				return
			}
		}
		if !v.actualNode.running() || !v.f.hub.running() {
			t.Fatal("delivery refusal was caused by a stopped Node or Hub")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual Node did not recheck and reject the original queued delivery after its writer wait")
}

func ownerGroupsEmptyTaskState(t *testing.T, v *codexProductFixture) {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var count int
	if db.QueryRow(`SELECT (SELECT count(*) FROM shared_tasks_v2)+(SELECT count(*) FROM shared_task_v2_results)+(SELECT count(*) FROM shared_task_v2_events)`).Scan(&count) != nil || count != 0 {
		t.Fatal("forbidden managed Actor Task requests changed the actual empty Task state")
	}
}

func exerciseOwnerGroupsM3(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity, g2 string) ownerGroupsDeniedDelivery {
	t.Helper()
	if len(original) != 4 {
		t.Fatal("M3 requires the four original native actors")
	}
	var preserved [3][2]string
	for index := 0; index < 3; index++ {
		preserved[index] = [2]string{ownerGroupsRelationAuthorityHash(t, v, original[index].Endpoint, actors.active.GroupID),
			ownerGroupsRelationAuthorityHash(t, v, original[index].Endpoint, g2)}
	}
	d := original[3]
	dG2 := ownerGroupsRelationAuthorityHash(t, v, d.Endpoint, g2)
	review := prepareOwnerGroupsEndpointChange(t, v, actors, d, actors.active.GroupID, wire.OwnerEndpointGroupsRemoveEndpoint, "")
	release := holdOwnerGroupsNativeWriter(t, v, d)
	defer release()
	body := "SYNTHETIC_OWNER_GROUP_QUESTION_" + host.fixtureScope + "_m3-denied-after-writer"
	from, started := len(v.f.proxy.snapshot()), time.Now()
	ask := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m3-held-g1-ask", Tool: "cicada_ask",
		Arguments:     map[string]any{"target": d.Endpoint, "question": body, "idempotency_key": host.fixtureScope + "-m3-held-g1"},
		Queue:         []ownerGroupsQueueInput{{Body: body, SID: d.SID, Sender: original[0].Endpoint, Receiver: d.Endpoint, GroupID: actors.active.GroupID, Kind: "ask"}},
		ObserveFields: []string{"request_id", "operation_id"}})
	request := ask.Public["request_id"]
	for attempt := 0; request == "" && ask.Public["operation_id"] != "" && attempt < 4; attempt++ {
		time.Sleep(250 * time.Millisecond)
		status := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m3-held-g1-status-" + strconv.Itoa(attempt), Tool: "cicada_operation_status",
			Arguments: map[string]any{"operation_id": ask.Public["operation_id"]}, ObserveFields: []string{"request_id"}})
		request = status.Public["request_id"]
	}
	if request == "" || ask.QueuePosts[body] != 0 {
		t.Fatal("writer-held actual ASK lacks one durable request or was already injected")
	}
	path := awaitOwnerGroupsDeliveryBeforeRemove(t, v, from, request, original[0], d, actors.active.GroupID)
	if time.Since(started) >= 10*time.Second {
		t.Fatal("writer fault did not leave time for the original 15-second production admission window")
	}
	submitOwnerGroupsReview(t, v, review, "REMOVED")
	afterRemove := len(v.f.proxy.snapshot())
	release()
	awaitOwnerGroupsFinalDeliveryDenied(t, v, afterRemove, path)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "REMOVED", "OWNER")
	host.groups(t, 3, "m3-removed-d-self", actors.active.NetworkID, "", map[string]string{g2: "OWNER_EXPLICIT"})
	// Other native actors and D's surviving Group retain exact original grants.
	host.roundtrip(t, "m3-abc-g1", actors.active.GroupID, 0, 1, original)
	host.roundtrip(t, "m3-dc-g2", g2, 3, 2, original)
	credential := originalOwnerGroupsRESTCredential(t, v, d, g2)
	ownerGroupsEmptyTaskState(t, v)
	exerciseOwnerGroupsActorCeiling(t, v, credential, g2, actors.active.GroupID)
	ownerGroupsEmptyTaskState(t, v)
	for index := 0; index < 3; index++ {
		if ownerGroupsRelationAuthorityHash(t, v, original[index].Endpoint, actors.active.GroupID) != preserved[index][0] ||
			ownerGroupsRelationAuthorityHash(t, v, original[index].Endpoint, g2) != preserved[index][1] {
			t.Fatal("removing D changed another original Endpoint's Group/Principal authority")
		}
	}
	if ownerGroupsRelationCount(t, v, d.Endpoint, actors.active.GroupID) != 0 || ownerGroupsRelationAuthorityHash(t, v, d.Endpoint, g2) != dG2 {
		t.Fatal("removing D-G1 changed D-G2 or retained an ACTIVE removed edge")
	}
	checkpoint := host.command(t, ownerGroupsHostCommand{Action: "checkpoint"})
	if checkpoint.QueuePosts[body] != 0 {
		t.Fatal("revoked original G1 work reached the native Runtime through another Group")
	}
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	observeOwnerGroupsCase(t, "M3_RemoveOnlyD", map[string]bool{
		"only_D_G1_removed": true, "A_B_C_unchanged": true, "D_G2_unchanged": true,
		"shared_Principal_grants_unchanged": true, "actual_five_right_Actor_Guards": true,
		"legacy_global_mutations_denied": true, "fresh_final_delivery_denied": true,
	})
	return ownerGroupsDeniedDelivery{RequestID: request, Body: body, Path: path, Group: actors.active.GroupID}
}
