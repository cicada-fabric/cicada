package n3_test

import (
	"bytes"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Opt-in only after the actual App Core action is delivered. The parent never
// opens an Owner key, signs a proof, restores an outbox or seeds SQL authority.
func ownerDirectoryReadAction(t *testing.T, snapshot appcore.Snapshot) appcore.Action {
	t.Helper()
	if snapshot.OwnerEndpoints.ReviewID == "" {
		t.Fatal("actual App has no current original-Node directory review")
	}
	return appcore.Action{Kind: appcore.ActionReadOwnerEndpoints,
		OwnerEndpoints: appcore.OwnerEndpointReadAction{ReviewID: snapshot.OwnerEndpoints.ReviewID, Limit: 64, ConfirmRead: true}}
}

func ownerDirectoryTrace(f *hubFixture, from int) []exchange {
	var result []exchange
	for _, ex := range f.proxy.snapshot()[from:] {
		if ex.Path == wire.OwnerEndpointReadPath {
			result = append(result, ex)
		}
	}
	return result
}

func assertOwnerDirectoryIdentity(t *testing.T, v *endpointSecurityFixture, s appcore.Snapshot) {
	t.Helper()
	if s.Account.OwnerID != v.original.Account.OwnerID || s.Account.DeviceID != v.original.Account.DeviceID ||
		s.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID || s.Account.OwnerFingerprint != v.original.Account.OwnerFingerprint ||
		s.Hub.Fingerprint != v.original.Hub.Fingerprint || s.Management != appcore.ManagementUnavailable || s.Canvas.State != appcore.CanvasNoAuthorization {
		t.Fatal("actual App directory changed its original identity or acquired management/canvas authority")
	}
}

func assertOwnerDirectoryCards(t *testing.T, v *endpointSecurityFixture, s appcore.Snapshot, expected map[string]nodewire.EndpointRegistration) {
	t.Helper()
	assertOwnerDirectoryIdentity(t, v, s)
	d := s.OwnerEndpoints
	// Public capability discovery is transient across an App restart. A verified
	// cached snapshot must not require a new GET to become valid again.
	t.Logf("OWNER_DIRECTORY snapshot_state=%s capability_available=%t pending=%t captured_present=%t original_Node=%t Node_name_present=%t cards=%d expected_cards=%d", d.State, d.Available, d.Pending, d.CapturedAt != "", d.NodeID == v.node.id, d.NodeName != "", len(d.Endpoints), len(expected))
	if d.Pending || d.State != "SNAPSHOT_ONLY" || d.CapturedAt == "" || d.NodeID != v.node.id || d.NodeName == "" ||
		d.NextCursor != "" || len(d.Endpoints) != len(expected) {
		t.Fatal("actual App did not expose only its authenticated finite Node snapshot")
	}
	seen := make(map[string]bool)
	for _, card := range d.Endpoints {
		want, found := expected[card.EndpointID]
		if !found || seen[card.EndpointID] || card.Name != want.Name || card.Workspace != want.Workspace || card.Harness != want.Harness || card.Presence != "offline" {
			t.Fatal("actual App changed or duplicated an original zero-rights directory card")
		}
		seen[card.EndpointID] = true
	}
}

func restartOwnerDirectoryApp(t *testing.T, v *endpointSecurityFixture) appcore.Snapshot {
	t.Helper()
	marker := filepath.Join(v.f.dir, "owner-directory-resume-"+must(wire.NewRequestID())+".json")
	v.app = startAppProcess(t, v.f, "resume-node", marker)
	v.sequence = 0
	awaitMarker(t, v.app.process, marker)
	var checkpoint appActorCheckpoint
	readJSON(t, marker, &checkpoint)
	assertOwnerDirectoryIdentity(t, v, checkpoint.Current)
	return checkpoint.Current
}

func TestN3OwnerDirectoryActualAppReadsZeroRightsSnapshot(t *testing.T) {
	v := newEndpointSecurityFixture(t)
	expected, rows := make(map[string]nodewire.EndpointRegistration), make(map[string]string)
	for _, sid := range []string{"synthetic-owner-directory-original-A", "synthetic-owner-directory-original-B"} {
		in := endpointSecurityRegistration(sid)
		var registered nodewire.EndpointRegistrationResult
		v.node.rpc(t, nodewire.EndpointRegisterOperation, in, &registered)
		expected[registered.EndpointID], rows[registered.EndpointID] = in, "offline"
	}
	before := v.command(t, appActorCommand{}).Current
	from := len(v.f.proxy.snapshot())
	s := v.do(ownerDirectoryReadAction(t, before))
	assertOwnerDirectoryCards(t, v, s, expected)
	if !s.OwnerEndpoints.Available {
		t.Fatal("successful new read did not preserve its preceding capability discovery")
	}
	trace := ownerDirectoryTrace(v.f, from)
	if len(trace) != 2 || trace[0].Method != http.MethodGet || trace[1].Method != http.MethodPost ||
		!trace[0].Forwarded || !trace[1].Forwarded || trace[0].Status != http.StatusOK || trace[1].Status != http.StatusOK {
		t.Fatal("actual App did not discover before its original Owner-signed directory POST")
	}
	v.assertRows(t, rows, 2)
	t.Log("OWNER_DIRECTORY actual_App_Core_child=true Owner_private_key_opened_by_parent=false actual_Owner_signed_read=true names_workspaces_retained=true duplicate_labels_distinct_ids=true SNAPSHOT_ONLY=true business_authority_zero=true Control_inference=false")
}

func TestN3OwnerDirectoryOldHubCannotStartRead(t *testing.T) {
	v := newEndpointSecurityFixture(t)
	before := v.command(t, appActorCommand{}).Current
	action := ownerDirectoryReadAction(t, before)
	from := len(v.f.proxy.snapshot())
	_, release := v.f.proxy.armMethod(wire.OwnerEndpointReadPath, http.MethodGet, "unsupported-before-forward", 1)
	defer release()
	reply := v.command(t, appActorCommand{Action: &action})
	assertOwnerDirectoryIdentity(t, v, reply.Current)
	trace := ownerDirectoryTrace(v.f, from)
	if !reply.ActionFailed || reply.Current.OwnerEndpoints.Pending || reply.Current.OwnerEndpoints.Available ||
		len(trace) != 1 || trace[0].Method != http.MethodGet || trace[0].Forwarded || trace[0].Status != http.StatusNotFound {
		t.Fatal("old-Hub availability failure created a pending read or secret POST")
	}
	t.Log("OWNER_DIRECTORY old_Hub_GET_404=true new_secret_POSTs=0 new_pending=false original_identity_retained=true")
}

func TestN3OwnerDirectoryOriginalPendingRecovers(t *testing.T) {
	for _, mode := range []string{"before-forward", "drop-after-response", "unsigned-403"} {
		t.Run(mode, func(t *testing.T) {
			v := newEndpointSecurityFixture(t)
			in := endpointSecurityRegistration("synthetic-owner-directory-recovery-" + mode)
			var registered nodewire.EndpointRegistrationResult
			v.node.rpc(t, nodewire.EndpointRegisterOperation, in, &registered)
			action := ownerDirectoryReadAction(t, v.command(t, appActorCommand{}).Current)
			from := len(v.f.proxy.snapshot())
			_, release := v.f.proxy.armMethod(wire.OwnerEndpointReadPath, http.MethodPost, mode, 1)
			defer release()
			lost := v.command(t, appActorCommand{Action: &action})
			assertOwnerDirectoryIdentity(t, v, lost.Current)
			trace := ownerDirectoryTrace(v.f, from)
			if !lost.ActionFailed || !lost.Current.OwnerEndpoints.Pending || lost.Current.Node.Pending || len(trace) != 2 ||
				trace[0].Method != http.MethodGet || !trace[0].Forwarded || trace[0].Status != http.StatusOK ||
				trace[1].Method != http.MethodPost || trace[1].Forwarded != (mode != "before-forward") || len(trace[1].request) == 0 {
				t.Fatal("POST fault consumed discovery or unsigned/lost response settled the actual App outbox")
			}
			original := trace[1]
			// An unavailable capability cannot replace an existing uncertain
			// read. Starting a new read must fail without another GET/POST.
			_, releaseOldHub := v.f.proxy.armMethod(wire.OwnerEndpointReadPath, http.MethodGet, "unsupported-before-forward", 1)
			defer releaseOldHub()
			blocked := v.command(t, appActorCommand{Action: &action})
			if !blocked.ActionFailed || !blocked.Current.OwnerEndpoints.Pending || len(ownerDirectoryTrace(v.f, from)) != 2 {
				t.Fatal("new read/capability displaced the original pending read")
			}
			v.app.kill(t)
			v.f.hub.kill(t)
			v.f.start(t)
			current := restartOwnerDirectoryApp(t, v)
			if current.OwnerEndpoints.Pending {
				current = v.do(appcore.Action{Kind: appcore.ActionRecoverOwnerEndpoints})
			}
			assertOwnerDirectoryCards(t, v, current, map[string]nodewire.EndpointRegistration{registered.EndpointID: in})
			trace = ownerDirectoryTrace(v.f, from)
			posts := 0
			for _, ex := range trace[2:] {
				if ex.Method != http.MethodPost || !ex.Forwarded || ex.Status != http.StatusOK || !bytes.Equal(ex.request, original.request) {
					t.Fatal("actual App restart/recovery discovered or signed a replacement instead of its original packet")
				}
				if original.Forwarded && !bytes.Equal(ex.response, original.response) {
					t.Fatal("actual App did not recover its original cached snapshot ciphertext")
				}
				posts++
			}
			if posts == 0 {
				t.Fatal("actual App recovery never resent its durable original read")
			}
			v.assertRows(t, map[string]string{registered.EndpointID: "offline"}, 1)
			t.Log("OWNER_DIRECTORY fault=" + mode + " actual_App_child_restart=true actual_Hub_restart=true original_PQ_packet_retained=true recovery_without_new_capability_GET=true authenticated_snapshot_recovered=true Parent_Owner_signer_SQL_grants=false")
		})
	}
}
