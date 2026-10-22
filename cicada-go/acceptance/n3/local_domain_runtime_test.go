package n3_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localDomainOpenAudit struct {
	PacketSHA256 string           `json:"encrypted_packet_sha256"`
	PacketDigest string           `json:"encrypted_packet_digest"`
	Route        clientwire.Route `json:"public_request_route"`
	Applied      bool             `json:"applied"`
}

// Runs only inside the actual App actor immediately after its own normal
// encrypted-vault open, before Controller resume can apply/reconcile anything.
// Read one opaque operation record, never an identity or signer. Only public
// route metadata and ciphertext digests cross the process boundary.
func auditLocalDomainOpen(t *testing.T, vault *appvault.Vault, directory string) {
	t.Helper()
	raw, _, found, err := vault.LoadState("appcore.local-domain-original.v1")
	if err != nil {
		t.Fatal("actual App could not inspect its retained opaque operation")
	}
	defer clear(raw)
	if !found {
		return
	}
	if len(raw) < 8 || len(raw) > 1<<20 || string(raw[:4]) != "CLD1" {
		t.Fatal("actual App original record framing differs from delivered record profile")
	}
	headerBytes := int(binary.BigEndian.Uint32(raw[4:8]))
	if headerBytes < 2 || headerBytes > 256<<10 || headerBytes > len(raw)-8 {
		t.Fatal("actual App original record header exceeds its profile")
	}
	var header struct {
		Route   clientwire.Route `json:"request_route"`
		Digest  string           `json:"packet_digest"`
		Applied bool             `json:"applied"`
	}
	packet := raw[8+headerBytes:]
	if json.Unmarshal(raw[8:8+headerBytes], &header) != nil || len(packet) == 0 || header.Digest != wire.LocalDomainPacketDigest(packet) {
		t.Fatal("actual App original encrypted packet changed before Controller resume")
	}
	if os.MkdirAll(directory, 0700) != nil {
		t.Fatal("owned App audit directory unavailable")
	}
	writeJSON(t, filepath.Join(directory, "open-"+must(wire.NewRequestID())+".json"), localDomainOpenAudit{
		PacketSHA256: hash(packet), PacketDigest: header.Digest, Route: header.Route, Applied: header.Applied,
	})
}

// Compile against the actual App public types. Until its consumer checkpoint
// arrives these references intentionally remain pending, rather than adding a
// substitute actor, signer, DTO overlay or silently ignored JSON input.
func localDomainTrace(f *hubFixture, from int) []exchange {
	var result []exchange
	for _, ex := range f.proxy.snapshot()[from:] {
		for _, op := range wire.LocalDomainHTTPOperations() {
			if ex.Path == wire.LocalDomainHTTPPath(op) {
				result = append(result, ex)
				break
			}
		}
	}
	return result
}

func requireLocalDomainAvailable(t *testing.T, v *codexProductFixture) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := must(client.Get(v.f.cfg.Origin + wire.LocalDomainCapabilitiesPath))
	defer response.Body.Close()
	raw := must(io.ReadAll(io.LimitReader(response.Body, 16385)))
	if response.StatusCode == http.StatusNotFound {
		t.Skip("LOCAL_DOMAIN_NOT_RUN actual Hub capability route HTTP=404")
	}
	var capabilities wire.LocalDomainCapabilities
	if response.StatusCode != http.StatusOK || len(raw) > 16384 || json.Unmarshal(raw, &capabilities) != nil ||
		capabilities.Format != wire.LocalDomainFormat || capabilities.ContractRevision != wire.LocalDomainContractRevision {
		t.Fatal("actual Hub local-domain capability response malformed or unavailable")
	}
	if !capabilities.Available {
		t.Skip("LOCAL_DOMAIN_NOT_RUN actual Hub advertises available=false")
	}
}

func requireSameLocalDomain(t *testing.T, expected, actual appcore.LocalCollaborationSnapshot) {
	t.Helper()
	requireLocalDomainCoordinates(t, expected, actual)
	if actual.Pending || !actual.Current {
		t.Fatal("actual App has no authenticated current domain authority")
	}
}

func requireLocalDomainCoordinates(t *testing.T, expected, actual appcore.LocalCollaborationSnapshot) {
	t.Helper()
	if actual.PolicyID != expected.PolicyID || actual.PolicyEpoch != expected.PolicyEpoch ||
		actual.NodeID != expected.NodeID || actual.LocalUserScope != expected.LocalUserScope || actual.NetworkID != expected.NetworkID ||
		actual.GroupID != expected.GroupID || actual.NetworkName != expected.NetworkName || actual.GroupName != expected.GroupName || actual.ExpiresAt != expected.ExpiresAt {
		t.Fatal("actual App changed the exact reviewed original domain authority")
	}
}

func closeLocalDomainApp(t *testing.T, v *codexProductFixture) {
	t.Helper()
	reply := v.command(t, appActorCommand{Close: true})
	if !reply.Closed || reply.ActionFailed {
		t.Fatal("actual App did not acknowledge controlled normal close")
	}
	select {
	case <-v.app.done:
	case <-time.After(10 * time.Second):
		t.Fatal("actual App normal Controller.Close did not finish")
	}
	if v.app.cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("actual App did not exit normally after Controller.Close")
	}
}

func TestN3LocalDomainActualAppOwnerPolicy(t *testing.T) {
	t.Setenv("CICADA_N3_LOCAL_DOMAIN_AUDIT", "1")
	v := newCodexProductFixture(t, "1s")
	requireLocalDomainAvailable(t, v)
	initial := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !initial.AvailabilityKnown || !initial.Available || !initial.Current || initial.Pending || initial.NodeID != v.actualNode.id || initial.State != "UNCONFIGURED" {
		t.Fatal("fresh actual App did not read an unconfigured original Node policy scope")
	}
	// Observe the actual agent's automatic report exchange. The Hub and App
	// independently verify its signature and writer scope; the parent signs none.
	reportReady := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !reportReady {
		for _, ex := range v.f.proxy.snapshot() {
			if ex.Method != http.MethodPost || ex.Path != "/v2/node/control/rpc" || !ex.Forwarded || ex.Status != http.StatusOK {
				continue
			}
			var packet nodewire.Packet
			if json.Unmarshal(ex.request, &packet) == nil && packet.Route.Operation == wire.OperationLocalDomainNodeAvailable {
				reportReady = true
				break
			}
		}
		if !reportReady {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if !reportReady {
		t.Fatal("actual Node did not automatically publish its local-user report")
	}
	preview := v.do(appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "Synthetic QA private Network", GroupName: "Synthetic QA dedicated Group", ExpiresInHours: 0}}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.State != wire.LocalDomainPrepared || preview.ReviewID == "" || preview.ReviewExpiresAt == "" ||
		preview.PolicyID == "" || preview.PolicyEpoch == 0 || preview.NodeID != v.actualNode.id || preview.LocalUserScope != "uid:1000" ||
		preview.NetworkID == "" || preview.GroupID == "" || preview.NetworkName != "Synthetic QA private Network" || preview.GroupName != "Synthetic QA dedicated Group" || preview.ExpiresAt != "" {
		t.Fatal("actual App preview changed or omitted the exact Node/report/Network/Group authority")
	}
	activate := appcore.Action{Kind: appcore.ActionActivateLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}
	from := len(v.f.proxy.snapshot())
	_, release := v.f.proxy.armMethod(wire.LocalDomainHTTPPath(wire.OperationLocalDomainActivate), http.MethodPost, "drop-after-response", 1)
	defer release()
	lost := v.command(t, appActorCommand{Action: &activate})
	assertOwnerDirectoryIdentity(t, v.endpointSecurityFixture, lost.Current)
	if !lost.ActionFailed || !lost.Current.LocalCollaboration.Pending || lost.Current.LocalCollaboration.PolicyID != preview.PolicyID {
		t.Fatal("lost activation response settled or replaced the actual App original operation")
	}
	var original *exchange
	for _, ex := range localDomainTrace(v.f, from) {
		if ex.Method == http.MethodPost && ex.Path == wire.LocalDomainHTTPPath(wire.OperationLocalDomainActivate) {
			if original != nil || !ex.Forwarded || ex.Status != http.StatusOK || len(ex.request) == 0 || len(ex.response) == 0 {
				t.Fatal("activation barrier missed the single actual Hub commit/receipt")
			}
			copy := ex
			original = &copy
		}
	}
	if original == nil {
		t.Fatal("actual original activation packet/receipt missing")
	}
	originalPacket := must(wire.DecodeLocalDomainPacket(original.request))
	auditDirectory := filepath.Join(v.f.dir, "domain-open-audit")
	oldAudits := make(map[string]bool)
	for _, path := range must(filepath.Glob(filepath.Join(auditDirectory, "*.json"))) {
		oldAudits[path] = true
	}
	blockedFrom := len(v.f.proxy.snapshot())
	blocked := v.command(t, appActorCommand{Action: &activate})
	if !blocked.ActionFailed || !blocked.Current.LocalCollaboration.Pending || len(localDomainTrace(v.f, blockedFrom)) != 0 {
		t.Fatal("fresh approval displaced an uncertain original activation")
	}
	v.app.kill(t) // Deliberate owned crash; recovery must keep the original vault.
	v.f.hub.kill(t)
	v.f.start(t)
	recoveryFrom := len(v.f.proxy.snapshot())
	current := restartOwnerDirectoryApp(t, v.endpointSecurityFixture)
	if current.LocalCollaboration.Pending {
		current = v.do(appcore.Action{Kind: appcore.ActionRecoverLocalCollaboration})
	}
	durableOriginal := false
	for _, path := range must(filepath.Glob(filepath.Join(auditDirectory, "*.json"))) {
		if oldAudits[path] {
			continue
		}
		var audit localDomainOpenAudit
		readJSON(t, path, &audit)
		if !audit.Applied && audit.PacketSHA256 == original.RequestSHA256 && audit.PacketDigest == wire.LocalDomainPacketDigest(original.request) &&
			audit.Route.Operation == wire.OperationLocalDomainActivate && audit.Route.OperationID == originalPacket.Packet.Route.OperationID {
			durableOriginal = true
		}
	}
	if !durableOriginal {
		t.Fatal("new actual App process did not open the exact unresolved original packet from its protected vault")
	}
	historical := current.LocalCollaboration
	requireLocalDomainCoordinates(t, preview, historical)
	if historical.Pending || historical.Current || historical.State != wire.LocalDomainActive || historical.Revision <= preview.Revision {
		t.Fatal("actual App did not recover the original activation outcome")
	}
	recovered := false
	for _, ex := range localDomainTrace(v.f, recoveryFrom) {
		if ex.Method != http.MethodPost {
			continue
		}
		switch ex.Path {
		case wire.LocalDomainHTTPPath(wire.OperationLocalDomainPrepare), wire.LocalDomainHTTPPath(wire.OperationLocalDomainRevoke):
			t.Fatal("activation recovery issued a fresh authority mutation")
		case wire.LocalDomainHTTPPath(wire.OperationLocalDomainActivate):
			if !bytes.Equal(ex.request, original.request) || !bytes.Equal(ex.response, original.response) || !ex.Forwarded || ex.Status != http.StatusOK {
				t.Fatal("activation recovery changed its exact original packet/receipt")
			}
			recovered = true
		case wire.LocalDomainHTTPPath(wire.OperationLocalDomainReconcile):
			packet := must(wire.DecodeLocalDomainPacket(ex.request))
			route, old := packet.Packet.Route, originalPacket.Packet.Route
			if !ex.Forwarded || ex.Status != http.StatusOK || route.HubID != old.HubID || route.OwnerID != old.OwnerID || route.DeviceID != old.DeviceID ||
				route.Operation != wire.OperationLocalDomainReconcile || route.OperationID == old.OperationID {
				t.Fatal("actual App reconciled through a substituted actor or route")
			}
			// The real App opens/authenticates the nested receipt and compares its
			// OriginalPacketDigest/Operation/RequestID before clearing Pending.
			// The parent never decrypts a private App payload or holds its signer.
			recovered = true
		}
	}
	if !recovered {
		t.Fatal("actual App never recovered its original accepted request")
	}
	// The recovered receipt establishes history. Explicitly authenticate the
	// current account session, then read current policy before any new action.
	inspected := v.do(appcore.Action{Kind: appcore.ActionSessionInspect})
	assertOwnerDirectoryIdentity(t, v.endpointSecurityFixture, inspected)
	active := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, historical, active)
	if active.State != wire.LocalDomainActive || active.Revision != historical.Revision || active.StateReviewID == "" {
		t.Fatal("actual App did not independently authenticate the current policy after historical recovery")
	}
	closeFrom := len(v.f.proxy.snapshot())
	closeLocalDomainApp(t, v)
	if !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("normal App close stopped the independent Node/Hub")
	}
	_ = restartOwnerDirectoryApp(t, v.endpointSecurityFixture)
	readback := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, active, readback)
	if readback.State != wire.LocalDomainActive || readback.Revision != active.Revision {
		t.Fatal("normal App close revoked the persistent Hub policy")
	}
	for _, ex := range localDomainTrace(v.f, closeFrom) {
		if ex.Path == wire.LocalDomainHTTPPath(wire.OperationLocalDomainRevoke) {
			t.Fatal("normal App close or profile resume sent a policy revocation")
		}
	}
	v.actualNode.kill(t)
	readback = v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, active, readback)
	if readback.State != wire.LocalDomainActive || readback.Revision != active.Revision || readback.StateReviewID == "" {
		t.Fatal("Owner policy read required Node online")
	}
	revoked := v.do(appcore.Action{Kind: appcore.ActionRevokeLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: readback.StateReviewID, ConfirmRevoke: true}}).LocalCollaboration
	requireSameLocalDomain(t, active, revoked)
	if revoked.State != wire.LocalDomainRevoked || revoked.Revision <= active.Revision {
		t.Fatal("actual App did not revoke its exact original policy with Node offline")
	}
	t.Logf("LOCAL_DOMAIN_APP_OWNER_POLICY actual_App_signer=true actual_Node_report=true persistent_until_revoke=true activation_response_loss_Hub_App_restart=true original_request_sha256=%s normal_Controller_Close_and_resume_policy_retained=true Node_offline_read_revoke=true native_A_B_Host_TTL_emptycache_crossscope_Windows=NOT_RUN", original.RequestSHA256)
}
