package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func appBindingTCP(t *testing.T, f *hubAccountTCPFixture, device *e2ee.Identity, body, out any) ([]byte, []byte) {
	t.Helper()
	raw, err := wire.SealClientRequest(device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	_, route, err := wire.NewClientRoute(f.hub, body, device.Public())
	if err != nil {
		t.Fatal(err)
	}
	status, packet := n3HTTP(t, f, http.MethodPost, wire.AppBindingHTTPPath(route.Operation), "", raw)
	if status != http.StatusOK {
		t.Fatalf("App binding %s HTTP %d", route.Operation, status)
	}
	if err = wire.OpenClientResponse(device, f.hub, raw, packet, out); err != nil {
		t.Fatal(err)
	}
	return raw, packet
}

func TestAppBindingHubTCPUnbindExactRecoveryAndZeroReplacement(t *testing.T) {
	f := newHubNodesTCPFixture(t)
	status, raw := n3HTTP(t, f, http.MethodGet, wire.AppBindingCapabilitiesPath, "", nil)
	var caps wire.AppBindingCapabilities
	if status != 200 || json.Unmarshal(raw, &caps) != nil || caps.ContractRevision != wire.AppBindingContract || !caps.Available || caps.Recovery != "BYTE_IDENTICAL_ORIGINAL_ONLY" || len(caps.Operations) != 4 {
		t.Fatal("missing additive capability", status)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	enroll, activation, _, _ := n2Prepare(t, f, *material, device, owner)
	complete, err := wire.NewActivationComplete(activation, f.hub, device.Public(), owner, "synthetic-unbind", "synthetic unbind retained password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &wire.ActivationResult{})
	login := n2Login(t, f, device, enroll.DeviceID, "synthetic-unbind", "synthetic unbind retained password")
	prepare, err := wire.NewAppUnbindPrepare(login.Context(), owner.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.AppBindingChallenge
	prepareRaw, _ := appBindingTCP(t, f, device, prepare, &challenge)
	if err = wire.ValidateAppBindingPreparedResponse(prepare, prepareRaw, challenge, f.hub, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	proof, err := ownerbootstrap.CreateProof(owner, challenge.Proof, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	unbinding, err := wire.NewAppBindingComplete(prepareRaw, challenge, proof, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var unbound wire.AppBindingResult
	original, receipt := appBindingTCP(t, f, device, unbinding, &unbound)
	if unbound.State != wire.AppBindingUnbound || wire.ValidateAppBindingResultTarget(unbound, original, challenge.Binding) != nil {
		t.Fatal("invalid authoritative unbind")
	}
	status, retry := n3HTTP(t, f, http.MethodPost, wire.AppBindingHTTPPath(wire.OperationAppUnbindComplete), "", original)
	if status != 200 || !bytes.Equal(receipt, retry) {
		t.Fatal("self-fenced exact retry lost", status)
	}
	oldInspect, err := wire.NewSessionInspectRequest(login.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	oldPacket, err := wire.SealClientRequest(device, f.hub, oldInspect)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, "/v2/owner/account/session/inspect", "", oldPacket)
	if status != 403 {
		t.Fatal("old session remained active", status)
	}
	fresh, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rebind, err := wire.NewAppRebindPrepare(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, enroll.DeviceID, challenge.Binding.Digest(), wire.AccountDeviceIDPrefix+strings.Repeat("8", 32), owner.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var replacement wire.AppBindingChallenge
	rebindRaw, _ := appBindingTCP(t, f, fresh, rebind, &replacement)
	proof, err = ownerbootstrap.CreateProof(owner, replacement.Proof, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	replacing, err := wire.NewAppBindingComplete(rebindRaw, replacement, proof, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var bound wire.AppBindingResult
	replacementRaw, replacementReceipt := appBindingTCP(t, f, fresh, replacing, &bound)
	if bound.State != wire.AppBindingBoundZero || wire.ValidateAppBindingResultTarget(bound, replacementRaw, replacement.Binding) != nil {
		t.Fatal("replacement did not start zero")
	}
	if f.db.CheckAppLease(f.setup.OwnerID, rebind.DeviceID, "nodes.list") == nil {
		t.Fatal("new App acquired Node status lease")
	}
	newLogin := n2Login(t, f, fresh, rebind.DeviceID, "synthetic-unbind", "synthetic unbind retained password")
	session := wire.AppNodeSession{Hub: f.hub, Origin: f.setup.Origin, AccountID: f.setup.AccountID, OwnerID: f.setup.OwnerID, DeviceID: rebind.DeviceID, AccountEpoch: newLogin.AccountEpoch, DeviceEpoch: newLogin.DeviceEpoch, Token: newLogin.SessionToken}
	query, err := wire.NewAppNodeStatus(session, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, snapshot := n3Authority(t, f, fresh, query)
	if snapshot.Result == nil || snapshot.Result.Authority.RootState != wire.RootActiveState || snapshot.Result.Authority.LoginRequired || snapshot.Result.Authority.CurrentHeadVersion != 0 || len(snapshot.Result.Authority.AllowedOperations) != 0 {
		t.Fatal("ordinary login transferred business authority")
	}
	status, retry = n3HTTP(t, f, http.MethodPost, wire.AppBindingHTTPPath(wire.OperationAppRebindComplete), "", replacementRaw)
	if status != 200 || !bytes.Equal(replacementReceipt, retry) {
		t.Fatal("replacement receipt changed after login", status)
	}
	if _, err = f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false); err == nil {
		t.Fatal("rebind reopened initial Root activation")
	}
}

func TestAppBindingHubTCPRealRelayHeartbeatUnbindAndSecurityFence(t *testing.T) {
	a := nativePairTCP(t)
	f := a.f
	path := "/v2/relay/nodes/" + url.PathEscape(a.scope.Node.NodeID) + "/heartbeat"
	status, _ := n3HTTP(t, f, http.MethodPost, path, a.nodeToken, []byte(`{}`))
	if status != http.StatusNoContent {
		t.Fatal("real bound Relay heartbeat unavailable", status)
	}
	before, err := f.db.GetMachine(a.scope.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(a.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	session := wire.SessionContext{Origin: a.session.Origin, HubID: f.hub.HubID, AccountID: a.session.AccountID, OwnerID: a.session.OwnerID, DeviceID: a.session.DeviceID, DeviceKeyID: a.device.Public().ID, DeviceKeyFingerprint: fingerprint, SessionToken: a.session.Token, AccountEpoch: a.session.AccountEpoch, DeviceEpoch: a.session.DeviceEpoch, ExpiresAt: a.scope.Actor.AccountSessionExpiresAt}
	prepare, err := wire.NewAppUnbindPrepare(session, a.owner.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.AppBindingChallenge
	original, _ := appBindingTCP(t, f, a.device, prepare, &challenge)
	proof, err := ownerbootstrap.CreateProof(a.owner, challenge.Proof, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	complete, err := wire.NewAppBindingComplete(original, challenge, proof, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var result wire.AppBindingResult
	appBindingTCP(t, f, a.device, complete, &result)
	if result.State != wire.AppBindingUnbound {
		t.Fatal("real unbind failed")
	}
	status, _ = n3HTTP(t, f, http.MethodPost, path, a.nodeToken, []byte(`{"status":"busy","capabilities":{"synthetic":"retained"}}`))
	if status != http.StatusNoContent {
		t.Fatal("voluntary unbind broke real Relay heartbeat", status)
	}
	after, err := f.db.GetMachine(a.scope.Node.NodeID)
	if err != nil || after.LastSeen == before.LastSeen || after.Status != "busy" {
		t.Fatal("real heartbeat projection missing", err)
	}
	if _, err = f.db.RevokeClientDevice(a.session.OwnerID, a.session.DeviceID, int64(result.ClientDeviceVersion)); err != nil {
		t.Fatal(err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, path, a.nodeToken, []byte(`{"status":"available","capabilities":{"synthetic":"forbidden"}}`))
	if status != http.StatusUnauthorized {
		t.Fatal("security revoked Relay heartbeat remained writable", status)
	}
	current, err := f.db.GetMachine(a.scope.Node.NodeID)
	if err != nil || !reflect.DeepEqual(current, after) {
		t.Fatal("refused real heartbeat changed machine projection", err)
	}
}
