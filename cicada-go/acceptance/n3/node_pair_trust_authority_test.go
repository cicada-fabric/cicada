package n3_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func nodePairZeroBusinessRights(t *testing.T) {
	nodePairAccountOnlyLogin(t)
	// activateApp executes/proves Root before Login, asserts Root-active while
	// the App lease is still unconfirmed, then logs in and requires the exact
	// finite N2 operations. Hub was started with --hub-nodes-only throughout.
	v := newNodePairFixture(t, "127.0.0.1")
	if v.original.Account.RootState != appcore.RootStateActive || !v.original.Authorization.Confirmed ||
		!reflect.DeepEqual(v.original.Authorization.AllowedOperations, wire.ActivationAllowedOperations()) ||
		v.original.Management != appcore.ManagementUnavailable || v.original.Canvas.State != appcore.CanvasNoAuthorization {
		t.Fatal("account login was conflated with Root proof or general management/business authority")
	}
	v.approve(t)
	v.awaitACK(t)
	current := v.action(t, appcore.Action{Kind: appcore.ActionRefreshNode})
	if current.Management != appcore.ManagementUnavailable || current.Canvas.State != appcore.CanvasNoAuthorization || current.Node.Binding == nil {
		t.Fatal("identity ceremony enabled Control inference or Manager/Worker authority")
	}
	before := v.admission(t)
	if before.remaining != 0 || before.ownerBindings != 1 || before.keyBindings != 1 || before.state != wire.NodePairTrustACKed {
		t.Fatal("completed identity ceremony retained a reusable admission confirmation budget")
	}
	saved := v.copiedAppState(t)
	defer saved.clear()
	if saved.PairTrust.Confirmation == nil || saved.PairTrust.Confirmation.GrantClaims == nil || !saved.PairTrust.Confirmation.Applied {
		t.Fatal("zero-authority test lacks its actual App's authenticated original confirmation")
	}
	claims := saved.PairTrust.Confirmation.GrantClaims
	var original clientwire.Packet
	if json.Unmarshal(saved.PairTrust.Confirmation.Request, &original) != nil {
		t.Fatal("original scoped App Client route unavailable")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	device := v.originalAppDevice(t)
	client := v.protocolClient(t)
	binding := clientwire.Binding{HubID: claims.Scope.HubID, OwnerID: claims.Scope.OwnerID, DeviceID: claims.Scope.DeviceID,
		SessionEpoch: claims.Scope.ClientSessionEpoch, HubKeyVersion: v.hub.descriptor.Claims.Hub.KeyVersion, DeviceKeyVersion: wire.DeviceKeyVersion}
	for _, operation := range []string{"goal.create", "goal.lifecycle", "group.key_grant", "link.invite_create", "monitor.broadcast_confirm", "nodes.revoke"} {
		route := original.Route
		route.Operation, route.Sequence = operation, before.lastRequest+1
		route.OperationID = must(wire.AppNodeBusinessOperationID(claims.GrantID, must(wire.NewRequestID())))
		packet := must(clientwire.SealRequest(device, v.hub.descriptor.Claims.Hub.Public, binding, route, []byte(`{}`)))
		time.Sleep(260 * time.Millisecond)
		response := nodePairHTTP(client, v.hub.material.Origin, "/v2/client/rpc", packet)
		clear(packet)
		clear(response.response)
		if response.err != nil || response.status != http.StatusForbidden || v.admission(t) != before {
			t.Fatalf("actual current scoped App key escaped identity-only authority: operation=%s status=%d", operation, response.status)
		}
	}
	// The actual relay-only Agent uses the Relay heartbeat, whose guarded
	// transaction advances machines.last_seen. The ordinary Control RPC is a
	// different operation and remains unavailable in Hub Nodes mode.
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	basis := v.existingBasis(t)
	observedAt := time.Now().UTC()
	var initialSeen string
	if db.QueryRow(`SELECT last_seen FROM machines WHERE id=? AND owner_id=?`, v.node.id, v.original.Account.OwnerID).Scan(&initialSeen) != nil {
		t.Fatal("actual original bound Node machine projection unavailable")
	}
	initialTime := must(time.Parse(time.RFC3339Nano, initialSeen))
	deadline := time.Now().Add(10 * time.Second)
	observed := false
	for time.Now().Before(deadline) {
		var seen string
		var workers int
		if db.QueryRow(`SELECT machine.last_seen FROM machines machine JOIN node_owner_bindings_v2 binding ON binding.node_id=machine.id AND binding.owner_id=machine.owner_id
JOIN fabric_node_credentials credential ON credential.node_id=binding.node_id AND credential.credential_hash=binding.node_credential_digest AND credential.version=binding.node_credential_version
WHERE machine.id=? AND machine.owner_id=? AND binding.id=? AND binding.state='ACTIVE' AND credential.status='active'`,
			v.node.id, v.original.Account.OwnerID, current.Node.Binding.ID).Scan(&seen) != nil ||
			db.QueryRow(`SELECT count(*) FROM workers`).Scan(&workers) != nil {
			t.Fatal("actual self-heartbeat/Worker authority observation unavailable")
		}
		if workers != 0 {
			t.Fatal("identity-only relay invented an executable business Worker")
		}
		at := must(time.Parse(time.RFC3339Nano, seen))
		if at.After(initialTime) && !at.Before(observedAt) {
			observed = true
			break
		}
		if !v.node.running() {
			t.Fatal("actual identity-only Node stopped before its self heartbeat")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !observed {
		t.Fatal("actual relay self heartbeat was not accepted with Control inference disabled")
	}
	if v.existingBasis(t) != basis || v.admission(t) != before {
		t.Fatal("actual Relay heartbeat replaced the original binding/credential/keys or authority")
	}
	// Stop the real Node before this negative wire actor reads its original
	// key. A valid, fresh successor Control heartbeat must still be refused.
	v.node.kill(t)
	c, _ := v.side(t)
	key := v.nodeIdentity(t)
	token := readPrivate(t, filepath.Join(filepath.Dir(v.node.statePath()), "relay.token"))
	defer clear(token)
	n := &appPairNodeFixture{f: &hubFixture{dir: v.hub.dir, cfg: fixtureConfig{Origin: v.hub.material.Origin}},
		id: v.node.id, key: key, token: strings.TrimSpace(string(token)), client: client,
		binding: nodewire.Binding{HubID: c.Hub.HubID, NodeID: v.node.id, BindingID: current.Node.Binding.ID,
			BindingVersion: current.Node.Binding.Version, NodeKeyEpoch: c.Candidate.NodeKeyEpoch, NodeKeyVersion: 1,
			NodeKey: key.Public(), HubKey: c.Candidate.HubNodeControlPublic, HubKeyVersion: c.Candidate.HubNodeControlKeyVersion}}
	if db.QueryRow(`SELECT COALESCE((SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?),0)`,
		n.binding.BindingID, n.binding.NodeKeyEpoch).Scan(&n.sequence) != nil {
		t.Fatal("original Node Control successor sequence unavailable")
	}
	request := n.prepareRPC(t, "node.heartbeat", map[string]any{"status": "available"})
	defer clear(request.Packet)
	status, response := n.http(t, http.MethodPost, "/v2/node/control/rpc", "CicadaNode "+n.token, "", json.RawMessage(request.Packet))
	clear(response)
	if status != http.StatusForbidden || v.existingBasis(t) != basis || v.admission(t) != before {
		t.Fatalf("ordinary Node Control heartbeat escaped the disabled Control boundary: HTTP=%d", status)
	}
	t.Log("NODE_PAIR_SELF_LIVENESS actual_Relay_machine_last_seen_advanced=true original_binding_credential_keys=true Workers=0 ordinary_Control_heartbeat_refused=true")
	nodePairFacts(t, "NPT12_ZeroBusinessRights", map[string]bool{"necessary_self_operations_only": true,
		"business_operations_denied": true, "login_not_Root": true, "Control_off_identity_flow": true})
}

func nodePairAccountOnlyLogin(t *testing.T) {
	// A separate fresh account-compatibility fixture issues no N2 bootstrap,
	// Owner proof or device-control grant. Do not downgrade an already active
	// Owner or mislabel this compatibility lane as default N2/App onboarding.
	f := newDirectIPHubSetup(t, "127.0.0.1", "", false)
	f.hub.kill(t)
	claimPath := filepath.Join(f.dir, "private", "account-only-claim.json")
	if directIPCLIAt(t, f.binary, "hub", "account-claim-issue", "--state-dir", f.state, "--claim-file", claimPath) != 0 {
		t.Fatal("fresh private account-only compatibility issuance unavailable")
	}
	var card wire.ClaimCard
	readJSON(t, claimPath, &card)
	if wire.ValidateClaimCard(card, f.descriptor.Claims.Hub, time.Now().UTC()) != nil {
		t.Fatal("actual local account-only claim does not match the retained Hub")
	}
	f.start(t)
	device, candidate := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	client := must(hubtransport.NewHTTPClient(f.descriptor, f.address, 12*time.Second))
	defer client.CloseIdleConnections()
	call := func(path string, body, out any) {
		packet := must(wire.SealClientRequest(device, f.descriptor.Claims.Hub, body))
		defer clear(packet)
		response := nodePairHTTP(client, card.Origin, path, packet)
		defer clear(response.response)
		if response.err != nil || response.status != http.StatusOK || wire.OpenClientResponse(device, f.descriptor.Claims.Hub, packet, response.response, out) != nil {
			t.Fatal("actual trusted-TLS/PQ account-only operation failed its authenticated original target")
		}
	}
	prepare := must(wire.NewClaimPrepare(card, f.descriptor.Claims.Hub, device.Public(), time.Now().UTC()))
	var challenge wire.ClaimChallenge
	call("/v2/owner/account/claim/prepare", prepare, &challenge)
	complete := must(wire.NewClaimCompleteFromChallenge(f.descriptor.Claims.Hub, challenge, device.Public(), "synthetic-account-only",
		syntheticPassword, candidate.Public(), time.Now().UTC()))
	var receipt wire.ClaimReceipt
	call("/v2/owner/account/claim/complete", complete, &receipt)
	if receipt.RootActive || receipt.RootState != wire.RootPendingState {
		t.Fatal("account claim public Owner candidate became Root without private-key proof")
	}
	login := must(wire.NewLoginPrepare(f.descriptor.Claims.Hub, card.Origin, card.AccountID, card.OwnerID, prepare.DeviceID,
		"synthetic-account-only", device.Public(), time.Now().UTC()))
	var loginChallenge wire.LoginChallenge
	call("/v2/owner/account/login/prepare", login, &loginChallenge)
	loginComplete := must(wire.NewLoginComplete(f.descriptor.Claims.Hub, loginChallenge, syntheticPassword, time.Now().UTC()))
	var session wire.SessionReceipt
	call("/v2/owner/account/login/complete", loginComplete, &session)
	defer clear(session.SessionToken)
	if len(session.SessionToken) != wire.MaxSessionTokenBytes || session.AccountID != card.AccountID || session.OwnerID != card.OwnerID {
		t.Fatal("account-only login did not create its legitimate scoped account session")
	}
	inspect := must(wire.NewSessionInspectRequest(session.Context(), time.Now().UTC()))
	var status wire.SessionInspection
	call("/v2/owner/account/session/inspect", inspect, &status)
	if status.RootActive || status.RootState != wire.RootPendingState || status.OwnerKeyID != candidate.Public().ID || status.ActorDeviceID != prepare.DeviceID {
		t.Fatal("successful account-only password login silently activated Root")
	}
	t.Log("NODE_PAIR_AUTHORITY actual_account_compatibility_login=true Root=PENDING_PROOF Owner_private_proof=false N2_control_grant=false TLS_PQ_authenticated=true")
}
