package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

type ownerGroupsRevocationWire struct {
	key      *e2ee.Identity
	binding  nodewire.Binding
	token    string
	sequence uint64
	digest   string
}

// Read the existing task-owned Node material for an adversarial cold renewal.
// No identity, credential, Owner proof or positive grant is created/replaced.
func captureOwnerGroupsRevocationWire(t *testing.T, v *codexProductFixture, d ownerGroupsIdentity) ownerGroupsRevocationWire {
	t.Helper()
	var state struct {
		nodeActorState
		HubKeyVersion   uint64 `json:"hub_key_version"`
		NodeKeyVersion  uint64 `json:"node_key_version"`
		Sequence        uint64 `json:"sequence"`
		PendingSequence uint64 `json:"pending_sequence"`
	}
	readJSON(t, v.actualNode.statePath(), &state)
	if state.BindingID != v.bound.BindingID || state.BindingVersion != v.bound.BindingVersion || state.NodeKeyEpoch != v.bound.NodeKeyEpoch ||
		state.NodeKeyID != v.bound.NodeKeyID || state.HubKeyVersion == 0 || state.NodeKeyVersion == 0 {
		t.Fatal("revocation adversary lost the original independently approved Node binding")
	}
	root := ownerGroupsNodeRoot(v)
	raw := readPrivate(t, filepath.Join(root, "node-control-identity.bin"))
	key := must(e2ee.UnmarshalIdentity(raw))
	clear(raw)
	if key.Public().ID != v.bound.NodeKeyID || nodewire.IdentityFingerprint(key.Public()) != v.bound.NodeFingerprint {
		t.Fatal("revocation adversary did not load the actual original Node key")
	}
	credential := readPrivate(t, filepath.Join(root, "relay.token"))
	token := strings.TrimSpace(string(credential))
	clear(credential)
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var digest string
	if db.QueryRow(`SELECT registration_digest FROM hub_endpoint_groups_registrations_v1 WHERE endpoint_id=? AND binding_id=? AND binding_epoch=?`, d.Endpoint, d.BindingID, d.BindingEpoch).Scan(&digest) != nil || token == "" || digest == "" {
		t.Fatal("revocation adversary lacks the original registration/credential")
	}
	return ownerGroupsRevocationWire{key: key, token: token, digest: digest, sequence: max(state.Sequence, state.PendingSequence) + 1,
		binding: nodewire.Binding{HubID: state.HubID, NodeID: state.NodeID, BindingID: state.BindingID, BindingVersion: state.BindingVersion,
			NodeKeyEpoch: state.NodeKeyEpoch, HubKeyVersion: state.HubKeyVersion, NodeKeyVersion: state.NodeKeyVersion, NodeKey: key.Public(), HubKey: state.HubPublic}}
}

func requireOwnerGroupsRevokedRenewal(t *testing.T, v *codexProductFixture, original ownerGroupsRevocationWire, d ownerGroupsIdentity) {
	t.Helper()
	body := must(json.Marshal(wire.EndpointGroupsNodeRenew{EndpointID: d.Endpoint, RegistrationDigest: original.digest,
		ExpectedBindingID: d.BindingID, ExpectedBindingEpoch: d.BindingEpoch}))
	defer clear(body)
	b := original.binding
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID,
		BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: original.sequence,
		OperationID: must(wire.NewRequestID()), Operation: wire.OperationEndpointGroupsNodeRenew, SenderKeyID: b.NodeKey.ID,
		SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	packet := must(nodewire.SealRequest(original.key, b.HubKey, b, route, body))
	defer clear(packet)
	request := must(http.NewRequest(http.MethodPost, v.f.cfg.Origin+"/v2/node/control/rpc", bytes.NewReader(packet)))
	request.Header.Set("Authorization", "CicadaNode "+original.token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := must(client.Do(request))
	defer response.Body.Close()
	raw := must(io.ReadAll(io.LimitReader(response.Body, nodewire.MaxPacketBytes+1)))
	defer clear(raw)
	if len(raw) > nodewire.MaxPacketBytes {
		t.Fatal("revoked renewal exceeded the actual Node response bound")
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal("cold renewal did not reach a known revocation Guard")
	}
	opened := must(nodewire.OpenResponse(original.key, b.HubKey, b, raw))
	defer clear(opened.Plaintext)
	var result appPairNodeReply
	if json.Unmarshal(opened.Plaintext, &result) != nil || result.OK || result.OperationID != route.OperationID || result.Sequence != route.Sequence || len(result.Result) != 0 {
		t.Fatal("revoked cold renewal produced a positive or unbound result")
	}
	switch result.ErrorCode {
	case "TARGET_NOT_AUTHORIZED", "UNAUTHORIZED", "OWNER_KEY_REVOKED", "NODE_BINDING_REVOKED", "NODE_KEY_REVOKED":
	default:
		t.Fatal("cold renewal failed for a reason other than actual authority revocation")
	}
}

func restartOwnerGroupsRevokedNode(t *testing.T, v *codexProductFixture, actors nativePeerActors) {
	t.Helper()
	v.actualNode.kill(t)
	command := exec.Command(filepath.Join(actors.prefix, "components/node/bin/cicada"), "machine", "agent", "--relay-only",
		"--id", v.actualNode.id, "--name", v.actualNode.id, "--control-url", v.f.cfg.Origin, "--state-dir", v.actualNode.state,
		"--interval", "1s", "--user-root", actors.prefix, "--mcp-session-state-file", v.mcpState, "--mcp-outbox-state-file", actors.outbox)
	command.Env = append(append([]string(nil), v.environment...), "CICADA_CODEX_BIN=/tools/codex-package/bin/codex")
	command.Stdout, command.Stderr = actors.log, actors.log
	v.actualNode = &nodeProcess{process: startProcess(v.f.parent, command), id: v.actualNode.id, state: v.actualNode.state}
	h := time.NewTimer(time.Second)
	defer h.Stop()
	<-h.C
	if !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("revocation cold check lost the actual owned Node or Hub process")
	}
}

// Two fresh independent authorized baselines: an Owner-key failure cannot mask
// a Node-binding failure. Only this task's synthetic production Store APIs are
// invoked. Physical user keys, Node state and public deployments are untouched.
func exerciseOwnerGroupsM7(t *testing.T) {
	t.Helper()
	for _, kind := range []string{"OwnerKey", "NodeBinding"} {
		v := newCodexProductFixture(t, "1s")
		registerOwnerGroupsProtocolAudit(t, v)
		requireOwnerGroupsAvailable(t, v)
		actors := prepareNativePeerActors(t, v, "revoke-"+strings.ToLower(kind), []string{"a", "b", "c", "d"})
		host, _ := startOwnerGroupsHost(t, v, actors)
		original := ownerGroupsOriginalActors(t, v, actors, host)
		d := original[3]
		panel := ownerGroupsCandidates(t, v, selectOwnerGroupsThread(t, v, actors.active.NetworkID, d))
		panel = prepareOwnerGroupsChange(t, v, panel, wire.OwnerEndpointGroupsCreateGroup, "", "Synthetic Revocation G2", "")
		submitOwnerGroupsReview(t, v, panel, "GROUP_CREATED")
		panel = ownerGroupsCandidates(t, v, selectOwnerGroupsThread(t, v, actors.active.NetworkID, d))
		g2 := ownerGroupsCandidateNamed(t, panel, "Synthetic Revocation G2").GroupID
		for _, index := range []int{0, 3} {
			review := prepareOwnerGroupsEndpointChange(t, v, actors, original[index], g2, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
			submitOwnerGroupsReview(t, v, review, "ADD_SUBMITTED")
			awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, original[index], g2, "ACTIVE", "OWNER")
		}
		host.roundtrip(t, "m7-before-g1", actors.active.GroupID, 3, 0, original)
		host.roundtrip(t, "m7-before-g2", g2, 3, 0, original)
		if kind == "OwnerKey" {
			logout := appcore.Action{Kind: appcore.ActionLogout}
			reply := v.command(t, appActorCommand{Action: &logout})
			if reply.ActionFailed || reply.Current.Account.SessionExpiresAt != "" {
				t.Fatal("actual synthetic App account logout was not acknowledged")
			}
			host.roundtrip(t, "m7-logout-g1", actors.active.GroupID, 3, 0, original)
			host.roundtrip(t, "m7-logout-g2", g2, 3, 0, original)
		}
		closeLocalDomainApp(t, v)
		credential := originalOwnerGroupsRESTCredential(t, v, d, g2)
		router := startOwnerGroupsFabricRouter(t, v)
		router.requireActor(t, credential, actors.active.GroupID)
		router.requireActor(t, credential, g2)
		material := captureOwnerGroupsRevocationWire(t, v, d)
		ownerGroupsSelect(t, host, 0, "m7-source-g1", actors.active.GroupID)
		release := holdOwnerGroupsNativeWriter(t, v, d)
		from, started := len(v.f.proxy.snapshot()), time.Now()
		body := "SYNTHETIC_OWNER_GROUP_QUESTION_" + host.fixtureScope + "_m7-" + kind
		ask := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m7-held-" + kind, Tool: "cicada_ask",
			Arguments:     map[string]any{"target": d.Endpoint, "question": body, "idempotency_key": host.fixtureScope + "-m7-" + kind},
			Queue:         []ownerGroupsQueueInput{{Body: body, SID: d.SID, Sender: original[0].Endpoint, Receiver: d.Endpoint, GroupID: actors.active.GroupID, Kind: "ask"}},
			ObserveFields: []string{"request_id", "operation_id"}})
		request := ask.Public["request_id"]
		for attempt := 0; request == "" && ask.Public["operation_id"] != "" && attempt < 4; attempt++ {
			time.Sleep(250 * time.Millisecond)
			status := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m7-held-status-" + kind + strconv.Itoa(attempt), Tool: "cicada_operation_status",
				Arguments: map[string]any{"operation_id": ask.Public["operation_id"]}, ObserveFields: []string{"request_id"}})
			request = status.Public["request_id"]
		}
		if request == "" || ask.QueuePosts[body] != 0 {
			release()
			t.Fatal("revocation writer fault missed the actual original pending ASK")
		}
		path := awaitOwnerGroupsDeliveryBeforeRemove(t, v, from, request, original[0], d, actors.active.GroupID)
		if time.Since(started) >= 10*time.Second {
			release()
			t.Fatal("revocation writer fault exceeded the original production admission window")
		}
		db := must(store.New(filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3")))
		key := must(db.GetOwnerApprovalKey(v.original.Account.OwnerID, v.original.Account.LocalOwnerKeyID))
		if key.State != store.OwnerApprovalKeyActive {
			db.Close()
			release()
			t.Fatal("independent revocation baseline already lacks the actual active Owner key")
		}
		if kind == "OwnerKey" {
			must(db.RevokeOwnerApprovalKeyLocal(key.OwnerID, key.KeyID, key.Version))
		} else {
			must(db.RevokeNodeDeviceBinding(key.OwnerID, v.bound.BindingID, int64(v.bound.BindingVersion)))
		}
		if db.Close() != nil {
			release()
			t.Fatal("actual production Store revocation did not close")
		}
		after := len(v.f.proxy.snapshot())
		release()
		awaitOwnerGroupsFinalDeliveryDenied(t, v, after, path)
		for _, group := range []string{actors.active.GroupID, g2} {
			status, raw := router.request(t, credential, group, http.MethodGet, "/v2/fabric/whoami", nil)
			clear(raw)
			if status != http.StatusUnauthorized && status != http.StatusForbidden {
				t.Fatal("true revocation left an original Group business actor authorized")
			}
		}
		restartOwnerGroupsRevokedNode(t, v, actors)
		host.command(t, ownerGroupsHostCommand{Action: "restart_host"})
		requireOwnerGroupsRevokedRenewal(t, v, material, d)
		checkpoint := host.command(t, ownerGroupsHostCommand{Action: "checkpoint"})
		if checkpoint.QueuePosts[body] != 0 {
			t.Fatal("true revoked authority reached the original native Runtime")
		}
		host.finish(t)
		router.process.kill(t)
		v.actualNode.kill(t)
		v.f.hub.kill(t)
	}
	observeOwnerGroupsCase(t, "M7_TrueAuthorityRevocation", map[string]bool{
		"actual_Owner_key_revoke": true, "actual_Node_binding_or_key_revoke": true, "all_Groups_denied": true,
		"cold_renewal_denied": true, "final_native_injection_denied": true, "App_logout_not_revocation": true,
	})
}
