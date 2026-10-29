package n3_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type ownerGroupsRetainedScope struct {
	selection                     string
	outbox                        ownerGroupsOutboxWitness
	oldDefaultRefusedWhileCurrent bool
}

// Private witnesses belong to this one owned Host, and are discarded with the
// parent fixture. They are observations, never actor tickets or grants.
var ownerGroupsRetainedScopes sync.Map

func ownerGroupsNodeRoot(v *codexProductFixture) string {
	return filepath.Join(v.actualNode.state, "nodes", "node-"+url.PathEscape(v.actualNode.id))
}

func ownerGroupsNodeAuditIdentity(t *testing.T, v *codexProductFixture) (*e2ee.Identity, nodewire.Binding) {
	t.Helper()
	var state struct {
		nodeActorState
		HubKeyVersion  uint64 `json:"hub_key_version"`
		NodeKeyVersion uint64 `json:"node_key_version"`
	}
	readJSON(t, v.actualNode.statePath(), &state)
	if state.BindingID != v.bound.BindingID || state.NodeID != v.actualNode.id || state.NodeKeyEpoch != v.bound.NodeKeyEpoch ||
		!reflect.DeepEqual(state.HubPublic, v.bound.HubPublic) || state.HubKeyVersion == 0 || state.NodeKeyVersion == 0 {
		t.Fatal("actual Node response audit changed its independently approved binding or Hub pin")
	}
	private := readPrivate(t, filepath.Join(ownerGroupsNodeRoot(v), "node-control-identity.bin"))
	identity, err := e2ee.UnmarshalIdentity(private)
	clear(private)
	if err != nil || identity.Public().ID != state.NodeKeyID {
		t.Fatal("actual Node response audit lost the original control key")
	}
	binding := nodewire.Binding{HubID: state.HubID, NodeID: state.NodeID, BindingID: state.BindingID,
		BindingVersion: state.BindingVersion, NodeKeyEpoch: state.NodeKeyEpoch, HubKeyVersion: state.HubKeyVersion,
		NodeKeyVersion: state.NodeKeyVersion, NodeKey: identity.Public(), HubKey: state.HubPublic}
	return identity, binding
}

// Decrypt only actual captured Node traffic with its already existing key.
// Neither this audit nor the parent signs a replacement Node/Owner completion.
func openOwnerGroupsNodeExchange(t *testing.T, v *codexProductFixture, ex exchange) appPairNodeReply {
	t.Helper()
	identity, binding := ownerGroupsNodeAuditIdentity(t, v)
	packet, err := nodewire.DecodePacket(ex.request)
	if err != nil || ex.Status != http.StatusOK || !ex.Forwarded || len(ex.response) == 0 {
		t.Fatal("actual Node response lacks its original forwarded encrypted request")
	}
	opened, err := nodewire.OpenResponse(identity, binding.HubKey, binding, ex.response)
	if err != nil {
		t.Fatal("actual Node response did not authenticate to its original approved key")
	}
	defer clear(opened.Plaintext)
	want := packet.Route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	var result appPairNodeReply
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &result) != nil || result.OperationID != packet.Route.OperationID ||
		result.Sequence != packet.Route.Sequence || result.OK && (result.ErrorCode != "" || len(result.Result) == 0) ||
		!result.OK && (result.ErrorCode == "" || len(result.Result) != 0) {
		t.Fatal("actual encrypted Node response changed its original operation or result")
	}
	return result
}

// The sender's outbound KEM packet can only be opened by the existing Hub
// Node-Control recipient key. Read it directly without a loader/initializer;
// its public identity must equal the Node's independently pinned Hub identity.
func openOwnerGroupsNodeRequest(t *testing.T, v *codexProductFixture, raw []byte) any {
	t.Helper()
	node, binding := ownerGroupsNodeAuditIdentity(t, v)
	private := readPrivate(t, filepath.Join(v.f.dir, "synthetic-hub", "e2ee", "node-control-identity.json"))
	hub, err := e2ee.UnmarshalIdentity(private)
	clear(private)
	if err != nil || !reflect.DeepEqual(hub.Public(), binding.HubKey) {
		t.Fatal("actual Node request audit lost the original pinned Hub recipient key")
	}
	packet, err := wire.DecodeEndpointGroupsNodePacket(raw)
	if err != nil || packet.Route.Direction != nodewire.DirectionRequest {
		t.Fatal("actual scoped Node request is malformed")
	}
	opened, err := nodewire.OpenRequest(hub, node.Public(), binding, raw)
	if err != nil || opened.Route != packet.Route {
		t.Fatal("actual scoped Node request did not authenticate its original sender and binding")
	}
	defer clear(opened.Plaintext)
	body, err := wire.DecodeEndpointGroupsNodeRequest(opened.Route.Operation, opened.Plaintext)
	if err != nil {
		t.Fatal("actual scoped Node request does not match its operation's canonical DTO")
	}
	return body
}

// A drop fault has no pausePoint entered signal. It consumes count under the
// proxy mutex, then records the actual upstream response before dropping it.
// One Node-Control client serializes all its RPCs under client.mu, so the first
// matching completed exchange after this exclusive arm is the consumed fault;
// a later retry cannot finish before that exchange is recorded and dropped.
func awaitOwnerGroupsDroppedNodeResponse(t *testing.T, p *faultProxy, from int, operation string) exchange {
	t.Helper()
	return awaitOwnerGroupsDroppedNodeResponseSince(t, p, from, operation, time.Now())
}

func awaitOwnerGroupsDroppedNodeResponseSince(t *testing.T, p *faultProxy, from int, operation string, started time.Time) exchange {
	t.Helper()
	deadline := started.Add(75 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		configured := p.path == "/v2/node/control/rpc" && p.method == http.MethodPost && p.nodeOperation == operation && p.mode == "drop-after-response"
		consumed := p.count == 0
		p.mu.Unlock()
		if !configured {
			t.Fatal("original Node response-loss fault was replaced before its exact packet was captured")
		}
		if consumed {
			for _, ex := range p.snapshot()[from:] {
				if ex.Path != "/v2/node/control/rpc" || ex.Method != http.MethodPost {
					continue
				}
				packet, err := nodewire.DecodePacket(ex.request)
				if err != nil {
					t.Fatal("actual Node emitted a malformed scoped packet during its response-loss fault")
				}
				if packet.Route.Operation != operation {
					continue
				}
				if !ex.Forwarded || ex.Status != http.StatusOK || len(ex.response) == 0 || ex.RequestSHA256 != hash(ex.request) || ex.ResponseSHA256 != hash(ex.response) {
					t.Fatal("the exact dropped Node response was not a recorded successful upstream encrypted exchange")
				}
				return ex
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual Node response-loss fault did not consume and retain its exact upstream exchange")
	return exchange{}
}

func requireOwnerGroupsLostRenewalRecovery(t *testing.T, v *codexProductFixture, from int, lost exchange, original []ownerGroupsIdentity) {
	t.Helper()
	originalPacket := must(wire.DecodeEndpointGroupsNodePacket(lost.request))
	originalBody, ok := openOwnerGroupsNodeRequest(t, v, lost.request).(wire.EndpointGroupsNodeRenew)
	if !ok || originalPacket.Route.Operation != wire.OperationEndpointGroupsNodeRenew {
		t.Fatal("response-loss witness was not the exact original renewal operation")
	}
	originalReply := openOwnerGroupsNodeExchange(t, v, lost)
	var renewed wire.EndpointGroupsNodeRenewResult
	if !originalReply.OK || json.Unmarshal(originalReply.Result, &renewed) != nil || renewed.ContractRevision != wire.OwnerEndpointGroupsContractRevision ||
		wire.ValidateEndpointGroupsRegistrationAnchor(renewed.Registration, v.f.cfg.Hub) != nil || renewed.Registration.RegistrationDigest != originalBody.RegistrationDigest ||
		renewed.Registration.BindingID != originalBody.ExpectedBindingID || renewed.Registration.BindingEpoch != originalBody.ExpectedBindingEpoch {
		t.Fatal("the exact lost renewal lacks its authenticated original registration result")
	}
	anchor, matched := renewed.Registration, false
	for _, identity := range original {
		if identity.Endpoint != originalBody.EndpointID {
			continue
		}
		if anchor.Registration.EndpointID != identity.Endpoint || anchor.Registration.NativeSessionID != identity.SID || anchor.Registration.PrincipalID != identity.Principal ||
			anchor.Registration.NodeID != identity.NodeID || anchor.Registration.Workspace != identity.Workspace || anchor.BindingID != identity.BindingID || anchor.BindingEpoch != identity.BindingEpoch ||
			hash(must(json.Marshal(anchor.CandidatePublic))) != identity.PublicKeySHA256 {
			t.Fatal("the dropped renewal changed its own exact original native actor or Endpoint key")
		}
		matched = true
	}
	if !matched {
		t.Fatal("the dropped renewal did not belong to one of the four original native actors")
	}
	recovered := false
	originalOccurrences := 0
	seen := make(map[string][]byte)
	for _, ex := range v.f.proxy.snapshot()[from:] {
		if ex.Path != "/v2/node/control/rpc" || ex.Method != http.MethodPost {
			continue
		}
		packet, err := nodewire.DecodePacket(ex.request)
		if err != nil {
			t.Fatal("actual Node emitted a malformed renewal/recovery envelope")
		}
		if packet.Route.Operation == wire.OperationEndpointGroupsNodeRenew {
			if prior, found := seen[packet.Route.OperationID]; found && !bytes.Equal(prior, ex.request) {
				t.Fatal("repeated Node renewal replaced its original exact packet")
			}
			seen[packet.Route.OperationID] = ex.request
		}
		if packet.Route.OperationID == originalPacket.Route.OperationID {
			originalOccurrences++
			if packet.Route != originalPacket.Route || !bytes.Equal(ex.request, lost.request) {
				t.Fatal("the uncertain lost renewal changed its original operation, sequence or ciphertext")
			}
			// An exact-packet retry is legitimate idempotency recovery. It only
			// proves THIS dropped operation when its authenticated receipt is the
			// immutable upstream receipt retained by the fault proxy.
			if ex.Forwarded && ex.Status == http.StatusOK && len(ex.response) != 0 {
				reply := openOwnerGroupsNodeExchange(t, v, ex)
				if !reply.OK || !bytes.Equal(ex.response, lost.response) || !bytes.Equal(reply.Result, originalReply.Result) {
					t.Fatal("the lost renewal replay did not return its exact immutable original receipt")
				}
				if originalOccurrences > 1 {
					recovered = true
				}
			}
		}
		if packet.Route.Operation != wire.OperationEndpointGroupsNodeReconcile {
			continue
		}
		reconcile, ok := openOwnerGroupsNodeRequest(t, v, ex.request).(wire.EndpointGroupsNodeReconcile)
		if !ok {
			t.Fatal("actual Node reconcile did not decode to its exact request DTO")
		}
		retained, err := wire.DecodeEndpointGroupsNodePacket(reconcile.OriginalPacket)
		if err != nil {
			t.Fatal("actual Node reconcile retained a malformed original packet")
		}
		if retained.Route.OperationID != originalPacket.Route.OperationID {
			continue
		}
		if !bytes.Equal(reconcile.OriginalPacket, lost.request) || retained.Route != originalPacket.Route {
			t.Fatal("lost-renewal reconciliation changed the original packet, operation ID or sequence")
		}
		want := originalPacket.Route
		want.Operation, want.OperationID = wire.OperationEndpointGroupsNodeReconcile, packet.Route.OperationID
		if packet.Route != want || packet.Route.OperationID == originalPacket.Route.OperationID {
			t.Fatal("lost-renewal reconciliation changed its original Node binding, sequence or recovery route")
		}
		if !ex.Forwarded || ex.Status != http.StatusOK || len(ex.response) == 0 {
			continue
		}
		outer := openOwnerGroupsNodeExchange(t, v, ex)
		var result wire.EndpointGroupsNodeReconciled
		if !outer.OK || json.Unmarshal(outer.Result, &result) != nil || wire.ValidateEndpointGroupsNodeReconcileTarget(result, lost.request) != nil ||
			result.State != "COMPLETED" || result.OriginalOperationID != originalPacket.Route.OperationID || result.OriginalSequence != originalPacket.Route.Sequence ||
			result.OriginalPacketDigest != nodewire.RecoveryDigest(lost.request) || !bytes.Equal(result.ReceiptPacket, lost.response) {
			t.Fatal("actual lost-renewal recovery did not authenticate the exact original ID, sequence, digest and immutable nested receipt")
		}
		nested := ex
		nested.request, nested.response = lost.request, result.ReceiptPacket
		receipt := openOwnerGroupsNodeExchange(t, v, nested)
		if !receipt.OK || receipt.OperationID != originalReply.OperationID || receipt.Sequence != originalReply.Sequence || !bytes.Equal(receipt.Result, originalReply.Result) {
			t.Fatal("actual nested lost-renewal receipt did not verify as the original successful renewal result")
		}
		recovered = true
	}
	if !recovered {
		t.Fatal("the exact dropped renewal has neither an authenticated identical replay nor a verified original-target nested reconciliation receipt")
	}
}

func readOwnerGroupsChallenge(t *testing.T, v *codexProductFixture, identity ownerGroupsIdentity, group string) wire.EndpointGroupKeyPrepareResult {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var raw []byte
	if db.QueryRow(`SELECT challenge_json FROM hub_endpoint_groups_key_challenges_v1 WHERE endpoint_id=? AND group_id=? AND state='PREPARED' ORDER BY created_at DESC LIMIT 1`, identity.Endpoint, group).Scan(&raw) != nil || len(raw) > wire.MaxOwnerEndpointGroupsPageBytes {
		t.Fatal("actual held completion lacks its original prepared challenge")
	}
	defer clear(raw)
	var challenge wire.EndpointGroupKeyPrepareResult
	if json.Unmarshal(raw, &challenge) != nil || challenge.ProjectedRelation.EndpointID != identity.Endpoint || challenge.ProjectedRelation.GroupID != group ||
		challenge.ProjectedRelation.BindingID != identity.BindingID || challenge.ProjectedRelation.BindingEpoch != identity.BindingEpoch ||
		must(wire.EndpointGroupKeyChallengeDigest(challenge)) != challenge.ChallengeDigest {
		t.Fatal("actual held challenge changed its exact original native projection")
	}
	return challenge
}

func readOwnerGroupsCompletedGrant(t *testing.T, v *codexProductFixture, challenge wire.EndpointGroupKeyPrepareResult) (wire.EndpointGroupDelegatedGrant, e2ee.EndpointGroupPolicy) {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var grantRaw, policyRaw []byte
	var state string
	if db.QueryRow(`SELECT grant_json,policy_json,state FROM hub_endpoint_groups_policies_v1 WHERE policy_id=? AND endpoint_id=? AND group_id=? AND epoch=?`,
		challenge.PolicyID, challenge.ProjectedRelation.EndpointID, challenge.ProjectedRelation.GroupID, challenge.PolicyEpoch).
		Scan(&grantRaw, &policyRaw, &state) != nil || state != "ACTIVE" || len(grantRaw) > wire.MaxOwnerEndpointGroupsPageBytes || len(policyRaw) > wire.MaxOwnerEndpointGroupsPageBytes {
		t.Fatal("actual completion lacks one exact active stored delegation")
	}
	defer clear(grantRaw)
	defer clear(policyRaw)
	var grant wire.EndpointGroupDelegatedGrant
	var policy e2ee.EndpointGroupPolicy
	if json.Unmarshal(grantRaw, &grant) != nil || json.Unmarshal(policyRaw, &policy) != nil || grant.Relation != challenge.ProjectedRelation ||
		!reflect.DeepEqual(grant.Manifest, challenge.ProjectedKeyManifest) || must(e2ee.OwnerDevicePublicKeyFingerprint(policy.OwnerPublic)) != v.original.Account.OwnerFingerprint {
		t.Fatal("actual completion changed the reviewed ACTIVE relation/manifest or original Owner key")
	}
	verified, err := wire.VerifyEndpointGroupDelegatedGrant(grant, v.f.cfg.Hub, v.original.Account.OwnerID, policy.OwnerPublic, time.Now().UTC())
	claims, claimsErr := e2ee.VerifyEndpointGroupKey(policy, grant.NodeProof, time.Now().UTC())
	expected, expectedErr := wire.EndpointGroupKeyClaimsForChallenge(challenge, policy)
	if err != nil || !reflect.DeepEqual(verified, policy) || claimsErr != nil || expectedErr != nil || claims != expected {
		t.Fatal("actual Node completion did not sign the original Owner-reviewed exact projection")
	}
	return grant, policy
}

type ownerGroupsActualPeerKey struct {
	Sender struct {
		Endpoint string                            `json:"endpoint_id"`
		Default  *wire.LocalDomainEndpointKeyGrant `json:"local_domain_grant"`
		Manual   *wire.EndpointGroupDelegatedGrant `json:"endpoint_group_grant"`
	} `json:"sender"`
	Receiver struct {
		Endpoint string                            `json:"endpoint_id"`
		Default  *wire.LocalDomainEndpointKeyGrant `json:"local_domain_grant"`
		Manual   *wire.EndpointGroupDelegatedGrant `json:"endpoint_group_grant"`
	} `json:"receiver"`
	Current *wire.EndpointGroupCurrent `json:"endpoint_group_current"`
}

func readOwnerGroupsActualPeerKey(t *testing.T, v *codexProductFixture, a, b ownerGroupsIdentity, group string) ownerGroupsActualPeerKey {
	t.Helper()
	// These are exactly the three required keys accepted by the production
	// relayNodeGroupSealedPeerKey handler. The existing Node credential may
	// request current public evidence; it cannot author a Current or grant.
	query := url.Values{"group_id": {group}, "source_endpoint_id": {a.Endpoint}, "target_endpoint_id": {b.Endpoint}}
	path := "/v2/relay/nodes/" + url.PathEscape(v.actualNode.id) + "/group/sealed/peer-key?" + query.Encode()
	status, raw := ownerGroupsNodeRequest(t, v, http.MethodGet, path, nil)
	defer clear(raw)
	var peer ownerGroupsActualPeerKey
	if status != http.StatusOK || json.Unmarshal(raw, &peer) != nil || peer.Sender.Endpoint != a.Endpoint || peer.Receiver.Endpoint != b.Endpoint ||
		peer.Current == nil || peer.Current.GroupID != group || peer.Current.Sender.Relation.EndpointID != a.Endpoint || peer.Current.Receiver.Relation.EndpointID != b.Endpoint ||
		wire.ValidateEndpointGroupCurrent(*peer.Current, "peer_key", a.Endpoint+":"+b.Endpoint, time.Now().UTC()) != nil {
		t.Fatal("actual Node-authenticated peer-key read changed its original Endpoint/Group tuple or fresh Current")
	}
	return peer
}

func ownerGroupsRetainedDefaultAllowed(t *testing.T, v *codexProductFixture, peer ownerGroupsActualPeerKey, phase string) bool {
	t.Helper()
	now := time.Now().UTC()
	current := peer.Current
	diagnostic := map[string]any{"phase": phase, "actual_wall": now.Format(time.RFC3339Nano), "current_present": current != nil,
		"sender_default": peer.Sender.Default != nil, "receiver_default": peer.Receiver.Default != nil,
		"sender_manual": peer.Sender.Manual != nil, "receiver_manual": peer.Receiver.Manual != nil}
	if current != nil {
		mode := func(value string) string {
			if value == "DEFAULT" || value == "OWNER" {
				return value
			}
			return "OTHER"
		}
		stamp := func(value string) string {
			if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
				return parsed.UTC().Format(time.RFC3339Nano)
			}
			return "INVALID"
		}
		diagnostic["sender_mode"], diagnostic["receiver_mode"] = mode(current.Sender.OwnerControl.Mode), mode(current.Receiver.OwnerControl.Mode)
		diagnostic["current_observed_at"], diagnostic["current_expires_at"] = stamp(current.ObservedAt), stamp(current.ExpiresAt)
		diagnostic["group_sha256"] = hash([]byte(current.GroupID))
	}
	if current == nil || peer.Sender.Default == nil || peer.Receiver.Default == nil || peer.Sender.Manual != nil || peer.Receiver.Manual != nil {
		t.Fatalf("old-default witness source shape changed: metadata=%s", must(json.Marshal(diagnostic)))
	}
	if current.Sender.OwnerControl.Mode != "DEFAULT" || current.Receiver.OwnerControl.Mode != "DEFAULT" {
		t.Fatalf("old-default witness is not DEFAULT: metadata=%s", must(json.Marshal(diagnostic)))
	}
	if wire.ValidateEndpointGroupCurrent(*current, current.Operation, current.AttemptID, now) != nil {
		t.Fatalf("old-default witness Current is invalid at actual wall clock: metadata=%s", must(json.Marshal(diagnostic)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	state := must(nodekeys.OpenExistingCryptoState(ctx, ownerGroupsNodeRoot(v)))
	defer state.Close()
	required, err := state.VerifyEndpointGroupsGroupAuthorization(ctx, peer.Sender.Endpoint, current.GroupID,
		wire.EndpointGroupPeerSource{LocalDomainGrant: peer.Sender.Default}, wire.EndpointGroupPeerSource{LocalDomainGrant: peer.Receiver.Default}, current,
		current.Operation, current.AttemptID, now)
	if !required {
		t.Fatal("actual original default source escaped the managed Group verifier")
	}
	if err != nil && !errors.Is(err, nodekeys.ErrEndpointGroupsConflict) {
		t.Fatal("actual old-default verification failed outside the expected permanent Owner highwater Guard")
	}
	diagnostic["allowed"] = err == nil
	t.Logf("OWNER_GROUPS_DEFAULT_WITNESS metadata=%s", must(json.Marshal(diagnostic)))
	return err == nil
}

func verifyOwnerGroupsRetainedDefault(t *testing.T, v *codexProductFixture, peer ownerGroupsActualPeerKey, wantAllowed bool) {
	t.Helper()
	phase := "PRE_RELEASE_DEFAULT"
	if !wantAllowed {
		phase = "AFTER_NODE_OWNER_HEAD"
	}
	if ownerGroupsRetainedDefaultAllowed(t, v, peer, phase) != wantAllowed {
		t.Fatal("actual existing Node verifier did not enforce permanent Owner takeover against the same still-current default source")
	}
}

func awaitOwnerGroupsNodeHead(t *testing.T, v *codexProductFixture, endpoint, group string, expected e2ee.EndpointGroupOwnerControl, takeoverDeadline, currentExpiry time.Time) {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(ownerGroupsNodeRoot(v), "node-crypto-state.sqlite"))
	defer db.Close()
	observe := func(closed map[string]any) {
		t.Logf("OWNER_GROUPS_NODE_HEAD_WAIT metadata=%s", must(json.Marshal(closed)))
	}
	if err := waitOwnerGroupsNodeHead(db, v.f.cfg.Hub.HubID, endpoint, group, expected, takeoverDeadline, currentExpiry, v.actualNode.running, observe); err != nil {
		t.Fatalf("actual Node head observation failed within the original Current window: code=%s", err)
	}
}

// Refresh only real DEFAULT Current while the normal worker completes the
// already signed original. A cancelled five-second HTTP attempt may need its
// next normal tick; the latest independently verified original still has its
// actual thirty-second window when the Node commits permanent OWNER highwater.
func awaitOwnerGroupsDefaultTakeover(t *testing.T, v *codexProductFixture, a, b ownerGroupsIdentity, group string, head e2ee.EndpointGroupOwnerControl, previous ownerGroupsActualPeerKey) {
	t.Helper()
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) {
		peer := readOwnerGroupsActualPeerKey(t, v, a, b, group)
		if peer.Current.Sender.OwnerControl == head {
			awaitOwnerGroupsNodeHead(t, v, a.Endpoint, group, head, deadline, must(time.Parse(time.RFC3339Nano, previous.Current.ExpiresAt)))
			verifyOwnerGroupsRetainedDefault(t, v, previous, false)
			return
		}
		if peer.Current.Sender.OwnerControl.Mode != "DEFAULT" || peer.Current.Receiver.OwnerControl.Mode != "DEFAULT" {
			t.Fatal("actual finite takeover changed to an unrelated Owner-control head or peer")
		}
		// A concurrent completion may commit after the Hub captured DEFAULT
		// but before this read guard. Only an actual successful positive check
		// replaces the retained witness; a racing rejection never supplies one.
		if ownerGroupsRetainedDefaultAllowed(t, v, peer, "REFRESH_DEFAULT") {
			previous = peer
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("actual normal Node worker did not complete the original finite takeover")
}

func requireOwnerGroupsPendingNoManualRights(t *testing.T, v *codexProductFixture, identity ownerGroupsIdentity, group string, challenge wire.EndpointGroupKeyPrepareResult, activeEdges int) {
	t.Helper()
	hub := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer hub.Close()
	var state, grant string
	if hub.QueryRow(`SELECT state,grant_json FROM hub_endpoint_groups_policies_v1 WHERE policy_id=? AND epoch=? AND endpoint_id=? AND group_id=?`,
		challenge.PolicyID, challenge.PolicyEpoch, identity.Endpoint, group).Scan(&state, &grant) != nil || state != "PENDING_KEY" || grant != "" ||
		ownerGroupsRelationCount(t, v, identity.Endpoint, group) != activeEdges {
		t.Fatal("held actual manual policy granted new Hub rights or changed the original effective Endpoint edge")
	}
	node := nodePairReadOnlyDB(t, filepath.Join(ownerGroupsNodeRoot(v), "node-crypto-state.sqlite"))
	defer node.Close()
	var sources, heads int
	if node.QueryRow(`SELECT count(*) FROM node_endpoint_group_sources_v1 WHERE hub_id=? AND endpoint_id=? AND group_id=? AND source='OWNER_EXPLICIT'
AND json_extract(CAST(relation_json AS TEXT),'$.authority_id')=? AND json_extract(CAST(relation_json AS TEXT),'$.state')='ACTIVE'`,
		v.f.cfg.Hub.HubID, identity.Endpoint, group, challenge.PolicyID).Scan(&sources) != nil ||
		node.QueryRow(`SELECT count(*) FROM node_endpoint_group_heads_v1 WHERE hub_id=? AND endpoint_id=? AND group_id=?
AND json_extract(CAST(head_json AS TEXT),'$.policy_id')=? AND json_extract(CAST(head_json AS TEXT),'$.mode')='OWNER'
AND json_extract(CAST(head_json AS TEXT),'$.deny_reason')='NONE'`, v.f.cfg.Hub.HubID, identity.Endpoint, group, challenge.PolicyID).Scan(&heads) != nil || sources != 0 || heads != 0 {
		t.Fatal("held actual manual policy installed a new ACTIVE Node source or Owner completion head")
	}
}

func requireOwnerGroupsRESTDenied(t *testing.T, router ownerGroupsFabricRouter, credential ownerGroupsRESTCredential, positiveGroup, deniedGroup string) {
	t.Helper()
	router.requireActor(t, credential, positiveGroup)
	status, raw := router.request(t, credential, deniedGroup, http.MethodGet, "/v2/fabric/whoami", nil)
	clear(raw)
	if status != http.StatusForbidden {
		t.Fatal("held pending re-add did not retain a real Group Guard denial under its original live credential")
	}
	router.requireActor(t, credential, positiveGroup)
}

// A held client may cancel before forwarding. Retain only the actual packet
// recorded by the fault proxy, then submit those SAME bytes after Owner REMOVE
// solely to prove the production negative fence. No signer or new completion.
func rejectOwnerGroupsHeldCompletion(t *testing.T, v *codexProductFixture, from int, identity ownerGroupsIdentity, group string, challenge wire.EndpointGroupKeyPrepareResult) exchange {
	t.Helper()
	var held exchange
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) && len(held.request) == 0 {
		for _, ex := range v.f.proxy.snapshot()[from:] {
			if ex.Method != http.MethodPost || ex.Path != "/v2/node/control/rpc" {
				continue
			}
			packet, err := nodewire.DecodePacket(ex.request)
			if err != nil || packet.Route.Operation != wire.OperationEndpointGroupsNodeKeyComplete {
				continue
			}
			q, ok := openOwnerGroupsNodeRequest(t, v, ex.request).(wire.EndpointGroupsNodeKeyComplete)
			if !ok || q.EndpointID != identity.Endpoint || q.GroupID != group || q.PolicyID != challenge.PolicyID || q.PolicyEpoch != challenge.PolicyEpoch ||
				q.ChallengeID != challenge.ChallengeID || q.ExpectedRelationRevision != challenge.Expected.RelationRevision {
				continue
			}
			if ex.RequestSHA256 != hash(ex.request) {
				t.Fatal("held old completion changed its original recorded ciphertext")
			}
			held = ex
			break
		}
		if len(held.request) == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if len(held.request) == 0 {
		t.Fatal("actual held old completion did not retain its precise original Node packet")
	}
	if held.Status == http.StatusOK {
		r := openOwnerGroupsNodeExchange(t, v, held)
		if r.OK || r.ErrorCode != "TARGET_NOT_AUTHORIZED" {
			t.Fatal("released old completion escaped the later exact Owner REMOVE")
		}
	}
	token := readPrivate(t, filepath.Join(ownerGroupsNodeRoot(v), "relay.token"))
	defer clear(token)
	request := must(http.NewRequest(http.MethodPost, v.f.cfg.Origin+"/v2/node/control/rpc", bytes.NewReader(held.request)))
	request.Header.Set("Authorization", "CicadaNode "+strings.TrimSpace(string(token)))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := must(client.Do(request))
	raw := must(io.ReadAll(io.LimitReader(response.Body, wire.MaxEndpointGroupsNodeReceiptBytes+1)))
	response.Body.Close()
	defer clear(raw)
	if response.StatusCode != http.StatusOK || len(raw) > wire.MaxEndpointGroupsNodeReceiptBytes {
		t.Fatal("negative exact-packet completion replay lacks its real sealed Node refusal")
	}
	actual := held
	actual.Forwarded, actual.Status, actual.response = true, response.StatusCode, raw
	rejected := openOwnerGroupsNodeExchange(t, v, actual)
	if rejected.OK || rejected.ErrorCode != "TARGET_NOT_AUTHORIZED" {
		t.Fatal("negative original completion replay was not authenticated as TARGET_NOT_AUTHORIZED")
	}
	packet := must(wire.DecodeEndpointGroupsNodePacket(held.request))
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var state, digest, operation string
	var receipt []byte
	if db.QueryRow(`SELECT state,request_digest,operation,response_packet FROM hub_endpoint_groups_node_operations_v1
WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=? AND sequence=?`, packet.Route.BindingID, packet.Route.NodeKeyEpoch, packet.Route.OperationID, packet.Route.Sequence).
		Scan(&state, &digest, &operation, &receipt) != nil || state != "REJECTED_FENCED" || digest != hash(held.request) || operation != wire.OperationEndpointGroupsNodeKeyComplete || !bytes.Equal(receipt, raw) {
		clear(receipt)
		t.Fatal("negative old completion lacks its exact original ID/sequence/ciphertext permanent Hub fence")
	}
	clear(receipt)
	// The returned witness is not local Node consumption. Its private response
	// survives this function's buffer clear only for the readonly settlement gate.
	actual.response = bytes.Clone(raw)
	return actual
}

func exerciseOwnerGroupsM4(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity, g2 string, denied ownerGroupsDeniedDelivery) {
	t.Helper()
	if len(original) != 4 || denied.Group != actors.active.GroupID {
		t.Fatal("M4 requires the four original actors and exact removed G1 request")
	}
	d, a := original[3], original[0]
	retained := &ownerGroupsRetainedScope{outbox: readOwnerGroupsCipher(t, v, readOwnerGroupsOutbox(t, actors, original[0], denied), denied.RequestID)}
	ownerGroupsRetainedScopes.Store(host, retained)
	v.f.parent.Cleanup(func() { ownerGroupsRetainedScopes.Delete(host) })
	// Select a real G1 card while it is still independently available. Prove
	// wrong-Group rejection immediately, before its 120-second reference expiry.
	ownerGroupsSelect(t, host, 0, "m4-original-g1-select", actors.active.GroupID)
	readPosts := ownerGroupsBusinessPosts(v, denied.RequestID)
	originalRead := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m4-original-readonly-status", Tool: "cicada_operation_status",
		Arguments: map[string]any{"operation_id": retained.outbox.Operation}, ObserveFields: []string{"operation_id", "request_id"}})
	if originalRead.Public["operation_id"] != retained.outbox.Operation || originalRead.Public["request_id"] != denied.RequestID || readPosts != 1 || ownerGroupsBusinessPosts(v, denied.RequestID) != readPosts {
		t.Fatal("actual original readonly recovery changed request/outbox identity or dispatched business")
	}
	card := selectOwnerGroupsThread(t, v, actors.active.NetworkID, original[1]).Selected
	if card == nil || card.Name == "" {
		t.Fatal("actual selection target lacks its authenticated native display name")
	}
	selected := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m4-retain-g1-peer", Tool: "cicada_select_peer",
		Arguments: map[string]any{"scope": "group", "query": card.Name}, Form: map[string]any{"action": "accept", "name": card.Name, "workspace": original[1].Workspace, "server": ""},
		ObserveFields: []string{"peer_selection_id", "endpoint_id", "scope_id"}})
	if selected.Public["peer_selection_id"] == "" || selected.Public["endpoint_id"] != original[1].Endpoint || selected.Public["scope_id"] != actors.active.GroupID {
		t.Fatal("actual G1 selection did not return its exact original authorized peer")
	}
	retained.selection = selected.Public["peer_selection_id"]
	ownerGroupsSelect(t, host, 0, "m4-g2-ref-check", g2)
	refused := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m4-g1-reference-in-g2", Tool: "cicada_ask",
		Arguments: map[string]any{"peer_selection_id": retained.selection, "question": "SYNTHETIC cross-Group retained selection", "idempotency_key": host.fixtureScope + "-m4-wrong-group-selection"}})
	requireOwnerGroupsHostRefusal(t, refused, "PEER_SELECTION_STALE", "PEER_SELECTION_INVALID")
	ownerGroupsCLIAdmission(t, v, actors, host, d, "leave")
	ownerGroupsCLIAdmission(t, v, actors, host, d, "join")
	restartNativePeerNode(t, v, actors)
	host.command(t, ownerGroupsHostCommand{Action: "restart_host"})
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "REMOVED", "OWNER")
	host.groups(t, 3, "m4-join-deny-survives", actors.active.NetworkID, "", map[string]string{g2: "OWNER_EXPLICIT"})
	ownerGroupsDenySelection(t, host, 3, "m4-new-attempt-g1-denied", actors.active.GroupID)
	host.roundtrip(t, "m4-join-original-g2", g2, 3, 2, original)
	router := startOwnerGroupsFabricRouter(t, v)
	defer router.process.kill(t)
	dCredential := originalOwnerGroupsRESTCredential(t, v, d, g2)
	requireOwnerGroupsRESTDenied(t, router, dCredential, g2, actors.active.GroupID)
	// A pending re-add cannot clear the existing permanent deny. Remove it
	// while its real Node completion is held, then release that exact old packet.
	panel := prepareOwnerGroupsEndpointChange(t, v, actors, d, actors.active.GroupID, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
	heldFrom := len(v.f.proxy.snapshot())
	entered, release := armOwnerGroupsFault(t, v.f.proxy, "complete-held-before-forward")
	defer release()
	submitOwnerGroupsReview(t, v, panel, "ADD_SUBMITTED")
	select {
	case <-entered:
	case <-time.After(75 * time.Second):
		t.Fatal("actual denied re-add did not reach its Node completion barrier")
	}
	pending := awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "REMOVED", "OWNER")
	if pending.DenyReason != "REMOVED" {
		t.Fatal("pending re-add cleared the existing manual deny")
	}
	manualPending := false
	for _, source := range pending.Contributions {
		if source.Source == "OWNER_EXPLICIT" && source.State == "PENDING_KEY" && !source.Effective && source.KeyState != "CURRENT" {
			manualPending = true
		}
	}
	if !manualPending {
		t.Fatal("actual denied re-add lacks its ineffective pending contribution")
	}
	deniedChallenge := readOwnerGroupsChallenge(t, v, d, actors.active.GroupID)
	// Fresh Hook/self/ASK shares the production completion mutex. During its
	// hold, the real Fabric router independently authenticates this ORIGINAL
	// native credential, brackets G1's 403 with live G2, and audits zero new
	// Hub/Node manual rights without passing through that blocked local mutex.
	requireOwnerGroupsPendingNoManualRights(t, v, d, actors.active.GroupID, deniedChallenge, 0)
	requireOwnerGroupsRESTDenied(t, router, dCredential, g2, actors.active.GroupID)
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, d, actors.active.GroupID, wire.OwnerEndpointGroupsRemoveEndpoint, "")
	submitOwnerGroupsReview(t, v, panel, "REMOVED")
	release()
	rejectedCompletion := rejectOwnerGroupsHeldCompletion(t, v, heldFrom, d, actors.active.GroupID, deniedChallenge)
	defer clear(rejectedCompletion.response)
	awaitOwnerGroupsNodeSettlement(t, v, "m4-released-original-complete", rejectedCompletion)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "REMOVED", "OWNER")
	requireOwnerGroupsRESTDenied(t, router, dCredential, g2, actors.active.GroupID)
	ownerGroupsDenySelection(t, host, 3, "m4-released-g1-denied", actors.active.GroupID)
	host.roundtrip(t, "m4-released-original-g2", g2, 3, 2, original)
	// Only a separate current Owner re-add may now clear D's deny. Lose that
	// actual completion response, recover it through ordinary Node restart,
	// then explicitly remove D again to retain M3's original G1 boundary.
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, d, actors.active.GroupID, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
	lostFrom := len(v.f.proxy.snapshot())
	_, lostRelease := armOwnerGroupsFault(t, v.f.proxy, "complete-lost-response")
	defer lostRelease()
	submitOwnerGroupsReview(t, v, panel, "ADD_SUBMITTED")
	lostCompletion := awaitOwnerGroupsDroppedNodeResponse(t, v.f.proxy, lostFrom, wire.OperationEndpointGroupsNodeKeyComplete)
	completion, ok := openOwnerGroupsNodeRequest(t, v, lostCompletion.request).(wire.EndpointGroupsNodeKeyComplete)
	reply := openOwnerGroupsNodeExchange(t, v, lostCompletion)
	var completed wire.EndpointGroupsNodeKeyResult
	var proof e2ee.OwnerEndpointGroupPolicyProof
	if !ok || completion.EndpointID != d.Endpoint || completion.GroupID != actors.active.GroupID || !reply.OK || json.Unmarshal(reply.Result, &completed) != nil ||
		json.Unmarshal(completed.PolicyProof, &proof) != nil || must(e2ee.OwnerDevicePublicKeyFingerprint(proof.Policy.OwnerPublic)) != v.original.Account.OwnerFingerprint || completed.Grant == nil ||
		completed.Grant.Relation.PolicyID != completion.PolicyID || completed.Grant.Relation.PolicyEpoch != completion.PolicyEpoch || completed.Grant.Relation.EndpointID != d.Endpoint || completed.Grant.Relation.GroupID != actors.active.GroupID {
		t.Fatal("actual dropped completion did not commit the exact new Owner re-add of original D-G1")
	}
	if _, err := wire.ValidateEndpointGroupsNodeKeyResult(completed, v.f.cfg.Hub, v.original.Account.OwnerID, proof.Policy.OwnerPublic, must(time.Parse(time.RFC3339Nano, completed.ObservedAt))); err != nil {
		t.Fatal("actual dropped D-G1 completion did not authenticate its exact original Node/Owner projection")
	}
	lostRelease()
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "ACTIVE", "OWNER")
	restartNativePeerNode(t, v, actors)
	awaitOwnerGroupsNodeSettlement(t, v, "m4-lost-complete-after-restart", lostCompletion)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "ACTIVE", "OWNER")
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, d, actors.active.GroupID, wire.OwnerEndpointGroupsRemoveEndpoint, "")
	submitOwnerGroupsReview(t, v, panel, "REMOVED")
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "REMOVED", "OWNER")
	// A_G1 is never denied. Hold a finite manual takeover and verify its
	// existing default rights stay live until exact completion commits OWNER.
	host.roundtrip(t, "m4-before-finite-takeover", actors.active.GroupID, 0, 1, original)
	aCredential := originalOwnerGroupsRESTCredential(t, v, a, actors.active.GroupID)
	router.requireActor(t, aCredential, actors.active.GroupID)
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, a, actors.active.GroupID, wire.OwnerEndpointGroupsAddEndpoint, "1d")
	if panel.Review == nil || panel.Review.PolicyExpiresAt == "" || panel.Review.Duration != "1d" {
		t.Fatal("actual finite Owner review omitted its original policy deadline")
	}
	policyEnd := panel.Review.PolicyExpiresAt
	finiteFrom := len(v.f.proxy.snapshot())
	entered, release = armOwnerGroupsFault(t, v.f.proxy, "finite-complete-held-until-release")
	defer release()
	submitOwnerGroupsReview(t, v, panel, "ADD_SUBMITTED")
	select {
	case <-entered:
	case <-time.After(75 * time.Second):
		t.Fatal("actual finite takeover did not reach its Node completion barrier")
	}
	pending = awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, a, actors.active.GroupID, "ACTIVE", "DEFAULT")
	defaultLive, manualPending := false, false
	for _, source := range pending.Contributions {
		if source.Source == "DEFAULT_POLICY" && source.State == "ACTIVE" && source.Effective && source.KeyState == "CURRENT" {
			defaultLive = true
		}
		if source.Source == "OWNER_EXPLICIT" && source.State == "PENDING_KEY" && !source.Effective && source.ExpiresAt == policyEnd {
			manualPending = true
		}
	}
	if !defaultLive || !manualPending || pending.DenyReason != "NONE" {
		t.Fatal("pending manual takeover lowered a never-denied default source or granted manual rights")
	}
	challenge := readOwnerGroupsChallenge(t, v, a, actors.active.GroupID)
	requireOwnerGroupsPendingNoManualRights(t, v, a, actors.active.GroupID, challenge, 1)
	router.requireActor(t, aCredential, actors.active.GroupID)
	// Capture the original positive default verifier as late as possible so
	// takeover is checked inside the SAME 30-second Current validity window.
	// This direct Node-authenticated Hub read avoids the held local Hook mutex.
	oldDefault := readOwnerGroupsActualPeerKey(t, v, a, original[1], actors.active.GroupID)
	verifyOwnerGroupsRetainedDefault(t, v, oldDefault, true)
	if time.Until(must(time.Parse(time.RFC3339Nano, oldDefault.Current.ExpiresAt))) < 10*time.Second {
		t.Fatal("original default Current did not leave an independent takeover observation window")
	}
	release()
	awaitOwnerGroupsDefaultTakeover(t, v, a, original[1], actors.active.GroupID, challenge.ProjectedOwnerControl, oldDefault)
	active := awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, a, actors.active.GroupID, "ACTIVE", "OWNER")
	awaitOwnerGroupsPositiveCompletion(t, v, finiteFrom, "m4-finite-original-complete", a, actors.active.GroupID)
	retained.oldDefaultRefusedWhileCurrent = true
	grant, policy := readOwnerGroupsCompletedGrant(t, v, challenge)
	if active.ExpiresAt != policyEnd || policy.ExpiresAt != policyEnd || grant.Manifest.ExpiresAt != policyEnd ||
		must(wire.EndpointGroupDurationExpiry("1d", must(time.Parse(time.RFC3339Nano, policy.IssuedAt)))) != policyEnd {
		t.Fatal("finite manual duration moved from the original Owner review")
	}
	restartNativePeerNode(t, v, actors)
	awaitOwnerGroupsPositiveCompletion(t, v, finiteFrom, "m4-finite-complete-after-restart", a, actors.active.GroupID)
	host.command(t, ownerGroupsHostCommand{Action: "restart_host"})
	active = awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, a, actors.active.GroupID, "ACTIVE", "OWNER")
	retried, retriedPolicy := readOwnerGroupsCompletedGrant(t, v, challenge)
	if active.ExpiresAt != policyEnd || !reflect.DeepEqual(retried, grant) || !reflect.DeepEqual(retriedPolicy, policy) {
		t.Fatal("normal restart/retry extended finite delegation or replaced its exact completion")
	}
	ownerGroupsDenySelection(t, host, 3, "m4-restart-g1-denied", actors.active.GroupID)
	host.roundtrip(t, "m4-owner-g1-after-retry", actors.active.GroupID, 0, 1, original)
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	observeOwnerGroupsCase(t, "M4_PermanentOwnerControl", map[string]bool{
		"manual_deny_survives_Join_and_restart": true, "pending_does_not_clear_deny": true,
		"pending_preserves_undenied_default": true, "Complete_commits_exact_ACTIVE_projection": true,
		"OWNER_mode_permanent": true, "finite_manual_duration_bound_to_original_review": true, "old_completion_after_remove_denied": true,
	})
	t.Log("OWNER_GROUPS_LIMIT M4_24h_wall_clock_expiry=NOT_RUN finite_manual_expiry_no_default_fallback=SEPARATE_PRODUCTION_STORE_CRYPTO_EVIDENCE")
}

// This is the existing native lease, read without a Store initializer or write
// connection. A Group operation must not rotate its credential, owner or epoch.
type ownerGroupsNativeLease struct {
	Binding, CredentialHash, LeaseOwner, ExpiresAt string
	Epoch                                          uint64
}

func readOwnerGroupsNativeLease(t *testing.T, v *codexProductFixture, identity ownerGroupsIdentity) ownerGroupsNativeLease {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
	defer db.Close()
	var lease ownerGroupsNativeLease
	if db.QueryRow(`SELECT id,credential_hash,lease_owner,lease_expires_at,epoch FROM session_bindings
WHERE id=? AND endpoint_id=? AND native_session_id=? AND node_id=? AND workspace_id=?
AND status IN('active','leased','online','ready','acquired')`, identity.BindingID, identity.Endpoint, identity.SID, identity.NodeID, identity.Workspace).
		Scan(&lease.Binding, &lease.CredentialHash, &lease.LeaseOwner, &lease.ExpiresAt, &lease.Epoch) != nil ||
		lease.Binding != identity.BindingID || lease.Epoch != identity.BindingEpoch || lease.CredentialHash == "" || lease.LeaseOwner == "" {
		t.Fatal("actual original native registration lost its binding, credential or lease owner")
	}
	if _, err := time.Parse(time.RFC3339Nano, lease.ExpiresAt); err != nil {
		t.Fatal("actual original native lease has a malformed expiry")
	}
	return lease
}

func requireOwnerGroupsSameLeaseIdentity(t *testing.T, before, after ownerGroupsNativeLease) {
	t.Helper()
	before.ExpiresAt, after.ExpiresAt = "", ""
	if before != after {
		t.Fatal("normal Group lifecycle or cold renewal rotated the original native credential or binding epoch")
	}
}

// Codex may retain content blocks without the outer MCP isError flag. Accept
// only an exact finite product refusal in that actual Host result. Service
// health and positive registration/Group checks are supplied by each caller.
func requireOwnerGroupsHostRefusal(t *testing.T, reply ownerGroupsHostReply, codes ...string) {
	t.Helper()
	if len(reply.Output) == 0 || len(reply.Output) > 1<<20 {
		t.Fatal("actual Host refusal has no bounded output")
	}
	var root any
	if json.Unmarshal(reply.Output, &root) != nil {
		t.Fatal("actual Host refusal output is malformed")
	}
	var text []string
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 16 {
			t.Fatal("actual Host refusal exceeded its bounded content nesting")
		}
		switch item := value.(type) {
		case map[string]any:
			if flag, found := item["isError"]; found && flag != true {
				t.Fatal("actual Host refusal contains a successful MCP flag")
			}
			for _, key := range []string{"operation_id", "peer_selection_id", "request_id"} {
				if id, _ := item[key].(string); id != "" {
					t.Fatal("actual Host refusal returned successful operation coordinates")
				}
			}
			for _, child := range item {
				walk(child, depth+1)
			}
		case []any:
			for _, child := range item {
				walk(child, depth+1)
			}
		case string:
			text = append(text, item)
			if strings.HasPrefix(strings.TrimSpace(item), "{") || strings.HasPrefix(strings.TrimSpace(item), "[") {
				var embedded any
				if json.Unmarshal([]byte(item), &embedded) == nil {
					walk(embedded, depth+1)
				}
			}
		}
	}
	walk(root, 0)
	joined := strings.Join(text, "\n")
	for _, code := range codes {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(code) + `\b`).MatchString(joined) {
			return
		}
	}
	t.Fatal("actual Host did not return the expected typed authority refusal")
}

func ownerGroupsSelect(t *testing.T, host *ownerGroupsHost, actor int, label, group string) {
	t.Helper()
	reply := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: actor, Label: label, Tool: "cicada_use_group",
		Arguments: map[string]any{"group_id": group}, ObserveFields: []string{"group_id"}})
	if reply.Public["group_id"] != group {
		t.Fatal("actual original native actor did not select the exact authorized Group")
	}
}

func ownerGroupsDenySelection(t *testing.T, host *ownerGroupsHost, actor int, label, group string) {
	t.Helper()
	reply := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: actor, Label: label, Tool: "cicada_use_group",
		Arguments: map[string]any{"group_id": group}})
	requireOwnerGroupsHostRefusal(t, reply, "OWNER_READD_REQUIRED")
}

// Freeze the actual Node, not a product clock, so a registration-only heartbeat
// cannot move the boundary under observation. Its ordinary restart must resume
// the same original registration after the unshortened five-minute cold period.
func exerciseOwnerGroupsM5(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity, g2 string, denied ownerGroupsDeniedDelivery) {
	t.Helper()
	if len(original) != 4 || denied.Group != actors.active.GroupID {
		t.Fatal("M5 requires the original four actors and retained G1 request")
	}
	d := original[3]
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "ACTIVE", "OWNER")
	before := readOwnerGroupsNativeLease(t, v, d)
	var nativeLeases [4]ownerGroupsNativeLease
	for index, identity := range original {
		nativeLeases[index] = readOwnerGroupsNativeLease(t, v, identity)
	}
	current := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, actors.active, current)
	if !current.Current || current.State != wire.LocalDomainActive || current.StateReviewID == "" {
		t.Fatal("actual App cannot review the original active default policy")
	}
	revoked := v.do(appcore.Action{Kind: appcore.ActionRevokeLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: current.StateReviewID, ConfirmRevoke: true}}).LocalCollaboration
	requireSameLocalDomain(t, actors.active, revoked)
	if !revoked.Current || revoked.Pending || revoked.State != wire.LocalDomainRevoked || !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("actual default-policy revoke lacks authenticated state and healthy original services")
	}
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "ACTIVE", "OWNER")
	closeLocalDomainApp(t, v)
	if v.app.running() {
		t.Fatal("M5 did not actually close the App")
	}
	host.command(t, ownerGroupsHostCommand{Action: "restart_host"})
	// New MCP connection and one-use fresh Hook are enforced by the existing
	// Host fixture's retired-nonce check on this first post-restart call.
	host.groups(t, 3, "m5-new-mcp-fresh-hook", actors.active.NetworkID, g2, map[string]string{g2: "OWNER_EXPLICIT"})
	ownerGroupsDenySelection(t, host, 1, "m5-revoked-default-g1", actors.active.GroupID)
	ownerGroupsSelect(t, host, 3, "m5-select-d-g2", g2)
	v.actualNode.kill(t)
	frozen := readOwnerGroupsNativeLease(t, v, d)
	frozenAnchors := readOwnerGroupsRenewalAnchors(t, v, original)
	requireOwnerGroupsSameLeaseIdentity(t, before, frozen)
	witness := startOwnerGroupsLeaseWitness(t, frozen.ExpiresAt)
	if remaining := time.Until(witness.originalExpiry); remaining <= 0 || remaining > 5*time.Minute+5*time.Second {
		t.Fatal("M5 did not capture the actual unshortened default native lease")
	}
	// Also require five full real minutes in this parent. This is deliberately
	// stronger than merely observing a nearly expired lease for one second.
	deadline := witness.started.Add(5*time.Minute + time.Second)
	if coldDeadline := witness.originalExpiry.Add(time.Second); coldDeadline.After(deadline) {
		deadline = coldDeadline
	}
	for time.Now().Before(deadline) {
		if v.app.running() || v.actualNode.running() || !v.f.hub.running() {
			t.Fatal("actual M5 cold interval changed App/Node/Hub process state")
		}
		remaining := time.Until(deadline)
		if remaining > 15*time.Second {
			remaining = 15 * time.Second
		}
		time.Sleep(remaining)
		t.Logf("OWNER_GROUPS_COLD elapsed_seconds=%.0f App_closed=true Node_stopped=true original_boundary_crossed=%t", time.Since(witness.started).Seconds(), time.Now().After(witness.originalExpiry))
	}
	from := len(v.f.proxy.snapshot())
	_, release := armOwnerGroupsFault(t, v.f.proxy, "renew-lost-response")
	defer release()
	restartNativePeerNode(t, v, actors)
	captureStarted := time.Now()
	lostRenew := awaitOwnerGroupsDroppedNodeResponseSince(t, v.f.proxy, from, wire.OperationEndpointGroupsNodeRenew, captureStarted)
	release()
	awaitOwnerGroupsRenewalSettlement(t, v, "m5-lost-renew-after-restart", lostRenew, captureStarted, frozenAnchors)
	host.command(t, ownerGroupsHostCommand{Action: "restart_host"})
	host.groups(t, 3, "m5-cold-renewed-self", actors.active.NetworkID, g2, map[string]string{g2: "OWNER_EXPLICIT"})
	host.roundtrip(t, "m5-after-real-boundary", g2, 3, 2, original)
	after := readOwnerGroupsNativeLease(t, v, d)
	requireOwnerGroupsSameLeaseIdentity(t, frozen, after)
	for index, identity := range original {
		requireOwnerGroupsSameLeaseIdentity(t, nativeLeases[index], readOwnerGroupsNativeLease(t, v, identity))
	}
	if v.app.running() || !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("post-boundary G2 exchange lacks closed App and healthy original services")
	}
	requireOwnerGroupsLostRenewalRecovery(t, v, from, lostRenew, original)
	witness.observeAfter(t, after.ExpiresAt)
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	observeOwnerGroupsCase(t, "M5_IndependentRealLease", map[string]bool{
		"App_closed": true, "default_policy_revoked": true, "G2_OWNER_EXPLICIT_renewal": true,
		"new_MCP_after_default_revoke": true, "new_fresh_Hook_after_default_revoke": true,
		"Node_restart_original_identity": true, "G2_Cicada_ASK_REPLY_after_boundary": true, "normal_binding_epoch_unchanged": true,
	})
}

func exerciseOwnerGroupsM6(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity, g2 string, denied ownerGroupsDeniedDelivery) {
	t.Helper()
	if len(original) != 4 || v.app.running() || denied.Group != actors.active.GroupID {
		t.Fatal("M6 requires the original four actors after M5 closed the App")
	}
	_ = restartOwnerGroupsApp(t, v)
	d := original[3]
	before := readOwnerGroupsNativeLease(t, v, d)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, actors.active.GroupID, "REMOVED", "OWNER")
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "ACTIVE", "OWNER")
	credential := originalOwnerGroupsRESTCredential(t, v, d, g2)
	panel := prepareOwnerGroupsEndpointChange(t, v, actors, d, g2, wire.OwnerEndpointGroupsRemoveEndpoint, "")
	exerciseOwnerGroupsLostApply(t, v, panel, "apply-lost-response", false)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "REMOVED", "OWNER")
	host.groups(t, 3, "m6-zero-groups", actors.active.NetworkID, "", map[string]string{})
	for _, group := range []string{actors.active.GroupID, g2} {
		if ownerGroupsRelationCount(t, v, d.Endpoint, group) != 0 {
			t.Fatal("removing D's final Group retained an active business relation")
		}
	}
	router := startOwnerGroupsFabricRouter(t, v)
	defer router.process.kill(t)
	for _, group := range []string{actors.active.GroupID, g2} {
		status, raw := router.request(t, credential, group, http.MethodGet, "/v2/fabric/whoami", nil)
		clear(raw)
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Fatal("registration-only native credential retained business authority after final Group removal")
		}
	}
	denial := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 3, Label: "m6-zero-business", Tool: "cicada_ask",
		Arguments: map[string]any{"target": original[2].Endpoint, "question": "SYNTHETIC last Group has no business authority", "idempotency_key": host.fixtureScope + "-m6-zero"}})
	requireOwnerGroupsHostRefusal(t, denial, "GROUP_SELECTION_REQUIRED")
	// A real local Join may restore liveness only. It cannot manufacture an
	// Owner re-add, substitute a key or clear either retained Group deny.
	ownerGroupsCLIAdmission(t, v, actors, host, d, "join")
	host.groups(t, 3, "m6-join-zero-groups", actors.active.NetworkID, "", map[string]string{})
	ownerGroupsDenySelection(t, host, 3, "m6-no-automatic-g2", g2)
	if !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("last-Group refusal was caused by stopped original services")
	}
	checkpoint := host.command(t, ownerGroupsHostCommand{Action: "checkpoint"})
	if !checkpoint.HistoryKept || checkpoint.RecordCount != 4 || checkpoint.QueuePosts[denied.Body] != 0 {
		t.Fatal("last Group removal lost original native history/results or dispatched revoked G1 work")
	}
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	requireOwnerGroupsSameLeaseIdentity(t, before, readOwnerGroupsNativeLease(t, v, d))
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, d, g2, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
	submitOwnerGroupsReview(t, v, panel, "ADD_SUBMITTED")
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "ACTIVE", "OWNER")
	host.groups(t, 3, "m6-explicit-readd-self", actors.active.NetworkID, "", map[string]string{g2: "OWNER_EXPLICIT"})
	host.roundtrip(t, "m6-explicit-readd", g2, 3, 2, original)
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	requireOwnerGroupsSameLeaseIdentity(t, before, readOwnerGroupsNativeLease(t, v, d))
	observeOwnerGroupsCase(t, "M6_LastGroupRetainsIdentity", map[string]bool{
		"last_Group_business_denied": true, "registration_zero_business_rights": true,
		"original_SID_Endpoint_key_workspace": true, "native_history_and_results_retained": true,
		"Node_still_running": true, "explicit_readd_same_identity": true,
	})
}

type ownerGroupsOutboxWitness struct {
	Operation, SID, Endpoint, Group, InputDigest, InputJSON, CreatedAt string
	CipherOperation, CipherDigest, CipherSHA256                        string
}

// Only the original M3 ASK is selected. Routine status/heartbeat timestamps,
// later G2 operations and their ciphertexts are deliberately outside this hash.
func readOwnerGroupsOutbox(t *testing.T, actors nativePeerActors, source ownerGroupsIdentity, denied ownerGroupsDeniedDelivery) ownerGroupsOutboxWitness {
	t.Helper()
	db := nodePairReadOnlyDB(t, actors.outbox)
	defer db.Close()
	var result ownerGroupsOutboxWitness
	var kind, network string
	rows := must(db.Query(`SELECT operation_id,kind,native_session_id,endpoint_id,group_id,network_id,input_digest,input_json,created_at
FROM mcp_outbox_operations WHERE native_session_id=? AND endpoint_id=? AND group_id=? AND kind='ask'
AND json_extract(input_json,'$.question')=?`, source.SID, source.Endpoint, denied.Group, denied.Body))
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&result.Operation, &kind, &result.SID, &result.Endpoint, &result.Group, &network, &result.InputDigest, &result.InputJSON, &result.CreatedAt) != nil {
			t.Fatal("actual original MCP outbox audit failed")
		}
	}
	if rows.Err() != nil || rows.Close() != nil || count != 1 || kind != "ask" || network != "" || result.Operation == "" ||
		result.Group != denied.Group || result.SID != source.SID || result.Endpoint != source.Endpoint || result.InputDigest == "" || result.CreatedAt == "" {
		t.Fatal("actual retained M3 ASK lost its unique original Group/outbox identity")
	}
	return result
}

func readOwnerGroupsCipher(t *testing.T, v *codexProductFixture, witness ownerGroupsOutboxWitness, request string) ownerGroupsOutboxWitness {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(ownerGroupsNodeRoot(v), "node-crypto-state.sqlite"))
	defer db.Close()
	rows := must(db.Query(`SELECT operation_id,digest,envelope FROM node_crypto_outbox WHERE source_endpoint_id=?
AND json_extract(CAST(envelope AS TEXT),'$.context.request_id')=?
AND json_extract(CAST(envelope AS TEXT),'$.context.kind')='REQUEST'`, witness.Endpoint, request))
	count := 0
	for rows.Next() {
		count++
		var digest, encoded []byte
		if rows.Scan(&witness.CipherOperation, &digest, &encoded) != nil || len(digest) != 32 || len(encoded) > 256<<10 {
			clear(encoded)
			t.Fatal("actual original ciphertext audit failed")
		}
		var envelope e2ee.EndpointMessageEnvelope
		if json.Unmarshal(encoded, &envelope) != nil || envelope.Context.RequestID != request || envelope.Context.SenderGroupID != witness.Group ||
			envelope.Context.ReceiverGroupID != witness.Group || envelope.Context.SenderEndpointID != witness.Endpoint || envelope.Context.LinkID != "" {
			clear(encoded)
			t.Fatal("actual original ciphertext changed its retained request, Endpoint or Group")
		}
		witness.CipherDigest, witness.CipherSHA256 = hash(digest), hash(encoded)
		clear(encoded)
	}
	if rows.Err() != nil || rows.Close() != nil || count != 1 || witness.CipherOperation == "" {
		t.Fatal("actual retained M3 ASK lost its unique durable original ciphertext")
	}
	return witness
}

func ownerGroupsNodeRequest(t *testing.T, v *codexProductFixture, method, path string, body any) (int, []byte) {
	t.Helper()
	prefix := "/v2/relay/nodes/" + url.PathEscape(v.actualNode.id) + "/group/sealed/"
	if !strings.HasPrefix(path, prefix) {
		t.Fatal("Group scope audit attempted an unrelated Node route")
	}
	token := readPrivate(t, filepath.Join(ownerGroupsNodeRoot(v), "relay.token"))
	defer clear(token)
	authorization := "CicadaNode " + strings.TrimSpace(string(token))
	if _, err := fabric.NodeCredentialFromAuthorization(authorization); err != nil {
		t.Fatal("original Node lost its retained private Relay credential")
	}
	var raw []byte
	if body != nil {
		raw = must(json.Marshal(body))
		defer clear(raw)
	}
	request := must(http.NewRequest(method, v.f.cfg.Origin+path, bytes.NewReader(raw)))
	request.Header.Set("Authorization", authorization)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := must(client.Do(request))
	defer response.Body.Close()
	result := must(io.ReadAll(io.LimitReader(response.Body, 512<<10+1)))
	if len(result) > 512<<10 {
		clear(result)
		t.Fatal("actual Node scope audit exceeded its private response bound")
	}
	return response.StatusCode, result
}

func ownerGroupsBusinessPosts(v *codexProductFixture, request string) int {
	count := 0
	for _, ex := range v.f.proxy.snapshot() {
		if ex.Method != http.MethodPost || !strings.Contains(ex.Path, "/group/sealed/") ||
			(!strings.HasSuffix(ex.Path, "/ask") && !strings.HasSuffix(ex.Path, "/reply") && !strings.HasSuffix(ex.Path, "/send")) {
			continue
		}
		var body struct {
			Request string `json:"request_id"`
		}
		if json.Unmarshal(ex.request, &body) == nil && body.Request == request {
			count++
		}
	}
	return count
}

func requireOwnerGroupsFailedReply(t *testing.T, actors nativePeerActors, identity ownerGroupsIdentity, group, operation string) {
	t.Helper()
	db := nodePairReadOnlyDB(t, actors.outbox)
	defer db.Close()
	var status, lastError, result string
	if operation == "" || db.QueryRow(`SELECT status,last_error,result_json FROM mcp_outbox_operations
WHERE operation_id=? AND kind='reply' AND native_session_id=? AND endpoint_id=? AND group_id=?`, operation, identity.SID, identity.Endpoint, group).
		Scan(&status, &lastError, &result) != nil || status != "FAILED" || result != "" ||
		(!strings.Contains(lastError, "current native session is not the original same-Group request responder") && !strings.Contains(lastError, "Cicada Hub 403")) {
		t.Fatal("actual wrong-Group reply lacks its original terminal authority refusal")
	}
}

// M8 runs after M6 and before intentional root revocation in M7. All positive
// controls use the same original native actors; failures retain G1's original
// request and ciphertext, while G2 remains live and independently authorized.
func exerciseOwnerGroupsM8(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity, g2 string, denied ownerGroupsDeniedDelivery) {
	t.Helper()
	value, exists := ownerGroupsRetainedScopes.Load(host)
	retained, ok := value.(*ownerGroupsRetainedScope)
	if !exists || !ok || len(original) != 4 || retained.selection == "" || !retained.oldDefaultRefusedWhileCurrent || denied.Group != actors.active.GroupID {
		t.Fatal("M8 lacks actual M4 selection and still-current old-default takeover witnesses")
	}
	before := readOwnerGroupsCipher(t, v, readOwnerGroupsOutbox(t, actors, original[0], denied), denied.RequestID)
	if before != retained.outbox || before.Group != denied.Group {
		t.Fatal("M4-M6 replaced the retained original G1 outbox intent")
	}
	posts := ownerGroupsBusinessPosts(v, denied.RequestID)
	if posts != 1 {
		t.Fatal("actual held G1 ASK was already redispatched before original recovery")
	}
	ownerGroupsSelect(t, host, 0, "m8-original-g1-read-scope", denied.Group)
	read := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m8-retired-source-read-refused", Tool: "cicada_operation_status",
		Arguments: map[string]any{"operation_id": before.Operation}})
	// M4 independently read this exact original while its source was current.
	// The new OWNER source cannot borrow its old DEFAULT outbox authority.
	requireOwnerGroupsHostRefusal(t, read, "MCP outbox operation belongs to a different authorized session context")
	if ownerGroupsBusinessPosts(v, denied.RequestID) != posts {
		t.Fatal("retired-source readonly recovery redispatched original business")
	}
	changed := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m8-same-key-changed-target", Tool: "cicada_ask",
		Arguments: map[string]any{"target": original[2].Endpoint, "question": denied.Body, "idempotency_key": host.fixtureScope + "-m3-held-g1"}})
	requireOwnerGroupsHostRefusal(t, changed, "MCP outbox operation belongs to a different authorized session context")
	ownerGroupsSelect(t, host, 0, "m8-surviving-g2-scope", g2)
	wrongScope := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m8-g1-outbox-in-g2", Tool: "cicada_operation_retry",
		Arguments: map[string]any{"operation_id": before.Operation}})
	requireOwnerGroupsHostRefusal(t, wrongScope, "MCP outbox operation belongs to a different authorized session context")
	stale := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m8-retained-g1-selection", Tool: "cicada_ask",
		Arguments: map[string]any{"peer_selection_id": retained.selection, "question": "SYNTHETIC retained G1 selection cannot borrow G2", "idempotency_key": host.fixtureScope + "-m8-old-selection"}})
	requireOwnerGroupsHostRefusal(t, stale, "PEER_SELECTION_STALE", "PEER_SELECTION_INVALID")
	ownerGroupsSelect(t, host, 3, "m8-d-only-g2", g2)
	wrongReply := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 3, Label: "m8-g1-request-g2-reply", Tool: "cicada_reply",
		Arguments: map[string]any{"request_id": denied.RequestID, "body": "SYNTHETIC original G1 request cannot borrow G2 responder", "idempotency_key": host.fixtureScope + "-m8-wrong-reply"}, ObserveFields: []string{"operation_id"}})
	requireOwnerGroupsFailedReply(t, actors, original[3], g2, wrongReply.Public["operation_id"])
	for index, extra := range []map[string]any{{"network_id": actors.active.NetworkID}, {"link_id": "synthetic-ungranted-G1-fallback"}} {
		args := map[string]any{"target": original[3].Endpoint, "question": denied.Body, "idempotency_key": host.fixtureScope + "-m3-held-g1"}
		for key, item := range extra {
			args[key] = item
		}
		refused := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 0, Label: "m8-no-fallback-" + string(rune('a'+index)), Tool: "cicada_ask", Arguments: args})
		requireOwnerGroupsHostRefusal(t, refused, "TARGET_NOT_AUTHORIZED")
	}
	if ownerGroupsBusinessPosts(v, denied.RequestID) != posts {
		t.Fatal("old G1 request/reply/selection/outbox dispatched through a surviving scope")
	}
	after := readOwnerGroupsCipher(t, v, readOwnerGroupsOutbox(t, actors, original[0], denied), denied.RequestID)
	if before != after {
		t.Fatal("readonly or denied recovery resealed the original G1 ciphertext or changed its immutable outbox")
	}
	checkpoint := host.command(t, ownerGroupsHostCommand{Action: "checkpoint"})
	if checkpoint.QueuePosts[denied.Body] != 0 {
		t.Fatal("retained original G1 work reached the Runtime through G2, Network or Link")
	}
	// Independent current G2 control permits a true same-ID/cipher conflict
	// assertion. G1's prior deny alone could only establish permission refusal.
	from := len(v.f.proxy.snapshot())
	control := host.roundtrip(t, "m8-current-g2-control", g2, 3, 2, original)
	changedCurrent := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 3, Label: "m8-current-same-key-new-target", Tool: "cicada_ask",
		Arguments: map[string]any{"target": original[0].Endpoint, "question": "SYNTHETIC changed current G2 target", "idempotency_key": host.fixtureScope + "-m8-current-g2-control"}})
	requireOwnerGroupsHostRefusal(t, changedCurrent, "MCP outbox idempotency key conflicts with the original request")
	var packet fabric.NodeSameGroupSealedV1AskInput
	for _, ex := range v.f.proxy.snapshot()[from:] {
		if ex.Method != http.MethodPost || !strings.HasSuffix(ex.Path, "/group/sealed/ask") {
			continue
		}
		var candidate fabric.NodeSameGroupSealedV1AskInput
		if json.Unmarshal(ex.request, &candidate) == nil && candidate.RequestID == control {
			packet = candidate
		}
	}
	if packet.RequestID != control || packet.GroupID != g2 || packet.SourceEndpointID != original[3].Endpoint || packet.TargetEndpointID != original[2].Endpoint {
		t.Fatal("actual G2 control omitted its original sealed ASK packet")
	}
	var envelope e2ee.EndpointMessageEnvelope
	if json.Unmarshal(packet.Ciphertext, &envelope) != nil || envelope.Context.RequestID != control {
		t.Fatal("actual G2 control ciphertext lost its request binding")
	}
	sender := must(nodekeys.LoadExisting(ownerGroupsNodeRoot(v), original[3].Endpoint))
	receiver := must(nodekeys.LoadExisting(ownerGroupsNodeRoot(v), original[2].Endpoint))
	changedCipher := must(e2ee.SealEndpointMessage(sender, receiver.Public(), envelope.Context, []byte("SYNTHETIC conflicting ciphertext for the same real request and message IDs"), 1))
	defer clear(changedCipher)
	if bytes.Equal(packet.Ciphertext, changedCipher) {
		t.Fatal("negative same-ID fixture did not actually change ciphertext")
	}
	packet.Ciphertext = changedCipher
	status, raw := ownerGroupsNodeRequest(t, v, http.MethodPost, "/v2/relay/nodes/"+url.PathEscape(v.actualNode.id)+"/group/sealed/ask", packet)
	clear(raw)
	if status != http.StatusConflict {
		t.Fatal("current authorized same-ID ASK accepted changed intent/ciphertext instead of an idempotency conflict")
	}
	// The conflict did not disturb the current independent Group or revive G1.
	host.roundtrip(t, "m8-after-cipher-conflict", g2, 3, 2, original)
	ownerGroupsDenySelection(t, host, 3, "m8-g1-still-denied", denied.Group)
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	observeOwnerGroupsCase(t, "M8_OriginalScopeRecovery", map[string]bool{
		"request_reply_selection_original_Group": true, "outbox_original_ID_and_ciphertext": true,
		"no_Group_Network_Link_fallback": true, "same_ID_changed_intent_rejected": true,
		"original_read_not_redispatch": true, "old_default_chain_after_takeover_denied": true,
	})
}
