package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

// Reuse the real Hub/Owner/Node enrollment fixture. No scripted authorization,
// replacement Endpoint key, direct SQL grant or native subprocess is involved.
func TestEndpointGroupsRealHTTPReplyReachesOriginalNodeInbox(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	domain := activateLocalDomainConsumer(t, f)
	for i := range f.native {
		q := localDomainEndpointCommand(t, f, i)
		if _, err := requestMachineAgentEndpoint(f.bridge.path, q); err != nil {
			t.Fatal("original native registration", err)
		}
	}
	// Serialize with the existing managed worker while exercising its actual
	// Describe/key-completion implementation against the real HTTP producer.
	f.bridge.endpointGroupsMu.Lock()
	defer f.bridge.endpointGroupsMu.Unlock()
	var registrations [2]machineEndpointGroupsRegistration
	for i := range registrations {
		r, _, err := f.client.endpointGroupsRegistrationCandidate(f.native[i], f.workspace)
		if err != nil {
			t.Fatal(err)
		}
		r, _, err = f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
		if err != nil {
			t.Fatal("real registered-Thread Describe", err)
		}
		registrations[i] = r
	}
	ownerHTTP := func(operation string, body any) ([]byte, wire.OwnerEndpointGroupsResult) {
		t.Helper()
		packet, err := wire.SealClientRequest(f.device, f.hub, body)
		if err != nil {
			t.Fatal(err)
		}
		raw := f.http(t, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(operation), "", "", packet, http.StatusOK)
		var result wire.OwnerEndpointGroupsResult
		if wire.OpenOwnerEndpointGroupsResponse(f.device, f.hub, packet, raw, &result) != nil || wire.VerifyOwnerEndpointGroupsResult(body, packet, result, f.hub) != nil {
			t.Fatal("real Owner response failed its original envelope/target verification")
		}
		return packet, result
	}
	apply := func(body wire.OwnerEndpointGroupsPrepareBody) wire.OwnerEndpointGroupsResult {
		t.Helper()
		body.NodeID, body.NetworkID = f.nodeID, domain.Policy.NetworkID
		q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope.Actor, body, f.owner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		original, prepared := ownerHTTP(wire.OperationOwnerEndpointGroupsPrepare, q)
		if prepared.State != "PREPARED" || prepared.Review == nil || wire.ValidateOwnerEndpointGroupsReview(q, original, *prepared.Review, f.hub, time.Now().UTC()) != nil {
			t.Fatal("real Owner review unavailable", prepared.ErrorCode)
		}
		complete, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope.Actor, q, original, *prepared.Review, f.owner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		packet, result := ownerHTTP(wire.OperationOwnerEndpointGroupsApply, complete)
		if result.State != "COMPLETED" || result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(*prepared.Review, packet, *result.Operation, nil) != nil {
			t.Fatal("real approved Owner change failed", result.ErrorCode)
		}
		return result
	}
	created := apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic original reply Group"})
	group := created.Operation.Target.GroupID
	for i, r := range registrations {
		apply(wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: group, EndpointID: r.Anchor.Registration.EndpointID, Duration: "until_revoked"})
		r, description, err := f.bridge.describeEndpointGroups(f.ctx, f.client, r, "", 64)
		if err != nil {
			t.Fatal(err)
		}
		completed := false
		for _, card := range description.Relations {
			if card.GroupID != group {
				continue
			}
			for _, source := range card.Contributions {
				if source.Source == "OWNER_EXPLICIT" {
					if err := f.bridge.completeEndpointGroupPolicy(f.ctx, f.client, r, card, source); err != nil {
						t.Fatal("real Node key completion", err)
					}
					completed = true
				}
			}
		}
		if !completed {
			t.Fatal("real manual contribution missing")
		}
		registrations[i] = r
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	var keys [2]*e2ee.Identity
	for i, r := range registrations {
		keys[i], err = loadLocalDomainPeerIdentity(f.ctx, state, machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
		if err != nil {
			t.Fatal("load original key without replacement", err)
		}
	}
	peer, err := f.bridge.fetchCrossNodeGroupPeerKey(group, registrations[0].Anchor.Registration.EndpointID, registrations[1].Anchor.Registration.EndpointID)
	if err != nil || peer.EndpointGroupCurrent == nil {
		t.Fatal("real manual peer carrier", err)
	}
	newID := func() string {
		t.Helper()
		id, err := wire.NewRequestID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	requestID, askID, replyID := newID(), newID(), newID()
	seal := func(sender, receiver crossNodeGroupEndpointEvidence, key int, message, kind, replyTo, body string) []byte {
		t.Helper()
		context := crossNodeGroupEndpointContext(peer, sender, receiver, message, requestID, replyTo, "", kind)
		raw, err := e2ee.SealEndpointMessage(keys[key], crossNodeGroupManifest(receiver).CandidatePublicIdentity, context, []byte(body), 1)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	base := "/v2/relay/nodes/" + url.PathEscape(f.nodeID) + "/group/sealed/"
	post := func(path string, body any, want int) []byte {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return f.http(t, http.MethodPost, path, "CicadaNode "+f.token, "", raw, want)
	}
	ask := fabric.NodeSameGroupSealedV1AskInput{GroupID: group, SourceEndpointID: peer.Sender.EndpointID, TargetEndpointID: peer.Receiver.EndpointID, MessageID: askID, RequestID: requestID, DataScope: store.SameGroupSealedV1DataScope, ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano), Ciphertext: seal(peer.Sender, peer.Receiver, 0, askID, "REQUEST", "", "synthetic original question")}
	post(base+"ask", ask, http.StatusAccepted)
	claim := func(want string) fabric.NodeSealedDelivery {
		t.Helper()
		var result struct {
			Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
		}
		raw := post(base+"claim", fabric.NodeClaimInput{ConsumerID: "synthetic-original-reply", Limit: 1}, http.StatusOK)
		if json.Unmarshal(raw, &result) != nil || len(result.Deliveries) != 1 || result.Deliveries[0].MessageID != want {
			t.Fatal("real claim did not return the exact original message")
		}
		return result.Deliveries[0]
	}
	claim(askID)
	const answer = "synthetic original answer"
	reply := fabric.NodeSameGroupSealedV1ReplyInput{RequestID: requestID, MessageID: replyID, Ciphertext: seal(peer.Receiver, peer.Sender, 1, replyID, "REPLY", askID, answer)}
	var accepted crossNodeGroupReplyReceipt
	if json.Unmarshal(post(base+"reply", reply, http.StatusAccepted), &accepted) != nil || accepted.State != store.FabricRequestReplied {
		t.Fatal("actual Reply was not REPLIED")
	}
	delivery := claim(replyID)
	authorization, err := fetchCrossNodeGroupDeliveryAuthorization(f.ctx, f.server.URL, f.nodeID, replyID, delivery.AttemptID)
	if err != nil || authorization.EndpointGroupCurrent == nil {
		t.Fatal("actual REPLY authorization lost mandatory Current before Node Inbox admission", err)
	}
	current := authorization.EndpointGroupCurrent
	a := registrations[0].Anchor
	if current.Sender != peer.EndpointGroupCurrent.Receiver || current.Receiver != peer.EndpointGroupCurrent.Sender || authorization.EndpointID != a.Registration.EndpointID || authorization.NativeSessionID != a.Registration.NativeSessionID || authorization.BindingID != a.BindingID || authorization.BindingEpoch != a.BindingEpoch {
		t.Fatal("Reply changed original native tuple or exact source/head")
	}
	carrier := func(x crossNodeGroupDeliveryAuthorization) crossNodeGroupPeerKey {
		return crossNodeGroupPeerKey{HubID: f.hub.HubID, GroupID: group, Sender: x.Sender, Receiver: x.Receiver, EndpointGroupCurrent: x.EndpointGroupCurrent}
	}
	for _, name := range []string{"missing_current", "changed_original_binding", "changed_source", "changed_owner_head"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(authorization)
			var bad crossNodeGroupDeliveryAuthorization
			if json.Unmarshal(raw, &bad) != nil {
				t.Fatal("copy actual carrier")
			}
			switch name {
			case "missing_current":
				bad.EndpointGroupCurrent = nil
			case "changed_original_binding":
				bad.Receiver.BindingEpoch++
			case "changed_source":
				bad.EndpointGroupCurrent.Receiver.Relation.AuthorityID = strings.Repeat("e", 32)
			case "changed_owner_head":
				bad.EndpointGroupCurrent.Receiver.OwnerControl.Revision++
			}
			if _, err := verifyEndpointGroupsPeerTarget(f.ctx, state, a.Registration.EndpointID, f.hub.HubID, group, bad.Sender, bad.Receiver, bad.EndpointGroupCurrent, "native_delivery", delivery.AttemptID); err == nil {
				t.Fatal("changed actual Reply carrier passed peer authorization")
			}
			if _, err := pinCurrentSameGroupPeer(f.ctx, state, carrier(bad), bad.Receiver, bad.Sender, keys[0]); err == nil {
				t.Fatal("changed actual Reply carrier installed a peer pin")
			}
			if _, err := openMachineCrossNodeGroupDelivery(f.ctx, f.nodeRoot, f.nodeID, delivery, bad); err == nil {
				t.Fatal("changed actual Reply carrier opened original ciphertext")
			}
		})
	}
	if required, err := verifyEndpointGroupsPeerTarget(f.ctx, state, a.Registration.EndpointID, f.hub.HubID, group, authorization.Sender, authorization.Receiver, current, "native_delivery", delivery.AttemptID); err != nil || !required {
		t.Fatal("real Reply carrier failed Node peer verification", err)
	}
	if _, err := pinCurrentSameGroupPeer(f.ctx, state, carrier(*authorization), authorization.Receiver, authorization.Sender, keys[0]); err != nil {
		t.Fatal("real Reply carrier failed original peer pin", err)
	}
	opened, err := openMachineCrossNodeGroupDelivery(f.ctx, f.nodeRoot, f.nodeID, delivery, *authorization)
	if err != nil || !bytes.Equal(opened.Plaintext, []byte(answer)) {
		t.Fatal("real Reply failed original Node open", err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(f.nodeRoot, f.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	journal, err := openMachineRelayJournal(f.nodeRoot, f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptMachineCrossNodeGroupDelivery(f.ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, delivery); err != nil {
		t.Fatal("actual Reply did not reach original Node Inbox", err)
	}
	saved, err := inbox.Get(f.ctx, replyID)
	if err != nil || saved.State != nodeinbox.NODE_RECEIVED || saved.EndpointID != a.Registration.EndpointID || saved.SessionID != a.Registration.NativeSessionID || saved.BindingEpoch != a.BindingEpoch || !bytes.Equal(saved.Payload, []byte(answer)) {
		t.Fatal("Reply Inbox changed original tuple, causal route or payload", err)
	}
	uri := (&url.URL{Scheme: "file", Path: machineNodeInboxPath(f.nodeRoot, f.nodeID), RawQuery: "mode=ro"}).String()
	readOnly, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	var savedGroup, kind, savedRequest, replyTo string
	err = readOnly.QueryRowContext(f.ctx, `SELECT g.group_id,r.kind,r.request_id,r.reply_to FROM node_inbox_message_groups g JOIN node_inbox_message_routes r ON r.message_id=g.message_id WHERE g.message_id=?`, replyID).Scan(&savedGroup, &kind, &savedRequest, &replyTo)
	if err != nil || savedGroup != group || kind != "REPLY" || savedRequest != requestID || replyTo != askID {
		t.Fatal("Reply Inbox omitted the original Group or causal metadata", err)
	}
}
