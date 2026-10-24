package n3_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func nodePairHTTP(client *http.Client, origin, path string, packet []byte) wireHTTPResult {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(packet))
	if err != nil {
		return wireHTTPResult{err: err}
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return wireHTTPResult{err: err}
	}
	defer response.Body.Close()
	out, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxNodePairTrustReconcileResponsePacketBytes+1))
	if len(out) > wire.MaxNodePairTrustReconcileResponsePacketBytes {
		clear(out)
		return wireHTTPResult{err: wire.ErrInvalid}
	}
	return wireHTTPResult{status: response.StatusCode, response: out, err: err}
}

func (v *nodePairFixture) protocolClient(t *testing.T) *http.Client {
	t.Helper()
	client := must(hubtransport.NewHTTPClient(v.hub.descriptor, v.hub.address, 12*time.Second))
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func (v *nodePairFixture) nodeIdentity(t *testing.T) *e2ee.Identity {
	t.Helper()
	if v.node.running() {
		t.Fatal("wire adversary must not compete with the actual Node's identity writer")
	}
	path := filepath.Join(v.state, "nodes", "node-"+url.PathEscape(v.node.id), "node-control-identity.bin")
	raw := readPrivate(t, path)
	defer clear(raw)
	key := must(e2ee.UnmarshalIdentity(raw))
	c, _ := v.side(t)
	if c.Candidate == nil || !reflect.DeepEqual(key.Public(), c.Candidate.NodePublic) {
		t.Fatal("wire adversary did not load the actual original Node private identity")
	}
	return key
}

func (v *nodePairFixture) seal(t *testing.T, sender *e2ee.Identity, op string, body any) []byte {
	t.Helper()
	return must(wire.SealNodePairTrustRequest(sender, v.hub.descriptor.Claims.Hub,
		wire.NodePairTrustPacket{Operation: op, RequestID: must(wire.NewRequestID()), AttemptID: v.local.AttemptID}, body, time.Now().UTC()))
}

// An adversary must reach the actual receiver's checks. The production SDK
// correctly refuses these malformed bodies locally, so this fixture uses the
// existing PQ primitive and the frozen public packet AAD, without changing it.
func nodePairAdversarialPacket(t *testing.T, sender *e2ee.Identity, hub wire.HubIdentity, attempt, operation string, body any) []byte {
	t.Helper()
	h := wire.NodePairTrustPacket{Format: wire.NodePairTrustPacketFormat, Version: 1, Operation: operation,
		RequestID: must(wire.NewRequestID()), AttemptID: attempt, SenderPublic: sender.Public()}
	aad := must(json.Marshal(struct {
		Header    wire.NodePairTrustPacket `json:"header"`
		Hub       wire.HubIdentity         `json:"hub"`
		Direction string                   `json:"direction"`
		Original  string                   `json:"original_packet_digest"`
	}{h, hub, "REQUEST", ""}))
	plain := must(json.Marshal(body))
	defer clear(plain)
	h.Packet = must(e2ee.Seal(sender, hub.Public, plain, append([]byte("cicada/node-pair-trust/packet-aad/v1\x00"), aad...), 1))
	return must(json.Marshal(h))
}

type nodePairAdmission struct {
	ownerBindings, keyBindings, provenance, clientRows, remaining, required, grants int
	lastRequest, nextResponse                                                       uint64
	state, slotState, slotDigest                                                    string
	slotRequest, slotResponse                                                       uint64
}

func (v *nodePairFixture) admission(t *testing.T) nodePairAdmission {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	defer db.Close()
	var a nodePairAdmission
	for _, q := range []struct {
		query string
		out   *int
	}{
		{`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id=?`, &a.ownerBindings},
		{`SELECT count(*) FROM node_control_key_bindings_v1 WHERE node_id=?`, &a.keyBindings},
		{`SELECT count(*) FROM hub_app_node_provenance_v1 WHERE owner_id=?`, &a.provenance},
		{`SELECT count(*) FROM client_device_requests_v2 WHERE owner_id=?`, &a.clientRows},
		{`SELECT COALESCE(sum(remaining),0) FROM hub_app_node_grants_v1 WHERE owner_id=?`, &a.remaining},
		{`SELECT count(*) FROM hub_app_node_grants_v1 WHERE owner_id=?`, &a.grants},
	} {
		arg := v.original.Account.OwnerID
		if q.out == &a.ownerBindings || q.out == &a.keyBindings {
			arg = v.node.id
		}
		if db.QueryRow(q.query, arg).Scan(q.out) != nil {
			t.Fatal("actual Hub admission observation failed")
		}
	}
	if db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`,
		v.original.Account.OwnerID, v.original.Account.DeviceID).Scan(&a.lastRequest, &a.nextResponse) != nil ||
		db.QueryRow(`SELECT require_pair_trust_ack FROM node_control_key_requests_v1 WHERE node_id=?`, v.node.id).Scan(&a.required) != nil {
		t.Fatal("actual Hub original ACK provenance/counters observation failed")
	}
	if err := db.QueryRow(`SELECT state FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, v.local.AttemptID).Scan(&a.state); err == sql.ErrNoRows {
		a.state = "MISSING" // Explicit malformed owned-state fixture only.
	} else if err != nil {
		t.Fatal("actual Hub attempt-state observation failed")
	}
	// A slot exists after real Owner prepare, including before approval/ACK.
	rows := must(db.Query(`SELECT state,packet_digest,request_sequence,response_sequence FROM hub_node_pair_trust_slots_v1 WHERE attempt_id=?`, v.local.AttemptID))
	defer rows.Close()
	count := 0
	for rows.Next() {
		if rows.Scan(&a.slotState, &a.slotDigest, &a.slotRequest, &a.slotResponse) != nil {
			t.Fatal("actual Hub reserved original slot observation failed")
		}
		count++
	}
	if rows.Err() != nil || count > 1 {
		t.Fatal("actual Hub has an unreadable or duplicated original slot")
	}
	return a
}

func nodePairExactCandidateAndPossession(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.approve(t)
	saved := v.copiedAppState(t)
	defer saved.clear()
	if saved.PairTrust.Pending == nil || saved.PairTrust.Pending.Operation != wire.OperationOwnerNodePairTrustComplete {
		t.Fatal("actual App did not leave its original approved operation for negative receiver checks")
	}
	var original wire.NodePairTrustOwnerComplete
	if json.Unmarshal(saved.PairTrust.Pending.Body, &original) != nil {
		t.Fatal("actual original OwnerComplete body unavailable")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	device := v.originalAppDevice(t)
	client := v.protocolClient(t)
	before := v.admission(t)
	if before.state != wire.NodePairTrustOwnerApproved || before.ownerBindings != 0 || before.keyBindings != 0 || before.remaining != 1 || before.required != 1 {
		t.Fatal("negative receiver checks lack a real unconsumed ACK-required original")
	}
	for _, name := range []string{"wrong-Hub", "wrong-Node", "wrong-Owner", "wrong-App-key", "stale-account-epoch", "stale-device-epoch", "missing-Owner-proof", "forged-Owner-proof", "stale-request"} {
		var body wire.NodePairTrustOwnerComplete
		if json.Unmarshal(must(json.Marshal(original)), &body) != nil {
			t.Fatal("owned negative request copy failed")
		}
		sender := device
		switch name {
		case "wrong-Hub":
			body.Context.Hub.HubID += "-forged"
		case "wrong-Node":
			body.Context.Candidate.NodeID += "-forged"
		case "wrong-Owner":
			body.Scope.OwnerID += "-forged"
		case "wrong-App-key":
			sender = must(e2ee.NewIdentity())
			body.Scope.DevicePublic = sender.Public()
		case "stale-account-epoch":
			body.Scope.AccountEpoch++
		case "stale-device-epoch":
			body.Scope.DeviceEpoch++
		case "missing-Owner-proof":
			body.OwnerProof = nil
		case "forged-Owner-proof":
			body.OwnerProof[len(body.OwnerProof)/2] ^= 1
		case "stale-request":
			body.IssuedAt = time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339Nano)
		}
		packet := nodePairAdversarialPacket(t, sender, v.hub.descriptor.Claims.Hub, v.local.AttemptID, wire.OperationOwnerNodePairTrustComplete, body)
		time.Sleep(260 * time.Millisecond) // Preserve the production account service's 4/s bucket.
		result := nodePairHTTP(client, v.hub.material.Origin, wire.NodePairTrustHTTPPath(wire.OperationOwnerNodePairTrustComplete), packet)
		clear(packet)
		clear(result.response)
		if result.err != nil || result.status != http.StatusForbidden && result.status != http.StatusBadRequest {
			t.Fatalf("actual Hub did not definitively reject adversarial original tuple: case=%s status=%d", name, result.status)
		}
		if v.admission(t) != before {
			t.Fatalf("rejected adversarial request changed original slot/counters/admission: case=%s", name)
		}
	}
	c, _ := v.side(t)
	key := must(e2ee.NewIdentity())
	now := time.Now().UTC()
	missing := wire.NodePairTrustStart{Format: wire.NodePairTrustFormat, Hub: c.Hub, Origin: c.Origin, DescriptorDigest: c.DescriptorDigest,
		NodeID: "synthetic-no-possession", NodeName: "SYNTHETIC missing possession", CredentialDigest: base64.RawURLEncoding.EncodeToString(must(wire.NewNonce())),
		RequestNonce: must(wire.NewNonce()), HubNodeControlPublic: c.Candidate.HubNodeControlPublic, HubNodeControlKeyVersion: c.Candidate.HubNodeControlKeyVersion,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	packet := nodePairAdversarialPacket(t, key, c.Hub, must(wire.NewRequestID()), wire.OperationNodePairTrustStart, missing)
	time.Sleep(260 * time.Millisecond)
	result := nodePairHTTP(client, c.Origin, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustStart), packet)
	clear(packet)
	clear(result.response)
	if result.err != nil || result.status != http.StatusForbidden || v.admission(t) != before {
		t.Fatal("actual Hub admitted missing Node possession or disturbed the legitimate original")
	}
	nodePairFacts(t, "NPT04_ExactCandidateAndPossession", map[string]bool{"wrong_Hub_Node_Owner_refused": true,
		"wrong_key_or_scope_refused": true, "missing_possession_refused": true, "original_tuple_retained": true})
}

func (v *nodePairFixture) independentACK(t *testing.T) ([]byte, wire.NodePairTrustACK) {
	t.Helper()
	key := v.nodeIdentity(t)
	c, state := v.side(t)
	if state != wire.NodePairTrustOwnerApproved {
		t.Fatal("independent duplicate-ACK actor requires actual prior App Owner approval")
	}
	o := must(wire.NodePairTrustOOBCommitment(v.local.ContextDigest, v.local.OOBSecret))
	poll := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: c, OOBCommitment: o, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	packet := v.seal(t, key, wire.OperationNodePairTrustPoll, poll)
	defer clear(packet)
	result := nodePairHTTP(v.protocolClient(t), c.Origin, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustPoll), packet)
	defer clear(result.response)
	if result.err != nil || result.status != http.StatusOK {
		t.Fatal("original real Node key could not poll actual App approval")
	}
	opened := must(wire.OpenNodePairTrustResponse(key, c.Hub, packet, result.response, poll))
	if opened.State != wire.NodePairTrustOwnerApproved || opened.ErrorCode != "" {
		t.Fatal("actual Hub did not deliver the original Owner approval")
	}
	capsule := must(wire.OpenNodePairTrustCapsule(key, c, o, opened.OwnerProof, opened.TrustCapsule, v.local.OOBSecret, time.Now().UTC()))
	defer clear(capsule.OOBSecret)
	ack := wire.NodePairTrustACK{Format: wire.NodePairTrustFormat, Context: c, OOBCommitment: o,
		PollPacketDigest: wire.NodePairTrustPacketDigest(packet), PollReceiptDigest: wire.NodePairTrustPacketDigest(result.response),
		OwnerProofDigest: wire.NodePairTrustProofDigest(opened.OwnerProof), CapsuleDigest: wire.NodePairTrustCapsuleDigest(opened.TrustCapsule),
		ACKNonce: capsule.ACKNonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	return v.seal(t, key, wire.OperationNodePairTrustACK, ack), ack
}

func nodePairConcurrentAndExactReplay(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.approve(t)
	before := v.admission(t)
	if before.state != wire.NodePairTrustOwnerApproved || before.ownerBindings != 0 || before.remaining != 1 || before.required != 1 ||
		before.slotState != "RESERVED" || before.lastRequest+1 != before.slotRequest || before.nextResponse != before.slotResponse {
		t.Fatal("concurrent ACK test lacks one genuine reserved unconsumed confirmation")
	}
	packet, ack := v.independentACK(t)
	defer clear(packet)
	defer clear(ack.ACKNonce)
	client := v.protocolClient(t)
	start, done := make(chan struct{}), make(chan wireHTTPResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			done <- nodePairHTTP(client, v.hub.material.Origin, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustACK), packet)
		}()
	}
	close(start)
	a, b := <-done, <-done
	defer clear(a.response)
	defer clear(b.response)
	if a.err != nil || b.err != nil || a.status != http.StatusOK || b.status != http.StatusOK || !bytes.Equal(a.response, b.response) {
		t.Fatal("concurrent exact ACKs failed to return one byte-identical original receipt")
	}
	key := v.nodeIdentity(t)
	result := must(wire.OpenNodePairTrustResponse(key, v.hub.descriptor.Claims.Hub, packet, a.response, ack))
	if result.State != wire.NodePairTrustACKed || result.Binding == nil || result.ErrorCode != "" {
		t.Fatal("concurrent ACK result is not an authenticated actual binding")
	}
	after := v.admission(t)
	if after.ownerBindings != 1 || after.keyBindings != 1 || after.provenance != 1 || after.remaining != 0 || after.slotState != "DONE" ||
		after.slotDigest != before.slotDigest || after.lastRequest != before.lastRequest+1 || after.nextResponse != before.nextResponse+1 ||
		after.clientRows != before.clientRows+1 || after.required != 1 {
		t.Fatal("concurrent ACKs duplicated admission, consumed grant more than once or moved the reserved counter slot")
	}
	cached := must(nodePairCachedOriginal(v.hub, packet))
	defer clear(cached.response)
	if cached.count != 1 || !bytes.Equal(cached.response, a.response) {
		t.Fatal("actual Hub did not retain exactly one original concurrent ACK receipt")
	}
	var header wire.NodePairTrustPacket
	if json.Unmarshal(packet, &header) != nil {
		t.Fatal("original actual ACK packet header unavailable")
	}
	// Same original request ID, different PQ ciphertext. This is a conflict,
	// even though the independently signed plaintext is otherwise identical.
	changed := must(wire.SealNodePairTrustRequest(key, v.hub.descriptor.Claims.Hub, header, ack, time.Now().UTC()))
	defer clear(changed)
	if bytes.Equal(changed, packet) {
		t.Fatal("changed-original control did not produce distinct request bytes")
	}
	conflict := nodePairHTTP(client, v.hub.material.Origin, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustACK), changed)
	defer clear(conflict.response)
	if conflict.err != nil || conflict.status != http.StatusForbidden || v.admission(t) != after {
		t.Fatal("changed bytes under the original ACK ID bypassed conflict fencing")
	}
	// The actual App, still using its own original vault and confirmation,
	// consumes the exact ACKed receipt. The wire actor did not sign an Owner grant.
	s := v.awaitACK(t)
	if s.Node.Binding.ID != result.Binding.OwnerBindingID {
		t.Fatal("actual App projected a different concurrent ACK binding")
	}
	nodePairFacts(t, "NPT07_ConcurrentAndExactReplay", map[string]bool{"one_atomic_binding": true,
		"one_consumption": true, "identical_original_receipt": true, "changed_original_conflicts": true})
}
