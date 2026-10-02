package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type reviewPolicyHTTPActor struct {
	ownerID, deviceID   string
	ownerKey, deviceKey *e2ee.Identity
	binding             clientwire.Binding
	sequence            uint64
}
type reviewPolicyHTTPFixture struct {
	server                  *httptest.Server
	store                   *store.Store
	hubKey                  e2ee.PublicIdentity
	link                    *store.CommunicationLink
	source, target, foreign *reviewPolicyHTTPActor
}
type reviewPolicyHTTPReply struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
}

// Reuse the real Owner enrollment + encrypted RPC pattern from client_link_keys_test
// and the leased endpoint/invite setup from the Store Link fixtures. No mocked
// authority or injected policy state participates in this actual loopback HTTP flow.
func newReviewPolicyHTTPFixture(t *testing.T) *reviewPolicyHTTPFixture {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	manager, err := control.New(control.Config{StateDir: state, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-review-policy-management"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	s, err := store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	server := httptest.NewServer(NewHandler(manager))
	t.Cleanup(server.Close)
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	f := &reviewPolicyHTTPFixture{server: server, store: s, hubKey: manager.ClientControlPublicIdentity()}
	actor := func(ownerID, deviceID string) *reviewPolicyHTTPActor {
		t.Helper()
		if err := s.EnsureLocalOwnerPrincipal(ownerID); err != nil {
			t.Fatal(err)
		}
		ownerKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		deviceKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
			t.Fatal(err)
		}
		grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, deviceKey.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID, "device_id": deviceID, "device_public_identity": deviceKey.Public(), "owner_device_grant": grant})
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Post(server.URL+"/v2/client/devices/enroll", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusCreated {
			t.Fatalf("synthetic enrollment HTTP%d: %v", response.StatusCode, err)
		}
		var enrolled struct {
			SessionEpoch     uint64 `json:"session_epoch"`
			DeviceKeyVersion uint64 `json:"device_key_version"`
		}
		if err := json.Unmarshal(data, &enrolled); err != nil || enrolled.SessionEpoch == 0 || enrolled.DeviceKeyVersion == 0 {
			t.Fatal("invalid enrollment coordinates")
		}
		return &reviewPolicyHTTPActor{ownerID: ownerID, deviceID: deviceID, ownerKey: ownerKey, deviceKey: deviceKey, binding: clientwire.Binding{HubID: hubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: enrolled.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: enrolled.DeviceKeyVersion}}
	}
	f.source = actor(manager.Identity().ID, "review-policy-source-device")
	f.target = actor("synthetic-review-policy-target-owner", "review-policy-target-device")
	f.foreign = actor("synthetic-review-policy-foreign-owner", "review-policy-foreign-device")
	endpoint := func(a *reviewPolicyHTTPActor, label string) (string, string) {
		t.Helper()
		group, err := s.CreateGroup(store.Group{ID: "group_review_" + label, Name: "Synthetic review " + label, OwnerPrincipalID: a.ownerID, TrustDomainID: a.ownerID, State: store.GroupStateActive})
		if err != nil {
			t.Fatal(err)
		}
		principal, err := s.CreatePrincipal(store.Principal{ID: "principal_review_" + label, Kind: store.PrincipalKindAgent, OwnerID: a.ownerID, TrustDomainID: a.ownerID, Name: label, Status: store.PrincipalStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(store.Membership{PrincipalID: principal.ID, GroupID: group.ID, Role: "member", Grants: []string{"message.ask"}}); err != nil {
			t.Fatal(err)
		}
		ep, err := s.UpsertEndpointV2(store.Endpoint{ID: "endpoint_review_" + label, Name: label, Harness: "codex", NativeSessionID: "native_review_" + label, MachineID: "node_review_" + label, Owner: a.ownerID, Status: "online", PrincipalID: principal.ID, GroupID: group.ID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := s.CreateSessionBinding(store.SessionBinding{EndpointID: ep.ID, PrincipalID: principal.ID, GroupID: group.ID, NativeSessionID: ep.NativeSessionID, NodeID: ep.MachineID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AcquireSessionBindingLease(binding.ID, "synthetic_lease_"+label, binding.Epoch, time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		return ep.ID, group.ID
	}
	sourceEndpoint, sourceGroup := endpoint(f.source, "source")
	targetEndpoint, targetGroup := endpoint(f.target, "target")
	invite, err := s.CreateExternalThreadInvite(store.ExternalThreadInviteInput{OwnerID: f.source.ownerID, SourceEndpointID: sourceEndpoint, SourceGroupID: sourceGroup, HubID: hubID, Direction: "forward", Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"}, ExpiresAt: time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := s.AcceptExternalThreadInvite(invite.Token, f.target.ownerID, targetEndpoint, targetGroup)
	if err != nil {
		t.Fatal(err)
	}
	f.link, err = s.GetCommunicationLinkForOwner(accepted.LinkID, f.source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *reviewPolicyHTTPFixture) seal(t *testing.T, a *reviewPolicyHTTPActor, operation string, input any) []byte {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	a.sequence++
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest, HubID: a.binding.HubID, OwnerID: a.ownerID, DeviceID: a.deviceID, SessionEpoch: a.binding.SessionEpoch, Sequence: a.sequence, OperationID: fmt.Sprintf("review-policy-%s-%d", a.deviceID, a.sequence), Operation: operation, SenderKeyID: a.deviceKey.Public().ID, SenderKeyVersion: a.binding.DeviceKeyVersion, ReceiverKeyID: f.hubKey.ID, ReceiverKeyVersion: a.binding.HubKeyVersion}
	packet, err := clientwire.SealRequest(a.deviceKey, f.hubKey, a.binding, route, body)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func (f *reviewPolicyHTTPFixture) post(t *testing.T, a *reviewPolicyHTTPActor, packet []byte) (int, []byte, reviewPolicyHTTPReply) {
	t.Helper()
	response, err := f.server.Client().Post(f.server.URL+"/v2/client/rpc", "application/json", bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var result reviewPolicyHTTPReply
	if response.StatusCode == http.StatusOK {
		opened, err := clientwire.OpenResponse(a.deviceKey, f.hubKey, a.binding, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(opened.Plaintext, &result); err != nil {
			t.Fatal(err)
		}
	}
	return response.StatusCode, data, result
}
func (f *reviewPolicyHTTPFixture) call(t *testing.T, a *reviewPolicyHTTPActor, operation string, input any) reviewPolicyHTTPReply {
	t.Helper()
	status, _, reply := f.post(t, a, f.seal(t, a, operation, input))
	if status != http.StatusOK {
		t.Fatalf("encrypted RPC HTTP%d", status)
	}
	return reply
}
func reviewPolicyGrantInput(linkID, keyID string, expected int64, policy store.CommunicationLinkReviewPolicy, proof []byte) map[string]any {
	return map[string]any{"link_id": linkID, "owner_key_id": keyID, "expected_policy_version": expected, "policy": policy, "signed_proof": proof}
}

func TestClientLinkReviewPolicyEncryptedHTTPCurrentCASAndNextProof(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	policy := store.CommunicationLinkReviewPolicy{Mode: store.CommunicationLinkReviewNone, Reviewers: []store.CommunicationLinkReviewer{}}
	preview := func(a *reviewPolicyHTTPActor, expected int64) store.CommunicationLinkReviewPolicyPreview {
		t.Helper()
		reply := f.call(t, a, "link.review_policy_preview", map[string]any{"link_id": f.link.ID, "policy": policy})
		var p store.CommunicationLinkReviewPolicyPreview
		if !reply.OK || json.Unmarshal(reply.Result, &p) != nil || p.ExpectedPolicyVersion != expected || p.PolicyVersion != expected+1 || p.OwnerID != a.ownerID {
			t.Fatal("preview did not return exact current/next Owner coordinates")
		}
		return p
	}
	sign := func(a *reviewPolicyHTTPActor, p store.CommunicationLinkReviewPolicyPreview, version uint64) []byte {
		t.Helper()
		expiry, err := time.Parse(time.RFC3339Nano, p.MaximumProofExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := a.ownerKey.SignOwnerLinkReviewPolicy(a.ownerID, f.link.ID, p.ContractDigest, p.PolicyDigest, uint64(p.LinkVersion), version, e2ee.OwnerLinkGrantSide(p.Side), time.Now().Add(-time.Minute), expiry)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	var lastTargetPacket, lastTargetProof, firstTargetProof []byte
	var lastTargetPreview store.CommunicationLinkReviewPolicyPreview
	for expected := int64(0); expected < 2; expected++ {
		sourcePreview, targetPreview := preview(f.source, expected), preview(f.target, expected)
		if sourcePreview.Side != "SOURCE" || targetPreview.Side != "TARGET" || sourcePreview.PolicyDigest != targetPreview.PolicyDigest {
			t.Fatal("bilateral preview scope differs")
		}
		sourceProof, targetProof := sign(f.source, sourcePreview, uint64(expected+1)), sign(f.target, targetPreview, uint64(expected+1))
		reply := f.call(t, f.source, "link.review_policy_grant", reviewPolicyGrantInput(f.link.ID, f.source.ownerKey.Public().ID, expected, policy, sourceProof))
		var pending store.CommunicationLinkReviewPolicyStatus
		if !reply.OK || json.Unmarshal(reply.Result, &pending) != nil || pending.Current || len(pending.AcceptedSides) != 1 {
			t.Fatal("single Owner proof activated bilateral policy")
		}
		// Current-version signed bytes are valid signatures but are the wrong candidate.
		if expected == 1 {
			bad := sign(f.target, targetPreview, uint64(expected))
			if f.call(t, f.target, "link.review_policy_grant", reviewPolicyGrantInput(f.link.ID, f.target.ownerKey.Public().ID, expected, policy, bad)).OK {
				t.Fatal("current-version proof accepted")
			}
		}
		packet := f.seal(t, f.target, "link.review_policy_grant", reviewPolicyGrantInput(f.link.ID, f.target.ownerKey.Public().ID, expected, policy, targetProof))
		status, response, reply := f.post(t, f.target, packet)
		var active store.CommunicationLinkReviewPolicyStatus
		if status != http.StatusOK || !reply.OK || json.Unmarshal(reply.Result, &active) != nil || !active.Current || active.PolicyVersion != expected+1 || len(active.AcceptedSides) != 2 {
			t.Fatal("dual Owner next-version policy failed")
		}
		status, retry, _ := f.post(t, f.target, packet)
		if status != http.StatusOK || !bytes.Equal(response, retry) {
			t.Fatal("exact encrypted retry changed response")
		}
		// A new RPC carrying the exact accepted Owner proof also reconciles a lost reply.
		recovered := f.call(t, f.target, "link.review_policy_grant", reviewPolicyGrantInput(f.link.ID, f.target.ownerKey.Public().ID, expected, policy, targetProof))
		if !recovered.OK {
			t.Fatal("exact accepted proof retry failed")
		}
		lastTargetPacket, lastTargetProof = packet, targetProof
		lastTargetPreview = targetPreview
		if expected == 0 {
			firstTargetProof = targetProof
		}
	}
	current := preview(f.source, 2)
	currentProof := sign(f.source, current, 2)
	freshTargetProof := sign(f.target, lastTargetPreview, 2)
	if bytes.Equal(freshTargetProof, lastTargetProof) {
		t.Fatal("fresh signed proof unexpectedly reused accepted bytes")
	}
	for _, test := range []struct {
		name     string
		actor    *reviewPolicyHTTPActor
		expected int64
		proof    []byte
	}{
		{"current-version-proof", f.source, 2, currentProof},
		{"malformed-proof", f.source, 2, []byte("{")},
		{"negative-expected", f.target, -1, lastTargetProof},
		{"max-overflow", f.target, math.MaxInt64, lastTargetProof},
		{"stale-CAS", f.target, 0, firstTargetProof},
		{"fresh-proof-is-not-exact-retry", f.target, 1, freshTargetProof},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := reviewPolicyGrantInput(f.link.ID, test.actor.ownerKey.Public().ID, test.expected, policy, test.proof)
			if f.call(t, test.actor, "link.review_policy_grant", input).OK {
				t.Fatal("invalid version/proof accepted")
			}
			state, err := f.store.GetCommunicationLinkReviewPolicyForOwner(f.link.ID, f.source.ownerID)
			if err != nil || state.PolicyVersion != 2 {
				t.Fatal("failed grant advanced policy head")
			}
		})
	}
	// Valid foreign Owner/device and its own signature still cannot approve either Link side.
	foreignPreview := current
	foreignPreview.Side = "SOURCE"
	foreignPreview.OwnerID = f.foreign.ownerID
	foreignProof := sign(f.foreign, foreignPreview, 3)
	if f.call(t, f.foreign, "link.review_policy_grant", reviewPolicyGrantInput(f.link.ID, f.foreign.ownerKey.Public().ID, 2, policy, foreignProof)).OK {
		t.Fatal("foreign Owner approved Link side")
	}
	device, err := f.store.GetClientDevice(f.target.ownerID, f.target.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeClientDevice(f.target.ownerID, f.target.deviceID, device.Version); err != nil {
		t.Fatal(err)
	}
	status, _, _ := f.post(t, f.target, lastTargetPacket)
	if status != http.StatusForbidden {
		t.Fatalf("revoked device reused cached grant response: HTTP%d", status)
	}
}
