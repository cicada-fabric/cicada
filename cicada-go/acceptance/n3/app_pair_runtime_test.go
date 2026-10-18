package n3_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Opt-in acceptance selector, executed only after Root approves actual Pair
// availability on the integrated source. The existing production App child
// owns every Owner/GroupKey proof. This driver never opens its private vault or
// signs a Pair Owner intent. The Node, SIDs and candidates are synthetic; no
// native Runtime, MCP consumer, queue or model turn is executed here.
func TestN3AppPairActionsBootstrapDualConsentAndRevoke(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "app-owner-pair-start.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	var initial appActorCheckpoint
	readJSON(t, marker, &initial)
	original := initial.Current
	sequence := 0
	do := func(action appcore.Action) appcore.Snapshot {
		t.Helper()
		sequence++
		reply := commandApp(t, f, app, sequence, appActorCommand{Action: &action})
		if reply.ActionFailed || reply.ClockMode != "WALL_CLOCK" {
			t.Fatalf("actual App Pair action failed: kind=%s code=%s pair_code=%s clock=%s", action.Kind, reply.ActionError, reply.Current.Pair.ErrorCode, reply.ClockMode)
		}
		s := reply.Current
		if s.Account.OwnerID != original.Account.OwnerID || s.Account.DeviceID != original.Account.DeviceID ||
			s.Account.LocalOwnerKeyID != original.Account.LocalOwnerKeyID || s.Account.OwnerFingerprint != original.Account.OwnerFingerprint ||
			s.Hub.Fingerprint != original.Hub.Fingerprint || s.Management != appcore.ManagementUnavailable {
			t.Fatal("actual App Pair flow replaced an original identity or claimed general management")
		}
		return s
	}
	// Read public evidence only with the owned Hub stopped. No SQL writes or
	// positive fixtures manufacture a Pair, consent, membership or key grant.
	readStore := func(check func(*store.Store)) {
		t.Helper()
		f.hub.kill(t)
		db := f.db(t)
		defer db.Close()
		check(db)
		if db.Close() != nil {
			t.Fatal("owned public-evidence Store did not close")
		}
		f.start(t)
	}
	var ownerPublic e2ee.PublicIdentity
	readStore(func(db *store.Store) {
		key := must(db.GetOwnerApprovalKey(original.Account.OwnerID, original.Account.LocalOwnerKeyID))
		if key.State != store.OwnerApprovalKeyActive || must(e2ee.OwnerDevicePublicKeyFingerprint(key.Public)) != original.Account.OwnerFingerprint {
			t.Fatal("Hub public Owner record differs from the original authenticated App pin")
		}
		ownerPublic = key.Public
	})
	node := newAppPairNodeFixture(t, f, do)
	prepared := do(appcore.Action{Kind: appcore.ActionPreparePair, Pair: appcore.PairAction{Label: "Synthetic actual App Owner ONLY"}})
	if prepared.Pair.PairID == "" || prepared.Pair.ReviewID == "" || !prepared.Pair.AdministrativePermission {
		t.Fatal("actual App did not retain an authenticated bootstrap review")
	}
	completed := do(appcore.Action{Kind: appcore.ActionCompletePair, Pair: appcore.PairAction{
		PairID: prepared.Pair.PairID, ReviewID: prepared.Pair.ReviewID, ConfirmBootstrap: true}})
	if completed.Pair.State != string(wire.NativePairWaitingJoin) || completed.Pair.NodeID != node.id || completed.Pair.Pending {
		t.Fatal("actual App bootstrap did not establish only its original two empty slots")
	}
	for _, slot := range completed.Pair.Slots {
		if slot.EndpointID != "" || slot.NativeSessionID != "" || slot.ConsentRecorded {
			t.Fatal("App bootstrap invented a joined or authorized native identity")
		}
	}
	pairID := completed.Pair.PairID
	var description wire.NativePairNodeDescription
	node.rpc(t, wire.OperationNativePairNodeDescribe, wire.NativePairNodeDescribe{ContractRevision: wire.NativePairContractRevision, PairID: pairID}, &description)
	claims := must(wire.VerifyNativePairNodeDescription(description, ownerPublic, pairID, time.Now().UTC()))
	if claims.Scope.Node.NodeID != node.id || claims.Scope.Node.OwnerBindingID != node.binding.BindingID ||
		claims.Scope.Actor.OwnerID != original.Account.OwnerID || claims.Scope.Actor.DeviceID != original.Account.DeviceID ||
		must(wire.HubFingerprint(description.HubIdentity)) != must(wire.HubFingerprint(f.cfg.Hub)) {
		t.Fatal("actual Node description moved the original App/Owner/Hub/Node tuple")
	}
	var joins [2]fabric.JoinResult
	var keys [2]*e2ee.Identity
	for i, letter := range []string{"A", "B"} {
		generation := description.SlotAGeneration
		if i == 1 {
			generation = description.SlotBGeneration
		}
		node.rpc(t, wire.OperationNativePairNodeJoin, wire.NativePairNodeJoin{
			ContractRevision: wire.NativePairContractRevision, PairID: pairID, Slot: letter, ExpectedGeneration: generation,
			BootstrapProofDigest: wire.NativePairProofDigest(description.BootstrapOwnerProof), Runtime: "codex",
			NativeSessionID: "synthetic-actual-app-original-" + letter, Workspace: "/synthetic/actual-app/" + letter,
			EndpointName: "Synthetic actual App slot " + letter}, &joins[i])
		j := joins[i]
		keys[i] = must(e2ee.NewIdentity())
		attestation := must(keys[i].SignEndpointKeyAttestation(j.Endpoint.ID, j.Endpoint.PrincipalID, node.id, j.BindingID, j.BindingEpoch))
		code, _ := node.http(t, http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+j.SessionToken,
			claims.Bootstrap.GroupID, map[string]any{"attestation": json.RawMessage(attestation)})
		if code != http.StatusOK {
			t.Fatal("actual synthetic candidate publication failed", code)
		}
	}
	observed := do(appcore.Action{Kind: appcore.ActionRefreshPair})
	if observed.Pair.State != string(wire.NativePairWaitingConsent) || !observed.Pair.Current || observed.Pair.NodeID != node.id {
		t.Fatal("actual App did not observe the two real synthetic candidates")
	}
	for i, slot := range observed.Pair.Slots {
		if slot.NativeSessionID != joins[i].Endpoint.NativeSessionID || slot.EndpointID != joins[i].Endpoint.ID ||
			slot.CandidateKeyID != keys[i].Public().ID || slot.ConsentRecorded || slot.State != string(wire.NativePairSlotCandidateReady) {
			t.Fatal("actual App review changed an original SID, candidate or zero-permission slot")
		}
	}
	assertZero := func() {
		t.Helper()
		readStore(func(db *store.Store) {
			for _, j := range joins {
				m := must(db.GetMembershipByPrincipalGroup(j.Endpoint.PrincipalID, claims.Bootstrap.GroupID))
				grant, err := db.GetGroupEndpointKeyGrant(original.Account.OwnerID, claims.Bootstrap.GroupID, j.Endpoint.ID)
				if len(m.Grants) != 0 || !errors.Is(err, store.ErrGroupEndpointKeyGrantNotFound) || grant != nil {
					t.Fatal("actual App first-consent boundary published partial authority")
				}
			}
		})
	}
	assertZero()
	reviewed := do(appcore.Action{Kind: appcore.ActionPreparePairConsent, Pair: appcore.PairAction{PairID: pairID}})
	if reviewed.Pair.ReviewID == "" || reviewed.Pair.ControlRevision != observed.Pair.ControlRevision {
		t.Fatal("actual App consent review advanced activation or omitted its immutable target")
	}
	first := do(appcore.Action{Kind: appcore.ActionApprovePairSlot, Pair: appcore.PairAction{
		PairID: pairID, ReviewID: reviewed.Pair.ReviewID, Slot: "A", ConfirmSlot: true}})
	if first.Pair.State != string(wire.NativePairWaitingConsent) || !first.Pair.Slots[0].ConsentRecorded || first.Pair.Slots[1].ConsentRecorded ||
		first.Pair.ControlRevision != observed.Pair.ControlRevision || first.Pair.ReviewID == "" {
		t.Fatal("actual App first consent activated peers or lost the second explicit review")
	}
	assertZero()
	active := do(appcore.Action{Kind: appcore.ActionApprovePairSlot, Pair: appcore.PairAction{
		PairID: pairID, ReviewID: first.Pair.ReviewID, Slot: "B", ConfirmSlot: true}})
	if active.Pair.State != string(wire.NativePairActive) || !active.Pair.Current || !active.Pair.Slots[0].ConsentRecorded ||
		!active.Pair.Slots[1].ConsentRecorded || active.Pair.ControlRevision != first.Pair.ControlRevision+1 {
		t.Fatal("actual App second consent did not activate the original pair exactly once")
	}
	readStore(func(db *store.Store) {
		for i, j := range joins {
			m := must(db.GetMembershipByPrincipalGroup(j.Endpoint.PrincipalID, claims.Bootstrap.GroupID))
			want, actual := wire.NativePairGroupGrants(), append([]string(nil), m.Grants...)
			sort.Strings(want)
			sort.Strings(actual)
			grant := must(db.VerifyCurrentGroupEndpointKeyGrant(original.Account.OwnerID, claims.Bootstrap.GroupID, j.Endpoint.ID))
			if !reflect.DeepEqual(actual, want) || uint64(m.Revision) != observed.Pair.Slots[i].MembershipRevision+1 ||
				grant.OwnerKeyID != ownerPublic.ID || grant.Manifest.CandidateKeyID != keys[i].Public().ID {
				t.Fatal("actual App grants do not project the original real candidates/memberships")
			}
			proof := must(e2ee.VerifyOwnerLinkKeyGrant(grant.SignedProof, ownerPublic, original.Account.OwnerID,
				grant.Manifest.Operation, grant.Manifest.Digest, grant.Manifest.CandidateBindingDigest,
				uint64(grant.Manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, time.Now().UTC()))
			if proof.IssuedAt != grant.Manifest.IssuedAt || proof.ExpiresAt != grant.Manifest.ExpiresAt {
				t.Fatal("actual App signed its click time instead of the reviewed GroupKey manifest time")
			}
		}
	})
	current := do(appcore.Action{Kind: appcore.ActionRefreshPair})
	if current.Pair.State != string(wire.NativePairActive) || !current.Pair.Current || current.Pair.StateReviewID == "" {
		t.Fatal("actual App did not re-observe its current ACTIVE state for explicit cleanup")
	}
	revoked := do(appcore.Action{Kind: appcore.ActionRevokePair, Pair: appcore.PairAction{
		PairID: pairID, ReviewID: current.Pair.StateReviewID, ConfirmRevoke: true}})
	if revoked.Pair.State != string(wire.NativePairRevoked) || revoked.Pair.Pending {
		t.Fatal("actual App did not explicitly revoke its owned synthetic pair")
	}
	readStore(func(db *store.Store) {
		for _, j := range joins {
			if _, err := db.VerifyCurrentGroupEndpointKeyGrant(original.Account.OwnerID, claims.Bootstrap.GroupID, j.Endpoint.ID); err == nil {
				t.Fatal("App revoke left an effective CURRENT key grant")
			}
		}
	})
	t.Log("NATIVE_PAIR_ACTUAL_APP_OWNER production_App_child_Actions=true Owner_private_key_remained_in_vault=true real_Hub_CLI_TCP_PQ=true synthetic_Node_zero_Joins=true first_consent_zero=true second_consent_actual_CURRENT_grants=true original_manifest_times=true App_revoke=true Control_inference=false native_MCP_queue_Runtime_Windows_NOT_RUN=true")
}

type appPairNodeFixture struct {
	f        *hubFixture
	id       string
	key      *e2ee.Identity
	token    string
	binding  nodewire.Binding
	sequence uint64
	client   *http.Client
}

// Only the synthetic Node owns these keys. App approval still uses the actual
// existing child/vault and the production Node confirmation path.
func newAppPairNodeFixture(t *testing.T, f *hubFixture, do func(appcore.Action) appcore.Snapshot) *appPairNodeFixture {
	t.Helper()
	n := &appPairNodeFixture{f: f, id: "synthetic-n3-actual-app-pair", key: must(e2ee.NewIdentity()),
		client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	t.Cleanup(n.client.CloseIdleConnections)
	code, raw := n.http(t, http.MethodGet, "/v2/node/identity", "", "", nil)
	var hub nodebinding.HubIdentity
	if code != http.StatusOK || json.Unmarshal(raw, &hub) != nil || hub.HubID != f.cfg.Hub.HubID {
		t.Fatal("original synthetic Hub Node identity is unavailable")
	}
	var credentialDigest string
	var err error
	n.token, credentialDigest, err = fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nonce := must(wire.NewNonce())
	transcript := must(nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID, NodeID: n.id,
		RequestNonce: nonce, CredentialDigest: credentialDigest, NodePublicIdentity: n.key.Public(),
		HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion}))
	proof := must(e2ee.Seal(n.key, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1))
	code, raw = n.http(t, http.MethodPost, "/v2/nodes/device-code", "", "", map[string]any{
		"node_id": n.id, "node_name": "Synthetic actual App Node", "credential_digest": credentialDigest,
		"request_nonce": nonce, "node_public_identity": n.key.Public(), "node_fingerprint": nodewire.IdentityFingerprint(n.key.Public()),
		"proof_packet": proof, "hub_id": hub.HubID, "hub_public_identity": hub.PublicIdentity,
		"hub_key_version": hub.KeyVersion, "hub_fingerprint": hub.Fingerprint})
	var pending nodebinding.DeviceCode
	if code != http.StatusCreated || json.Unmarshal(raw, &pending) != nil || pending.Candidate == nil {
		t.Fatal("actual synthetic Node proof was not admitted", code)
	}
	preview := do(appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.UserCode})
	if preview.Node.Candidate == nil || preview.Node.Candidate.NodeID != n.id ||
		preview.Node.Candidate.NodeFingerprint != nodewire.IdentityFingerprint(n.key.Public()) || preview.Node.Candidate.HubControlFingerprint != hub.Fingerprint {
		t.Fatal("actual App Node review moved the synthetic original key tuple")
	}
	approved := do(appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: preview.Node.Candidate.ReviewID,
		ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	path := "/v2/node/device-code/" + url.PathEscape(pending.Candidate.RequestID) + "/status?node_id=" + url.QueryEscape(n.id)
	code, raw = n.http(t, http.MethodGet, path, "CicadaNode "+n.token, "", nil)
	var binding struct {
		State          string `json:"state"`
		BindingID      string `json:"binding_id"`
		BindingVersion uint64 `json:"binding_version"`
		NodeKeyEpoch   uint64 `json:"node_key_epoch"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &binding) != nil || binding.State != "CONFIRMED" ||
		approved.Node.Binding == nil || binding.BindingID != approved.Node.Binding.ID ||
		binding.BindingVersion != approved.Node.Binding.Version || binding.NodeKeyEpoch == 0 {
		t.Fatal("actual App did not confirm the synthetic Node's original binding")
	}
	n.binding = nodewire.Binding{HubID: hub.HubID, NodeID: n.id, BindingID: binding.BindingID,
		BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch, HubKeyVersion: hub.KeyVersion,
		NodeKeyVersion: 1, NodeKey: n.key.Public(), HubKey: hub.PublicIdentity}
	return n
}

func (n *appPairNodeFixture) http(t *testing.T, method, path, authorization, group string, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw = must(json.Marshal(body))
	}
	req := must(http.NewRequest(method, n.f.cfg.Origin+path, bytes.NewReader(raw)))
	req.Header.Set("Origin", n.f.cfg.Origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Cicada-Group-Scope", group)
	response := must(n.client.Do(req))
	defer response.Body.Close()
	out := must(io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairNodeReconcilePacketBytes+1)))
	if len(out) > wire.MaxNativePairNodeReconcilePacketBytes {
		t.Fatal("owned synthetic Node response exceeded its bounded fixture")
	}
	return response.StatusCode, out
}

func (n *appPairNodeFixture) rpc(t *testing.T, operation string, body, target any) {
	t.Helper()
	n.sequence++
	b := n.binding
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID,
		NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch,
		Sequence: n.sequence, OperationID: must(wire.NewRequestID()), Operation: operation,
		SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	packet := must(nodewire.SealRequest(n.key, b.HubKey, b, route, must(json.Marshal(body))))
	atomicPrivate(t, filepath.Join(n.f.dir, "app-pair-original-node-"+route.OperationID+".packet"), packet)
	req := must(http.NewRequest(http.MethodPost, n.f.cfg.Origin+"/v2/node/control/rpc", bytes.NewReader(packet)))
	req.Header.Set("Origin", n.f.cfg.Origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "CicadaNode "+n.token)
	response := must(n.client.Do(req))
	defer response.Body.Close()
	raw := must(io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairNodeReconcilePacketBytes+1)))
	if response.StatusCode != http.StatusOK || len(raw) > wire.MaxNativePairNodeReconcilePacketBytes {
		t.Fatal("owned synthetic Node PQ operation failed", operation, response.StatusCode)
	}
	opened := must(nodewire.OpenResponse(n.key, b.HubKey, b, raw))
	want := route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	var reply struct {
		OK          bool            `json:"ok"`
		OperationID string          `json:"operation_id"`
		Sequence    uint64          `json:"sequence"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   string          `json:"error_code"`
	}
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &reply) != nil || !reply.OK || reply.OperationID != route.OperationID ||
		reply.Sequence != route.Sequence || json.Unmarshal(reply.Result, target) != nil {
		t.Fatal("owned synthetic Node response changed its original route or result", operation, reply.ErrorCode)
	}
}
