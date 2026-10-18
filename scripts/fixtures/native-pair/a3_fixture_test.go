package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Independent low-level PQ caller over a disposable production Handler. Prior
// N2/N3, Node proof, zero Joins, candidates and both consents use actual APIs.
// This is a producer-core fixture, not public SDK availability/App UI/Runtime
// acceptance. SIDs/passwords/keys are synthetic and never initialize deployment.
type qaA3Fixture struct {
	*nativePairTCPActor
	bootstrap wire.NativePairBootstrapChallenge
	describe  wire.NativePairNodeDescription
	joins     [2]fabric.JoinResult
	keys      [2]*e2ee.Identity
	plan      wire.NativePairPlanChallenge
	client    *http.Client
}

func qaA3Setup(t *testing.T) *qaA3Fixture {
	t.Helper()
	a := &qaA3Fixture{nativePairTCPActor: nativePairTCP(t), client: &http.Client{
		Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	t.Cleanup(a.client.CloseIdleConnections)
	a.bootstrap = a.completePair(t)
	a.scope = a.bootstrap.Scope
	a.describe = a.describePair(t, a.bootstrap, 1)
	for i, slot := range []string{"A", "B"} {
		generation := a.describe.SlotAGeneration
		if i == 1 {
			generation = a.describe.SlotBGeneration
		}
		q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision,
			PairID: a.bootstrap.Bootstrap.PairID, Slot: slot, ExpectedGeneration: generation,
			BootstrapProofDigest: wire.NativePairProofDigest(a.describe.BootstrapOwnerProof),
			Runtime:              "codex", NativeSessionID: "synthetic-qa-a3-original-" + slot,
			Workspace: "/synthetic/qa-a3/" + slot, EndpointName: "Synthetic QA A3 " + slot}
		packet := a.nodeSeal(t, wire.OperationNativePairNodeJoin, uint64(i+2), q)
		reply := a.nodeOpen(t, packet, a.nodePost(t, packet, http.StatusOK))
		if !reply.OK || json.Unmarshal(reply.Result, &a.joins[i]) != nil {
			t.Fatal("actual synthetic zero Join failed")
		}
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		a.keys[i] = key
		j := a.joins[i]
		proof, err := key.SignEndpointKeyAttestation(j.Endpoint.ID, j.Endpoint.PrincipalID,
			a.scope.Node.NodeID, j.BindingID, j.BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := a.http(t, http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+j.SessionToken,
			a.bootstrap.Bootstrap.GroupID, map[string]any{"attestation": json.RawMessage(proof)})
		if code != http.StatusOK {
			t.Fatal("actual synthetic self candidate publication failed", code)
		}
	}
	status := a.status(t)
	if status.SlotA == nil || status.SlotB == nil || status.SlotA.NativeSessionID == status.SlotB.NativeSessionID ||
		status.SlotA.NodeID != status.SlotB.NodeID || status.SlotAState != wire.NativePairSlotCandidateReady ||
		status.SlotBState != wire.NativePairSlotCandidateReady {
		t.Fatal("fixture did not produce two distinct zero-permission candidates on its original Node")
	}
	a.assertZero(t)
	c, claims := a.claims(t, e2ee.OwnerNativePairConsentPreview, time.Time{})
	ad, err := wire.NativePairSlotDigest(*status.SlotA)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := wire.NativePairSlotDigest(*status.SlotB)
	if err != nil {
		t.Fatal(err)
	}
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: status.PairID,
		ExpectedRevision: status.ControlRevision, SlotADigest: ad, SlotBDigest: bd, PeerExpiresAt: status.PeerExpiresAt}
	proof, err := e2ee.SignOwnerNativePair(a.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairConsentPrepare{Format: wire.NativePairFormat, Context: c,
		SessionToken: a.session.Token, OwnerProof: proof}
	packet, _ := a.call(t, wire.OperationNativePairConsentPrepare, q, &a.plan)
	if wire.ValidateNativePairPlanTarget(q, packet, a.plan, a.describe.BootstrapOwnerProof, a.f.hub, time.Now().UTC()) != nil {
		t.Fatal("actual activation plan changed the reviewed signed scope")
	}
	a.assertZero(t)
	return a
}

func (a *qaA3Fixture) http(t *testing.T, method, path, authorization, group string, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, a.f.http.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Cicada-Group-Scope", group)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		t.Fatal("owned loopback HTTP failed")
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxNativePairCarrierBytes+1))
	if err != nil || len(out) > wire.MaxNativePairCarrierBytes {
		t.Fatal("owned loopback carrier was truncated or oversized")
	}
	return res.StatusCode, out
}

func (a *qaA3Fixture) claims(t *testing.T, purpose string, until time.Time) (wire.NativePairRequestContext, e2ee.OwnerNativePairClaims) {
	t.Helper()
	c := a.context(t)
	issued, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	end := issued.Add(time.Minute)
	sessionEnd, err := time.Parse(time.RFC3339Nano, a.scope.Actor.AccountSessionExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	if !until.IsZero() && until.Before(end) {
		end = until
	}
	return c, e2ee.OwnerNativePairClaims{Version: 1, Purpose: purpose, Scope: a.scope,
		RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt,
		ExpiresAt: end.Format(time.RFC3339Nano)}
}

func (a *qaA3Fixture) packet(t *testing.T, body any) []byte {
	t.Helper()
	raw := a.seal(t, body)
	p, err := wire.DecodeNativePairPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	// A test-owned private durable original, written before its sole HTTP POST.
	path := filepath.Join(a.f.stateDir, "qa-a3-original-"+p.Packet.Route.OperationID+".packet")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil {
		t.Fatal("original ciphertext could not be retained durably")
	}
	return raw
}

func (a *qaA3Fixture) sendPacket(t *testing.T, origin, operation string, packet []byte) ([]byte, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, origin+wire.NativePairHTTPPath(operation), bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", a.f.setup.Origin)
	res, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxNativePairReconcilePacketBytes+1))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK || len(raw) > wire.MaxNativePairReconcilePacketBytes {
		t.Fatal("actual pair HTTP response refused or exceeded its bound", res.StatusCode)
	}
	return raw, nil
}

func (a *qaA3Fixture) call(t *testing.T, op string, q, out any) ([]byte, []byte) {
	t.Helper()
	packet := a.packet(t, q)
	reply, err := a.sendPacket(t, a.f.http.URL, op, packet)
	if err != nil || wire.OpenClientResponse(a.device, a.f.hub, packet, reply, out) != nil {
		t.Fatal("actual pair response lacked a complete authenticated original receipt")
	}
	return packet, reply
}

func (a *qaA3Fixture) status(t *testing.T) wire.NativePairResult {
	t.Helper()
	q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: a.context(t),
		SessionToken: a.session.Token, PairID: a.bootstrap.Bootstrap.PairID}
	var result wire.NativePairResult
	a.call(t, wire.OperationNativePairStatus, q, &result)
	return result
}

func (a *qaA3Fixture) consent(t *testing.T, i int) wire.NativePairConsentComplete {
	t.Helper()
	p := a.plan.Plan
	slot, peer, manifest := p.SlotA, p.SlotB, p.SlotAKeyManifest
	if i == 1 {
		slot, peer, manifest = p.SlotB, p.SlotA, p.SlotBKeyManifest
	}
	end, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	c, claims := a.claims(t, e2ee.OwnerNativePairSlotConsent, end)
	ad, _ := wire.NativePairSlotDigest(p.SlotA)
	bd, _ := wire.NativePairSlotDigest(p.SlotB)
	claims.Consent = &e2ee.NativePairConsentClaims{PairID: p.PairID, ExpectedRevision: p.ExpectedRevision,
		PlanID: p.PlanID, PlanDigest: p.Digest, SlotADigest: ad, SlotBDigest: bd, Slot: slot.Slot,
		SlotGeneration: slot.Generation, SlotAttemptID: slot.AttemptID, NativeSessionID: slot.NativeSessionID,
		PeerNativeSessionID: peer.NativeSessionID, ActivateWhenBoth: true,
		PlanExpiresAt: p.ExpiresAt, PeerExpiresAt: p.PeerExpiresAt}
	if wire.ValidateNativePairConsentTarget(claims, p) != nil {
		t.Fatal("test consent did not match the actual plan")
	}
	proof, err := e2ee.SignOwnerNativePair(a.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	group, err := a.owner.SignOwnerLinkKeyGrant(manifest.OwnerID, manifest.Operation, manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	return wire.NativePairConsentComplete{Format: wire.NativePairFormat, Context: c,
		SessionToken: a.session.Token, OwnerProof: proof, GroupKeyProof: group}
}

func (a *qaA3Fixture) assertZero(t *testing.T) {
	t.Helper()
	for _, j := range a.joins {
		membership, err := a.f.db.GetMembershipByPrincipalGroup(j.Endpoint.PrincipalID, a.bootstrap.Bootstrap.GroupID)
		if err != nil || len(membership.Grants) != 0 {
			t.Fatal("partial consent supplied a membership grant")
		}
		if grant, err := a.f.db.GetGroupEndpointKeyGrant(a.scope.Actor.OwnerID, a.bootstrap.Bootstrap.GroupID, j.Endpoint.ID); !errors.Is(err, store.ErrGroupEndpointKeyGrantNotFound) || grant != nil {
			t.Fatal("partial consent supplied an effective legacy key grant")
		}
	}
	code, _ := a.http(t, http.MethodPost, "/v2/fabric/resolve", "CicadaSession "+a.joins[0].SessionToken,
		a.bootstrap.Bootstrap.GroupID, fabric.ResolveInput{Query: a.joins[1].Endpoint.ID})
	if code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatal("zero-permission scope did not deny peer resolve", code)
	}
}

func (a *qaA3Fixture) assertActive(t *testing.T, result wire.NativePairResult) {
	t.Helper()
	if result.State != wire.NativePairActive || result.SlotAState != wire.NativePairSlotActive ||
		result.SlotBState != wire.NativePairSlotActive || result.ControlRevision <= a.plan.Plan.ExpectedRevision {
		t.Fatal("second consent did not publish both active slots together")
	}
	for i, j := range a.joins {
		member, err := a.f.db.GetMembershipByPrincipalGroup(j.Endpoint.PrincipalID, a.bootstrap.Bootstrap.GroupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append([]string(nil), member.Grants...)
		want := wire.NativePairGroupGrants()
		sort.Strings(grants)
		sort.Strings(want)
		projected, manifest := a.plan.Plan.ProjectedSlotAMembership, a.plan.Plan.SlotAKeyManifest
		if i == 1 {
			projected, manifest = a.plan.Plan.ProjectedSlotBMembership, a.plan.Plan.SlotBKeyManifest
		}
		if !reflect.DeepEqual(grants, want) || member.Revision != int64(projected) {
			t.Fatal("activation did not use the exact projected fixed membership")
		}
		grant, err := a.f.db.VerifyCurrentGroupEndpointKeyGrant(a.scope.Actor.OwnerID, a.bootstrap.Bootstrap.GroupID, j.Endpoint.ID)
		if err != nil || grant.Manifest.Digest != manifest.Digest || grant.Manifest.CandidateBindingDigest != manifest.CandidateBindingDigest {
			t.Fatal("activation did not install both original CURRENT GroupKeyGrant manifests")
		}
	}
}
