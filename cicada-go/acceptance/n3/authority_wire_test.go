package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Wire adversaries exercise the real Hub independently of App preflight. They
// reuse the actual production App's synthetic keys/session, while positive
// native workflows run in appProcess. Neither this actor nor the opaque packet
// sender is evidence that the production App handles an operation correctly.
type authorityWireActor struct {
	f             *hubFixture
	device, owner *e2ee.Identity
	session       wire.AppNodeSession
	scope         e2ee.OwnerAppNodeScope
}

type wireHTTPResult struct {
	status   int
	response []byte
	err      error
}

func parallelPosts(t *testing.T, f *hubFixture, paths []string, packets [][]byte) []wireHTTPResult {
	t.Helper()
	if len(paths) != len(packets) || len(paths) == 0 {
		t.Fatal("invalid independent concurrent request set")
	}
	requests := make([]*http.Request, len(paths))
	for i := range paths {
		requests[i] = must(http.NewRequest(http.MethodPost, f.proxy.server.URL+paths[i], bytes.NewReader(packets[i])))
		requests[i].Header.Set("Origin", f.cfg.Origin)
		requests[i].Header.Set("Content-Type", "application/json")
	}
	type indexed struct {
		i int
		wireHTTPResult
	}
	start, done := make(chan struct{}), make(chan indexed, len(paths))
	for i, request := range requests {
		go func(i int, request *http.Request) {
			<-start
			response, err := f.proxy.client.Do(request)
			result := wireHTTPResult{err: err}
			if err == nil {
				result.status = response.StatusCode
				result.response, result.err = io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1))
				response.Body.Close()
			}
			done <- indexed{i, result}
		}(i, request)
	}
	close(start)
	results := make([]wireHTTPResult, len(paths))
	for range paths {
		got := <-done
		results[got.i] = got.wireHTTPResult
	}
	for _, result := range results {
		if result.err != nil || len(result.response) > wire.MaxPacketBytes {
			t.Fatal("actual concurrent Hub requests did not produce bounded transport outcomes")
		}
	}
	return results
}

func newAuthorityWireActor(t *testing.T, f *hubFixture) *authorityWireActor {
	t.Helper()
	if f.mode != "--hub-nodes-only" {
		t.Fatal("N3 wire actor requires the reviewed production Hub/Node composition")
	}
	account := ownedAccountSession(t, f)
	a := &authorityWireActor{f: f, device: ownedAppIdentity(t, f, appvault.PurposeAppDevice),
		owner: ownedAppIdentity(t, f, appvault.PurposeOwnerSigner)}
	a.session = wire.AppNodeSession{Hub: f.cfg.Hub, Origin: f.cfg.Origin, AccountID: account.AccountID,
		OwnerID: account.OwnerID, DeviceID: account.DeviceID, AccountEpoch: account.AccountEpoch,
		DeviceEpoch: account.DeviceEpoch, Token: bytes.Clone(account.SessionToken)}
	t.Cleanup(func() { clear(a.session.Token) })
	// Even adversarial drivers discover before their first new N3 secret POST.
	response := must(f.proxy.client.Get(f.proxy.server.URL + wire.AppNodeCapabilitiesPath))
	raw := must(io.ReadAll(io.LimitReader(response.Body, wire.MaxAppNodeCapabilitiesBytes+1)))
	response.Body.Close()
	defer clear(raw)
	if _, err := wire.DecodeAppNodeCapabilities(raw); response.StatusCode != 200 || err != nil {
		t.Fatal("production N3 capabilities unavailable or unrecognized; runtime is not accepted")
	}
	request := must(wire.NewAppNodeStatus(a.session, "", time.Now().UTC()))
	_, opened := a.call(t, wire.OperationAppNodeStatus, request)
	if opened.Result == nil {
		t.Fatal("actual Hub returned no authenticated N3 bootstrap context")
	}
	a.scope = opened.Result.Authority.Scope
	if wire.ValidateAppNodeScope(a.scope, f.cfg.Hub) != nil || a.scope.AccountID != account.AccountID ||
		a.scope.OwnerID != account.OwnerID || a.scope.DeviceID != account.DeviceID ||
		!reflect.DeepEqual(a.scope.OwnerPublic, a.owner.Public()) || !reflect.DeepEqual(a.scope.DevicePublic, a.device.Public()) ||
		opened.Result.Authority.RootState != wire.RootActiveState || opened.Result.Authority.LoginRequired || opened.Result.Node != nil {
		t.Fatal("N3 bootstrap context differs from the actual proved Root/App/session")
	}
	return a
}

func (a *authorityWireActor) post(t *testing.T, path string, packet []byte) (int, []byte) {
	t.Helper()
	loopback(t, a.f.cfg.Origin)
	for attempt := 0; attempt < 60; attempt++ {
		// Ordinary wire/stress traffic respects the existing auth token bucket.
		// A 429 never reseals or changes ID/nonce/body: retry exactly this frame.
		// Actual App fault injection uses its own transport, outside this helper.
		request := must(http.NewRequest(http.MethodPost, a.f.proxy.server.URL+path, bytes.NewReader(packet)))
		request.Header.Set("Origin", a.f.cfg.Origin)
		request.Header.Set("Content-Type", "application/json")
		response := must(a.f.proxy.client.Do(request))
		raw := must(io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1)))
		response.Body.Close()
		if len(raw) > wire.MaxPacketBytes {
			clear(raw)
			t.Fatal("actual Hub response exceeds the reviewed packet bound")
		}
		if response.StatusCode != http.StatusTooManyRequests {
			return response.StatusCode, raw
		}
		clear(raw)
		time.Sleep(time.Second)
	}
	t.Fatal("ordinary exact-frame retry remained throttled for its bounded deadline")
	return 0, nil
}

func (a *authorityWireActor) call(t *testing.T, operation string, body any) ([]byte, wire.AppNodeResponse) {
	t.Helper()
	packet := must(wire.SealClientRequest(a.device, a.f.cfg.Hub, body))
	decoded := must(wire.DecodePacket(packet))
	if decoded.Packet.Route.Operation != operation {
		t.Fatal("wire actor operation does not match its reviewed typed constructor")
	}
	atomicPrivate(t, filepath.Join(a.f.dir, "synthetic-authority-"+decoded.Packet.Route.OperationID+".packet"), packet)
	code, response := a.post(t, wire.AppNodeHTTPPath(operation), packet)
	defer clear(response)
	if code != http.StatusOK {
		t.Fatalf("actual N3 operation did not return an authenticated outcome: HTTP=%d", code)
	}
	opened, err := wire.OpenAppNodeResponse(a.device, a.f.cfg.Hub, packet, response)
	if err != nil {
		t.Fatal("actual Hub response failed full pinned PQ authentication")
	}
	return packet, opened
}

// Independently inspect decrypted JSON for privacy checks, including fields a
// typed decoder might discard. The existing lower-level wire still verifies
// real PQ crypto/AAD; the complete pinned sender and mirrored route are checked.
func rawAuthorityReply(t *testing.T, a *authorityWireActor, original, response []byte) []byte {
	t.Helper()
	request := must(wire.DecodePacket(original))
	reply := must(wire.DecodePacket(response))
	expected := request.Packet.Route
	expected.Direction = clientwire.DirectionResponse
	expected.SenderKeyID, expected.ReceiverKeyID = expected.ReceiverKeyID, expected.SenderKeyID
	expected.SenderKeyVersion, expected.ReceiverKeyVersion = expected.ReceiverKeyVersion, expected.SenderKeyVersion
	if reply.Packet.Route != expected || !reflect.DeepEqual(reply.SenderPublicIdentity, a.f.cfg.Hub.Public) {
		t.Fatal("privacy observation changed the full Hub pin or exact response route")
	}
	binding := clientwire.Binding{HubID: expected.HubID, OwnerID: expected.OwnerID, DeviceID: expected.DeviceID,
		SessionEpoch: expected.SessionEpoch, HubKeyVersion: a.f.cfg.Hub.KeyVersion, DeviceKeyVersion: wire.DeviceKeyVersion}
	inner := must(json.Marshal(reply.Packet))
	defer clear(inner)
	opened := must(clientwire.OpenResponseWithLimits(a.device, a.f.cfg.Hub.Public, binding, inner,
		wire.MaxAppNodeBodyBytes, wire.MaxAppNodeInnerPacketBytes))
	if opened.Route != expected {
		clear(opened.Plaintext)
		t.Fatal("privacy observation failed authenticated route binding")
	}
	return opened.Plaintext
}

func (a *authorityWireActor) prepare(t *testing.T, target wire.AppNodePrepareTarget) (wire.AppNodePrepare, []byte, wire.AppNodeChallenge) {
	t.Helper()
	context := must(wire.NewAppNodeStatus(a.session, "", time.Now().UTC()))
	_, current := a.call(t, wire.OperationAppNodeStatus, context)
	if current.Result == nil || wire.ValidateAppNodeScope(current.Result.Authority.Scope, a.f.cfg.Hub) != nil {
		t.Fatal("new explicit preview lacks a fresh authenticated current head/session")
	}
	a.scope = current.Result.Authority.Scope
	request := must(wire.NewAppNodePrepare(a.session, a.scope, target, a.owner, time.Now().UTC()))
	packet, opened := a.call(t, wire.OperationAppNodePrepare, request)
	intent := must(e2ee.VerifyOwnerAppNodePreview(a.owner.Public(), request.OwnerIntent, time.Time{}))
	if opened.Challenge == nil || wire.ValidateAppNodePreparedResponse(*opened.Challenge, intent, request.OwnerIntent, packet, a.f.cfg.Hub, time.Now().UTC()) != nil {
		t.Fatal("actual Hub did not produce the exact authenticated selected candidate")
	}
	return request, packet, *opened.Challenge
}

func (a *authorityWireActor) complete(t *testing.T, prepare wire.AppNodePrepare, original []byte, challenge wire.AppNodeChallenge) wire.AppNodeResult {
	t.Helper()
	request := must(wire.NewAppNodeComplete(a.session, prepare, original, challenge, a.owner, time.Now().UTC()))
	_, opened := a.call(t, wire.OperationAppNodeComplete, request)
	if opened.Result == nil || opened.Result.State != wire.AppNodeCompleted || opened.Result.Authority.State != wire.AppNodeActive ||
		opened.Result.Authority.GrantID != challenge.Claims.GrantID || opened.Result.Authority.CurrentHeadVersion != challenge.Claims.Scope.HeadVersion ||
		!reflect.DeepEqual(opened.Result.Authority.Scope, challenge.Claims.Scope) {
		t.Fatal("actual Hub did not activate the exact finite instance")
	}
	a.scope = opened.Result.Authority.Scope
	return *opened.Result
}

// Bypass only the outgoing typed-body validation to put a genuinely encrypted
// invalid request onto TCP. This uses the reviewed lower-level sealer, the same
// real crypto and the exact frozen route/limits; it is never a product fallback.
func rawAuthorityPacket(t *testing.T, f *hubFixture, key *e2ee.Identity, operation string, ctx wire.AppNodeRequestContext, body any) []byte {
	return rawAuthorityPacketForHub(t, f.cfg.Hub, key, operation, ctx, body)
}

func rawAuthorityPacketForHub(t *testing.T, hub wire.HubIdentity, key *e2ee.Identity, operation string, ctx wire.AppNodeRequestContext, body any) []byte {
	t.Helper()
	binding, route, err := wire.RequestRoute(hub, ctx.OwnerID, ctx.DeviceID, ctx.RequestID, operation, wire.HandshakeEpoch, key.Public())
	if err != nil {
		t.Fatal("adversarial request cannot use the reviewed N3 route")
	}
	plain := must(json.Marshal(body))
	defer clear(plain)
	inner := must(clientwire.SealRequestWithLimits(key, hub.Public, binding, route, plain, wire.MaxAppNodeBodyBytes, wire.MaxAppNodeInnerPacketBytes))
	defer clear(inner)
	var packet clientwire.Packet
	if json.Unmarshal(inner, &packet) != nil {
		t.Fatal("actual encrypted adversarial frame is invalid")
	}
	return must(json.Marshal(wire.Packet{Format: wire.PacketFormat, Version: wire.PacketVersion,
		SenderPublicIdentity: key.Public(), Packet: packet}))
}

// A real signature over unsupported claims/purpose distinguishes semantic
// refusal from signature-corruption refusal. All valid requests use the shared
// proof constructor; only independent adversarial cases sign raw frozen claims.
func adversarialOwnerPreview(t *testing.T, signer *e2ee.Identity, claims e2ee.OwnerAppNodePreviewClaims) []byte {
	return must(json.Marshal(e2ee.OwnerAppNodePreview{Claims: claims,
		Signature: adversarialOwnerSignature(t, signer, e2ee.OwnerAppNodePreviewDomain, claims)}))
}

func adversarialOwnerGrant(t *testing.T, signer *e2ee.Identity, claims e2ee.OwnerAppNodeGrantClaims) []byte {
	return must(json.Marshal(e2ee.OwnerAppNodeGrant{Claims: claims,
		Signature: adversarialOwnerSignature(t, signer, e2ee.OwnerAppNodeGrantDomain, claims)}))
}

func adversarialOwnerSignature(t *testing.T, signer *e2ee.Identity, domain string, claims any) []byte {
	t.Helper()
	raw := must(json.Marshal(claims))
	signed := append([]byte(domain), raw...)
	defer clear(raw)
	defer clear(signed)
	signature := must(signer.Sign(signed))
	var public mldsa65.PublicKey
	if public.UnmarshalBinary(signer.Public().SigningPublic) != nil || !mldsa65.Verify(&public, signed, nil, signature) {
		t.Fatal("adversarial semantic case lacks a valid real ML-DSA signature")
	}
	return signature
}
