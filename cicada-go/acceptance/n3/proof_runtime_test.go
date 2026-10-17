package n3_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// These real TCP cases remain outside the preparation selector. A missing
// production --hub-nodes-only composition is a failure, not a skipped test.
func TestN3ServerRejectsIndependentProofScopeAttacks(t *testing.T) {
	for _, kind := range []string{"missing-proof", "forged-signature", "wrong-signer", "unauthorized-purpose", "wrong-owner", "wrong-account", "wrong-origin", "wrong-app-key", "wrong-hub-public", "target-substitution", "expired-intent"} {
		t.Run(kind, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "proved-account-ready.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			app.kill(t)
			a := newAuthorityWireActor(t, f)
			node := startNodeProcess(t, f, "synthetic-n3-proof-target")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			target := wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode}
			request := must(wire.NewAppNodePrepare(a.session, a.scope, target, a.owner, time.Now().UTC()))
			var proof e2ee.OwnerAppNodePreview
			if json.Unmarshal(request.OwnerIntent, &proof) != nil {
				t.Fatal("reviewed preview proof fixture is invalid")
			}
			key := a.device
			targetHub := f.cfg.Hub
			switch kind {
			case "missing-proof":
				request.OwnerIntent = nil
			case "forged-signature":
				proof.Signature[0] ^= 1
				request.OwnerIntent = must(json.Marshal(proof))
			case "wrong-signer":
				request.OwnerIntent = adversarialOwnerPreview(t, must(e2ee.NewIdentity()), proof.Claims)
			case "unauthorized-purpose":
				proof.Claims.Purpose = "SYNTHETIC_UNAUTHORIZED_MANAGER"
				request.OwnerIntent = adversarialOwnerPreview(t, a.owner, proof.Claims)
			case "wrong-owner":
				request.Context.OwnerID, proof.Claims.Scope.OwnerID = "synthetic-foreign-owner", "synthetic-foreign-owner"
				request.OwnerIntent = adversarialOwnerPreview(t, a.owner, proof.Claims)
			case "wrong-account":
				request.Context.AccountID, proof.Claims.Scope.AccountID = "synthetic-foreign-account", "synthetic-foreign-account"
				request.OwnerIntent = adversarialOwnerPreview(t, a.owner, proof.Claims)
			case "wrong-origin":
				request.Context.Origin, proof.Claims.Scope.Origin = "http://127.0.0.1:1", "http://127.0.0.1:1"
				request.OwnerIntent = adversarialOwnerPreview(t, a.owner, proof.Claims)
			case "wrong-app-key":
				key = must(e2ee.NewIdentity())
			case "wrong-hub-public":
				targetHub.Public = must(e2ee.NewIdentity()).Public()
			case "target-substitution":
				request.Target.Code = "222222222222"
				if normalized := must(wire.NormalizeAppNodeCode(pending.PendingCode)); normalized == request.Target.Code {
					request.Target.Code = "333333333333"
				}
			case "expired-intent":
				issued := time.Now().UTC().Add(-2 * time.Second)
				request.Context.IssuedAt = issued.Format(time.RFC3339Nano)
				proof.Claims.IssuedAt = request.Context.IssuedAt
				proof.Claims.ExpiresAt = issued.Add(time.Second).Format(time.RFC3339Nano)
				request.OwnerIntent = adversarialOwnerPreview(t, a.owner, proof.Claims)
			}
			packet := rawAuthorityPacketForHub(t, targetHub, key, wire.OperationAppNodePrepare, request.Context, request)
			defer clear(packet)
			code, response := a.post(t, wire.AppNodeHTTPPath(wire.OperationAppNodePrepare), packet)
			defer clear(response)
			// A transport denial is not an authenticated fence for App recovery.
			// It can establish server rejection here only with the independent
			// unchanged-authority and still-usable-candidate checks below.
			if code == http.StatusOK {
				opened, err := wire.OpenAppNodeResponse(key, f.cfg.Hub, packet, response)
				if err != nil || opened.Result == nil || opened.Result.State != wire.AppNodeRejectedFenced {
					t.Fatal("invalid signed/encrypted N3 request was not authentically refused")
				}
			} else if code != http.StatusBadRequest && code != http.StatusForbidden && code != http.StatusUnauthorized {
				t.Fatalf("negative case reached an unavailable/error response, HTTP=%d", code)
			}
			status := must(wire.NewAppNodeStatus(a.session, "", time.Now().UTC()))
			_, current := a.call(t, wire.OperationAppNodeStatus, status)
			if current.Result == nil || current.Result.Authority.Scope.HeadVersion != a.scope.HeadVersion ||
				current.Result.Authority.CurrentHeadVersion != a.scope.HeadVersion || current.Result.Authority.GrantID != "" ||
				current.Result.Authority.LatestGrantID != "" || current.Result.Node != nil {
				t.Fatal("refused adversarial request left published authority or a Node observation")
			}
			prepare, original, challenge := a.prepare(t, target)
			defer clear(original)
			result := a.complete(t, prepare, original, challenge)
			if result.Authority.RemainingConfirmations != 1 || result.Node != nil {
				t.Fatal("refusal consumed the valid candidate or created a partial Node binding")
			}
			t.Logf("ACTUAL_N3 independent_server_refusal=true kind=%s real_PQ_frame_sha256=%s native_App_preflight_bypassed=true", kind, hash(packet))
		})
	}
}

func TestN3ServerRejectsForgedCompletionPreservingPreview(t *testing.T) {
	for _, kind := range []string{"missing-grant", "forged-grant", "wrong-owner-signature", "broader-operations", "head-substitution", "candidate-key-substitution", "missing-candidate-version"} {
		t.Run(kind, func(t *testing.T) {
			f := newNodeHubFixture(t)
			marker := filepath.Join(f.dir, "completion-account-ready.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			app.kill(t)
			a := newAuthorityWireActor(t, f)
			node := startNodeProcess(t, f, "synthetic-n3-completion-target")
			pending := node.awaitState(t, f, false)
			node.kill(t)
			prepare, original, challenge := a.prepare(t, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: pending.PendingCode})
			defer clear(original)
			request := must(wire.NewAppNodeComplete(a.session, prepare, original, challenge, a.owner, time.Now().UTC()))
			var proof e2ee.OwnerAppNodeGrant
			if json.Unmarshal(request.OwnerGrant, &proof) != nil || proof.Claims.Candidate == nil {
				t.Fatal("genuine completion fixture lacks its exact Node claims")
			}
			signer := a.owner
			switch kind {
			case "missing-grant":
				request.OwnerGrant = nil
			case "forged-grant":
				proof.Signature[0] ^= 1
				request.OwnerGrant = must(json.Marshal(proof))
			case "wrong-owner-signature":
				signer = must(e2ee.NewIdentity())
			case "broader-operations":
				proof.Claims.AllowedOperations = []string{"nodes.confirm", "status.snapshot"}
			case "head-substitution":
				proof.Claims.ExpectedHeadVersion++
				proof.Claims.Scope.HeadVersion++
			case "candidate-key-substitution":
				proof.Claims.Candidate.NodePublic = must(e2ee.NewIdentity()).Public()
				proof.Claims.Candidate.NodeKeyFingerprint = nodewire.IdentityFingerprint(proof.Claims.Candidate.NodePublic)
			case "missing-candidate-version":
				proof.Claims.Candidate.Version = 0
			}
			if kind != "missing-grant" && kind != "forged-grant" {
				request.OwnerGrant = adversarialOwnerGrant(t, signer, proof.Claims)
			}
			packet := rawAuthorityPacket(t, f, a.device, wire.OperationAppNodeComplete, request.Context, request)
			defer clear(packet)
			code, response := a.post(t, wire.AppNodeHTTPPath(wire.OperationAppNodeComplete), packet)
			defer clear(response)
			if code == 200 {
				opened := must(wire.OpenAppNodeResponse(a.device, f.cfg.Hub, packet, response))
				if opened.Result == nil || opened.Result.State != wire.AppNodeRejectedFenced {
					t.Fatal("forged/substituted finite completion activated authority")
				}
			} else if code != http.StatusBadRequest && code != http.StatusForbidden && code != http.StatusUnauthorized {
				t.Fatalf("completion negative reached an unavailable/error response, HTTP=%d", code)
			}
			status := must(wire.NewAppNodeStatus(a.session, challenge.Claims.GrantID, time.Now().UTC()))
			_, current := a.call(t, wire.OperationAppNodeStatus, status)
			if current.Result == nil || current.Result.Authority.State != wire.AppNodePrepared ||
				current.Result.Authority.CurrentHeadVersion != a.scope.HeadVersion || current.Result.Node != nil ||
				len(current.Result.Authority.AllowedOperations) != 0 {
				t.Fatal("refused completion left a partial published grant or Node binding")
			}
			result := a.complete(t, prepare, original, challenge)
			if result.Authority.RemainingConfirmations != 1 || result.Node != nil {
				t.Fatal("invalid completion consumed or substituted the valid original preview")
			}
			t.Logf("ACTUAL_N3 independent_completion_refusal=true kind=%s valid_preview_retained=true real_PQ_frame_sha256=%s", kind, hash(packet))
		})
	}
}
