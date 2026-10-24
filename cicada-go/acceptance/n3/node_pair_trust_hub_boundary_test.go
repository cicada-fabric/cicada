package n3_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// This is explicitly a Hub-side observation/adversary, with only its owned
// synthetic Hub TLS/CC keys. It is not the opaque fault peer and is never used
// as evidence of direct end-to-end Node -> Hub-binary TLS. NPT01/08/09 cover
// that separately. Every request still reaches the actual frozen Hub over a
// second normally verified TCP/TLS connection; no Doer or response stub is used.
type nodePairHubBoundary struct {
	server  *httptest.Server
	mu      sync.Mutex
	plain   [][]byte // Bounded private Hub-readable Node requests, never public evidence.
	seen    map[string]int
	invalid bool
	forged  int
	fake    bool
	owner   *e2ee.Identity // Synthetic self-invented attacker Owner only.
}

func newNodePairHubBoundary(t *testing.T, hub *directIPHub, fake bool) *nodePairHubBoundary {
	t.Helper()
	b := &nodePairHubBoundary{seen: make(map[string]int), fake: fake}
	if fake {
		b.owner = must(e2ee.NewIdentity())
	}
	rawKey := readPrivate(t, filepath.Join(hub.state, "e2ee", "client-control-identity.json"))
	cc := must(e2ee.UnmarshalIdentity(rawKey))
	clear(rawKey)
	profile := must(hubtransport.LoadProfile(hub.state, must(hubtransport.EncodeDescriptor(hub.descriptor))))
	client := must(hubtransport.NewHTTPClient(hub.descriptor, hub.address, 12*time.Second))
	t.Cleanup(client.CloseIdleConnections)
	// Hub-readable memory belongs only to this adversary and is cleared on
	// cleanup. It never receives the actual Node code, S or any Owner signer.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxNodePairTrustPacketBytes+1))
		defer clear(packet)
		if err != nil || len(packet) > wire.MaxNodePairTrustPacketBytes {
			b.mu.Lock()
			b.invalid = true
			b.mu.Unlock()
			http.Error(w, "owned boundary rejected", http.StatusBadRequest)
			return
		}
		op := ""
		for _, candidate := range wire.NodePairTrustContractCapabilities().Operations {
			if wire.NodePairTrustHTTPPath(candidate) == r.URL.Path {
				op = candidate
				break
			}
		}
		var body any
		if op != "" {
			body = wire.NewNodePairTrustRequestBody(op)
			_, err = wire.OpenNodePairTrustRequest(cc, hub.descriptor.Claims.Hub, packet, op, body, time.Now().UTC())
			if err == nil {
				plain := mustBoundaryJSON(body)
				b.mu.Lock()
				if len(b.plain) < 128 && len(plain) <= wire.MaxNodePairTrustBodyBytes {
					b.plain = append(b.plain, plain)
				} else {
					clear(plain)
					b.invalid = true
				}
				b.seen[op]++
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" {
					b.invalid = true
				}
				b.mu.Unlock()
			}
			if err != nil {
				b.mu.Lock()
				b.invalid = true
				b.mu.Unlock()
				http.Error(w, "owned boundary rejected", http.StatusBadRequest)
				return
			}
		} else {
			metadata := r.URL.Path == wire.NodePairTrustDescriptorPath || r.URL.Path == wire.NodePairTrustCapabilitiesPath
			invalid := metadata && (r.Method != http.MethodGet || len(packet) != 0 || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "")
			if !metadata {
				// Ordinary credential/business traffic is forbidden until the
				// actual original attempt has committed ACK, even with valid TLS.
				db, e := nodePairBoundaryDB(hub)
				var admitted int
				if e == nil {
					e = db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_v1 WHERE node_id=? AND state=?`, "synthetic-n3-node-pair", wire.NodePairTrustACKed).Scan(&admitted)
					db.Close()
				}
				invalid = e != nil || admitted != 1
			}
			if invalid {
				b.mu.Lock()
				b.invalid = true
				b.mu.Unlock()
				http.Error(w, "owned pretrust boundary rejected", http.StatusForbidden)
				return
			}
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, hub.material.Origin+r.URL.RequestURI(), bytes.NewReader(packet))
		if err != nil {
			http.Error(w, "owned boundary unavailable", http.StatusBadGateway)
			return
		}
		request.Header = r.Header.Clone()
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "owned boundary unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		out, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxNodePairTrustResponsePacketBytes+1))
		defer func() { clear(out) }()
		if err != nil || len(out) > wire.MaxNodePairTrustResponsePacketBytes {
			http.Error(w, "owned boundary unavailable", http.StatusBadGateway)
			return
		}
		if b.fake && op == wire.OperationNodePairTrustPoll && response.StatusCode == http.StatusOK {
			// This Hub knows C/O and the public real approval, but never S. A
			// purpose-valid fake Owner proof with a random different S is its
			// strongest self-consistent replacement. No Owner key is obtained.
			var q wire.NodePairTrustPoll
			if encoded, e := json.Marshal(body); e == nil && json.Unmarshal(encoded, &q) == nil {
				db, e := nodePairBoundaryDB(hub)
				if e == nil {
					var record []byte
					e = db.QueryRow(`SELECT record_json FROM hub_node_pair_trust_v1 WHERE attempt_id=? AND state=?`, q.Context.AttemptID, wire.NodePairTrustOwnerApproved).Scan(&record)
					db.Close()
					if e == nil {
						var saved struct {
							Approval *wire.NodePairTrustApproval `json:"approval"`
						}
						if json.Unmarshal(record, &saved) == nil && saved.Approval != nil {
							approval := *saved.Approval
							approval.Scope.OwnerPublic = b.owner.Public()
							proof, capsule, e := nodePairInventOwner(b.owner, q.Context, q.OOBCommitment, approval)
							if e == nil {
								var h wire.NodePairTrustPacket
								if json.Unmarshal(packet, &h) == nil {
									forged := wire.NodePairTrustResult{Format: wire.NodePairTrustFormat, Operation: op, RequestID: h.RequestID, AttemptID: h.AttemptID,
										RequestPacketDigest: wire.NodePairTrustPacketDigest(packet), State: wire.NodePairTrustOwnerApproved, Context: &q.Context,
										OOBCommitment: q.OOBCommitment, OwnerProof: proof, TrustCapsule: capsule, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
									if replacement, e := wire.SealNodePairTrustResponse(cc, hub.descriptor.Claims.Hub, packet, body, forged); e == nil {
										clear(out)
										out = replacement
										b.mu.Lock()
										b.forged++
										b.mu.Unlock()
									}
								}
							}
							clear(proof)
							clear(capsule)
						}
						clear(record)
					}
				}
			}
		}
		if contentType := response.Header.Get("Content-Type"); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(out)
	})
	b.server = httptest.NewUnstartedServer(handler)
	b.server.TLS = profile.TLSConfig()
	b.server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return profile.TLSConfig(), nil }
	b.server.StartTLS()
	t.Cleanup(func() {
		b.server.Close()
		for _, plain := range b.plain {
			clear(plain)
		}
	})
	return b
}

// Handler helpers return ordinary errors, never testing.Fatal in a worker.
func mustBoundaryJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

func nodePairBoundaryDB(hub *directIPHub) (*sql.DB, error) {
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(hub.state, "cicada.sqlite3"), RawQuery: "mode=ro"}).String()
	return sql.Open("sqlite", uri)
}

func nodePairInventOwner(owner *e2ee.Identity, c wire.NodePairTrustContext, o string, a wire.NodePairTrustApproval) ([]byte, []byte, error) {
	secret, err := wire.NewNonce()
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	x, err := wire.NewNonce()
	if err != nil {
		return nil, nil, err
	}
	defer clear(x)
	digest, err := wire.NodePairTrustApprovalDigest(a)
	if err != nil {
		return nil, nil, err
	}
	d, err := hex.DecodeString(digest)
	if err != nil {
		return nil, nil, err
	}
	plain, err := json.Marshal(wire.NodePairTrustCapsule{Format: wire.NodePairTrustFormat, Approval: a, OwnerPublic: owner.Public(), OOBSecret: secret, ACKNonce: x})
	if err != nil {
		return nil, nil, err
	}
	defer clear(plain)
	capsule, err := e2ee.Seal(owner, c.Candidate.NodePublic, plain, append([]byte("cicada/node-pair-trust/capsule-aad/v1\x00"), d...), 1)
	if err != nil {
		return nil, nil, err
	}
	ack, err := wire.NodePairTrustACKCommitment(a, x)
	if err != nil {
		return nil, nil, err
	}
	claims := wire.NodePairTrustOwnerClaims{Version: 1, Purpose: wire.NodePairTrustOwnerPurpose, Approval: a, CapsuleDigest: wire.NodePairTrustCapsuleDigest(capsule), ACKCommitment: ack}
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.New()
	h.Write([]byte("cicada/node-pair-trust/owner-claims/v1\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(raw)))
	h.Write(length[:])
	h.Write(raw)
	var commitment [32]byte
	copy(commitment[:], h.Sum(nil))
	signature, err := e2ee.SignNodePairTrustOwner(owner, commitment)
	if err != nil {
		return nil, nil, err
	}
	proof, err := json.Marshal(wire.NodePairTrustOwnerProof{Claims: claims, Signature: signature})
	if err != nil {
		return nil, nil, err
	}
	if _, err = wire.VerifyNodePairTrustOwnerProof(owner.Public(), c, o, proof, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	return proof, capsule, nil
}

func nodePairSecretNeverUploaded(t *testing.T) {
	var boundary *nodePairHubBoundary
	v := newNodePairFixtureWithBoundary(t, "127.0.0.1", func(v *nodePairFixture) string {
		boundary = newNodePairHubBoundary(t, v.hub, false)
		return boundary.server.Listener.Addr().String()
	})
	lowered := strings.ToLower(v.code)
	if lowered == v.code {
		t.Fatal("case-preservation control unexpectedly did not change the actual code")
	}
	before := v.admission(t)
	wrong := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionReviewNodePairing, DevicePairingCode: lowered}})
	if !wrong.ActionFailed || v.admission(t) != before {
		t.Fatal("actual App normalized the complete secret code as a case-insensitive old selector")
	}
	c, _ := v.side(t)
	if must(wire.EncodeNodePairTrustCode(c, v.local.Selector, v.local.OOBSecret)) != v.code {
		t.Fatal("actual TTY pairing code was truncated or changed during local transfer")
	}
	review := v.review(t)
	nodePairAuditAppPlain(t, v)
	v.action(t, appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: review.Node.Pairing.ReviewID, ConfirmNodePairing: true})
	nodePairAuditAppPlain(t, v)
	v.awaitACK(t)
	nodePairAuditAppPlain(t, v)
	v.node.kill(t)
	v.app.command(t, directIPAppCommand{Close: true})
	boundary.server.Close()
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.invalid || boundary.forged != 0 {
		t.Fatal("actual pretrust Node escaped the closed credential-free packet family")
	}
	for _, operation := range []string{wire.OperationNodePairTrustStart, wire.OperationNodePairTrustCommit, wire.OperationNodePairTrustPoll, wire.OperationNodePairTrustACK} {
		if boundary.seen[operation] == 0 {
			t.Fatal("Hub-readable secret audit missed an actual Node ceremony operation")
		}
	}
	for _, raw := range boundary.plain {
		if nodePairContainsSecret(raw, v.code, v.local.OOBSecret) {
			t.Fatal("actual Hub-readable Node request disclosed the retained local secret")
		}
	}
	log := readPrivate(t, filepath.Join(v.state, "private-process.log"))
	defer clear(log)
	if nodePairContainsSecret(log, v.code, v.local.OOBSecret) || nodePairContainsSecret(must(json.Marshal(wrong.Snapshot)), v.code, v.local.OOBSecret) {
		t.Fatal("actual Node/App diagnostics disclosed a complete pairing code or S")
	}
	nodePairFacts(t, "NPT02_SecretNeverUploaded", map[string]bool{"Hub_plaintexts_without_S": true,
		"no_pretrust_bearer": true, "no_S_in_snapshots_or_diagnostics": true, "complete_case_preserving_code": true})
}

func nodePairAuditAppPlain(t *testing.T, v *nodePairFixture) {
	t.Helper()
	saved := v.copiedAppState(t)
	defer saved.clear()
	p := saved.PairTrust.Pending
	if p == nil || len(p.Request) == 0 {
		t.Fatal("Hub plaintext audit missed the actual original App packet")
	}
	body := wire.NewNodePairTrustRequestBody(p.Operation)
	if body == nil {
		t.Fatal("Hub plaintext audit found an unreviewed App operation")
	}
	raw := readPrivate(t, filepath.Join(v.hub.state, "e2ee", "client-control-identity.json"))
	cc := must(e2ee.UnmarshalIdentity(raw))
	clear(raw)
	if _, err := wire.OpenNodePairTrustRequest(cc, v.hub.descriptor.Claims.Hub, p.Request, p.Operation, body, time.Now().UTC()); err != nil {
		t.Fatal("actual Hub CC key could not authenticate the original App packet")
	}
	plain := must(json.Marshal(body))
	defer clear(plain)
	if nodePairContainsSecret(plain, v.code, v.local.OOBSecret) || nodePairContainsSecret(p.Body, v.code, v.local.OOBSecret) {
		t.Fatal("actual Hub-readable App request disclosed a full secret code or S outside the Owner-to-Node capsule")
	}
}

func nodePairFakeHubOwnerRefused(t *testing.T) {
	var boundary *nodePairHubBoundary
	v := newNodePairFixtureWithBoundary(t, "127.0.0.1", func(v *nodePairFixture) string {
		boundary = newNodePairHubBoundary(t, v.hub, true)
		return boundary.server.Listener.Addr().String()
	})
	v.approve(t)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		boundary.mu.Lock()
		forged := boundary.forged
		boundary.mu.Unlock()
		if forged > 0 {
			break
		}
		if !v.node.running() {
			t.Fatal("actual Node stopped before receiving the purpose-valid self-invented Owner")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if v.node.running() {
		v.node.kill(t)
	}
	boundary.server.Close()
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.invalid || boundary.forged == 0 || boundary.seen[wire.OperationNodePairTrustACK] != 0 {
		t.Fatal("actual Node ACKed an invented Owner or the adversary never delivered its valid forged proof")
	}
	for _, raw := range boundary.plain {
		if nodePairContainsSecret(raw, v.code, v.local.OOBSecret) {
			t.Fatal("a false Hub obtained S from the actual Node")
		}
	}
	a := v.admission(t)
	if a.state != wire.NodePairTrustOwnerApproved || a.ownerBindings != 0 || a.keyBindings != 0 || a.remaining != 1 {
		t.Fatal("false Hub/Owner caused an admission despite missing the independent local S")
	}
	log := readPrivate(t, filepath.Join(v.state, "private-process.log"))
	defer clear(log)
	if !bytes.Contains(log, []byte("NODE_PAIR_INDEPENDENT_TRUST_REJECTED")) || nodePairContainsSecret(log, v.code, v.local.OOBSecret) {
		t.Fatal("actual Node did not reach the independent first-trust capsule check or disclosed the local secret")
	}
	path := filepath.Join(v.state, "nodes", "node-"+v.node.id, "node-crypto-state.sqlite")
	var pins int
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		db := nodePairReadOnlyDB(t, path)
		if db.QueryRow(`SELECT count(*) FROM node_crypto_owner_key_trust`).Scan(&pins) != nil || pins != 0 {
			t.Fatal("actual Node pinned a self-consistent but independently untrusted Owner")
		}
	}
	nodePairFacts(t, "NPT03_FakeHubOwnerRefused", map[string]bool{"self_consistent_fake_Hub_Owner": true,
		"local_S_required": true, "zero_new_pin_or_binding": true, "zero_secrets_disclosed": true})
}
