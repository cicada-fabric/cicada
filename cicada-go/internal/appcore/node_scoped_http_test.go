//go:build cicada_scoped_app_integration

package appcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// A disposable real TLS Hub and real App core. Node actors use the frozen SDK
// with independent private keys; this is not a native Node or Runtime test.
// Only the Hub's explicit test constructor opens the scoped carrier.
type scopedAppHTTPFixture struct {
	t                                  *testing.T
	c                                  *nativeController
	db                                 *store.Store
	hub                                wire.HubIdentity
	descriptor                         hubtransport.Descriptor
	client                             *http.Client
	http                               *httptest.Server
	root, origin, dial, descriptorText string
	posts                              map[string]int
	dropOperation                      string
	dropHTTPStatus                     int
	droppedPacket                      []byte
	nextPost                           time.Time
	falseCapabilityPath                string
}

func newScopedAppHTTPFixture(t *testing.T) *scopedAppHTTPFixture {
	t.Helper()
	return newScopedAppHTTPFixtureMode(t, true)
}

func newScopedAppHTTPFixtureMode(t *testing.T, scoped bool) *scopedAppHTTPFixture {
	t.Helper()
	f := &scopedAppHTTPFixture{t: t, root: t.TempDir(), posts: map[string]int{}}
	var err error
	f.db, err = store.New(filepath.Join(f.root, "SYNTHETIC-hub.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.c != nil {
			_ = f.c.Close()
		}
		if f.client != nil {
			f.client.CloseIdleConnections()
		}
		if f.http != nil {
			f.http.Close()
		}
		_ = f.db.Close()
	})
	id, err := f.db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	f.origin, err = hubtransport.DefaultOrigin(id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.db.InitializeHubOwnerLocal("SYNTHETIC scoped App Owner", f.origin, false)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(f.root, "SYNTHETIC-hub-keys")
	ids, err := hubidentity.LoadOrCreate(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := hubowner.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	var auth *hubauth.Service
	if scoped {
		auth, err = hubauth.NewServiceWithScopedNodeAuthority(f.db, ids)
	} else {
		auth, err = hubauth.NewServiceWithNodeAuthority(f.db, ids)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.hub, err = auth.HubIdentity()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := hubtransport.InitializeProfile(stateDir, ids.ClientControl, f.hub, ids.NodeControl.Public(), f.origin, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.BindHubNativeTLSLocal(profile.DescriptorText()); err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	f.http = httptest.NewUnstartedServer(server.NewHubNodesHandler(owner, auth, nodes))
	f.http.TLS = profile.TLSConfig()
	f.http.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return profile.TLSConfig(), nil }
	f.http.StartTLS()
	f.dial = f.http.Listener.Addr().String()
	candidate, err := hubtransport.DiscoverCandidate(context.Background(), f.dial)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.DescriptorText != profile.DescriptorText() {
		t.Fatal("independent descriptor discovery changed")
	}
	f.descriptor, f.descriptorText = candidate.Descriptor, candidate.DescriptorText
	f.client, err = hubtransport.NewHTTPClient(f.descriptor, f.dial, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.open()
	material, err := auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := wire.EncodeActivationCode(*material)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := hubtransport.EncodeBootstrap(f.descriptor, activation)
	if err != nil {
		t.Fatal(err)
	}
	f.dispatch(Action{Kind: ActionConnect, HubAddress: f.dial, BootstrapCode: bootstrap})
	f.dispatch(Action{Kind: ActionGenerateOwner})
	f.dispatch(Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-scoped-app", Password: n2SyntheticPassword})
	f.dispatch(Action{Kind: ActionLogin, Username: "synthetic-scoped-app", Password: n2SyntheticPassword})
	if f.c.nodeConfirmation != nil || len(f.c.localTargets().Nodes) != 0 {
		t.Fatal("fixture acquired legacy Node authority")
	}
	return f
}

func (f *scopedAppHTTPFixture) open() {
	f.t.Helper()
	root := filepath.Join(f.root, "SYNTHETIC-app-vault")
	controller, err := NewController(Config{OpenVault: fixtureVaultOpener(root, "SYNTHETIC scoped vault passphrase"), DiscoverVaults: NewProfileDiscovery(root), DirectHTTPFactory: func(d hubtransport.Descriptor, dial string, timeout time.Duration) (HTTPDoer, error) {
		client, err := hubtransport.NewHTTPClient(d, dial, timeout)
		if err != nil {
			return nil, err
		}
		return &scopedAppHTTPProbe{f: f, client: client}, nil
	}})
	if err != nil {
		f.t.Fatal(err)
	}
	f.c = controller.(*nativeController)
}

type scopedAppHTTPProbe struct {
	f      *scopedAppHTTPFixture
	client *http.Client
}

// Preserve the actual Hub's four-per-second admission limit. This transport
// fixture paces first sends; it never retries or replaces an uncertain packet.
func (f *scopedAppHTTPFixture) pace(ctx context.Context) error {
	if delay := time.Until(f.nextPost); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.nextPost = time.Now().Add(300 * time.Millisecond)
	return nil
}

func (p *scopedAppHTTPProbe) CloseIdleConnections() { p.client.CloseIdleConnections() }
func (p *scopedAppHTTPProbe) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		response, err := p.client.Do(req)
		if err == nil && req.URL.Path == p.f.falseCapabilityPath {
			raw, e := io.ReadAll(io.LimitReader(response.Body, 16385))
			_ = response.Body.Close()
			var metadata map[string]any
			if e != nil || len(raw) > 16384 || json.Unmarshal(raw, &metadata) != nil {
				p.f.t.Fatal("synthetic public discovery fault setup", e)
			}
			metadata["available"] = false
			raw, e = json.Marshal(metadata)
			if e != nil {
				p.f.t.Fatal(e)
			}
			response.Body = io.NopCloser(bytes.NewReader(raw))
		}
		return response, err
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(raw))
	p.f.posts[req.URL.Path]++
	if bytes.Contains([]byte(req.URL.Path), []byte("scoped/")) {
		original := p.f.c.scoped.original
		if original != nil && !original.Applied && bytes.Equal(original.Packet, raw) {
			saved, _, found, e := p.f.c.vault.LoadState(scopedWorkspaces[scopedOriginalSlot])
			defer clear(saved)
			stored, de := decodeScopedOriginal(saved)
			if e != nil || de != nil || !found || !bytes.Equal(stored.Packet, raw) {
				p.f.t.Fatal("scoped HTTP preceded exact original persistence")
			}
		}
	}
	if err := p.f.pace(req.Context()); err != nil {
		return nil, err
	}
	response, err := p.client.Do(req)
	if err == nil && response.StatusCode != http.StatusOK {
		p.f.t.Logf("synthetic App HTTP path=%s status=%d", req.URL.Path, response.StatusCode)
	}
	if err == nil && p.f.dropOperation != "" && req.URL.Path == p.f.dropOperation {
		p.f.dropOperation = ""
		p.f.droppedPacket = bytes.Clone(raw)
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if p.f.dropHTTPStatus != 0 {
			response.StatusCode = p.f.dropHTTPStatus
			response.Body = io.NopCloser(bytes.NewBufferString(`{"error":"SYNTHETIC unauthenticated refusal"}`))
			p.f.dropHTTPStatus = 0
			return response, nil
		}
		return nil, io.ErrUnexpectedEOF
	}
	return response, err
}

func (f *scopedAppHTTPFixture) dispatch(a Action) {
	f.t.Helper()
	if err := f.c.Dispatch(context.Background(), a); err != nil {
		s := f.c.Snapshot()
		if f.c.scoped.errorCode == "APP_NODE_PAIRING_STORAGE_FULL" && f.c.scoped.flow != nil && f.c.scoped.flow.Context != nil {
			flow := f.c.scoped.flow
			q := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: f.c.session.SessionToken, Scope: flow.Scope, Context: *flow.Context, OOBCommitment: flow.OOB, IssuedAt: f.c.scopedNow()}
			probe, e := f.c.newScopedOriginal(q, flow.NodeID, true)
			if e == nil {
				u, e := f.c.scopedBudgetUpdates(probe)
				f.t.Logf("synthetic budget projection err=%v", e)
				if e == nil {
					f.t.Logf("synthetic complete vault projection=%v", f.c.vault.CheckStateUpdates(u))
					f.t.Logf("synthetic vault encoded current=%d projected=%d", f.encodedVaultLength(nil), f.encodedVaultLength(u))
					names := []string{appStateNamespace, appSessionNamespace, nodeStateNamespace, nodeRecoveryNamespace, nodeConfirmationNamespace}
					names = append(names, pairNamespaces[:]...)
					names = append(names, localDomainNamespaces[:]...)
					names = append(names, threadGroupNamespaces[:]...)
					for id := range f.c.scoped.nodes {
						names = append(names, scopedNodeNamespace(id))
					}
					for _, name := range names {
						if _, updated := u[name]; !updated {
							raw, _, found, _ := f.c.vault.LoadState(name)
							if found && len(raw) > 0 {
								f.t.Logf("synthetic retained namespace=%s bytes=%d", name, len(raw))
							}
							clear(raw)
						}
					}
					for name, raw := range u {
						f.t.Logf("synthetic budget namespace=%s bytes=%d", name, len(raw))
						clear(raw)
					}
				}
			}
		}
		if p := f.c.scoped.original; p != nil {
			stage := "none"
			if f.c.scoped.flow != nil {
				stage = f.c.scoped.flow.Stage
			}
			f.t.Logf("synthetic scoped original op=%s applied=%v receiptBytes=%d flowStage=%s", p.Operation, p.Applied, len(p.Response), stage)
			if !p.PairTrust && len(p.Response) != 0 {
				device, _ := f.c.device.E2EE()
				r, opened := wire.OpenAppNodeScopedResponse(device, f.hub, p.Packet, p.Response)
				if r.Result != nil {
					f.t.Logf("synthetic authority open=%v state=%s authority=%s identityMatch=%v sessionMatch=%v counters=%+v localCounters=%+v", opened, r.Result.State, r.Result.Authority.State, f.c.scopedScopeMatches(r.Result.Authority.Scope, false), f.c.scopedSessionLeafMatches(r.Result.Authority.Scope), r.Result.Authority.Counters, f.c.node.Client)
				}
				if r.Challenge != nil && f.c.scoped.flow != nil && f.c.scoped.flow.Context != nil {
					f.t.Logf("synthetic prepare open=%v candidateMatch=%v", opened, reflect.DeepEqual(r.Challenge.Claims.Candidate, f.c.scoped.flow.Context.Candidate))
				}
			}
		}
		f.t.Fatalf("actual scoped Core %s: %v (App=%s Node=%s scoped=%s local=%s)", a.Kind, err, s.ErrorCode, s.Node.ErrorCode, f.c.scoped.errorCode, s.LocalCollaboration.ErrorCode)
	}
}

// Reproduce encodePayload's JSON shape with zero bytes of the same lengths.
// Only lengths are returned/logged; actual private keys never enter a report.
func (f *scopedAppHTTPFixture) encodedVaultLength(updates map[string][]byte) int {
	f.t.Helper()
	type entry struct {
		Purpose appvault.Purpose `json:"purpose"`
		KeyID   string           `json:"key_id"`
		Private []byte           `json:"private_identity"`
	}
	type state struct {
		Namespace string `json:"namespace"`
		Version   uint64 `json:"version"`
		Payload   []byte `json:"payload"`
	}
	payload := struct {
		Version int     `json:"version"`
		Entries []entry `json:"entries"`
		States  []state `json:"states"`
	}{Version: 1}
	for purpose, identity := range map[appvault.Purpose]*appkeys.Identity{appvault.PurposeAppDevice: f.c.device, appvault.PurposeOwnerSigner: f.c.owner} {
		raw, err := identity.MarshalBinary()
		if err != nil {
			f.t.Fatal(err)
		}
		length := len(raw)
		clear(raw)
		payload.Entries = append(payload.Entries, entry{Purpose: purpose, KeyID: identity.Public().ID, Private: make([]byte, length)})
		f.t.Logf("synthetic private-key serialized purpose=%s bytes=%d", purpose, length)
	}
	names := []string{appStateNamespace, appSessionNamespace, nodeStateNamespace, nodeRecoveryNamespace, nodeConfirmationNamespace}
	names = append(names, pairNamespaces[:]...)
	names = append(names, localDomainNamespaces[:]...)
	names = append(names, threadGroupNamespaces[:]...)
	names = append(names, scopedWorkspaces[:]...)
	for id := range f.c.scoped.nodes {
		names = append(names, scopedNodeNamespace(id))
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		raw, version, found, err := f.c.vault.LoadState(name)
		if err != nil {
			f.t.Fatal(err)
		}
		length := len(raw)
		clear(raw)
		if next, updating := updates[name]; updating {
			found = true
			length = len(next)
			if version == 0 {
				version = 1
			}
		}
		if found {
			var opaque []byte
			if length > 0 {
				opaque = make([]byte, length)
			}
			payload.States = append(payload.States, state{Namespace: name, Version: version, Payload: opaque})
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	length := len(raw)
	clear(raw)
	for _, e := range payload.Entries {
		clear(e.Private)
	}
	for _, s := range payload.States {
		clear(s.Payload)
	}
	return length
}

type scopedAppNodeActor struct {
	key                       *e2ee.Identity
	token, attempt, code, oob string
	secret                    []byte
	context                   wire.NodePairTrustScopedContext
	binding                   *e2ee.OwnerAppNodeBinding
}

func (f *scopedAppHTTPFixture) nodeRequest(n *scopedAppNodeActor, operation string, body any) (wire.NodePairTrustScopedResult, []byte, []byte) {
	f.t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		f.t.Fatal(err)
	}
	packet, err := wire.SealNodePairTrustScopedRequest(n.key, f.hub, wire.NodePairTrustScopedPacket{Operation: operation, RequestID: id, AttemptID: n.attempt}, body, time.Now().UTC())
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.origin+wire.NodePairTrustScopedHTTPPath(operation), bytes.NewReader(packet))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.origin)
	if err := f.pace(req.Context()); err != nil {
		f.t.Fatal(err)
	}
	response, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxNodePairTrustScopedResponsePacketBytes+1))
	if err != nil || response.StatusCode != 200 {
		f.t.Fatal("actual Node scoped HTTP", operation, response.StatusCode, err)
	}
	result, err := wire.OpenNodePairTrustScopedResponse(n.key, f.hub, packet, raw, body)
	if err != nil {
		f.t.Fatal("actual Node receipt", operation, err)
	}
	return result, packet, raw
}

func (f *scopedAppHTTPFixture) startNode(id string) *scopedAppNodeActor {
	f.t.Helper()
	n := new(scopedAppNodeActor)
	var err error
	n.key, err = e2ee.NewIdentity()
	if err != nil {
		f.t.Fatal(err)
	}
	var digest string
	n.token, digest, err = fabric.NewNodeCredential()
	if err != nil {
		f.t.Fatal(err)
	}
	n.attempt, err = wire.NewRequestID()
	if err != nil {
		f.t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	start := wire.NodePairTrustScopedStart{ScopeVersion: 2, Format: wire.NodePairTrustScopedFormat, Hub: f.hub, Origin: f.origin, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(f.descriptorText), NodeID: id, NodeName: "SYNTHETIC " + id, CredentialDigest: digest, RequestNonce: nonce, HubNodeControlPublic: f.descriptor.Claims.NodeControl, HubNodeControlKeyVersion: 1, IssuedAt: stamp, ExpiresAt: now.Add(9 * time.Minute).Format(time.RFC3339Nano)}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: id, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: n.key.Public(), HubPublicIdentity: start.HubNodeControlPublic, HubKeyVersion: 1})
	if err != nil {
		f.t.Fatal(err)
	}
	start.PairingProof, err = e2ee.Seal(n.key, start.HubNodeControlPublic, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		f.t.Fatal(err)
	}
	started, _, _ := f.nodeRequest(n, wire.OperationNodePairTrustScopedStart, start)
	if started.Context == nil || started.Context.AuthorityNodeID != id {
		f.t.Fatal("actual scoped Node context absent")
	}
	n.context = *started.Context
	n.secret, err = wire.NewNonce()
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { clear(n.secret) })
	n.code, err = wire.EncodeNodePairTrustScopedCode(n.context, started.Selector, n.secret)
	if err != nil {
		f.t.Fatal(err)
	}
	code, err := wire.DecodeNodePairTrustScopedCode(n.code, time.Now().UTC())
	if err != nil {
		f.t.Fatal(err)
	}
	defer clear(code.OOBSecret)
	n.oob, err = wire.MatchNodePairTrustScopedCode(code, n.context, f.hub, start.HubNodeControlPublic, f.origin, start.DescriptorDigest, time.Now().UTC())
	if err != nil {
		f.t.Fatal(err)
	}
	f.nodeRequest(n, wire.OperationNodePairTrustScopedCommit, wire.NodePairTrustScopedCommit{Format: wire.NodePairTrustScopedFormat, Context: n.context, OOBCommitment: n.oob, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	return n
}

func (f *scopedAppHTTPFixture) approveNode(n *scopedAppNodeActor) {
	f.t.Helper()
	f.dispatch(Action{Kind: ActionReviewNodePairing, DevicePairingCode: n.code})
	p := f.c.Snapshot().Node.Pairing
	if p == nil || p.State != "REVIEW" || p.ReviewID == "" {
		f.t.Fatal("exact App review absent")
	}
	f.dispatch(Action{Kind: ActionApproveNodePairing, NodePairingReviewID: p.ReviewID, ConfirmNodePairing: true})
	if f.c.scoped.flow.Stage != wire.NodePairTrustScopedOwnerApproved {
		f.t.Fatal("actual Owner proof not settled")
	}
	if b := f.c.selectedNodeBinding(); b != nil && b.NodeID == n.context.AuthorityNodeID {
		f.t.Fatal("Owner completion installed without private Node ACK")
	}
}

func (f *scopedAppHTTPFixture) ackNode(n *scopedAppNodeActor) {
	f.t.Helper()
	poll := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: n.context, OOBCommitment: n.oob, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	polled, packet, receipt := f.nodeRequest(n, wire.OperationNodePairTrustScopedPoll, poll)
	opened, err := wire.OpenNodePairTrustScopedCapsule(n.key, n.context, n.oob, polled.OwnerProof, polled.TrustCapsule, n.secret, time.Now().UTC())
	if err != nil {
		f.t.Fatal(err)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	ack := wire.NodePairTrustScopedACK{Format: wire.NodePairTrustScopedFormat, Context: n.context, OOBCommitment: n.oob, PollPacketDigest: wire.NodePairTrustScopedPacketDigest(packet), PollReceiptDigest: wire.NodePairTrustScopedPacketDigest(receipt), OwnerProofDigest: wire.NodePairTrustScopedProofDigest(polled.OwnerProof), CapsuleDigest: wire.NodePairTrustScopedCapsuleDigest(polled.TrustCapsule), ACKNonce: opened.ACKNonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	acked, _, _ := f.nodeRequest(n, wire.OperationNodePairTrustScopedACK, ack)
	if acked.State != wire.NodePairTrustScopedACKed || acked.Binding == nil {
		f.t.Fatal("original Node private ACK not settled")
	}
	n.binding = acked.Binding
}

func (f *scopedAppHTTPFixture) reportNodeUser(n *scopedAppNodeActor) {
	f.t.Helper()
	b := n.binding
	nonce, err := wire.NewNonce()
	if err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().UTC()
	report := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: b.HubID, NodeID: b.NodeID, OwnerBindingID: b.OwnerBindingID, NodeKeyEpoch: b.NodeKeyEpoch, LocalUserScope: "uid:1000", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	proof, err := e2ee.SignLocalDomainUserReport(n.key, report)
	if err != nil {
		f.t.Fatal(err)
	}
	binding := nodewire.Binding{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyVersion: b.HubNodeControlKeyVersion, NodeKeyVersion: b.NodeKeyVersion, NodeKey: b.NodePublic, HubKey: b.HubNodeControlPublic}
	id, err := wire.NewRequestID()
	if err != nil {
		f.t.Fatal(err)
	}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: 1, OperationID: id, Operation: wire.OperationLocalDomainNodeAvailable, SenderKeyID: binding.NodeKey.ID, SenderKeyVersion: binding.NodeKeyVersion, ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	body, err := json.Marshal(wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: report.LocalUserScope, LocalUserReport: proof})
	if err != nil {
		f.t.Fatal(err)
	}
	packet, err := nodewire.SealRequest(n.key, binding.HubKey, binding, route, body)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.origin+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.origin)
	req.Header.Set("Authorization", "CicadaNode "+n.token)
	response, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 {
		f.t.Fatal("actual Node user report HTTP", response.StatusCode, err)
	}
	opened, err := nodewire.OpenResponse(n.key, binding.HubKey, binding, raw)
	if err != nil {
		f.t.Fatal(err)
	}
	want := route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	var result struct {
		OK        bool   `json:"ok"`
		ErrorCode string `json:"error_code"`
	}
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &result) != nil || !result.OK {
		f.t.Fatal("actual Node user report verification", result.ErrorCode)
	}
}

func TestScopedAppRealTLSFreshNodesSwitchAndExistingNetwork(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	ownerID, deviceID := f.c.state.OwnerKeyID, f.c.state.DeviceKeyID
	a := f.startNode("SYNTHETIC-App-A")
	f.approveNode(a)
	f.ackNode(a)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if f.c.Snapshot().Targets.SelectedNodeID != a.binding.NodeID || f.c.nodeConfirmation != nil || f.c.scopedBusy() {
		t.Fatal("fresh scoped A did not install and settle")
	}
	first := f.c.scopedNode(a.binding.NodeID)
	firstProvenance, firstHead := first.ProvenanceID, first.HighestHead
	firstConfirmation := bytes.Clone(first.Confirmation.Response)
	if firstProvenance == "" || firstHead != 1 || f.c.node.Client.NextRequest != 2 || f.c.node.Client.NextResponse != 2 {
		t.Fatal("first scoped Node authority/counters")
	}
	f.reportNodeUser(a)
	f.dispatch(Action{Kind: ActionRefreshLocalCollaboration})
	f.dispatch(Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: "SYNTHETIC shared Network", GroupName: "SYNTHETIC A default"}})
	f.dispatch(Action{Kind: ActionActivateLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ReviewID: f.c.Snapshot().LocalCollaboration.ReviewID, ConfirmActivation: true}})
	locations := f.c.Snapshot().Targets.Networks
	if len(locations) != 1 {
		t.Fatal("settled authenticated Network was not offered")
	}
	networkID := locations[0].NetworkID
	firstGroupID := f.c.Snapshot().LocalCollaboration.GroupID
	f.dispatch(Action{Kind: ActionBeginAddNode})
	b := f.startNode("SYNTHETIC-App-B")
	f.approveNode(b)
	f.ackNode(b)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	second := f.c.scopedNode(b.binding.NodeID)
	if second == nil || second.ProvenanceID == "" || second.ProvenanceID == firstProvenance || second.HighestHead != 1 || f.c.node.Client.NextRequest != 3 || f.c.node.Client.NextResponse != 3 {
		t.Fatal("second scoped Node overwrote/copy-reset authority/counters")
	}
	if first.ProvenanceID != firstProvenance || first.HighestHead != firstHead || !bytes.Equal(first.Confirmation.Response, firstConfirmation) {
		t.Fatal("A immutable provenance/confirmation was overwritten")
	}
	if f.c.state.OwnerKeyID != ownerID || f.c.state.DeviceKeyID != deviceID {
		t.Fatal("multi-Node changed Owner/App identities")
	}
	f.reportNodeUser(b)
	f.dispatch(Action{Kind: ActionRefreshLocalCollaboration})
	f.dispatch(Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NetworkID: networkID, GroupName: "SYNTHETIC B default"}})
	f.dispatch(Action{Kind: ActionActivateLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ReviewID: f.c.Snapshot().LocalCollaboration.ReviewID, ConfirmActivation: true}})
	if f.c.Snapshot().LocalCollaboration.NetworkID != networkID {
		t.Fatal("B created a different Network")
	}
	if firstGroupID == "" || f.c.Snapshot().LocalCollaboration.GroupID == "" || f.c.Snapshot().LocalCollaboration.GroupID == firstGroupID {
		t.Fatal("same Network merged independent Node default Groups")
	}
	if !f.c.Snapshot().ThreadGroups.Available {
		t.Fatal("actual Hub Group discovery was not available")
	}
	f.dispatch(Action{Kind: ActionReadThreadGroups, ThreadGroups: ThreadGroupAction{GestureID: f.c.Snapshot().ThreadGroups.GestureID}})
	f.dispatch(Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: f.c.Snapshot().ThreadGroups.GestureID, Change: "CREATE_GROUP", Name: "SYNTHETIC scoped Owner Group"}})
	review := f.c.Snapshot().ThreadGroups.Review
	if review == nil || review.NodeID != b.binding.NodeID || review.NetworkID != networkID || !f.c.Snapshot().Targets.Locked {
		t.Fatal("scoped Group review lacks exact B binding/Network or prepared selection barrier")
	}
	f.dropOperation = wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply)
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionApplyThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: review.GestureID, Confirm: true}}); err == nil || !f.c.hasThreadGroupPending() {
		t.Fatal("lost actual Group apply response did not preserve original")
	}
	original := bytes.Clone(f.c.threadGroups.original.Packet)
	f.restart()
	if !bytes.Equal(original, f.c.threadGroups.original.Packet) {
		t.Fatal("cold Group recovery replaced original")
	}
	f.dispatch(Action{Kind: ActionRecoverThreadGroup})
	if f.c.hasThreadGroupPending() || f.posts[wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply)] != 1 {
		t.Fatal("Group recovery repeated the business mutation")
	}
	settled, err := f.c.openThreadGroupResult(f.c.threadGroups.original, f.c.threadGroups.response.Packet, nil)
	if err != nil || settled.Operation == nil || settled.Operation.State != "COMPLETED" || settled.Operation.Action != wire.OwnerEndpointGroupsCreateGroup || !f.c.threadGroups.original.Applied || f.c.Snapshot().ThreadGroups.Current {
		t.Fatal("scoped actor did not recover the exact completed Group receipt, or made historical cards current", err)
	}
	s := f.c.Snapshot()
	f.dispatch(Action{Kind: ActionSelectSavedNode, NodeSelection: NodeSelectionAction{NodeID: a.binding.NodeID, GestureID: s.Targets.GestureID}})
	if got := f.c.selectedNodeBinding(); !reflect.DeepEqual(got, a.binding) {
		t.Fatal("A to B to A selected wrong authenticated binding")
	}
	if f.c.Snapshot().LocalCollaboration.Current || f.c.Snapshot().ThreadGroups.Current {
		t.Fatal("selection reused current views from previous Node")
	}
	f.dispatch(Action{Kind: ActionRefreshNode})
	if got := f.c.selectedNodeBinding(); !reflect.DeepEqual(got, a.binding) || f.c.node.Client.NextRequest != 3 || f.c.node.Client.NextResponse != 3 {
		t.Fatal("returning to A changed binding/global counters")
	}
}

func TestScopedAppRealTLSFreshNodesSwitchOnly(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	ownerID, deviceID := f.c.state.OwnerKeyID, f.c.state.DeviceKeyID
	a := f.startNode("SYNTHETIC-switch-A")
	f.approveNode(a)
	f.ackNode(a)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	first := f.c.scopedNode(a.binding.NodeID)
	provenance, head := first.ProvenanceID, first.HighestHead
	confirmation := bytes.Clone(first.Confirmation.Response)
	target, auto := AutomaticNodeStatusTarget(f.c.Snapshot(), time.Now().UTC())
	if !auto {
		t.Fatal("ACKed current scoped Node missing automatic read target")
	}
	f.dispatch(Action{Kind: ActionRefreshNode, AutoNodeStatus: &target})
	f.dispatch(Action{Kind: ActionBeginAddNode})
	b := f.startNode("SYNTHETIC-switch-B")
	f.approveNode(b)
	f.ackNode(b)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if f.c.Snapshot().Targets.SelectedNodeID != b.binding.NodeID || f.c.nodeConfirmation != nil || f.c.scopedBusy() {
		t.Fatal("fresh scoped B did not settle")
	}
	if first.ProvenanceID != provenance || first.HighestHead != head || !bytes.Equal(first.Confirmation.Response, confirmation) {
		t.Fatal("B overwrote A authority")
	}
	if f.c.state.OwnerKeyID != ownerID || f.c.state.DeviceKeyID != deviceID || f.c.node.Client.NextRequest != 3 || f.c.node.Client.NextResponse != 3 {
		t.Fatal("B changed identities/global counters")
	}
	before := f.posts[wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedStatus)]
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNode, AutoNodeStatus: &target}) == nil || before != f.posts[wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedStatus)] {
		t.Fatal("old A automatic target sent under B selection")
	}
	f.dispatch(Action{Kind: ActionSelectSavedNode, NodeSelection: NodeSelectionAction{NodeID: a.binding.NodeID, GestureID: f.c.Snapshot().Targets.GestureID}})
	f.dispatch(Action{Kind: ActionRefreshNode})
	if !reflect.DeepEqual(f.c.selectedNodeBinding(), a.binding) || f.c.node.Client.NextRequest != 3 || f.c.node.Client.NextResponse != 3 {
		t.Fatal("A to B to A lost original binding/counters")
	}
}

func TestScopedAppRealTLSDefaultHubMatchesPublishedAvailability(t *testing.T) {
	f := newScopedAppHTTPFixtureMode(t, false)
	before, err := json.Marshal(f.c.node)
	if err != nil {
		t.Fatal(err)
	}
	available := wire.AppNodeScopedPublicAvailable && wire.NodePairTrustScopedPublicAvailable
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionBeginAddNode}); (err == nil) != available {
		t.Fatal("normal Hub differs from published scoped availability", available, err)
	}
	after, err := json.Marshal(f.c.node)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || f.c.scoped.flow != nil || f.c.scoped.original != nil || f.c.scoped.recovery != nil {
		t.Fatal("unavailable carrier created scoped durable work")
	}
	for path, count := range f.posts {
		if count != 0 && bytes.Contains([]byte(path), []byte("scoped/")) {
			t.Fatal("secret POST preceded exact capability availability")
		}
	}
}

func TestScopedAppRealTLSExplicitFalseMetadataNeverCreatesSecretPOST(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	n := f.startNode("SYNTHETIC-unavailable-discovery")
	f.falseCapabilityPath = wire.NodePairTrustScopedCapabilitiesPath
	if f.c.Dispatch(context.Background(), Action{Kind: ActionReviewNodePairing, DevicePairingCode: n.code}) == nil {
		t.Fatal("false capability admitted scoped code")
	}
	if f.c.scoped.flow != nil || f.c.scoped.original != nil || f.c.scoped.recovery != nil {
		t.Fatal("false capability persisted new ceremony")
	}
	for path, count := range f.posts {
		if count > 0 && strings.Contains(path, "scoped/") {
			t.Fatal("secret App POST preceded both available documents")
		}
	}
}

func TestScopedAppRealTLSStatusOnlyReauthorizationAndCancelKeepOriginalBinding(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	n := f.startNode("SYNTHETIC-finite-status")
	f.approveNode(n)
	f.ackNode(n)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	first := f.c.selectedScopedNode()
	confirmation := bytes.Clone(first.Confirmation.Response)
	provenance := first.ProvenanceID
	counters := f.c.node.Client
	f.dispatch(Action{Kind: ActionCancelNodeAccess, NodeReviewID: f.c.Snapshot().Node.Access.ReviewID})
	cancelledHead := f.c.selectedScopedNode().HighestHead
	f.dispatch(Action{Kind: ActionReauthorizeNodeStatus})
	p := f.c.Snapshot().Node.Candidate
	if p == nil || !p.StatusOnly || p.ReviewID == "" || !f.c.Snapshot().Targets.Locked {
		t.Fatal("READ grant lacks exact prepared review/selection barrier")
	}
	if f.c.Dispatch(context.Background(), Action{Kind: ActionBeginAddNode}) == nil {
		t.Fatal("PREPARED allowed a second ceremony")
	}
	f.dispatch(Action{Kind: ActionApproveNode, NodeReviewID: p.ReviewID, ConfirmNodeAccess: true})
	current := f.c.selectedScopedNode()
	if current.ReadProposal != nil || current.HighestHead != cancelledHead+1 || current.Grant.Claims.Profile != wire.AppNodeScopedProfileStatus || !f.c.Snapshot().Node.Access.Confirmed || counters != f.c.node.Client {
		t.Logf("synthetic READ proposal=%v head=%d profile=%s access=%+v latestMatch=%v fresh=%v live=%v countersEqual=%v", current.ReadProposal != nil, current.HighestHead, current.Grant.Claims.Profile, f.c.Snapshot().Node.Access, current.LatestGrantID == current.Grant.Claims.GrantID, f.c.scoped.fresh[current.NodeID+"/grant"] == sessionTokenDigest(f.c.session.SessionToken), wire.ValidateAppNodeScopedLiveResult(*current.Current, current.Grant.Claims, f.hub, time.Now().UTC()), counters == f.c.node.Client)
		t.Fatal("status-only approval consumed confirmation or changed global counters")
	}
	if !reflect.DeepEqual(current.Binding, n.binding) || current.ProvenanceID != provenance || !bytes.Equal(current.Confirmation.Response, confirmation) {
		t.Fatal("READ grant changed immutable first confirmation/binding")
	}
	f.dispatch(Action{Kind: ActionCancelNodeAccess, NodeReviewID: f.c.Snapshot().Node.Access.ReviewID})
	if f.c.Snapshot().Node.Access.Confirmed || f.c.Snapshot().Node.Binding.Authorized || !reflect.DeepEqual(f.c.selectedNodeBinding(), n.binding) || counters != f.c.node.Client {
		t.Fatal("cancelled grant remained confirmed or changed original Node")
	}
	before := f.posts[wire.AppNodeHTTPPath(wire.OperationAppNodePrepare)]
	if f.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: "23456789ABCD"}) == nil || before != f.posts[wire.AppNodeHTTPPath(wire.OperationAppNodePrepare)] {
		t.Fatal("scoped selection fell back to legacy INITIAL")
	}
}

func (f *scopedAppHTTPFixture) restart() {
	f.t.Helper()
	if err := f.c.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.open()
	f.dispatch(Action{Kind: ActionDiscoverProfiles})
	profiles := f.c.Snapshot().Profiles
	if len(profiles) != 1 {
		f.t.Fatal("saved encrypted profile missing")
	}
	f.dispatch(Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID})
}

func TestScopedAppRealTLSLostAuthorityResponseRetainsOriginalAcrossRestart(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	n := f.startNode("SYNTHETIC-lost-authority")
	f.dispatch(Action{Kind: ActionReviewNodePairing, DevicePairingCode: n.code})
	review := f.c.Snapshot().Node.Pairing.ReviewID
	f.dropOperation = wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedComplete)
	f.dropHTTPStatus = http.StatusForbidden
	if f.c.Dispatch(context.Background(), Action{Kind: ActionApproveNodePairing, NodePairingReviewID: review, ConfirmNodePairing: true}) == nil || !f.c.scopedPending() {
		t.Fatal("untrusted HTTP refusal discarded uncertain authority original")
	}
	original := bytes.Clone(f.c.scoped.original.Packet)
	if !bytes.Equal(original, f.droppedPacket) {
		t.Fatal("retained original differs from sent packet")
	}
	if f.c.Dispatch(context.Background(), Action{Kind: ActionBeginAddNode}) == nil {
		t.Fatal("unknown original allowed second ceremony")
	}
	f.restart()
	if !f.c.scopedPending() || !bytes.Equal(f.c.scoped.original.Packet, original) || f.c.selectedNodeBinding() != nil {
		t.Fatal("restart discarded original or manufactured trust")
	}
	f.dispatch(Action{Kind: ActionRecoverNodePairing})
	if !f.c.scoped.original.Applied || !bytes.Equal(f.c.scoped.original.Packet, original) || f.c.scoped.recovery != nil {
		t.Fatal("reconcile did not settle exact original")
	}
	if f.posts[wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedComplete)] != 1 {
		t.Fatal("recovery issued a replacement authority write")
	}
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	f.ackNode(n)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if f.c.scopedBusy() || f.c.selectedNodeBinding() == nil || f.c.selectedNodeBinding().NodeID != n.binding.NodeID {
		t.Fatal("recovered ceremony did not finish private ACK")
	}
}

func TestScopedAppRealTLSLostACKReadRestoresExactReceiptAndSelection(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	n := f.startNode("SYNTHETIC-lost-ACK-read")
	f.approveNode(n)
	f.ackNode(n)
	f.dropOperation = wire.NodePairTrustScopedHTTPPath(wire.OperationOwnerNodePairTrustScopedStatus)
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRefreshNodePairing}) == nil || !f.c.scopedPending() {
		t.Fatal("lost ACK read was not retained")
	}
	original := bytes.Clone(f.c.scoped.original.Packet)
	f.restart()
	if !bytes.Equal(original, f.c.scoped.original.Packet) {
		t.Fatal("restart replaced ACK read")
	}
	f.dispatch(Action{Kind: ActionRecoverNodePairing})
	if f.c.scopedBusy() || !reflect.DeepEqual(f.c.selectedNodeBinding(), n.binding) || f.c.node.Client.NextRequest != 2 || f.c.node.Client.NextResponse != 2 {
		t.Fatal("ACK recovery did not install exact binding and once-only counters")
	}
	confirmation := bytes.Clone(f.c.selectedScopedNode().Confirmation.Response)
	f.restart()
	if f.c.scopedBusy() || !reflect.DeepEqual(f.c.selectedNodeBinding(), n.binding) || !bytes.Equal(confirmation, f.c.selectedScopedNode().Confirmation.Response) || f.c.node.Client.NextRequest != 2 || f.c.node.Client.NextResponse != 2 {
		t.Fatal("confirmed cold load changed binding, evidence or counters")
	}
}

func TestScopedAppRealTLSSavedReviewRequiresRefreshAndNewConsent(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	n := f.startNode("SYNTHETIC-saved-review")
	f.dispatch(Action{Kind: ActionReviewNodePairing, DevicePairingCode: n.code})
	review := f.c.Snapshot().Node.Pairing.ReviewID
	prepare := bytes.Clone(f.c.scoped.flow.PreparePacket)
	f.restart()
	for _, action := range f.c.Snapshot().AvailableActions {
		if action == ActionApproveNodePairing {
			t.Fatal("cold review became actionable without current session discovery")
		}
	}
	if f.posts[wire.NodePairTrustScopedHTTPPath(wire.OperationOwnerNodePairTrustScopedComplete)] != 0 {
		t.Fatal("restart generated Owner approval")
	}
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if f.c.Snapshot().Node.Pairing.ReviewID != review || !bytes.Equal(prepare, f.c.scoped.flow.PreparePacket) {
		t.Fatal("review refresh replaced original candidate/proof target")
	}
	f.dispatch(Action{Kind: ActionApproveNodePairing, NodePairingReviewID: review, ConfirmNodePairing: true})
	f.ackNode(n)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if !reflect.DeepEqual(f.c.selectedNodeBinding(), n.binding) || f.c.scopedBusy() {
		t.Fatal("review restart did not complete original Node")
	}
}

func TestScopedAppRealTLSApprovedNodeACKNeedsNoOnlineApp(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	n := f.startNode("SYNTHETIC-approved-restart")
	f.approveNode(n)
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	f.ackNode(n)
	f.restart()
	if f.c.selectedNodeBinding() != nil {
		t.Fatal("cold load trusted unobserved ACK")
	}
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if !reflect.DeepEqual(f.c.selectedNodeBinding(), n.binding) || f.c.scopedBusy() || f.c.node.Client.NextRequest != 2 || f.c.node.Client.NextResponse != 2 {
		t.Fatal("offline original Node ACK did not restore exact selection/counters")
	}
}
