package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// This layer models the real Store GC's HTTP refusal; the Store test exercises
// its actual writer clock/GC separately. Never treat this 403 as a Hub proof.
func expiredUnacceptedScopedFixture(t *testing.T) (*nodePairScopedConsumerFixture, *machineNodeControlClient, *machineNodePairScopedState) {
	t.Helper()
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, s := f.load(t)
	var b wire.NodePairTrustScopedStart
	if json.Unmarshal(s.StartBody, &b) != nil {
		t.Fatal("synthetic original start")
	}
	past := time.Now().UTC().Add(-21 * time.Minute)
	b.IssuedAt, b.ExpiresAt = past.Format(time.RFC3339Nano), past.Add(10*time.Minute).Format(time.RFC3339Nano)
	s.StartBody, _ = json.Marshal(b)
	s.Context.IssuedAt, s.Context.ExpiresAt = b.IssuedAt, b.ExpiresAt
	s.Context.Candidate.ExpiresAt = b.ExpiresAt
	n := s.Context.Candidate
	digest, err := nodewire.PairingCandidateDigest(nodewire.PairingCandidateBasis{RequestID: n.RequestID, Version: int64(n.Version), Mode: n.Mode, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: n.CodeDigest, NodePublicIdentity: n.NodePublic, NodeFingerprint: n.NodeKeyFingerprint, HubPublicIdentity: n.HubNodeControlPublic, HubKeyVersion: n.HubNodeControlKeyVersion, HubFingerprint: n.HubNodeControlFingerprint, NodeKeyEpoch: n.NodeKeyEpoch, ExpiresAt: n.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	n.CandidateDigest = digest
	d, _ := wire.NodePairTrustScopedContextDigest(*s.Context)
	s.OOB, _ = wire.NodePairTrustScopedOOBCommitment(d, s.Secret)
	s.Stage = wire.NodePairTrustScopedExpired
	if err := saveMachineNodePairScopedState(f.f.state, c.identity, s); err != nil {
		t.Fatal(err)
	}
	return f, c, s
}

func TestNodePairScopedExplicitLocalAbandonAfterGCRefusal(t *testing.T) {
	f, c, old := expiredUnacceptedScopedFixture(t)
	defer clear(old.Secret)
	keyPath, _ := machineNodeControlPaths(f.f.state, f.f.node)
	key, _ := os.ReadFile(keyPath)
	defer clear(key)
	token, _ := os.ReadFile(machineNodeCredentialPath(f.f.state, f.f.node))
	defer clear(token)
	actual := f.f.server.Config.Handler
	var archivedSource []byte
	var sourceMu sync.Mutex
	f.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedPoll) {
			sourceMu.Lock()
			archivedSource, _ = os.ReadFile(machineNodePairScopedStatePath(f.f.state, f.f.node))
			sourceMu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			return
		}
		actual.ServeHTTP(w, r)
	})
	defer func() { sourceMu.Lock(); clear(archivedSource); sourceMu.Unlock() }()
	next, err := retryMachineNodePairScoped(context.Background(), f.f.state, f.f.node, c, old, f.f.native.d, f.f.http)
	if err != nil {
		t.Fatal("explicit local withdrawal must not depend on an old-context HTTP refusal", err)
	}
	defer clear(next.Secret)
	sourceMu.Lock()
	source := bytes.Clone(archivedSource)
	sourceMu.Unlock()
	defer clear(source)
	raw, err := os.ReadFile(machineNodePairScopedArchivePath(f.f.state, f.f.node, old.AttemptID))
	defer clear(raw)
	if err != nil || !bytes.Equal(raw, source) || next.PreviousAttemptDigest != machineNodePairArchiveDigest(raw) || next.AttemptID == old.AttemptID || bytes.Equal(next.Secret, old.Secret) {
		t.Fatal("local withdrawal lost exact original sealed bytes or new-attempt link")
	}
	encoded, _ := json.Marshal(next)
	if !bytes.Contains(encoded, []byte(`"previous_local_abandonment"`)) {
		t.Fatal("local withdrawal was mislabeled as Hub terminal")
	}
	clear(encoded)
	archive, err := loadMachineNodePairScopedStateAtPath(machineNodePairScopedArchivePath(f.f.state, f.f.node, old.AttemptID), f.f.node, c.identity)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(archive.Secret)
	if !machineNodePairScopedRetryArchiveSource(archive, next, c.identity) {
		t.Fatal("local archive marker did not validate")
	}
	marker := *next.PreviousLocalAbandonment
	next.PreviousLocalAbandonment.ContextDigest = strings.Repeat("0", 64)
	if machineNodePairScopedRetryArchiveSource(archive, next, c.identity) {
		t.Fatal("changed archive context marker accepted")
	}
	*next.PreviousLocalAbandonment = marker
	// Simulate the existing crash window after the new journal was durable but
	// before its public attempt marker. Cold recovery must verify the archive.
	c.state.NodePairTrustAttemptID = old.AttemptID
	if err := c.persistLocked(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(c.statePath)
	c, resumed, err := beginMachineNodePairScoped(context.Background(), f.f.state, f.f.node, f.f.node, f.f.address, "", false, f.f.native.text)
	if err != nil {
		t.Fatal("local-withdrawal marker crash did not recover original new intent", err)
	}
	defer clear(resumed.Secret)
	if resumed.AttemptID != next.AttemptID || !bytes.Equal(resumed.Secret, next.Secret) || c.state.NodePairTrustAttemptID != next.AttemptID {
		t.Fatal("cold recovery replaced the new intent")
	}
	keyAfter, _ := os.ReadFile(keyPath)
	defer clear(keyAfter)
	tokenAfter, _ := os.ReadFile(machineNodeCredentialPath(f.f.state, f.f.node))
	defer clear(tokenAfter)
	if !bytes.Equal(key, keyAfter) || !bytes.Equal(token, tokenAfter) || resumed.DescriptorText != old.DescriptorText || resumed.StartOperation != old.StartOperation || machineNodePairScopedCredentialDigest(resumed) != machineNodePairScopedCredentialDigest(old) || c.state.BindingID != "" {
		t.Fatal("local withdrawal changed identity or installed authority")
	}
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("new intent must still wait for fresh Owner approval", err)
	}
}

func TestNodePairScopedLocalAbandonBoundaries(t *testing.T) {
	f, c, s := expiredUnacceptedScopedFixture(t)
	defer clear(s.Secret)
	mutations := map[string]func(*machineNodePairScopedState){
		"unknown":  func(s *machineNodePairScopedState) { s.Stage = "UNKNOWN" },
		"fenced":   func(s *machineNodePairScopedState) { s.Stage = wire.NodePairTrustScopedFenced },
		"acked":    func(s *machineNodePairScopedState) { s.Stage = wire.NodePairTrustScopedACKed },
		"existing": func(s *machineNodePairScopedState) { s.StartOperation = wire.OperationNodePairTrustScopedExisting },
		"live": func(s *machineNodePairScopedState) {
			s.Context.ExpiresAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
		},
		"approval":         func(s *machineNodePairScopedState) { s.Approval = &wire.NodePairTrustScopedApproval{} },
		"proof":            func(s *machineNodePairScopedState) { s.OwnerProof = []byte("SYNTHETIC") },
		"capsule":          func(s *machineNodePairScopedState) { s.Capsule = []byte("SYNTHETIC") },
		"pin":              func(s *machineNodePairScopedState) { s.TrustAcceptedAt = time.Now().UTC().Format(time.RFC3339Nano) },
		"ack":              func(s *machineNodePairScopedState) { s.ACKPacket = []byte("SYNTHETIC") },
		"uncertain_commit": func(s *machineNodePairScopedState) { s.PendingOperation = wire.OperationNodePairTrustScopedCommit },
		"fenced_history": func(s *machineNodePairScopedState) {
			s.FencedOriginals = []machineNodePairScopedFencedOriginal{{Operation: wire.OperationNodePairTrustScopedACK}}
		},
		"secret":     func(s *machineNodePairScopedState) { s.Secret[0] ^= 1 },
		"context":    func(s *machineNodePairScopedState) { s.Context.NodeNonce = strings.Repeat("0", 64) },
		"descriptor": func(s *machineNodePairScopedState) { s.DescriptorText += " " },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(s)
			var bad machineNodePairScopedState
			if json.Unmarshal(raw, &bad) != nil {
				t.Fatal("clone")
			}
			clear(raw)
			defer clear(bad.Secret)
			mutate(&bad)
			if machineNodePairScopedAbandonReason(&bad, c.identity, time.Now().UTC()) == "" {
				t.Fatal("unsafe local initial withdrawal accepted")
			}
		})
	}
	_ = f
}

func TestNodePairScopedOrdinaryTerminalPollRetainsOriginal(t *testing.T) {
	f, c, s := expiredUnacceptedScopedFixture(t)
	defer clear(s.Secret)
	q := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := newMachineNodePairScopedRequest(f.f.state, c.identity, s, f.f.native.d.Claims.Hub, wire.OperationNodePairTrustScopedPoll, q); err != nil {
		t.Fatal(err)
	}
	packet, body := bytes.Clone(s.PendingPacket), bytes.Clone(s.PendingBody)
	var h wire.NodePairTrustScopedPacket
	if json.Unmarshal(packet, &h) != nil {
		t.Fatal("packet")
	}
	r := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(packet), State: wire.NodePairTrustScopedExpired, Context: s.Context, OOBCommitment: s.OOB, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	receipt, err := wire.SealNodePairTrustScopedResponse(f.ids.ClientControl, f.f.native.d.Claims.Hub, packet, q, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = applyMachineNodePairScopedResult(f.f.state, c, s, f.f.native.d, r, receipt); err != nil {
		t.Fatal(err)
	}
	_, saved := f.load(t)
	defer clear(saved.Secret)
	if saved.TerminalOriginal == nil || !bytes.Equal(saved.TerminalOriginal.Packet, packet) || !bytes.Equal(saved.TerminalOriginal.Body, body) || !bytes.Equal(saved.TerminalOriginal.Receipt, receipt) {
		t.Fatal("ordinary terminal receipt or original body was discarded")
	}
	if reason := machineNodePairScopedAbandonReason(saved, c.identity, time.Now().UTC()); reason != "" {
		t.Fatal("cold terminal original cannot be authenticated", reason)
	}
}

func TestNodePairScopedLocalAbandonPublicStateRefusals(t *testing.T) {
	f, c, s := expiredUnacceptedScopedFixture(t)
	defer clear(s.Secret)
	base := cloneMachineNodeControlState(c.state)
	for name, mutate := range map[string]func(*machineNodeControlState){
		"hub_id":           func(p *machineNodeControlState) { p.HubID = "synthetic-partial-hub" },
		"hub_fingerprint":  func(p *machineNodeControlState) { p.HubFingerprint = "synthetic-partial-pin" },
		"hub_public":       func(p *machineNodeControlState) { p.HubPublicIdentity = c.identity.Public() },
		"node_fingerprint": func(p *machineNodeControlState) { p.NodeKeyFingerprint = "synthetic-partial-pin" },
		"sequence":         func(p *machineNodeControlState) { p.Sequence = 1 },
		"pending_id":       func(p *machineNodeControlState) { p.PendingOperationID = "synthetic-pending" },
		"pending_sequence": func(p *machineNodeControlState) { p.PendingSequence = 1 },
		"pending_response": func(p *machineNodeControlState) { p.PendingResponsePacket = []byte("SYNTHETIC") },
		"pending_body":     func(p *machineNodeControlState) { p.PendingNativePairBody = []byte("SYNTHETIC") },
	} {
		t.Run(name, func(t *testing.T) {
			c.mu.Lock()
			c.state = cloneMachineNodeControlState(base)
			mutate(&c.state)
			c.mu.Unlock()
			if _, err := machineNodePairScopedLocalAbandon(f.f.state, c, s, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "PUBLIC_ADMISSION_OR_PENDING") {
				t.Fatal("partial public admission or pending state allowed abandonment", err)
			}
		})
	}
	c.mu.Lock()
	c.state = base
	c.mu.Unlock()
}

func TestNodePairScopedLocalAbandonCancelledRetry(t *testing.T) {
	f, c, s := expiredUnacceptedScopedFixture(t)
	defer clear(s.Secret)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	actual := f.f.server.Config.Handler
	f.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedPoll) {
			actual.ServeHTTP(w, r)
			return
		}
		cancel()
		w.WriteHeader(http.StatusForbidden)
	})
	if _, err := retryMachineNodePairScoped(ctx, f.f.state, f.f.node, c, s, f.f.native.d, f.f.http); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled retry must stop before abandonment", err)
	}
	_, after := f.load(t)
	defer clear(after.Secret)
	if after.AttemptID != s.AttemptID || after.PreviousLocalAbandonment != nil {
		t.Fatal("cancelled retry replaced the original intent")
	}
	if _, err := os.Lstat(machineNodePairScopedArchivePath(f.f.state, f.f.node, s.AttemptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled retry archived the original")
	}
}

func TestNodePairScopedLocalAbandonRejectsDifferentArchive(t *testing.T) {
	f, c, s := expiredUnacceptedScopedFixture(t)
	defer clear(s.Secret)
	actual := f.f.server.Config.Handler
	f.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedPoll) {
			actual.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	for _, which := range []string{"dial", "secret_context"} {
		t.Run(which, func(t *testing.T) {
			raw, _ := json.Marshal(s)
			var old machineNodePairScopedState
			if json.Unmarshal(raw, &old) != nil {
				t.Fatal("clone")
			}
			clear(raw)
			defer clear(old.Secret)
			if which == "dial" {
				old.DialAddress = "127.0.0.1:1"
			} else {
				old.Secret[0] ^= 1
				digest, _ := wire.NodePairTrustScopedContextDigest(*old.Context)
				old.OOB, _ = wire.NodePairTrustScopedOOBCommitment(digest, old.Secret)
			}
			if reason := machineNodePairScopedAbandonReason(&old, c.identity, time.Now().UTC()); reason != "" {
				t.Fatal("archive fixture must independently qualify", reason)
			}
			if err := saveMachineNodePairScopedState(f.f.state, c.identity, &old); err != nil {
				t.Fatal(err)
			}
			archive := machineNodePairScopedArchivePath(f.f.state, f.f.node, s.AttemptID)
			raw, _ = os.ReadFile(machineNodePairScopedStatePath(f.f.state, f.f.node))
			if err := persistNodeSecretFile(archive, raw, ".synthetic-archive-*"); err != nil {
				t.Fatal(err)
			}
			clear(raw)
			if err := saveMachineNodePairScopedState(f.f.state, c.identity, s); err != nil {
				t.Fatal(err)
			}
			if _, err := retryMachineNodePairScoped(context.Background(), f.f.state, f.f.node, c, s, f.f.native.d, f.f.http); !errors.Is(err, errMachineNodePairState) {
				t.Fatal("different original archive accepted", err)
			}
			if err := os.Remove(archive); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodePairScopedLocalAbandonRejectsAuthenticatedCurrentState(t *testing.T) {
	for _, state := range []string{wire.NodePairTrustScopedPending, wire.NodePairTrustScopedFenced, wire.NodePairTrustScopedACKed, "BAD_RECEIPT", "UNAVAILABLE"} {
		t.Run(state, func(t *testing.T) {
			f, c, s := expiredUnacceptedScopedFixture(t)
			defer clear(s.Secret)
			actual := f.f.server.Config.Handler
			f.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if state == "UNAVAILABLE" && req.URL.Path == wire.NodePairTrustScopedCapabilitiesPath {
					_, _ = w.Write([]byte(`{"available":false}`))
					return
				}
				if req.URL.Path != wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedPoll) {
					actual.ServeHTTP(w, req)
					return
				}
				if state == "BAD_RECEIPT" {
					_, _ = w.Write([]byte(`{"synthetic":"bad receipt"}`))
					return
				}
				packet, _ := io.ReadAll(req.Body)
				q := &wire.NodePairTrustScopedPoll{}
				h, err := wire.OpenNodePairTrustScopedRequest(f.ids.ClientControl, f.f.native.d.Claims.Hub, packet, wire.OperationNodePairTrustScopedPoll, q, time.Now().UTC())
				if err != nil {
					t.Error("poll request", err)
					w.WriteHeader(400)
					return
				}
				r := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(packet), State: state, Context: &q.Context, OOBCommitment: q.OOBCommitment, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				if state == wire.NodePairTrustScopedFenced {
					r.ErrorCode, r.Context, r.OOBCommitment = "FENCED", nil, ""
				}
				if state == wire.NodePairTrustScopedACKed {
					n := s.Context.Candidate
					r.Binding = &e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-positive-binding", OwnerID: "synthetic-owner", HubID: s.Context.Hub.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: wire.AccountDeviceIDPrefix + strings.Repeat("a", 32), OwnerKeyID: f.owner.Public().ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch, HubNodeControlPublic: n.HubNodeControlPublic, HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: n.HubNodeControlKeyVersion, ApprovedRequestID: n.RequestID, ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano), State: "ACTIVE"}
				}
				raw, err := wire.SealNodePairTrustScopedResponse(f.ids.ClientControl, f.f.native.d.Claims.Hub, packet, q, r)
				if err != nil {
					t.Error("authenticated response", err)
					w.WriteHeader(500)
					return
				}
				_, _ = w.Write(raw)
			})
			want := "REFUSED_AUTHENTICATED_" + state
			if state == "BAD_RECEIPT" {
				want = "RESPONSE_INVALID"
			}
			_, err := retryMachineNodePairScoped(context.Background(), f.f.state, f.f.node, c, s, f.f.native.d, f.f.http)
			if state == "UNAVAILABLE" {
				if !errors.Is(err, errMachineNodePairScopedUnavailable) {
					t.Fatal("unavailable capability changed intent", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal("current authenticated state bypassed", err)
			}
			if _, err := os.Lstat(machineNodePairScopedArchivePath(f.f.state, f.f.node, s.AttemptID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("current state refusal created archive")
			}
		})
	}
}

func TestNodePairScopedLostACKCannotBeLocallyAbandoned(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	_, s := f.load(t)
	defer clear(s.Secret)
	f.approve(t, s)
	f.drop[wire.OperationNodePairTrustScopedACK] = 1
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, pending := f.load(t)
	defer clear(pending.Secret)
	ack := bytes.Clone(pending.ACKPacket)
	defer clear(ack)
	pending.Stage = wire.NodePairTrustScopedExpired // A stage claim cannot erase an uncertain ACK.
	if err := saveMachineNodePairScopedState(f.f.state, c.identity, pending); err != nil {
		t.Fatal(err)
	}
	f.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wire.NodePairTrustScopedCapabilitiesPath {
			raw, _ := json.Marshal(wire.NodePairTrustScopedContractCapabilities())
			_, _ = w.Write(raw)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := retryMachineNodePairScoped(context.Background(), f.f.state, f.f.node, c, pending, f.f.native.d, f.f.http)
	if err == nil || !strings.Contains(err.Error(), "ACK_EVIDENCE") {
		t.Fatal("uncertain ACK needs a precise refusal, never a new attempt", err)
	}
	_, after := f.load(t)
	defer clear(after.Secret)
	if after.AttemptID != pending.AttemptID || !bytes.Equal(after.ACKPacket, ack) || after.PendingOperation != wire.OperationNodePairTrustScopedACK {
		t.Fatal("local refusal discarded the original ACK")
	}
	if _, err := os.Lstat(machineNodePairScopedArchivePath(f.f.state, f.f.node, pending.AttemptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncertain ACK was archived as abandoned")
	}
}
