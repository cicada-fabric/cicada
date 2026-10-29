package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These fixtures exercise the real SDK and encrypted vault, not carrier/Guard
// acceptance. All identities and retained opaque records are synthetic.
func budgetScope(f *nodeActorFixture, id string) e2ee.OwnerAppNodeScopedScope {
	s := f.scope
	return e2ee.OwnerAppNodeScopedScope{Version: 2, AuthorityNodeID: id, Origin: s.Origin, HubID: s.HubID,
		HubFingerprint: s.HubFingerprint, AccountID: s.AccountID, AccountSessionID: s.AccountSessionID,
		AccountSessionExpiresAt: s.AccountSessionExpiresAt, OwnerID: s.OwnerID, OwnerPublic: s.OwnerPublic,
		OwnerKeyVersion: s.OwnerKeyVersion, DeviceID: s.DeviceID, DevicePublic: s.DevicePublic,
		AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, ClientSessionEpoch: s.ClientSessionEpoch,
		TransportPolicy: s.TransportPolicy}
}

func budgetStatus(t *testing.T, c *nativeController, id, grant string) (wire.AppNodeScopedStatus, *scopedOriginal) {
	t.Helper()
	q, err := wire.NewAppNodeScopedStatus(c.nodeSession(), wire.AppNodeScopedStatusTarget{NodeID: id}, grant, c.cfg.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.newScopedOriginal(q, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return q, p
}

func budgetUpdates(t *testing.T, c *nativeController, p *scopedOriginal) map[string][]byte {
	t.Helper()
	u, err := c.scopedBudgetUpdates(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, raw := range u {
			clear(raw)
		}
	})
	return u
}

func budgetPayload(t *testing.T, c *nativeController, name string, raw []byte) []byte {
	t.Helper()
	old, version, _, err := c.vault.LoadState(name)
	clear(old)
	if err != nil {
		t.Fatal(err)
	}
	return raw[:len(raw)-(20-len(strconv.FormatUint(max(version, 1), 10)))]
}

func TestScopedBudgetMaximumSDKStatus(t *testing.T) {
	f := newNodeActorFixture(t)
	c, id := f.c, "synthetic-budget-node"
	c.scopedNode(id)
	_, p := budgetStatus(t, c, id, "")
	limit, err := c.scopedBudgetPlainLimit(p)
	if err != nil {
		t.Fatal(err)
	}
	result := wire.AppNodeScopedResult{Format: wire.AppNodeScopedResultFormat, Operation: p.Operation, RequestID: p.RequestID,
		RequestPacketDigest: wire.AppNodeScopedPacketDigest(p.Packet), State: wire.AppNodeScopedCompleted, ObservedAt: c.scopedNow(),
		Authority: wire.AppNodeScopedAuthoritySnapshot{Scope: budgetScope(f, id), State: wire.AppNodeScopedAbsent,
			RootState: wire.RootUnavailableState, Counters: wire.AppNodeClientCounters{SessionEpoch: 1, NextResponseSequence: 1}}}
	if err := scopedBudgetDTO(&result, &result.Authority.LatestGrantID, limit); err != nil {
		t.Fatal(err)
	}
	request, _ := wire.DecodePacket(p.Packet)
	response, err := wire.SealResponse(f.n2.hubKey, c.device.Public(), request.Packet.Route, result)
	if err != nil {
		t.Fatal("maximum SDK sample:", err)
	}
	defer clear(response)
	predicted, err := c.scopedBudgetPacketSize(p, limit, true)
	if err != nil || predicted != len(response) || len(response) > wire.MaxAppNodeScopedReceiptBytes {
		t.Fatalf("real packet=%d predicted=%d limit=%d err=%v", len(response), predicted, wire.MaxAppNodeScopedReceiptBytes, err)
	}
	next, err := c.scopedBudgetPacketSize(p, limit+1, true)
	if err != nil || next <= wire.MaxAppNodeScopedReceiptBytes {
		t.Fatalf("plaintext boundary not maximal: %d, %v", next, err)
	}
	if err := c.checkScopedResponse(p, response); err != nil {
		t.Fatal("maximum sample failed SDK/local verification:", err)
	}
	u := budgetUpdates(t, c, p)
	if err := c.vault.CheckStateUpdates(u); err != nil {
		t.Fatal("empty-capacity positive:", err)
	}
	// Apply the actual maximum accepted response; the projection must cover the
	// DTO plus its duplicated metadata and the shared target/counter records.
	p.Response = response
	if err := c.applyScopedResponse(p, false); err != nil {
		t.Fatal(err)
	}
	n := c.scoped.nodes[id]
	if n.Context == nil || n.LatestGrantID != result.Authority.LatestGrantID {
		t.Fatal("actual response did not take the growing Status branch")
	}
	actual, _ := json.Marshal(n)
	if len(actual) > len(u[scopedNodeNamespace(id)]) {
		t.Fatalf("actual Node %d exceeds projection %d", len(actual), len(u[scopedNodeNamespace(id)]))
	}
	for _, name := range []string{nodeStateNamespace, appStateNamespace} {
		raw, _, found, err := c.vault.LoadState(name)
		if err != nil || !found || len(raw) > len(u[name]) {
			t.Fatalf("shared record %s exceeds projection: %d/%d %v", name, len(raw), len(u[name]), err)
		}
		clear(raw)
	}
	t.Logf("SDK canonical plaintext=%d real signed response=%d ceiling=%d Node=%d projected=%d", limit, len(response), wire.MaxAppNodeScopedReceiptBytes, len(actual), len(u[scopedNodeNamespace(id)]))

	// Authority reconcile uses the SDK's 384-KiB outer decoder even though
	// the shared HTTP reader admits 512 KiB for the independent PairTrust family.
	r, err := c.makeScopedRecovery(p)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(r.Body)
	defer clear(r.Packet)
	request, err = wire.DecodePacket(r.Packet)
	if err != nil {
		t.Fatal(err)
	}
	reconciled := wire.AppNodeScopedReconciled{AuthorityNodeID: id, Format: wire.AppNodeScopedReconciledFormat,
		Origin: c.connection.Origin, HubID: c.hub.HubID, AccountID: c.connection.AccountID, OwnerID: c.connection.OwnerID,
		DeviceID: c.state.DeviceID, AccountEpoch: c.session.AccountEpoch, DeviceEpoch: c.session.DeviceEpoch,
		RequestID: r.RequestID, RequestPacketDigest: wire.AppNodeScopedPacketDigest(r.Packet),
		OriginalKind: wire.AppNodeScopedOriginalAuthority, OriginalOperation: p.Operation, OriginalRequestID: p.RequestID,
		OriginalPacketDigest: wire.AppNodeScopedPacketDigest(p.Packet), State: wire.AppNodeScopedCompleted,
		ObservedAt: c.scopedNow(), ReceiptPacket: response}
	outer, err := wire.SealResponse(f.n2.hubKey, c.device.Public(), request.Packet.Route, reconciled)
	if err != nil {
		t.Fatal("maximum nested authority SDK receipt", err)
	}
	defer clear(outer)
	pad := func(maximum int) []byte {
		t.Helper()
		h, err := wire.DecodePacket(outer)
		if err != nil {
			t.Fatal(err)
		}
		encoded := (len(h.Packet.Envelope) + 2) / 3 * 4
		inner := (maximum - len(outer) + encoded) / 4 * 3
		h.Packet.Envelope = append(h.Packet.Envelope, bytes.Repeat([]byte{' '}, inner-len(h.Packet.Envelope))...)
		raw, err := json.Marshal(h)
		if err != nil || len(raw) > maximum || maximum-len(raw) >= 4 {
			t.Fatal("authority padded boundary", err)
		}
		return raw
	}
	maximum := pad(wire.MaxPacketBytes)
	defer clear(maximum)
	got, terminal, err := c.openScopedRecovery(r, p, maximum)
	if err != nil || terminal || !bytes.Equal(got, response) {
		t.Fatal("SDK outer boundary rejected valid nested authority receipt", err)
	}
	oversized := pad(wire.MaxPacketBytes + 4)
	defer clear(oversized)
	if _, _, err := c.openScopedRecovery(r, p, oversized); err == nil {
		t.Fatal("authority SDK accepted an outer response above its own bound")
	}
	u = budgetUpdates(t, c, p)
	frame, err := decodeScopedOriginal(budgetPayload(t, c, scopedWorkspaces[scopedRecoverySlot], u[scopedWorkspaces[scopedRecoverySlot]]))
	if err != nil || len(frame.Response) != wire.MaxPacketBytes || c.scopedResponseLimit(r) != scopedLocalRecoveryReceiptBytes {
		t.Fatal("projection differs from SDK boundary or changed HTTP admission", err)
	}
	t.Logf("authority_recovery_sdk_outer=%d projected=%d HTTP_reader=%d", len(maximum), len(frame.Response), c.scopedResponseLimit(r))
}

func budgetPairFlow(t *testing.T) (*nodePairingFixture, *scopedPairFlow) {
	t.Helper()
	f := newNodePairingFixture(t)
	c := f.n.c
	old := f.context
	ctx := wire.NodePairTrustScopedContext{ScopeVersion: 2, AuthorityNodeID: old.Candidate.NodeID,
		Format: wire.NodePairTrustScopedFormat, AttemptID: old.AttemptID, Hub: old.Hub, Origin: old.Origin,
		DescriptorDigest: old.DescriptorDigest, NodeNonce: old.NodeNonce, Mode: wire.NodePairTrustScopedInitial,
		Candidate: old.Candidate, IssuedAt: old.IssuedAt, ExpiresAt: old.ExpiresAt}
	text, err := wire.EncodeNodePairTrustScopedCode(ctx, f.n.code, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, err := wire.DecodeNodePairTrustScopedCode(text, c.cfg.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	oob, err := wire.NodePairTrustScopedOOBCommitment(code.ContextDigest, code.OOBSecret)
	if err != nil {
		t.Fatal(err)
	}
	s := budgetScope(f.n, ctx.AuthorityNodeID)
	flow := &scopedPairFlow{Format: scopedStateFormat, Vault: c.vault.Scope(), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID,
		NodeID: ctx.AuthorityNodeID, Code: code, Scope: s, Context: &ctx, OOB: oob, ApprovedAt: c.scopedNow(),
		LastError: "APP_NODE_PAIRING_TRUST_MISMATCH", Stage: wire.NodePairTrustScopedOwnerApproved,
		Approval: &wire.NodePairTrustScopedApproval{Scope: s},
		// Retained bytes are deliberately large: the budget must carry the exact
		// already-persisted confirmation, independently of future ACK receipt.
		Confirmation: &scopedConfirmation{Request: bytes.Repeat([]byte{0x51}, 32<<10), ExpectedResponseSequence: math.MaxInt64}}
	c.scoped.flow = flow
	c.scopedNode(flow.NodeID)
	return f, flow
}

func TestScopedBudgetPrepareCompleteModels(t *testing.T) {
	for _, previous := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous=%v", previous), func(t *testing.T) {
			f, flow := budgetPairFlow(t)
			c := f.n.c
			owner, err := c.owner.E2EE()
			if err != nil {
				t.Fatal(err)
			}
			target := wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.n.code}
			if previous {
				target = wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetPrevious, PreviousGrantID: strings.Repeat("a", 32)}
			}
			prepare, err := wire.NewAppNodeScopedPrepare(c.nodeSession(), flow.Scope, target, owner, c.cfg.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			p, err := c.newScopedOriginal(prepare, flow.NodeID, false)
			if err != nil {
				t.Fatal(err)
			}
			intent, _ := e2ee.VerifyOwnerAppNodeScopedPreview(c.owner.Public(), prepare.OwnerIntent, c.cfg.Now().UTC())
			claims := e2ee.OwnerAppNodeScopedGrantClaims{Purpose: e2ee.OwnerAppNodeScopedGrantPurpose, Scope: flow.Scope, GrantID: intent.GrantID,
				ExpectedHeadVersion: flow.Scope.HeadVersion, Profile: wire.AppNodeScopedProfileInitial,
				PrepareRequestID: p.RequestID, PreparePacketDigest: wire.AppNodeScopedPacketDigest(p.Packet), PreviewProofDigest: wire.AppNodeScopedProofDigest(prepare.OwnerIntent),
				ServerNonce: strings.Repeat("1", 64), Candidate: flow.Context.Candidate, AllowedOperations: wire.AppNodeScopedAllowedOperations(), ReadNodeStatus: true, ConfirmationLimit: 1,
				PreparedAt: c.scopedNow(), ProofExpiresAt: f.n.stamp(c.cfg.Now().Add(time.Minute)), LeaseExpiresAt: f.n.stamp(c.cfg.Now().Add(wire.AppNodeScopedLeaseLifetime))}
			claims.Scope.HeadVersion++
			n := c.newScopedNode(flow.NodeID)
			if previous {
				binding, err := scopedBudgetBinding(flow)
				if err != nil {
					t.Fatal(err)
				}
				n.Binding = binding
				claims.Purpose, claims.Profile = e2ee.OwnerAppNodeScopedStatusGrantPurpose, wire.AppNodeScopedProfileStatus
				claims.PreviousGrantID, claims.ConfirmationProvenanceID = target.PreviousGrantID, strings.Repeat("b", 32)
				claims.Candidate, claims.Binding, claims.AllowedOperations, claims.ConfirmationLimit = nil, binding, []string{}, 0
			}
			ch := &wire.AppNodeScopedChallenge{Format: wire.AppNodeScopedChallengeFormat, RequestID: p.RequestID, RequestPacketDigest: claims.PreparePacketDigest, Claims: claims, ObservedAt: c.scopedNow()}
			if err := wire.ValidateAppNodeScopedPreparedResponse(*ch, intent, prepare.OwnerIntent, p.Packet, c.hub, c.cfg.Now().UTC()); err != nil {
				t.Fatal("real scoped challenge fixture:", err)
			}
			u := budgetUpdates(t, c, p)
			if err := c.vault.CheckStateUpdates(u); err != nil {
				t.Fatal(err)
			}
			if previous {
				var future scopedNodeRecord
				name := scopedNodeNamespace(p.NodeID)
				if err := json.Unmarshal(budgetPayload(t, c, name, u[name]), &future); err != nil || future.ReadProposal == nil || future.ReadProposal.Challenge == nil || !bytes.Equal(future.ReadProposal.Packet, p.Packet) {
					t.Fatal("prepare did not reserve typed read proposal/exact packet", err)
				}
				n.ReadProposal = &scopedReadProposal{Prepare: prepare, Packet: p.Packet, Challenge: ch}
			} else {
				var future scopedPairFlow
				name := scopedWorkspaces[scopedFlowSlot]
				if err := json.Unmarshal(budgetPayload(t, c, name, u[name]), &future); err != nil || future.Prepare == nil || future.Challenge == nil || !bytes.Equal(future.PreparePacket, p.Packet) {
					t.Fatal("prepare did not reserve typed flow/challenge/exact packet", err)
				}
				flow.Prepare, flow.PreparePacket, flow.Challenge = &prepare, p.Packet, ch
			}
			complete, err := wire.NewAppNodeScopedComplete(c.nodeSession(), prepare, p.Packet, *ch, owner, c.cfg.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			cp, err := c.newScopedOriginal(complete, flow.NodeID, false)
			if err != nil {
				t.Fatal(err)
			}
			cu := budgetUpdates(t, c, cp)
			var future scopedNodeRecord
			name := scopedNodeNamespace(p.NodeID)
			if err := json.Unmarshal(budgetPayload(t, c, name, cu[name]), &future); err != nil || future.Current == nil || future.ReadProposal != nil || !reflect.DeepEqual(future.Grant, ch) {
				t.Fatal("Complete projection lost current/grant transition", err)
			}
			if err := c.vault.CheckStateUpdates(cu); err != nil {
				t.Fatal(err)
			}
			if !previous {
				device, _ := c.device.E2EE()
				confirmation, err := wire.SealAppNodeScopedConfirmation(device, c.hub, ch.Claims, flow.Code.Selector, c.node.Client.NextRequest, c.cfg.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				flow.Scope = ch.Claims.Scope
				pairPrepare := wire.NodePairTrustScopedOwnerPrepare{Format: wire.NodePairTrustScopedFormat, SessionToken: c.session.SessionToken, Scope: flow.Scope,
					Context: *flow.Context, OOBCommitment: flow.OOB, GrantProof: complete.OwnerGrant, ConfirmationPacket: confirmation, IssuedAt: c.scopedNow()}
				pp, err := c.newScopedOriginal(pairPrepare, flow.NodeID, true)
				if err != nil {
					t.Fatal("real Pair Prepare fixture:", err)
				}
				pu := budgetUpdates(t, c, pp)
				name := scopedWorkspaces[scopedFlowSlot]
				var future scopedPairFlow
				if err := json.Unmarshal(budgetPayload(t, c, name, pu[name]), &future); err != nil || future.Approval == nil || !reflect.DeepEqual(future.Context, flow.Context) || future.LastError != flow.LastError {
					t.Fatal("Pair Prepare lost future Approval or retained ceremony fields", err)
				}
				if err := c.vault.CheckStateUpdates(pu); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// Re-encode only the outer packet after adding whitespace to its opaque E2EE
// JSON. The signature still authenticates the same values. These bytes must
// retain the sealed ceiling even when the decrypted DTO is small.
func budgetPadPairEnvelope(t *testing.T, raw []byte, maximum int) []byte {
	t.Helper()
	var h wire.NodePairTrustScopedPacket
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	encoded := ((len(h.Packet) + 2) / 3) * 4
	inner := (maximum - len(raw) + encoded) / 4 * 3
	if inner < len(h.Packet) {
		t.Fatal("packet already exceeds ceiling")
	}
	h.Packet = append(h.Packet, bytes.Repeat([]byte{' '}, inner-len(h.Packet))...)
	result, err := json.Marshal(h)
	if err != nil || len(result) > maximum || maximum-len(result) >= 4 {
		t.Fatal("sealed padding did not reach representable boundary", err)
	}
	return result
}

func TestScopedBudgetPairACKStatusAndCancel(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancel), func(t *testing.T) {
			f, flow := budgetPairFlow(t)
			c := f.n.c
			lookup := wire.NodePairTrustScopedOwnerLookup{Format: wire.NodePairTrustScopedFormat, SessionToken: c.session.SessionToken, Scope: flow.Scope,
				Selector: flow.Code.Selector, ContextDigest: flow.Code.ContextDigest, IssuedAt: c.scopedNow()}
			lp, err := c.newScopedOriginal(lookup, flow.NodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			lu := budgetUpdates(t, c, lp)
			var futureFlow scopedPairFlow
			flowName := scopedWorkspaces[scopedFlowSlot]
			if err := json.Unmarshal(budgetPayload(t, c, flowName, lu[flowName]), &futureFlow); err != nil || futureFlow.Context == nil || futureFlow.LastError != flow.LastError {
				t.Fatal("Lookup lost future Context or retained diagnostic", err)
			}
			q := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: c.session.SessionToken,
				Scope: flow.Scope, Context: *flow.Context, OOBCommitment: flow.OOB, IssuedAt: c.scopedNow()}
			var body any = q
			if cancel {
				body = &q
			}
			p, err := c.newScopedOriginal(body, flow.NodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.makeScopedRecovery(p)
			if err != nil {
				t.Fatal(err)
			}
			rb, err := c.scopedBody(r, p)
			if err != nil {
				t.Fatal(err)
			}
			for _, recovered := range []bool{false, true} {
				u, err := c.scopedBudgetPhase(p, recovered)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					for _, raw := range u {
						clear(raw)
					}
				})
				if err := c.vault.CheckStateUpdates(u); err != nil {
					t.Fatal(err)
				}
				name := scopedNodeNamespace(p.NodeID)
				var n scopedNodeRecord
				if err := json.Unmarshal(budgetPayload(t, c, name, u[name]), &n); err != nil {
					t.Fatal(err)
				}
				if n.Binding == nil || n.Trust == nil || n.Trust.Original == nil || n.Confirmation == nil ||
					!bytes.Equal(n.Confirmation.Request, flow.Confirmation.Request) || !bytes.Equal(n.Trust.Original.Body, p.Body) || !bytes.Equal(n.Trust.Original.Packet, p.Packet) {
					t.Fatal("ACKED projection omitted binding, confirmation or exact original")
				}
				originalCap := len(n.Trust.Original.Response)
				confirmationCap := len(n.Confirmation.Response)
				if originalCap > scopedLocalReceiptBytes || confirmationCap >= wire.MaxAppNodeScopedReceiptBytes || confirmationCap <= 0 ||
					(!recovered && originalCap != scopedLocalReceiptBytes) || (recovered && originalCap >= scopedLocalReceiptBytes) {
					t.Fatal("nested response bounds are not coupled to their phase")
				}
				frameName := scopedWorkspaces[scopedOriginalSlot]
				original, err := decodeScopedOriginal(budgetPayload(t, c, frameName, u[frameName]))
				if err != nil || len(original.Response) != originalCap {
					t.Fatal("original frame differs from Node trust original", err)
				}
				frameName = scopedWorkspaces[scopedRecoverySlot]
				if recovered {
					frame, err := decodeScopedOriginal(budgetPayload(t, c, frameName, u[frameName]))
					if err != nil || len(frame.Response) != scopedLocalRecoveryReceiptBytes {
						t.Fatal("recovery sealed ceiling was reduced", err)
					}
				} else if len(budgetPayload(t, c, frameName, u[frameName])) != 0 {
					t.Fatal("direct success invented a recovery receipt")
				}
				// SDK envelope acceptance only: opaque inner confirmation bytes are
				// checked separately by the actual ACK consumer, not by this size test.
				binding := *n.Binding
				binding.OwnerBindingID, binding.CredentialVersion, binding.BindingVersion, binding.ApprovedAt = "x", 1, 1, "2000-01-01T00:00:00Z"
				result := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: p.Operation, RequestID: p.RequestID,
					AttemptID: p.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(p.Packet), State: wire.NodePairTrustScopedACKed,
					Context: flow.Context, OOBCommitment: flow.OOB, Binding: &binding, ObservedAt: "2000-01-01T00:00:00Z", ConfirmationResponse: make([]byte, confirmationCap)}
				response, err := wire.SealNodePairTrustScopedResponse(f.n.n2.hubKey, c.hub, p.Packet, body, result)
				if err != nil || len(response) > originalCap || c.checkScopedResponse(p, response) != nil {
					t.Fatal("real SDK original at coupled boundary", len(response), originalCap, err)
				}
				result.ConfirmationResponse = make([]byte, confirmationCap+1)
				next, err := wire.SealNodePairTrustScopedResponse(f.n.n2.hubKey, c.hub, p.Packet, body, result)
				if err != nil || len(next) <= originalCap {
					t.Fatal("confirmation +1B should exceed enclosing packet boundary", len(next), originalCap, err)
				}
				response = budgetPadPairEnvelope(t, response, originalCap)
				if err := c.checkScopedResponse(p, response); err != nil {
					t.Fatal("inner whitespace invalidated original", err)
				}
				rr := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: r.Operation, RequestID: r.RequestID, AttemptID: r.AttemptID,
					RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(r.Packet), State: wire.NodePairTrustScopedRecovered,
					ObservedAt: "2000-01-01T00:00:00Z", OriginalPacketDigest: wire.NodePairTrustScopedPacketDigest(p.Packet), OriginalReceipt: response}
				receipt, err := wire.SealNodePairTrustScopedResponse(f.n.n2.hubKey, c.hub, r.Packet, rb, rr)
				if err != nil {
					t.Fatal(err)
				}
				if recovered {
					if len(receipt) > scopedLocalRecoveryReceiptBytes {
						t.Fatal("nested recovery exceeds sealed bound")
					}
					receipt = budgetPadPairEnvelope(t, receipt, scopedLocalRecoveryReceiptBytes)
					got, terminal, err := c.openScopedRecovery(r, p, receipt)
					if err != nil || terminal || !bytes.Equal(got, response) {
						t.Fatal("maximum sealed nested recovery", err)
					}
				} else if len(receipt) <= scopedLocalRecoveryReceiptBytes {
					t.Fatal("direct maximum incorrectly treated as recoverable at same maximum")
				}
				t.Logf("op=%s recovered=%v original=%d confirmation=%d sealedRecovery=%d nodeProjection=%d", p.Operation, recovered, originalCap, confirmationCap, len(receipt), len(u[name]))
			}
			if flow.Confirmation.Response != nil || c.scoped.nodes[p.NodeID] != nil || c.scoped.original != nil {
				t.Fatal("projection mutated live authority")
			}
		})
	}
}

func TestScopedBudgetRetainsPendingRecovery(t *testing.T) {
	f, flow := budgetPairFlow(t)
	c := f.n.c
	q := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: c.session.SessionToken,
		Scope: flow.Scope, Context: *flow.Context, OOBCommitment: flow.OOB, IssuedAt: c.scopedNow()}
	p, err := c.newScopedOriginal(q, flow.NodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.makeScopedRecovery(p)
	if err != nil {
		t.Fatal(err)
	}
	c.scoped.original, c.scoped.recovery = p, r
	c.scoped.loaded, c.scoped.available = true, true
	for slot, packet := range map[int]*scopedOriginal{scopedOriginalSlot: p, scopedRecoverySlot: r} {
		raw, err := encodeScopedOriginal(packet)
		if err != nil {
			t.Fatal(err)
		}
		budgetPut(t, c, scopedWorkspaces[slot], raw)
		clear(raw)
	}
	if _, err := c.scopedBudgetPhase(p, false); err == nil {
		t.Fatal("direct projection cleared an existing recovery outbox")
	}
	u := budgetUpdates(t, c, p)
	name := scopedWorkspaces[scopedRecoverySlot]
	projected, err := decodeScopedOriginal(budgetPayload(t, c, name, u[name]))
	if err != nil || !bytes.Equal(projected.Packet, r.Packet) || !bytes.Equal(projected.Body, r.Body) || projected.RequestID != r.RequestID || projected.CreatedAt != r.CreatedAt {
		t.Fatal("projection replaced the existing exact recovery", err)
	}
	if err := c.scopedBudget(p); err != nil {
		t.Fatal(err)
	}
	// An unknown/mismatching recovery must remain byte-for-byte on disk and
	// refuse both recovery and a new send, without consuming identity/counters.
	bad := cloneScopedOriginal(r)
	bad.NodeID = "synthetic-unknown-node"
	c.scoped.recovery = bad
	raw, _ := encodeScopedOriginal(bad)
	budgetPut(t, c, name, raw)
	clear(raw)
	before, version, _, _ := c.vault.LoadState(name)
	originalBefore, originalVersion, _, _ := c.vault.LoadState(scopedWorkspaces[scopedOriginalSlot])
	defer clear(before)
	defer clear(originalBefore)
	client, device, owner := c.node.Client, c.device.Public(), c.owner.Public()
	trap := new(connectionHTTPProbe)
	c.directConnection = false
	c.cfg.HTTP = trap
	if c.scopedBudget(p) == nil || c.recoverScopedNode(context.Background()) == nil || c.sendScopedNew(context.Background(), q, flow.NodeID, true) == nil {
		t.Fatal("unknown recovery permitted projection or network")
	}
	after, afterVersion, _, _ := c.vault.LoadState(name)
	originalAfter, originalAfterVersion, _, _ := c.vault.LoadState(scopedWorkspaces[scopedOriginalSlot])
	defer clear(after)
	defer clear(originalAfter)
	if trap.calls != 0 || version != afterVersion || originalVersion != originalAfterVersion || !bytes.Equal(before, after) || !bytes.Equal(originalBefore, originalAfter) ||
		client != c.node.Client || !reflect.DeepEqual(device, c.device.Public()) || !reflect.DeepEqual(owner, c.owner.Public()) {
		t.Fatal("refusal changed an unknown outbox, original, identity or counter")
	}
}

func budgetPut(t *testing.T, c *nativeController, name string, raw []byte) {
	t.Helper()
	old, version, _, err := c.vault.LoadState(name)
	clear(old)
	if err == nil {
		_, err = c.vault.CompareAndSwapState(name, version, raw)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestScopedBudgetACKWithRetainedNodeAndNetwork(t *testing.T) {
	f, flow := budgetPairFlow(t)
	c := f.n.c
	// Length-only replay of the real fresh A + Network + B failure captured at
	// scoped-app-20261029-979wh9w8/budget-shape-and-status-read.jsonl. The opaque
	// records/proof below are capacity fixtures, not authorization or carrier
	// evidence. No private state is copied from that integration run.
	retained := map[string]int{
		appStateNamespace: 438567, appSessionNamespace: 48236,
		localDomainNamespaces[localDomainOriginal]:  71051,
		localDomainNamespaces[localDomainResponse]:  90534,
		localDomainNamespaces[localDomainState]:     41607,
		scopedNodeNamespace("synthetic-retained-a"): 429002,
	}
	for name, size := range retained {
		budgetPut(t, c, name, make([]byte, size))
	}
	// Match the captured flow's encoded size without inventing signed material.
	// The current valid SDK Status request never carries this retained proof.
	flow.LastError = "APP_NODE_PAIRING_STORAGE_FULL"
	base, _ := json.Marshal(flow)
	const flowBytes = 266269 - 19 // Projection's CAS decimal-width allowance.
	flow.OwnerProof = make([]byte, (flowBytes-len(base)+2)/4*3)
	raw, _ := json.Marshal(flow)
	flow.ReviewID = strings.Repeat("x", flowBytes-len(raw))
	q := wire.NodePairTrustScopedOwnerStatus{Format: wire.NodePairTrustScopedFormat, SessionToken: c.session.SessionToken,
		Scope: flow.Scope, Context: *flow.Context, OOBCommitment: flow.OOB, IssuedAt: c.scopedNow()}
	p, err := c.newScopedOriginal(q, flow.NodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.scopedBudget(p); err != nil {
		u := budgetUpdates(t, c, p)
		for name, payload := range u {
			t.Logf("projected %s bytes=%d", name, len(payload))
		}
		t.Fatal("retained A/Network must allow the bounded B ACK lifecycle:", err)
	}
	for name, size := range retained {
		raw, version, found, err := c.vault.LoadState(name)
		if err != nil || !found || len(raw) != size || version == 0 || !bytes.Equal(raw, make([]byte, size)) {
			t.Fatal("budget discarded or changed retained namespace", name, err)
		}
		clear(raw)
	}
}

func TestScopedBudgetCapacityBoundaryBeforePOST(t *testing.T) {
	f := newNodeActorFixture(t)
	c, id := f.c, "synthetic-budget-node"
	c.scopedNode(id)
	c.scoped.available = true
	q, p := budgetStatus(t, c, id, "")
	u := budgetUpdates(t, c, p)
	// Existing opaque legacy state counts in S. Locate the exact encoded-vault
	// boundary with read-only checks, then write one final fixture allocation.
	for i := 0; i < 2; i++ {
		budgetPut(t, c, fmt.Sprintf("budget.opaque.%d", i), make([]byte, 768<<10))
	}
	name := "budget.boundary"
	low, high := 0, 1<<20
	for low < high {
		mid := (low + high + 1) / 2
		u[name] = make([]byte, mid)
		if c.vault.CheckStateUpdates(u) == nil {
			low = mid
		} else {
			high = mid - 1
		}
	}
	if low == 0 || low == 1<<20 {
		t.Fatalf("fixture did not reach the total encoded boundary: %d; projection=%v", low, c.vault.CheckStateUpdates(u))
	}
	u[name] = make([]byte, low)
	if err := c.vault.CheckStateUpdates(u); err != nil {
		t.Fatal("last fitting byte:", err)
	}
	u[name] = make([]byte, low+1)
	if c.vault.CheckStateUpdates(u) == nil {
		t.Fatal("one more payload byte did not reject")
	}
	delete(u, name)
	budgetPut(t, c, name, make([]byte, low+1))
	// The original old frames-only admission would fit here. The added typed
	// Node/global growth is what must now reject before creating any pending.
	framesOnly := map[string][]byte{}
	for _, ns := range scopedWorkspaces {
		framesOnly[ns] = u[ns]
	}
	if err := c.vault.CheckStateUpdates(framesOnly); err != nil {
		t.Fatal("counterexample no longer separates receipt-only admission:", err)
	}
	beforeClient, beforeDevice, beforeOwner := c.node.Client, c.device.Public(), c.owner.Public()
	oldBytes, version, _, _ := c.vault.LoadState(name)
	defer clear(oldBytes)
	trap := new(connectionHTTPProbe)
	c.cfg.HTTP = trap
	if !c.scopedOperationAllowed(id) {
		t.Fatal("fixture is blocked before capacity admission")
	}
	if err := c.sendScopedNew(context.Background(), q, id, false); err == nil || c.scoped.errorCode != "APP_NODE_PAIRING_STORAGE_FULL" {
		t.Fatal("over-capacity send did not fail at storage admission:", err)
	}
	if trap.calls != 0 || c.scoped.original != nil || c.node.Client != beforeClient || !reflect.DeepEqual(c.device.Public(), beforeDevice) || !reflect.DeepEqual(c.owner.Public(), beforeOwner) {
		t.Fatal("storage refusal posted, replaced pending, identity or counters")
	}
	after, afterVersion, _, _ := c.vault.LoadState(name)
	defer clear(after)
	if version != afterVersion || !bytes.Equal(after, oldBytes) {
		t.Fatal("storage refusal changed opaque retained bytes/CAS generation")
	}
	for _, ns := range []string{scopedWorkspaces[scopedOriginalSlot], scopedWorkspaces[scopedRecoverySlot]} {
		raw, v, found, err := c.vault.LoadState(ns)
		clear(raw)
		if err != nil || found || v != 0 {
			t.Fatal("space refusal created a pending namespace", ns, err)
		}
	}
	t.Logf("last fitting opaque payload=%d; +1 byte rejects with zero HTTP and unchanged original identities/counters", low)
}

func TestScopedBudgetPreservesRecordAndKeyBounds(t *testing.T) {
	f := newNodeActorFixture(t)
	c, id := f.c, "synthetic-budget-eighth"
	protector, err := appvault.NewPasswordProtector([]byte("synthetic budget-only vault passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := appvault.Create(filepath.Join(t.TempDir(), "private", "budget.vault"), c.vault.Scope(), protector)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	oldVault := c.vault
	c.vault = vault
	defer func() { c.vault = oldVault }()
	if err := vault.Put(appvault.PurposeAppDevice, c.device); err != nil {
		t.Fatal(err)
	}
	if err := vault.Put(appvault.PurposeOwnerSigner, c.owner); err != nil {
		t.Fatal(err)
	}
	// The old 21 include global App and Node slots, and empty tombstones count.
	for i := 0; i < 19; i++ {
		budgetPut(t, c, fmt.Sprintf("budget.tombstone.%02d", i), nil)
	}
	budgetPut(t, c, appStateNamespace, nil)
	budgetPut(t, c, nodeStateNamespace, nil)
	c.node.Targets = &localTargetDirectory{Format: localTargetsFormat}
	for i := 0; i < 7; i++ {
		node := fmt.Sprintf("synthetic-budget-old-%d", i)
		budgetPut(t, c, scopedNodeNamespace(node), nil)
		c.node.Targets.Nodes = append(c.node.Targets.Nodes, savedNodeReference{ScopeVersion: 2, NodeID: node})
	}
	c.scopedNode(id)
	_, p := budgetStatus(t, c, id, "")
	if err := c.scopedBudget(p); err != nil {
		t.Fatal("21 old + 3 workspaces + 8 Nodes should fit:", err)
	}
	budgetPut(t, c, "budget.extra-tombstone", nil)
	if c.scopedBudget(p) == nil {
		t.Fatal("33 records admitted by discarding an opaque tombstone")
	}
	entries, err := vault.List()
	if err != nil || len(entries) != 2 {
		t.Fatal("key inventory changed", err)
	}
	// Reference bound is independent of the vault record count.
	c.node.Targets.Nodes = append(c.node.Targets.Nodes, savedNodeReference{ScopeVersion: 2, NodeID: "synthetic-budget-other-eighth"})
	if _, err := c.scopedBudgetUpdates(p); err == nil {
		t.Fatal("ninth local Node admitted")
	}
}
