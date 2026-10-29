package appcore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const scopedBudgetTime = "9999-12-31T23:59:59.999999999Z"

// No projected bytes leave memory. All live records, keys, packets and counters
// remain untouched; the vault checks its actual JSON/base64 encoding and every
// retained namespace (including opaque legacy tombstones).
func (c *nativeController) scopedBudget(p *scopedOriginal) error {
	for _, recovered := range []bool{false, true} {
		if !recovered && c.scoped.recovery != nil {
			continue // An existing recovery belongs to its own retained outbox.
		}
		updates, err := c.scopedBudgetPhase(p, recovered)
		if err != nil {
			return err
		}
		err = c.vault.CheckStateUpdates(updates)
		for _, raw := range updates {
			clear(raw)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func scopedBudgetClone(from, to any) error {
	raw, err := json.Marshal(from)
	if err != nil {
		return err
	}
	defer clear(raw)
	return json.Unmarshal(raw, to)
}

// A canonical decoded DTO cannot exceed the plaintext that fits its actual
// signed packet header and the consumer's existing receipt ceiling. This also
// covers SDK fields without individual string bounds; no new decoder limit is
// introduced. The shared PQ size codec includes signatures and the GCM tag.
func (c *nativeController) scopedBudgetPacketSize(p *scopedOriginal, plain int, response bool) (int, error) {
	sender := c.device.Public()
	if response {
		sender = c.hub.Public
	}
	size, err := e2ee.InstallationSealedEnvelopeSize(sender, plain)
	if err != nil {
		return 0, err
	}
	var raw []byte
	if p.PairTrust {
		var h wire.NodePairTrustScopedPacket
		if err = json.Unmarshal(p.Packet, &h); err != nil {
			return 0, err
		}
		h.SenderPublic = sender
		h.Packet = nil
		raw, err = json.Marshal(h)
	} else {
		h, e := wire.DecodePacket(p.Packet)
		if e != nil {
			return 0, e
		}
		if response {
			r := &h.Packet.Route
			r.Direction = "RESPONSE"
			r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
			r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
		}
		h.SenderPublicIdentity = sender
		h.Packet.Envelope = nil
		raw, err = json.Marshal(h)
	}
	if err != nil {
		return 0, err
	}
	return len(raw) - len("null") + 2 + base64.StdEncoding.EncodedLen(size), nil
}

func (c *nativeController) scopedBudgetPlainLimit(p *scopedOriginal) (int, error) {
	return c.scopedBudgetPlainLimitFor(p, c.scopedResponseLimit(p))
}

func (c *nativeController) scopedBudgetPlainLimitFor(p *scopedOriginal, packetLimit int) (int, error) {
	high := wire.MaxAppNodeScopedBodyBytes
	if p.PairTrust {
		high = wire.MaxNodePairTrustScopedResponseBodyBytes
		if p.Recovery {
			high = wire.MaxNodePairTrustScopedReconcileResponseBodyBytes
		}
	}
	low := 0
	for low < high {
		mid := (low + high + 1) / 2
		n, err := c.scopedBudgetPacketSize(p, mid, true)
		if err != nil {
			return 0, err
		}
		if n <= packetLimit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low, nil
}

// Measure the DTO with the actual base64 field present, including an
// omitempty key. A whole-DTO plaintext ceiling bounds the raw embedded bytes.
// All other fields must be exact or minimum encodings: this computes an upper
// bound, and does not narrow any SDK or sealed-response ceiling.
func scopedBudgetEmbeddedLimit(dto any, field *[]byte, plainLimit, maximum int) (int, error) {
	*field = make([]byte, 3)
	raw, err := json.Marshal(dto)
	if err != nil {
		return 0, err
	}
	defer clear(raw)
	available := plainLimit - (len(raw) - base64.StdEncoding.EncodedLen(3))
	if available < 0 {
		return 0, appvault.ErrInvalidVault
	}
	return min(maximum, available/4*3), nil
}

func (c *nativeController) scopedBudgetRecoveredOriginalLimit(p, r *scopedOriginal) (int, error) {
	limit, err := c.scopedBudgetPlainLimit(r)
	if err != nil {
		return 0, err
	}
	if p.PairTrust {
		v := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: r.Operation, RequestID: r.RequestID,
			AttemptID: r.AttemptID, RequestPacketDigest: strings.Repeat("f", 64), State: wire.NodePairTrustScopedRecovered,
			ObservedAt: "2000-01-01T00:00:00Z", OriginalPacketDigest: strings.Repeat("f", 64)}
		return scopedBudgetEmbeddedLimit(&v, &v.OriginalReceipt, limit, c.scopedResponseLimit(p))
	}
	// Unknown diagnostic scalars use their minimum encodings. They can consume
	// more of the body, but cannot make its embedded original receipt larger.
	v := wire.AppNodeScopedReconciled{AuthorityNodeID: p.NodeID, Format: wire.AppNodeScopedReconciledFormat,
		HubID: c.hub.HubID, OwnerID: c.connection.OwnerID, DeviceID: c.state.DeviceID, RequestID: r.RequestID,
		RequestPacketDigest: strings.Repeat("f", 64), OriginalKind: wire.AppNodeScopedOriginalAuthority,
		OriginalOperation: p.Operation, OriginalRequestID: p.RequestID, OriginalPacketDigest: strings.Repeat("f", 64),
		State: wire.AppNodeScopedCompleted, ObservedAt: "2000-01-01T00:00:00Z"}
	return scopedBudgetEmbeddedLimit(&v, &v.ReceiptPacket, limit, c.scopedResponseLimit(p))
}

func (c *nativeController) scopedBudgetConfirmationLimit(p *scopedOriginal, f *scopedPairFlow, packetLimit int) (int, error) {
	plain, err := c.scopedBudgetPlainLimitFor(p, packetLimit)
	if err != nil {
		return 0, err
	}
	b, err := scopedBudgetBinding(f)
	if err != nil {
		return 0, err
	}
	if f.Context.Mode == wire.NodePairTrustScopedInitial {
		// Immutable candidate leaves are exact; newly assigned fields use the
		// smallest legal encodings when bounding room for the embedded receipt.
		b.OwnerBindingID, b.CredentialVersion, b.BindingVersion, b.ApprovedAt = "x", 1, 1, "2000-01-01T00:00:00Z"
	}
	v := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: p.Operation, RequestID: p.RequestID,
		AttemptID: p.AttemptID, RequestPacketDigest: strings.Repeat("f", 64), State: wire.NodePairTrustScopedACKed,
		Context: f.Context, OOBCommitment: f.OOB, Binding: b, ObservedAt: "2000-01-01T00:00:00Z"}
	return scopedBudgetEmbeddedLimit(&v, &v.ConfirmationResponse, plain, wire.MaxAppNodeScopedReceiptBytes)
}

// This fills a *whole DTO's* canonical size bound in one scalar solely for
// encoding measurement. It makes no assertion that that scalar is independently
// authorized or unbounded; it is never passed to a signer, decoder or writer.
func scopedBudgetDTO(value any, field *string, limit int) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) > limit {
		return appvault.ErrInvalidVault
	}
	*field += strings.Repeat("x", limit-len(raw))
	return nil
}

func (c *nativeController) scopedBudgetScope(id string) e2ee.OwnerAppNodeScopedScope {
	return e2ee.OwnerAppNodeScopedScope{AuthorityNodeID: id, Version: 2, Origin: c.connection.Origin, HubID: c.hub.HubID, HubFingerprint: c.connection.HubFingerprint,
		AccountID: c.connection.AccountID, AccountSessionID: strings.Repeat("<", 128), AccountSessionExpiresAt: scopedBudgetTime,
		OwnerID: c.connection.OwnerID, OwnerPublic: c.owner.Public(), OwnerKeyVersion: math.MaxInt64, DeviceID: c.state.DeviceID, DevicePublic: c.device.Public(),
		AccountEpoch: math.MaxInt64, DeviceEpoch: math.MaxInt64, ClientSessionEpoch: math.MaxInt64, HeadVersion: math.MaxInt64, TransportPolicy: wire.AppNodeScopedTransportLoopbackTest}
}

// ACK acceptance copies the exact candidate/binding leaf. Only the newly
// assigned binding ID, versions and approval time are unknown for INITIAL.
func scopedBudgetBinding(f *scopedPairFlow) (*e2ee.OwnerAppNodeBinding, error) {
	if f == nil || f.Context == nil || f.Approval == nil {
		return nil, appvault.ErrInvalidVault
	}
	if f.Context.Mode == wire.NodePairTrustScopedExisting {
		if f.Context.Binding == nil {
			return nil, appvault.ErrInvalidVault
		}
		b := *f.Context.Binding
		return &b, nil
	}
	n := f.Context.Candidate
	if n == nil {
		return nil, appvault.ErrInvalidVault
	}
	s := f.Approval.Scope
	return &e2ee.OwnerAppNodeBinding{OwnerBindingID: strings.Repeat("<", 128), OwnerID: s.OwnerID, HubID: s.HubID, NodeID: n.NodeID, NodeName: n.NodeName,
		ClientDeviceID: s.DeviceID, OwnerKeyID: s.OwnerPublic.ID, CredentialVersion: math.MaxInt64, BindingVersion: math.MaxInt64,
		NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch, HubNodeControlPublic: n.HubNodeControlPublic,
		HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: n.HubNodeControlKeyVersion, ApprovedRequestID: n.RequestID,
		ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: scopedBudgetTime, State: "ACTIVE"}, nil
}

func (c *nativeController) scopedBudgetUpdates(p *scopedOriginal) (map[string][]byte, error) {
	return c.scopedBudgetPhase(p, true)
}

// Direct success has no newly created recovery packet/receipt. Recovery success
// retains both receipts, but its original must fit inside the real reconcile
// response. Check each phase separately; independent maxima cannot coexist.
func (c *nativeController) scopedBudgetPhase(p *scopedOriginal, recovered bool) (map[string][]byte, error) {
	if p == nil || p.Recovery || c.vault == nil {
		return nil, appvault.ErrInvalidVault
	}
	if old := c.scoped.original; old != nil && !old.Applied && !bytes.Equal(old.Packet, p.Packet) {
		return nil, appvault.ErrInvalidVault
	}
	if !recovered && c.scoped.recovery != nil {
		return nil, appvault.ErrInvalidVault
	}
	// Keep an already sealed recovery's exact bytes. For a future recovery use
	// the real codec, then project maximum-width times without sealing a new RPC.
	r := cloneScopedOriginal(c.scoped.recovery)
	projectedRecoveryPacketBytes := 0
	if r == nil {
		var err error
		r, err = c.makeScopedRecovery(p)
		if err != nil {
			return nil, err
		}
		body, err := c.scopedBody(r, p)
		if err != nil {
			return nil, err
		}
		switch q := body.(type) {
		case *wire.AppNodeScopedReconcile:
			q.Context.IssuedAt = scopedBudgetTime
		case *wire.NodePairTrustScopedReconcile:
			q.IssuedAt = scopedBudgetTime
		default:
			return nil, appvault.ErrInvalidVault
		}
		full, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		size, err := c.scopedBudgetPacketSize(r, len(full), false)
		clear(full)
		if err != nil {
			return nil, err
		}
		switch q := body.(type) {
		case *wire.AppNodeScopedReconcile:
			q.OriginalPacket = nil
		case *wire.NodePairTrustScopedReconcile:
			q.OriginalPacket = nil
		}
		compact, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		clear(r.Body)
		r.Body, r.CreatedAt = compact, scopedBudgetTime
		projectedRecoveryPacketBytes = size
	}
	defer func() { clear(r.Body); clear(r.Packet) }()
	if !r.Recovery || r.NodeID != p.NodeID || r.PairTrust != p.PairTrust {
		return nil, appvault.ErrInvalidVault
	}
	originalLimit := c.scopedResponseLimit(p)
	if recovered {
		var err error
		originalLimit, err = c.scopedBudgetRecoveredOriginalLimit(p, r)
		if err != nil {
			return nil, err
		}
	}
	originalLimit = max(originalLimit, len(p.Response))
	if projectedRecoveryPacketBytes != 0 {
		clear(r.Packet)
		r.Packet = make([]byte, projectedRecoveryPacketBytes)
	}
	q := cloneScopedOriginal(p)
	clear(q.Response)
	q.Response = make([]byte, originalLimit)
	defer clear(q.Body)
	defer clear(q.Packet)
	defer clear(q.Response)
	clear(r.Response)
	if recovered {
		r.Response = make([]byte, max(c.scopedResponseLimit(r), len(r.Response)))
	} else {
		r.Response = nil
	}
	defer clear(r.Response)
	original, err := encodeScopedOriginal(q)
	if err != nil {
		return nil, err
	}
	recovery, err := encodeScopedOriginal(r)
	if err != nil {
		clear(original)
		return nil, err
	}
	if !recovered {
		clear(recovery)
		recovery = nil // New-send clears this slot before persisting the original.
	}
	updates := map[string][]byte{scopedWorkspaces[scopedOriginalSlot]: original, scopedWorkspaces[scopedRecoverySlot]: recovery}
	ok := false
	defer func() {
		if !ok {
			for _, raw := range updates {
				clear(raw)
			}
		}
	}()
	// Per-namespace maxima include both pre-apply and post-apply models while
	// this phase's original/recovery receipts still coexist on disk.
	put := func(name string, value any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			return e
		}
		if len(raw) > len(updates[name]) {
			clear(updates[name])
			updates[name] = raw
		} else {
			clear(raw)
		}
		return nil
	}
	var f *scopedPairFlow
	if err := scopedBudgetClone(c.scoped.flow, &f); err != nil {
		return nil, err
	}
	if err := put(scopedWorkspaces[scopedFlowSlot], f); err != nil {
		return nil, err
	}
	n := &scopedNodeRecord{Format: scopedStateFormat, Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, NodeID: p.NodeID}
	if old := c.scoped.nodes[p.NodeID]; old != nil {
		if err := scopedBudgetClone(old, n); err != nil {
			return nil, err
		}
	}
	nodeWritten := !p.PairTrust
	if nodeWritten {
		if err := put(scopedNodeNamespace(p.NodeID), n); err != nil {
			return nil, err
		}
	}
	limit, err := c.scopedBudgetPlainLimitFor(p, originalLimit)
	if err != nil {
		return nil, err
	}
	body, err := c.scopedBody(p, nil)
	if err != nil {
		return nil, err
	}
	if !p.PairTrust {
		n.HighestHead = max(n.HighestHead, uint64(math.MaxInt64))
		result := &wire.AppNodeScopedResult{}
		result.Authority.ConfirmationProvenanceID = n.ProvenanceID
		// Latest/provenance are copied a second time into Node metadata. Filling
		// one of these equally weighted scalars bounds their combined duplication.
		if err := scopedBudgetDTO(result, &result.Authority.LatestGrantID, limit); err != nil {
			return nil, err
		}
		switch v := body.(type) {
		case *wire.AppNodeScopedStatus:
			n.LatestGrantID = result.Authority.LatestGrantID
			if v.GrantID == "" {
				n.Context = result
				if f != nil && f.NodeID == p.NodeID {
					f.Scope = c.scopedBudgetScope(p.NodeID)
				}
			} else {
				n.Current = result
			}
		case *wire.AppNodeScopedPrepare:
			ch := &wire.AppNodeScopedChallenge{}
			if err := scopedBudgetDTO(ch, &ch.Claims.ServerNonce, limit); err != nil {
				return nil, err
			}
			if v.Target.Kind == wire.AppNodeScopedTargetPrevious {
				n.ReadProposal = &scopedReadProposal{Prepare: *v, Packet: bytes.Clone(p.Packet), Challenge: ch}
			} else {
				if f == nil || f.NodeID != p.NodeID {
					return nil, appvault.ErrInvalidVault
				}
				f.Prepare = v
				f.PreparePacket = bytes.Clone(p.Packet)
				f.Challenge = ch
			}
		case *wire.AppNodeScopedComplete:
			n.LatestGrantID = result.Authority.LatestGrantID
			if n.ReadProposal != nil {
				n.Grant = n.ReadProposal.Challenge
			} else if f != nil && f.NodeID == p.NodeID {
				n.Grant = f.Challenge
			}
			n.Current = result
			n.ReadProposal = nil
		case *wire.AppNodeScopedCancel:
			n.LatestGrantID = result.Authority.LatestGrantID
			n.Current = result
			n.ReadProposal = nil
			n.SelfCancelledGrantID = p.GrantID
		default:
			return nil, appvault.ErrInvalidVault
		}
	} else {
		if f == nil || f.NodeID != p.NodeID {
			return nil, appvault.ErrInvalidVault
		}
		switch p.Operation {
		case wire.OperationOwnerNodePairTrustScopedLookup:
			future := &wire.NodePairTrustScopedContext{}
			if err := scopedBudgetDTO(future, &future.Origin, limit); err != nil {
				return nil, err
			}
			f.Context = future
			f.OOB = strings.Repeat("f", 64)
		case wire.OperationOwnerNodePairTrustScopedPrepare:
			a := &wire.NodePairTrustScopedApproval{}
			if err := scopedBudgetDTO(a, &a.ServerNonce, limit); err != nil {
				return nil, err
			}
			f.Approval = a
		case wire.OperationOwnerNodePairTrustScopedComplete:
		case wire.OperationOwnerNodePairTrustScopedStatus, wire.OperationOwnerNodePairTrustScopedCancel:
			if f.Context != nil && f.Approval != nil {
				if c.state.Transport == nil {
					return nil, appvault.ErrInvalidVault
				}
				b, err := scopedBudgetBinding(f)
				if err != nil {
					return nil, err
				}
				n.Binding = b
				n.Trust = &scopedAcceptedTrust{Code: f.Code, Context: *f.Context, Approval: *f.Approval, OOB: f.OOB, AcceptedAt: f.ApprovedAt, Original: q,
					TrustedNodeControl: c.state.Transport.Descriptor.Claims.NodeControl, DescriptorDigest: f.Context.DescriptorDigest}
				if f.Context.Mode == wire.NodePairTrustScopedInitial && f.Confirmation != nil {
					confirmationLimit, err := c.scopedBudgetConfirmationLimit(p, f, originalLimit)
					if err != nil {
						return nil, err
					}
					confirmation := *f.Confirmation
					confirmation.Response = make([]byte, max(confirmationLimit, len(confirmation.Response)))
					defer clear(confirmation.Response)
					n.Confirmation = &confirmation
				}
				// false is one JSON byte larger than the subsequent committed=true.
				n.CountersCommitted = false
				nodeWritten = true
			}
		default:
			return nil, appvault.ErrInvalidVault
		}
	}
	if f != nil {
		if len(f.Stage) < len(wire.NodePairTrustScopedOwnerApproved) {
			f.Stage = wire.NodePairTrustScopedOwnerApproved
		}
		if len(f.LastError) < len("APP_NODE_PAIRING_STORAGE_FULL") {
			f.LastError = "APP_NODE_PAIRING_STORAGE_FULL"
		}
		if err := put(scopedWorkspaces[scopedFlowSlot], f); err != nil {
			return nil, err
		}
	}
	if nodeWritten {
		if err := put(scopedNodeNamespace(p.NodeID), n); err != nil {
			return nil, err
		}
		var global nodeAuthorityState
		if err := scopedBudgetClone(c.node, &global); err != nil {
			return nil, err
		}
		global.Client.Epoch, global.Client.NextRequest, global.Client.NextResponse = math.MaxInt64, math.MaxInt64, math.MaxInt64
		global.Targets = c.localTargets()
		ref := scopedReference(n)
		if n.Trust != nil {
			ref.ConfirmationDigest = strings.Repeat("f", 64)
		}
		found := false
		for i, old := range global.Targets.Nodes {
			if old.NodeID == p.NodeID {
				found = true
				if old.ScopeVersion == 2 {
					global.Targets.Nodes[i] = ref
				}
			}
		}
		if !found {
			if len(global.Targets.Nodes) >= maxLocalNodes {
				return nil, appvault.ErrInvalidVault
			}
			global.Targets.Nodes = append(global.Targets.Nodes, ref)
		}
		if n.Trust != nil && len(p.NodeID) > len(global.Targets.SelectedNodeID) {
			global.Targets.SelectedNodeID = p.NodeID
		}
		if err := put(nodeStateNamespace, global); err != nil {
			return nil, err
		}
	}
	if !p.PairTrust {
		// A current Root-unavailable observation also persists the shared App state.
		state := c.state
		state.RootState = RootStateUnavailable
		raw, err := encodeDurableState(state)
		if err != nil {
			return nil, err
		}
		updates[appStateNamespace] = raw
	}
	// CheckStateUpdates preserves CAS generations instead of incrementing them.
	// Charge their possible decimal-width growth (at most 19 bytes per touched
	// namespace) in the measured payload, without changing any real CAS counter.
	for name, raw := range updates {
		old, version, _, err := c.vault.LoadState(name)
		clear(old)
		if err != nil {
			return nil, err
		}
		width := len(strconv.FormatUint(max(version, 1), 10))
		updates[name] = append(raw, make([]byte, 20-width)...)
	}
	ok = true
	return updates, nil
}
