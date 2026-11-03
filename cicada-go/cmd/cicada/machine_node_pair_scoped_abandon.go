package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// A local withdrawal is deliberately separate from authenticated Hub terminal
// receipts. It authorizes only creation of another zero-right INITIAL intent.
type machineNodePairScopedLocalAbandonment struct {
	Kind          string `json:"kind"`
	At            string `json:"at"`
	ContextDigest string `json:"context_digest"`
}

func machineNodePairScopedAbandonReason(s *machineNodePairScopedState, node *e2ee.Identity, at time.Time) string {
	if s == nil || node == nil || s.Context == nil {
		return "ORIGINAL_CONTEXT"
	}
	if s.ACKBody != nil || len(s.ACKPacket) != 0 || len(s.ACKReceipt) != 0 || s.PendingOperation == wire.OperationNodePairTrustScopedACK || s.TerminalOriginal != nil && s.TerminalOriginal.Operation == wire.OperationNodePairTrustScopedACK {
		return "ACK_EVIDENCE"
	}
	if s.Stage != wire.NodePairTrustScopedExpired {
		return "STAGE_NOT_EXPIRED"
	}
	if s.Binding != nil || s.Approval != nil || s.OwnerPublic != nil || s.TrustAcceptedAt != "" || len(s.OwnerProof) != 0 || len(s.Capsule) != 0 || s.PollBody != nil || len(s.PollPacket) != 0 || len(s.PollReceipt) != 0 {
		return "ADMISSION_EVIDENCE"
	}
	if s.PendingOperation != "" || len(s.PendingPacket) != 0 || len(s.PendingBody) != 0 || s.ReconcileBody != nil || len(s.ReconcilePacket) != 0 {
		return "UNCERTAIN_MUTATION"
	}
	if len(s.FencedOriginals) != 0 {
		return "FENCED_HISTORY"
	}
	c := s.Context
	if s.StartOperation != wire.OperationNodePairTrustScopedStart || c.Mode != wire.NodePairTrustScopedInitial || c.Candidate == nil || c.Binding != nil {
		return "NOT_INITIAL"
	}
	end, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || at.IsZero() || !at.After(end) {
		return "DEADLINE_NOT_PASSED"
	}
	d, err := hubtransport.DecodeDescriptor(s.DescriptorText)
	body, be := machineNodePairScopedTypedBody(s.StartOperation, s.StartBody)
	if err != nil || be != nil || wire.ValidateNodePairTrustScopedContext(*c, time.Time{}) != nil {
		return "ORIGINAL_CONTEXT"
	}
	b, ok := body.(wire.NodePairTrustScopedStart)
	n := c.Candidate
	issued, ie := time.Parse(time.RFC3339Nano, c.IssuedAt)
	start, se := time.Parse(time.RFC3339Nano, b.IssuedAt)
	if !ok || ie != nil || se != nil || issued.Before(start.Add(-30*time.Second)) || b.ScopeVersion != 2 || b.Format != wire.NodePairTrustScopedFormat || len(s.Secret) != 32 || c.AttemptID != s.AttemptID || c.AuthorityNodeID != s.NodeID || b.NodeID != s.NodeID || n.NodeID != s.NodeID || n.NodeName != b.NodeName || !reflect.DeepEqual(c.Hub, d.Claims.Hub) || !reflect.DeepEqual(b.Hub, c.Hub) || c.Origin != d.Claims.Origin || b.Origin != c.Origin || c.DescriptorDigest != wire.NodePairTrustScopedDescriptorDigest(s.DescriptorText) || b.DescriptorDigest != c.DescriptorDigest || c.NodeNonce != hex.EncodeToString(b.RequestNonce) || b.ExpiresAt != c.ExpiresAt || n.ExpiresAt != c.ExpiresAt || !reflect.DeepEqual(n.NodePublic, node.Public()) || !reflect.DeepEqual(n.HubNodeControlPublic, d.Claims.NodeControl) || !reflect.DeepEqual(b.HubNodeControlPublic, n.HubNodeControlPublic) || b.HubNodeControlKeyVersion != n.HubNodeControlKeyVersion || n.NodeKeyFingerprint != nodewire.IdentityFingerprint(node.Public()) {
		return "ORIGINAL_CONTEXT"
	}
	code, ce := wire.AppNodeCodeDigest(c.Hub.HubID, s.Selector)
	digest, de := nodewire.PairingCandidateDigest(nodewire.PairingCandidateBasis{RequestID: n.RequestID, Version: int64(n.Version), Mode: n.Mode, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: n.CodeDigest, NodePublicIdentity: n.NodePublic, NodeFingerprint: n.NodeKeyFingerprint, HubPublicIdentity: n.HubNodeControlPublic, HubKeyVersion: n.HubNodeControlKeyVersion, HubFingerprint: n.HubNodeControlFingerprint, NodeKeyEpoch: n.NodeKeyEpoch, ExpiresAt: n.ExpiresAt})
	cd, _ := wire.NodePairTrustScopedContextDigest(*c)
	o, oe := wire.NodePairTrustScopedOOBCommitment(cd, s.Secret)
	if ce != nil || de != nil || oe != nil || code != n.CodeDigest || digest != n.CandidateDigest || o != s.OOB {
		return "ORIGINAL_COMMITMENT"
	}
	if old := s.TerminalOriginal; old != nil {
		body, err := machineNodePairScopedTypedBody(old.Operation, old.Body)
		if err != nil || old.Operation != wire.OperationNodePairTrustScopedPoll {
			return "UNKNOWN_TERMINAL_EVIDENCE"
		}
		q := body.(wire.NodePairTrustScopedPoll)
		r, err := wire.OpenNodePairTrustScopedResponse(node, c.Hub, old.Packet, old.Receipt, q)
		if err != nil || !reflect.DeepEqual(q.Context, *c) || q.OOBCommitment != s.OOB || r.State != wire.NodePairTrustScopedExpired || r.Binding != nil || r.ErrorCode != old.ErrorCode || old.State != r.State {
			return "UNKNOWN_TERMINAL_EVIDENCE"
		}
	}
	return ""
}

func machineNodePairScopedLocalAbandon(stateDir string, client *machineNodeControlClient, s *machineNodePairScopedState, at time.Time) (*machineNodePairScopedLocalAbandonment, error) {
	reason := machineNodePairScopedAbandonReason(s, client.identity, at)
	if reason == "" {
		client.mu.Lock()
		p := cloneMachineNodeControlState(client.state)
		client.mu.Unlock()
		// Only these original intent coordinates are allowed. Any partial pin,
		// sequence, response, pending write or other positive state refuses too.
		expected := machineNodeControlState{Version: machineNodeControlStateVersion, NodeID: s.NodeID, HubOrigin: s.Context.Origin, NodePairTrustAttemptID: s.AttemptID}
		if !reflect.DeepEqual(p, expected) {
			reason = "PUBLIC_ADMISSION_OR_PENDING"
		}
	}
	if reason == "" {
		// Even an unrecognized existing crypto DB may contain a pin committed
		// before a journal crash. Conservatively refuse; never open/repair it.
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_, err := os.Lstat(filepath.Join(machineNodeStateDir(stateDir, s.NodeID), "node-crypto-state.sqlite"+suffix))
			if !os.IsNotExist(err) {
				reason = "LOCAL_TRUST_STATE"
				break
			}
		}
	}
	if reason == "" {
		raw, err := machineNodePairPrivateRead(machineNodeCredentialPath(stateDir, s.NodeID), 64*1024)
		if err != nil || hashNodeCredential(strings.TrimSpace(string(raw))) != machineNodePairScopedCredentialDigest(s) {
			reason = "ORIGINAL_CREDENTIAL"
		}
		clear(raw)
	}
	if reason != "" {
		return nil, fmt.Errorf("NODE_PAIR_RETRY_REFUSED_%s: no new attempt; retain original evidence and reconcile its original state: %w", reason, errMachineNodePairPending)
	}
	digest, _ := wire.NodePairTrustScopedContextDigest(*s.Context)
	return &machineNodePairScopedLocalAbandonment{Kind: "LOCAL_UNACCEPTED_INITIAL", At: at.UTC().Format(time.RFC3339Nano), ContextDigest: digest}, nil
}

// Read-only retry observations may differ across a crash. The original intent,
// secret and accepted Context must still be identical before reusing an archive.
func machineNodePairScopedSameOriginal(a, b *machineNodePairScopedState) bool {
	return a.Version == b.Version && a.NodeID == b.NodeID && a.AttemptID == b.AttemptID && a.DescriptorText == b.DescriptorText && a.DialAddress == b.DialAddress && a.StartOperation == b.StartOperation && bytes.Equal(a.StartBody, b.StartBody) && bytes.Equal(a.Secret, b.Secret) && a.Selector == b.Selector && a.OOB == b.OOB && reflect.DeepEqual(a.Context, b.Context) && machineNodePairScopedCredentialDigest(a) == machineNodePairScopedCredentialDigest(b)
}

func machineNodePairScopedRetryArchiveSource(old, next *machineNodePairScopedState, node *e2ee.Identity) bool {
	m := next.PreviousLocalAbandonment
	if m == nil {
		return machineNodePairScopedTerminalRetry(old, node)
	}
	at, err := time.Parse(time.RFC3339Nano, m.At)
	if err != nil || m.Kind != "LOCAL_UNACCEPTED_INITIAL" || next.StartOperation != wire.OperationNodePairTrustScopedStart || machineNodePairScopedAbandonReason(old, node, at) != "" {
		return false
	}
	digest, _ := wire.NodePairTrustScopedContextDigest(*old.Context)
	return digest == m.ContextDigest
}
