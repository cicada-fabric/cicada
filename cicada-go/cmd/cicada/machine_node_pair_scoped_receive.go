package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func machineNodePairScopedCurrentTrust(stateDir string, s *machineNodePairScopedState) error {
	if s.Approval == nil || s.OwnerPublic == nil || s.TrustAcceptedAt == "" || !reflect.DeepEqual(*s.OwnerPublic, s.Approval.Scope.OwnerPublic) {
		return errMachineNodePairState
	}
	at, e := time.Parse(time.RFC3339Nano, s.TrustAcceptedAt)
	end, ee := time.Parse(time.RFC3339Nano, s.Approval.AcceptBefore)
	if e != nil || ee != nil || at.IsZero() || !at.Before(end) {
		return errMachineNodePairState
	}
	root := machineNodeStateDir(stateDir, s.NodeID)
	existing, e := nodekeys.OpenExistingCryptoState(context.Background(), root)
	if e != nil {
		return errMachineNodePairState
	}
	trust, e := existing.GetNodeOwnerKeyTrustLocal(s.Approval.Scope.OwnerID, s.OwnerPublic.ID)
	existing.Close()
	fp, fe := nodekeys.PeerKeyFingerprint(*s.OwnerPublic)
	if e != nil || fe != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive || trust.ExpectedFingerprint != fp || !reflect.DeepEqual(trust.PublicIdentity, *s.OwnerPublic) {
		return errMachineNodePairState
	}
	// Conditional Owner-wide check is inside the existing SQLite writer. The
	// preceding existing-only read cannot cause a missing pin to be initialized.
	state, e := nodekeys.OpenCryptoState(root)
	if e != nil {
		return e
	}
	defer state.Close()
	_, e = state.TrustOwnerApprovalKeyForPairLocal(s.Approval.Scope.OwnerID, s.OwnerPublic.ID, *s.OwnerPublic, fp)
	return e
}
func acceptMachineNodePairScopedCapsule(stateDir string, client *machineNodeControlClient, s *machineNodePairScopedState, r wire.NodePairTrustScopedResult, now time.Time) error {
	if s.Context == nil {
		return errMachineNodePairState
	}
	checkAt := now
	if s.TrustAcceptedAt != "" {
		if machineNodePairScopedCurrentTrust(stateDir, s) != nil || !bytes.Equal(s.OwnerProof, r.OwnerProof) || !bytes.Equal(s.Capsule, r.TrustCapsule) {
			return errMachineNodePairState
		}
		var e error
		checkAt, e = time.Parse(time.RFC3339Nano, s.TrustAcceptedAt)
		if e != nil {
			return errMachineNodePairState
		}
	}
	opened, e := wire.OpenNodePairTrustScopedCapsule(client.identity, *s.Context, s.OOB, r.OwnerProof, r.TrustCapsule, s.Secret, checkAt)
	if e != nil {
		return errMachineNodePairIndependentTrust
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	if s.TrustAcceptedAt == "" {
		// This is the only first-pin branch. It uses the actual live clock checked
		// by OpenNodePairTrustScopedCapsule, never a historical Hub receipt timestamp.
		crypto, e := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, s.NodeID))
		if e != nil {
			return e
		}
		fp, e := nodekeys.PeerKeyFingerprint(opened.OwnerPublic)
		if e == nil {
			_, e = crypto.TrustOwnerApprovalKeyForPairLocal(opened.Approval.Scope.OwnerID, opened.OwnerPublic.ID, opened.OwnerPublic, fp)
		}
		crypto.Close()
		if e != nil {
			return e
		}
		s.TrustAcceptedAt = now.UTC().Format(time.RFC3339Nano)
		owner := opened.OwnerPublic
		s.OwnerPublic = &owner
		approval := opened.Approval
		s.Approval = &approval
		s.OwnerProof = append([]byte(nil), r.OwnerProof...)
		s.Capsule = append([]byte(nil), r.TrustCapsule...)
	}
	return nil
}
func machineNodePairScopedACKBody(stateDir string, client *machineNodeControlClient, s *machineNodePairScopedState, now time.Time) (wire.NodePairTrustScopedACK, error) {
	if s.Context == nil || s.Approval == nil || machineNodePairScopedCurrentTrust(stateDir, s) != nil {
		return wire.NodePairTrustScopedACK{}, errMachineNodePairState
	}
	end, e := time.Parse(time.RFC3339Nano, s.Approval.AcceptBefore)
	if e != nil || !now.Before(end) {
		return wire.NodePairTrustScopedACK{}, errMachineNodePairPending
	}
	at, e := time.Parse(time.RFC3339Nano, s.TrustAcceptedAt)
	if e != nil {
		return wire.NodePairTrustScopedACK{}, errMachineNodePairState
	}
	opened, e := wire.OpenNodePairTrustScopedCapsule(client.identity, *s.Context, s.OOB, s.OwnerProof, s.Capsule, s.Secret, at)
	if e != nil {
		return wire.NodePairTrustScopedACK{}, errMachineNodePairState
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	if len(s.PollPacket) == 0 || len(s.PollReceipt) == 0 {
		return wire.NodePairTrustScopedACK{}, errMachineNodePairState
	}
	return wire.NodePairTrustScopedACK{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, PollPacketDigest: wire.NodePairTrustScopedPacketDigest(s.PollPacket), PollReceiptDigest: wire.NodePairTrustScopedPacketDigest(s.PollReceipt), OwnerProofDigest: wire.NodePairTrustScopedProofDigest(s.OwnerProof), CapsuleDigest: wire.NodePairTrustScopedCapsuleDigest(s.Capsule), ACKNonce: append([]byte(nil), opened.ACKNonce...), IssuedAt: now.UTC().Format(time.RFC3339Nano)}, nil
}

func applyMachineNodePairScopedResult(stateDir string, client *machineNodeControlClient, s *machineNodePairScopedState, d hubtransport.Descriptor, r wire.NodePairTrustScopedResult, receipt []byte) (err error) {
	previous, e := json.Marshal(s)
	if e != nil {
		return errMachineNodePairState
	}
	defer clear(previous)
	defer func() {
		if err != nil {
			_ = json.Unmarshal(previous, s)
		}
	}()
	op := s.PendingOperation
	original := append([]byte(nil), s.PendingPacket...)
	body, e := machineNodePairScopedTypedBody(op, s.PendingBody)
	if e != nil {
		return e
	}
	if r.ErrorCode != "" && r.ErrorCode != "FENCED" {
		if (r.State == wire.NodePairTrustScopedExpired || r.State == wire.NodePairTrustScopedCancelled || r.State == wire.NodePairTrustScopedRevoked) && r.ErrorCode == r.State {
			s.TerminalOriginal = &machineNodePairScopedTerminalOriginal{Operation: op, Packet: original, Body: append([]byte(nil), s.PendingBody...), Receipt: append([]byte(nil), receipt...), State: r.State, ErrorCode: r.ErrorCode}
			clearMachineNodePairScopedPending(s)
			s.Stage = r.State
			return saveMachineNodePairScopedState(stateDir, client.identity, s)
		}
		return errMachineNodePairPending
	}
	if r.ErrorCode == "FENCED" && r.State != wire.NodePairTrustScopedFenced {
		return errMachineNodePairState
	}
	if r.ErrorCode == "FENCED" {
		if len(s.FencedOriginals) >= 32 {
			return errMachineNodePairState
		}
		history := machineNodePairScopedFencedOriginal{Operation: op, Packet: original, Body: append([]byte(nil), s.PendingBody...), Receipt: append([]byte(nil), receipt...)}
		if r.Operation == wire.OperationNodePairTrustScopedReconcile {
			history.QueryPacket = append([]byte(nil), s.ReconcilePacket...)
			history.QueryBody = s.ReconcileBody
		}
		s.FencedOriginals = append(s.FencedOriginals, history)
		clearMachineNodePairScopedPending(s)
		// Only this exact original is fenced. The immutable proof/secret/deadline
		// and saved ACK intent survive; fresh poll determines current attempt state.
		if s.Context != nil && op != wire.OperationNodePairTrustScopedCommit {
			s.Stage = wire.NodePairTrustScopedPending
		}
		return saveMachineNodePairScopedState(stateDir, client.identity, s)
	}
	clearMachineNodePairScopedPending(s)
	switch op {
	case wire.OperationNodePairTrustScopedStart, wire.OperationNodePairTrustScopedExisting:
		if r.Context == nil {
			return errMachineNodePairState
		}
		s.Context = r.Context
		s.Selector = r.Selector
		digest, e := wire.NodePairTrustScopedContextDigest(*s.Context)
		if e != nil {
			return errMachineNodePairState
		}
		s.OOB, e = wire.NodePairTrustScopedOOBCommitment(digest, s.Secret)
		if e != nil {
			return errMachineNodePairState
		}
		s.Stage = "COMMIT"
	case wire.OperationNodePairTrustScopedCommit:
		if r.State != wire.NodePairTrustScopedPending {
			return errMachineNodePairState
		}
		s.Stage = wire.NodePairTrustScopedPending
	case wire.OperationNodePairTrustScopedPoll:
		switch r.State {
		case wire.NodePairTrustScopedPending:
			s.Stage = wire.NodePairTrustScopedPending
		case wire.NodePairTrustScopedOwnerApproved:
			if e = acceptMachineNodePairScopedCapsule(stateDir, client, s, r, time.Now().UTC()); e != nil {
				return e
			}
			s.PollPacket = original
			poll, ok := body.(wire.NodePairTrustScopedPoll)
			if !ok {
				return errMachineNodePairState
			}
			s.PollBody = &poll
			s.PollReceipt = append([]byte(nil), receipt...)
			s.Stage = "PINNED"
		case wire.NodePairTrustScopedACKed:
			if s.ACKBody == nil || len(s.ACKPacket) == 0 || machineNodePairScopedACKWasFenced(s, s.ACKPacket) || machineNodePairScopedCurrentTrust(stateDir, s) != nil {
				return errMachineNodePairState
			}
			// Projection is insufficient. Recover the exact already retained ACK.
			s.PendingOperation = wire.OperationNodePairTrustScopedACK
			s.PendingPacket = append([]byte(nil), s.ACKPacket...)
			s.PendingBody, e = json.Marshal(*s.ACKBody)
			if e != nil {
				return e
			}
		case wire.NodePairTrustScopedExpired, wire.NodePairTrustScopedCancelled, wire.NodePairTrustScopedRevoked, wire.NodePairTrustScopedFenced:
			s.Stage = r.State
		default:
			return errMachineNodePairState
		}
	case wire.OperationNodePairTrustScopedACK:
		if r.State != wire.NodePairTrustScopedACKed || r.Binding == nil || s.Context == nil || s.Approval == nil || machineNodePairScopedCurrentTrust(stateDir, s) != nil || wire.ValidateNodePairTrustScopedAccepted(*s.Context, *s.Approval, *r.Binding) != nil {
			return errMachineNodePairState
		}
		ack, ok := body.(wire.NodePairTrustScopedACK)
		if !ok {
			return errMachineNodePairState
		}
		s.ACKPacket = original
		s.ACKBody = &ack
		s.ACKReceipt = append([]byte(nil), receipt...)
		s.Binding = r.Binding
		s.Stage = wire.NodePairTrustScopedACKed
	default:
		return errMachineNodePairState
	}
	return saveMachineNodePairScopedState(stateDir, client.identity, s)
}

func installMachineNodePairScopedBinding(stateDir string, client *machineNodeControlClient, s *machineNodePairScopedState, d hubtransport.Descriptor) error {
	if s.Stage != wire.NodePairTrustScopedACKed || s.Context == nil || s.Approval == nil || s.Binding == nil || s.ACKBody == nil || machineNodePairScopedCurrentTrust(stateDir, s) != nil {
		return errMachineNodePairState
	}
	accepted, e := wire.OpenNodePairTrustScopedResponse(client.identity, d.Claims.Hub, s.ACKPacket, s.ACKReceipt, *s.ACKBody)
	if e != nil || accepted.State != wire.NodePairTrustScopedACKed || !reflect.DeepEqual(accepted.Binding, s.Binding) || wire.ValidateNodePairTrustScopedAccepted(*s.Context, *s.Approval, *s.Binding) != nil {
		return errMachineNodePairState
	}
	return installMachineNodePairValidatedBinding(client, *s.Binding, d, s.DescriptorText, s.DialAddress, s.AttemptID, machineNodePairScopedCredentialDigest(s))
}

func machineNodePairScopedACKWasFenced(s *machineNodePairScopedState, packet []byte) bool {
	for _, old := range s.FencedOriginals {
		if old.Operation == wire.OperationNodePairTrustScopedACK && bytes.Equal(old.Packet, packet) {
			return true
		}
	}
	return false
}
func machineNodePairScopedCredentialDigest(s *machineNodePairScopedState) string {
	body, e := machineNodePairScopedTypedBody(s.StartOperation, s.StartBody)
	if e != nil {
		return ""
	}
	switch b := body.(type) {
	case wire.NodePairTrustScopedStart:
		return b.CredentialDigest
	case wire.NodePairTrustScopedExistingStart:
		if b.RetainedBinding != nil {
			return b.RetainedBinding.CredentialDigest
		}
	}
	return ""
}

func requireMachineNodePairScopedAdmission(stateDir, nodeID string) error {
	public, exists, e := readMachineNativeState(stateDir, nodeID)
	if e != nil {
		return e
	}
	_, pairErr := os.Lstat(machineNodePairScopedStatePath(stateDir, nodeID))
	if public.NodePairTrustAttemptID == "" && errors.Is(pairErr, os.ErrNotExist) {
		return nil
	}
	if !exists || pairErr != nil {
		return errMachineNodePairState
	}
	keyPath, statePath := machineNodeControlPaths(stateDir, nodeID)
	for _, p := range []string{keyPath, statePath, filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), machineNodeCredentialPath(stateDir, nodeID)} {
		raw, e := machineNodePairPrivateRead(p, machineNodePairScopedLocalMax)
		clear(raw)
		if e != nil {
			return e
		}
	}
	client, e := openMachineNodeControlClientMode(stateDir, public.HubOrigin, nodeID, true)
	if e != nil {
		return e
	}
	s, e := loadMachineNodePairScopedState(stateDir, nodeID, client.identity)
	if e != nil {
		return e
	}
	defer clear(s.Secret)
	if s.Stage != wire.NodePairTrustScopedACKed || s.AttemptID != public.NodePairTrustAttemptID {
		return errMachineNodePairPending
	}
	token, e := machineNodePairPrivateRead(machineNodeCredentialPath(stateDir, nodeID), 64*1024)
	if e != nil {
		return e
	}
	digest := hashNodeCredential(strings.TrimSpace(string(token)))
	clear(token)
	if digest != machineNodePairScopedCredentialDigest(s) {
		return errMachineNodePairState
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return errMachineNodePairState
	}
	return installMachineNodePairScopedBinding(stateDir, client, s, d)
}
