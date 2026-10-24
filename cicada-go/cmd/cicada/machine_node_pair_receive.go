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

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

var errMachineNodePairIndependentTrust = errors.New("NODE_PAIR_INDEPENDENT_TRUST_REJECTED")

func machineNodePairCurrentTrust(stateDir string, s *machineNodePairState) error {
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
func acceptMachineNodePairCapsule(stateDir string, client *machineNodeControlClient, s *machineNodePairState, r wire.NodePairTrustResult, now time.Time) error {
	if s.Context == nil {
		return errMachineNodePairState
	}
	checkAt := now
	if s.TrustAcceptedAt != "" {
		if machineNodePairCurrentTrust(stateDir, s) != nil || !bytes.Equal(s.OwnerProof, r.OwnerProof) || !bytes.Equal(s.Capsule, r.TrustCapsule) {
			return errMachineNodePairState
		}
		var e error
		checkAt, e = time.Parse(time.RFC3339Nano, s.TrustAcceptedAt)
		if e != nil {
			return errMachineNodePairState
		}
	}
	opened, e := wire.OpenNodePairTrustCapsule(client.identity, *s.Context, s.OOB, r.OwnerProof, r.TrustCapsule, s.Secret, checkAt)
	if e != nil {
		return errMachineNodePairIndependentTrust
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	if s.TrustAcceptedAt == "" {
		// This is the only first-pin branch. It uses the actual live clock checked
		// by OpenNodePairTrustCapsule, never a historical Hub receipt timestamp.
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
func machineNodePairACKBody(stateDir string, client *machineNodeControlClient, s *machineNodePairState, now time.Time) (wire.NodePairTrustACK, error) {
	if s.Context == nil || s.Approval == nil || machineNodePairCurrentTrust(stateDir, s) != nil {
		return wire.NodePairTrustACK{}, errMachineNodePairState
	}
	end, e := time.Parse(time.RFC3339Nano, s.Approval.AcceptBefore)
	if e != nil || !now.Before(end) {
		return wire.NodePairTrustACK{}, errMachineNodePairPending
	}
	at, e := time.Parse(time.RFC3339Nano, s.TrustAcceptedAt)
	if e != nil {
		return wire.NodePairTrustACK{}, errMachineNodePairState
	}
	opened, e := wire.OpenNodePairTrustCapsule(client.identity, *s.Context, s.OOB, s.OwnerProof, s.Capsule, s.Secret, at)
	if e != nil {
		return wire.NodePairTrustACK{}, errMachineNodePairState
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	if len(s.PollPacket) == 0 || len(s.PollReceipt) == 0 {
		return wire.NodePairTrustACK{}, errMachineNodePairState
	}
	return wire.NodePairTrustACK{Format: wire.NodePairTrustFormat, Context: *s.Context, OOBCommitment: s.OOB, PollPacketDigest: wire.NodePairTrustPacketDigest(s.PollPacket), PollReceiptDigest: wire.NodePairTrustPacketDigest(s.PollReceipt), OwnerProofDigest: wire.NodePairTrustProofDigest(s.OwnerProof), CapsuleDigest: wire.NodePairTrustCapsuleDigest(s.Capsule), ACKNonce: append([]byte(nil), opened.ACKNonce...), IssuedAt: now.UTC().Format(time.RFC3339Nano)}, nil
}

func applyMachineNodePairResult(stateDir string, client *machineNodeControlClient, s *machineNodePairState, d hubtransport.Descriptor, r wire.NodePairTrustResult, receipt []byte) error {
	op := s.PendingOperation
	original := append([]byte(nil), s.PendingPacket...)
	body, e := machineNodePairTypedBody(op, s.PendingBody)
	if e != nil {
		return e
	}
	if r.ErrorCode != "" && r.ErrorCode != "FENCED" {
		if (r.State == wire.NodePairTrustExpired || r.State == wire.NodePairTrustCancelled || r.State == wire.NodePairTrustRevoked) && r.ErrorCode == r.State {
			s.TerminalOriginal = &machineNodePairTerminalOriginal{Operation: op, Packet: original, Body: append([]byte(nil), s.PendingBody...), Receipt: append([]byte(nil), receipt...), State: r.State, ErrorCode: r.ErrorCode}
			clearMachineNodePairPending(s)
			s.Stage = r.State
			return saveMachineNodePairState(stateDir, client.identity, s)
		}
		return errMachineNodePairPending
	}
	if r.ErrorCode == "FENCED" && r.State != wire.NodePairTrustFenced {
		return errMachineNodePairState
	}
	if r.ErrorCode == "FENCED" {
		if len(s.FencedOriginals) >= 32 {
			return errMachineNodePairState
		}
		history := machineNodePairFencedOriginal{Operation: op, Packet: original, Body: append([]byte(nil), s.PendingBody...), Receipt: append([]byte(nil), receipt...)}
		if r.Operation == wire.OperationNodePairTrustReconcile {
			history.QueryPacket = append([]byte(nil), s.ReconcilePacket...)
			history.QueryBody = s.ReconcileBody
		}
		s.FencedOriginals = append(s.FencedOriginals, history)
		clearMachineNodePairPending(s)
		// Only this exact original is fenced. The immutable proof/secret/deadline
		// and saved ACK intent survive; fresh poll determines current attempt state.
		if s.Context != nil && op != wire.OperationNodePairTrustCommit {
			s.Stage = wire.NodePairTrustPending
		}
		return saveMachineNodePairState(stateDir, client.identity, s)
	}
	clearMachineNodePairPending(s)
	switch op {
	case wire.OperationNodePairTrustStart, wire.OperationNodePairTrustExisting:
		if r.Context == nil {
			return errMachineNodePairState
		}
		s.Context = r.Context
		s.Selector = r.Selector
		digest, e := wire.NodePairTrustContextDigest(*s.Context)
		if e != nil {
			return errMachineNodePairState
		}
		s.OOB, e = wire.NodePairTrustOOBCommitment(digest, s.Secret)
		if e != nil {
			return errMachineNodePairState
		}
		s.Stage = "COMMIT"
	case wire.OperationNodePairTrustCommit:
		if r.State != wire.NodePairTrustPending {
			return errMachineNodePairState
		}
		s.Stage = wire.NodePairTrustPending
	case wire.OperationNodePairTrustPoll:
		switch r.State {
		case wire.NodePairTrustPending:
			s.Stage = wire.NodePairTrustPending
		case wire.NodePairTrustOwnerApproved:
			if e = acceptMachineNodePairCapsule(stateDir, client, s, r, time.Now().UTC()); e != nil {
				return e
			}
			s.PollPacket = original
			poll, ok := body.(wire.NodePairTrustPoll)
			if !ok {
				return errMachineNodePairState
			}
			s.PollBody = &poll
			s.PollReceipt = append([]byte(nil), receipt...)
			s.Stage = "PINNED"
		case wire.NodePairTrustACKed:
			if s.ACKBody == nil || len(s.ACKPacket) == 0 || machineNodePairACKWasFenced(s, s.ACKPacket) || machineNodePairCurrentTrust(stateDir, s) != nil {
				return errMachineNodePairState
			}
			// Projection is insufficient. Recover the exact already retained ACK.
			s.PendingOperation = wire.OperationNodePairTrustACK
			s.PendingPacket = append([]byte(nil), s.ACKPacket...)
			s.PendingBody, e = json.Marshal(*s.ACKBody)
			if e != nil {
				return e
			}
		case wire.NodePairTrustExpired, wire.NodePairTrustCancelled, wire.NodePairTrustRevoked, wire.NodePairTrustFenced:
			s.Stage = r.State
		default:
			return errMachineNodePairState
		}
	case wire.OperationNodePairTrustACK:
		if r.State != wire.NodePairTrustACKed || r.Binding == nil || s.Context == nil || s.Approval == nil || machineNodePairCurrentTrust(stateDir, s) != nil || wire.ValidateNodePairTrustAccepted(*s.Context, *s.Approval, *r.Binding) != nil {
			return errMachineNodePairState
		}
		ack, ok := body.(wire.NodePairTrustACK)
		if !ok {
			return errMachineNodePairState
		}
		s.ACKPacket = original
		s.ACKBody = &ack
		s.ACKReceipt = append([]byte(nil), receipt...)
		s.Binding = r.Binding
		s.Stage = wire.NodePairTrustACKed
	default:
		return errMachineNodePairState
	}
	return saveMachineNodePairState(stateDir, client.identity, s)
}

func installMachineNodePairBinding(stateDir string, client *machineNodeControlClient, s *machineNodePairState, d hubtransport.Descriptor) error {
	if s.Stage != wire.NodePairTrustACKed || s.Context == nil || s.Approval == nil || s.Binding == nil || s.ACKBody == nil || machineNodePairCurrentTrust(stateDir, s) != nil {
		return errMachineNodePairState
	}
	accepted, e := wire.OpenNodePairTrustResponse(client.identity, d.Claims.Hub, s.ACKPacket, s.ACKReceipt, *s.ACKBody)
	if e != nil || accepted.State != wire.NodePairTrustACKed || !reflect.DeepEqual(accepted.Binding, s.Binding) || wire.ValidateNodePairTrustAccepted(*s.Context, *s.Approval, *s.Binding) != nil {
		return errMachineNodePairState
	}
	b := *s.Binding
	if b.NodeID != client.nodeID || !reflect.DeepEqual(b.NodePublic, client.identity.Public()) || hubtransport.MatchNodeControl(d, b.HubID, b.HubNodeControlPublic, b.HubNodeControlKeyVersion, b.HubNodeControlFingerprint) != nil {
		return errMachineNodePairState
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	old := cloneMachineNodeControlState(client.state)
	address, e := retainedMachineNodePairRouting(old, s)
	if e != nil {
		return e
	}
	if old.BindingID != "" {
		r := wire.NodePairTrustRetainedBinding{NodeID: old.NodeID, OwnerBindingID: old.BindingID, BindingVersion: old.BindingVersion, NodeKeyID: old.NodeKeyID, NodeKeyVersion: old.NodeKeyVersion, NodeKeyEpoch: old.NodeKeyEpoch, NodeKeyFingerprint: old.NodeKeyFingerprint, HubNodeControlPublic: old.HubPublicIdentity, HubNodeControlKeyVersion: old.HubKeyVersion, HubNodeControlFingerprint: old.HubFingerprint, ApprovedRequestID: old.ApprovedRequestID, ApprovedRequestVersion: uint64(old.ApprovedRequestVersion), ApprovedCandidateDigest: old.ApprovedCandidateDigest, CredentialDigest: machineNodePairCredentialDigest(s)}
		if wire.MatchNodePairTrustRetainedBinding(r, b, client.identity.Public()) != nil {
			return errMachineNodePairState
		}
	}
	if old.HubTransportDescriptor != "" && old.HubTransportDescriptor != s.DescriptorText {
		return errMachineNodePairState
	}
	client.state.HubID = b.HubID
	client.state.HubKeyID = b.HubNodeControlPublic.ID
	client.state.HubFingerprint = b.HubNodeControlFingerprint
	client.state.HubKeyVersion = b.HubNodeControlKeyVersion
	client.state.HubPublicIdentity = b.HubNodeControlPublic
	client.state.NodeKeyID = b.NodePublic.ID
	client.state.NodeKeyFingerprint = nodewire.IdentityFingerprint(b.NodePublic)
	client.state.NodeKeyVersion = b.NodeKeyVersion
	client.state.BindingID = b.OwnerBindingID
	client.state.BindingVersion = b.BindingVersion
	client.state.NodeKeyEpoch = b.NodeKeyEpoch
	client.state.ApprovedRequestID = b.ApprovedRequestID
	client.state.ApprovedRequestVersion = int64(b.ApprovedRequestVersion)
	client.state.ApprovedCandidateDigest = b.ApprovedCandidateDigest
	client.state.HubCandidateID = ""
	client.state.HubCandidateFingerprint = ""
	client.state.HubCandidateVersion = 0
	client.state.HubCandidateIdentity = e2ee.PublicIdentity{}
	client.state.PendingPairing = nil
	client.state.PendingPairingUserCode = ""
	client.state.PendingPairingURI = ""
	client.state.HubTransportDescriptor = s.DescriptorText
	client.state.HubDialAddress = address
	client.state.NodePairTrustAttemptID = s.AttemptID
	if e = client.persistLocked(); e != nil {
		client.state = old
		return e
	}
	return nil
}

func machineNodePairACKWasFenced(s *machineNodePairState, packet []byte) bool {
	for _, old := range s.FencedOriginals {
		if old.Operation == wire.OperationNodePairTrustACK && bytes.Equal(old.Packet, packet) {
			return true
		}
	}
	return false
}
func machineNodePairCredentialDigest(s *machineNodePairState) string {
	body, e := machineNodePairTypedBody(s.StartOperation, s.StartBody)
	if e != nil {
		return ""
	}
	switch b := body.(type) {
	case wire.NodePairTrustStart:
		return b.CredentialDigest
	case wire.NodePairTrustExistingStart:
		if b.RetainedBinding != nil {
			return b.RetainedBinding.CredentialDigest
		}
	}
	return ""
}

func requireMachineNodePairAdmission(stateDir, nodeID string) error {
	public, exists, e := readMachineNativeState(stateDir, nodeID)
	if e != nil {
		return e
	}
	_, pairErr := os.Lstat(machineNodePairStatePath(stateDir, nodeID))
	if public.NodePairTrustAttemptID == "" && errors.Is(pairErr, os.ErrNotExist) {
		return nil
	}
	if !exists || pairErr != nil {
		return errMachineNodePairState
	}
	keyPath, statePath := machineNodeControlPaths(stateDir, nodeID)
	for _, p := range []string{keyPath, statePath, filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), machineNodeCredentialPath(stateDir, nodeID)} {
		raw, e := machineNodePairPrivateRead(p, machineNodePairLocalMax)
		clear(raw)
		if e != nil {
			return e
		}
	}
	client, e := openMachineNodeControlClientMode(stateDir, public.HubOrigin, nodeID, true)
	if e != nil {
		return e
	}
	s, e := loadMachineNodePairState(stateDir, nodeID, client.identity)
	if e != nil {
		return e
	}
	defer clear(s.Secret)
	if s.Stage != wire.NodePairTrustACKed || s.AttemptID != public.NodePairTrustAttemptID {
		return errMachineNodePairPending
	}
	token, e := machineNodePairPrivateRead(machineNodeCredentialPath(stateDir, nodeID), 64*1024)
	if e != nil {
		return e
	}
	digest := hashNodeCredential(strings.TrimSpace(string(token)))
	clear(token)
	if digest != machineNodePairCredentialDigest(s) {
		return errMachineNodePairState
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return errMachineNodePairState
	}
	return installMachineNodePairBinding(stateDir, client, s, d)
}

// An ACK proves a binding, not authority to roll back a subsequently verified
// mutable dial locator. Missing or partial bound routing is not repaired here.
func retainedMachineNodePairRouting(old machineNodeControlState, s *machineNodePairState) (string, error) {
	if old.BindingID == "" && old.HubTransportDescriptor == "" && old.HubDialAddress == "" {
		if pqtls.ValidateIPDialAddress(s.DialAddress) != nil {
			return "", errMachineNodePairState
		}
		return s.DialAddress, nil
	}
	if old.BindingID == "" || old.HubTransportDescriptor == "" || old.HubTransportDescriptor != s.DescriptorText || pqtls.ValidateIPDialAddress(old.HubDialAddress) != nil {
		return "", errMachineNodePairState
	}
	return old.HubDialAddress, nil
}
