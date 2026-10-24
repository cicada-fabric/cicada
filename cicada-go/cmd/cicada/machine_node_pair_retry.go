package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func machineNodePairArchivePath(stateDir, nodeID, attempt string) string {
	if !machineNodePairHex(attempt, 16) {
		return ""
	}
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "node-pair-trust."+attempt+".sealed.json")
}
func machineNodePairArchiveDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func machineNodePairTerminalRetry(s *machineNodePairState, node *e2ee.Identity) bool {
	if s.Context == nil {
		return machineNodePairNoContextRetired(s, node)
	}
	if s.RetryPollBody == nil || len(s.RetryPollPacket) == 0 || len(s.RetryTerminalReceipt) == 0 {
		return false
	}
	r, e := wire.OpenNodePairTrustResponse(node, s.Context.Hub, s.RetryPollPacket, s.RetryTerminalReceipt, *s.RetryPollBody)
	return e == nil && r.Binding == nil && (r.State == wire.NodePairTrustExpired || r.State == wire.NodePairTrustCancelled || r.State == wire.NodePairTrustRevoked)
}
func verifyMachineNodePairPrevious(stateDir string, client *machineNodeControlClient, s *machineNodePairState, oldAttempt string) error {
	if oldAttempt == "" || s.PreviousAttemptID != oldAttempt || len(s.PreviousAttemptDigest) != 64 {
		return errMachineNodePairState
	}
	path := machineNodePairArchivePath(stateDir, s.NodeID, oldAttempt)
	if path == "" {
		return errMachineNodePairState
	}
	raw, e := machineNodePairPrivateRead(path, machineNodePairLocalMax)
	if e != nil {
		return e
	}
	digest := machineNodePairArchiveDigest(raw)
	clear(raw)
	old, e := loadMachineNodePairStateAtPath(path, s.NodeID, client.identity)
	if e != nil {
		return e
	}
	defer clear(old.Secret)
	if digest != s.PreviousAttemptDigest || old.AttemptID != oldAttempt || old.DescriptorText != s.DescriptorText || old.DialAddress != s.DialAddress || old.StartOperation != s.StartOperation || machineNodePairCredentialDigest(old) != machineNodePairCredentialDigest(s) || !machineNodePairTerminalRetry(old, client.identity) {
		return errMachineNodePairState
	}
	return nil
}

// An explicit new-code action first observes an authenticated current terminal
// attempt. It preserves original identities/transport/credential and archives
// every uncertain old original. It never revives an old attempt or its deadline.
func retryMachineNodePair(ctx context.Context, stateDir, name string, client *machineNodeControlClient, s *machineNodePairState, d hubtransport.Descriptor, httpClient *http.Client) (*machineNodePairState, error) {
	if s.Stage == wire.NodePairTrustACKed {
		return nil, errMachineNodePairPending
	}
	if s.TrustAcceptedAt != "" && machineNodePairCurrentTrust(stateDir, s) != nil {
		return nil, errMachineNodePairState
	}
	if s.Context == nil {
		if s.PendingOperation != "" {
			if s.PendingOperation != s.StartOperation {
				return nil, errMachineNodePairState
			}
			r, receipt, e := sendOrObserveMachineNodePairPending(ctx, stateDir, client.identity, s, d, httpClient, true)
			if e != nil {
				return nil, e
			}
			if e = applyMachineNodePairResult(stateDir, client, s, d, r, receipt); e != nil {
				return nil, e
			}
		}
		if s.Context == nil {
			end, e := machineNodePairStartExpiry(s)
			if e != nil || !time.Now().UTC().After(end) || !machineNodePairAllStartsFenced(s, client.identity) {
				return nil, errMachineNodePairPending
			}
			s.StartNoEffectRetiredAt = time.Now().UTC().Format(time.RFC3339Nano)
			s.Stage = "RETIRED_NO_EFFECT"
			if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
				return nil, e
			}
		}
	}
	if s.Context != nil {
		now := time.Now().UTC()
		if s.RetryPollBody == nil || func() bool {
			at, e := time.Parse(time.RFC3339Nano, s.RetryPollBody.IssuedAt)
			return e != nil || now.After(at.Add(50*time.Second))
		}() {
			b := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: now.Format(time.RFC3339Nano)}
			id, e := wire.NewRequestID()
			if e != nil {
				return nil, e
			}
			raw, e := wire.SealNodePairTrustRequest(client.identity, d.Claims.Hub, wire.NodePairTrustPacket{Operation: wire.OperationNodePairTrustPoll, RequestID: id, AttemptID: s.AttemptID}, b, now)
			if e != nil {
				return nil, errMachineNodePairState
			}
			s.RetryPollBody = &b
			s.RetryPollPacket = raw
			s.RetryTerminalReceipt = nil
			if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
				return nil, e
			}
		}
		raw, e := machineNodePairPOST(ctx, httpClient, d.Claims.Origin, wire.OperationNodePairTrustPoll, s.RetryPollPacket)
		if e != nil {
			return nil, e
		}
		r, e := wire.OpenNodePairTrustResponse(client.identity, d.Claims.Hub, s.RetryPollPacket, raw, *s.RetryPollBody)
		if e != nil {
			return nil, errMachineNodePairPending
		}
		if r.Binding != nil || (r.State != wire.NodePairTrustExpired && r.State != wire.NodePairTrustCancelled && r.State != wire.NodePairTrustRevoked) || (r.ErrorCode != "" && r.ErrorCode != r.State) {
			// A completed observation is not an uncertain mutation. The next
			// explicit retry action must observe current state with a new read ID.
			s.RetryPollPacket = nil
			s.RetryPollBody = nil
			s.RetryTerminalReceipt = nil
			if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
				return nil, e
			}
			return nil, errMachineNodePairPending
		}
		s.RetryTerminalReceipt = raw
		s.Stage = r.State
		if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
			return nil, e
		}
	}
	archive := machineNodePairArchivePath(stateDir, s.NodeID, s.AttemptID)
	if archive == "" {
		return nil, errMachineNodePairState
	}
	prior, e := machineNodePairPrivateRead(archive, machineNodePairLocalMax)
	if e != nil {
		if _, statErr := os.Lstat(archive); !errors.Is(statErr, os.ErrNotExist) {
			return nil, errMachineNodePairState
		}
		prior, e = machineNodePairPrivateRead(machineNodePairStatePath(stateDir, s.NodeID), machineNodePairLocalMax)
		if e != nil {
			return nil, e
		}
		if e = persistNodeSecretFile(archive, prior, ".node-pair-archive-*"); e != nil {
			return nil, e
		}
	} else {
		old, e := loadMachineNodePairStateAtPath(archive, s.NodeID, client.identity)
		if e != nil {
			clear(prior)
			return nil, e
		}
		valid := old.AttemptID == s.AttemptID && old.DescriptorText == s.DescriptorText && machineNodePairTerminalRetry(old, client.identity)
		clear(old.Secret)
		if !valid {
			clear(prior)
			return nil, errMachineNodePairState
		}
	}
	priorDigest := machineNodePairArchiveDigest(prior)
	clear(prior)
	var retained *machineNodeControlState
	client.mu.Lock()
	current := cloneMachineNodeControlState(client.state)
	client.mu.Unlock()
	if s.StartOperation == wire.OperationNodePairTrustExisting {
		retained = &current
	} else if s.StartOperation != wire.OperationNodePairTrustStart || current.BindingID != "" {
		return nil, errMachineNodePairState
	}
	next, e := newMachineNodePairAttempt(client, s.DescriptorText, s.DialAddress, name, machineNodePairCredentialDigest(s), retained)
	if e != nil {
		return nil, e
	}
	next.PreviousAttemptID = s.AttemptID
	next.PreviousAttemptDigest = priorDigest
	if e = saveMachineNodePairState(stateDir, client.identity, next); e != nil {
		clear(next.Secret)
		return nil, e
	}
	client.mu.Lock()
	client.state.NodePairTrustAttemptID = next.AttemptID
	e = client.persistLocked()
	client.mu.Unlock()
	if e != nil {
		clear(next.Secret)
		return nil, e
	}
	if bytes.Equal(next.Secret, s.Secret) {
		clear(next.Secret)
		return nil, errMachineNodePairState
	}
	return next, nil
}

func machineNodePairStartExpiry(s *machineNodePairState) (time.Time, error) {
	body, e := machineNodePairTypedBody(s.StartOperation, s.StartBody)
	if e != nil {
		return time.Time{}, e
	}
	var stamp string
	switch b := body.(type) {
	case wire.NodePairTrustStart:
		stamp = b.ExpiresAt
	case wire.NodePairTrustExistingStart:
		stamp = b.Context.ExpiresAt
	default:
		return time.Time{}, errMachineNodePairState
	}
	return time.Parse(time.RFC3339Nano, stamp)
}
func machineNodePairAllStartsFenced(s *machineNodePairState, node *e2ee.Identity) bool {
	if s.Context != nil || s.OOB != "" || s.PendingOperation != "" || len(s.PollPacket) != 0 || len(s.OwnerProof) != 0 || s.Approval != nil || s.TrustAcceptedAt != "" || len(s.ACKPacket) != 0 || s.ACKBody != nil || s.Binding != nil || len(s.FencedOriginals) == 0 {
		return false
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return false
	}
	for _, old := range s.FencedOriginals {
		if old.Operation != s.StartOperation || (old.Operation != wire.OperationNodePairTrustStart && old.Operation != wire.OperationNodePairTrustExisting) {
			return false
		}
		body, e := machineNodePairTypedBody(old.Operation, old.Body)
		if e != nil {
			return false
		}
		var r wire.NodePairTrustResult
		if old.QueryBody != nil {
			if !bytes.Equal(old.QueryBody.OriginalPacket, old.Packet) || old.QueryBody.OriginalPacketDigest != wire.NodePairTrustPacketDigest(old.Packet) {
				return false
			}
			r, e = wire.OpenNodePairTrustResponse(node, d.Claims.Hub, old.QueryPacket, old.Receipt, *old.QueryBody)
		} else {
			r, e = wire.OpenNodePairTrustResponse(node, d.Claims.Hub, old.Packet, old.Receipt, body)
		}
		if e != nil || r.State != wire.NodePairTrustFenced || r.ErrorCode != "FENCED" || r.AttemptID != s.AttemptID {
			return false
		}
	}
	return true
}
func machineNodePairNoContextRetired(s *machineNodePairState, node *e2ee.Identity) bool {
	end, e := machineNodePairStartExpiry(s)
	at, ae := time.Parse(time.RFC3339Nano, s.StartNoEffectRetiredAt)
	return e == nil && ae == nil && !at.IsZero() && at.After(end) && s.Stage == "RETIRED_NO_EFFECT" && machineNodePairAllStartsFenced(s, node)
}
