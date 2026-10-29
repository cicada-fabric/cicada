package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func machineNodePairScopedArchivePath(stateDir, nodeID, attempt string) string {
	if !machineNodePairHex(attempt, 16) {
		return ""
	}
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "node-pair-trust-scoped."+attempt+".sealed.json")
}
func machineNodePairScopedTerminalRetry(s *machineNodePairScopedState, node *e2ee.Identity) bool {
	if s.Context == nil {
		return machineNodePairScopedNoContextRetired(s, node)
	}
	if s.RetryPollBody == nil || len(s.RetryPollPacket) == 0 || len(s.RetryTerminalReceipt) == 0 {
		return false
	}
	r, e := wire.OpenNodePairTrustScopedResponse(node, s.Context.Hub, s.RetryPollPacket, s.RetryTerminalReceipt, *s.RetryPollBody)
	return e == nil && r.Binding == nil && (r.State == wire.NodePairTrustScopedExpired || r.State == wire.NodePairTrustScopedCancelled || r.State == wire.NodePairTrustScopedRevoked)
}
func verifyMachineNodePairScopedPrevious(stateDir string, client *machineNodeControlClient, s *machineNodePairScopedState, oldAttempt string) error {
	if oldAttempt == "" || s.PreviousAttemptID != oldAttempt || len(s.PreviousAttemptDigest) != 64 {
		return errMachineNodePairState
	}
	path := machineNodePairScopedArchivePath(stateDir, s.NodeID, oldAttempt)
	if path == "" {
		return errMachineNodePairState
	}
	raw, e := machineNodePairPrivateRead(path, machineNodePairScopedLocalMax)
	if e != nil {
		return e
	}
	digest := machineNodePairArchiveDigest(raw)
	clear(raw)
	old, e := loadMachineNodePairScopedStateAtPath(path, s.NodeID, client.identity)
	if e != nil {
		return e
	}
	defer clear(old.Secret)
	if digest != s.PreviousAttemptDigest || old.AttemptID != oldAttempt || old.DescriptorText != s.DescriptorText || old.DialAddress != s.DialAddress || old.StartOperation != s.StartOperation || machineNodePairScopedCredentialDigest(old) != machineNodePairScopedCredentialDigest(s) || !machineNodePairScopedTerminalRetry(old, client.identity) {
		return errMachineNodePairState
	}
	return nil
}

// An explicit new-code action first observes an authenticated current terminal
// attempt. It preserves original identities/transport/credential and archives
// every uncertain old original. It never revives an old attempt or its deadline.
func retryMachineNodePairScoped(ctx context.Context, stateDir, name string, client *machineNodeControlClient, s *machineNodePairScopedState, d hubtransport.Descriptor, httpClient *http.Client) (*machineNodePairScopedState, error) {
	if s.Stage == wire.NodePairTrustScopedACKed {
		return nil, errMachineNodePairPending
	}
	if s.TrustAcceptedAt != "" && machineNodePairScopedCurrentTrust(stateDir, s) != nil {
		return nil, errMachineNodePairState
	}
	if s.Context == nil {
		if s.PendingOperation != "" {
			if s.PendingOperation != s.StartOperation {
				return nil, errMachineNodePairState
			}
			r, receipt, e := sendOrObserveMachineNodePairScopedPending(ctx, stateDir, client.identity, s, d, httpClient, true)
			if e != nil {
				return nil, e
			}
			if e = applyMachineNodePairScopedResult(stateDir, client, s, d, r, receipt); e != nil {
				return nil, e
			}
		}
		if s.Context == nil {
			end, e := machineNodePairScopedStartExpiry(s)
			if e != nil || !time.Now().UTC().After(end) || !machineNodePairScopedAllStartsFenced(s, client.identity) {
				return nil, errMachineNodePairPending
			}
			s.StartNoEffectRetiredAt = time.Now().UTC().Format(time.RFC3339Nano)
			s.Stage = "RETIRED_NO_EFFECT"
			if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
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
			b := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: now.Format(time.RFC3339Nano)}
			id, e := wire.NewRequestID()
			if e != nil {
				return nil, e
			}
			raw, e := wire.SealNodePairTrustScopedRequest(client.identity, d.Claims.Hub, wire.NodePairTrustScopedPacket{Operation: wire.OperationNodePairTrustScopedPoll, RequestID: id, AttemptID: s.AttemptID}, b, now)
			if e != nil {
				return nil, errMachineNodePairState
			}
			s.RetryPollBody = &b
			s.RetryPollPacket = raw
			s.RetryTerminalReceipt = nil
			if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
				return nil, e
			}
		}
		raw, e := machineNodePairScopedPOST(ctx, httpClient, d.Claims.Origin, wire.OperationNodePairTrustScopedPoll, s.RetryPollPacket)
		if e != nil {
			return nil, e
		}
		r, e := wire.OpenNodePairTrustScopedResponse(client.identity, d.Claims.Hub, s.RetryPollPacket, raw, *s.RetryPollBody)
		if e != nil {
			return nil, errMachineNodePairPending
		}
		if r.Binding != nil || (r.State != wire.NodePairTrustScopedExpired && r.State != wire.NodePairTrustScopedCancelled && r.State != wire.NodePairTrustScopedRevoked) || (r.ErrorCode != "" && r.ErrorCode != r.State) {
			// A completed observation is not an uncertain mutation. The next
			// explicit retry action must observe current state with a new read ID.
			s.RetryPollPacket = nil
			s.RetryPollBody = nil
			s.RetryTerminalReceipt = nil
			if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
				return nil, e
			}
			return nil, errMachineNodePairPending
		}
		s.RetryTerminalReceipt = raw
		s.Stage = r.State
		if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
			return nil, e
		}
	}
	archive := machineNodePairScopedArchivePath(stateDir, s.NodeID, s.AttemptID)
	if archive == "" {
		return nil, errMachineNodePairState
	}
	prior, e := machineNodePairPrivateRead(archive, machineNodePairScopedLocalMax)
	if e != nil {
		if _, statErr := os.Lstat(archive); !errors.Is(statErr, os.ErrNotExist) {
			return nil, errMachineNodePairState
		}
		prior, e = machineNodePairPrivateRead(machineNodePairScopedStatePath(stateDir, s.NodeID), machineNodePairScopedLocalMax)
		if e != nil {
			return nil, e
		}
		if e = persistNodeSecretFile(archive, prior, ".node-pair-archive-*"); e != nil {
			return nil, e
		}
	} else {
		old, e := loadMachineNodePairScopedStateAtPath(archive, s.NodeID, client.identity)
		if e != nil {
			clear(prior)
			return nil, e
		}
		valid := old.AttemptID == s.AttemptID && old.DescriptorText == s.DescriptorText && machineNodePairScopedTerminalRetry(old, client.identity)
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
	if s.StartOperation == wire.OperationNodePairTrustScopedExisting {
		retained = &current
	} else if s.StartOperation != wire.OperationNodePairTrustScopedStart || current.BindingID != "" {
		return nil, errMachineNodePairState
	}
	next, e := newMachineNodePairScopedAttempt(client, s.DescriptorText, s.DialAddress, name, machineNodePairScopedCredentialDigest(s), retained)
	if e != nil {
		return nil, e
	}
	next.PreviousAttemptID = s.AttemptID
	next.PreviousAttemptDigest = priorDigest
	if e = saveMachineNodePairScopedState(stateDir, client.identity, next); e != nil {
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

func machineNodePairScopedStartExpiry(s *machineNodePairScopedState) (time.Time, error) {
	body, e := machineNodePairScopedTypedBody(s.StartOperation, s.StartBody)
	if e != nil {
		return time.Time{}, e
	}
	var stamp string
	switch b := body.(type) {
	case wire.NodePairTrustScopedStart:
		stamp = b.ExpiresAt
	case wire.NodePairTrustScopedExistingStart:
		stamp = b.Context.ExpiresAt
	default:
		return time.Time{}, errMachineNodePairState
	}
	return time.Parse(time.RFC3339Nano, stamp)
}
func machineNodePairScopedAllStartsFenced(s *machineNodePairScopedState, node *e2ee.Identity) bool {
	if s.Context != nil || s.OOB != "" || s.PendingOperation != "" || len(s.PollPacket) != 0 || len(s.OwnerProof) != 0 || s.Approval != nil || s.TrustAcceptedAt != "" || len(s.ACKPacket) != 0 || s.ACKBody != nil || s.Binding != nil || len(s.FencedOriginals) == 0 {
		return false
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return false
	}
	for _, old := range s.FencedOriginals {
		if old.Operation != s.StartOperation || (old.Operation != wire.OperationNodePairTrustScopedStart && old.Operation != wire.OperationNodePairTrustScopedExisting) {
			return false
		}
		body, e := machineNodePairScopedTypedBody(old.Operation, old.Body)
		if e != nil {
			return false
		}
		var r wire.NodePairTrustScopedResult
		if old.QueryBody != nil {
			if !bytes.Equal(old.QueryBody.OriginalPacket, old.Packet) || old.QueryBody.OriginalPacketDigest != wire.NodePairTrustScopedPacketDigest(old.Packet) {
				return false
			}
			r, e = wire.OpenNodePairTrustScopedResponse(node, d.Claims.Hub, old.QueryPacket, old.Receipt, *old.QueryBody)
		} else {
			r, e = wire.OpenNodePairTrustScopedResponse(node, d.Claims.Hub, old.Packet, old.Receipt, body)
		}
		if e != nil || r.State != wire.NodePairTrustScopedFenced || r.ErrorCode != "FENCED" || r.AttemptID != s.AttemptID {
			return false
		}
	}
	return true
}
func machineNodePairScopedNoContextRetired(s *machineNodePairScopedState, node *e2ee.Identity) bool {
	end, e := machineNodePairScopedStartExpiry(s)
	at, ae := time.Parse(time.RFC3339Nano, s.StartNoEffectRetiredAt)
	return e == nil && ae == nil && !at.IsZero() && at.After(end) && s.Stage == "RETIRED_NO_EFFECT" && machineNodePairScopedAllStartsFenced(s, node)
}
