package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

// This collector preserves the complete bounded HTTP body, including padding,
// so the Pair carrier limit measures bytes received rather than re-encoded JSON.
type machineNativePairRawJSON []byte

// The shared transport's existing 2 MiB bound remains unchanged. Only the
// explicitly extended Pair carrier and its two independent additions tighten.
func validateNativePairCarrierBounds(raw []byte, carrier any, evidence *wire.NativePairPeerEvidence, current *wire.NativePairPeerCurrent) error {
	if evidence == nil && current == nil {
		return nil
	}
	if len(raw) > wire.MaxNativePairCarrierBytes || wire.ValidateNativePairCarrierSize(carrier) != nil {
		return errors.New("native Pair authorization carrier exceeds its bounded profile")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields["native_pair_evidence"]) > wire.MaxNativePairEvidenceBytes || len(fields["native_pair_current"]) > wire.MaxNativePairPeerCurrentBytes {
		return errors.New("native Pair authorization additions exceed their bounded profile")
	}
	if current != nil {
		if _, err := wire.DecodeNativePairPeerCurrent(fields["native_pair_current"]); err != nil {
			return errors.New("native Pair Current carrier is invalid")
		}
	}
	return nil
}

func verifyNativePairPeerTarget(ctx context.Context, state *nodekeys.CryptoState, hubID, groupID string, evidence *wire.NativePairPeerEvidence, current *wire.NativePairPeerCurrent, sender, receiver crossNodeGroupEndpointEvidence) (bool, error) {
	required, err := state.VerifyNativePairGroupAuthorization(ctx, groupID, evidence, current, sender.EndpointID, receiver.EndpointID, time.Now().UTC())
	if err != nil || !required {
		return required, err
	}
	if evidence.Plan.Scope.Actor.HubID != hubID {
		return true, nodekeys.ErrNativePairPolicy
	}
	for _, actual := range []crossNodeGroupEndpointEvidence{sender, receiver} {
		slot := evidence.Plan.SlotA
		if actual.EndpointID != slot.EndpointID {
			slot = evidence.Plan.SlotB
		}
		if err := matchNativePairEndpoint(actual, slot, evidence.Plan); err != nil {
			return true, err
		}
	}
	return true, nil
}

func loadNativePairPeerIdentity(ctx context.Context, state *nodekeys.CryptoState, stateDir, endpointID string, required bool) (*e2ee.Identity, error) {
	if !required {
		return nodekeys.LoadOrCreate(stateDir, endpointID)
	}
	original, err := state.NativePairOriginalLocalKey(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	return loadNativePairPublicationIdentity(stateDir, endpointID, &original)
}

func nativePairGroupRequired(ctx context.Context, stateDir, nodeID, groupID string) (bool, error) {
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
	if err != nil {
		return false, err
	}
	defer state.Close()
	return state.NativePairPolicyRequired(ctx, groupID)
}

func nativePairMessage(kind, messageID, requestID, parent, sender, receiver string, plaintext, ciphertext []byte) (nodekeys.NativePairMessage, error) {
	if kind == "REQUEST" || kind == "ask" {
		kind = "ASK"
	} else if kind == "reply" {
		kind = "REPLY"
	}
	if (kind != "ASK" && kind != "REPLY") || parent != "" || len(plaintext) > 8192 || len(ciphertext) == 0 || len(ciphertext) > 128*1024 {
		return nodekeys.NativePairMessage{}, nodekeys.ErrNativePairBudget
	}
	digest := sha256.Sum256(ciphertext)
	return nodekeys.NativePairMessage{MessageID: messageID, RequestID: requestID, Kind: kind, SenderEndpointID: sender, ReceiverEndpointID: receiver, Digest: hex.EncodeToString(digest[:]), PlaintextBytes: uint64(len(plaintext)), CiphertextBytes: uint64(len(ciphertext))}, nil
}

// The caller holds the original physical writer. Existing reservations can
// settle only an outcome that writer already recorded, never a new invocation.
func reserveNativePairQueueAdmission(ctx context.Context, stateDir, nodeID string, authorization crossNodeGroupDeliveryAuthorization, message nodekeys.NativePairMessage, nativeID string) error {
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
	if err != nil {
		return err
	}
	defer state.Close()
	required, err := verifyNativePairPeerTarget(ctx, state, machinePinnedHubID(ctx), authorization.Receiver.GroupID, authorization.NativePairEvidence, authorization.NativePairCurrent, authorization.Sender, authorization.Receiver)
	if err != nil || !required {
		return err
	}
	previous, writerHeld := ctx.Value(machineNativeWriterOutcomeKey{}).(nodelock.NativeOutcomeState)
	if !writerHeld {
		return errors.New("native Pair submission is missing its held original writer outcome")
	}
	existing, err := state.ReserveNativePairSubmission(ctx, *authorization.NativePairEvidence, message, nativeID, time.Now().UTC())
	if err != nil {
		return err
	}
	if existing && previous != nodelock.NativeQueueAccepted && previous != nodelock.NativeUncertain && previous != nodelock.NativeInjecting {
		return errors.New("native Pair submission already reserved; original writer has no accepted or uncertain invocation to reconcile")
	}
	return nil
}

func verifyNativePairDeliveryTarget(ctx context.Context, stateDir, nodeID string, authorization crossNodeGroupDeliveryAuthorization) (bool, error) {
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
	if err != nil {
		return false, err
	}
	defer state.Close()
	return verifyNativePairPeerTarget(ctx, state, machinePinnedHubID(ctx), authorization.Receiver.GroupID, authorization.NativePairEvidence, authorization.NativePairCurrent, authorization.Sender, authorization.Receiver)
}

// A fresh live observation has a new timestamp. All authority coordinates still
// match exactly; each observation is independently verified before comparison.
func sameNativePairDeliveryAuthority(a, b crossNodeGroupDeliveryAuthorization) bool {
	if a.NativePairCurrent != nil {
		current := *a.NativePairCurrent
		current.ObservedAt = ""
		a.NativePairCurrent = &current
	}
	if b.NativePairCurrent != nil {
		current := *b.NativePairCurrent
		current.ObservedAt = ""
		b.NativePairCurrent = &current
	}
	return reflect.DeepEqual(a, b)
}
