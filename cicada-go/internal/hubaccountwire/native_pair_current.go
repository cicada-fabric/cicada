package hubaccountwire

import (
	"encoding/json"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func nativePairCurrentShape(c NativePairPeerCurrent) error {
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > MaxNativePairPeerCurrentBytes || c.State != "CURRENT" ||
		!nativePairPositive(c.ControlRevision) || validateCanonicalTime(c.ObservedAt) != nil ||
		c.Sender.Slot == c.Receiver.Slot {
		return ErrInvalid
	}
	for _, s := range []NativePairCurrentSlot{c.Sender, c.Receiver} {
		if (s.Slot != "A" && s.Slot != "B") || s.Generation == 0 || s.Generation > MaxNativePairSlotGenerations ||
			!isHex(s.AttemptID, RequestIDBytes) || !nativePairToken(s.NativeSessionID) ||
			!nativePairToken(s.NetworkAccessBindingID) || !nativePairToken(s.LeaseOwner) ||
			!nativePairPositive(s.NetworkAccessEpoch) || !nativePairPositive(s.NetworkMembershipRevision) ||
			!nativePairPositive(s.EndpointNetworkRevision) || validateCanonicalTime(s.LeaseCeiling) != nil {
			return ErrInvalid
		}
	}
	return nil
}

// required comes from the persisted policy marker or authoritative Group,
// never from a peer-supplied flag. Legacy carriers keep both additions absent.
func VerifyNativePairPeerAuthorization(required bool, evidence *NativePairPeerEvidence, current *NativePairPeerCurrent,
	hub HubIdentity, trustedOwner e2ee.PublicIdentity, expectedNodeTupleDigest, senderEndpointID, receiverEndpointID string, now time.Time) error {
	if !required {
		if evidence == nil && current == nil {
			return nil
		}
		return ErrInvalid
	}
	if evidence == nil || current == nil || VerifyNativePairPeerEvidence(*evidence, hub, trustedOwner, expectedNodeTupleDigest, now) != nil {
		return ErrInvalid
	}
	return ValidateNativePairPeerCurrent(*current, evidence.Plan, senderEndpointID, receiverEndpointID, now)
}

func DecodeNativePairPeerCurrent(raw []byte) (NativePairPeerCurrent, error) {
	var c NativePairPeerCurrent
	if decodeCanonical(raw, MaxNativePairPeerCurrentBytes, &c) != nil || nativePairCurrentShape(c) != nil {
		return NativePairPeerCurrent{}, ErrInvalid
	}
	return c, nil
}

// ValidateNativePairPeerCurrent compares independent live coordinates with the
// approved Plan in either direction. The containing old Sender/Receiver DTOs
// must separately match its endpoint/principal/key/binding and projected
// membership revisions. Callers must also verify NativePairPeerEvidence using
// their independent original Owner pin; CURRENT is not a signature or a lease.
func ValidateNativePairPeerCurrent(c NativePairPeerCurrent, p NativePairConsentPlan,
	senderEndpointID, receiverEndpointID string, now time.Time) error {
	if now.IsZero() || nativePairCurrentShape(c) != nil || c.ControlRevision < p.ExpectedRevision ||
		senderEndpointID == receiverEndpointID {
		return ErrInvalid
	}
	observed, err := parseCanonicalUTC(c.ObservedAt)
	end, ee := parseCanonicalUTC(p.PeerExpiresAt)
	if err != nil || ee != nil || observed.After(now.Add(30*time.Second)) || !observed.Before(end) || !now.Before(end) {
		return ErrInvalid
	}
	for i, actual := range []NativePairCurrentSlot{c.Sender, c.Receiver} {
		approved := p.SlotA
		if actual.Slot == "B" {
			approved = p.SlotB
		}
		endpoint := senderEndpointID
		if i == 1 {
			endpoint = receiverEndpointID
		}
		if endpoint != approved.EndpointID || actual.Generation != approved.Generation ||
			actual.AttemptID != approved.AttemptID || actual.NativeSessionID != approved.NativeSessionID ||
			actual.NetworkAccessBindingID != approved.NetworkAccessBindingID || actual.NetworkAccessEpoch != approved.NetworkAccessEpoch ||
			actual.NetworkMembershipRevision != approved.NetworkMembershipRevision || actual.EndpointNetworkRevision != approved.EndpointNetworkRevision ||
			actual.LeaseOwner != approved.LeaseOwner || actual.LeaseCeiling != approved.LeaseCeiling {
			return ErrInvalid
		}
		ceiling, err := parseCanonicalUTC(actual.LeaseCeiling)
		if err != nil || !now.Before(ceiling) || ceiling.After(end) {
			return ErrInvalid
		}
	}
	return nil
}
