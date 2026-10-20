package appui

import (
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

// PublicField is one complete display value, never a serialized snapshot,
// credential, proof or key blob. Key selects only the translated caption.
type PublicField struct {
	Key   string
	Value string
}

func presentPublicFields(fields ...PublicField) []PublicField {
	var result []PublicField
	for _, field := range fields {
		if field.Value != "" {
			result = append(result, field)
		}
	}
	return result
}

func AccountPublicFields(s appcore.Snapshot, now time.Time) []PublicField {
	if !AccountInformationVisible(s, now) {
		return nil
	}
	return presentPublicFields(
		PublicField{"hub.origin", s.Hub.Origin},
		PublicField{"hub.identity", s.Hub.HubID},
		PublicField{"hub.fingerprint", s.Hub.Fingerprint},
		PublicField{"account.id", s.Account.AccountID},
		PublicField{"account.owner_id", s.Account.OwnerID},
		PublicField{"account.device_id", s.Account.DeviceID},
		PublicField{"account.owner_fingerprint", s.Account.OwnerFingerprint},
		PublicField{"account.owner_key_id", s.Account.LocalOwnerKeyID},
		PublicField{"account.owner_peer_fingerprint", s.Account.OwnerPeerFingerprint},
	)
}

func NodePublicFields(s appcore.Snapshot, now time.Time) []PublicField {
	if !AccountInformationVisible(s, now) {
		return nil
	}
	var fields []PublicField
	if c := s.Node.Candidate; c != nil {
		fields = append(fields, PublicField{"node.id", c.NodeID},
			PublicField{"node.fingerprint", c.NodeFingerprint}, PublicField{"node.hub_fingerprint", c.HubControlFingerprint})
	} else if b := s.Node.Binding; b != nil {
		fields = append(fields, PublicField{"node.id", b.NodeID})
	}
	if b := s.Node.Binding; b != nil {
		fields = append(fields, PublicField{"node.binding_id", b.ID})
	}
	return presentPublicFields(fields...)
}

func PairPublicFields(s appcore.Snapshot, now time.Time) []PublicField {
	if !AccountInformationVisible(s, now) || s.Pair.PairID == "" {
		return nil
	}
	return presentPublicFields(PublicField{"pair.id", s.Pair.PairID}, PublicField{"pair.node", s.Pair.NodeID})
}

func PairSlotPublicFields(s appcore.Snapshot, index int, review bool, now time.Time) []PublicField {
	if !AccountInformationVisible(s, now) || s.Pair.PairID == "" || index < 0 || index >= len(s.Pair.Slots) {
		return nil
	}
	slot := s.Pair.Slots[index]
	if slot.NativeSessionID == "" {
		return nil
	}
	fields := []PublicField{{"pair.sid", slot.NativeSessionID}, {"pair.fingerprint", slot.CandidateFingerprint}}
	if review {
		fields = append(fields, PublicField{"pair.key_id", slot.CandidateKeyID}, PublicField{"pair.target_digest", slot.TargetDigest})
	}
	return presentPublicFields(fields...)
}
