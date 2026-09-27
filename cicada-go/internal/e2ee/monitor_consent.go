package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const MonitorBroadcastConsentVersion = 1

const monitorBroadcastConsentDomain = "cicada/client/monitor-broadcast/consent/v1\x00"

// MonitorBroadcastConsentEndpoint contains the identity and key facts a user
// approves. Its order in Recipients is part of the signed consent digest.
type MonitorBroadcastConsentEndpoint struct {
	EndpointID         string `json:"endpoint_id"`
	PrincipalID        string `json:"principal_id"`
	OwnerID            string `json:"owner_id"`
	NodeID             string `json:"node_id"`
	MembershipRevision int64  `json:"membership_revision"`
	GroupJoinRevision  int64  `json:"group_join_revision"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	KeyID              string `json:"key_id"`
	KeyVersion         int64  `json:"key_version"`
	KeyFingerprint     string `json:"key_fingerprint"`
	KeyProofDigest     string `json:"key_proof_digest"`
}

type MonitorBroadcastConsentScope struct {
	Version       int                               `json:"version"`
	BroadcastID   string                            `json:"broadcast_id"`
	GroupID       string                            `json:"group_id"`
	GroupRevision int64                             `json:"group_revision"`
	Source        MonitorBroadcastConsentEndpoint   `json:"source"`
	Recipients    []MonitorBroadcastConsentEndpoint `json:"recipients"`
}

// MonitorBroadcastConsentDigest is independently reproducible from the public
// ordered cards. The Hub and Node must both derive cards from the stored
// snapshot; an opaque snapshot hash alone cannot express user consent.
func MonitorBroadcastConsentDigest(scope MonitorBroadcastConsentScope) (string, error) {
	if scope.Version != MonitorBroadcastConsentVersion || scope.Recipients == nil || len(scope.Recipients) > 32 ||
		!monitorBroadcastID(scope.BroadcastID) || !monitorBroadcastID(scope.GroupID) || scope.GroupRevision <= 0 {
		return "", ErrInvalidEnvelope
	}
	valid := func(card MonitorBroadcastConsentEndpoint) bool {
		return monitorBroadcastID(card.EndpointID) && monitorBroadcastID(card.PrincipalID) &&
			monitorBroadcastID(card.OwnerID) && monitorBroadcastID(card.NodeID) &&
			monitorBroadcastID(card.BindingID) && card.BindingEpoch > 0 &&
			card.MembershipRevision > 0 && card.GroupJoinRevision > 0 &&
			monitorBroadcastID(card.KeyID) && card.KeyVersion > 0 &&
			strings.HasPrefix(card.KeyFingerprint, "sha256:") &&
			monitorBroadcastDigest(strings.TrimPrefix(card.KeyFingerprint, "sha256:")) &&
			monitorBroadcastDigest(card.KeyProofDigest)
	}
	if !valid(scope.Source) {
		return "", ErrInvalidEnvelope
	}
	seen := map[string]bool{scope.Source.EndpointID: true}
	last := ""
	for _, card := range scope.Recipients {
		if !valid(card) || card.OwnerID != scope.Source.OwnerID || seen[card.EndpointID] || (last != "" && card.EndpointID <= last) {
			return "", errors.New("invalid Monitor consent recipient order or key")
		}
		seen[card.EndpointID] = true
		last = card.EndpointID
	}
	encoded, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(monitorBroadcastConsentDomain), encoded...))
	return hex.EncodeToString(sum[:]), nil
}
