package nodewire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// PairingCandidateBasis is the original Store candidate's exact JSON shape,
// order and domain. Moving this pure hash lets the Node verify its original
// credential digest without copying or changing the frozen algorithm.
type PairingCandidateBasis struct {
	RequestID          string              `json:"request_id"`
	Version            int64               `json:"version"`
	Mode               string              `json:"mode"`
	HubID              string              `json:"hub_id"`
	NodeID             string              `json:"node_id"`
	NodeName           string              `json:"node_name"`
	CredentialDigest   string              `json:"credential_digest"`
	CodeDigest         string              `json:"code_digest"`
	NodePublicIdentity e2ee.PublicIdentity `json:"node_public_identity"`
	NodeFingerprint    string              `json:"node_fingerprint"`
	HubPublicIdentity  e2ee.PublicIdentity `json:"hub_public_identity"`
	HubKeyVersion      uint64              `json:"hub_key_version"`
	HubFingerprint     string              `json:"hub_fingerprint"`
	NodeKeyEpoch       uint64              `json:"node_key_epoch"`
	TargetBindingID    string              `json:"target_binding_id"`
	ExpiresAt          string              `json:"expires_at"`
}

func PairingCandidateDigest(b PairingCandidateBasis) (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("cicada/node-control/candidate/v1\x00"), raw...))
	return hex.EncodeToString(h[:]), nil
}
