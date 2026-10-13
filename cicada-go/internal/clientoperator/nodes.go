package clientoperator

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// NodeCandidate mirrors the current nodes.preview response, without granting
// authority to the public code or treating a short key ID as a complete pin.
type NodeCandidate struct {
	RequestID                 string `json:"request_id"`
	Version                   int64  `json:"version"`
	Mode                      string `json:"mode"`
	HubID                     string `json:"hub_id"`
	NodeID                    string `json:"node_id"`
	NodeName                  string `json:"node_name"`
	NodeKeyID                 string `json:"node_key_id"`
	NodeKeyFingerprint        string `json:"node_key_fingerprint"`
	HubNodeControlKeyID       string `json:"hub_node_control_key_id"`
	HubNodeControlKeyVersion  uint64 `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string `json:"hub_node_control_fingerprint"`
	NodeKeyEpoch              uint64 `json:"node_key_epoch"`
	CandidateDigest           string `json:"candidate_digest"`
	ExpiresAt                 string `json:"expires_at"`
	State                     string `json:"state"`
	BindingID                 string `json:"binding_id,omitempty"`
	BindingVersion            uint64 `json:"binding_version,omitempty"`
}
type NodeReview struct {
	Code      string        `json:"code"`
	Candidate NodeCandidate `json:"candidate"`
}

var ErrUpgradeReview = errors.New("Node key upgrade confirmation is unavailable: current preview omits the exact target binding/version; use the established Owner-approved upgrade flow")

func digestValid(value string) bool {
	b, e := hex.DecodeString(value)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == value
}
func validCandidate(c NodeCandidate, hubID string) bool {
	_, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	return err == nil && (c.Mode == "INITIAL" || c.Mode == "UPGRADE") && c.HubID == hubID && c.RequestID != "" && c.Version > 0 && c.NodeID != "" && c.NodeName != "" &&
		c.NodeKeyID != "" && c.HubNodeControlKeyID != "" && c.HubNodeControlKeyVersion > 0 && c.NodeKeyEpoch > 0 &&
		digestValid(c.NodeKeyFingerprint) && digestValid(c.HubNodeControlFingerprint) && digestValid(c.CandidateDigest)
}

func (p *Profile) PreviewNode(ctx context.Context, code string) (*Response, error) {
	if p.state.Pending != nil {
		return nil, ErrPending
	}
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.NewReplacer("-", "", " ", "").Replace(code)
	if len(code) != 12 || strings.ContainsAny(code, "\r\n\t") {
		return nil, errors.New("invalid Node device code")
	}
	for _, c := range code {
		if !strings.ContainsRune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ", c) {
			return nil, errors.New("invalid Node device code")
		}
	}
	p.state.Review = &NodeReview{Code: code}
	return p.call(ctx, "nodes.preview", struct {
		Code string `json:"user_code"`
	}{code})
}

func (p *Profile) NodeReview() (NodeCandidate, error) {
	if p.state.Pending != nil {
		return NodeCandidate{}, ErrPending
	}
	if p.state.Review == nil || !validCandidate(p.state.Review.Candidate, p.state.Hub.HubID) {
		return NodeCandidate{}, errors.New("preview the exact Node candidate first")
	}
	return p.state.Review.Candidate, nil
}

// ConfirmNode consumes only a previously reviewed tuple. The CLI obtains the
// explicit approval gesture; other callers must provide the same reviewed tuple.
func (p *Profile) ConfirmNode(ctx context.Context, reviewed NodeCandidate) (*Response, error) {
	if p.state.Uncertain {
		return nil, ErrUncertain
	}
	current, err := p.NodeReview()
	if err != nil {
		return nil, err
	}
	if current.Mode == "UPGRADE" && (current.BindingID == "" || current.BindingVersion == 0) {
		return nil, ErrUpgradeReview
	}
	if current != reviewed {
		return nil, errors.New("Node candidate changed after review")
	}
	expiry, err := time.Parse(time.RFC3339Nano, current.ExpiresAt)
	if err != nil || !time.Now().Before(expiry) || current.State != "PENDING" {
		return nil, errors.New("Node candidate is not pending or has expired")
	}
	return p.call(ctx, "nodes.confirm", struct {
		Code    string `json:"user_code"`
		Digest  string `json:"candidate_digest"`
		Version int64  `json:"candidate_version"`
	}{p.state.Review.Code, current.CandidateDigest, current.Version})
}
