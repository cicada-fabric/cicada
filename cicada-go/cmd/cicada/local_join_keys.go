package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

// publishJoinedLocalEndpointKey makes explicit Join sufficient for same-Node
// sealed delivery. The private key remains in the Node's owner-only state;
// Hub receives a self-attested public candidate for its current binding.
// Candidate publication is not a cross-owner trust decision or Link approval.
func (b *machineAgentJoinBridge) publishJoinedLocalEndpointKey(joined *fabric.JoinResult) error {
	if joined == nil || joined.SessionToken == "" || joined.Endpoint.ID == "" ||
		joined.Endpoint.GroupID == "" || joined.BindingID == "" || joined.BindingEpoch == 0 {
		return errors.New("local Join did not return a complete Endpoint binding")
	}
	card, err := b.verifyCurrentMCPBinding(joined.SessionToken, joined.Endpoint.GroupID)
	if err != nil {
		return err
	}
	if card.EndpointID != joined.Endpoint.ID || card.BindingID != joined.BindingID ||
		card.BindingEpoch != joined.BindingEpoch || card.NodeID != b.nodeID ||
		card.PrincipalID == "" || card.NativeSessionID == "" ||
		card.NativeSessionID != joined.Endpoint.NativeSessionID ||
		harness.Canonical(card.Harness) != "codex" {
		return errors.New("local Join key publication requires the current native binding")
	}
	identity, err := nodekeys.LoadOrCreate(machineNodeStateDir(b.stateDir, b.nodeID), card.EndpointID)
	if err != nil {
		return fmt.Errorf("load joined Endpoint key: %w", err)
	}
	proof, err := identity.SignEndpointKeyAttestation(card.EndpointID, card.PrincipalID,
		card.NodeID, card.BindingID, card.BindingEpoch)
	if err != nil {
		return fmt.Errorf("attest joined Endpoint key: %w", err)
	}
	payload, err := json.Marshal(struct {
		Attestation json.RawMessage `json:"attestation"`
	}{Attestation: json.RawMessage(proof)})
	if err != nil {
		return err
	}
	data, err := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/endpoint-keys", payload,
		"CicadaSession "+joined.SessionToken, joined.Endpoint.GroupID)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var candidate store.EndpointKeyCandidate
	if err := decoder.Decode(&candidate); err != nil {
		return errors.New("Hub returned an invalid joined Endpoint key candidate")
	}
	if err := validateMCPCurrentCandidate(candidate, card, strings.TrimSpace(joined.Endpoint.Owner)); err != nil {
		return err
	}
	if !sameMCPKeyPublic(candidate.Public, identity.Public()) {
		return errors.New("Hub returned a different public key for the joined Endpoint")
	}
	return nil
}
