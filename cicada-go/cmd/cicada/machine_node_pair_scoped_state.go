package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

const machineNodePairScopedLocalFormat = "cicada.node-pair-scoped-local.v1"
const machineNodePairScopedLocalMax = 8 << 20

type machineNodePairScopedState struct {
	StartNoEffectRetiredAt string                                 `json:"start_no_effect_retired_at,omitempty"`
	PreviousAttemptID      string                                 `json:"previous_attempt_id,omitempty"`
	PreviousAttemptDigest  string                                 `json:"previous_attempt_digest,omitempty"`
	RetryPollPacket        []byte                                 `json:"retry_poll_packet,omitempty"`
	RetryPollBody          *wire.NodePairTrustScopedPoll          `json:"retry_poll_body,omitempty"`
	RetryTerminalReceipt   []byte                                 `json:"retry_terminal_receipt,omitempty"`
	Version                int                                    `json:"version"`
	NodeID                 string                                 `json:"node_id"`
	AttemptID              string                                 `json:"attempt_id"`
	DescriptorText         string                                 `json:"descriptor_text"`
	DialAddress            string                                 `json:"dial_address"`
	Secret                 []byte                                 `json:"oob_secret"`
	Stage                  string                                 `json:"stage"`
	StartOperation         string                                 `json:"start_operation"`
	StartBody              json.RawMessage                        `json:"start_body"`
	Context                *wire.NodePairTrustScopedContext       `json:"context,omitempty"`
	Selector               string                                 `json:"selector,omitempty"`
	OOB                    string                                 `json:"oob_commitment,omitempty"`
	PendingOperation       string                                 `json:"pending_operation,omitempty"`
	PendingPacket          []byte                                 `json:"pending_packet,omitempty"`
	PendingBody            json.RawMessage                        `json:"pending_body,omitempty"`
	ReconcilePacket        []byte                                 `json:"reconcile_packet,omitempty"`
	ReconcileBody          *wire.NodePairTrustScopedReconcile     `json:"reconcile_body,omitempty"`
	PollPacket             []byte                                 `json:"poll_packet,omitempty"`
	PollBody               *wire.NodePairTrustScopedPoll          `json:"poll_body,omitempty"`
	PollReceipt            []byte                                 `json:"poll_receipt,omitempty"`
	OwnerProof             []byte                                 `json:"owner_proof,omitempty"`
	Capsule                []byte                                 `json:"capsule,omitempty"`
	Approval               *wire.NodePairTrustScopedApproval      `json:"approval,omitempty"`
	OwnerPublic            *e2ee.PublicIdentity                   `json:"owner_public_identity,omitempty"`
	TrustAcceptedAt        string                                 `json:"trust_accepted_at,omitempty"`
	ACKPacket              []byte                                 `json:"ack_packet,omitempty"`
	ACKBody                *wire.NodePairTrustScopedACK           `json:"ack_body,omitempty"`
	ACKReceipt             []byte                                 `json:"ack_receipt,omitempty"`
	Binding                *e2ee.OwnerAppNodeBinding              `json:"binding,omitempty"`
	TerminalOriginal       *machineNodePairScopedTerminalOriginal `json:"terminal_original,omitempty"`
	FencedOriginals        []machineNodePairScopedFencedOriginal  `json:"fenced_originals,omitempty"`
}

func (machineNodePairScopedState) String() string   { return "NodePairLocal[redacted]" }
func (machineNodePairScopedState) GoString() string { return "NodePairLocal[redacted]" }

type machineNodePairScopedLocalEnvelope struct {
	Format           string `json:"format"`
	NodeID           string `json:"node_id"`
	NodeKeyID        string `json:"node_key_id"`
	HubID            string `json:"hub_id"`
	AttemptID        string `json:"attempt_id"`
	DescriptorDigest string `json:"descriptor_digest"`
	Packet           []byte `json:"packet"`
}

func machineNodePairScopedStatePath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "node-pair-trust-scoped.sealed.json")
}
func machineNodePairScopedAAD(h machineNodePairScopedLocalEnvelope) []byte {
	h.Packet = nil
	raw, _ := json.Marshal(h)
	return append([]byte("cicada/node-pair-scoped-local/sealed/v1\x00"), raw...)
}
func saveMachineNodePairScopedState(stateDir string, node *e2ee.Identity, s *machineNodePairScopedState) error {
	if node == nil || s == nil || s.Version != 1 || len(s.Secret) != 32 || s.NodeID == "" || !machineNodePairHex(s.AttemptID, 16) {
		return errMachineNodePairState
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return errMachineNodePairState
	}
	path := machineNodePairScopedStatePath(stateDir, s.NodeID)
	if machineNodePairPrivateDirectory(filepath.Dir(path)) != nil {
		return errMachineNodePairState
	}
	if _, e := os.Lstat(path); e == nil {
		raw, e := machineNodePairPrivateRead(path, machineNodePairScopedLocalMax)
		clear(raw)
		if e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return errMachineNodePairState
	}
	plain, e := json.Marshal(s)
	if e != nil || len(plain) > machineNodePairScopedLocalMax/2 {
		return errMachineNodePairState
	}
	defer clear(plain)
	h := machineNodePairScopedLocalEnvelope{Format: machineNodePairScopedLocalFormat, NodeID: s.NodeID, NodeKeyID: node.Public().ID, HubID: d.Claims.Hub.HubID, AttemptID: s.AttemptID, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(s.DescriptorText)}
	h.Packet, e = e2ee.Seal(node, node.Public(), plain, machineNodePairScopedAAD(h), 1)
	if e != nil {
		return errMachineNodePairState
	}
	raw, e := json.Marshal(h)
	if e != nil || len(raw) > machineNodePairScopedLocalMax {
		return errMachineNodePairState
	}
	return persistNodeSecretFile(path, raw, ".node-pair-sealed-*")
}
func loadMachineNodePairScopedState(stateDir, nodeID string, node *e2ee.Identity) (*machineNodePairScopedState, error) {
	if node == nil {
		return nil, errMachineNodePairState
	}
	return loadMachineNodePairScopedStateAtPath(machineNodePairScopedStatePath(stateDir, nodeID), nodeID, node)
}
func loadMachineNodePairScopedStateAtPath(path, nodeID string, node *e2ee.Identity) (*machineNodePairScopedState, error) {
	raw, e := machineNodePairPrivateRead(path, machineNodePairScopedLocalMax)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var h machineNodePairScopedLocalEnvelope
	if machineNodePairStrictJSON(raw, &h) != nil || h.Format != machineNodePairScopedLocalFormat || h.NodeID != nodeID || h.NodeKeyID != node.Public().ID || !machineNodePairHex(h.AttemptID, 16) {
		return nil, errMachineNodePairState
	}
	plain, seq, e := e2ee.Open(node, node.Public(), h.Packet, machineNodePairScopedAAD(h))
	if e != nil || seq != 1 {
		return nil, errMachineNodePairState
	}
	defer clear(plain)
	var s machineNodePairScopedState
	if machineNodePairStrictJSON(plain, &s) != nil || s.Version != 1 || s.NodeID != nodeID || s.AttemptID != h.AttemptID || len(s.Secret) != 32 || wire.NodePairTrustScopedDescriptorDigest(s.DescriptorText) != h.DescriptorDigest {
		return nil, errMachineNodePairState
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil || d.Claims.Hub.HubID != h.HubID {
		return nil, errMachineNodePairState
	}
	if s.Context != nil && (s.Context.AuthorityNodeID != nodeID || wire.ValidateNodePairTrustScopedContext(*s.Context, time.Time{}) != nil) {
		return nil, errMachineNodePairState
	}
	return &s, nil
}

type machineNodePairScopedFencedOriginal struct {
	Operation   string                             `json:"operation"`
	Packet      []byte                             `json:"packet"`
	Body        json.RawMessage                    `json:"body"`
	QueryPacket []byte                             `json:"query_packet,omitempty"`
	QueryBody   *wire.NodePairTrustScopedReconcile `json:"query_body,omitempty"`
	Receipt     []byte                             `json:"receipt"`
}

type machineNodePairScopedTerminalOriginal struct {
	Operation string          `json:"operation"`
	Packet    []byte          `json:"packet"`
	Body      json.RawMessage `json:"body"`
	Receipt   []byte          `json:"receipt"`
	State     string          `json:"state"`
	ErrorCode string          `json:"error_code"`
}
