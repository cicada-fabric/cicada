package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

const machineNodePairLocalFormat = "cicada.node-pair-local.v1"
const machineNodePairLocalMax = 8 << 20

var errMachineNodePairState = errors.New("original protected Node pairing state is unavailable or conflicts; refusing replacement")

type machineNodePairState struct {
	StartNoEffectRetiredAt string                           `json:"start_no_effect_retired_at,omitempty"`
	PreviousAttemptID      string                           `json:"previous_attempt_id,omitempty"`
	PreviousAttemptDigest  string                           `json:"previous_attempt_digest,omitempty"`
	RetryPollPacket        []byte                           `json:"retry_poll_packet,omitempty"`
	RetryPollBody          *wire.NodePairTrustPoll          `json:"retry_poll_body,omitempty"`
	RetryTerminalReceipt   []byte                           `json:"retry_terminal_receipt,omitempty"`
	Version                int                              `json:"version"`
	NodeID                 string                           `json:"node_id"`
	AttemptID              string                           `json:"attempt_id"`
	DescriptorText         string                           `json:"descriptor_text"`
	DialAddress            string                           `json:"dial_address"`
	Secret                 []byte                           `json:"oob_secret"`
	Stage                  string                           `json:"stage"`
	StartOperation         string                           `json:"start_operation"`
	StartBody              json.RawMessage                  `json:"start_body"`
	Context                *wire.NodePairTrustContext       `json:"context,omitempty"`
	Selector               string                           `json:"selector,omitempty"`
	OOB                    string                           `json:"oob_commitment,omitempty"`
	PendingOperation       string                           `json:"pending_operation,omitempty"`
	PendingPacket          []byte                           `json:"pending_packet,omitempty"`
	PendingBody            json.RawMessage                  `json:"pending_body,omitempty"`
	ReconcilePacket        []byte                           `json:"reconcile_packet,omitempty"`
	ReconcileBody          *wire.NodePairTrustReconcile     `json:"reconcile_body,omitempty"`
	PollPacket             []byte                           `json:"poll_packet,omitempty"`
	PollBody               *wire.NodePairTrustPoll          `json:"poll_body,omitempty"`
	PollReceipt            []byte                           `json:"poll_receipt,omitempty"`
	OwnerProof             []byte                           `json:"owner_proof,omitempty"`
	Capsule                []byte                           `json:"capsule,omitempty"`
	Approval               *wire.NodePairTrustApproval      `json:"approval,omitempty"`
	OwnerPublic            *e2ee.PublicIdentity             `json:"owner_public_identity,omitempty"`
	TrustAcceptedAt        string                           `json:"trust_accepted_at,omitempty"`
	ACKPacket              []byte                           `json:"ack_packet,omitempty"`
	ACKBody                *wire.NodePairTrustACK           `json:"ack_body,omitempty"`
	ACKReceipt             []byte                           `json:"ack_receipt,omitempty"`
	Binding                *e2ee.OwnerAppNodeBinding        `json:"binding,omitempty"`
	TerminalOriginal       *machineNodePairTerminalOriginal `json:"terminal_original,omitempty"`
	FencedOriginals        []machineNodePairFencedOriginal  `json:"fenced_originals,omitempty"`
}

func (machineNodePairState) String() string   { return "NodePairLocal[redacted]" }
func (machineNodePairState) GoString() string { return "NodePairLocal[redacted]" }

type machineNodePairLocalEnvelope struct {
	Format           string `json:"format"`
	NodeID           string `json:"node_id"`
	NodeKeyID        string `json:"node_key_id"`
	HubID            string `json:"hub_id"`
	AttemptID        string `json:"attempt_id"`
	DescriptorDigest string `json:"descriptor_digest"`
	Packet           []byte `json:"packet"`
}

func machineNodePairStatePath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "node-pair-trust.sealed.json")
}
func machineNodePairOwned(info os.FileInfo) bool {
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	uid := v.Elem().FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(os.Geteuid())
}
func machineNodePairPrivateDirectory(path string) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return errMachineNodePairState
	}
	resolved, e := filepath.EvalSymlinks(abs)
	if e != nil || resolved != abs {
		return errMachineNodePairState
	}
	info, e := os.Lstat(abs)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !machineNodePairOwned(info) {
		return errMachineNodePairState
	}
	return nil
}
func machineNodePairPrivateRead(path string, max int64) ([]byte, error) {
	if machineNodePairPrivateDirectory(filepath.Dir(path)) != nil {
		return nil, errMachineNodePairState
	}
	info, e := os.Lstat(path)
	if e != nil || !machineNodePairOwned(info) {
		return nil, errMachineNodePairState
	}
	raw, e := clientoperator.ReadPrivateFile(path, max)
	if e != nil {
		return nil, errMachineNodePairState
	}
	return raw, nil
}
func machineNodePairAAD(h machineNodePairLocalEnvelope) []byte {
	h.Packet = nil
	raw, _ := json.Marshal(h)
	return append([]byte("cicada/node-pair-local/sealed/v1\x00"), raw...)
}
func machineNodePairStrictJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errMachineNodePairState
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errMachineNodePairState
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return errMachineNodePairState
	}
	return nil
}
func saveMachineNodePairState(stateDir string, node *e2ee.Identity, s *machineNodePairState) error {
	if node == nil || s == nil || s.Version != 1 || len(s.Secret) != 32 || s.NodeID == "" || !machineNodePairHex(s.AttemptID, 16) {
		return errMachineNodePairState
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return errMachineNodePairState
	}
	path := machineNodePairStatePath(stateDir, s.NodeID)
	if machineNodePairPrivateDirectory(filepath.Dir(path)) != nil {
		return errMachineNodePairState
	}
	if _, e := os.Lstat(path); e == nil {
		raw, e := machineNodePairPrivateRead(path, machineNodePairLocalMax)
		clear(raw)
		if e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return errMachineNodePairState
	}
	plain, e := json.Marshal(s)
	if e != nil || len(plain) > machineNodePairLocalMax/2 {
		return errMachineNodePairState
	}
	defer clear(plain)
	h := machineNodePairLocalEnvelope{Format: machineNodePairLocalFormat, NodeID: s.NodeID, NodeKeyID: node.Public().ID, HubID: d.Claims.Hub.HubID, AttemptID: s.AttemptID, DescriptorDigest: wire.NodePairTrustDescriptorDigest(s.DescriptorText)}
	h.Packet, e = e2ee.Seal(node, node.Public(), plain, machineNodePairAAD(h), 1)
	if e != nil {
		return errMachineNodePairState
	}
	raw, e := json.Marshal(h)
	if e != nil || len(raw) > machineNodePairLocalMax {
		return errMachineNodePairState
	}
	return persistNodeSecretFile(path, raw, ".node-pair-sealed-*")
}
func loadMachineNodePairState(stateDir, nodeID string, node *e2ee.Identity) (*machineNodePairState, error) {
	if node == nil {
		return nil, errMachineNodePairState
	}
	return loadMachineNodePairStateAtPath(machineNodePairStatePath(stateDir, nodeID), nodeID, node)
}
func loadMachineNodePairStateAtPath(path, nodeID string, node *e2ee.Identity) (*machineNodePairState, error) {
	raw, e := machineNodePairPrivateRead(path, machineNodePairLocalMax)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var h machineNodePairLocalEnvelope
	if machineNodePairStrictJSON(raw, &h) != nil || h.Format != machineNodePairLocalFormat || h.NodeID != nodeID || h.NodeKeyID != node.Public().ID || !machineNodePairHex(h.AttemptID, 16) {
		return nil, errMachineNodePairState
	}
	plain, seq, e := e2ee.Open(node, node.Public(), h.Packet, machineNodePairAAD(h))
	if e != nil || seq != 1 {
		return nil, errMachineNodePairState
	}
	defer clear(plain)
	var s machineNodePairState
	if machineNodePairStrictJSON(plain, &s) != nil || s.Version != 1 || s.NodeID != nodeID || s.AttemptID != h.AttemptID || len(s.Secret) != 32 || wire.NodePairTrustDescriptorDigest(s.DescriptorText) != h.DescriptorDigest {
		return nil, errMachineNodePairState
	}
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil || d.Claims.Hub.HubID != h.HubID {
		return nil, errMachineNodePairState
	}
	return &s, nil
}

func machineNodePairNoSymlinkPath(path string) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return errMachineNodePairState
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return errMachineNodePairState
		}
		if e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errMachineNodePairState
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

type machineNodePairFencedOriginal struct {
	Operation   string                       `json:"operation"`
	Packet      []byte                       `json:"packet"`
	Body        json.RawMessage              `json:"body"`
	QueryPacket []byte                       `json:"query_packet,omitempty"`
	QueryBody   *wire.NodePairTrustReconcile `json:"query_body,omitempty"`
	Receipt     []byte                       `json:"receipt"`
}

func machineNodePairHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}

type machineNodePairTerminalOriginal struct {
	Operation string          `json:"operation"`
	Packet    []byte          `json:"packet"`
	Body      json.RawMessage `json:"body"`
	Receipt   []byte          `json:"receipt"`
	State     string          `json:"state"`
	ErrorCode string          `json:"error_code"`
}
