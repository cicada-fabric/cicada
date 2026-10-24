package hubaccountwire

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestNodePairTrustClosedContractInventory(t *testing.T) {
	raw, err := os.ReadFile("node-pair-trust-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Revision             string              `json:"contract_revision"`
		Format               string              `json:"format"`
		Packet               string              `json:"packet_format"`
		Code                 string              `json:"code_prefix"`
		Available            bool                `json:"available"`
		Operations           []string            `json:"operations"`
		Fields               map[string][]string `json:"fields"`
		CodeMax              int                 `json:"max_code_bytes"`
		ReceiptMax           int                 `json:"max_original_receipt_bytes"`
		ReconcileResponseMax int                 `json:"reconcile_response_packet_bytes"`
		Observations         []string            `json:"observation_operations"`
		CancelTerminals      []string            `json:"cancel_terminal_states"`
		CancelReceipt        bool                `json:"owner_cancel_acked_initial_requires_original_confirmation_response"`
		FenceOriginalOnly    bool                `json:"reconcile_fences_original_packet_only"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Revision != NodePairTrustContractRevision || m.Format != NodePairTrustFormat || m.Packet != NodePairTrustPacketFormat || m.Code != NodePairTrustCodePrefix || m.Available || NodePairTrustContractCapabilities().Available || m.CodeMax != MaxNodePairTrustCodeBytes || m.ReceiptMax != MaxNodePairTrustOriginalReceiptBytes || m.ReconcileResponseMax != MaxNodePairTrustReconcileResponsePacketBytes {
		t.Fatal("contract inventory drift")
	}
	if !m.CancelReceipt || !m.FenceOriginalOnly || !reflect.DeepEqual(m.Observations, []string{OperationNodePairTrustPoll, OperationNodePairTrustCancel, OperationOwnerNodePairTrustStatus, OperationOwnerNodePairTrustCancel}) || !reflect.DeepEqual(m.CancelTerminals, []string{NodePairTrustCancelled, NodePairTrustExpired, NodePairTrustRevoked, NodePairTrustFenced, NodePairTrustACKed}) {
		t.Fatal("observation, terminal receipt or original-only fence contract drift")
	}
	caps := NodePairTrustContractCapabilities()
	if len(m.Operations) != len(caps.Operations) {
		t.Fatal("closed operation set drift")
	}
	seen := map[string]bool{}
	for _, op := range m.Operations {
		if seen[op] || NodePairTrustHTTPPath(op) == "" || nodePairBody(op) == nil {
			t.Fatal("unknown/duplicate operation", op)
		}
		seen[op] = true
	}
	for _, op := range caps.Operations {
		if !seen[op] {
			t.Fatal("capability not in contract", op)
		}
	}
	types := []any{NodePairTrustCapabilities{}, NodePairTrustContext{}, NodePairTrustApproval{}, NodePairTrustOwnerClaims{}, NodePairTrustOwnerProof{}, NodePairTrustCapsule{}, NodePairTrustPacket{}, NodePairTrustStart{}, NodePairTrustExistingStart{}, NodePairTrustCommit{}, NodePairTrustACK{}, NodePairTrustReconcile{}, NodePairTrustOwnerLookup{}, NodePairTrustOwnerPrepare{}, NodePairTrustOwnerComplete{}, NodePairTrustOwnerStatus{}, NodePairTrustResult{}}
	for _, v := range types {
		typ := reflect.TypeOf(v)
		var fields []string
		for i := 0; i < typ.NumField(); i++ {
			fields = append(fields, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		if !reflect.DeepEqual(fields, m.Fields[typ.Name()]) {
			t.Fatal("DTO declaration order drift", typ.Name())
		}
	}
	for _, op := range caps.Operations {
		typ := reflect.TypeOf(nodePairBody(op)).Elem()
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i).Name
			if f == "OOBSecret" || f == "Code" || f == "UserCode" {
				t.Fatal("HTTP DTO exposes whole secret code/S", op)
			}
		}
	}
}
