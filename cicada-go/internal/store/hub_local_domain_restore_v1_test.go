package store

import (
	"encoding/json"
	"errors"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These values are visibly synthetic restore metadata, never deployment keys.
func syntheticLocalDomainCheckpoint(t *testing.T) *HubRestoreCheckpoint {
	t.Helper()
	cp := syntheticHubCheckpoint()
	for _, table := range localDomainRestoreTables {
		cp.Tables = append(cp.Tables, table)
		cp.rows[table] = map[string]map[string]any{}
	}
	cp.rows["hub_local_domain_epochs_v1"]["epoch"] = map[string]any{"epoch": int64(9)}
	cp.rows["hub_local_domains_v1"]["policy"] = map[string]any{
		"policy_id": "synthetic-policy", "state": "ACTIVE", "revision": int64(2),
		"policy_json": "synthetic-original-policy", "policy_proof": "synthetic-original-proof", "hub_identity_json": "synthetic-original-Hub",
	}
	m := wire.LocalDomainMember{MemberID: "synthetic-member", Revision: 2, State: "ACTIVE", NativeSessionID: "synthetic-SID", Workspace: "/synthetic/cwd", BindingID: "synthetic-binding", BindingEpoch: 7, NetworkAccessBindingID: "synthetic-access", NetworkAccessEpoch: 8, MembershipRevision: 2, CandidateVersion: 1, CandidateKeyID: "synthetic-key", CandidateFingerprint: "synthetic-fingerprint", LeaseOwner: "synthetic-writer"}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	cp.rows["hub_local_domain_members_v1"]["member"] = map[string]any{"member_id": m.MemberID, "access_id": m.NetworkAccessBindingID, "member_json": string(raw), "state": "ACTIVE", "revision": int64(2)}
	cp.rows["hub_local_domain_challenges_v1"]["challenge"] = map[string]any{"challenge_id": "synthetic-challenge", "state": "COMPLETED", "challenge_json": "synthetic-original-challenge"}
	for _, table := range []string{"hub_local_domain_owner_operations_v1", "hub_local_domain_node_operations_v1"} {
		cp.rows[table]["receipt"] = map[string]any{"state": "REJECTED_FENCED", "request_digest": "synthetic-original-request", "response_packet": "synthetic-original-response"}
	}
	return cp
}

func TestLocalDomainRestorePreservesAuthorityReceiptsAndMemberCoordinates(t *testing.T) {
	for _, fault := range []struct {
		name, table, key, field string
		value                   any
		remove                  bool
	}{
		{"epoch rollback", "hub_local_domain_epochs_v1", "epoch", "epoch", int64(8), false},
		{"Owner policy replacement", "hub_local_domains_v1", "policy", "policy_json", "synthetic-new-policy", false},
		{"Owner proof replacement", "hub_local_domains_v1", "policy", "policy_proof", "synthetic-new-proof", false},
		{"Hub identity replacement", "hub_local_domains_v1", "policy", "hub_identity_json", "synthetic-new-Hub", false},
		{"policy revival", "hub_local_domains_v1", "policy", "state", "PREPARED", false},
		{"member revival", "hub_local_domain_members_v1", "member", "state", "JOINED_ZERO", false},
		{"challenge revival", "hub_local_domain_challenges_v1", "challenge", "state", "PREPARED", false},
		{"Owner fence loss", "hub_local_domain_owner_operations_v1", "receipt", "", nil, true},
		{"Node fence loss", "hub_local_domain_node_operations_v1", "receipt", "", nil, true},
		{"Owner response replacement", "hub_local_domain_owner_operations_v1", "receipt", "response_packet", "synthetic-new-response", false},
		{"Node response replacement", "hub_local_domain_node_operations_v1", "receipt", "response_packet", "synthetic-new-response", false},
	} {
		t.Run(fault.name, func(t *testing.T) {
			base, next := syntheticLocalDomainCheckpoint(t), syntheticLocalDomainCheckpoint(t)
			if fault.remove {
				delete(next.rows[fault.table], fault.key)
			} else {
				next.rows[fault.table][fault.key][fault.field] = fault.value
			}
			if err := CompareHubRestoreCoverage(base, next); !errors.Is(err, ErrHubRestoreCoverage) {
				t.Fatal("restore accepted lost or replaced domain history", err)
			}
		})
	}
	for _, field := range []string{"native_session_id", "workspace", "binding_id", "binding_epoch", "network_access_binding_id", "network_access_epoch", "lease_owner", "candidate_key_id"} {
		t.Run("member JSON "+field, func(t *testing.T) {
			base, next := syntheticLocalDomainCheckpoint(t), syntheticLocalDomainCheckpoint(t)
			row := next.rows["hub_local_domain_members_v1"]["member"]
			var m map[string]any
			if err := json.Unmarshal([]byte(row["member_json"].(string)), &m); err != nil {
				t.Fatal(err)
			}
			if field == "binding_epoch" || field == "network_access_epoch" {
				m[field] = float64(99)
			} else {
				m[field] = "synthetic-replaced"
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			row["member_json"], row["revision"] = string(raw), int64(3)
			if err := CompareHubRestoreCoverage(base, next); !errors.Is(err, ErrHubRestoreCoverage) {
				t.Fatal("restore accepted rewritten member coordinates", err)
			}
		})
	}
}

func TestLocalDomainRestoreAllowsCacheEvictionButRetainsBurnedSequences(t *testing.T) {
	base, next := syntheticLocalDomainCheckpoint(t), syntheticLocalDomainCheckpoint(t)
	for _, table := range localDomainRestoreTables {
		if localDomainRestoreCache(table) {
			base.rows[table]["expired"] = map[string]any{"synthetic": "bounded-cache"}
		}
	}
	base.rows["node_control_rpc_inbox_v1"]["read"] = map[string]any{"state": "COMPLETE", "operation": wire.OperationLocalDomainNodeAvailable, "sequence": int64(40)}
	if err := CompareHubRestoreCoverage(base, next); err != nil {
		t.Fatal("ordinary read-cache eviction rejected", err)
	}
	next.rows["node_control_rpc_sequences_v1"]["binding/key"]["last_sequence"] = int64(40)
	if err := CompareHubRestoreCoverage(base, next); !errors.Is(err, ErrHubRestoreCoverage) {
		t.Fatal("read eviction allowed a burned sequence rollback", err)
	}
}

func TestLocalDomainRestoreAccessRejoinRequiresHigherEpochAndSameCoordinates(t *testing.T) {
	makeCheckpoint := func() *HubRestoreCheckpoint {
		cp := syntheticLocalDomainCheckpoint(t)
		cp.Tables = append(cp.Tables, "network_access_sessions_v2")
		cp.rows["network_access_sessions_v2"] = map[string]map[string]any{"access": {"id": "synthetic-access", "epoch": int64(8), "credential_hash": "synthetic-original-credential", "endpoint_id": "synthetic-endpoint", "network_id": "synthetic-Network"}}
		return cp
	}
	base, next := makeCheckpoint(), makeCheckpoint()
	next.rows["network_access_sessions_v2"]["access"]["epoch"] = int64(9)
	next.rows["network_access_sessions_v2"]["access"]["credential_hash"] = "synthetic-rejoin-credential"
	if err := CompareHubRestoreCoverage(base, next); err != nil {
		t.Fatal("new explicit rejoin rejected", err)
	}
	for _, fault := range []string{"epoch", "endpoint_id", "network_id", "missing-domain-member"} {
		t.Run(fault, func(t *testing.T) {
			base, next := makeCheckpoint(), makeCheckpoint()
			row := next.rows["network_access_sessions_v2"]["access"]
			row["epoch"], row["credential_hash"] = int64(9), "synthetic-rejoin-credential"
			if fault == "missing-domain-member" {
				base.rows["hub_local_domain_members_v1"] = map[string]map[string]any{}
			} else if fault == "epoch" {
				row[fault] = int64(8)
			} else {
				row[fault] = "synthetic-replaced"
			}
			if err := CompareHubRestoreCoverage(base, next); !errors.Is(err, ErrHubRestoreCoverage) {
				t.Fatal("credential replacement escaped exact domain rejoin", err)
			}
		})
	}
}
