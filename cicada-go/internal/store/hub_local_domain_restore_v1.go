package store

import (
	"encoding/json"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var localDomainRestoreTables = []string{"hub_local_domain_guard_v1", "hub_local_domain_epochs_v1", "hub_local_domain_user_reports_v1", "hub_local_domains_v1", "hub_local_domain_members_v1", "hub_local_domain_challenges_v1", "hub_local_domain_owner_operations_v1", "hub_local_domain_node_operations_v1", "hub_local_domain_owner_reads_v1", "hub_local_domain_node_reads_v1", "hub_local_domain_rates_v1"}

func localDomainRestoreCache(table string) bool {
	switch table {
	case "hub_local_domain_guard_v1", "hub_local_domain_user_reports_v1", "hub_local_domain_owner_reads_v1", "hub_local_domain_node_reads_v1", "hub_local_domain_rates_v1":
		return true
	}
	return false
}

func localDomainRestoreRowAdvance(table string, old, next map[string]any) error {
	immutable := func(fields ...string) bool {
		for _, f := range fields {
			if hubRestoreDigest(old[f]) != hubRestoreDigest(next[f]) {
				return false
			}
		}
		return true
	}
	terminal := func(states ...string) bool {
		for _, s := range states {
			if old["state"] == s {
				return true
			}
		}
		return false
	}
	switch table {
	case "hub_local_domain_owner_operations_v1", "hub_local_domain_node_operations_v1":
		if hubRestoreDigest(old) != hubRestoreDigest(next) {
			return ErrHubRestoreCoverage
		}
	case "hub_local_domains_v1":
		if next["state"] != "PREPARED" && next["state"] != "ACTIVE" && next["state"] != "REVOKED" && next["state"] != "EXPIRED" {
			return ErrHubRestoreCoverage
		}
		if !immutable("policy_id", "hub_id", "owner_id", "node_id", "local_user_scope", "network_id", "group_id", "epoch", "policy_json", "hub_identity_json", "creator_account_id", "creator_device_id", "prepare_proof", "user_report", "proof_expires_at", "created_at") {
			return ErrHubRestoreCoverage
		}
		if old["policy_proof"] != nil && !immutable("policy_proof") {
			return ErrHubRestoreCoverage
		}
		if terminal("REVOKED", "EXPIRED") && hubRestoreDigest(old) != hubRestoreDigest(next) {
			return ErrHubRestoreCoverage
		}
		if old["state"] == "ACTIVE" && next["state"] != "ACTIVE" && next["state"] != "REVOKED" && next["state"] != "EXPIRED" {
			return ErrHubRestoreCoverage
		}
		if old["revision"] == next["revision"] && hubRestoreDigest(old) != hubRestoreDigest(next) {
			return ErrHubRestoreCoverage
		}
	case "hub_local_domain_members_v1":
		if next["state"] != "JOINED_ZERO" && next["state"] != "ACTIVE" && next["state"] != "LEFT" && next["state"] != "REVOKED" && next["state"] != "EXPIRED" {
			return ErrHubRestoreCoverage
		}
		if !immutable("member_id", "policy_id", "owner_id", "node_id", "native_session_id", "endpoint_id", "principal_id", "binding_id", "access_id", "runtime", "workspace", "attempt_id", "join_operation_id", "join_sequence", "created_at") {
			return ErrHubRestoreCoverage
		}
		if terminal("LEFT", "REVOKED", "EXPIRED") && hubRestoreDigest(old) != hubRestoreDigest(next) {
			return ErrHubRestoreCoverage
		}
		if old["state"] == "ACTIVE" && next["state"] != "ACTIVE" && next["state"] != "LEFT" && next["state"] != "REVOKED" && next["state"] != "EXPIRED" {
			return ErrHubRestoreCoverage
		}
		if old["revision"] == next["revision"] && hubRestoreDigest(old) != hubRestoreDigest(next) {
			return ErrHubRestoreCoverage
		}
		var a, b wire.LocalDomainMember
		ar, aok := old["member_json"].(string)
		br, bok := next["member_json"].(string)
		if !aok || !bok || json.Unmarshal([]byte(ar), &a) != nil || json.Unmarshal([]byte(br), &b) != nil {
			return ErrHubRestoreCoverage
		}
		if a.MemberID != b.MemberID || a.Selection != b.Selection || a.NodeID != b.NodeID || a.LocalUserScope != b.LocalUserScope || a.NativeSessionID != b.NativeSessionID || a.Runtime != b.Runtime || a.Workspace != b.Workspace || a.EndpointID != b.EndpointID || a.PrincipalID != b.PrincipalID || a.BindingID != b.BindingID || a.BindingEpoch != b.BindingEpoch || a.NetworkAccessBindingID != b.NetworkAccessBindingID || a.NetworkAccessEpoch != b.NetworkAccessEpoch || a.LeaseOwner != b.LeaseOwner || a.NetworkMembershipRevision != b.NetworkMembershipRevision || a.EndpointNetworkRevision != b.EndpointNetworkRevision || a.EndpointJoinRevision != b.EndpointJoinRevision || b.MembershipRevision < a.MembershipRevision || b.CandidateVersion < a.CandidateVersion || (a.CandidateKeyID != "" && (a.CandidateKeyID != b.CandidateKeyID || a.CandidateFingerprint != b.CandidateFingerprint)) {
			return ErrHubRestoreCoverage
		}
	case "hub_local_domain_challenges_v1":
		if next["state"] != "PREPARED" && next["state"] != "COMPLETED" && next["state"] != "INVALIDATED" && next["state"] != "EXPIRED" {
			return ErrHubRestoreCoverage
		}
		if !immutable("challenge_id", "policy_id", "member_id", "expected_revision", "challenge_json", "expires_at", "created_at") {
			return ErrHubRestoreCoverage
		}
		if old["state"] != "PREPARED" && hubRestoreDigest(old) != hubRestoreDigest(next) {
			return ErrHubRestoreCoverage
		}
	}
	return nil
}

// The existing Network table keeps a stable session ID. A newly explicit
// same-Network domain Join may advance that row's epoch and credential while
// every old member/receipt still retains its original binding tuple.
func localDomainRestoreAccessAdvance(base *HubRestoreCheckpoint, table string, old, next map[string]any) bool {
	if table != "network_access_sessions_v2" {
		return false
	}
	a, aok := old["epoch"].(int64)
	b, bok := next["epoch"].(int64)
	if !aok || !bok || b <= a {
		return false
	}
	for _, m := range base.rows["hub_local_domain_members_v1"] {
		if m["access_id"] == old["id"] {
			for _, f := range []string{"id", "network_id", "endpoint_id", "principal_id", "native_session_id", "node_id", "owner_key_id"} {
				if hubRestoreDigest(old[f]) != hubRestoreDigest(next[f]) {
					return false
				}
			}
			return true
		}
	}
	return false
}
