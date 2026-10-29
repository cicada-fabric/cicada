package hubaccountwire

import "time"

func AppNodeScopedHTTPOperations() []string {
	return []string{OperationAppNodeScopedPrepare, OperationAppNodeScopedComplete, OperationAppNodeScopedStatus, OperationAppNodeScopedCancel, OperationAppNodeScopedReconcile}
}

func AppNodeScopedContractCapabilities(policy string) AppNodeScopedCapabilities {
	return AppNodeScopedCapabilities{
		Format: AppNodeScopedCapabilitiesFormat, ContractRevision: AppNodeScopedContractRevision,
		ScopeKind: AppNodeScopedScopeKind, ScopeVersion: AppNodeScopedScopeVersion,
		ServeMode: "--hub-nodes-only", Available: AppNodeScopedPublicAvailable,
		HTTPOperations: AppNodeScopedHTTPOperations(), Profiles: []string{AppNodeScopedProfileInitial, AppNodeScopedProfileStatus},
		RuntimeLeaseSeconds: uint64(AppNodeScopedLeaseLifetime / time.Second), MaxOriginalBytes: MaxAppNodeScopedOriginalBytes, TransportPolicy: policy,
	}
}

func appNodeScopedNodeID(id string) bool {
	return validID(id) && id != "control-local" && id != "worker-local"
}

// Candidate resolution is read-only and requires a current login. It cannot
// select an arbitrary head, create a grant or spend a confirmation. Exact Node
// reads can still settle an old original after the login has expired.
func appNodeScopedStatusTargetValid(t AppNodeScopedStatusTarget, token []byte, grant string) bool {
	if grant != "" && !isHex(grant, RequestIDBytes) {
		return false
	}
	if t.NodeID != "" {
		return appNodeScopedNodeID(t.NodeID) && t.CandidateCode == ""
	}
	code, err := NormalizeAppNodeCode(t.CandidateCode)
	return err == nil && code == t.CandidateCode && grant == "" && len(token) == MaxSessionTokenBytes
}
