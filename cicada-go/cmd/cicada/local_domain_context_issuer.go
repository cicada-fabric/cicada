package main

import (
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func localCodexContextEventIDs(q localCodexContextIssue) bool {
	if localContextText(q.TurnID, 256) && localContextText(q.ToolUseID, 256) {
		return true
	}
	switch q.ToolName {
	case "codex.operator.endpoint_register", "codex.operator.endpoint_leave", "codex.operator.endpoint_directory", "codex.operator.native_pair_available", "codex.operator.native_pair_join_named":
		// UserPromptSubmit carries its real turn ID and no tool-use ID.
		// Older operator events may omit both; MCP still needs both IDs.
		return q.ToolUseID == "" && (q.TurnID == "" || localContextText(q.TurnID, 256))
	}
	return false
}

func (b *machineAgentJoinBridge) localCodexVerificationProfile(q localCodexContextIssue) (localCodexContext, error) {
	v := localCodexContext{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, TurnID: q.TurnID, ToolUseID: q.ToolUseID}
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return v, err
	}
	// An explicitly existing Pair context and the two advanced Pair commands
	// retain their original verifier. Availability of a new domain does not
	// migrate an enrolled SID or expand old Pair proofs.
	if q.ToolName == "codex.operator.native_pair_available" || q.ToolName == "codex.operator.native_pair_join_named" {
		return v, nil
	}
	client.mu.Lock()
	pair := false
	for _, m := range client.state.ManagedPairLeases {
		if m.State != "STOPPED" && m.Join.NativeSessionID == q.NativeSessionID && m.Join.Workspace == q.Workspace {
			pair = true
			break
		}
	}
	client.mu.Unlock()
	if pair {
		return v, nil
	}
	if managed, selected, err := b.endpointGroupsVerificationProfile(q); selected || err != nil {
		return managed, err
	}
	var p *nodekeys.LocalDomainPolicy
	if q.ToolName == "codex.operator.endpoint_register" || q.ToolName == "cicada_endpoint_register" {
		p, err = b.readLocalDomainCurrent(b.ctx, client)
	} else {
		p, err = client.currentLocalDomainPolicy(b.ctx, b.nodeToken, time.Now().UTC())
	}
	if err != nil {
		return v, err
	}
	if p == nil {
		return v, nil
	}
	selection, err := wire.LocalDomainSelectionForPolicy(p.Policy)
	if err != nil {
		return v, err
	}
	v.VerificationProfile = LocalCodexContextProfileDomain
	v.LocalDomainVersion = 1
	v.LocalDomain = selection
	return v, nil
}

func (a *localCodexContextAuthority) verifiedNative(sid, workspace string, now time.Time) (localCodexContextRecord, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.native[sid+"\x00"+workspace]
	return r, ok && now.Before(r.Expires)
}

// Outbound data uses the known explicit admission's exact record, not a walk
// through native history. The Group marker and independent pin select this
// verifier; a caller cannot choose the relaxed record-permission profile.
func (b *machineAgentJoinBridge) verifyManagedLocalDomainNativeRecord(group, endpoint, binding string, epoch uint64, sid, cwd string) error {
	s, err := nodekeys.OpenExistingCryptoState(b.ctx, machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return err
	}
	p, err := s.LocalDomainPolicyForGroup(b.ctx, group)
	if err == nil {
		err = s.CheckLocalDomainPolicy(b.ctx, *p, time.Now().UTC())
	}
	_ = s.Close()
	if err != nil {
		return err
	}
	selection, err := wire.LocalDomainSelectionForPolicy(p.Policy)
	if err != nil {
		return err
	}
	path := ""
	if r, ok := b.codexContexts.verifiedNative(sid, cwd, time.Now()); ok && r.Context.VerificationProfile == LocalCodexContextProfileDomain && r.Context.LocalDomain == selection {
		path = r.TranscriptPath
	}
	if path == "" {
		client, e := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
		if e != nil {
			return e
		}
		client.mu.Lock()
		for _, m := range client.state.ManagedLocalDomainLeases {
			if m.State != "ACTIVE" || m.Join.Selection != selection || m.Join.NativeSessionID != sid || m.Join.Workspace != cwd {
				continue
			}
			var completed wire.LocalDomainNodeKeyResult
			if client.localDomainOriginalLocked(m, "domain.complete", &completed) == nil && completed.Member.EndpointID == endpoint && completed.Member.BindingID == binding && completed.Member.BindingEpoch == epoch {
				path = m.TranscriptPath
				break
			}
		}
		client.mu.Unlock()
	}
	if path == "" {
		return errLocalCodexContext
	}
	return verifyCodexContextTranscriptProfile(path, sid, cwd, true)
}
