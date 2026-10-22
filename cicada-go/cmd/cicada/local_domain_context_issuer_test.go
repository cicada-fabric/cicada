package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func activateLocalDomainConsumer(t *testing.T, f *nativePairTCPConsumerFixture) wire.LocalDomainDescription {
	t.Helper()
	f.bridge.refreshLocalDomainReport(f.ctx, time.Now)
	prepare, err := wire.NewLocalDomainPrepare(f.session, f.scope.Actor, e2ee.LocalDomainTarget{Node: f.scope.Node, NewNetworkName: "Synthetic immediate domain Network", GroupName: "Synthetic immediate domain Group"}, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(f.device, f.hub, prepare)
	if err != nil {
		t.Fatal(err)
	}
	reply := f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainPrepare), "", "", packet, http.StatusOK)
	var challenge wire.LocalDomainChallenge
	if err := wire.OpenLocalDomainResponse(f.device, f.hub, packet, reply, &challenge); err != nil {
		t.Fatal(err)
	}
	activate, err := wire.NewLocalDomainActivate(f.session, f.scope.Actor, prepare, packet, challenge, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err = wire.SealClientRequest(f.device, f.hub, activate)
	if err != nil {
		t.Fatal(err)
	}
	reply = f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainActivate), "", "", packet, http.StatusOK)
	var result wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(f.device, f.hub, packet, reply, &result) != nil || wire.ValidateLocalDomainResultTarget(activate, packet, result, f.hub) != nil || result.Description == nil {
		t.Fatal("actual domain activation failed")
	}
	return *result.Description
}

func localDomainConsumerIssue(t *testing.T, f *nativePairTCPConsumerFixture, index int) localCodexContextIssue {
	t.Helper()
	sid := f.native[index]
	path := filepath.Join(os.Getenv("CODEX_HOME"), "sessions", "2026", "09", "23", "rollout-2026-09-23T00-00-00-"+sid+".jsonl")
	data, err := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": sid, "session_id": sid, "cwd": f.workspace, "source": "vscode", "originator": "codex-tui"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o775); err != nil {
		t.Fatal(err)
	}
	q := syntheticCodexContextIssue()
	q.APIOrigin, q.NativeSessionID, q.Workspace, q.TranscriptPath = f.server.URL, sid, f.workspace, path
	q.ToolName, q.TurnID, q.ToolUseID = "codex.operator.endpoint_register", "", ""
	return q
}

func TestLocalDomainContextIssuerReadsImmediateActivationWithoutNewReport(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	d := activateLocalDomainConsumer(t, f)
	f.client.mu.Lock()
	before := cloneMachineLocalDomainState(f.client.state).LocalDomainReport
	sequence := f.client.state.Sequence
	f.client.mu.Unlock()
	if before == nil || before.Current != nil || len(before.ReportProof) == 0 || !time.Now().Before(parseMachineNativePairTime(before.NextAt)) {
		t.Fatal("fixture did not preserve initial pre-activation report")
	}
	q := localDomainConsumerIssue(t, f, 0)
	ticket, err := f.bridge.codexContextIssue(q)
	if err != nil {
		t.Fatal("first explicit Join context waited for another report/daemon restart", err)
	}
	consumed, err := f.bridge.codexContextConsume(syntheticCodexContextConsume(q, ticket.Ticket))
	selection, selectionErr := wire.LocalDomainSelectionForPolicy(d.Policy)
	if err != nil || selectionErr != nil || consumed.Context.VerificationProfile != LocalCodexContextProfileDomain || consumed.Context.LocalDomain != selection || consumed.Context.TurnID != "" || consumed.Context.ToolUseID != "" {
		t.Fatal("Node did not bind its actual selected domain into the operator ticket", err)
	}
	f.client.mu.Lock()
	after := cloneMachineLocalDomainState(f.client.state).LocalDomainReport
	afterSequence := f.client.state.Sequence
	f.client.mu.Unlock()
	if !bytes.Equal(before.ReportProof, after.ReportProof) || before.NextAt != after.NextAt || afterSequence != sequence+1 {
		t.Fatal("explicit current read signed another report or changed its refresh deadline")
	}
	// An advanced legacy Pair operation keeps the original strict verifier even
	// when an active domain exists and this record has normal umask-002 modes.
	q.ToolName = "codex.operator.native_pair_available"
	_, err = f.bridge.codexContextIssue(q)
	var diagnostic *LocalCodexContextError
	if !errors.As(err, &diagnostic) || diagnostic.Stage != "PERMISSION" {
		t.Fatal("domain availability relaxed an explicit legacy Pair record", err)
	}
}

func TestLocalDomainContextTicketBindsNodeProfileAndExactOperatorPurpose(t *testing.T) {
	q := syntheticCodexContextIssue()
	for _, tool := range []string{"codex.operator.endpoint_register", "codex.operator.endpoint_leave", "codex.operator.endpoint_directory", "codex.operator.native_pair_available", "codex.operator.native_pair_join_named", "cicada_endpoint_register", "cicada_ask", "codex.operator.unrecognized", "codex.operator.endpoint_register.extra"} {
		operator := strings.HasPrefix(tool, "codex.operator.") && tool != "codex.operator.unrecognized" && tool != "codex.operator.endpoint_register.extra"
		for _, tc := range []struct {
			name, turn, use string
			want            bool
		}{
			{"both", "synthetic-turn", "synthetic-use", true},
			{"prompt turn only", "synthetic-turn", "", operator},
			{"legacy empty", "", "", operator},
			{"tool only", "", "synthetic-use", false},
			{"invalid turn", " invalid-turn", "", false},
			{"invalid use", "synthetic-turn", "invalid\nuse", false},
		} {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				input := q
				input.ToolName, input.TurnID, input.ToolUseID = tool, tc.turn, tc.use
				if localCodexContextEventIDs(input) != tc.want {
					t.Fatal("native event ID shape escaped its exact purpose")
				}
			})
		}
	}
	q.ToolName, q.TurnID, q.ToolUseID = "codex.operator.endpoint_register", "synthetic-original-prompt-turn", ""
	var a localCodexContextAuthority
	ctx := localCodexContext{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, TurnID: q.TurnID, VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1, LocalDomain: wire.LocalDomainSelection{PolicyID: strings.Repeat("1", 32), PolicyEpoch: 1, PolicyDigest: strings.Repeat("2", 64)}}
	now := time.Now().UTC()
	ticket, err := a.issueVerified(q, "synthetic-original-binding", now, ctx)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := a.consume(syntheticCodexContextConsume(q, ticket.Ticket), "synthetic-original-binding", now)
	if err != nil || consumed.Context.TurnID != q.TurnID || consumed.Context.ToolUseID != "" {
		t.Fatal("operator ticket replaced the original prompt turn or fabricated a tool-use ID")
	}
	ticket, err = a.issueVerified(q, "synthetic-original-binding", now, ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Split(ticket.Ticket, ".")[0]
	a.mu.Lock()
	record := a.live[id]
	record.Context.LocalDomain.PolicyEpoch++
	a.live[id] = record
	a.mu.Unlock()
	if _, err := a.consume(syntheticCodexContextConsume(q, ticket.Ticket), "synthetic-original-binding", now); err == nil {
		t.Fatal("profile/selection tampering retained a valid ticket HMAC")
	}
}
