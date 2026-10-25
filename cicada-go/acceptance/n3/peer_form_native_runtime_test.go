package n3_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type peerFormNativeCheckpoint struct {
	nativeDomainCheckpoint
	Cancelled     bool   `json:"cancel_decline_no_handle"`
	Selected      bool   `json:"selection_has_no_business_effect"`
	RequestID     string `json:"roundtrip_request_id"`
	Retry         bool   `json:"exact_retry_same_request"`
	Expired       bool   `json:"actual_selection_lifetime_elapsed"`
	NetworkDenied bool   `json:"shared_domain_network_denied"`
	Revoked       bool   `json:"revoke_denied_new_business"`
}

// Actual installed plugin, original daemon and original TUI-created A/B use
// production Hook proofs on every call. The standard app-server form relay is
// automated; physical TUI presentation and Windows remain separate NOT_RUN.
// The existing manual public Owner pin is an explicit prerequisite, not NPT12.
func TestN3PeerFormNativeOriginalDaemonAB(t *testing.T) {
	if os.Getenv("CICADA_N3_PEER_FORM") != "1" {
		t.Skip("NOT_RUN: opt in to actual native peer-form fixture with CICADA_N3_PEER_FORM=1")
	}
	v := newCodexProductFixture(t, "1s")
	requireLocalDomainAvailable(t, v)
	v.coldOwnerPin(t)
	v.actualNode.kill(t)
	controlHash := hash(readPrivate(t, v.actualNode.statePath()))
	prefix := filepath.Join(v.root, "peer-form-selected-root")
	if os.Mkdir(prefix, 0755) != nil || os.Chmod(prefix, 0755) != nil {
		t.Fatal("owned peer-form installation root unavailable")
	}
	var workspaces []string
	for _, name := range []string{"a", "b"} {
		path := filepath.Join(v.root, "peer-form-workspace-"+name)
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("owned native peer-form workspace unavailable")
		}
		workspaces = append(workspaces, path)
	}
	var environment []string
	for _, item := range v.environment {
		name := strings.SplitN(item, "=", 2)[0]
		if !strings.HasPrefix(name, "CICADA_") && name != "PATH" {
			environment = append(environment, item)
		}
	}
	environment = append(environment, "PATH=/usr/local/bin:/usr/bin:/bin")
	log := must(os.OpenFile(filepath.Join(v.root, "private-peer-form-native.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	var assets [][]string
	for _, path := range []string{".agents/plugins/cicada/.codex-plugin/plugin.json", ".agents/plugins/cicada/.mcp.json",
		".agents/plugins/cicada/hooks/hooks.json", ".agents/plugins/cicada/skills/cicada-network/SKILL.md", ".agents/plugins/marketplace.json"} {
		assets = append(assets, []string{path, hash(readPrivate(t, filepath.Join("/repo", path)))})
	}
	assetHash := hash(must(json.Marshal(map[string]any{"format": "cicada.codex-plugin-assets.v1", "files": assets})))
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	install := exec.Command(binary, "components", "install", "--prefix", prefix, "--components", "node", "--binary", binary,
		"--sha256", hash(readPrivateBinary(t, binary)), "--licenses", "/licenses", "--codex-plugin-assets", "/repo", "--codex-plugin-sha256", assetHash)
	install.Env, install.Stdout, install.Stderr = environment, log, log
	if install.Run() != nil || hash(readPrivate(t, v.actualNode.statePath())) != controlHash || v.actualNode.running() {
		t.Fatal("file-only peer-form installation failed or changed original Node state")
	}
	installed := filepath.Join(prefix, "components/node/bin/cicada")
	if hash(readPrivateBinary(t, installed)) != hash(readPrivateBinary(t, binary)) {
		t.Fatal("peer-form installed binary differs from the tested executable")
	}
	outbox := filepath.Join(filepath.Dir(v.mcpState), "outbox.sqlite3")
	node := exec.Command(installed, "machine", "agent", "--relay-only", "--id", v.actualNode.id, "--name", v.actualNode.id,
		"--control-url", v.f.cfg.Origin, "--state-dir", v.actualNode.state, "--interval", "1s", "--user-root", prefix,
		"--mcp-session-state-file", v.mcpState, "--mcp-outbox-state-file", outbox)
	node.Env = append(append([]string(nil), v.environment...), "CICADA_CODEX_BIN=/tools/codex-package/bin/codex")
	node.Stdout, node.Stderr = log, log
	v.actualNode = &nodeProcess{process: startProcess(t, node), id: v.actualNode.id, state: v.actualNode.state}
	bound := v.actualNode.awaitState(t, v.f, true)
	if bound.BindingID != v.bound.BindingID || bound.NodeKeyID != v.bound.NodeKeyID ||
		bound.NodeKeyEpoch != v.bound.NodeKeyEpoch || bound.NodeFingerprint != v.bound.NodeFingerprint {
		t.Fatal("peer-form installed Node replaced its original approved identity")
	}
	_, _ = threeStageLivePin(t, v, prefix, outbox, "")
	initial := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !initial.Current || initial.Pending || initial.State != "UNCONFIGURED" || initial.NodeID != v.actualNode.id {
		t.Fatal("peer-form original Node policy is not unconfigured")
	}
	preview := v.do(appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "Synthetic peer-form Network", GroupName: "Synthetic peer-form Group"}}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.ReviewID == "" || preview.NodeID != v.actualNode.id || preview.LocalUserScope != "uid:1000" {
		t.Fatal("peer-form actual App policy review changed its original scope")
	}
	active := v.do(appcore.Action{Kind: appcore.ActionActivateLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}).LocalCollaboration
	requireSameLocalDomain(t, preview, active)
	if active.State != wire.LocalDomainActive || active.GroupID == "" || active.NetworkID == "" {
		t.Fatal("peer-form actual App did not activate its policy")
	}
	control, config, result := filepath.Join(v.root, "peer-form-native-control"), filepath.Join(v.root, "private-peer-form-config.json"), filepath.Join(v.root, "private-peer-form-result.json")
	writeJSON(t, config, map[string]any{"root": v.root, "workspace": workspaces[0], "workspaces": workspaces,
		"codex_home": v.codexHome, "environment": environment, "codex_binary": "/tools/codex-package/bin/codex",
		"codex_sha256": directIPCodexSHA256, "marketplace": filepath.Join(prefix, "components/node/share/codex"),
		"step": "peer-form-native", "persistent_daemon": true, "allow_test_termination": true, "daemon_umask": "0002",
		"preparation": "none", "selected_root": prefix, "control": control, "result": result})
	command := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/peer_form_native.py", config)
	command.Env, command.Dir, command.Stdout, command.Stderr = environment, workspaces[0], log, log
	client := startProcess(t, command)
	var originalDaemon nativeDomainDaemon
	await := func(step int) peerFormNativeCheckpoint {
		t.Helper()
		deadline := time.Now().Add(5 * time.Minute)
		path := filepath.Join(control, strconv.Itoa(step)+".reply.json")
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				var checkpoint peerFormNativeCheckpoint
				readJSON(t, path, &checkpoint)
				if checkpoint.Status != "SCOPED_PASS" || checkpoint.LiteralPosts != 0 || checkpoint.Daemon.PID <= 0 ||
					checkpoint.Daemon.Start == "" || checkpoint.Daemon.Umask != "0002" || !checkpoint.Daemon.EnvEmpty || checkpoint.Daemon.Binary != directIPCodexSHA256 {
					t.Fatal("peer-form original daemon checkpoint invalid")
				}
				if step == 1 {
					originalDaemon = checkpoint.Daemon
				} else if checkpoint.Daemon != originalDaemon {
					t.Fatal("peer-form original Codex daemon changed or restarted")
				}
				return checkpoint
			}
			if !client.running() {
				var failure struct {
					Phase string                `json:"failure_phase"`
					Kind  string                `json:"failure_kind"`
					Code  string                `json:"failure_code"`
					Host  *nativeHostDiagnostic `json:"host_diagnostic"`
					Peer  *struct {
						Codes  []string `json:"codes"`
						Kinds  []string `json:"text_kinds"`
						Blocks int      `json:"text_blocks"`
						Array  bool     `json:"root_array"`
						Flag   bool     `json:"is_error_flag_present"`
					} `json:"peer_form_diagnostic"`
					NamesMatch *bool  `json:"literal_names_match_authenticated_names"`
					Policy     string `json:"host_approval_policy"`
					Reviewer   string `json:"host_approvals_reviewer"`
				}
				if _, err := os.Stat(result); err == nil {
					readJSON(t, result, &failure)
					t.Fatalf("actual peer-form driver failed: phase=%s kind=%s code=%s host=%s peer=%s literal_name_matches=%s host_policy=%s reviewer=%s", failure.Phase, failure.Kind, failure.Code, must(json.Marshal(failure.Host)), must(json.Marshal(failure.Peer)), must(json.Marshal(failure.NamesMatch)), failure.Policy, failure.Reviewer)
				}
				t.Fatal("actual peer-form driver stopped before safe diagnostics")
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("actual peer-form checkpoint timed out")
		return peerFormNativeCheckpoint{}
	}
	send := func(step int, value any) {
		writeJSON(t, filepath.Join(control, strconv.Itoa(step)+".command.json"), value)
	}
	joined := await(1)
	if len(joined.IDs) != 2 || joined.IDs[0] == "" || joined.IDs[0] == joined.IDs[1] {
		t.Fatal("peer-form A/B native identities are not distinct")
	}
	// Normal App closure is deliberately separate from current policy revoke.
	closeLocalDomainApp(t, v)
	send(1, map[string]any{"node_id": v.actualNode.id, "group_id": active.GroupID, "network_id": active.NetworkID})
	identified := await(2)
	if len(identified.Actors) != 2 {
		t.Fatal("actual peer-form Host identity results missing")
	}
	var before []peerSharedAccessAudit
	database := filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3")
	for i, actor := range identified.Actors {
		if actor.SID != joined.IDs[i] || actor.Workspace != workspaces[i] || actor.NodeID != v.actualNode.id ||
			actor.GroupID != active.GroupID || actor.Endpoint == "" || actor.Epoch == 0 {
			t.Fatal("peer-form Host did not retain original native actor")
		}
		before = append(before, peerSharedAccessState(t, database, active.NetworkID, actor.Endpoint))
	}
	if identified.Actors[0].Endpoint == identified.Actors[1].Endpoint {
		t.Fatal("peer-form original Endpoints were merged")
	}
	unchanged := func() {
		t.Helper()
		for i, actor := range identified.Actors {
			observed := peerSharedAccessState(t, database, active.NetworkID, actor.Endpoint)
			if observed != before[i] {
				t.Fatalf("peer selection changed original shared authority: access_changed=%t binding_changed=%t membership_changed=%t enrollment_changed=%t row_counts_changed=%t", observed.Access != before[i].Access, observed.Group != before[i].Group, observed.Membership != before[i].Membership, observed.Endpoint != before[i].Endpoint, observed.AccessRows != before[i].AccessRows || observed.GroupRows != before[i].GroupRows || observed.MembershipRows != before[i].MembershipRows || observed.EndpointRows != before[i].EndpointRows)
			}
		}
	}
	requests := func() int {
		t.Helper()
		db := nodePairReadOnlyDB(t, database)
		defer db.Close()
		var n int
		if db.QueryRow(`SELECT count(*) FROM relay_v2_requests`).Scan(&n) != nil {
			t.Fatal("owned peer-form request observation unavailable")
		}
		return n
	}
	originalRequests := requests()
	send(2, map[string]any{"audit_ready": true})
	cancelled := await(3)
	if !cancelled.Cancelled || !cancelled.NetworkDenied || requests() != originalRequests {
		t.Fatal("cancel/decline peer selection created business state")
	}
	unchanged()
	send(3, map[string]any{"no_business_effect": true})
	selected := await(4)
	if !selected.Selected || requests() != originalRequests {
		t.Fatal("accepted peer selection sent a business request")
	}
	unchanged()
	send(4, map[string]any{"no_business_effect": true})
	communicated := await(5)
	if communicated.RequestID == "" || !communicated.Retry || !communicated.Expired || requests() != originalRequests+1 {
		t.Fatal("selected ASK/REPLY or exact retry did not retain one durable request")
	}
	unchanged()
	send(5, map[string]any{"one_original_request": true})
	await(6)
	marker := filepath.Join(v.f.dir, "peer-form-App-resumed.json")
	v.app = startAppProcess(t, v.f, "resume-node", marker)
	v.sequence = 0
	awaitMarker(t, v.app.process, marker)
	current := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, active, current)
	if current.State != wire.LocalDomainActive || current.StateReviewID == "" {
		t.Fatal("App closure unexpectedly revoked peer-form policy")
	}
	revoked := v.do(appcore.Action{Kind: appcore.ActionRevokeLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: current.StateReviewID, ConfirmRevoke: true}}).LocalCollaboration
	if revoked.State != wire.LocalDomainRevoked || !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("peer-form revocation missing healthy original services")
	}
	send(6, map[string]any{"current_policy_revoked": true})
	denied := await(7)
	if !denied.Revoked || requests() != originalRequests+1 {
		t.Fatal("revoked peer selection created a new durable request")
	}
	send(7, map[string]any{"no_new_request": true})
	select {
	case <-client.done:
		if client.cmd.ProcessState == nil || client.cmd.ProcessState.ExitCode() != 0 {
			t.Fatal("peer-form actual native driver exited unsuccessfully")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("owned peer-form native driver did not stop")
	}
	var final struct {
		Status    string `json:"status"`
		Clean     bool   `json:"cleanup_confirmed"`
		Form      bool   `json:"actual_Host_form_relay"`
		Literal   int    `json:"literal_provider_posts"`
		Host      int    `json:"host_provider_posts"`
		Queue     int    `json:"native_queue_provider_posts"`
		Posts     int    `json:"static_provider_posts"`
		Models    int    `json:"real_model_turns"`
		Policy    string `json:"host_approval_policy"`
		Reviewer  string `json:"host_approvals_reviewer"`
		Summaries []struct {
			Tool  string `json:"tool"`
			Posts int    `json:"provider_posts"`
			Forms []struct {
				Action string `json:"action"`
			} `json:"forms"`
		} `json:"tool_summaries"`
	}
	readJSON(t, result, &final)
	if final.Status != "SCOPED_PASS" || !final.Clean || !final.Form || final.Literal != 0 || final.Models != 0 || final.Policy != "GRANULAR_MCP_ELICITATIONS_ONLY" || final.Reviewer != "user" ||
		final.Host != 2*len(final.Summaries) || final.Posts != final.Host+final.Queue || len(final.Summaries) < 12 {
		t.Fatal("actual peer-form relay or owned cleanup was not confirmed")
	}
	forms := map[string]int{"accept": 0, "decline": 0, "cancel": 0}
	for _, summary := range final.Summaries {
		if summary.Posts != 2 {
			t.Fatal("actual static Host call did not have exactly two provider requests")
		}
		for _, form := range summary.Forms {
			if _, ok := forms[form.Action]; !ok || summary.Tool != "cicada_select_peer" {
				t.Fatal("unexpected actual Host form result")
			}
			forms[form.Action]++
		}
	}
	if forms["accept"] != 2 || forms["decline"] != 1 || forms["cancel"] != 1 {
		t.Fatal("actual Host form action coverage missing")
	}
	if path := os.Getenv("CICADA_N3_PEER_FORM_PUBLIC_SUMMARY"); path != "" {
		if path != "/state/peer-form-native-public-summary.json" {
			t.Fatal("owned peer-form public summary path required")
		}
		writeJSON(t, path, map[string]any{"scope": "ACTUAL_HOST_FORM_NATIVE_AB_NOT_PHYSICAL_UI", "status": "SCOPED_PASS",
			"daemon": originalDaemon, "actors": identified.Actors, "form_actions": forms, "host_calls": len(final.Summaries),
			"host_provider_posts": final.Host, "native_queue_provider_posts": final.Queue, "static_provider_posts": final.Posts,
			"real_model_turns": 0, "literal_provider_posts": 0, "cleanup_confirmed": true, "App_closed_during_business": true,
			"host_approval_policy": final.Policy, "host_approvals_reviewer": final.Reviewer,
			"selection_no_send": true, "cancel_decline_no_effect": true, "shared_credentials_unchanged": true,
			"shared_domain_network_denied": true, "actual_selection_lifetime_elapsed": true, "exact_retry_one_request": true,
			"current_revoke_denied": true, "physical_form_UI": "NOT_RUN", "Windows_DPAPI_ACL": "NOT_RUN"})
	}
	t.Log("PEER_FORM_NATIVE actual_Codex=0.164.0 original_daemon=true literal_AB=true actual_Host_form_relay=true actual_Hook_per_call=true actual_Hub_Node_App=true App_closed=true cancel_decline_no_effect=true selection_no_send=true ASK_REPLY=true exact_retry_one_request=true shared_credentials_unchanged=true current_revoke_denied=true real_models=0 physical_form_UI=NOT_RUN Windows_DPAPI_ACL=NOT_RUN")
}
