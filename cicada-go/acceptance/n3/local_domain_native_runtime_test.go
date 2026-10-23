package n3_test

import (
	"encoding/json"
	"net/http"
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

type nativeDomainActor struct {
	SID       string `json:"native_session_id"`
	Workspace string `json:"workspace"`
	NodeID    string `json:"node_id"`
	Endpoint  string `json:"endpoint_id"`
	GroupID   string `json:"group_id"`
	Epoch     uint64 `json:"binding_epoch"`
}

type nativeHostFieldDiagnostic struct {
	Present bool     `json:"present"`
	Types   []string `json:"types"`
}

type nativeHostErrorDiagnostic struct {
	Present         bool     `json:"present"`
	Types           []string `json:"types"`
	SHA256          []string `json:"sha256"`
	ErrnoCategories []string `json:"errno_categories"`
}

type nativeHostDiagnostic struct {
	Observed          bool                                 `json:"observed"`
	OutputType        string                               `json:"output_type"`
	JSONStringPrefix  string                               `json:"json_string_prefix"`
	ParsedObject      bool                                 `json:"parsed_object_present"`
	IsErrorObserved   bool                                 `json:"is_error_observed"`
	IsError           *bool                                `json:"is_error"`
	OperationStatuses []string                             `json:"operation_statuses"`
	ErrorSummary      nativeHostErrorDiagnostic            `json:"error_summary"`
	Fields            map[string]nativeHostFieldDiagnostic `json:"fields"`
	ProductErrorCodes []string                             `json:"product_error_codes"`
	HubHTTPStatuses   []int                                `json:"hub_http_statuses"`
	ProviderIssues    []string                             `json:"provider_issues"`
}

type nativeDomainDaemon struct {
	PID      int    `json:"pid"`
	Start    string `json:"start_ticks"`
	Umask    string `json:"umask"`
	Binary   string `json:"executable_sha256"`
	EnvEmpty bool   `json:"five_deployment_variables_absent"`
}

type nativeDomainCheckpoint struct {
	Status          string              `json:"status"`
	Daemon          nativeDomainDaemon  `json:"daemon"`
	IDs             []string            `json:"native_session_ids"`
	Actors          []nativeDomainActor `json:"actors"`
	LiteralPosts    int                 `json:"literal_provider_posts"`
	Expired         bool                `json:"actual_wall_clock_expiry"`
	Denied          bool                `json:"new_business_denied_after_current_revoke"`
	Directory       bool                `json:"directory_filters_verified"`
	DirectoryDenied bool                `json:"directory_after_revoke_denied"`
}

func TestN3LocalDomainNativeOriginalDaemonAB(t *testing.T) {
	v := newCodexProductFixture(t, "1s")
	requireLocalDomainAvailable(t, v)
	waitExpiry := os.Getenv("CICADA_N3_DOMAIN_WAIT_LOGIN_EXPIRY") == "1"
	initialAccount := v.command(t, appActorCommand{}).Current.Account
	loginDeadline := must(time.Parse(time.RFC3339Nano, initialAccount.SessionExpiresAt))
	// This existing operator command uses only an actual App public export.
	// Do it before starting the original Codex daemon or measuring admission.
	v.coldOwnerPin(t)
	v.actualNode.kill(t)
	originalControl := hash(readPrivate(t, v.actualNode.statePath()))
	prefix := filepath.Join(v.root, "selected-native-root")
	if os.Mkdir(prefix, 0755) != nil || os.Chmod(prefix, 0755) != nil {
		t.Fatal("owned selected root unavailable")
	}
	var workspaces []string
	for _, letter := range []string{"a", "b", "c"} {
		path := filepath.Join(v.root, "native-workspace-"+letter)
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("owned native workspace unavailable")
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
	control := filepath.Join(v.root, "domain-native-control")
	config, result := filepath.Join(v.root, "private-domain-native-config.json"), filepath.Join(v.root, "private-domain-native-result.json")
	writeJSON(t, config, map[string]any{"root": v.root, "workspace": workspaces[0], "workspaces": workspaces,
		"codex_home": v.codexHome, "environment": environment, "codex_binary": "/tools/codex-package/bin/codex",
		"codex_sha256": "399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215", "marketplace": "/repo",
		"step": "domain-native", "persistent_daemon": true, "allow_test_termination": true,
		"daemon_umask": "0002", "preparation": "none", "selected_root": prefix, "control": control, "result": result,
		"public_summary": os.Getenv("CICADA_N3_DOMAIN_PUBLIC_SUMMARY")})
	log := must(os.OpenFile(filepath.Join(v.root, "private-domain-native.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/codex_domain_native.py", config)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = environment, workspaces[0], log, log
	client := startProcess(t, cmd)
	var originalDaemon nativeDomainDaemon
	await := func(step int) nativeDomainCheckpoint {
		t.Helper()
		deadline := time.Now().Add(4 * time.Minute)
		if step == 3 && waitExpiry {
			deadline = loginDeadline.Add(5 * time.Minute)
		}
		path := filepath.Join(control, strconv.Itoa(step)+".reply.json")
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				var r nativeDomainCheckpoint
				readJSON(t, path, &r)
				if r.Status != "SCOPED_PASS" || r.LiteralPosts != 0 || r.Daemon.PID <= 0 || r.Daemon.Start == "" || r.Daemon.Umask != "0002" || !r.Daemon.EnvEmpty ||
					r.Daemon.Binary != "399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215" {
					t.Fatal("original native daemon/literal checkpoint refused")
				}
				if step == 0 {
					originalDaemon = r.Daemon
				} else if r.Daemon != originalDaemon {
					t.Fatal("original umask-0002 Codex daemon restarted or changed")
				}
				return r
			}
			if !client.running() {
				var failure struct {
					Phase        string                `json:"failure_phase"`
					Label        string                `json:"failure_label"`
					Kind         string                `json:"failure_kind"`
					Code         string                `json:"failure_code"`
					Hook         string                `json:"hook_result"`
					LiteralPosts int                   `json:"literal_provider_posts"`
					Posts        int                   `json:"provider_posts"`
					Host         *nativeHostDiagnostic `json:"host_diagnostic"`
				}
				if _, err := os.Stat(result); err != nil {
					t.Fatal("actual native driver stopped before its final safe diagnostics")
				}
				readJSON(t, result, &failure)
				t.Fatalf("actual native driver stopped: phase=%s label=%s category=%s code=%s hook=%s literal_posts=%d provider_posts=%d host=%s", failure.Phase, failure.Label, failure.Kind, failure.Code, failure.Hook, failure.LiteralPosts, failure.Posts, must(json.Marshal(failure.Host)))
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("actual native domain checkpoint timeout")
		return nativeDomainCheckpoint{}
	}
	send := func(step int, value any) {
		writeJSON(t, filepath.Join(control, strconv.Itoa(step)+".command.json"), value)
	}
	await(0)
	if v.actualNode.running() || hash(readPrivate(t, v.actualNode.statePath())) != originalControl {
		t.Fatal("Codex startup changed or started the stopped original Node")
	}
	assetPaths := []string{".agents/plugins/cicada/.codex-plugin/plugin.json", ".agents/plugins/cicada/.mcp.json", ".agents/plugins/cicada/hooks/hooks.json", ".agents/plugins/cicada/skills/cicada-network/SKILL.md", ".agents/plugins/marketplace.json"}
	var rows [][]string
	for _, path := range assetPaths {
		rows = append(rows, []string{path, hash(readPrivate(t, filepath.Join("/repo", path)))})
	}
	assets := hash(must(json.Marshal(map[string]any{"format": "cicada.codex-plugin-assets.v1", "files": rows})))
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	install := exec.Command(binary, "components", "install", "--prefix", prefix, "--components", "node", "--binary", binary,
		"--sha256", hash(readPrivateBinary(t, binary)), "--licenses", "/licenses", "--codex-plugin-assets", "/repo", "--codex-plugin-sha256", assets)
	install.Env, install.Stdout, install.Stderr = environment, log, log
	if install.Run() != nil || hash(readPrivate(t, v.actualNode.statePath())) != originalControl || v.actualNode.running() {
		t.Fatal("actual file-only installation failed or changed original Node state")
	}
	installed := filepath.Join(prefix, "components/node/bin/cicada")
	if hash(readPrivateBinary(t, installed)) != hash(readPrivateBinary(t, binary)) {
		t.Fatal("installed Node is not the tested executable")
	}
	outbox := filepath.Join(filepath.Dir(v.mcpState), "outbox.sqlite3")
	nodeCommand := exec.Command(installed, "machine", "agent", "--relay-only", "--id", v.actualNode.id, "--name", v.actualNode.id,
		"--control-url", v.f.cfg.Origin, "--state-dir", v.actualNode.state, "--interval", "1s", "--user-root", prefix,
		"--mcp-session-state-file", v.mcpState, "--mcp-outbox-state-file", outbox)
	nodeCommand.Env = append(append([]string(nil), v.environment...), "CICADA_CODEX_BIN=/tools/codex-package/bin/codex")
	nodeCommand.Stdout, nodeCommand.Stderr = log, log
	v.actualNode = &nodeProcess{process: startProcess(t, nodeCommand), id: v.actualNode.id, state: v.actualNode.state}
	bound := v.actualNode.awaitState(t, v.f, true)
	if bound.BindingID != v.bound.BindingID || bound.NodeKeyID != v.bound.NodeKeyID || bound.NodeKeyEpoch != v.bound.NodeKeyEpoch || bound.NodeFingerprint != v.bound.NodeFingerprint {
		t.Fatal("installed Node changed its original approved identity")
	}
	_, _ = threeStageLivePin(t, v, prefix, outbox, "")
	initial := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !initial.Current || initial.Pending || initial.State != "UNCONFIGURED" || initial.NodeID != v.actualNode.id {
		t.Fatal("actual original Node policy scope is not unconfigured")
	}
	preview := v.do(appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "Synthetic native Network", GroupName: "Synthetic native Group", ExpiresInHours: 0}}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.ReviewID == "" || preview.NodeID != v.actualNode.id || preview.LocalUserScope != "uid:1000" || preview.ExpiresAt != "" {
		t.Fatal("actual App did not review the exact persistent Node/user policy")
	}
	active := v.do(appcore.Action{Kind: appcore.ActionActivateLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}).LocalCollaboration
	requireSameLocalDomain(t, preview, active)
	if active.State != wire.LocalDomainActive || active.GroupID == "" {
		t.Fatal("actual App did not activate its own original policy")
	}
	send(1, map[string]any{"marketplace": filepath.Join(prefix, "components/node/share/codex"), "node_id": v.actualNode.id,
		"group_id": active.GroupID, "policy_id": active.PolicyID})
	joined := await(1)
	if len(joined.IDs) != 2 || joined.IDs[0] == "" || joined.IDs[0] == joined.IDs[1] {
		t.Fatal("literal A/B did not retain distinct actual native records")
	}
	closeLocalDomainApp(t, v)
	send(2, map[string]any{"app_closed": true})
	communicated := await(2)
	if len(communicated.Actors) != 2 || !communicated.Directory {
		t.Fatal("actual A/B Host identity results missing")
	}
	checkActors := func(r nativeDomainCheckpoint, count int) {
		t.Helper()
		seen := make(map[string]bool)
		if len(r.Actors) != count || len(r.IDs) != 0 && len(r.IDs) != count {
			t.Fatal("actual native actor count differs")
		}
		for i, actor := range r.Actors {
			if actor.SID == "" || actor.Workspace != workspaces[i] || actor.NodeID != v.actualNode.id || actor.GroupID != active.GroupID || actor.Endpoint == "" || actor.Epoch == 0 || seen[actor.Endpoint] || (i < 2 && actor.SID != joined.IDs[i]) {
				t.Fatal("actual Host tool used another native identity or scope")
			}
			seen[actor.Endpoint] = true
		}
	}
	checkActors(communicated, 2)
	send(3, map[string]any{"wait_login_expiry": waitExpiry, "login_expires_at": initialAccount.SessionExpiresAt})
	aged := await(3)
	count := 2
	if waitExpiry {
		count = 3
		if !aged.Expired || !time.Now().After(loginDeadline) {
			t.Fatal("App logical-clock offset was substituted for actual Hub session expiry")
		}
	}
	checkActors(aged, count)
	// Reopen the same protected profile; login after real expiry uses the same
	// original device/Owner keys and a genuine current account challenge.
	marker := filepath.Join(v.f.dir, "native-domain-App-resumed.json")
	v.app = startAppProcess(t, v.f, "resume-node", marker)
	v.sequence = 0
	awaitMarker(t, v.app.process, marker)
	if waitExpiry {
		login := appcore.Action{Kind: appcore.ActionLogin, Username: initialAccount.Username, Password: syntheticPassword}
		reply := v.command(t, appActorCommand{Action: &login})
		if reply.ActionFailed {
			t.Fatal("actual original App could not log in after its real account-session expiry")
		}
		assertOwnerDirectoryIdentity(t, v.endpointSecurityFixture, reply.Current)
	}
	current := v.do(appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, active, current)
	if current.State != wire.LocalDomainActive || current.Revision != active.Revision || current.StateReviewID == "" {
		t.Fatal("normal App close/session expiry changed the persistent policy")
	}
	revokeFrom := len(v.f.proxy.snapshot())
	revoked := v.do(appcore.Action{Kind: appcore.ActionRevokeLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: current.StateReviewID, ConfirmRevoke: true}}).LocalCollaboration
	requireSameLocalDomain(t, active, revoked)
	if revoked.State != wire.LocalDomainRevoked || !v.f.hub.running() || !v.actualNode.running() {
		t.Fatal("actual policy revoke or healthy Hub/Node precondition missing")
	}
	heartbeat := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !heartbeat {
		for _, ex := range v.f.proxy.snapshot()[revokeFrom:] {
			if ex.Method == http.MethodPost && ex.Path == "/v2/relay/nodes/"+v.actualNode.id+"/heartbeat" && ex.Forwarded && ex.Status == http.StatusNoContent {
				heartbeat = true
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !heartbeat {
		t.Fatal("policy revocation incorrectly disabled the original Node or Hub")
	}
	send(4, map[string]any{"current_policy_state": wire.LocalDomainRevoked, "Hub_and_Node_healthy": true})
	denied := await(4)
	if !denied.Denied || !denied.DirectoryDenied || !v.actualNode.running() || !v.f.hub.running() {
		t.Fatal("current native denial is not qualified by healthy original services")
	}
	select {
	case <-client.done:
	case <-time.After(15 * time.Second):
		t.Fatal("owned native daemon driver cleanup timeout")
	}
	var final struct {
		Status        string `json:"status"`
		HostCalls     int    `json:"host_calls_completed"`
		HostPosts     int    `json:"host_provider_posts"`
		QueuePosts    int    `json:"native_queue_provider_posts"`
		ProviderPosts int    `json:"static_provider_posts"`
	}
	readJSON(t, result, &final)
	if client.cmd.ProcessState.ExitCode() != 0 || final.Status != "SCOPED_PASS" || final.HostCalls < 8 || final.HostPosts != final.HostCalls*2 || final.QueuePosts < 0 || final.ProviderPosts != final.HostPosts+final.QueuePosts {
		t.Fatal("actual Native domain driver did not finish its measured main line")
	}
	if path := os.Getenv("CICADA_N3_DOMAIN_PUBLIC_SUMMARY"); path == "/state/domain-native-public-summary.json" {
		writeJSON(t, path, map[string]any{"scope": "ACTUAL_NATIVE_DOMAIN_MAIN_STATIC_PROVIDER_NOT_REAL_MODEL_OR_WINDOWS", "status": "SCOPED_PASS",
			"original_daemon": originalDaemon, "literal_provider_posts": 0, "actors": aged.Actors,
			"actual_wall_clock_login_expiry": waitExpiry, "manual_independent_Owner_pin": true,
			"host_calls_completed": final.HostCalls, "host_submission_mode": "START_OR_STEER",
			"host_provider_posts": final.HostPosts, "native_queue_provider_posts": final.QueuePosts,
			"static_provider_posts": final.ProviderPosts, "real_model_turns_started": 0,
			"Hub_and_Node_healthy_at_revoke": true, "authenticated_policy_state_after_revoke": revoked.State,
			"new_business_denied_after_revoke": denied.Denied, "directory_filters_verified": communicated.Directory,
			"directory_after_revoke_denied": denied.DirectoryDenied})
	}
	t.Logf("LOCAL_DOMAIN_NATIVE_MAIN original_0002_daemon=true no_record_chmod=true literal_AB_provider_posts=0 actual_named_ASK_Reply=true normal_App_Close_communication=true current_revoke_denied_healthy_Node_Hub=true actual_login_expiry_and_new_C=%t manual_Owner_public_pin=true real_model_and_real_model_automatic_wake_Windows=NOT_RUN", waitExpiry)
}
