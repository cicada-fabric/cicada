package n3_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nodePairInstallConsumerFiles(t *testing.T, v *nodePairFixture) {
	t.Helper()
	var rows [][]string
	for _, path := range []string{".agents/plugins/cicada/.codex-plugin/plugin.json", ".agents/plugins/cicada/.mcp.json", ".agents/plugins/cicada/hooks/hooks.json", ".agents/plugins/cicada/skills/cicada-network/SKILL.md", ".agents/plugins/marketplace.json"} {
		rows = append(rows, []string{path, hash(readPrivate(t, filepath.Join("/repo", path)))})
	}
	assets := hash(must(json.Marshal(map[string]any{"format": "cicada.codex-plugin-assets.v1", "files": rows})))
	if directIPCLIAt(t, v.hub.binary, "components", "install", "--prefix", v.userRoot, "--components", "node", "--binary", v.binary,
		"--sha256", hash(readPrivateBinary(t, v.binary)), "--licenses", "/licenses", "--codex-plugin-assets", "/repo", "--codex-plugin-sha256", assets) != 0 {
		t.Fatal("initial file-only Node/plugin material installation failed")
	}
	noDirectIPInstalledProcess(t, v.userRoot)
	v.binary = filepath.Join(v.userRoot, "components", "node", "bin", "cicada")
	if hash(readPrivateBinary(t, v.binary)) != hash(readPrivateBinary(t, v.hub.binary)) {
		t.Fatal("file-installed consumer executable changed the acceptance build")
	}
	for i, value := range v.environment {
		if strings.HasPrefix(value, "CODEX_HOME=") {
			v.environment[i] = "CODEX_HOME=" + filepath.Join(v.home, "consumer-codex")
		}
	}
	v.environment = append(v.environment, "CICADA_CODEX_BIN=/tools/codex-package/bin/codex")
	if os.Mkdir(filepath.Join(v.home, "consumer-codex"), 0700) != nil {
		t.Fatal("owned zero-model native consumer home unavailable")
	}
}

func nodePairAutomaticPinConsumer(t *testing.T, v *nodePairFixture) {
	t.Helper()
	originalPID := v.node.cmd.Process.Pid
	originalContext, _ := v.side(t)
	v.assertAutomaticOwnerPin(t, v.original)
	admitted := v.action(t, appcore.Action{Kind: appcore.ActionRefreshNode})
	if admitted.Node.Binding == nil {
		t.Fatal("original automatic admission binding unavailable before native consumer")
	}
	initial := v.action(t, appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !initial.Current || initial.Pending || initial.State != "UNCONFIGURED" {
		t.Fatal("new automatically pinned Node did not expose an initially unconfigured separate local policy")
	}
	preview := v.action(t, appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "SYNTHETIC automatic-pin consumer Network", GroupName: "SYNTHETIC automatic-pin consumer Group"}}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.ReviewID == "" || preview.NodeID != v.node.id || preview.LocalUserScope != "uid:1000" {
		t.Fatal("actual original App did not review the same Node/user local policy")
	}
	active := v.action(t, appcore.Action{Kind: appcore.ActionActivateLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}).LocalCollaboration
	requireSameLocalDomain(t, preview, active)
	if active.State != wire.LocalDomainActive || active.GroupID == "" || active.PolicyID == "" {
		t.Fatal("explicit separate original Owner policy did not activate for the automatically pinned Node")
	}
	workspace := filepath.Join(v.home, "single-native-consumer-workspace")
	if os.Mkdir(workspace, 0700) != nil {
		t.Fatal("owned single native consumer workspace unavailable")
	}
	config, result := filepath.Join(v.hub.dir, "private-native-consumer-config.json"), filepath.Join(v.hub.dir, "private-native-consumer-result.json")
	environment := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + v.home, "CODEX_HOME=" + filepath.Join(v.home, "consumer-codex"),
		"TMPDIR=" + filepath.Join(v.home, "tmp"), "LANG=C.UTF-8", "TERM=xterm-256color"}
	writeJSON(t, config, map[string]any{"root": v.hub.dir, "workspace": workspace, "codex_home": filepath.Join(v.home, "consumer-codex"),
		"environment": environment, "codex_binary": "/tools/codex-package/bin/codex", "codex_sha256": directIPCodexSHA256, "codex_version": directIPCodexVersion,
		"marketplace": filepath.Join(v.userRoot, "components/node/share/codex"), "step": "node-pair-consumer", "persistent_daemon": true,
		"allow_test_termination": true, "daemon_umask": "0002", "preparation": "none", "result": result, "selected_root": v.userRoot,
		"require_unique_literal_titles": true})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "/qa/scripts/fixtures/native-pair/node_pair_native_consumer.py", config)
	cmd.Env, cmd.Dir = environment, workspace
	log := must(os.OpenFile(filepath.Join(v.hub.dir, "private-native-consumer.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600))
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	runError := cmd.Run()
	var r struct {
		Scope           string `json:"scope"`
		Status          string `json:"status"`
		NativeID        string `json:"native_session_id"`
		Workspace       string `json:"workspace"`
		ProviderPosts   *int   `json:"provider_posts"`
		RealModelTurns  *int   `json:"real_model_turns"`
		ManualPin       *bool  `json:"manual_Owner_pin_used"`
		Cleanup         bool   `json:"cleanup_confirmed"`
		FailurePhase    string `json:"failure_phase"`
		FailureCategory string `json:"failure_category"`
		DaemonStopState string `json:"daemon_after_stop_state"`
		Daemon          struct {
			PID       int    `json:"pid"`
			Start     string `json:"start_ticks"`
			Umask     string `json:"umask"`
			EnvAbsent bool   `json:"five_deployment_variables_absent"`
			SHA       string `json:"executable_sha256"`
		} `json:"daemon"`
		MCP struct {
			Tools int             `json:"tools_count"`
			Error json.RawMessage `json:"tools_error"`
		} `json:"MCP"`
	}
	if _, err := os.Stat(result); err != nil {
		t.Fatal("actual zero-model native consumer did not retain its bounded result")
	}
	readJSON(t, result, &r)
	if runError != nil || ctx.Err() != nil || r.Scope != "ACTUAL_AUTOMATIC_PIN_TO_EXISTING_NATIVE_DAEMON_PLUGIN_LITERAL_JOIN" || r.Status != "SCOPED_PASS" ||
		r.NativeID == "" || r.Workspace != workspace || r.ProviderPosts == nil || *r.ProviderPosts != 0 || r.RealModelTurns == nil || *r.RealModelTurns != 0 ||
		r.ManualPin == nil || *r.ManualPin || !r.Cleanup || r.Daemon.PID <= 0 || r.Daemon.Start == "" || r.Daemon.Umask != "0002" ||
		!r.Daemon.EnvAbsent || r.Daemon.SHA != directIPCodexSHA256 || r.MCP.Tools <= 0 || len(r.MCP.Error) != 0 && string(r.MCP.Error) != "null" {
		posts, models := -1, -1
		if r.ProviderPosts != nil {
			posts = *r.ProviderPosts
		}
		if r.RealModelTurns != nil {
			models = *r.RealModelTurns
		}
		t.Fatalf("actual automatically pinned native consumer refused: phase=%s category=%s status=%s run_failed=%t timeout=%t scope_ok=%t native_ID_present=%t workspace_same=%t provider_posts=%d model_turns=%d manual_pin_present=%t cleanup=%t daemon_after_stop=%s daemon_PID_present=%t daemon_start_present=%t daemon_umask=%s daemon_environment_absent=%t daemon_hash_same=%t MCP_tools=%d MCP_error_null=%t", r.FailurePhase, r.FailureCategory,
			r.Status, runError != nil, ctx.Err() != nil, r.Scope == "ACTUAL_AUTOMATIC_PIN_TO_EXISTING_NATIVE_DAEMON_PLUGIN_LITERAL_JOIN", r.NativeID != "", r.Workspace == workspace,
			posts, models, r.ManualPin != nil, r.Cleanup, r.DaemonStopState, r.Daemon.PID > 0, r.Daemon.Start != "", r.Daemon.Umask,
			r.Daemon.EnvAbsent, r.Daemon.SHA == directIPCodexSHA256, r.MCP.Tools, string(r.MCP.Error) == "null")
	}
	if !v.node.running() || v.node.cmd.Process.Pid != originalPID {
		t.Fatal("native consumer replaced the original automatically pinned Node process")
	}
	currentContext, state := v.side(t)
	if state != wire.NodePairTrustACKed || !reflect.DeepEqual(currentContext, originalContext) {
		t.Fatal("existing consumer regenerated the original Node onboarding identity")
	}
	// The actual literal Hook/Node created this member; no fixture supplies SID,
	// Endpoint, key grant, context ticket or a manual Owner pin.
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	var memberJSON, grantJSON []byte
	if db.QueryRow(`SELECT member_json,key_grant_json FROM hub_local_domain_members_v1 WHERE policy_id=? AND native_session_id=? AND node_id=? AND state='ACTIVE'`,
		active.PolicyID, r.NativeID, v.node.id).Scan(&memberJSON, &grantJSON) != nil {
		t.Fatal("actual native consumer has no original active Hub member/key grant")
	}
	db.Close()
	var member wire.LocalDomainMember
	var grant wire.LocalDomainEndpointKeyGrant
	if json.Unmarshal(memberJSON, &member) != nil || json.Unmarshal(grantJSON, &grant) != nil || !reflect.DeepEqual(member, grant.Member) ||
		member.NativeSessionID != r.NativeID || member.Workspace != workspace || member.EndpointID == "" || member.BindingEpoch == 0 || member.NodeID != v.node.id {
		t.Fatal("actual native member changed original Thread/workspace/Node identity")
	}
	crypto := nodePairReadOnlyDB(t, filepath.Join(v.state, "nodes", "node-"+url.PathEscape(v.node.id), "node-crypto-state.sqlite"))
	defer crypto.Close()
	var pinJSON, localGrant []byte
	if crypto.QueryRow(`SELECT public_identity_json FROM node_crypto_owner_key_trust WHERE owner_id=? AND key_id=? AND state='ACTIVE' AND version=1`,
		v.original.Account.OwnerID, v.original.Account.LocalOwnerKeyID).Scan(&pinJSON) != nil ||
		crypto.QueryRow(`SELECT grant_json FROM node_local_domain_members_v1 WHERE group_id=? AND endpoint_id=?`, active.GroupID, member.EndpointID).Scan(&localGrant) != nil {
		t.Fatal("existing Node consumer did not retain the original automatic pin and delegated native grant together")
	}
	var owner e2ee.PublicIdentity
	var delegated wire.LocalDomainEndpointKeyGrant
	if json.Unmarshal(pinJSON, &owner) != nil || json.Unmarshal(localGrant, &delegated) != nil || !reflect.DeepEqual(delegated, grant) {
		t.Fatal("existing native consumer substituted its stored Owner pin/delegation")
	}
	policy := must(wire.VerifyLocalDomainEndpointKeyGrant(delegated, v.hub.descriptor.Claims.Hub, v.original.Account.OwnerID, owner, time.Now().UTC()))
	if policy.PolicyID != active.PolicyID || policy.Node.NodeID != v.node.id {
		t.Fatal("native delegated endpoint proof differs from the original explicit Owner policy")
	}
	v.assertAutomaticOwnerPin(t, v.original)
	publicPath := os.Getenv("CICADA_N3_NODE_PAIR_CONSUMER_PUBLIC_SUMMARY")
	if publicPath != "/state/node-pair-native-consumer-public-summary.json" {
		t.Fatal("owned exact automatic-pin consumer summary path required")
	}
	writeJSON(t, publicPath, map[string]any{"scope": "ACTUAL_AUTOMATIC_PIN_EXISTING_DAEMON_PLUGIN_ZERO_MODEL", "status": "SCOPED_PASS",
		"codex_version": directIPCodexVersion, "original_daemon": r.Daemon, "hub_id": v.hub.descriptor.Claims.Hub.HubID,
		"node_id": v.node.id, "node_binding_id": admitted.Node.Binding.ID, "Owner_key_id": owner.ID,
		"native_session_id": r.NativeID, "workspace": workspace, "endpoint_id": member.EndpointID, "group_id": active.GroupID,
		"policy_id": active.PolicyID, "binding_epoch": member.BindingEpoch, "MCP_tools_count": r.MCP.Tools,
		"provider_posts": 0, "real_model_turns": 0, "manual_Owner_pin_used": false, "automatic_pin": true,
		"same_original_Node": true, "delegated_grant_verified": true, "cleanup_confirmed": true})
	t.Logf("NODE_PAIR_EXISTING_CONSUMER same_original_Node=true automatic_pin=true delegated_native_grant_verified=true actual_daemon_plugin_literal=true provider_posts=0 native_SID_sha256=%s", hash([]byte(r.NativeID)))
}
