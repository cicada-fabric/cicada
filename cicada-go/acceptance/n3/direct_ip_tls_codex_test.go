package n3_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const directIPCodexVersion = "0.164.0"
const directIPCodexSHA256 = "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"

type directIPNodeFixture struct {
	hub                      *directIPHub
	app                      *directIPApp
	original                 appcore.Snapshot
	node                     *nodeProcess
	bound                    nodeActorState
	adapter                  *hubFixture
	root, home, codex, mcp   string
	state, prefix, workspace string
	environment              []string
}

func (v *directIPNodeFixture) do(t *testing.T, action appcore.Action) appcore.Snapshot {
	t.Helper()
	// Respect the production account rate bucket; concurrent attack cases use
	// separate paths and do not gain authority from this orchestration delay.
	time.Sleep(time.Second)
	reply := v.app.command(t, directIPAppCommand{Action: &action})
	s := reply.Snapshot
	if reply.ActionFailed || s.Account.OwnerID != v.original.Account.OwnerID || s.Account.DeviceID != v.original.Account.DeviceID ||
		s.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID || s.Hub.Fingerprint != v.original.Hub.Fingerprint ||
		s.Management != appcore.ManagementUnavailable {
		t.Fatalf("actual direct TLS App action failed or changed identity: action=%s", action.Kind)
	}
	return s
}

func newDirectIPNodeFixture(t *testing.T, host string) *directIPNodeFixture {
	t.Helper()
	f := newDirectIPHub(t, host)
	a, original := f.activateApp(t)
	v := &directIPNodeFixture{hub: f, app: a, original: original, root: filepath.Join(f.dir, "native-product")}
	v.home, v.codex = filepath.Join(v.root, "home"), filepath.Join(v.root, "codex")
	v.state, v.prefix = filepath.Join(v.home, ".cicada", "node", "state"), filepath.Join(v.root, "installed-native-root")
	v.mcp, v.workspace = filepath.Join(v.root, "mcp", "sessions.json"), filepath.Join(v.root, "workspace")
	for _, dir := range []string{v.home, v.codex, v.state, v.workspace, filepath.Dir(v.mcp), filepath.Join(v.root, "tmp")} {
		if os.MkdirAll(dir, 0700) != nil {
			t.Fatal("owned direct TLS Node directories unavailable")
		}
	}
	v.environment = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + v.home, "CODEX_HOME=" + v.codex,
		"TMPDIR=" + filepath.Join(v.root, "tmp"), "LANG=C.UTF-8", "TERM=xterm-256color", "CICADA_CODEX_BIN=/tools/codex-package/bin/codex"}
	v.adapter = &hubFixture{dir: f.dir, parent: t, mode: "--hub-nodes-only", cfg: fixtureConfig{Origin: f.material.Origin, Hub: f.descriptor.Claims.Hub, Material: f.material}, hub: f.hub}
	v.start(t, false)
	pending := v.node.awaitState(t, v.adapter, false)
	v.node.kill(t)
	s := v.do(t, appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode})
	c := s.Node.Candidate
	if c == nil || c.NodeID != v.node.id || c.NodeFingerprint != pending.PendingCandidate.NodeFingerprint ||
		c.NodeKeyEpoch != pending.PendingCandidate.NodeKeyEpoch || c.HubControlFingerprint != pending.PendingCandidate.HubFingerprint {
		t.Fatal("actual direct TLS App changed the actual Node's original pending candidate")
	}
	s = v.do(t, appcore.Action{Kind: appcore.ActionApproveNode, NodeReviewID: c.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if s.Node.Binding == nil || !s.Node.Binding.Authorized || !s.Node.Access.Confirmed {
		t.Fatal("actual App did not approve the exact direct TLS Node")
	}
	v.start(t, false)
	v.bound = v.node.awaitState(t, v.adapter, true)
	if v.bound.NodeKeyID != pending.PendingCandidate.NodeKeyID || v.bound.BindingID != s.Node.Binding.ID {
		t.Fatal("actual Node restart changed the approved cryptographic binding")
	}
	return v
}

func (v *directIPNodeFixture) start(t *testing.T, installed bool) {
	t.Helper()
	binary := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(v.hub.binary))), "node", "bin", "cicada")
	if installed {
		binary = filepath.Join(v.prefix, "components", "node", "bin", "cicada")
	}
	args := []string{"machine", "agent", "--relay-only", "--id", "synthetic-n3-direct-tls", "--name", "Synthetic direct TLS Node",
		"--hub-connection-file", filepath.Join(v.hub.dir, "public-transport.txt"), "--hub-dial-address", v.hub.address,
		"--state-dir", v.state, "--interval", "1s"}
	if installed {
		args = append(args, "--user-root", v.prefix, "--mcp-session-state-file", v.mcp,
			"--mcp-outbox-state-file", filepath.Join(filepath.Dir(v.mcp), "outbox.sqlite3"))
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = v.environment
	log := must(os.OpenFile(filepath.Join(v.state, "private-process.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600))
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log
	v.node = &nodeProcess{process: startProcess(t, cmd), id: "synthetic-n3-direct-tls", state: v.state}
}

func (v *directIPNodeFixture) publicOwnerPin(t *testing.T) {
	t.Helper()
	path := filepath.Join(v.root, "actual-app-owner-public.json")
	s := v.do(t, appcore.Action{Kind: appcore.ActionExportOwnerPublic, PublicExportPath: path})
	var public e2ee.PublicIdentity
	readJSON(t, path, &public)
	if public.ID != s.Account.LocalOwnerKeyID || must(nodekeys.PeerKeyFingerprint(public)) != s.Account.OwnerPeerFingerprint {
		t.Fatal("actual App public Owner export differs from its independent display")
	}
	v.node.kill(t)
	cmd := exec.Command(v.hub.binary, "machine", "trust-owner-key", "--id", v.node.id, "--state-dir", v.state, "--writer-root", v.state,
		"--owner-id", s.Account.OwnerID, "--public", path, "--expect-key-id", s.Account.LocalOwnerKeyID, "--expect-fingerprint", s.Account.OwnerPeerFingerprint)
	cmd.Env = v.environment
	if cmd.Run() != nil {
		t.Fatal("existing manual public Owner pin command failed")
	}
}

func directIPNativeCodex(t *testing.T, v *directIPNodeFixture) map[string]any {
	t.Helper()
	v.publicOwnerPin(t)
	originalNode := hash(readPrivate(t, v.node.statePath()))
	var workspaces []string
	for _, letter := range []string{"a", "b", "c"} {
		path := filepath.Join(v.root, "native-workspace-"+letter)
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("owned native workspace unavailable")
		}
		workspaces = append(workspaces, path)
	}
	control := filepath.Join(v.root, "native-control")
	config, result := filepath.Join(v.root, "private-native-config.json"), filepath.Join(v.root, "private-native-result.json")
	environment := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + v.home, "CODEX_HOME=" + v.codex,
		"TMPDIR=" + filepath.Join(v.root, "tmp"), "LANG=C.UTF-8", "TERM=xterm-256color"}
	writeJSON(t, config, map[string]any{"root": v.root, "workspace": workspaces[0], "workspaces": workspaces, "codex_home": v.codex,
		"environment": environment, "codex_binary": "/tools/codex-package/bin/codex", "codex_sha256": directIPCodexSHA256, "codex_version": directIPCodexVersion,
		"marketplace": "/repo", "step": "domain-native", "persistent_daemon": true, "allow_test_termination": true,
		"daemon_umask": "0002", "fresh_threads": 2, "preparation": "none", "control": control, "result": result,
		"require_unique_literal_titles": true, "selected_root": v.prefix})
	log := must(os.OpenFile(filepath.Join(v.root, "private-native.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600))
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/codex_domain_native.py", config)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = environment, workspaces[0], log, log
	client := startProcess(t, cmd)
	var daemon nativeDomainDaemon
	var roundtrip struct {
		RequestID string `json:"request_id"`
		Question  string `json:"question_sha256"`
		Answer    string `json:"answer_sha256"`
	}
	await := func(step int) nativeDomainCheckpoint {
		t.Helper()
		deadline := time.Now().Add(4 * time.Minute)
		path := filepath.Join(control, strconv.Itoa(step)+".reply.json")
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				var r nativeDomainCheckpoint
				readJSON(t, path, &r)
				if step == 2 {
					var proof struct {
						Roundtrip json.RawMessage `json:"roundtrip"`
					}
					readJSON(t, path, &proof)
					if json.Unmarshal(proof.Roundtrip, &roundtrip) != nil || roundtrip.RequestID == "" || len(roundtrip.Question) != 64 || len(roundtrip.Answer) != 64 {
						t.Fatal("actual Host roundtrip lacks its original request and content digests")
					}
				}
				if r.Status != "SCOPED_PASS" || r.LiteralPosts != 0 || r.Daemon.PID <= 0 || r.Daemon.Start == "" || r.Daemon.Umask != "0002" || !r.Daemon.EnvEmpty ||
					r.Daemon.Binary != directIPCodexSHA256 || step != 0 && daemon != r.Daemon {
					t.Fatal("actual native daemon checkpoint changed identity or refused")
				}
				if step == 0 {
					daemon = r.Daemon
				}
				return r
			}
			if !client.running() {
				var failure struct {
					Phase string `json:"failure_phase"`
					Label string `json:"failure_label"`
					Code  string `json:"failure_code"`
				}
				if _, err := os.Stat(result); err == nil {
					readJSON(t, result, &failure)
				}
				t.Fatalf("actual native driver stopped: phase=%s label=%s code=%s", failure.Phase, failure.Label, failure.Code)
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("actual native driver checkpoint deadline exceeded")
		return nativeDomainCheckpoint{}
	}
	send := func(step int, value any) {
		writeJSON(t, filepath.Join(control, strconv.Itoa(step)+".command.json"), value)
	}
	await(0)
	if v.node.running() || hash(readPrivate(t, v.node.statePath())) != originalNode {
		t.Fatal("original daemon startup changed or started the stopped Node")
	}
	assetPaths := []string{".agents/plugins/cicada/.codex-plugin/plugin.json", ".agents/plugins/cicada/.mcp.json", ".agents/plugins/cicada/hooks/hooks.json", ".agents/plugins/cicada/skills/cicada-network/SKILL.md", ".agents/plugins/marketplace.json"}
	var rows [][]string
	for _, path := range assetPaths {
		rows = append(rows, []string{path, hash(readPrivate(t, filepath.Join("/repo", path)))})
	}
	assets := hash(must(json.Marshal(map[string]any{"format": "cicada.codex-plugin-assets.v1", "files": rows})))
	if directIPCLIAt(t, v.hub.binary, "components", "install", "--prefix", v.prefix, "--components", "node", "--binary", v.hub.binary,
		"--sha256", hash(readPrivateBinary(t, v.hub.binary)), "--licenses", "/licenses", "--codex-plugin-assets", "/repo", "--codex-plugin-sha256", assets) != 0 ||
		v.node.running() || hash(readPrivate(t, v.node.statePath())) != originalNode {
		t.Fatal("file-only Node/plugin installation changed or started the original Node")
	}
	noDirectIPInstalledProcess(t, v.prefix)
	v.start(t, true)
	bound := v.node.awaitState(t, v.adapter, true)
	if bound.BindingID != v.bound.BindingID || bound.NodeKeyID != v.bound.NodeKeyID || bound.NodeKeyEpoch != v.bound.NodeKeyEpoch {
		t.Fatal("installed Node replaced its approved original identity")
	}
	initial := v.do(t, appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	if !initial.Current || initial.Pending || initial.State != "UNCONFIGURED" {
		t.Fatal("actual Node policy is not initially unconfigured")
	}
	preview := v.do(t, appcore.Action{Kind: appcore.ActionPrepareLocalCollaboration, LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "Synthetic direct TLS Network", GroupName: "Synthetic direct TLS Group"}}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.ReviewID == "" || preview.NodeID != v.node.id || preview.LocalUserScope != "uid:1000" || preview.ExpiresAt != "" {
		t.Fatal("actual App did not review the exact persistent Node/user policy")
	}
	active := v.do(t, appcore.Action{Kind: appcore.ActionActivateLocalCollaboration, LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}).LocalCollaboration
	requireSameLocalDomain(t, preview, active)
	if active.State != wire.LocalDomainActive || active.GroupID == "" {
		t.Fatal("actual App did not activate its original policy")
	}
	send(1, map[string]any{"marketplace": filepath.Join(v.prefix, "components/node/share/codex"), "node_id": v.node.id, "group_id": active.GroupID, "policy_id": active.PolicyID})
	joined := await(1)
	if len(joined.IDs) != 2 || joined.IDs[0] == "" || joined.IDs[0] == joined.IDs[1] {
		t.Fatal("actual native A/B records are not distinct")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	send(2, map[string]any{"app_closed": true})
	communicated := await(2)
	if !communicated.Directory || len(communicated.Actors) != 2 {
		t.Fatal("actual Host identity/directory/ASK/Reply results missing")
	}
	for i, actor := range communicated.Actors {
		if actor.SID != joined.IDs[i] || actor.Workspace != workspaces[i] || actor.NodeID != v.node.id || actor.GroupID != active.GroupID || actor.Endpoint == "" || actor.Epoch == 0 {
			t.Fatal("actual Host used another native identity or scope")
		}
	}
	if communicated.Actors[0].Endpoint == communicated.Actors[1].Endpoint {
		t.Fatal("actual A/B endpoints collapsed")
	}
	send(3, map[string]any{"wait_login_expiry": false})
	aged := await(3)
	if aged.Expired || !reflect.DeepEqual(aged.Actors, communicated.Actors) {
		t.Fatal("short native gate changed identity or claimed unexecuted expiry")
	}
	v.app = startDirectIPApp(t, v.app.dir)
	profiles := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if profiles.ActionFailed || len(profiles.Snapshot.Profiles) != 1 {
		t.Fatal("original direct TLS profile unavailable after normal App close")
	}
	resumed := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles.Snapshot.Profiles[0].ID}})
	if resumed.ActionFailed || resumed.Snapshot.Account.DeviceID != v.original.Account.DeviceID {
		t.Fatal("actual App resume changed its original device")
	}
	read := ownerDirectoryReadAction(t, resumed.Snapshot)
	directory := v.do(t, read).OwnerEndpoints
	if directory.State != "SNAPSHOT_ONLY" || directory.Pending {
		t.Fatal("actual App did not authenticate the original Node's signed directory snapshot")
	}
	for _, actor := range communicated.Actors {
		found := false
		for _, card := range directory.Endpoints {
			if card.EndpointID == actor.Endpoint && card.Workspace == actor.Workspace {
				found = true
			}
		}
		if !found {
			t.Fatal("actual Host coordinates differ from the App's Owner-signed directory read")
		}
	}
	current := v.do(t, appcore.Action{Kind: appcore.ActionRefreshLocalCollaboration}).LocalCollaboration
	requireSameLocalDomain(t, active, current)
	revoked := v.do(t, appcore.Action{Kind: appcore.ActionRevokeLocalCollaboration, LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: current.StateReviewID, ConfirmRevoke: true}}).LocalCollaboration
	if revoked.State != wire.LocalDomainRevoked || !v.hub.hub.running() || !v.node.running() {
		t.Fatal("actual revoke lacks healthy original Hub/Node")
	}
	revokeCommitted := time.Now().UTC()
	heartbeat := directIPPostRevokeHeartbeat(t, v, revokeCommitted)
	send(4, map[string]any{"current_policy_state": wire.LocalDomainRevoked, "Hub_and_Node_healthy": true})
	denied := await(4)
	if !denied.Denied || !denied.DirectoryDenied || !v.hub.hub.running() || !v.node.running() {
		t.Fatal("current native denial lacks healthy original services")
	}
	select {
	case <-client.done:
	case <-time.After(20 * time.Second):
		t.Fatal("owned native driver cleanup deadline exceeded")
	}
	var final struct {
		Status        string `json:"status"`
		HostCalls     int    `json:"host_calls_completed"`
		HostPosts     int    `json:"host_provider_posts"`
		QueuePosts    int    `json:"native_queue_provider_posts"`
		ProviderPosts int    `json:"static_provider_posts"`
	}
	readJSON(t, result, &final)
	if client.cmd.ProcessState.ExitCode() != 0 || final.Status != "SCOPED_PASS" || final.HostCalls < 8 || final.HostPosts != 2*final.HostCalls || final.QueuePosts < 0 || final.ProviderPosts != final.HostPosts+final.QueuePosts {
		t.Fatal("actual native static-provider gate did not finish its measured main line")
	}
	family := 4
	if strings.HasPrefix(v.hub.address, "[") {
		family = 6
	}
	public := map[string]any{
		"scope": "ACTUAL_DIRECT_NATIVE_TLS_HUB_APP_NODE_CODEX_STATIC_NOT_PUBLIC_WINDOWS", "status": "SCOPED_PASS", "original_daemon": daemon,
		"codex_version":       directIPCodexVersion,
		"revoke_committed_at": revokeCommitted.Format(time.RFC3339Nano), "post_revoke_node_heartbeat_at": heartbeat,
		"address_family": family, "dial_address": v.hub.address, "hub_id": v.hub.material.HubID,
		"actors": communicated.Actors, "original_roundtrip": roundtrip, "App_Owner_signed_directory_matched": true,
		"host_calls_completed": final.HostCalls, "host_provider_posts": final.HostPosts, "native_queue_provider_posts": final.QueuePosts,
		"static_provider_posts": final.ProviderPosts, "literal_provider_posts": 0, "real_model_turns_started": 0,
		"actual_wall_clock_login_expiry": false, "manual_independent_Owner_public_pin": true,
		"directory_filters_verified": communicated.Directory, "directory_after_revoke_denied": denied.DirectoryDenied,
		"new_business_denied_after_revoke": denied.Denied, "Hub_Node_healthy_at_revoke": v.hub.hub.running() && v.node.running(),
	}
	t.Logf("DIRECT_IP_NATIVE actual_Host_calls=%d static_provider_POSTs=%d actual_native_A_B=true directory_ASK_Reply=true selected_Node=true manual_Owner_public_pin=true login_expiry=NOT_RUN real_model=NOT_RUN", final.HostCalls, final.ProviderPosts)
	return public
}

func directIPPostRevokeHeartbeat(t *testing.T, v *directIPNodeFixture, after time.Time) string {
	t.Helper()
	u := &url.URL{Scheme: "file", Path: filepath.Join(v.hub.state, "cicada.sqlite3"), RawQuery: "mode=ro"}
	db := must(sql.Open("sqlite", u.String()))
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		if !v.hub.hub.running() || !v.node.running() {
			t.Fatal("original Hub/Node exited while qualifying current revoke")
		}
		var stamp, status string
		if err := db.QueryRowContext(ctx, `SELECT m.last_seen,m.status FROM machines m JOIN node_owner_bindings_v2 b ON b.node_id=m.id AND b.owner_id=m.owner_id WHERE m.id=? AND m.owner_id=? AND b.id=? AND b.state='ACTIVE'`, v.node.id, v.original.Account.OwnerID, v.bound.BindingID).Scan(&stamp, &status); err == nil {
			at, err := time.Parse(time.RFC3339Nano, stamp)
			// Relay-only deliberately leaves the worker-status projection
			// unchanged. A fresh authenticated heartbeat on the exact active
			// binding proves transport health even when no Worker is online.
			if err == nil && at.After(after) {
				return stamp
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("read-only Hub witness did not observe a fresh authorized Node heartbeat after policy revoke")
	return ""
}

func directIPFamilies(t *testing.T) {
	directIPNodeTrustFaults(t)
	var reports []map[string]any
	for _, host := range []string{"127.0.0.1", "::1"} {
		v := newDirectIPNodeFixture(t, host)
		reports = append(reports, directIPNativeCodex(t, v))
		v.app.command(t, directIPAppCommand{Close: true})
		v.node.kill(t)
		v.hub.hub.kill(t)
	}
	writeJSON(t, "/state/direct-ip-native-public-summary.json", map[string]any{"scope": "DUAL_STACK_ACTUAL_DIRECT_NATIVE_TLS_STATIC_PROVIDER", "reports": reports})
	directIPFacts(t, "DIP02_IPv4IPv6NoDNS", map[string]bool{"IPv4_App_Node": true, "IPv6_App_Node": true, "actual_Node_restart": true,
		"Node_wrong_live_identity_zero_secrets": true, "actual_original_Codex_Host": true, "selected_Node_MCP_directory_ASK_Reply": true, "normal_App_close_communication": true, "current_revoke_healthy_services": true})
}

func directIPNodeTrustFaults(t *testing.T) {
	t.Helper()
	a := newDirectIPTLSAdversary(t)
	other := newDirectIPTLSAdversary(t)
	now := time.Now().UTC()
	leaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
	for _, fault := range []string{"Node-Control-key", "Hub-ID", "Node-key-version"} {
		public := a.descriptor.Claims.NodeControl
		identity := nodebinding.HubIdentity{Version: nodewire.Version, Algorithm: e2ee.Algorithm, HubID: a.descriptor.Claims.Hub.HubID,
			KeyID: public.ID, KeyVersion: a.descriptor.Claims.NodeControlKeyVersion, Fingerprint: nodewire.IdentityFingerprint(public), PublicIdentity: public}
		switch fault {
		case "Node-Control-key":
			identity.PublicIdentity = other.descriptor.Claims.NodeControl
			identity.KeyID = identity.PublicIdentity.ID
			identity.Fingerprint = nodewire.IdentityFingerprint(identity.PublicIdentity)
		case "Hub-ID":
			identity.HubID = "hub_SYNTHETIC_foreign_Node_scope"
		case "Node-key-version":
			identity.KeyVersion++
		}
		trap := newDirectIPIdentityTrap(t, http.StatusOK, "", &identity, leaf)
		dir := t.TempDir()
		descriptorFile := filepath.Join(dir, "public-transport.txt")
		atomicPrivate(t, descriptorFile, []byte(must(hubtransport.EncodeDescriptor(a.descriptor))))
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, os.Getenv("CICADA_N3_CICADA_BINARY"), "machine", "agent", "--relay-only", "--once", "--id", "synthetic-n3-wrong-live-node",
			"--name", "Synthetic rejected Node", "--state-dir", filepath.Join(dir, "state"), "--hub-connection-file", descriptorFile, "--hub-dial-address", trap.server.Listener.Addr().String())
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir}
		err := cmd.Run()
		expired := ctx.Err() != nil
		cancel()
		if expired || err == nil || trap.calls.Load() == 0 || trap.posts.Load() != 0 || trap.bytes.Load() != 0 || trap.creds.Load() != 0 {
			t.Fatal("actual Node failed to fence a valid-TLS mismatched Node-Control identity before credential/device-code traffic")
		}
	}
}
