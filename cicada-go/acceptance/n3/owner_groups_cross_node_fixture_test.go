package n3_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// One existing NPT Hub/App owns both independent actual Node/Host roots.
type ownerGroupsCrossNodeFixture struct {
	parent   *testing.T
	hub      *directIPHub
	app      *directIPApp
	original appcore.Snapshot
	current  appcore.Snapshot
	nodes    [2]*ownerGroupsCrossNode
}

type ownerGroupsCrossNode struct {
	shared                          *ownerGroupsCrossNodeFixture
	pair                            *nodePairFixture
	root, id, codexHome, privateLog string
	actors                          nativePeerActors
	process                         *nodeProcess
	host                            *ownerGroupsHost
	bound                           nodeActorState
	code                            string // Actual private TTY -> actual App only.
	local                           wire.NodePairTrustScopedCode
	keySHA256                       string
	instance                        string
}

// One explicit, bounded environment for this Node, its private code reader
// and its Host. Never inherit a developer HOME or rely on installer rewrites.
func ownerGroupsCrossEnvironment(home, codexHome string) []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home,
		"CODEX_HOME=" + codexHome, "TMPDIR=" + filepath.Join(home, "tmp"), "LANG=C.UTF-8",
		"CICADA_CODEX_BIN=/tools/codex-package/bin/codex"}
}

func newOwnerGroupsCrossNodeFixture(t *testing.T) *ownerGroupsCrossNodeFixture {
	t.Helper()
	hub := newDirectIPHub(t, "127.0.0.1")
	app, original := hub.activateApp(t)
	f := &ownerGroupsCrossNodeFixture{parent: t, hub: hub, app: app, original: original, current: original}
	for index, tag := range []string{"a", "b"} {
		root := filepath.Join(hub.dir, "cross-node-"+tag)
		home := filepath.Join(root, "home")
		codexHome := filepath.Join(home, "consumer-codex")
		userRoot := filepath.Join(home, ".cicada")
		p := &nodePairFixture{hub: hub, app: app, original: original, home: home, userRoot: userRoot,
			state: filepath.Join(userRoot, "node", "state"), binary: os.Getenv("CICADA_N3_CICADA_BINARY")}
		for _, path := range []string{home, userRoot, p.state, filepath.Join(userRoot, "mcp"), filepath.Join(home, "tmp")} {
			if os.MkdirAll(path, 0700) != nil {
				t.Fatal("independent cross-Node root unavailable")
			}
		}
		p.environment = ownerGroupsCrossEnvironment(home, codexHome)
		nodePairInstallConsumerFiles(t, p) // Real file installation, no enrollment.
		p.environment = ownerGroupsCrossEnvironment(home, codexHome)
		log := must(os.OpenFile(filepath.Join(root, "private-native.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
		t.Cleanup(func() { log.Close() })
		actors := nativePeerActors{prefix: userRoot, log: log, outbox: filepath.Join(userRoot, "mcp", "outbox.sqlite3"),
			environment: ownerGroupsCrossEnvironment(home, codexHome)}
		for actor := 0; actor < 4; actor++ {
			workspace := filepath.Join(root, "workspace-"+string(rune('a'+actor)))
			if os.Mkdir(workspace, 0700) != nil {
				t.Fatal("original four-Thread cross-Node workspace unavailable")
			}
			actors.workspaces = append(actors.workspaces, workspace)
		}
		f.nodes[index] = &ownerGroupsCrossNode{shared: f, pair: p, root: root, id: "synthetic-n3-cross-node-" + tag,
			codexHome: codexHome, privateLog: filepath.Join(p.state, "private-process.log"), actors: actors}
	}
	return f
}

func (f *ownerGroupsCrossNodeFixture) action(t *testing.T, action appcore.Action) appcore.Snapshot {
	t.Helper()
	time.Sleep(time.Second) // Preserve the existing real App account rate bucket.
	reply := f.app.command(t, directIPAppCommand{Action: &action})
	s := reply.Snapshot
	if reply.ActionFailed || s.Account.AccountID != f.original.Account.AccountID || s.Account.OwnerID != f.original.Account.OwnerID || s.Account.DeviceID != f.original.Account.DeviceID ||
		s.Account.LocalOwnerKeyID != f.original.Account.LocalOwnerKeyID || s.Account.OwnerFingerprint != f.original.Account.OwnerFingerprint ||
		s.Account.RootState != f.original.Account.RootState || s.Hub.Fingerprint != f.original.Hub.Fingerprint || s.Hub.HubID != f.original.Hub.HubID ||
		s.Hub.Origin != f.original.Hub.Origin || !s.Hub.Verified || s.Management != appcore.ManagementUnavailable {
		phase := "UNKNOWN"
		switch s.Phase {
		case appcore.PhaseNeedConnection, appcore.PhaseVerifyingHub, appcore.PhaseConnected, appcore.PhaseLocked,
			appcore.PhaseClaimChallenge, appcore.PhaseLoginChallenge, appcore.PhaseAccountPending, appcore.PhaseSessionCheck,
			appcore.PhaseAccountSession, appcore.PhaseOwnerReady, appcore.PhaseActivationPending, appcore.PhaseUnavailable, appcore.PhaseError:
			phase = string(s.Phase)
		}
		t.Logf("OWNER_GROUPS_CROSS_APP_FAILURE action_failed=%t phase=%s app_error_code=%s node_error_code=%s pairing_error_code=%s group_error_code=%s policy_error_code=%s",
			reply.ActionFailed, phase, ownerGroupsCrossErrorCode(s.ErrorCode), ownerGroupsCrossErrorCode(s.Node.ErrorCode),
			ownerGroupsCrossPairError(s), ownerGroupsCrossErrorCode(s.ThreadGroups.ErrorCode), ownerGroupsCrossErrorCode(s.LocalCollaboration.ErrorCode))
		t.Fatalf("actual shared App action failed or changed its original identity: action=%s", action.Kind)
	}
	raw := must(json.Marshal(s))
	defer clear(raw)
	for _, n := range f.nodes {
		if n.code != "" && nodePairContainsSecret(raw, n.code, n.local.OOBSecret) {
			t.Fatal("actual shared App snapshot disclosed private pairing material")
		}
	}
	f.current = s
	return s
}

// Exact static codes only. Neither arbitrary errors nor a syntactically valid
// uppercase secret may enter exported diagnostics through a public view field.
func ownerGroupsCrossErrorCode(code string) string {
	switch code {
	case "APP_NODE_PAIRING_UNKNOWN", "APP_NODE_PAIRING_REFUSED", "APP_NODE_PAIRING_EXPIRED", "APP_NODE_PAIRING_UNAVAILABLE",
		"APP_NODE_PAIRING_STORAGE_FULL", "APP_NODE_PAIRING_CODE_INVALID", "APP_NODE_PAIRING_TRUST_MISMATCH", "APP_NODE_UNAVAILABLE",
		"APP_THREAD_GROUP_STORAGE_FAILED", "APP_THREAD_GROUP_STORAGE_BUDGET", "UNSUPPORTED_PROFILE", "OWNER_AUTHORITY_REQUIRED",
		"TARGET_NOT_AUTHORIZED", "REVIEW_EXPIRED", "CAS_CONFLICT", "KEY_NOT_READY", "OWNER_READD_REQUIRED", "ORIGINAL_PACKET_CONFLICT",
		"OUTCOME_UNCERTAIN", "GROUP_RELATION_LIMIT", "SHARED_MEMBERSHIP_CONFLICT", "CURSOR_STALE", "MANUAL_SOURCE_ALREADY_ACTIVE",
		"RELATION_PENDING", "READ_EXPIRED", "APP_LOCAL_COLLABORATION_UNAVAILABLE", "APP_LOCAL_COLLABORATION_READ_LIMIT":
		return code
	default:
		return safeAppStartupDiagnostic(appStartupDiagnostic{ErrorCode: code}).ErrorCode
	}
}

func ownerGroupsCrossPairError(s appcore.Snapshot) string {
	if s.Node.Pairing == nil {
		return ""
	}
	return ownerGroupsCrossErrorCode(s.Node.Pairing.ErrorCode)
}

func TestN3OwnerGroupsCrossDiagnosticRejectsPrivateText(t *testing.T) {
	for _, private := range []string{"SYNTHETIC_SECRET_UPPERCASE", "SYNTHETIC private code/proof/payload", strings.Repeat("SYNTHETIC_SECRET", 1000)} {
		if ownerGroupsCrossErrorCode(private) != "OTHER" {
			t.Fatal("closed cross-Node App diagnostic disclosed an unregistered private value")
		}
	}
	if ownerGroupsCrossErrorCode("APP_NODE_PAIRING_TRUST_MISMATCH") != "APP_NODE_PAIRING_TRUST_MISMATCH" || ownerGroupsCrossErrorCode("") != "" {
		t.Fatal("closed cross-Node App diagnostic discarded its defined trust refusal or absent code")
	}
}

func (n *ownerGroupsCrossNode) start(t *testing.T) {
	t.Helper()
	if n.process != nil && n.process.running() {
		t.Fatal("cross-Node start would create a second writer for the same root")
	}
	command := exec.Command(n.pair.binary, "machine", "agent", "--relay-only", "--id", n.id, "--name", "SYNTHETIC cross-Node",
		"--hub-address", n.shared.hub.address, "--pairing-profile", "scoped", "--state-dir", n.pair.state, "--interval", "1s",
		"--user-root", n.pair.userRoot, "--mcp-session-state-file", filepath.Join(n.pair.userRoot, "mcp", "sessions.json"),
		"--mcp-outbox-state-file", n.actors.outbox)
	command.Env = append(ownerGroupsCrossEnvironment(n.pair.home, n.codexHome), "CICADA_NODE_SEALED_PHASE_DEBUG=1")
	log := must(os.OpenFile(n.privateLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600))
	n.shared.parent.Cleanup(func() { log.Close() })
	command.Stdout, command.Stderr = log, log
	n.process = &nodeProcess{process: startProcess(n.shared.parent, command), id: n.id, state: n.pair.state}
}

func (n *ownerGroupsCrossNode) readScopedCode(t *testing.T) {
	t.Helper()
	if n.code != "" || n.process == nil {
		t.Fatal("scoped code must come from the original pending actual Node")
	}
	// The delivered consumer emits this non-secret marker only after commit.
	// Observe it, never manufacture an attempt or infer readiness from a timer.
	ready := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		raw, status := ownerGroupsColdRead(n.privateLog, 64<<10)
		ready = status == "COMPLETE" && strings.Contains(string(raw), "Node pairing is pending; use machine pairing-code from a local interactive terminal.")
		clear(raw)
		if ready || !n.process.running() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready || !n.process.running() {
		t.Fatal("actual scoped consumer has not committed a displayable pending request")
	}
	argv := []string{n.pair.binary, "machine", "pairing-code", "--id", n.id, "--state-dir", n.pair.state}
	n.code = nodePairPrivateTTYCodeText(t, n.root, argv, n.pair.environment, wire.NodePairTrustScopedCodePrefix, wire.MaxNodePairTrustScopedCodeBytes)
	n.local = must(wire.DecodeNodePairTrustScopedCode(n.code, time.Now().UTC()))
	n.shared.parent.Cleanup(func() { clear(n.local.OOBSecret); n.code = "" })
	if n.local.AuthorityNodeID != n.id || n.local.Origin != n.shared.hub.descriptor.Claims.Origin ||
		n.local.HubID != n.shared.hub.descriptor.Claims.Hub.HubID || n.local.HubFingerprint != n.shared.original.Hub.Fingerprint {
		t.Fatal("actual scoped code changed its original Node or independently trusted Hub")
	}
	nodePairRedirectRefusesSecret(t, argv, n.pair.environment, n.code, wire.NodePairTrustScopedCodePrefix, n.local.OOBSecret)
	key, status := ownerGroupsColdRead(filepath.Join(filepath.Dir(n.process.statePath()), "node-control-identity.bin"), 1<<20)
	defer clear(key)
	if status != "COMPLETE" || len(key) == 0 {
		t.Fatal("actual pending Node lost its original private key")
	}
	n.keySHA256 = hash(key)
}

// Called only with the actual shared App's authenticated ACKED snapshot, after
// its delivered scoped review/approval/refresh and selected-Node checks.
func (n *ownerGroupsCrossNode) retainACK(t *testing.T, snapshot appcore.Snapshot) {
	t.Helper()
	if n.code == "" || snapshot.Account.OwnerID != n.shared.original.Account.OwnerID || snapshot.Account.DeviceID != n.shared.original.Account.DeviceID ||
		snapshot.Account.LocalOwnerKeyID != n.shared.original.Account.LocalOwnerKeyID || snapshot.Hub.Fingerprint != n.shared.original.Hub.Fingerprint ||
		snapshot.Node.Pairing == nil || snapshot.Node.Pairing.State != wire.NodePairTrustACKed || snapshot.Node.Pairing.NodeID != n.id ||
		snapshot.Node.Binding == nil || snapshot.Node.Binding.NodeID != n.id || snapshot.Node.Binding.ID == "" {
		t.Fatal("actual scoped App has not acknowledged this exact original Node")
	}
	installed := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		raw, status := ownerGroupsColdRead(n.process.statePath(), 8<<20)
		if status == "COMPLETE" && json.Unmarshal(raw, &n.bound) == nil {
			installed = n.bound.BindingID == snapshot.Node.Binding.ID && n.bound.BindingVersion == snapshot.Node.Binding.Version
		}
		clear(raw)
		if installed || !n.process.running() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	key, status := ownerGroupsColdRead(filepath.Join(filepath.Dir(n.process.statePath()), "node-control-identity.bin"), 1<<20)
	defer clear(key)
	if !installed || status != "COMPLETE" || hash(key) != n.keySHA256 || n.bound.NodeID != n.id || n.bound.BindingID != snapshot.Node.Binding.ID ||
		n.bound.BindingVersion != snapshot.Node.Binding.Version || n.bound.NodeKeyID == "" || n.bound.NodeFingerprint == "" ||
		nodewire.IdentityFingerprint(n.bound.HubPublic) != n.local.NodeControlFingerprint {
		t.Fatal("original Node ACK changed its key, binding or independent Node-Control trust")
	}
}

func (n *ownerGroupsCrossNode) startHost(t *testing.T, policy appcore.LocalCollaborationSnapshot) {
	t.Helper()
	if n.bound.BindingID == "" || !policy.Current || policy.Pending || policy.State != wire.LocalDomainActive || policy.NodeID != n.id || policy.NetworkID == "" || policy.GroupID == "" {
		t.Fatal("cross-Node Host lacks actual ACK and explicit current Owner policy")
	}
	n.actors.active = policy
	_, n.instance = threeStageLivePinAt(t, n.process, n.shared.hub.descriptor.Claims.Origin,
		filepath.Join(n.pair.userRoot, "mcp", "sessions.json"), n.pair.userRoot, n.actors.outbox, "")
	n.host, _ = startOwnerGroupsHostAt(n.shared.parent, n.root, n.codexHome, n.process, n.actors)
}

func (n *ownerGroupsCrossNode) restartRetained(t *testing.T, originalBody string) {
	t.Helper()
	if n.bound.BindingID == "" || n.host == nil || n.instance == "" || originalBody == "" {
		t.Fatal("cross-Node restart lacks its original admitted Host and Node")
	}
	original, oldInstance := n.bound, n.instance
	n.process.kill(t)
	if n.process.running() {
		t.Fatal("cross-Node Host recovery requires its original receiving Node stopped")
	}
	// Keep the original pending ASK offline until its retained Host is ready.
	// Never stop the daemon after the receiving Node can accept that delivery.
	recovered := n.host.command(t, ownerGroupsHostCommand{Action: "restart_host"})
	if n.process.running() {
		t.Fatal("cross-Node Host recovery restarted its receiving Node")
	}
	if count, known := recovered.QueuePosts[originalBody]; !known || count != 0 {
		t.Fatal("original offline ASK reached native Runtime during Host recovery")
	}
	n.start(t) // Same actual executable, ID, scoped journal, state and user root.
	_, n.instance = threeStageLivePinAt(t, n.process, n.shared.hub.descriptor.Claims.Origin,
		filepath.Join(n.pair.userRoot, "mcp", "sessions.json"), n.pair.userRoot, n.actors.outbox, oldInstance)
	var current nodeActorState
	readJSON(t, n.process.statePath(), &current)
	key, status := ownerGroupsColdRead(filepath.Join(filepath.Dir(n.process.statePath()), "node-control-identity.bin"), 1<<20)
	defer clear(key)
	if status != "COMPLETE" || hash(key) != n.keySHA256 || current.NodeID != original.NodeID || current.BindingID != original.BindingID ||
		current.BindingVersion != original.BindingVersion || current.NodeKeyID != original.NodeKeyID || current.NodeKeyEpoch != original.NodeKeyEpoch || current.NodeFingerprint != original.NodeFingerprint {
		t.Fatal("cross-Node restart changed its original root, key or binding")
	}
	n.host.node = n.process
}

func (n *ownerGroupsCrossNode) identities(t *testing.T) []ownerGroupsIdentity {
	t.Helper()
	if n.host == nil {
		t.Fatal("cross-Node identity audit requires the actual original Host")
	}
	return ownerGroupsStoredIdentitiesAt(t, filepath.Join(n.shared.hub.state, "cicada.sqlite3"), n.id, n.pair.state,
		n.shared.original.Account.OwnerID, n.actors.workspaces, n.host.originalSIDs)
}

func (f *ownerGroupsCrossNodeFixture) requireIndependentOriginals(t *testing.T) {
	t.Helper()
	a, b := f.nodes[0], f.nodes[1]
	if a.shared != f || b.shared != f || a.pair.app != f.app || b.pair.app != f.app || a.pair.hub != f.hub || b.pair.hub != f.hub ||
		a.root == b.root || a.pair.state == b.pair.state || a.codexHome == b.codexHome || a.actors.outbox == b.actors.outbox ||
		a.id == b.id || a.bound.BindingID == "" || b.bound.BindingID == "" || a.bound.BindingID == b.bound.BindingID ||
		a.keySHA256 == "" || b.keySHA256 == "" || a.keySHA256 == b.keySHA256 || a.process == nil || b.process == nil ||
		a.process.cmd.Process.Pid == b.process.cmd.Process.Pid || a.host == nil || b.host == nil || a.host.latestDaemon.PID == b.host.latestDaemon.PID {
		t.Fatal("cross-Node fixture merged an original process, root, key, binding or Hub/App")
	}
	if a.actors.active.NetworkID == "" || a.actors.active.NetworkID != b.actors.active.NetworkID {
		t.Fatal("cross-Node policies did not select the same existing Network")
	}
	seen := make(map[string]bool)
	for _, n := range f.nodes {
		for _, sid := range n.host.originalSIDs {
			if seen[sid] {
				t.Fatal("two actual Nodes share an original native Thread SID")
			}
			seen[sid] = true
		}
	}
	if len(seen) != 8 {
		t.Fatal("two actual Hosts did not retain four original Threads each")
	}
}
