package n3_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Actual original App/Hub/Node bootstrap shared with the established native
// peer-form scene. No management authority is installed by SQL or a fake actor.
type nativePeerActors struct {
	prefix      string
	workspaces  []string
	environment []string
	log         *os.File
	outbox      string
	active      appcore.LocalCollaborationSnapshot
}

func prepareNativePeerActors(t *testing.T, v *codexProductFixture, tag string, names []string) nativePeerActors {
	t.Helper()
	requireLocalDomainAvailable(t, v)
	v.coldOwnerPin(t)
	v.actualNode.kill(t)
	controlHash := hash(readPrivate(t, v.actualNode.statePath()))
	prefix := filepath.Join(v.root, tag+"-selected-root")
	if os.Mkdir(prefix, 0755) != nil || os.Chmod(prefix, 0755) != nil {
		t.Fatal("owned peer-form installation root unavailable")
	}
	var workspaces []string
	for _, name := range names {
		path := filepath.Join(v.root, tag+"-workspace-"+name)
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
	log := must(os.OpenFile(filepath.Join(v.root, "private-"+tag+"-native.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
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
		LocalCollaboration: appcore.LocalCollaborationAction{NewNetworkName: "Synthetic " + tag + " Network", GroupName: "Synthetic " + tag + " Group"}}).LocalCollaboration
	if !preview.Current || preview.Pending || preview.ReviewID == "" || preview.NodeID != v.actualNode.id || preview.LocalUserScope != "uid:1000" {
		t.Fatal("peer-form actual App policy review changed its original scope")
	}
	active := v.do(appcore.Action{Kind: appcore.ActionActivateLocalCollaboration,
		LocalCollaboration: appcore.LocalCollaborationAction{ReviewID: preview.ReviewID, ConfirmActivation: true}}).LocalCollaboration
	requireSameLocalDomain(t, preview, active)
	if active.State != wire.LocalDomainActive || active.GroupID == "" || active.NetworkID == "" {
		t.Fatal("peer-form actual App did not activate its policy")
	}
	return nativePeerActors{prefix: prefix, workspaces: workspaces, environment: environment, log: log, outbox: outbox, active: active}
}

// Capability is availability only. Actual App Owner review/signing and every
// Node/Group Guard remain separate. No absent handler becomes a mock positive.
func requireOwnerGroupsAvailable(t *testing.T, v *codexProductFixture) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := must(client.Get(v.f.cfg.Origin + wire.OwnerEndpointGroupsCapabilitiesPath))
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		t.Skip("OWNER_GROUPS_NOT_RUN actual Hub capability HTTP=404")
	}
	raw := must(io.ReadAll(io.LimitReader(response.Body, 16385)))
	if response.StatusCode != http.StatusOK || len(raw) > 16384 {
		t.Fatal("actual Owner Group capability response failed")
	}
	caps, err := wire.DecodeOwnerEndpointGroupsCapabilities(raw, v.f.cfg.Hub)
	if err != nil {
		t.Fatal("actual Owner Group capability does not match the pinned Hub/contract")
	}
	if !caps.Available || !caps.NativeSelfGroups {
		t.Skip("OWNER_GROUPS_NOT_RUN actual Hub/Node/self-list profile unavailable")
	}
}

func ownerGroupsTrace(f *hubFixture, from int) []exchange {
	var trace []exchange
	for _, ex := range f.proxy.snapshot()[from:] {
		for _, op := range wire.OwnerEndpointGroupsHTTPOperations() {
			if ex.Path == wire.OwnerEndpointGroupsHTTPPath(op) {
				trace = append(trace, ex)
				break
			}
		}
	}
	return trace
}

func restartNativePeerNode(t *testing.T, v *codexProductFixture, actors nativePeerActors) {
	t.Helper()
	v.actualNode.kill(t)
	installed := filepath.Join(actors.prefix, "components/node/bin/cicada")
	if hash(readPrivateBinary(t, installed)) != hash(readPrivateBinary(t, os.Getenv("CICADA_N3_CICADA_BINARY"))) {
		t.Fatal("Node restart attempted a different installed binary")
	}
	command := exec.Command(installed, "machine", "agent", "--relay-only", "--id", v.actualNode.id, "--name", v.actualNode.id,
		"--control-url", v.f.cfg.Origin, "--state-dir", v.actualNode.state, "--interval", "1s", "--user-root", actors.prefix,
		"--mcp-session-state-file", v.mcpState, "--mcp-outbox-state-file", actors.outbox)
	command.Env = append(append([]string(nil), v.environment...), "CICADA_CODEX_BIN=/tools/codex-package/bin/codex")
	command.Stdout, command.Stderr = actors.log, actors.log
	v.actualNode = &nodeProcess{process: startProcess(v.f.parent, command), id: v.actualNode.id, state: v.actualNode.state}
	bound := v.actualNode.awaitState(t, v.f, true)
	if bound.BindingID != v.bound.BindingID || bound.NodeKeyID != v.bound.NodeKeyID || bound.NodeKeyEpoch != v.bound.NodeKeyEpoch || bound.NodeFingerprint != v.bound.NodeFingerprint {
		t.Fatal("Node restart replaced the original Owner-approved Node identity")
	}
}
