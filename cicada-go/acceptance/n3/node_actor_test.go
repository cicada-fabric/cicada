package n3_test

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type nodeProcess struct {
	*process
	id, state string
}

// This is a read-only view of existing production Node persistence, not a new
// protocol. It includes only fields needed to select the real pending code and
// compare the original identity/candidate after an actual process restart.
type nodeActorState struct {
	NodeID           string              `json:"node_id"`
	HubOrigin        string              `json:"hub_origin"`
	HubID            string              `json:"hub_id"`
	HubPublic        e2ee.PublicIdentity `json:"hub_public_identity"`
	NodeKeyID        string              `json:"node_key_id"`
	NodeFingerprint  string              `json:"node_key_fingerprint"`
	BindingID        string              `json:"binding_id"`
	BindingVersion   uint64              `json:"binding_version"`
	NodeKeyEpoch     uint64              `json:"node_key_epoch"`
	PendingCode      string              `json:"pending_pairing_user_code"`
	PendingCandidate *struct {
		RequestID       string `json:"request_id"`
		Version         uint64 `json:"version"`
		Mode            string `json:"mode"`
		HubID           string `json:"hub_id"`
		NodeID          string `json:"node_id"`
		NodeKeyID       string `json:"node_key_id"`
		NodeFingerprint string `json:"node_key_fingerprint"`
		CandidateDigest string `json:"candidate_digest"`
		HubFingerprint  string `json:"hub_node_control_fingerprint"`
		HubKeyID        string `json:"hub_node_control_key_id"`
		HubKeyVersion   uint64 `json:"hub_node_control_key_version"`
		NodeKeyEpoch    uint64 `json:"node_key_epoch"`
		State           string `json:"state"`
	} `json:"pending_pairing"`
}

var syntheticNodeID = regexp.MustCompile(`^synthetic-n3-[a-z0-9-]+$`)

func startNodeProcess(t *testing.T, f *hubFixture, id string) *nodeProcess {
	return startNodeProcessMode(t, f, id, false)
}

func startNodeProcessMode(t *testing.T, f *hubFixture, id string, once bool) *nodeProcess {
	t.Helper()
	if f.mode != "--hub-nodes-only" || !syntheticNodeID.MatchString(id) {
		t.Fatal("actual Node requires the reviewed isolated Hub/Node composition and synthetic ID")
	}
	state := filepath.Join(f.dir, id)
	if os.MkdirAll(state, 0700) != nil {
		t.Fatal("private Node fixture directory unavailable")
	}
	// The real CLI may print the synthetic pairing code. Redirect it only to
	// private fixture state; no Node log or full payload is copied to evidence.
	log := must(os.OpenFile(filepath.Join(state, "private-process.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600))
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command(os.Getenv("CICADA_N3_CICADA_BINARY"), "machine", "agent", "--relay-only",
		"--id", id, "--name", id, "--control-url", f.cfg.Origin, "--state-dir", state, "--interval", "1s")
	if once {
		cmd.Args = append(cmd.Args, "--once")
	}
	cmd.Stdout, cmd.Stderr = log, log
	return &nodeProcess{process: startProcess(t, cmd), id: id, state: state}
}

func (p *nodeProcess) statePath() string {
	return filepath.Join(p.state, "nodes", "node-"+url.PathEscape(p.id), "node-control-state.json")
}

func (p *nodeProcess) reportFailure(t *testing.T) {
	t.Helper()
	raw := readPrivate(t, filepath.Join(p.state, "private-process.log"))
	defer clear(raw)
	paths := regexp.MustCompile(`/v2/[A-Za-z0-9_./-]+`).FindAll(raw, -1)
	codes := regexp.MustCompile(`\b[45][0-9][0-9]\b`).FindAll(raw, -1)
	var categories []string
	for _, word := range []string{"unexpected", "not found", "unauthorized", "forbidden", "binding", "peer", "network", "direct", "invalid character", "deadline"} {
		if strings.Contains(strings.ToLower(string(raw)), word) {
			categories = append(categories, word)
		}
	}
	if root := os.Getenv("CICADA_N3_PRIVATE_DIAGNOSTICS"); root == "/state/private-diagnostics" {
		if os.MkdirAll(root, 0700) == nil {
			name := must(wire.NewRequestID()) + ".private-node.log"
			atomicPrivate(t, filepath.Join(root, name), raw)
			t.Logf("private_state_diagnostic=%s file_sha256=%s", name, hash(raw))
		}
	}
	var safePaths, safeCodes []string
	for _, p := range paths {
		safePaths = append(safePaths, string(p))
	}
	for _, c := range codes {
		safeCodes = append(safeCodes, string(c))
	}
	t.Logf("NODE_FAILURE_SAFE_ONLY paths=%v status_numbers=%v categories=%v", safePaths, safeCodes, categories)
}

func (p *nodeProcess) awaitState(t *testing.T, f *hubFixture, bound bool) nodeActorState {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p.statePath()); err == nil {
			raw := readPrivate(t, p.statePath())
			var state nodeActorState
			err := json.Unmarshal(raw, &state)
			clear(raw)
			if err != nil || state.NodeID != p.id || state.HubOrigin != f.cfg.Origin {
				t.Fatal("actual Node durable scope differs from its owned fixture")
			}
			if bound && state.BindingID != "" && state.BindingVersion > 0 && state.NodeKeyEpoch > 0 && state.HubID == f.cfg.Hub.HubID {
				return state
			}
			if !bound && state.PendingCandidate != nil && state.PendingCode != "" {
				c := state.PendingCandidate
				if _, err := wire.NormalizeAppNodeCode(state.PendingCode); err != nil || c.NodeID != p.id ||
					c.HubID != f.cfg.Hub.HubID || c.Mode != "INITIAL" || c.State != "PENDING" ||
					c.RequestID == "" || c.Version == 0 || c.NodeKeyID == "" || c.CandidateDigest == "" ||
					c.NodeFingerprint == "" || c.HubFingerprint == "" || c.HubKeyVersion == 0 || c.NodeKeyEpoch == 0 {
					t.Fatal("actual Node did not persist the exact initial cryptographic candidate")
				}
				return state
			}
		}
		select {
		case <-p.done:
			p.reportFailure(t)
			t.Fatal("actual Node CLI exited before its required persistent state")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.reportFailure(t)
	t.Fatal("actual Node did not reach the required persistent state before deadline")
	return nodeActorState{}
}
