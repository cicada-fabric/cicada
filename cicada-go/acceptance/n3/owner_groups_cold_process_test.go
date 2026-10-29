package n3_test

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

type ownerGroupsColdProcess struct {
	State    string `json:"state"`
	PID      int    `json:"pid,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

func ownerGroupsColdProcessState(p *process) ownerGroupsColdProcess {
	d := ownerGroupsColdProcess{State: "UNKNOWN"}
	if p == nil || p.cmd == nil || p.cmd.Process == nil || p.done == nil {
		return d
	}
	d.PID = p.cmd.Process.Pid
	select {
	case <-p.done:
		// Wait publishes ProcessState before closing done. Never inspect it while
		// the process can still be running or while its Wait is in progress.
		if p.cmd.ProcessState != nil {
			code := p.cmd.ProcessState.ExitCode()
			d.State, d.ExitCode = "EXITED", &code
		}
	default:
		d.State = "RUNNING"
	}
	return d
}

// Task-owned regular files only; no raw body or OS error leaves this helper.
func ownerGroupsColdRead(path string, limit int64) ([]byte, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "UNAVAILABLE"
	}
	if !info.Mode().IsRegular() {
		return nil, "NON_REGULAR"
	}
	if info.Size() > limit {
		return nil, "OVERSIZED"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "UNAVAILABLE"
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, "CHANGED"
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, "UNAVAILABLE_OR_OVERSIZED"
	}
	return raw, "COMPLETE"
}

type ownerGroupsColdStderr struct {
	ReadCode       string          `json:"read_code"`
	Bytes          int             `json:"bytes"`
	SHA256         string          `json:"sha256,omitempty"`
	TerminalReason string          `json:"terminal_reason"`
	PanicReported  bool            `json:"panic_reported"`
	LineCount      int             `json:"line_count,omitempty"`
	LastLineClass  string          `json:"last_line_class,omitempty"`
	KnownMarkers   map[string]bool `json:"known_markers,omitempty"`
}

func ownerGroupsColdStderrState(path string) ownerGroupsColdStderr {
	raw, code := ownerGroupsColdRead(path, 64<<10)
	defer clear(raw)
	d := ownerGroupsColdStderr{ReadCode: code, Bytes: len(raw), TerminalReason: "UNKNOWN"}
	if code != "COMPLETE" {
		return d
	}
	d.SHA256 = hash(raw)
	lines := strings.Split(strings.TrimRight(string(raw), "\r\n"), "\n")
	d.LineCount, d.LastLineClass = len(lines), "UNKNOWN"
	d.KnownMarkers = make(map[string]bool)
	markers := map[string]string{
		"NODE_CREDENTIAL_REVOKED":    "Node credential was revoked or rotated; stopping machine agent:",
		"RELAY_AUTH_REJECTED":        "Node authorization was rejected; stopping the machine agent:",
		"HTTP_AUTH_401":              "Hub API returned 401 Unauthorized:",
		"HTTP_AUTH_403":              "Hub API returned 403 Forbidden:",
		"OWNER_BINDING_VERIFICATION": "verify Owner-approved Node-Control binding:",
		"DURABLE_OUTBOX_RECOVERY":    "recover durable Node-Control outbox:",
		"CONFIG_REQUIRED":            "LOCAL_NODE_CONFIG_REQUIRED",
		"FLAG_PARSE":                 "flag provided but not defined:",
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "panic:") || strings.HasPrefix(line, "fatal error:") {
			d.PanicReported = true
		}
		for code, marker := range markers {
			if strings.Contains(line, marker) {
				d.KnownMarkers[code] = true
			}
		}
	}
	for code, marker := range markers {
		if strings.HasPrefix(lines[len(lines)-1], marker) {
			d.LastLineClass = code
		}
	}
	if len(lines) == 0 || d.PanicReported {
		return d
	}
	// main prints nodeCredentialRevokedError's exact terminal prefix. Match no
	// arbitrary HTTP substring, response body, earlier warning or shared Host log.
	const prefix = "Node credential was revoked or rotated; stopping machine agent: Hub API returned "
	last := lines[len(lines)-1]
	if strings.HasPrefix(last, prefix+"401 Unauthorized: ") {
		d.TerminalReason = "NODE_CREDENTIAL_REVOKED_HTTP_401"
	} else if strings.HasPrefix(last, prefix+"403 Forbidden: ") {
		d.TerminalReason = "NODE_CREDENTIAL_REVOKED_HTTP_403"
	} else if !strings.HasPrefix(last, prefix) && strings.HasPrefix(last, "Node credential was revoked or rotated; stopping machine agent: ") {
		// Inner errors can have additional wrappers. This fixed final-line
		// report alone never admits an exit: an actual post-start original-Node
		// HTTP auth refusal is independently required below.
		d.TerminalReason = "NODE_CREDENTIAL_REJECTION_REPORTED"
	}
	return d
}

type ownerGroupsColdIdentity struct {
	ReadCode         string `json:"read_code"`
	RootSHA256       string `json:"root_sha256"`
	UserRootSHA256   string `json:"user_root_sha256"`
	KeySHA256        string `json:"key_sha256,omitempty"`
	CredentialSHA256 string `json:"credential_sha256,omitempty"`
	BindingSHA256    string `json:"binding_sha256,omitempty"`
}

func ownerGroupsColdOriginalIdentity(v *codexProductFixture, prefix string) ownerGroupsColdIdentity {
	d := ownerGroupsColdIdentity{ReadCode: "UNKNOWN"}
	if v == nil || v.actualNode == nil || v.actualNode.state == "" || prefix == "" {
		return d
	}
	root := filepath.Dir(v.actualNode.statePath())
	d.RootSHA256, d.UserRootSHA256 = hash([]byte(root)), hash([]byte(prefix))
	key, keyCode := ownerGroupsColdRead(filepath.Join(root, "node-control-identity.bin"), 1<<20)
	defer clear(key)
	credential, credentialCode := ownerGroupsColdRead(filepath.Join(root, "relay.token"), 1<<20)
	defer clear(credential)
	state, stateCode := ownerGroupsColdRead(v.actualNode.statePath(), 8<<20)
	defer clear(state)
	if keyCode != "COMPLETE" || credentialCode != "COMPLETE" || stateCode != "COMPLETE" || len(key) == 0 || len(credential) == 0 {
		return d
	}
	var binding nodeActorState
	if json.Unmarshal(state, &binding) != nil || binding.NodeID != v.actualNode.id ||
		binding.BindingID != v.bound.BindingID || binding.BindingVersion != v.bound.BindingVersion ||
		binding.NodeKeyID != v.bound.NodeKeyID || binding.NodeFingerprint != v.bound.NodeFingerprint || binding.NodeKeyEpoch != v.bound.NodeKeyEpoch {
		return d
	}
	// Pending/progress fields are mutable; only the existing identity leaf is
	// compared. Full protected state and its secrets are never exported.
	binding.PendingCode, binding.PendingCandidate = "", nil
	public, err := json.Marshal(binding)
	if err != nil {
		return d
	}
	d.ReadCode, d.KeySHA256, d.CredentialSHA256, d.BindingSHA256 = "COMPLETE", hash(key), hash(credential), hash(public)
	return d
}

type ownerGroupsColdObservation struct {
	Scope        string                       `json:"scope"`
	Observed     string                       `json:"observed_at"`
	Node         ownerGroupsColdProcess       `json:"node"`
	Hub          ownerGroupsColdProcess       `json:"hub"`
	Stderr       ownerGroupsColdStderr        `json:"node_private_stderr"`
	Before       ownerGroupsColdIdentity      `json:"original_before"`
	After        ownerGroupsColdIdentity      `json:"original_after"`
	Started      string                       `json:"cold_started_at"`
	AuthRefusals []ownerGroupsColdHTTPRefusal `json:"original_node_http_auth_refusals"`
}

type ownerGroupsColdHTTPRefusal struct {
	Route          string `json:"route"`
	Status         int    `json:"status"`
	StartedAt      string `json:"started_at"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
}

func ownerGroupsObserveCold(v *codexProductFixture, prefix, stderr string, before ownerGroupsColdIdentity, started time.Time) ownerGroupsColdObservation {
	d := ownerGroupsColdObservation{Scope: "COLD_PROCESS_OBSERVATION_NOT_M7_ACCEPTANCE", Observed: time.Now().UTC().Format(time.RFC3339Nano), Started: started.UTC().Format(time.RFC3339Nano),
		Node: ownerGroupsColdProcessState(v.actualNode.process), Hub: ownerGroupsColdProcessState(v.f.hub),
		Stderr: ownerGroupsColdStderrState(stderr), Before: before, After: ownerGroupsColdOriginalIdentity(v, prefix)}
	for _, ex := range v.f.proxy.snapshot() {
		at, err := time.Parse(time.RFC3339Nano, ex.StartedAt)
		if err != nil || started.IsZero() || at.Before(started) || !ex.Forwarded || (ex.Status != 401 && ex.Status != 403) {
			continue
		}
		route := ""
		if ex.Path == "/v2/node/control/rpc" {
			packet, err := nodewire.DecodePacket(ex.request)
			if err == nil && packet.Route.NodeID == v.actualNode.id && packet.Route.BindingID == v.bound.BindingID && packet.Route.NodeKeyEpoch == v.bound.NodeKeyEpoch {
				route = "ORIGINAL_NODE_CONTROL_RPC"
			}
		} else if strings.HasPrefix(ex.Path, "/v2/relay/nodes/"+v.actualNode.id+"/") {
			route = "ORIGINAL_NODE_RELAY"
		}
		if route != "" {
			d.AuthRefusals = append(d.AuthRefusals, ownerGroupsColdHTTPRefusal{Route: route, Status: ex.Status, StartedAt: ex.StartedAt, RequestSHA256: ex.RequestSHA256, ResponseSHA256: ex.ResponseSHA256})
		}
	}
	return d
}

func ownerGroupsColdRefusal(d ownerGroupsColdObservation) string {
	if d.Hub.State != "RUNNING" {
		return "HUB_NOT_RUNNING"
	}
	if d.Before.ReadCode != "COMPLETE" || d.After.ReadCode != "COMPLETE" || d.Before != d.After ||
		d.Before.RootSHA256 == "" || d.Before.UserRootSHA256 == "" || d.Before.KeySHA256 == "" || d.Before.CredentialSHA256 == "" || d.Before.BindingSHA256 == "" {
		return "ORIGINAL_IDENTITY_CHANGED_OR_UNKNOWN"
	}
	if d.Stderr.ReadCode != "COMPLETE" || d.Stderr.PanicReported {
		return "STDERR_UNKNOWN_OR_PANIC"
	}
	if d.Node.State == "RUNNING" {
		return ""
	}
	if d.Node.State == "EXITED" && d.Node.ExitCode != nil && *d.Node.ExitCode == 1 &&
		len(d.AuthRefusals) > 0 && (d.Stderr.TerminalReason == "NODE_CREDENTIAL_REVOKED_HTTP_401" || d.Stderr.TerminalReason == "NODE_CREDENTIAL_REVOKED_HTTP_403" || d.Stderr.TerminalReason == "NODE_CREDENTIAL_REJECTION_REPORTED") {
		return ""
	}
	return "NODE_EXIT_NOT_PROVEN_AUTH_REJECTION"
}
