package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Private control messages for the existing real Host fixture. No context
// ticket, device credential, Owner key or substitute native actor is accepted.
type ownerGroupsHostCommand struct {
	Action             string                  `json:"action"`
	Actor              int                     `json:"actor,omitempty"`
	Label              string                  `json:"label,omitempty"`
	Tool               string                  `json:"tool,omitempty"`
	Arguments          map[string]any          `json:"arguments,omitempty"`
	Form               map[string]any          `json:"form,omitempty"`
	Queue              []ownerGroupsQueueInput `json:"queue,omitempty"`
	BindQueue          map[string]string       `json:"bind_queue,omitempty"`
	ObserveFields      []string                `json:"observe_fields,omitempty"`
	ExpectedRequestID  string                  `json:"expected_request_id,omitempty"`
	ExpectedBodyMarker string                  `json:"expected_body_marker,omitempty"`
	ObserveSelfGroups  bool                    `json:"observe_self_groups,omitempty"`
}

type ownerGroupsQueueInput struct {
	Body     string `json:"body"`
	SID      string `json:"native_session_id"`
	Sender   string `json:"sender_endpoint_id"`
	Receiver string `json:"receiver_endpoint_id"`
	GroupID  string `json:"group_id"`
	Kind     string `json:"kind"`
}

type ownerGroupsHostReply struct {
	Status             string               `json:"status"`
	Daemon             nativeDomainDaemon   `json:"daemon"`
	SIDs               []string             `json:"native_session_ids"`
	FixtureScope       string               `json:"fixture_scope"`
	Output             json.RawMessage      `json:"output"`
	Summary            json.RawMessage      `json:"summary"`
	Restarts           int                  `json:"daemon_restarts"`
	LiteralPosts       int                  `json:"literal_provider_posts"`
	Public             map[string]string    `json:"public"`
	QueuePosts         map[string]int       `json:"queue_posts"`
	RecordCount        int                  `json:"native_record_count"`
	HistoryKept        bool                 `json:"native_history_prefix_conserved"`
	SelfGroups         *ownerGroupsSelfList `json:"self_groups,omitempty"`
	OperationStatus    string               `json:"operation_status,omitempty"`
	OperationRetryable *bool                `json:"operation_retryable,omitempty"`
	Diagnostic         json.RawMessage      `json:"host_diagnostic,omitempty"`
}

type ownerGroupsSelfList struct {
	Groups            []ownerGroupsSelfCard `json:"groups"`
	CurrentGroupID    string                `json:"current_group_id"`
	SelectionRequired bool                  `json:"selection_required"`
	Complete          bool                  `json:"complete"`
	NextCursor        string                `json:"next_cursor"`
	Freshness         string                `json:"freshness"`
}

type ownerGroupsSelfCard struct {
	GroupID          string `json:"group_id"`
	Name             string `json:"name"`
	NetworkID        string `json:"network_id"`
	Current          bool   `json:"current"`
	RelationRevision uint64 `json:"relation_revision"`
	Source           string `json:"source"`
	ExpiresAt        string `json:"expires_at"`
	Freshness        string `json:"freshness"`
}

type ownerGroupsHost struct {
	fixture      *codexProductFixture
	node         *nodeProcess
	workspaces   []string
	mu           sync.Mutex
	process      *process
	control      string
	result       string
	sequence     int
	originalSIDs []string
	latestDaemon nativeDomainDaemon
	fixtureScope string
}

// Both private IPC directions publish complete, exclusive checkpoints. A
// duplicate sequence cannot overwrite the original command under review.
func publishOwnerGroupsControl(path string, raw []byte) error {
	temporary := path + ".next"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	n, writeErr := file.Write(raw)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil {
		return writeErr
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func startOwnerGroupsHost(t *testing.T, v *codexProductFixture, actors nativePeerActors) (*ownerGroupsHost, ownerGroupsHostReply) {
	t.Helper()
	h, first := startOwnerGroupsHostAt(t, v.root, v.codexHome, v.actualNode, actors)
	h.fixture = v
	return h, first
}

// Address-only NPT fixtures own their actual Hub/App separately. Reuse the
// same four-Thread Host without constructing another Hub or a legacy approval.
func startOwnerGroupsHostAt(t *testing.T, root, codexHome string, node *nodeProcess, actors nativePeerActors) (*ownerGroupsHost, ownerGroupsHostReply) {
	t.Helper()
	if len(actors.workspaces) != 4 {
		t.Fatal("Owner Group runtime requires four actual original native Threads")
	}
	control := filepath.Join(root, "owner-groups-native-control")
	config, result := filepath.Join(root, "private-owner-groups-native-config.json"), filepath.Join(root, "private-owner-groups-native-result.json")
	writeJSON(t, config, map[string]any{"root": root, "workspace": actors.workspaces[0], "workspaces": actors.workspaces,
		"codex_home": codexHome, "environment": actors.environment, "codex_binary": "/tools/codex-package/bin/codex",
		"codex_sha256": directIPCodexSHA256, "marketplace": filepath.Join(actors.prefix, "components/node/share/codex"),
		"step": "owner-groups-native", "persistent_daemon": true, "allow_test_termination": true, "daemon_umask": "0002",
		"preparation": "none", "selected_root": actors.prefix, "control": control, "result": result,
		"cicada_sha256": hash(readPrivateBinary(t, filepath.Join(actors.prefix, "components/node/bin/cicada")))})
	command := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/peer_form_native.py", config)
	command.Env, command.Dir, command.Stdout, command.Stderr = actors.environment, actors.workspaces[0], actors.log, actors.log
	h := &ownerGroupsHost{node: node, workspaces: append([]string(nil), actors.workspaces...), process: startProcess(t, command), control: control, result: result, sequence: 1}
	first := h.await(t, 0)
	if len(first.SIDs) != 4 || first.FixtureScope == "" {
		t.Fatal("actual four-Thread Host bootstrap omitted original identities")
	}
	seen := make(map[string]bool)
	for _, sid := range first.SIDs {
		if !ownerGroupsSIDPattern.MatchString(sid) || seen[sid] {
			t.Fatal("actual Host merged or fabricated a native Thread identity")
		}
		seen[sid] = true
	}
	h.originalSIDs = append([]string(nil), first.SIDs...)
	h.latestDaemon = first.Daemon
	h.fixtureScope = first.FixtureScope
	return h, first
}

func (h *ownerGroupsHost) await(t *testing.T, sequence int) ownerGroupsHostReply {
	t.Helper()
	path := filepath.Join(h.control, strconv.Itoa(sequence)+".reply.json")
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			var result ownerGroupsHostReply
			readJSON(t, path, &result)
			if result.Status != "OBSERVED" || result.LiteralPosts != 0 || result.RecordCount != 4 || !result.HistoryKept || result.Daemon.PID <= 0 || result.Daemon.Start == "" ||
				result.Daemon.Umask != "0002" || !result.Daemon.EnvEmpty || result.Daemon.Binary != directIPCodexSHA256 {
				t.Fatal("actual Owner Group Host checkpoint lacks its original private daemon proof")
			}
			if len(h.originalSIDs) > 0 {
				if len(result.SIDs) != 4 {
					t.Fatal("Owner Group Host lost an original native Thread")
				}
				for i, sid := range result.SIDs {
					if sid != h.originalSIDs[i] {
						t.Fatal("Owner Group Host replaced a native Thread on restart")
					}
				}
			}
			return result
		}
		if !h.process.running() {
			var failure struct {
				Phase      string          `json:"failure_phase"`
				Code       string          `json:"failure_code"`
				Shapes     json.RawMessage `json:"unclassified_shapes"`
				Diagnostic json.RawMessage `json:"host_diagnostic"`
			}
			if _, err := os.Stat(h.result); err == nil {
				readJSON(t, h.result, &failure)
			}
			t.Fatalf("actual Owner Group Host stopped: phase=%s code=%s shapes=%s host_diagnostic=%s", failure.Phase, failure.Code, failure.Shapes, failure.Diagnostic)
		}
		time.Sleep(25 * time.Millisecond)
	}
	progress := must(filepath.Glob(filepath.Join(h.control, strconv.Itoa(sequence)+".progress-*.json")))
	var latest string
	var last time.Time
	for _, path := range progress {
		info, err := os.Stat(path)
		if err == nil && info.ModTime().After(last) {
			latest, last = path, info.ModTime()
		}
	}
	if latest != "" {
		t.Logf("OWNER_GROUPS_RECEIVE_PROGRESS %s", readPrivate(t, latest))
	}
	running := h.process.running()
	exitObserved, exitCode := false, -1
	if !running && h.process.cmd.ProcessState != nil {
		exitObserved, exitCode = true, h.process.cmd.ProcessState.ExitCode()
	}
	t.Logf("OWNER_GROUPS_HOST_TIMEOUT sequence=%d host_running=%t host_exit_observed=%t host_exit_code=%d", sequence, running, exitObserved, exitCode)
	t.Fatal("actual Owner Group Host checkpoint timed out")
	return ownerGroupsHostReply{}
}

func (h *ownerGroupsHost) command(t *testing.T, value ownerGroupsHostCommand) ownerGroupsHostReply {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if value.Actor < 0 || value.Actor >= 4 {
		t.Fatal("invalid original Owner Group actor index")
	}
	if _, present := value.Arguments["_cicada_context"]; present {
		t.Fatal("fixture must not provide an actor ticket")
	}
	raw := must(json.Marshal(value))
	defer clear(raw)
	if publishOwnerGroupsControl(filepath.Join(h.control, strconv.Itoa(h.sequence)+".command.json"), raw) != nil {
		t.Fatal("owned Host command cannot be published completely and exclusively")
	}
	result := h.await(t, h.sequence)
	h.sequence++
	if value.Action != "restart_host" && result.Daemon != h.latestDaemon {
		t.Fatal("private Host daemon changed outside the explicit restart")
	}
	if value.Action == "restart_host" && result.Daemon == h.latestDaemon {
		t.Fatal("new MCP proof used the old daemon process")
	}
	h.latestDaemon = result.Daemon
	return result
}

func (h *ownerGroupsHost) finish(t *testing.T) {
	t.Helper()
	h.command(t, ownerGroupsHostCommand{Action: "finish"})
	select {
	case <-h.process.done:
	case <-time.After(15 * time.Second):
		t.Fatal("owned Owner Group Host did not stop after its final checkpoint")
	}
	var result struct {
		Status     string            `json:"status"`
		Cleanup    bool              `json:"cleanup_confirmed"`
		RealModels int               `json:"real_model_turns"`
		Literal    int               `json:"literal_provider_posts"`
		Host       int               `json:"host_provider_posts"`
		Queue      int               `json:"native_queue_provider_posts"`
		Seed       int               `json:"native_seed_provider_posts"`
		Title      int               `json:"native_title_provider_posts"`
		Total      int               `json:"static_provider_posts"`
		Calls      []json.RawMessage `json:"tool_summaries"`
	}
	readJSON(t, h.result, &result)
	if result.Status != "HOST_FIXTURE_COMPLETED_NOT_PRODUCT_ACCEPTANCE" || !result.Cleanup || result.RealModels != 0 || result.Literal != 0 ||
		result.Seed != 4 || result.Title < 0 || result.Title > 1024 || result.Host != 2*len(result.Calls) || result.Total != result.Host+result.Queue+result.Seed+result.Title || h.process.cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("actual Owner Group Host cleanup/provider accounting did not match its measured calls")
	}
}

func (h *ownerGroupsHost) groups(t *testing.T, actor int, label, network, selected string, sources map[string]string) ownerGroupsSelfList {
	t.Helper()
	reply := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: actor, Label: label, Tool: "cicada_groups",
		Arguments: map[string]any{"limit": 64}, ObserveSelfGroups: true})
	list := reply.SelfGroups
	if list == nil || !list.Complete || list.NextCursor != "" || list.Freshness != "SNAPSHOT_ONLY" ||
		list.CurrentGroupID != selected || list.SelectionRequired != (selected == "") || len(list.Groups) != len(sources) {
		t.Fatalf("actual self-Group list mismatch: present=%t complete=%t cursor_empty=%t snapshot=%t selected_matches=%t required_matches=%t count_matches=%t", list != nil, list != nil && list.Complete, list != nil && list.NextCursor == "", list != nil && list.Freshness == "SNAPSHOT_ONLY", list != nil && list.CurrentGroupID == selected, list != nil && list.SelectionRequired == (selected == ""), list != nil && len(list.Groups) == len(sources))
	}
	seen := make(map[string]bool)
	for _, group := range list.Groups {
		if group.GroupID == "" || seen[group.GroupID] || group.NetworkID != network || group.Name == "" || group.RelationRevision == 0 ||
			group.Freshness != "SNAPSHOT_ONLY" || group.Current != (group.GroupID == selected) || sources[group.GroupID] != group.Source {
			t.Fatal("actual self-Group card changed its exact source, Network or current selection")
		}
		if group.Source != "DEFAULT_POLICY" && group.Source != "OWNER_EXPLICIT" {
			t.Fatal("actual self-Group card has an unknown or mixed authority source")
		}
		if group.ExpiresAt != "" {
			deadline, err := time.Parse(time.RFC3339Nano, group.ExpiresAt)
			if err != nil || !time.Now().Before(deadline) {
				t.Fatal("actual self-Group card exposed an expired policy")
			}
		}
		seen[group.GroupID] = true
	}
	return *list
}

// Real original-Thread calls through the installed Host/Hook. Sequential
// correlation keeps other inbox items out of the oracle; accepted/queued alone
// is insufficient: both exact request and reply must reach their original SID.
func (h *ownerGroupsHost) roundtrip(t *testing.T, label, group string, source, target int, identities []ownerGroupsIdentity) string {
	t.Helper()
	if len(identities) != 4 || source == target || source < 0 || source >= 4 || target < 0 || target >= 4 {
		t.Fatal("invalid original Group roundtrip actors")
	}
	for i, identity := range identities {
		if identity.SID != h.originalSIDs[i] {
			t.Fatal("Group roundtrip Endpoint index does not belong to its original native SID")
		}
	}
	for _, index := range []int{source, target} {
		selected := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: index, Label: label + "-select", Tool: "cicada_use_group",
			Arguments: map[string]any{"group_id": group}, ObserveFields: []string{"group_id"}})
		if selected.Public["group_id"] != group {
			h.recordSelectionFailure(t, index, label+"-select", group, selected)
			t.Fatal("actual original actor did not select the exact authorized Group")
		}
	}
	question := "SYNTHETIC_OWNER_GROUP_QUESTION_" + h.fixtureScope + "_" + label
	answer := "SYNTHETIC_OWNER_GROUP_ANSWER_" + h.fixtureScope + "_" + label
	ask := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: source, Label: label + "-ask", Tool: "cicada_ask",
		Arguments:     map[string]any{"target": identities[target].Endpoint, "question": question, "idempotency_key": h.fixtureScope + "-" + label},
		Queue:         []ownerGroupsQueueInput{{Body: question, SID: h.originalSIDs[target], Sender: identities[source].Endpoint, Receiver: identities[target].Endpoint, GroupID: group, Kind: "ask"}},
		ObserveFields: []string{"request_id", "operation_id"}})
	if ask.OperationStatus == "FAILED" && ask.OperationRetryable != nil && !*ask.OperationRetryable {
		t.Fatalf("actual ASK is terminal FAILED; diagnostic=%s", ask.Diagnostic)
	}
	request, operation := ask.Public["request_id"], ask.Public["operation_id"]
	for attempt := 0; request == "" && operation != "" && attempt < 30; attempt++ {
		time.Sleep(250 * time.Millisecond)
		status := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: source, Label: label + "-status", Tool: "cicada_operation_status",
			Arguments: map[string]any{"operation_id": operation}, ObserveFields: []string{"request_id"}})
		if status.OperationStatus == "FAILED" && status.OperationRetryable != nil && !*status.OperationRetryable {
			t.Fatalf("actual ASK reached terminal FAILED; diagnostic=%s", status.Diagnostic)
		}
		request = status.Public["request_id"]
	}
	if request == "" {
		t.Fatal("actual Cicada ASK did not retain its durable request ID")
	}
	received := h.command(t, ownerGroupsHostCommand{Action: "receive_match", Actor: target, Label: label + "-request-receive", Tool: "cicada_receive",
		Arguments: map[string]any{"limit": 16}, ExpectedRequestID: request, ExpectedBodyMarker: question, BindQueue: map[string]string{question: request}})
	if received.QueuePosts[question] != 1 {
		t.Fatal("exact request did not reach its original native Runtime once")
	}
	reply := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: target, Label: label + "-reply", Tool: "cicada_reply",
		Arguments: map[string]any{"request_id": request, "body": answer, "idempotency_key": h.fixtureScope + "-reply-" + label},
		Queue:     []ownerGroupsQueueInput{{Body: answer, SID: h.originalSIDs[source], Sender: identities[target].Endpoint, Receiver: identities[source].Endpoint, GroupID: group, Kind: "reply"}},
		BindQueue: map[string]string{answer: request}, ObserveFields: []string{"operation_id", "request_id"}})
	t.Logf("OWNER_GROUPS_REPLY_OBSERVATION label=%s-reply caller_actor=%d request_sha256=%s operation_present=%t status=%s", label, target, hash([]byte(request)), reply.Public["operation_id"] != "", reply.OperationStatus)
	if reply.Public["operation_id"] == "" || (reply.OperationStatus != "PENDING" && reply.OperationStatus != "UNKNOWN" && reply.OperationStatus != "SENT") ||
		(reply.Public["request_id"] != "" && reply.Public["request_id"] != request) {
		t.Fatalf("actual REPLY lacks its original accepted operation: label=%s-reply caller_actor=%d diagnostic=%s", label, target, reply.Diagnostic)
	}
	replied := h.command(t, ownerGroupsHostCommand{Action: "receive_match", Actor: source, Label: label + "-reply-receive", Tool: "cicada_receive",
		Arguments: map[string]any{"limit": 16}, ExpectedRequestID: request, ExpectedBodyMarker: answer})
	if replied.QueuePosts[answer] != 1 {
		t.Fatal("correlated reply did not reach the original requester Runtime once")
	}
	t.Logf("OWNER_GROUPS_ROUNDTRIP label=%s original_Group_and_native_SIDs=true request_and_reply_received=true native_each_once=true", label)
	return request
}

// Capture selection failures synchronously before fixture cleanup. This reads
// one bounded atomic file and never calls a product API or changes Node state.
func ownerGroupsSelectionDiagnostic(path, node, sid, workspace string, actor int, label, group string, reply ownerGroupsHostReply) map[string]any {
	unknown := "UNKNOWN"
	d := map[string]any{"scope": "CLOSED_SELECTION_FAILURE_NOT_AUTHORITY", "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "actor": actor,
		"target_group_sha256": hash([]byte(group)), "returned_group_present": reply.Public["group_id"] != "", "group_matches": reply.Public["group_id"] == group,
		"output_sha256": hash(reply.Output), "output_bytes": len(reply.Output), "state_read_code": unknown, "state_bytes": unknown, "state_limit_bytes": 8 << 20,
		"registration_present": unknown, "registration_matches": unknown, "registration_lease_expires_at": unknown}
	if regexp.MustCompile(`^m[1-8]-[A-Za-z0-9_-]{1,84}$`).MatchString(label) {
		d["label"] = label
	} else {
		d["label_sha256"] = hash([]byte(label))
	}
	if value := reply.Public["group_id"]; value != "" {
		d["returned_group_sha256"] = hash([]byte(value))
	}
	flags := map[string]any{}
	for name := range (ownerGroupsSettlementState{}).remaining() {
		flags[name] = unknown
	}
	d["remaining"] = flags
	// Project existing Host diagnostics; retain only fixed booleans, enum codes
	// and error hashes. Neither Output nor the raw diagnostic is exported.
	var diagnostic struct {
		Observed      *bool    `json:"observed"`
		Parsed        *bool    `json:"parsed_object_present"`
		ErrorObserved *bool    `json:"is_error_observed"`
		IsError       *bool    `json:"is_error"`
		Codes         []string `json:"product_error_codes"`
		Errors        struct {
			Present *bool    `json:"present"`
			SHA     []string `json:"sha256"`
		} `json:"error_summary"`
	}
	for _, name := range []string{"host_observed", "parsed_object_present", "is_error_observed", "is_error", "error_present"} {
		d[name] = unknown
	}
	if json.Unmarshal(reply.Diagnostic, &diagnostic) == nil {
		values := map[string]*bool{"host_observed": diagnostic.Observed, "parsed_object_present": diagnostic.Parsed, "is_error_observed": diagnostic.ErrorObserved, "is_error": diagnostic.IsError, "error_present": diagnostic.Errors.Present}
		for name, value := range values {
			if value != nil {
				d[name] = *value
			}
		}
	}
	allowed := map[string]bool{}
	for _, code := range []string{"CODEX_CALL_CONTEXT_REQUIRED", "CODEX_NATIVE_COORDINATES_INVALID", "CODEX_NATIVE_RECORD_UNVERIFIED", "CODEX_TOOL_INPUT_MISSING", "CODEX_CALL_CONTEXT_MISSING", "CODEX_CONNECTION_NONCE_INVALID", "CODEX_TOOL_ARGUMENTS_INVALID", "CODEX_ARGUMENT_DIGEST_UNAVAILABLE", "CODEX_NODE_TICKET_UNAVAILABLE"} {
		allowed[code] = true
	}
	for _, stage := range []string{"ROOT", "PATH", "OWNERSHIP", "PERMISSION", "INODE", "METADATA", "SOURCE", "SESSION", "WORKSPACE"} {
		allowed["CODEX_NATIVE_RECORD_"+stage] = true
	}
	found := map[string]bool{}
	for _, code := range diagnostic.Codes {
		if allowed[code] {
			found[code] = true
		}
	}
	for code := range allowed {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(code) + `\b`).Match(reply.Output) {
			found[code] = true
		}
	}
	codes := []string{}
	for code := range found {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	d["product_error_codes"] = codes
	hashes := []string{}
	for _, value := range diagnostic.Errors.SHA {
		if len(hashes) < 32 && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(value) {
			hashes = append(hashes, value)
		}
	}
	d["error_sha256"] = hashes
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			d["state_read_code"] = "MISSING"
		} else if os.IsPermission(err) {
			d["state_read_code"] = "PERMISSION"
		} else {
			d["state_read_code"] = "STAT_ERROR"
		}
		return d
	}
	d["state_bytes"] = info.Size()
	d["space_to_file_limit_bytes"] = (8 << 20) - info.Size()
	d["fixed_rpc_reserve_bytes"] = 2 << 20
	d["space_after_fixed_rpc_reserve_bytes"] = (8 << 20) - info.Size() - (2 << 20)
	d["managed_reserve_bytes"] = "NOT_MEASURED"
	// Reject directories, leaf symlinks and other nonregular entries before
	// opening; the atomic Node writer may replace a regular file concurrently.
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		d["state_read_code"] = "NONREGULAR_OR_OVER_LIMIT"
		return d
	}
	file, err := os.Open(path)
	if err != nil {
		d["state_read_code"] = "OPEN_ERROR"
		return d
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > 8<<20 || !os.SameFile(info, opened) {
		d["state_read_code"] = "FILE_CHANGED_OR_UNAVAILABLE"
		return d
	}
	raw, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	defer clear(raw)
	if err != nil || len(raw) > 8<<20 {
		d["state_read_code"] = "READ_ERROR_OR_OVER_LIMIT"
		return d
	}
	var state struct {
		ownerGroupsSettlementState
		Node string `json:"node_id"`
	}
	if json.Unmarshal(raw, &state) != nil {
		d["state_read_code"] = "INVALID_JSON"
		return d
	}
	if node == "" || state.Node != node {
		d["state_read_code"] = "NODE_SCOPE_UNKNOWN_OR_CHANGED"
		return d
	}
	d["state_read_code"] = "OK"
	d["remaining"] = state.remaining()
	intents, steps, settled := len(state.Intents), 0, 0
	for _, intent := range state.Intents {
		for _, step := range intent.Steps {
			steps++
			if step.Settled {
				settled++
			}
		}
	}
	d["local_intent_count"], d["step_count"], d["settled_step_count"], d["registration_count"] = intents, steps, settled, len(state.Registrations)
	if sid == "" || workspace == "" {
		d["registration_scope_code"] = "ORIGINAL_NATIVE_SCOPE_UNKNOWN"
		return d
	}
	matches := 0
	for digest, registration := range state.Registrations {
		a := registration.Anchor
		if a.Registration.NodeID != node || a.Registration.NativeSessionID != sid || a.Registration.Workspace != workspace {
			continue
		}
		matches++
		d["registration_digest_sha256"] = hash([]byte(digest))
		d["registration_intent_sha256"] = hash([]byte(registration.IntentID))
		if a.State == "REGISTERED" || a.State == "OFFLINE" || a.State == "REVOKED" {
			d["registration_state"] = a.State
		} else {
			d["registration_state"] = "UNKNOWN"
		}
		if expiry, err := time.Parse(time.RFC3339Nano, a.LeaseExpiresAt); err == nil {
			d["registration_lease_expires_at"] = expiry.UTC().Format(time.RFC3339Nano)
			d["registration_lease_current"] = time.Now().Before(expiry)
		} else {
			d["registration_lease_expires_at"] = "UNKNOWN"
			d["registration_lease_current"] = "UNKNOWN"
		}
		a.LeaseExpiresAt = ""
		encoded, _ := json.Marshal(a)
		d["registration_immutable_sha256"] = hash(encoded)
	}
	d["registration_matches"], d["registration_present"], d["registration_unique"] = matches, matches > 0, matches == 1
	if matches != 1 {
		d["registration_lease_expires_at"] = "UNKNOWN"
		delete(d, "registration_lease_current")
		delete(d, "registration_immutable_sha256")
	}
	return d
}

func (h *ownerGroupsHost) recordSelectionFailure(t *testing.T, actor int, label, group string, reply ownerGroupsHostReply) {
	t.Helper()
	path, node, sid, workspace := "", "", "", ""
	if h.fixture != nil && h.fixture.actualNode != nil {
		path, node = h.fixture.actualNode.statePath(), h.fixture.actualNode.id
	} else if h.node != nil {
		path, node = h.node.statePath(), h.node.id
	}
	if actor >= 0 && actor < len(h.originalSIDs) {
		sid = h.originalSIDs[actor]
	}
	if actor >= 0 && actor < len(h.workspaces) {
		workspace = h.workspaces[actor]
	}
	d := ownerGroupsSelectionDiagnostic(path, node, sid, workspace, actor, label, group, reply)
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Log("OWNER_GROUPS_SELECTION_FAILURE serialization=FAILED")
		return
	}
	t.Logf("OWNER_GROUPS_SELECTION_FAILURE metadata=%s", encoded)
	// A separate diagnostics directory cannot be mistaken for an M7 baseline
	// audit. Failure to preserve this evidence never replaces the original FAIL.
	if filepath.Dir(os.Getenv("CICADA_N3_CICADA_BINARY")) != "/out" {
		t.Log("OWNER_GROUPS_SELECTION_FAILURE artifact=UNAVAILABLE")
		return
	}
	directory := filepath.Join("/out", "owner-groups-selection-diagnostics")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Log("OWNER_GROUPS_SELECTION_FAILURE artifact=MKDIR_ERROR")
		return
	}
	name := hash([]byte(h.control + "\x00" + label + "\x00" + strconv.Itoa(actor)))[:24] + ".json"
	f, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Log("OWNER_GROUPS_SELECTION_FAILURE artifact=OPEN_ERROR")
		return
	}
	_, writeErr := f.Write(append(encoded, '\n'))
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Log("OWNER_GROUPS_SELECTION_FAILURE artifact=WRITE_ERROR")
		return
	}
	t.Logf("OWNER_GROUPS_SELECTION_FAILURE file=owner-groups-selection-diagnostics/%s sha256=%s", name, hash(append(encoded, '\n')))
}

// Pure diagnostic/privacy checks only. No product API, crypto or Runtime runs.
func TestN3OwnerGroupsSelectionFailureKeepsClosedImmediateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const node, sid, workspace = "SYNTHETIC_NODE", "SYNTHETIC_PRIVATE_SID", "/SYNTHETIC_PRIVATE_WORKSPACE"
	const secret = "SYNTHETIC_SECRET_PAYLOAD"
	raw := []byte(`{"node_id":"SYNTHETIC_NODE","pending_operation":"SYNTHETIC_SECRET_PAYLOAD","pending_packet":"U1lOVEhFVElDX1NFQ1JFVF9QQVlMT0FE","local_endpoint_intents":{},"endpoint_groups_registrations":{"private-digest":{"intent_id":"PRIVATE_INTENT","anchor":{"registration":{"node_id":"SYNTHETIC_NODE","native_session_id":"SYNTHETIC_PRIVATE_SID","workspace":"/SYNTHETIC_PRIVATE_WORKSPACE"},"state":"REGISTERED","lease_expires_at":"2099-01-01T00:00:00Z"}}}}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reply := ownerGroupsHostReply{Public: map[string]string{}, Output: json.RawMessage(`"CODEX_NODE_TICKET_UNAVAILABLE SYNTHETIC_SECRET_PAYLOAD"`), Diagnostic: json.RawMessage(`{"observed":true,"parsed_object_present":false,"is_error_observed":false,"product_error_codes":["CODEX_NODE_TICKET_UNAVAILABLE","SYNTHETIC_SECRET_PAYLOAD"],"private":"SYNTHETIC_SECRET_PAYLOAD"}`)}
	d := ownerGroupsSelectionDiagnostic(path, node, sid, workspace, 2, "m6-explicit-readd-select", "PRIVATE_GROUP", reply)
	if d["state_read_code"] != "OK" || d["registration_present"] != true || d["registration_matches"] != 1 || d["parsed_object_present"] != false {
		t.Fatal("immediate known state not captured")
	}
	flags := d["remaining"].(map[string]bool)
	if !flags["operation"] || !flags["packet"] || flags["response"] {
		t.Fatal("fifteen-field state projection changed")
	}
	encoded := must(json.Marshal(d))
	for _, private := range []string{secret, sid, workspace, "PRIVATE_GROUP", "PRIVATE_INTENT", "private-digest"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("diagnostic leaked private payload or coordinate")
		}
	}
	if !bytes.Equal(raw, must(os.ReadFile(path))) {
		t.Fatal("diagnostic changed protected state")
	}
	if codes := d["product_error_codes"].([]string); len(codes) != 1 || codes[0] != "CODEX_NODE_TICKET_UNAVAILABLE" {
		t.Fatal("closed product error was lost or unclassified payload escaped")
	}
	rawOnly := reply
	rawOnly.Diagnostic = nil
	if codes := ownerGroupsSelectionDiagnostic(path, node, sid, workspace, 2, "m6-test", "PRIVATE_GROUP", rawOnly)["product_error_codes"].([]string); len(codes) != 1 {
		t.Fatal("raw return lost its white-listed code when Host diagnostic was absent")
	}
	other := ownerGroupsSelectionDiagnostic(path, "OTHER_NODE", sid, workspace, 2, "m6-test", "PRIVATE_GROUP", reply)
	if other["state_read_code"] != "NODE_SCOPE_UNKNOWN_OR_CHANGED" || other["remaining"].(map[string]any)["packet"] != "UNKNOWN" {
		t.Fatal("unknown Node scope became empty pending state")
	}
	missing := ownerGroupsSelectionDiagnostic(path+".missing", node, sid, workspace, 2, "m6-test", "PRIVATE_GROUP", ownerGroupsHostReply{})
	if missing["registration_present"] != "UNKNOWN" || missing["remaining"].(map[string]any)["packet"] != "UNKNOWN" || missing["parsed_object_present"] != "UNKNOWN" {
		t.Fatal("unread state silently became false")
	}
	badLease := bytes.ReplaceAll(raw, []byte("2099-01-01T00:00:00Z"), []byte(secret))
	if err := os.WriteFile(path, badLease, 0600); err != nil {
		t.Fatal(err)
	}
	bad := ownerGroupsSelectionDiagnostic(path, node, sid, workspace, 2, "m6-test", "PRIVATE_GROUP", reply)
	if bad["registration_lease_expires_at"] != "UNKNOWN" || bytes.Contains(must(json.Marshal(bad)), []byte(secret)) {
		t.Fatal("invalid lease escaped closed time projection")
	}
	if !bytes.Equal(badLease, must(os.ReadFile(path))) {
		t.Fatal("bad lease diagnostic changed state")
	}
	directory := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, nonregular := range []string{directory, link} {
		got := ownerGroupsSelectionDiagnostic(nonregular, node, sid, workspace, 0, "m7-source-g1", "PRIVATE_GROUP", reply)
		if got["state_read_code"] != "NONREGULAR_OR_OVER_LIMIT" || got["registration_present"] != "UNKNOWN" || got["remaining"].(map[string]any)["packet"] != "UNKNOWN" {
			t.Fatal("nonregular entry was opened or silently became absent state")
		}
	}
	if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	invalid := ownerGroupsSelectionDiagnostic(path, node, sid, workspace, 0, "m7-source-g1", "PRIVATE_GROUP", reply)
	if invalid["state_read_code"] != "INVALID_JSON" || invalid["registration_present"] != "UNKNOWN" {
		t.Fatal("invalid state treated as an absent registration")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", (8<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	large := ownerGroupsSelectionDiagnostic(path, node, sid, workspace, 0, "m7-source-g1", "PRIVATE_GROUP", reply)
	if large["state_read_code"] != "NONREGULAR_OR_OVER_LIMIT" || large["remaining"].(map[string]any)["packet"] != "UNKNOWN" {
		t.Fatal("over-limit state decoded or treated as empty")
	}
}
