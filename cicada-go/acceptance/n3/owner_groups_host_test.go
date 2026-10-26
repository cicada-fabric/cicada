package n3_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	Status       string               `json:"status"`
	Daemon       nativeDomainDaemon   `json:"daemon"`
	SIDs         []string             `json:"native_session_ids"`
	FixtureScope string               `json:"fixture_scope"`
	Output       json.RawMessage      `json:"output"`
	Summary      json.RawMessage      `json:"summary"`
	Restarts     int                  `json:"daemon_restarts"`
	LiteralPosts int                  `json:"literal_provider_posts"`
	Public       map[string]string    `json:"public"`
	QueuePosts   map[string]int       `json:"queue_posts"`
	RecordCount  int                  `json:"native_record_count"`
	HistoryKept  bool                 `json:"native_history_prefix_conserved"`
	SelfGroups   *ownerGroupsSelfList `json:"self_groups,omitempty"`
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
	if len(actors.workspaces) != 4 {
		t.Fatal("Owner Group runtime requires four actual original native Threads")
	}
	control := filepath.Join(v.root, "owner-groups-native-control")
	config, result := filepath.Join(v.root, "private-owner-groups-native-config.json"), filepath.Join(v.root, "private-owner-groups-native-result.json")
	writeJSON(t, config, map[string]any{"root": v.root, "workspace": actors.workspaces[0], "workspaces": actors.workspaces,
		"codex_home": v.codexHome, "environment": actors.environment, "codex_binary": "/tools/codex-package/bin/codex",
		"codex_sha256": directIPCodexSHA256, "marketplace": filepath.Join(actors.prefix, "components/node/share/codex"),
		"step": "owner-groups-native", "persistent_daemon": true, "allow_test_termination": true, "daemon_umask": "0002",
		"preparation": "none", "selected_root": actors.prefix, "control": control, "result": result,
		"cicada_sha256": hash(readPrivateBinary(t, filepath.Join(actors.prefix, "components/node/bin/cicada")))})
	command := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/peer_form_native.py", config)
	command.Env, command.Dir, command.Stdout, command.Stderr = actors.environment, actors.workspaces[0], actors.log, actors.log
	h := &ownerGroupsHost{process: startProcess(t, command), control: control, result: result, sequence: 1}
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
			t.Fatal("actual original actor did not select the exact authorized Group")
		}
	}
	question := "SYNTHETIC_OWNER_GROUP_QUESTION_" + h.fixtureScope + "_" + label
	answer := "SYNTHETIC_OWNER_GROUP_ANSWER_" + h.fixtureScope + "_" + label
	ask := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: source, Label: label + "-ask", Tool: "cicada_ask",
		Arguments:     map[string]any{"target": identities[target].Endpoint, "question": question, "idempotency_key": h.fixtureScope + "-" + label},
		Queue:         []ownerGroupsQueueInput{{Body: question, SID: h.originalSIDs[target], Sender: identities[source].Endpoint, Receiver: identities[target].Endpoint, GroupID: group, Kind: "ask"}},
		ObserveFields: []string{"request_id", "operation_id"}})
	request, operation := ask.Public["request_id"], ask.Public["operation_id"]
	for attempt := 0; request == "" && operation != "" && attempt < 30; attempt++ {
		time.Sleep(250 * time.Millisecond)
		status := h.command(t, ownerGroupsHostCommand{Action: "call", Actor: source, Label: label + "-status", Tool: "cicada_operation_status",
			Arguments: map[string]any{"operation_id": operation}, ObserveFields: []string{"request_id"}})
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
	h.command(t, ownerGroupsHostCommand{Action: "call", Actor: target, Label: label + "-reply", Tool: "cicada_reply",
		Arguments: map[string]any{"request_id": request, "body": answer, "idempotency_key": h.fixtureScope + "-reply-" + label},
		Queue:     []ownerGroupsQueueInput{{Body: answer, SID: h.originalSIDs[source], Sender: identities[target].Endpoint, Receiver: identities[source].Endpoint, GroupID: group, Kind: "reply"}},
		BindQueue: map[string]string{answer: request}})
	replied := h.command(t, ownerGroupsHostCommand{Action: "receive_match", Actor: source, Label: label + "-reply-receive", Tool: "cicada_receive",
		Arguments: map[string]any{"limit": 16}, ExpectedRequestID: request, ExpectedBodyMarker: answer})
	if replied.QueuePosts[answer] != 1 {
		t.Fatal("correlated reply did not reach the original requester Runtime once")
	}
	return request
}
