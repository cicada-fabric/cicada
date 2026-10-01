#!/usr/bin/env python3
"""Run the Hub -> PQ-paired Node Agent -> real Codex approval path in isolation.

The Go test is overlaid temporarily so this runner adds no production or test
source changes. Pairing uses the production Node-Control proof, encrypted Owner
preview/confirm, and sealed Worker approval RPCs. Its result reports IDs only in
redacted form and omits prompts, approval request bodies, provider output, and
credentials.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time


TEST_NAME = "TestMachineAgentBinaryRemoteApprovalEndToEnd"
MIN_CODEX_VERSION = (0, 159, 3)
SAFE_GO_TEST_STAGES = frozenset({
    "approval_target", "codex_config", "codex_config_write", "codex_home", "codex_wrapper",
    "docker_cli", "encrypted_goal_result_failed", "intent_encode", "native_approval_attempt_mismatch",
    "native_approval_not_observed", "native_approval_request_invalid", "native_approval_thread_missing",
    "native_thread_identity_mismatch", "pending_list_decode", "pending_list_encode",
    "workspace_cwd_not_absolute", "workspace_cwd_mount_mismatch", "approved_native_action_not_verified",
    "agent_exit_after_approval", "agent_exit_before_approval", "agent_timeout_after_approval",
    "additional_decision_failed", "approval_identity_changed", "decision_encode",
    "too_many_native_approvals", "unsupported_native_approval",
})
BOOTSTRAP = r'''import os, re
text = open('/run/secrets/provider.env', encoding='utf-8').read()
match = re.search(r'(?m)^\s*(?:export\s+)?API_KEY=(.*?)\s*$', text)
if not match or not match.group(1).strip():
    raise SystemExit(31)
os.environ['API_KEY'] = match.group(1).strip().strip("\"'")
for name in ('CICADA_API_TOKEN', 'CICADA_API_TOKEN_FILE', 'CICADA_NODE_TOKEN', 'CICADA_NODE_TOKEN_FILE'):
    if os.environ.get(name):
        raise SystemExit(32)
proxy = os.environ.get('CICADA_TEST_PROXY', '')
if proxy:
    os.environ['HTTP_PROXY'] = proxy
    os.environ['HTTPS_PROXY'] = proxy
os.environ['CODEX_HOME'] = '/home/cicada/.codex'
os.execvp('codex', ['codex', 'app-server', '--stdio', '--disable', 'plugins'])
'''


class Reporter:
    def __init__(self, output_file, record):
        self.output_file = output_file
        self.log_file = output_file.with_suffix(output_file.suffix + ".go.log")
        self.record = record

    @staticmethod
    def _write_private(path, payload):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)

    def finish(self, status, reason, exit_code, stage, go_log=None, extra=None):
        record = dict(self.record)
        record.update({"status": status, "reason": reason, "exit_code": exit_code,
                       "failed_stage": stage})
        if extra:
            record.update(extra)
        if go_log is not None:
            raw = go_log.encode("utf-8", errors="replace")
            self._write_private(self.log_file, raw)
            record["private_go_log"] = str(self.log_file)
            record["private_go_log_sha256"] = hashlib.sha256(raw).hexdigest()
        self._write_private(self.output_file, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        summary = {"status": status, "failed_stage": stage, "exit_code": exit_code,
                   "result_file": str(self.output_file)}
        if status != "PASS":
            summary["reason"] = reason
        print(json.dumps(summary, sort_keys=True))
        raise SystemExit(exit_code)


def fail(message, code=1, status="BLOCKED", reporter=None, stage=None):
    if reporter:
        reporter.finish(status, message, code, stage or message)
    print(json.dumps({"status": status, "reason": message, "exit_code": code}, sort_keys=True))
    raise SystemExit(code)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def docker(args, timeout=30, capture=True):
    return subprocess.run(["docker", *args], text=True, capture_output=capture,
                          check=False, timeout=timeout)


def supports_required_codex_version(output):
    match = re.search(r"(?<![0-9])(\d+)\.(\d+)\.(\d+)(?![0-9])", output)
    return bool(match and tuple(int(part) for part in match.groups()) >= MIN_CODEX_VERSION)


def classify_go_test_stage(raw):
    for line in raw.splitlines():
        match = re.search(r"stage=([a-z0-9_]+)", line)
        if match and match.group(1) in SAFE_GO_TEST_STAGES:
            return match.group(1)
    return "go_test_or_compile"


def shell_quote_posix(value):
    """Match the generated Go wrapper's single-argument POSIX shell quoting."""
    return "'" + value.replace("'", "'\\''") + "'"


def replaced_test_source(source):
    replacements = [
        (
            'intentBody := []byte(`{"text":"Run the approval protocol fixture for this Node","kind":"goal","goal":{"objective":"Run the approval protocol fixture for this Node","success_criteria":"Return the fake app-server completion summary","constraints":"Do not modify files or contact external services","machine_id":"node-binary-approval","harness":"codex","resources":{"physical_resource_id":"gpu/0"}}}`)',
            '''marker := fmt.Sprintf("CICADA_NATIVE_%x", time.Now().UnixNano())
	approvalTarget := filepath.Join(root, "approval-target")
	if err := os.MkdirAll(approvalTarget, 0o700); err != nil { t.Fatal("stage=approval_target") }
	objective := fmt.Sprintf("Use the Codex command tool to create exactly one file at /approval-target/result.txt containing exactly %s. This is an isolated test directory outside the workspace. Request normal approval, perform no other actions, do not contact external services, and reply with the marker alone.", marker)
	intentBody, err := json.Marshal(map[string]any{"text": objective, "kind": "goal", "goal": map[string]any{
		"objective": objective, "success_criteria": "The isolated marker file matches exactly",
		"constraints": "Only write the specified isolated test file after explicit approval; no network access or other files",
		"machine_id": "node-binary-approval", "harness": "codex",
		"resources": map[string]any{"physical_resource_id": "gpu/0"},
	}})
	if err != nil { t.Fatal("stage=intent_encode") }''',
        ),
        (
            '''codexBin := filepath.Join(root, "fake-codex")
	approvalCapture := filepath.Join(root, "app-server-approval-reply.json")
	fakeAppServer := `#!/bin/sh
set -eu
test "$1" = app-server
test "$2" = --stdio
test "$3" = --disable
test "$4" = plugins
test -z "${CICADA_API_TOKEN:-}"
test -z "${CICADA_API_TOKEN_FILE:-}"
test -z "${CICADA_NODE_TOKEN:-}"
test -z "${CICADA_NODE_TOKEN_FILE:-}"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\\n' '{"id":1,"result":{}}' ;;
    *'"method":"thread/start"'*) printf '%s\\n' '{"id":2,"result":{"thread":{"id":"fake-native-thread"}}}' ;;
    *'"method":"turn/start"'*)
      printf '%s\\n' '{"id":3,"result":{"turn":{"id":"fake-native-turn","status":"inProgress"}}}'
      printf '%s\\n' '{"id":77,"method":"item/commandExecution/requestApproval","params":{"threadId":"fake-native-thread","turnId":"fake-native-turn","itemId":"fake-native-item","availableDecisions":["accept","decline"],"command":"echo fake approval integration"}}'
      ;;
    *'"id":77'*)
      printf '%s\\n' "$line" > "$CICADA_TEST_APPROVAL_CAPTURE"
      case "$line" in
        *'"decision":"accept"'*) printf '%s\\n' '{"method":"turn/completed","params":{"turn":{"status":"completed"},"item":{"type":"agentMessage","text":"FAKE_APP_SERVER_APPROVAL_COMPLETE"}}}' ;;
        *) printf '%s\\n' '{"method":"turn/completed","params":{"turn":{"status":"failed"}}}' ;;
      esac
      ;;
  esac
done
`
	if err := os.WriteFile(codexBin, []byte(fakeAppServer), 0o700); err != nil {
		t.Fatal(err)
	}''',
            '''codexBin := filepath.Join(root, "real-codex-wrapper")
	codexHome := filepath.Join(root, "codex-home")
	if err := os.MkdirAll(codexHome, 0o700); err != nil { t.Fatal("stage=codex_home") }
	configPath := os.Getenv("CICADA_NATIVE_CODEX_CONFIG")
	config, err := os.ReadFile(configPath)
	if err != nil { t.Fatal("stage=codex_config") }
	config = []byte(strings.Replace(string(config), `model = "gpt-5.5"`, `model = "gpt-5.6-luna"`, 1))
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), config, 0o600); err != nil { t.Fatal("stage=codex_config_write") }
	if err := os.MkdirAll(approvalTarget, 0o700); err != nil { t.Fatal("stage=approval_target") }
	nativeWorkspace := filepath.Join(nodeWorkspaceRoot, "workspaces", workspaces[0].ID)
	if !filepath.IsAbs(nativeWorkspace) { t.Fatal("stage=workspace_cwd_not_absolute") }
	workspaceCWD := filepath.Clean(nativeWorkspace)
	if workspaceCWD != nativeWorkspace { t.Fatal("stage=workspace_cwd_mount_mismatch") }
	containerName := "cicada-real-node-codex-" + fmt.Sprintf("%x", time.Now().UnixNano())
	dockerBin, err := exec.LookPath("docker")
	if err != nil { t.Fatal("stage=docker_cli") }
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\\\''") + "'" }
	proxy := os.Getenv("CICADA_NATIVE_PROXY")
	wrapper := "#!/bin/sh\\nset -eu\\n"
	wrapper += "test \\\"$1\\\" = app-server; test \\\"$2\\\" = --stdio; test \\\"$3\\\" = --disable; test \\\"$4\\\" = plugins\\n"
	wrapper += "exec " + quote(dockerBin) + " run --rm -i --name " + quote(containerName) + " --network host "
	for _, mount := range []string{
		codexHome + ":/home/cicada/.codex",
		// The production Node sends its host-local absolute workspace as the
		// app-server cwd. Mount that exact path inside the disposable runtime.
		nativeWorkspace + ":" + workspaceCWD,
		nativeWorkspace + ":/workspace",
		approvalTarget + ":/approval-target",
		os.Getenv("CICADA_NATIVE_ENV_FILE") + ":/run/secrets/provider.env:ro",
	} { wrapper += "-v " + quote(mount) + " " }
	wrapper += "-e CODEX_HOME=/home/cicada/.codex -e CICADA_TEST_PROXY=" + quote(proxy) +
		" --entrypoint python3 " + quote(os.Getenv("CICADA_NATIVE_CODEX_IMAGE")) + " -c " + quote(`'''+BOOTSTRAP+'''`) + "\\n"
	if err := os.WriteFile(codexBin, []byte(wrapper), 0o700); err != nil { t.Fatal("stage=codex_wrapper") }''',
        ),
        (
            '''processCtx, cancelProcess := context.WithTimeout(context.Background(), 35*time.Second)''',
            '''processCtx, cancelProcess := context.WithTimeout(context.Background(), 360*time.Second)''',
        ),
        (
            '''"CICADA_CODEX_BIN=" + codexBin, "CICADA_CODEX_MODEL=fake-model",
		"CICADA_NODE_RESOURCE_ID=gpu/0",
		"CICADA_TEST_APPROVAL_CAPTURE=" + approvalCapture,
		"CICADA_WORKSPACE_ROOT=" + nodeWorkspaceRoot,
		"CICADA_WORKER_TIMEOUT_SECONDS=25",''',
            '''"CICADA_CODEX_BIN=" + codexBin, "CICADA_CODEX_MODEL=gpt-5.6-luna",
		"CODEX_HOME=" + codexHome,
		"CICADA_NODE_RESOURCE_ID=gpu/0",
		"CICADA_NATIVE_CODEX_IMAGE=" + os.Getenv("CICADA_NATIVE_CODEX_IMAGE"),
		"CICADA_NATIVE_ENV_FILE=" + os.Getenv("CICADA_NATIVE_ENV_FILE"),
		"CICADA_NATIVE_CODEX_CONFIG=" + os.Getenv("CICADA_NATIVE_CODEX_CONFIG"),
		"CICADA_NATIVE_PROXY=" + os.Getenv("CICADA_NATIVE_PROXY"),
		"CICADA_WORKSPACE_ROOT=" + nodeWorkspaceRoot,
		"CICADA_WORKER_TIMEOUT_SECONDS=360",''',
        ),
        (
            '''for index := range approvals {
		if approvals[index].GoalID == goal.ID && approvals[index].Method == store.NodeApprovalCommandExecution &&
			approvals[index].Status == "pending" {
			pending = &approvals[index]
			break
		}
	}
	if pending == nil || pending.Attempt != 1 || !strings.Contains(string(pending.Request), "fake approval integration") {
		failedGoal, goalErr := controlPlane.Goal(goal.ID)
		var workerStatus, workerError string
		if failedGoal != nil && failedGoal.Worker != nil {
			workerStatus, workerError = failedGoal.Worker.Status, failedGoal.Worker.LastError
		}
		t.Fatalf("encrypted Client approvals.list did not expose the live fake app-server request: approvals=%#v worker_status=%s worker_error=%q goalErr=%v stdout=%s stderr=%s",
			approvals, workerStatus, workerError, goalErr, agentStdout.String(), agentStderr.String())
	}''',
            '''for index := range approvals {
		if approvals[index].GoalID == goal.ID && approvals[index].Status == "pending" &&
			(approvals[index].Method == store.NodeApprovalCommandExecution || approvals[index].Method == store.NodeApprovalFileChange) {
			pending = &approvals[index]
			break
		}
	}
	var nativeApproval struct { ThreadID string `json:"threadId"` }
	if pending == nil {
		t.Fatal("stage=native_approval_not_observed")
	}
	if pending.Attempt != 1 {
		t.Fatal("stage=native_approval_attempt_mismatch")
	}
	if err := json.Unmarshal(pending.Request, &nativeApproval); err != nil {
		t.Fatal("stage=native_approval_request_invalid")
	}
	if nativeApproval.ThreadID == "" {
		t.Fatal("stage=native_approval_thread_missing")
	}''',
        ),
        (
            '''approvalReply, err := os.ReadFile(approvalCapture)
	if err != nil || !bytes.Contains(approvalReply, []byte(`"id":77`)) ||
		!bytes.Contains(approvalReply, []byte(`"decision":"accept"`)) {
		currentGoal, goalErr := controlPlane.Goal(goal.ID)
		t.Fatalf("fake app-server did not receive the original approval request ID and Client decision: %s err=%v worker=%#v goalErr=%v stdout=%s stderr=%s",
			approvalReply, err, currentGoal.Worker, goalErr, agentStdout.String(), agentStderr.String())
	}''',
            '''markerBytes, err := os.ReadFile(filepath.Join(approvalTarget, "result.txt"))
	if err != nil || strings.TrimSpace(string(markerBytes)) != marker {
		t.Fatal("stage=approved_native_action_not_verified")
	}
	goal, err = controlPlane.Goal(goal.ID)
	if err != nil || goal == nil || goal.Worker == nil || goal.Worker.ThreadID != nativeApproval.ThreadID {
		t.Fatal("stage=native_thread_identity_mismatch")
	}''',
        ),
        (
            '''if err := json.Unmarshal(callClientRPC("goal.result", goalResultRequest), &goalResult); err != nil ||
		goalResult.IntentID != accepted.ID || goalResult.GoalID != goal.ID || len(goalResult.Workers) != 1 ||
		goalResult.Workers[0].Status != "completed" ||
		goalResult.Workers[0].Summary != "FAKE_APP_SERVER_APPROVAL_COMPLETE" {
		t.Fatalf("encrypted Client goal.result omitted the actual Node binary result: result=%#v err=%v", goalResult, err)
	}''',
            '''if err := json.Unmarshal(callClientRPC("goal.result", goalResultRequest), &goalResult); err != nil ||
		goalResult.IntentID != accepted.ID || goalResult.GoalID != goal.ID || len(goalResult.Workers) != 1 ||
		goalResult.Workers[0].Status != "completed" || goalResult.Workers[0].Attempt != 1 ||
		goalResult.Workers[0].Summary == "" || goalResult.IntentStatus != "resolved" {
		t.Fatal("stage=encrypted_goal_result_failed")
	}
	result := map[string]any{
		"status": "PASS", "hub": "isolated_http_handler", "node_agent": "real_binary",
		"node_pairing": "production_pq_owner_confirmed", "management_channel": "sealed_node_control_rpc",
		"codex_app_server": os.Getenv("CICADA_NATIVE_CODEX_VERSION"), "model": "gpt-5.6-luna",
		"client": "encrypted_synthetic_protocol_client", "thread_id": redactNativeTestID(nativeApproval.ThreadID),
		"native_session_exact": goal.Worker.ThreadID == nativeApproval.ThreadID,
		"approval_method": pending.Method, "approval_id": redactNativeTestID(pending.ID),
		"worker_attempt": goalResult.Workers[0].Attempt, "worker_status": goalResult.Workers[0].Status,
		"goal_result_intent_status": goalResult.IntentStatus, "goal_result_worker_status": goalResult.Workers[0].Status,
		"approved_action_verified": true,
	}
	encoded, _ := json.Marshal(result)
	fmt.Printf("REAL_NATIVE_E2E_RESULT: %s\\n", encoded)''',
        ),
    ]
    native_start_marker = 'codexBin := filepath.Join(root, "fake-codex")'
    if native_start_marker not in source:
        raise ValueError("source_anchor_missing:native_codex_wrapper")
    native_start = source.index(native_start_marker)
    native_end_marker = '\n\tif err := os.WriteFile(codexBin, []byte(fakeAppServer), 0o700); err != nil {\n\t\tt.Fatal(err)\n\t}'
    native_end = source.index(native_end_marker, native_start) + len(native_end_marker)
    source = source[:native_start] + replacements[1][1] + source[native_end:]
    del replacements[1]
    for old, new in replacements:
        if old not in source:
            raise ValueError("source_anchor_missing:" + old[:80].replace("\\n", " "))
        source = source.replace(old, new, 1)
    wait_start = source.index('\tselect {\n\tcase processErr := <-processDone:',
                              source.index('decisionRequest, err := json.Marshal'))
    wait_end = source.index('\tmarkerBytes, err := os.ReadFile(', wait_start)
    source = source[:wait_start] + '''\tapprovedIDs := map[string]bool{pending.ID: true}
    for {
        select {
        case processErr := <-processDone:
            if processErr != nil { t.Fatal("stage=agent_exit_after_approval") }
            goto agentComplete
        case <-processCtx.Done():
            t.Fatal("stage=agent_timeout_after_approval")
        case <-time.After(250 * time.Millisecond):
            listBody, err := json.Marshal(map[string]bool{"pending_only": true})
            if err != nil { t.Fatal("stage=pending_list_encode") }
            var more []store.Approval
            if err := json.Unmarshal(callClientRPC("approvals.list", listBody), &more); err != nil {
                t.Fatal("stage=pending_list_decode")
            }
            for _, candidate := range more {
                if candidate.GoalID != goal.ID || candidate.WorkerID != pending.WorkerID ||
                    candidate.Status != "pending" || approvedIDs[candidate.ID] { continue }
                if candidate.Method != store.NodeApprovalCommandExecution &&
                    candidate.Method != store.NodeApprovalFileChange { t.Fatal("stage=unsupported_native_approval") }
                if len(approvedIDs) >= 6 { t.Fatal("stage=too_many_native_approvals") }
                var identity struct { ThreadID string `json:"threadId"` }
                if candidate.Attempt != 1 || json.Unmarshal(candidate.Request, &identity) != nil ||
                    identity.ThreadID != nativeApproval.ThreadID { t.Fatal("stage=approval_identity_changed") }
                request, err := json.Marshal(map[string]string{"approval_id": candidate.ID, "decision": "accept"})
                if err != nil { t.Fatal("stage=decision_encode") }
                var acceptedDecision store.Approval
                if err := json.Unmarshal(callClientRPC("approvals.decide", request), &acceptedDecision); err != nil ||
                    acceptedDecision.ID != candidate.ID || acceptedDecision.Decision != "accept" {
                    t.Fatal("stage=additional_decision_failed")
                }
                approvedIDs[candidate.ID] = true
            }
        }
    }
agentComplete:
    cancelProcess()

''' + source[wait_end:]
    approval_deadline = 'approvalDeadline := time.Now().Add(20 * time.Second)'
    if approval_deadline not in source:
        raise ValueError("approval_deadline_anchor_missing")
    source = source.replace(approval_deadline,
                            'approvalDeadline := time.Now().Add(180 * time.Second)', 1)
    source += '''
func redactNativeTestID(value string) string {
	if len(value) <= 12 { return value }
	return value[:8] + "…" + value[len(value)-4:]
}
'''
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--image", default="cicada-codex:client-hub-dev")
    parser.add_argument("--go-image", default="golang:1.27.1-bookworm")
    parser.add_argument("--proxy", default="http://127.0.0.1:7890")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-root", type=Path,
                        help="immutable CICADA source tree to test; defaults to this driver's repository")
    parser.add_argument("--source-fingerprint", default="",
                        help="externally verified source-tree fingerprint for evidence attribution")
    args = parser.parse_args()
    driver_root = Path(__file__).resolve().parent.parent
    source_root = args.source_root.resolve() if args.source_root else driver_root
    if args.source_fingerprint and not re.fullmatch(r"[0-9a-f]{64}", args.source_fingerprint):
        fail("source_fingerprint_must_be_sha256", stage="source_fingerprint")
    module = source_root / "cicada-go"
    target = module / "internal/server/machine_agent_approval_integration_test.go"
    output_file = args.output.resolve() if args.output else driver_root / ".cicada-data/v01-finish-20260930T145216Z" / (
        "node-approval-native-" + str(time.time_ns()) + ".json")
    if output_file.exists() or output_file.with_suffix(output_file.suffix + ".go.log").exists():
        output_file = output_file.with_name(output_file.stem + "-" + str(time.time_ns()) + output_file.suffix)
    identity = {
        "driver": "test-real-node-codex-approval.py",
        "driver_sha256": sha256_file(Path(__file__).resolve()),
        "go_test": TEST_NAME,
        "go_test_source_sha256": sha256_file(target) if target.is_file() else "unavailable",
        "source_root": str(source_root),
        "source_fingerprint": args.source_fingerprint or None,
        "repository_head": None,
        "codex_image": args.image,
        "codex_image_id": None,
        "codex_cli_version": None,
        "model": "gpt-5.6-luna",
        "go_image": args.go_image,
        "go_test_exit_code": None,
        "credential_file_mode": None,
        "credential_file_size_bytes": None,
    }
    head = subprocess.run(["git", "-C", str(driver_root), "rev-parse", "HEAD"], text=True,
                         capture_output=True, check=False)
    if head.returncode == 0:
        identity["repository_head"] = head.stdout.strip()
    reporter = Reporter(output_file, identity)
    try:
        env_file = args.env_file.resolve(strict=True)
    except OSError:
        fail("provider_env_file_unavailable", reporter=reporter, stage="credential_file")
    metadata = env_file.stat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("provider_env_permissions_must_be_0600", reporter=reporter, stage="credential_file_permissions")
    reporter.record["credential_file_mode"] = format(stat.S_IMODE(metadata.st_mode), "04o")
    reporter.record["credential_file_size_bytes"] = metadata.st_size
    docker_bin = shutil.which("docker")
    if not docker_bin:
        fail("docker_unavailable", reporter=reporter, stage="docker_cli")
    if not Path("/var/run/docker.sock").exists():
        fail("local_docker_socket_unavailable_for_isolated_runner", reporter=reporter, stage="docker_socket")
    context = subprocess.run([docker_bin, "context", "show"], text=True, capture_output=True)
    if context.returncode:
        fail("docker_context_unavailable", reporter=reporter, stage="docker_context")
    endpoint = subprocess.run([docker_bin, "context", "inspect", context.stdout.strip(),
                               "--format", "{{(index .Endpoints \"docker\").Host}}"],
                              text=True, capture_output=True)
    if endpoint.returncode or not endpoint.stdout.strip().startswith("unix:///var/run/docker.sock"):
        fail("docker_context_is_not_local_default_socket", reporter=reporter, stage="docker_context_endpoint")
    if docker(["info", "--format", "{{.ServerVersion}}"], timeout=20).returncode:
        fail("docker_daemon_unavailable", reporter=reporter, stage="docker_daemon")
    image_id_result = docker(["image", "inspect", args.image, "--format", "{{.Id}}"])
    if image_id_result.returncode:
        fail("codex_image_unavailable", reporter=reporter, stage="codex_image")
    reporter.record["codex_image_id"] = image_id_result.stdout.strip()
    version = docker(["run", "--rm", "--network", "host", "--entrypoint", "codex",
                      args.image, "--version"], timeout=20)
    if version.returncode or not supports_required_codex_version(version.stdout):
        fail("codex_cli_version_below_0_159_3_or_unparseable", reporter=reporter, stage="codex_cli_version")
    reporter.record["codex_cli_version"] = version.stdout.strip()

    try:
        transformed = replaced_test_source(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        fail("test_overlay_source_anchor_mismatch", reporter=reporter, stage="go_test_overlay")
    reporter.record["overlay_test_source_sha256"] = hashlib.sha256(transformed.encode("utf-8")).hexdigest()

    with tempfile.TemporaryDirectory(prefix="cicada-real-node-approval-") as temporary:
        scratch = Path(temporary)
        os.chmod(scratch, 0o700)
        (scratch / "tmp").mkdir(mode=0o700)
        (scratch / "home").mkdir(mode=0o700)
        replacement = scratch / "machine_agent_approval_integration_test.go"
        replacement.write_text(transformed, encoding="utf-8")
        os.chmod(replacement, 0o600)
        overlay = scratch / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(target): str(replacement)}}), encoding="utf-8")
        os.chmod(overlay, 0o600)
        output_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        run_env = os.environ.copy()
        run_env.update({
            "CICADA_NATIVE_ENV_FILE": str(env_file), "CICADA_NATIVE_CODEX_IMAGE": args.image,
            "CICADA_NATIVE_CODEX_VERSION": version.stdout.strip(), "CICADA_NATIVE_PROXY": args.proxy,
            "CICADA_NATIVE_CODEX_CONFIG": str(source_root / "docker/codex-config.toml"),
            "CICADA_NATIVE_DOCKER_IMAGE_ID": image_id_result.stdout.strip(),
        })
        go = shutil.which("go")
        try:
            if go:
                command = [go, "test", "-v", "-count=1", "-overlay", str(overlay),
                           "./internal/server", "-run", "^" + TEST_NAME + "$", "-timeout", "8m"]
                result = subprocess.run(command, cwd=module, env=run_env, text=True,
                                        capture_output=True, timeout=540)
            else:
                socket_gid = str(Path("/var/run/docker.sock").stat().st_gid)
                module_cache = driver_root / ".cicada-data/m1-gomodcache"
                build_cache = Path("/home/zyf/.cache/go-build")
                command = [docker_bin, "run", "--rm", "--network", "host", "--user",
                           f"{os.getuid()}:{os.getgid()}", "--group-add", socket_gid,
                           "-v", f"{source_root}:{source_root}:ro", "-v", f"{scratch}:{scratch}",
                           "-v", f"{env_file}:{env_file}:ro", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                           "-v", f"{docker_bin}:/usr/bin/docker:ro", "-v", f"{module_cache}:/gomod:ro",
                           "-v", f"{build_cache}:/cache", "-w", str(module),
                           "-e", f"TMPDIR={scratch / 'tmp'}", "-e", f"HOME={scratch / 'home'}",
                           "-e", "GOMODCACHE=/gomod", "-e", "GOCACHE=/cache", "-e", "GOTOOLCHAIN=local",
                           "-e", "GOPROXY=off", "-e", "CGO_ENABLED=1", "-e", f"CICADA_NATIVE_ENV_FILE={env_file}",
                           "-e", f"CICADA_NATIVE_CODEX_IMAGE={args.image}", "-e",
                           f"CICADA_NATIVE_CODEX_VERSION={version.stdout.strip()}", "-e",
                           f"CICADA_NATIVE_CODEX_CONFIG={source_root / 'docker/codex-config.toml'}", "-e",
                           f"CICADA_NATIVE_PROXY={args.proxy}", args.go_image,
                           "go", "test", "-v", "-count=1", "-overlay", str(overlay),
                           "./internal/server", "-run", "^" + TEST_NAME + "$", "-timeout", "8m"]
                result = subprocess.run(command, text=True, capture_output=True, timeout=540)
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
            reporter.finish("FAIL", "go_test_timeout", 1, "go_test_timeout", stdout + stderr,
                            {"go_test_exit_code": None})
        except OSError:
            reporter.finish("BLOCKED", "go_test_runner_unavailable", 1, "go_test_runner")
        raw = result.stdout + result.stderr

    evidence = None
    for line in raw.splitlines():
        marker = "REAL_NATIVE_E2E_RESULT: "
        if marker in line:
            try:
                evidence = json.loads(line.split(marker, 1)[1])
            except ValueError:
                evidence = None
    reporter.record["go_test_exit_code"] = result.returncode
    if result.returncode or not evidence or evidence.get("status") != "PASS":
        stage = classify_go_test_stage(raw)
        reporter.finish("FAIL", "real_native_e2e_" + stage, result.returncode or 1, stage,
                        raw, {"go_test_evidence_status": evidence.get("status") if evidence else None})
    reporter.record["node_pairing"] = evidence.get("node_pairing")
    reporter.record["management_channel"] = evidence.get("management_channel")
    reporter.record["native_evidence"] = evidence
    reporter.finish("PASS", "native_approval_path_verified", 0, "complete", raw)


if __name__ == "__main__":
    main()
