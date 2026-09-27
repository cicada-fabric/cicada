#!/usr/bin/env python3
"""Prove Codex's native approval and persisted Thread continuity in Docker.

This is a native-runtime probe, not a Cicada Hub/Node/Client end-to-end test.
It never copies a provider credential into the repository, image, or output.
"""

import argparse
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import tempfile
import threading
import time


BOOTSTRAP = """
import os
import re
text = open('/run/secrets/provider.env', encoding='utf-8').read()
match = re.search(r'(?m)^\\s*(?:export\\s+)?API_KEY=(.*?)\\s*$', text)
if not match or not match.group(1).strip():
    raise SystemExit('API_KEY is missing from the mounted test environment')
os.environ['API_KEY'] = match.group(1).strip().strip('\\"\\'')
proxy = os.environ.get('CICADA_TEST_PROXY', '')
if proxy:
    os.environ['HTTP_PROXY'] = proxy
    os.environ['HTTPS_PROXY'] = proxy
os.execvp('codex', ['codex', 'app-server', '--stdio', '--disable', 'plugins'])
"""


class AppServer:
    def __init__(self, image, home, workspace, env_file, proxy, phase):
        self.name = f"cicada-native-probe-{os.getpid()}-{phase}-{secrets.token_hex(3)}"
        self.messages = queue.Queue()
        self.next_id = 1
        command = [
            "docker", "run", "--rm", "-i", "--name", self.name, "--network", "host",
            "-v", f"{home}:/home/cicada/.codex",
            "-v", f"{workspace}:/workspace",
            "-v", f"{env_file}:/run/secrets/provider.env:ro",
            "-e", "CODEX_HOME=/home/cicada/.codex",
            "-e", f"CICADA_TEST_PROXY={proxy}",
            "--entrypoint", "python3", image, "-c", BOOTSTRAP,
        ]
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )

        def read_messages():
            for line in self.process.stdout:
                try:
                    self.messages.put(json.loads(line))
                except json.JSONDecodeError:
                    continue
            self.messages.put({"closed": True})

        threading.Thread(target=read_messages, daemon=True).start()

    def write(self, message):
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def take(self, timeout):
        try:
            return self.messages.get(timeout=timeout)
        except queue.Empty:
            return {"timeout": True}

    def request(self, method, params, timeout=12):
        request_id = self.next_id
        self.next_id += 1
        self.write({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            message = self.take(min(1, deadline - time.monotonic()))
            if message.get("id") == request_id or message.get("closed"):
                return message
        return {"timeout": True}

    def initialize(self):
        response = self.request("initialize", {
            "clientInfo": {"name": "cicada-native-probe", "title": "Cicada Native Probe", "version": "1"},
            "capabilities": {"experimentalApi": True},
        })
        if "result" not in response:
            raise RuntimeError("Codex initialize did not complete")
        self.write({"method": "initialized", "params": {}})

    def turn(self, thread_id, prompt, model, timeout, approve):
        request_id = self.next_id
        self.next_id += 1
        self.write({
            "id": request_id, "method": "turn/start", "params": {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
                "cwd": "/workspace", "model": model,
                "approvalPolicy": "on-request",
                "sandboxPolicy": {"type": "workspaceWrite"},
            },
        })
        accepted = False
        approvals = []
        summary = ""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            message = self.take(min(1, deadline - time.monotonic()))
            if message.get("closed"):
                return accepted, approvals, "closed", summary
            if message.get("id") == request_id:
                accepted = "result" in message
                if not accepted:
                    return False, approvals, "turn_start_error", summary
            method = message.get("method", "")
            if method and message.get("id") is not None:
                approvals.append(method)
                if method not in (
                    "item/commandExecution/requestApproval",
                    "item/fileChange/requestApproval",
                ):
                    return accepted, approvals, "unsupported_request", summary
                self.write({
                    "id": message["id"], "result": {
                        "decision": "accept" if approve else "decline",
                    },
                })
            if method in ("item/completed", "item/updated"):
                item = message.get("params", {}).get("item", {})
                if item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                    summary = item["text"].strip()
            if method == "turn/completed":
                status = message.get("params", {}).get("turn", {}).get("status", "completed")
                return accepted, approvals, status, summary
        return accepted, approvals, "timeout", summary

    def file_matches(self, path, expected):
        result = subprocess.run(
            ["docker", "exec", self.name, "cat", path],
            capture_output=True, text=True, check=False, timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == expected

    def close(self):
        self.process.kill()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
        subprocess.run(
            ["docker", "rm", "-f", self.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--image", default="cicada-codex:client-hub-dev")
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--proxy", default="http://127.0.0.1:7890")
    parser.add_argument("--timeout", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    env_file = args.env_file.resolve(strict=True)
    if env_file.stat().st_mode & 0o077:
        parser.error("the provider environment file must not be group/world accessible")
    if args.timeout < 10:
        parser.error("--timeout must be at least 10 seconds")

    repo_root = Path(__file__).resolve().parent.parent
    config = (repo_root / "docker/codex-config.toml").read_text(encoding="utf-8")
    marker = "CICADA_" + secrets.token_hex(8).upper()
    result = {"level": "real_codex_appserver_direct", "model": args.model,
              "hub_node_client": "NOT_RUN", "status": "FAIL"}
    with tempfile.TemporaryDirectory(prefix="cicada-native-probe-") as directory:
        root = Path(directory)
        home, workspace = root / "codex-home", root / "workspace"
        home.mkdir(mode=0o700)
        workspace.mkdir(mode=0o700)
        (home / "config.toml").write_text(config, encoding="utf-8")

        first = AppServer(args.image, home, workspace, env_file, args.proxy, "first")
        try:
            first.initialize()
            started = first.request("thread/start", {
                "model": args.model, "cwd": "/workspace",
                "approvalPolicy": "on-request", "sandbox": "workspace-write",
            })
            thread_id = started.get("result", {}).get("thread", {}).get("id")
            if not thread_id:
                raise RuntimeError("Codex did not return the first native Thread ID")
            result["thread_id"] = thread_id
            accepted, approvals, status, summary = first.turn(
                thread_id,
                "Use your command tool to create /home/cicada/native-approval-probe.txt "
                f"containing exactly {marker}. Request approval if needed. "
                "Then reply with the marker alone.",
                args.model, args.timeout, True,
            )
            result.update(first_turn=status, approval_methods=approvals,
                          first_marker_match=summary == marker,
                          file_match=first.file_matches(
                              "/home/cicada/native-approval-probe.txt", marker,
                          ))
            if not (accepted and status == "completed" and approvals
                    and result["first_marker_match"] and result["file_match"]):
                raise RuntimeError("first native approval turn did not complete")
        finally:
            first.close()

        second = AppServer(args.image, home, workspace, env_file, args.proxy, "second")
        try:
            second.initialize()
            resumed = second.request("thread/resume", {
                "threadId": thread_id, "model": args.model, "cwd": "/workspace",
                "approvalPolicy": "on-request", "sandbox": "workspace-write",
            })
            result["resume_exact"] = resumed.get("result", {}).get("thread", {}).get("id") == thread_id
            if not result["resume_exact"]:
                raise RuntimeError("Codex did not resume the exact native Thread")
            accepted, approvals, status, summary = second.turn(
                thread_id,
                "What exact marker did I ask you to write in the previous turn? "
                "Answer the marker alone; do not use tools.",
                args.model, args.timeout, False,
            )
            result.update(second_turn=status, second_approval_methods=approvals,
                          context_marker_match=summary == marker)
            if not (accepted and status == "completed" and not approvals
                    and result["context_marker_match"]):
                raise RuntimeError("resumed native Thread did not retain context")
        finally:
            second.close()

    result["status"] = "PASS"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(args.output, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
