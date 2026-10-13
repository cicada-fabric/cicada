#!/usr/bin/env python3
"""Exercise the local Hub install/update guard through a fake Docker CLI."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parent.parent
INSTALLER = REPO / "scripts" / "install-cicada-server.sh"
CHECKER = REPO / "scripts" / "hub-update-backup-check.py"
BACKUP_SOURCE = REPO / "cicada-go" / "internal" / "store" / "state_backup.go"
BACKUP_CLI_SOURCE = REPO / "cicada-go" / "cmd" / "cicada" / "migration_backup.go"
HUB_VOLUME = "cicada-v2-local-hub-state"
PROJECT = "cicada-v2-local"
CID = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
UNRELATED_CID = "d" * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
state = pathlib.Path(os.environ["FAKE_DOCKER_STATE"])
log = pathlib.Path(os.environ["FAKE_DOCKER_LOG"])
config_output = pathlib.Path(os.environ["FAKE_CONFIG_OUTPUT"])
volume = os.environ.get("CICADA_HUB_VOLUME", "cicada-v2-local-hub-state")
project = os.environ.get("CICADA_DEPLOY_PROJECT", "cicada-v2-local")
target_image = os.environ.get("CICADA_HUB_IMAGE", "cicada-hub:local")
mountpoint = os.environ["FAKE_VOLUME_MOUNTPOINT"]
backup = pathlib.Path(os.environ["FAKE_BACKUP_DESTINATION"])
cid = os.environ["FAKE_CID"]
image_id = os.environ["FAKE_IMAGE_ID"]

with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args, separators=(",", ":")) + "\n")

def output(value):
    sys.stdout.write(value if isinstance(value, str) else json.dumps(value, separators=(",", ":")))

def container(container_id, status="running"):
    if container_id == cid:
        return [{
            "Id": cid,
            "Name": "/cicada-v2-local-hub-1",
            "Image": image_id,
            "Config": {
                "Image": "cicada-hub:previous",
                "User": "",
                "Labels": {
                    "com.docker.compose.project": project,
                    "com.docker.compose.service": "hub",
                },
            },
            "HostConfig": {"NetworkMode": "host"},
            "State": {"Status": status, "Paused": False, "Restarting": False, "Dead": False},
            "Mounts": [{
                "Type": "volume", "Name": volume, "Source": mountpoint,
                "Destination": "/state", "RW": True,
            }],
        }]
    if container_id == "c" * 64 and os.environ.get("FAKE_EXTRA_CONSUMER") == "1":
        if os.environ.get("FAKE_EXTRA_SUBDIR") == "1":
            mount = {"Type": "bind", "Name": "", "Source": str(pathlib.Path(mountpoint) / "nodes"),
                     "Destination": "/nodes", "RW": True}
        else:
            mount = {"Type": "volume", "Name": volume, "Source": mountpoint,
                     "Destination": "/state", "RW": os.environ.get("FAKE_EXTRA_READONLY") != "1"}
        return [{
            "Id": container_id, "Name": "/other-writer", "Image": image_id,
            "Config": {"Image": "other:local", "Labels": {}},
            "HostConfig": {"NetworkMode": "bridge"},
            "State": {"Status": "running", "Paused": False, "Restarting": False, "Dead": False},
            "Mounts": [mount],
        }]
    raise SystemExit(1)

def manifest():
    paths = ["cicada.sqlite3"]
    if os.environ.get("FAKE_MANIFEST_NODES") == "1":
        paths.append("nodes/node-a/state.json")
    return {
        "format_version": 1,
        "complete": True,
        "created_at": "2026-10-12T00:00:00Z",
        "database": {
            "copy_mode": "offline-byte-copy",
            "sqlite_version": "3.45.0",
            "journal_mode": "wal",
            "integrity_check": "ok", "foreign_key_check": "ok",
            "schema_fingerprint": "f" * 64,
            "checksum": "d" * 64,
            "tables": [{"name": "contacts", "rows": 0}],
        },
        "contacts": {
            "contacts": 0, "peer_sessions": 0, "peer_messages": 0, "replay_sequences": 0,
            "send_sequence_total": 0, "receive_count_total": 0, "send_count_total": 0,
            "contact_digest": "a" * 64, "peer_session_digest": "b" * 64,
            "peer_message_digest": "c" * 64, "digest": "e" * 64,
        },
        "files": [{"path": path, "size": 0, "mode": 384, "sha256": "e" * 64} for path in paths],
    }

if not args:
    raise SystemExit(2)
if args == ["info"] or args[:2] == ["compose", "version"]:
    raise SystemExit(0)
if args[0] == "ps":
    if "-aq" in args:
        if os.environ.get("FAKE_EXISTING", "1") == "1":
            output(cid + "\n")
            if os.environ.get("FAKE_MULTIPLE_PROJECT_CONTAINERS") == "1":
                output("c" * 64 + "\n")
    elif "-q" in args:
        filters = [args[index + 1] for index, item in enumerate(args[:-1]) if item == "--filter"]
        if f"volume={volume}" not in filters:
            if os.environ.get("FAKE_UNRELATED_RUNNING") == "1":
                output("d" * 64 + "\n")
                raise SystemExit(0)
            raise SystemExit(4)
        if os.environ.get("FAKE_EXISTING", "1") == "1" and not (state / "stopped").exists():
            output(cid + "\n")
            if os.environ.get("FAKE_EXTRA_CONSUMER") == "1":
                output("c" * 64 + "\n")
    raise SystemExit(0)
if args[:2] == ["volume", "ls"]:
    if "--filter" in args:
        project_volume_present = os.environ.get(
            "FAKE_PROJECT_VOLUME_PRESENT", "1" if os.environ.get("FAKE_EXISTING", "1") == "1" else "0"
        )
        if project_volume_present == "1":
            output(os.environ.get("FAKE_PROJECT_VOLUME_NAME", volume) + "\n")
    elif os.environ.get("FAKE_VOLUME_PRESENT", "0") == "1":
        output(volume + "\n")
    raise SystemExit(0)
if args[:2] == ["volume", "inspect"]:
    output([{
        "Name": volume,
        "Driver": "local",
        "Mountpoint": mountpoint,
        "Labels": {
            "com.docker.compose.project": project,
            "com.docker.compose.volume": "hub-state",
        },
    }])
    raise SystemExit(0)
if args[:2] == ["image", "inspect"]:
    output([{
        "Id": image_id,
        "Config": {"User": "cicada", "Labels": {"org.cicada.role": "hub"}},
    }])
    raise SystemExit(0)
if args[0] == "inspect":
    container_id = args[1]
    status = "exited" if (state / "stopped").exists() else "running"
    output(container(container_id, status))
    raise SystemExit(0)
if args[0] == "stop":
    if args[-1] != cid:
        raise SystemExit(2)
    if os.environ.get("FAKE_STOP_FAIL") == "1":
        raise SystemExit(1)
    if os.environ.get("FAKE_STOP_REMAINS_RUNNING") == "1":
        raise SystemExit(0)
    (state / "stopped").write_text("stopped\n", encoding="utf-8")
    raise SystemExit(0)
if args[0] == "run":
    if "migration" in args:
        index = args.index("migration")
        command = args[index + 1]
        if command == "backup" and "--state-dir" not in args:
            if os.environ.get("FAKE_CLI_UNSUPPORTED") == "1":
                sys.stderr.write("unknown migration command")
                raise SystemExit(2)
            sys.stderr.write("migration backup requires explicit --state-dir and --output")
            raise SystemExit(2)
        if command == "verify" and "--backup" not in args:
            if os.environ.get("FAKE_CLI_UNSUPPORTED") == "1":
                sys.stderr.write("unknown migration command")
                raise SystemExit(2)
            sys.stderr.write("migration verify requires explicit --backup")
            raise SystemExit(2)
        if command == "backup":
            if os.environ.get("FAKE_BACKUP_FAIL") == "1":
                raise SystemExit(1)
            destination = backup
            destination.mkdir(mode=0o700)
            (destination / "payload").mkdir(mode=0o700)
            value = manifest()
            if os.environ.get("FAKE_DUPLICATE_MANIFEST") == "1":
                (destination / "manifest.json").write_text(
                    '{"format_version":1,"format_version":1}', encoding="utf-8"
                )
            elif os.environ.get("FAKE_OVERSIZE_MANIFEST") == "1":
                (destination / "manifest.json").write_bytes(b" " * (8 * 1024 * 1024 + 1))
            else:
                (destination / "manifest.json").write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
            output(value)
            raise SystemExit(0)
        if command == "verify":
            if os.environ.get("FAKE_VERIFY_FAIL") == "1":
                raise SystemExit(1)
            value = manifest()
            if os.environ.get("FAKE_VERIFY_MISMATCH") == "1":
                value["contacts"]["contacts"] = 1
            output(value)
            raise SystemExit(0)
    if "-c" in args:
        uid = os.environ["FAKE_UID"]
        gid = os.environ["FAKE_GID"]
        output(f"{uid}:{gid}\n{uid}:{gid}:700\n")
        raise SystemExit(0)
    raise SystemExit(2)
if args[0] == "compose":
    if "config" not in args:
        if "up" in args:
            (state / "compose-up").write_text("up\n", encoding="utf-8")
        raise SystemExit(0)
    project_name = args[args.index("-p") + 1]
    if "--format" in args:
        if os.environ.get("FAKE_DUPLICATE_CONFIG") == "1":
            sys.stdout.write('{"name":"cicada-v2-local","name":"cicada-v2-local","services":{},"volumes":{}}')
            raise SystemExit(0)
        if os.environ.get("FAKE_OVERSIZE_CONFIG") == "1":
            sys.stdout.write(" " * (2 * 1024 * 1024 + 1))
            raise SystemExit(0)
        value = {
            "name": project_name,
            "services": {"hub": {
                "image": target_image,
                "network_mode": "host",
                "restart": "unless-stopped",
                "environment": {
                    "CICADA_API_HOST": "127.0.0.1",
                    "CICADA_API_PORT": "8788",
                    "CICADA_STATE_DIR": "/state",
                },
                "volumes": [{"type": "volume", "source": "hub-state", "target": "/state", "read_only": False}],
            }},
            "volumes": {"hub-state": {"name": volume}},
        }
        config_output.write_text(json.dumps(value), encoding="utf-8")
        output(value)
    raise SystemExit(0)
raise SystemExit(2)
'''


class InstallerUpdateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cicada-install-update-")
        self.root = pathlib.Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        fake = self.bin / "docker"
        fake.write_text(FAKE_DOCKER, encoding="utf-8")
        fake.chmod(0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.volume = self.root / "volume"
        self.volume.mkdir(mode=0o700)
        self.backup_parent = self.root / "backups"
        self.backup_parent.mkdir(mode=0o700)
        self.backup = self.backup_parent / "hub-state-backup"
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.log = self.root / "docker.jsonl"
        self.env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", str(self.root)),
            "FAKE_DOCKER_STATE": str(self.state),
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_CONFIG_OUTPUT": str(self.root / "compose-config.json"),
            "FAKE_VOLUME_MOUNTPOINT": str(self.volume),
            "FAKE_BACKUP_DESTINATION": str(self.backup),
            "TMPDIR": str(self.scratch),
            "FAKE_CID": CID,
            "FAKE_IMAGE_ID": IMAGE_ID,
            "FAKE_UID": str(os.getuid()),
            "FAKE_GID": str(os.getgid()),
            "CICADA_HUB_IMAGE": "cicada-hub:next",
            "CICADA_DEPLOY_PROJECT": PROJECT,
            "CICADA_HUB_VOLUME": HUB_VOLUME,
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_installer(self, **updates: str) -> subprocess.CompletedProcess[str]:
        env = dict(self.env)
        env.update(updates)
        env.setdefault("FAKE_EXISTING", "1")
        env.setdefault("FAKE_VOLUME_PRESENT", "1")
        return subprocess.run(
            ["bash", str(INSTALLER)],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def compose_up_calls(self) -> list[list[str]]:
        return [call for call in self.calls() if call[:1] == ["compose"] and "up" in call]

    def mutating_calls(self) -> list[list[str]]:
        calls = []
        compose_mutations = {"up", "down", "run", "create", "start", "stop", "rm", "build"}
        docker_mutations = {"run", "create", "start", "stop", "rm"}
        for call in self.calls():
            if call[:1] == ["compose"] and any(command in call for command in compose_mutations):
                calls.append(call)
            elif call and call[0] in docker_mutations:
                calls.append(call)
            elif call[:2] in (["volume", "create"], ["volume", "rm"]):
                calls.append(call)
        return calls

    def migration_calls(self, name: str) -> list[list[str]]:
        return [call for call in self.calls() if "migration" in call and name in call]

    def test_default_pristine_install_refuses_before_mutation(self) -> None:
        env = {
            "FAKE_EXISTING": "0",
            "FAKE_VOLUME_PRESENT": "0",
            "CICADA_DEPLOY_PROJECT": PROJECT,
        }
        result = self.run_installer(**env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pristine fresh Hub install is not supported", result.stderr)
        self.assertIn("docs/hub-owner-bootstrap.md", result.stderr)
        self.assertEqual(self.mutating_calls(), [])
        self.assertFalse(self.migration_calls("backup"))

    def test_custom_pristine_install_refuses_before_mutation(self) -> None:
        result = self.run_installer(
            FAKE_EXISTING="0",
            FAKE_VOLUME_PRESENT="0",
            CICADA_DEPLOY_PROJECT="hub-check-a",
            CICADA_HUB_VOLUME="",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pristine fresh Hub install is not supported", result.stderr)
        self.assertIn("docs/hub-owner-bootstrap.md", result.stderr)
        self.assertEqual(self.mutating_calls(), [])

    def test_orphan_named_volume_is_not_treated_as_fresh_install(self) -> None:
        result = self.run_installer(FAKE_EXISTING="0", FAKE_VOLUME_PRESENT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("volume exists without a matching project container", result.stderr)
        self.assertFalse(self.compose_up_calls())

    def test_orphan_project_volume_with_different_current_name_blocks_fresh_install(self) -> None:
        result = self.run_installer(
            FAKE_EXISTING="0",
            FAKE_VOLUME_PRESENT="0",
            FAKE_PROJECT_VOLUME_PRESENT="1",
            FAKE_PROJECT_VOLUME_NAME="old-hub-volume",
            CICADA_DEPLOY_PROJECT="isolated-hub",
            CICADA_HUB_VOLUME="isolated-hub-hub-state",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Compose-owned volumes exist without a matching project container", result.stderr)
        self.assertFalse(self.compose_up_calls())

    def test_multiple_project_containers_block_update(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
            FAKE_MULTIPLE_PROJECT_CONTAINERS="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one inspectable container", result.stderr)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_existing_update_requires_a_new_backup_before_stopping(self) -> None:
        result = self.run_installer(CICADA_DEPLOY_UPDATE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires CICADA_HUB_UPDATE_BACKUP", result.stderr)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_verified_backup_precedes_rebuild_and_uses_current_image_id(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
            FAKE_EXTRA_CONSUMER="1",
            FAKE_EXTRA_READONLY="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        stop_index = next(i for i, call in enumerate(calls) if call[:1] == ["stop"])
        backup_index = next(i for i, call in enumerate(calls) if "migration" in call and "backup" in call and "--state-dir" in call)
        verify_index = next(i for i, call in enumerate(calls) if "migration" in call and "verify" in call and "--backup" in call)
        up_index = next(i for i, call in enumerate(calls) if call[:1] == ["compose"] and "up" in call)
        self.assertLess(stop_index, backup_index)
        self.assertLess(backup_index, verify_index)
        self.assertLess(verify_index, up_index)
        backup_call = calls[backup_index]
        verify_call = calls[verify_index]
        self.assertIn(IMAGE_ID, backup_call)
        self.assertIn("--network", backup_call)
        self.assertIn("none", backup_call)
        self.assertIn("--read-only", backup_call)
        self.assertIn("--cap-drop", backup_call)
        self.assertIn("ALL", backup_call)
        backup_mounts = [arg for arg in backup_call if arg.startswith("type=")]
        self.assertCountEqual(backup_mounts, [
            f"type=volume,src={HUB_VOLUME},dst=/state,volume-nocopy",
            f"type=bind,src={self.backup_parent},dst=/backup",
        ])
        verify_mounts = [arg for arg in verify_call if arg.startswith("type=")]
        self.assertEqual(verify_mounts, [f"type=bind,src={self.backup_parent},dst=/backup,readonly"])
        self.assertNotIn("cicada-hub:next", backup_call)
        self.assertTrue((self.backup / "manifest.json").is_file())
        self.assertFalse(any(call[:2] == ["volume", "rm"] for call in calls))
        self.assertIn("Existing Hub state confirmed: exited", result.stdout)
        self.assertIn("Hub backup manifest SHA-256:", result.stdout)
        helper_calls = [call for call in calls if call[:1] == ["run"]]
        run_labels = {
            call[index + 1]
            for call in helper_calls
            for index, value in enumerate(call[:-1])
            if value == "--label" and call[index + 1].startswith("org.cicada.update-run=")
        }
        self.assertEqual(len(run_labels), 1)
        self.assertTrue(all("org.cicada.update-helper=1" in call for call in helper_calls))
        self.assertTrue(all(f"org.cicada.update-project={PROJECT}" in call for call in helper_calls))
        self.assertIn(next(iter(run_labels)).split("=", 1)[1], result.stdout)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_volume_candidate_filter_never_inspects_unrelated_running_containers(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
            FAKE_UNRELATED_RUNNING="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        candidate_queries = [call for call in calls if call[:2] == ["ps", "-q"]]
        self.assertTrue(candidate_queries)
        self.assertTrue(all("--filter" in call and f"volume={HUB_VOLUME}" in call for call in candidate_queries))
        inspected = [call[1] for call in calls if call[:1] == ["inspect"] and len(call) > 1]
        self.assertNotIn(UNRELATED_CID, inspected)
        self.assertIn(CID, inspected)

    def test_failed_backup_or_verify_never_rebuilds(self) -> None:
        cases = (
            {"FAKE_BACKUP_FAIL": "1"},
            {"FAKE_VERIFY_FAIL": "1"},
            {"FAKE_VERIFY_MISMATCH": "1"},
        )
        for options in cases:
            with self.subTest(options=options):
                self.state.joinpath("stopped").unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                if self.backup.exists():
                    shutil.rmtree(self.backup)
                result = self.run_installer(
                    CICADA_DEPLOY_UPDATE="1",
                    CICADA_HUB_UPDATE_BACKUP=str(self.backup),
                    **options,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.compose_up_calls())
                self.assertFalse(any(call[:2] == ["volume", "rm"] for call in self.calls()))
                self.assertEqual(list(self.scratch.iterdir()), [])

    def test_other_running_exact_volume_read_write_consumer_blocks_before_stop(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
            FAKE_EXTRA_CONSUMER="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another running read-write container", result.stderr)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_failed_or_unconfirmed_stop_blocks_backup_and_rebuild(self) -> None:
        for options in ({"FAKE_STOP_FAIL": "1"}, {"FAKE_STOP_REMAINS_RUNNING": "1"}):
            with self.subTest(options=options):
                self.log.unlink(missing_ok=True)
                self.state.joinpath("stopped").unlink(missing_ok=True)
                result = self.run_installer(
                    CICADA_DEPLOY_UPDATE="1",
                    CICADA_HUB_UPDATE_BACKUP=str(self.backup),
                    **options,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any("--state-dir" in call for call in self.migration_calls("backup")))
                self.assertFalse(self.compose_up_calls())

    def test_existing_backup_destination_blocks_before_stop(self) -> None:
        self.backup.mkdir(mode=0o700)
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_nonprivate_or_symlink_backup_parent_blocks_before_stop(self) -> None:
        self.backup_parent.chmod(0o755)
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

        self.backup_parent.chmod(0o700)
        self.log.unlink(missing_ok=True)
        linked_parent = self.root / "linked-backups"
        linked_parent.symlink_to(self.backup_parent, target_is_directory=True)
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(linked_parent / "new-state-backup"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_private_ancestor_parent_is_allowed_when_backup_does_not_overlap_source(self) -> None:
        destination = self.root / "backup-next-to-volume"
        self.assertFalse(destination.exists())
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(destination),
            FAKE_BACKUP_DESTINATION=str(destination),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / "manifest.json").is_file())

    def test_backup_path_mount_encoding_blocks_before_stop(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup_parent / "bad,name"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_unsupported_cli_blocks_before_stop(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
            FAKE_CLI_UNSUPPORTED="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
        self.assertFalse(self.compose_up_calls())

    def test_backup_manifest_cannot_claim_node_state(self) -> None:
        result = self.run_installer(
            CICADA_DEPLOY_UPDATE="1",
            CICADA_HUB_UPDATE_BACKUP=str(self.backup),
            FAKE_MANIFEST_NODES="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not match a complete supported Hub backup", result.stderr)
        self.assertFalse(self.compose_up_calls())

    def test_duplicate_or_oversized_compose_metadata_blocks_before_stop(self) -> None:
        for option in ("FAKE_DUPLICATE_CONFIG", "FAKE_OVERSIZE_CONFIG"):
            with self.subTest(option=option):
                self.log.unlink(missing_ok=True)
                result = self.run_installer(
                    CICADA_DEPLOY_UPDATE="1",
                    CICADA_HUB_UPDATE_BACKUP=str(self.backup),
                    **{option: "1"},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[:1] == ["stop"] for call in self.calls()))
                self.assertFalse(self.compose_up_calls())

    def test_duplicate_or_oversized_manifest_blocks_rebuild(self) -> None:
        for option in ("FAKE_DUPLICATE_MANIFEST", "FAKE_OVERSIZE_MANIFEST"):
            with self.subTest(option=option):
                self.state.joinpath("stopped").unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                if self.backup.exists():
                    shutil.rmtree(self.backup)
                result = self.run_installer(
                    CICADA_DEPLOY_UPDATE="1",
                    CICADA_HUB_UPDATE_BACKUP=str(self.backup),
                    **{option: "1"},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.compose_up_calls())

    def test_manifest_validator_matches_go_state_backup_json_tags_and_cli_errors(self) -> None:
        source = BACKUP_SOURCE.read_text(encoding="utf-8")
        cli = BACKUP_CLI_SOURCE.read_text(encoding="utf-8")
        expected_tags = {
            "StateBackupFile": ("path", "size", "mode", "sha256"),
            "StateBackupTable": ("name", "rows"),
            "StateBackupDatabase": (
                "copy_mode", "sqlite_version", "journal_mode", "integrity_check", "foreign_key_check",
                "schema_fingerprint", "checksum", "tables",
            ),
            "StateBackupContacts": (
                "contacts", "peer_sessions", "peer_messages", "replay_sequences", "send_sequence_total",
                "receive_count_total", "send_count_total", "contact_digest", "peer_session_digest",
                "peer_message_digest", "digest",
            ),
            "StateBackupManifest": ("format_version", "complete", "created_at", "database", "contacts", "files"),
        }
        for struct, tags in expected_tags.items():
            match = re.search(rf"type {struct} struct \{{(.*?)\n\}}", source, re.DOTALL)
            self.assertIsNotNone(match, struct)
            declared = match.group(1)
            for tag in tags:
                with self.subTest(struct=struct, tag=tag):
                    self.assertRegex(declared, rf'`json:"{tag}"`')
        self.assertIn("migration backup requires explicit --state-dir and --output", cli)
        self.assertIn("migration verify requires explicit --backup", cli)
        self.assertIn('CopyMode:          "offline-byte-copy"', source)

    def test_json_checker_rejects_duplicate_and_oversized_documents(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"name":"one","name":"two"}', encoding="utf-8")
        args = ["python3", str(CHECKER), "compose", str(duplicate), PROJECT, HUB_VOLUME, "cicada-hub:next", "8788"]
        self.assertNotEqual(subprocess.run(args, capture_output=True, check=False).returncode, 0)

        oversized = self.root / "oversized.json"
        oversized.write_bytes(b" " * (2 * 1024 * 1024 + 1))
        args[3] = str(oversized)
        self.assertNotEqual(subprocess.run(args, capture_output=True, check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
