#!/usr/bin/env python3
"""Tests for the data-only Hub build-input inventory and source-only path."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
HELPER_PATH = ROOT / "scripts" / "hub-build-input-inventory.py"
BUILD_SCRIPT = ROOT / "scripts" / "build-hub-image.sh"
SPEC = importlib.util.spec_from_file_location("hub_build_input_inventory", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


class BuildInputInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cicada-build-input-inventory-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name) / "repo"
        self.root.mkdir()
        self._make_repository()

    def _run_git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"git {' '.join(arguments)} failed: {result.stderr}")
        return result

    def _write(self, relative: str, content: bytes, mode: int = 0o644):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def _make_repository(self):
        self._write("cicada-go/internal/clientcontract/catalog.json", b'{"revision":"synthetic"}\n')
        self._write("cicada-go/tracked.txt", b"tracked source\n")
        self._write("cicada-go/delete-me.txt", b"will be deleted\n")
        executable = self._write("cicada-go/tool.sh", b"#!/bin/sh\nexit 0\n", 0o755)
        del executable
        self._write("docker/Dockerfile.hub", b"FROM scratch\n")
        self._write(".dockerignore", b".cicada-data\n")
        self._write("scripts/build-web-panel.sh", b"#!/bin/sh\nexit 0\n", 0o755)
        self._write("scripts/write-web-panel-manifest.py", b"# synthetic\n")
        self._write(".github/workflows/release.yml", b"name: synthetic\n")
        for relative in ("scripts/build-hub-image.sh", "scripts/hub-build-input-inventory.py"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        (self.root / "cicada-go/link.txt").symlink_to("tracked.txt")

        self._run_git("init", "-q")
        self._run_git("add", "--all")
        self._run_git(
            "-c",
            "user.name=Inventory Test",
            "-c",
            "user.email=inventory@example.invalid",
            "commit",
            "-qm",
            "synthetic input fixture",
        )

    def _entries(self, manifest):
        return {entry["path"]: entry for entry in manifest["entries"]}

    def test_inventory_fingerprint_reproduces_from_captured_bytes_and_modes(self):
        manifest = INVENTORY.capture(self.root)
        entries = self._entries(manifest)
        self.assertEqual(manifest["schema_version"], "cicada.hub-build-input-inventory.v1")
        self.assertEqual(manifest["fingerprint"]["algorithm"], "sha256")
        self.assertEqual(
            manifest["fingerprint"]["domain_hex"],
            "6369636164612d6875622d6275696c642d696e7075742d696e76656e746f72792d763100",
        )

        regular = entries["cicada-go/tracked.txt"]
        regular_bytes = (self.root / regular["path"]).read_bytes()
        actual_mode = (self.root / regular["path"]).lstat().st_mode
        self.assertEqual(regular["file_type"], "regular")
        self.assertEqual(regular["raw_mode"], f"0o{actual_mode:o}")
        self.assertEqual(bytes.fromhex(regular["path_bytes_hex"]), os.fsencode(regular["path"]))
        self.assertEqual(regular["size_bytes"], len(regular_bytes))
        self.assertEqual(regular["content_sha256"], hashlib.sha256(regular_bytes).hexdigest())
        self.assertEqual(regular["git_index"]["mode"], "100644")

        executable = entries["cicada-go/tool.sh"]
        self.assertEqual(executable["git_index"]["mode"], "100755")
        symlink = entries["cicada-go/link.txt"]
        link_bytes = os.fsencode(os.readlink(self.root / symlink["path"]))
        self.assertEqual(symlink["file_type"], "symlink")
        self.assertEqual(symlink["content_sha256"], hashlib.sha256(link_bytes).hexdigest())
        self.assertEqual(symlink["size_bytes"], len(link_bytes))
        self.assertEqual(symlink["git_index"]["mode"], "120000")

        payload = {
            "entries": manifest["entries"],
            "implementation": manifest["implementation"],
            "source_fingerprint_v4": manifest["source_fingerprint_v4"],
            "scope": manifest["scope"],
        }
        canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        independently_reproduced = hashlib.sha256(
            b"cicada-hub-build-input-inventory-v1\0" + canonical
        ).hexdigest()
        self.assertEqual(manifest["fingerprint"]["sha256"], independently_reproduced)

        v4 = hashlib.sha256(bytes.fromhex(manifest["source_fingerprint_v4"]["domain_hex"]))
        for entry in manifest["entries"]:
            if entry["file_type"] == "missing":
                continue
            path_bytes = bytes.fromhex(entry["path_bytes_hex"])
            self.assertEqual(path_bytes, os.fsencode(entry["path"]))
            v4.update(len(path_bytes).to_bytes(8, "big"))
            v4.update(path_bytes)
            v4.update(stat.S_IMODE(int(entry["raw_mode"], 8)).to_bytes(4, "big"))
            v4.update(bytes.fromhex(entry["content_sha256"]))
        self.assertEqual(manifest["source_fingerprint_v4"]["algorithm"], "sha256")
        self.assertEqual(
            manifest["source_fingerprint_v4"]["domain_hex"],
            "6369636164612d6875622d6275696c642d696e707574732d763400",
        )
        self.assertEqual(manifest["source_fingerprint_v4"]["sha256"], v4.hexdigest())
        self.assertEqual(
            manifest["implementation"]["sha256"],
            hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(),
        )

    def test_raw_mode_change_is_visible_even_when_git_stays_clean(self):
        target = self.root / "cicada-go/tracked.txt"
        before = INVENTORY.capture(self.root)
        self.assertEqual(self._run_git("status", "--porcelain").stdout, "")

        target.chmod(0o664)
        after = INVENTORY.capture(self.root)

        self.assertEqual(self._run_git("status", "--porcelain").stdout, "")
        before_entry = self._entries(before)["cicada-go/tracked.txt"]
        after_entry = self._entries(after)["cicada-go/tracked.txt"]
        self.assertNotEqual(before["fingerprint"]["sha256"], after["fingerprint"]["sha256"])
        self.assertNotEqual(
            before["source_fingerprint_v4"]["sha256"],
            after["source_fingerprint_v4"]["sha256"],
        )
        self.assertNotEqual(before_entry["raw_mode"], after_entry["raw_mode"])
        self.assertEqual(before_entry["content_sha256"], after_entry["content_sha256"])
        self.assertEqual(after_entry["git_index"]["mode"], "100644")

    def test_tracked_deletion_and_untracked_input_are_inventory_rows(self):
        (self.root / "cicada-go/delete-me.txt").unlink()
        self._write("cicada-go/untracked.txt", b"new local source\n")

        manifest = INVENTORY.capture(self.root)
        entries = self._entries(manifest)

        self.assertEqual(entries["cicada-go/delete-me.txt"]["file_type"], "missing")
        self.assertIsNone(entries["cicada-go/delete-me.txt"]["raw_mode"])
        self.assertIsNone(entries["cicada-go/delete-me.txt"]["content_sha256"])
        self.assertEqual(entries["cicada-go/untracked.txt"]["file_type"], "regular")
        self.assertNotIn("git_index", entries["cicada-go/untracked.txt"])

    def test_verify_rejects_a_changed_current_snapshot(self):
        expected = INVENTORY.capture(self.root)
        INVENTORY.verify(self.root, expected)
        (self.root / "cicada-go/tracked.txt").write_bytes(b"changed after capture\n")

        with self.assertRaises(INVENTORY.InventoryError):
            INVENTORY.verify(self.root, expected)

    def test_source_info_only_emits_additive_private_inventory_without_docker(self):
        output = self.root.parent / "source-info.json"
        minimal_bin = self.root.parent / "source-only-bin"
        minimal_bin.mkdir()
        for command in ("bash", "git", "python3", "sha256sum", "mktemp", "chmod", "cut", "dirname", "rm"):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"missing test command: {command}")
            (minimal_bin / command).symlink_to(executable)
        environment = os.environ.copy()
        environment["PATH"] = str(minimal_bin)
        result = subprocess.run(
            ["bash", str(self.root / "scripts/build-hub-image.sh"), "--source-info-only", "--metadata-file", str(output)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        metadata = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(metadata["schema_version"], "cicada.hub-build-source.v1")
        source = metadata["source"]
        self.assertTrue({"revision", "dirty", "source_fingerprint", "catalog_sha256"}.issubset(source))
        self.assertFalse(source["dirty"])
        self.assertEqual(source["input_inventory"]["schema_version"], "cicada.hub-build-input-inventory.v1")
        self.assertEqual(
            source["input_inventory"]["fingerprint"]["sha256"],
            INVENTORY.capture(self.root)["fingerprint"]["sha256"],
        )
        self.assertEqual(
            source["source_fingerprint"],
            source["input_inventory"]["source_fingerprint_v4"]["sha256"],
        )
        self.assertNotIn(b"tracked source", output.read_bytes())

    def test_image_metadata_carries_inventory_and_build_mutation_is_rejected(self):
        bin_dir = self.root.parent / "bin"
        bin_dir.mkdir()
        fake_docker = bin_dir / "docker"
        fake_docker.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "iid = pathlib.Path(args[args.index('--iidfile') + 1])\n"
            "iid.write_text('sha256:synthetic-image-id\\n', encoding='ascii')\n"
            "mutation = os.environ.get('CICADA_TEST_MUTATE')\n"
            "if mutation:\n"
            "    pathlib.Path(mutation).write_bytes(b'mutated during build\\n')\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
        environment["CICADA_BUILD_PROXY"] = ""
        metadata_path = self.root.parent / "image-metadata.json"
        result = subprocess.run(
            [
                "bash",
                str(self.root / "scripts/build-hub-image.sh"),
                "--metadata-file",
                str(metadata_path),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(metadata_path.stat().st_mode), 0o600)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["schema_version"], "cicada.hub-build.v1")
        self.assertEqual(metadata["image"]["id"], "sha256:synthetic-image-id")
        self.assertEqual(
            metadata["source"]["input_inventory"]["fingerprint"]["sha256"],
            INVENTORY.capture(self.root)["fingerprint"]["sha256"],
        )
        self.assertEqual(
            metadata["source"]["source_fingerprint"],
            metadata["source"]["input_inventory"]["source_fingerprint_v4"]["sha256"],
        )

        mutation_path = self.root / "cicada-go/tracked.txt"
        rejected_metadata = self.root.parent / "rejected-image-metadata.json"
        environment["CICADA_TEST_MUTATE"] = str(mutation_path)
        rejected = subprocess.run(
            [
                "bash",
                str(self.root / "scripts/build-hub-image.sh"),
                "--metadata-file",
                str(rejected_metadata),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("source changed during the Docker build", rejected.stderr)
        self.assertFalse(rejected_metadata.exists())


if __name__ == "__main__":
    unittest.main()
