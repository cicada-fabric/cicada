"""Execute the Group-key fixture metadata gate without a Docker daemon."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import secrets
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/client-group-key-fixture.sh"
CATALOG = ROOT / "cicada-go/internal/clientcontract/catalog.json"


class ClientGroupKeyFixtureTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cicada-group-key-parser-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "docker-calls.jsonl"
        # PATH contains only these executables. No real Docker can be called,
        # including if a future regression tries to continue past `info`.
        for name in ("bash", "python3", "dirname", "uname", "sha256sum", "basename", "tr"):
            target = shutil.which(name)
            self.assertIsNotNone(target, name)
            (self.bin / name).symlink_to(target)
        docker = self.bin / "docker"
        docker.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, sys\n"
            "with open(os.environ['FIXTURE_TEST_DOCKER_CALLS'], 'a') as out:\n"
            "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "raise SystemExit(91)\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.catalog_bytes = CATALOG.read_bytes()
        self.metadata = {
            "schema_version": "cicada.hub-build.v1",
            "source": {
                "revision": "a" * 40,
                "dirty": False,
                "source_fingerprint": "b" * 64,
                "catalog_sha256": hashlib.sha256(self.catalog_bytes).hexdigest(),
            },
            "image": {
                "reference": "cicada-synthetic-parser-test:fixed",
                "id": "sha256:" + "c" * 64,
                "dockerfile": "docker/Dockerfile.hub",
            },
        }
        self.metadata_path = self.root / "build.json"
        self.controlled_script = self.root / "repo/scripts/client-group-key-fixture.sh"
        self.controlled_script.parent.mkdir(parents=True)
        self.controlled_script.write_bytes(SCRIPT.read_bytes())
        self.controlled_catalog = (
            self.root / "repo/cicada-go/internal/clientcontract/catalog.json"
        )
        self.controlled_catalog.parent.mkdir(parents=True)

    def run_gate(self, metadata=None, *, revision=None, symlink=False):
        self.calls.unlink(missing_ok=True)
        data = copy.deepcopy(self.metadata if metadata is None else metadata)
        script = SCRIPT
        if revision is not None:
            catalog = json.loads(self.catalog_bytes)
            catalog["contract_revision"] = revision
            raw = (json.dumps(catalog) + "\n").encode()
            self.controlled_catalog.write_bytes(raw)
            build = data.get("build", data)
            build["source"]["catalog_sha256"] = hashlib.sha256(raw).hexdigest()
            script = self.controlled_script
        self.metadata_path.write_text(json.dumps(data), encoding="utf-8")
        path = self.metadata_path
        if symlink:
            path = self.root / "symlink-build.json"
            path.symlink_to(self.metadata_path)
        result = subprocess.run(
            [str(self.bin / "bash"), str(script), "start", "--build-metadata", str(path)],
            cwd=self.root,
            env={"PATH": str(self.bin), "HOME": str(self.root), "LANG": "C.UTF-8",
                 "FIXTURE_TEST_DOCKER_CALLS": str(self.calls)},
            text=True, capture_output=True, timeout=10, check=False,
        )
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        self.assertEqual(CATALOG.read_bytes(), self.catalog_bytes)
        return result, calls

    def assert_parser_accepted(self, **kwargs):
        result, calls = self.run_gate(**kwargs)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("BLOCKED: Docker daemon unavailable", result.stderr)
        self.assertEqual(calls, [["info"]])

    def assert_parser_refused(self, **kwargs):
        result, calls = self.run_gate(**kwargs)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("BLOCKED:", result.stderr)
        self.assertNotIn("Docker daemon unavailable", result.stderr)
        self.assertEqual(calls, [])

    def test_current_authoritative_catalog_reaches_only_docker_info(self):
        self.assert_parser_accepted()

    def test_supported_canonical_revision_boundaries(self):
        for revision in ("client-hub-v1.3", "client-hub-v1.3.0", "client-hub-v1.6.5",
                         "client-hub-v1.9.1", "client-hub-v1.10", "client-hub-v1.10.12"):
            with self.subTest(revision=revision):
                self.assert_parser_accepted(revision=revision)

    def test_unsupported_or_noncanonical_revisions_refused_before_docker(self):
        for revision in ("client-hub-v1.2.1", "client-hub-v1.2.999", "client-hub-v2.3",
                         "client-hub-v1.03", "client-hub-v1.6.05", "client-hub-v1.6.",
                         "client-hub-v1.6.5.1", "client-hub-v1.6.5-dev", "client-hub-v1.6.5\n",
                         "client-hub-v1.6.5+build"):
            with self.subTest(revision=revision):
                self.assert_parser_refused(revision=revision)

    def test_invalid_source_or_image_refused_before_docker(self):
        cases = (("source", "dirty", True), ("source", "dirty", None),
                 ("source", "catalog_sha256", "0" * 64),
                 ("source", "revision", "short"), ("source", "source_fingerprint", "short"),
                 ("image", "id", "cicada:latest"), ("image", "id", "sha256:" + "c" * 63),
                 ("image", "reference", "cicada:latest"),
                 ("image", "dockerfile", "docker/other"))
        for section, field, value in cases:
            with self.subTest(section=section, field=field, value=value):
                data = copy.deepcopy(self.metadata)
                data[section][field] = value
                self.assert_parser_refused(metadata=data)

    def test_symlink_metadata_refused_before_docker(self):
        self.assert_parser_refused(symlink=True)

    def test_completed_interop_metadata_only(self):
        wrapped = {"schema_version": "cicada.client-hub-interop.v1", "status": "PASS",
                   "phase": "complete", "exit_code": 0, "build": self.metadata}
        self.assert_parser_accepted(metadata=wrapped)
        for field, value in (("status", "FAIL"), ("phase", "build"),
                             ("exit_code", 1), ("exit_code", False)):
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(wrapped)
                data[field] = value
                self.assert_parser_refused(metadata=data)

    def private_fixture(self):
        # Same direct, private path shape as the real tool. This contains only
        # synthetic public marker data and a deletion sentinel, never credentials.
        root = Path("/tmp") / ("cgk." + secrets.token_hex(4))
        root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        hub = "cicada-cgk-" + root.name.replace(".", "").lower() + "-hub"
        marker = {"schema": "cicada.client-group-key-fixture.v1", "fixture_dir": str(root),
                  "hub_container": hub, "image_id": self.metadata["image"]["id"],
                  "source_revision": self.metadata["source"]["revision"],
                  "catalog_sha256": self.metadata["source"]["catalog_sha256"],
                  "source_fingerprint": self.metadata["source"]["source_fingerprint"],
                  "source_dirty": False, "contract_revision": "client-hub-v1.6.5",
                  "provenance_labels": True}
        path = root / ".cicada-client-group-key-fixture.json"
        path.write_text(json.dumps(marker))
        path.chmod(0o600)
        (root / "state-sentinel").write_text("synthetic disposable test state")
        return root, marker

    def cleanup_docker(self, root, marker, *, wrong_labels=False, stop_failed=False,
                       rm_failed=False, inspect_unknown=False, extract=False,
                       stop_delay_polls=0, stop_present=False, post_stop_unknown=False):
        config = self.root / "docker-config.json"
        data = {"hub": marker["hub_container"], "extract": "d" * 64 if extract else "",
                "image": marker["image_id"], "revision": marker["source_revision"],
                "catalog": marker["catalog_sha256"], "fingerprint": marker["source_fingerprint"],
                "root": str(root), "wrong_labels": wrong_labels, "stop_failed": stop_failed,
                "rm_failed": rm_failed, "inspect_unknown": inspect_unknown, "removed": [],
                "stop_delay_polls": stop_delay_polls, "stop_present": stop_present,
                "post_stop_unknown": post_stop_unknown, "stopped": False}
        config.write_text(json.dumps(data))
        (self.bin / "docker").write_text(
            "#!" + sys.executable + "\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['FIXTURE_TEST_DOCKER_CALLS'], 'a') as out:\n"
            "    out.write(json.dumps(args) + '\\n')\n"
            "path = os.environ['FIXTURE_TEST_DOCKER_CONFIG']\n"
            "with open(path) as source: c = json.load(source)\n"
            "if args[:2] == ['container', 'inspect']:\n"
            "    name = args[2]\n"
            "    target = c['hub'] if name == 'e'*64 else name\n"
            "    if c['inspect_unknown'] or (c['stopped'] and c['post_stop_unknown']):\n"
            "        print('Docker daemon unavailable', file=sys.stderr); sys.exit(1)\n"
            "    if c['stopped'] and target == c['hub'] and not c['stop_present'] and target not in c['removed']:\n"
            "        if c['stop_delay_polls'] > 0: c['stop_delay_polls'] -= 1\n"
            "        else: c['removed'].append(target)\n"
            "        with open(path, 'w') as out: json.dump(c, out)\n"
            "    if target in c['removed'] or target not in (c['hub'], c['extract']):\n"
            "        print('[]'); print('Error response from daemon: No such container: ' + name, file=sys.stderr); sys.exit(1)\n"
            "    labels = {'org.cicada.fixture': 'client-group-key', 'org.cicada.fixture.dir': c['root'],\n"
            "      'org.cicada.role':'hub', 'org.opencontainers.image.revision':c['revision'],\n"
            "      'org.cicada.build.dirty':'false', 'org.cicada.client-catalog.sha256':c['catalog'],\n"
            "      'org.cicada.build.source-fingerprint':c['fingerprint'],\n"
            "      'org.cicada.fixture.source.revision':c['revision'], 'org.cicada.fixture.catalog.sha256':c['catalog']}\n"
            "    if c['wrong_labels']: labels['org.cicada.fixture.dir'] = '/unrelated'\n"
            "    print(json.dumps([{'Id':'e'*64 if target == c['hub'] else target,'Name':'/'+target,'Image':c['image'],'Config':{'Labels':labels}}])); sys.exit(0)\n"
            "if args[:3] == ['stop', '--time', '10'] or args[:2] == ['container', 'rm']:\n"
            "    name = args[-1]\n"
            "    if (args[0]=='stop' and c['stop_failed']) or (args[0]=='container' and c['rm_failed']): sys.exit(91)\n"
            "    if args[0]=='stop': c['stopped'] = True\n"
            "    else: c['removed'].append(name)\n"
            "    with open(path, 'w') as out: json.dump(c, out)\n"
            "    sys.exit(0)\n"
            "sys.exit(91)\n", encoding="utf-8")
        return config, data["extract"]

    def run_cleanup(self, root, marker, *, failure=False, conditional=False, **faults):
        self.calls.unlink(missing_ok=True)
        config, extract = self.cleanup_docker(root, marker, **faults)
        env = {"PATH": str(self.bin), "HOME": str(self.root), "LANG": "C.UTF-8",
               "FIXTURE_TEST_DOCKER_CALLS": str(self.calls),
               "FIXTURE_TEST_DOCKER_CONFIG": str(config)}
        if failure:
            # Execute the exact shell definitions, ending before CLI dispatch.
            # Calling under `if` recreates Bash's errexit suppression regression.
            prefix, boundary, _ = SCRIPT.read_text().partition("\nif [[ $# -lt 1 ]]; then\n")
            self.assertTrue(boundary)
            variables = {"fixture_dir": str(root), "hub_container": marker["hub_container"],
                         "image_id": marker["image_id"], "expected_revision": marker["source_revision"],
                         "expected_catalog": marker["catalog_sha256"],
                         "expected_source_fingerprint": marker["source_fingerprint"],
                         "require_provenance_labels": "true", "extract_id": extract}
            body = "\n".join(k + "=" + shlex.quote(v) for k, v in variables.items())
            body += "\nif start_failure_cleanup 41; then exit 0; else exit $?; fi\n"
            actual = self.root / "actual-functions.sh"
            actual.write_text(prefix + "\n" + body)
            argv = [str(self.bin / "bash"), str(actual)]
        elif conditional:
            prefix, boundary, _ = SCRIPT.read_text().partition("\nif [[ $# -lt 1 ]]; then\n")
            self.assertTrue(boundary)
            actual = self.root / "actual-functions.sh"
            actual.write_text(prefix + "\nif stop_fixture " + shlex.quote(str(root))
                              + "; then exit 0; else exit $?; fi\n")
            argv = [str(self.bin / "bash"), str(actual)]
        else:
            argv = [str(self.bin / "bash"), str(SCRIPT), "stop", str(root)]
        result = subprocess.run(argv, cwd=self.root, env=env, text=True,
                                capture_output=True, timeout=10, check=False)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return result, calls

    def test_failure_cleanup_wrong_owner_never_stops_and_retains_state(self):
        root, marker = self.private_fixture()
        result, calls = self.run_cleanup(root, marker, failure=True, wrong_labels=True)
        self.assertEqual(result.returncode, 41)
        self.assertIn("UNKNOWN/INCOMPLETE", result.stderr)
        self.assertTrue((root / "state-sentinel").is_file())
        self.assertFalse(any(call[0] == "stop" for call in calls))

    def test_failed_stop_or_unknown_inspect_retains_state(self):
        for fault in ("stop_failed", "inspect_unknown"):
            for failure in (False, True):
                with self.subTest(fault=fault, failure=failure):
                    root, marker = self.private_fixture()
                    result, calls = self.run_cleanup(root, marker, failure=failure, **{fault: True})
                    self.assertEqual(result.returncode, 41 if failure else 2)
                    self.assertIn("UNKNOWN/INCOMPLETE", result.stderr)
                    self.assertTrue((root / "state-sentinel").is_file())
                    if fault == "inspect_unknown":
                        self.assertFalse(any(call[0] == "stop" for call in calls))

    def test_failed_extraction_remove_retains_state(self):
        root, marker = self.private_fixture()
        result, calls = self.run_cleanup(root, marker, failure=True, extract=True, rm_failed=True)
        self.assertEqual(result.returncode, 41)
        self.assertIn("UNKNOWN/INCOMPLETE", result.stderr)
        self.assertTrue((root / "state-sentinel").is_file())
        self.assertIn(["container", "rm", "d" * 64], calls)

    def test_successful_owned_cleanup_removes_only_its_temp_state(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                root, marker = self.private_fixture()
                result, calls = self.run_cleanup(root, marker, failure=failure, extract=failure)
                self.assertEqual(result.returncode, 41 if failure else 0, result.stderr)
                self.assertFalse(root.exists())
                self.assertIn(["stop", "--time", "10", "e" * 64], calls)
                self.assertTrue(self.root.exists())

    def test_conditional_stop_refuses_foreign_owner_without_state_deletion(self):
        root, marker = self.private_fixture()
        result, calls = self.run_cleanup(root, marker, conditional=True, wrong_labels=True)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(root.exists())
        self.assertFalse(any(call[0] == "stop" for call in calls))

    def test_delayed_autoremove_waits_for_exact_id_before_deleting_state(self):
        root, marker = self.private_fixture()
        result, calls = self.run_cleanup(root, marker, stop_delay_polls=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(root.exists())
        stop_at = calls.index(["stop", "--time", "10", "e" * 64])
        self.assertEqual(calls[stop_at + 1:], [["container", "inspect", "e" * 64]] * 3)

    def test_stop_zero_but_container_remains_retains_state_on_timeout(self):
        root, marker = self.private_fixture()
        result, calls = self.run_cleanup(root, marker, stop_present=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("removal timed out", result.stderr)
        self.assertIn("UNKNOWN/INCOMPLETE", result.stderr)
        self.assertTrue((root / "state-sentinel").is_file())
        self.assertIn(["stop", "--time", "10", "e" * 64], calls)

    def test_unknown_inspect_after_stop_does_not_wait_or_delete_state(self):
        root, marker = self.private_fixture()
        result, calls = self.run_cleanup(root, marker, post_stop_unknown=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("absence is unconfirmed", result.stderr)
        self.assertIn("UNKNOWN/INCOMPLETE", result.stderr)
        self.assertTrue((root / "state-sentinel").is_file())
        stop_at = calls.index(["stop", "--time", "10", "e" * 64])
        self.assertEqual(calls[stop_at + 1:], [["container", "inspect", "e" * 64]])

    def test_invalid_private_paths_refused_before_docker(self):
        for fault in ("root_mode", "marker_mode", "root_symlink", "marker_symlink", "alias", "bad_name"):
            with self.subTest(fault=fault):
                root, marker = self.private_fixture()
                target = root
                marker_path = root / ".cicada-client-group-key-fixture.json"
                if fault == "root_mode":
                    root.chmod(0o755)
                elif fault == "marker_mode":
                    marker_path.chmod(0o644)
                elif fault == "root_symlink":
                    target = Path("/tmp") / ("cgk." + secrets.token_hex(4))
                    target.symlink_to(root)
                    self.addCleanup(target.unlink, missing_ok=True)
                elif fault == "marker_symlink":
                    regular = root / "regular-marker"
                    marker_path.rename(regular)
                    marker_path.symlink_to(regular)
                elif fault == "alias":
                    target = str(root) + "/../" + root.name
                else:
                    target = self.root
                result, calls = self.run_cleanup(target, marker, conditional=True)
                self.assertEqual(result.returncode, 2)
                self.assertTrue(root.exists())
                self.assertEqual(calls, [])
                if fault == "root_symlink":
                    target.unlink()


if __name__ == "__main__":
    unittest.main()
