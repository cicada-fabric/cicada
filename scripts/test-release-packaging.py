#!/usr/bin/env python3
"""Focused local checks for binary release assets and the Node installer modes."""

import os
import pathlib
import gzip
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import tarfile
import urllib.error
import urllib.request
import unittest
import importlib.util
import shutil
import stat
import struct
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts" / "install-cicada-worker.sh"
if len(sys.argv) == 2 and sys.argv[1] not in {"-h", "--help"}:
    os.environ["CICADA_RELEASE_ARTIFACT_DIR"] = sys.argv.pop()


def synthetic_elf64(machine: int, interpreter: str, needed: tuple[str, ...], runpath: str) -> bytes:
    """Return a tiny marked synthetic ELF metadata fixture; it cannot execute."""
    strings = bytearray(b"\0")
    offsets = {}
    for value in (*needed, runpath):
        offsets[value] = len(strings)
        strings.extend(value.encode() + b"\0")
    dynamic = bytearray()
    for value in needed:
        dynamic.extend(struct.pack("<QQ", 1, offsets[value]))  # DT_NEEDED
    dynamic.extend(struct.pack("<QQ", 5, 0))  # DT_STRTAB, patched below
    dynamic.extend(struct.pack("<QQ", 10, len(strings)))  # DT_STRSZ
    dynamic.extend(struct.pack("<QQ", 29, offsets[runpath]))  # DT_RUNPATH
    dynamic.extend(struct.pack("<QQ", 0, 0))
    phoff, phentsize, phnum = 64, 56, 3
    interp_offset = phoff + phentsize * phnum
    interp = interpreter.encode() + b"\0"
    dyn_offset = (interp_offset + len(interp) + 15) & ~15
    str_offset = dyn_offset + len(dynamic)
    dynamic[16 * len(needed) + 8:16 * len(needed) + 16] = struct.pack("<Q", str_offset)
    end = str_offset + len(strings)
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 3, machine, 1, 0, phoff, 0, 0, 64, phentsize, phnum, 0, 0, 0)
    phdrs = bytearray()
    phdrs.extend(struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, end, end, 0x1000))
    phdrs.extend(struct.pack("<IIQQQQQQ", 3, 4, interp_offset, interp_offset, interp_offset, len(interp), len(interp), 1))
    phdrs.extend(struct.pack("<IIQQQQQQ", 2, 6, dyn_offset, dyn_offset, dyn_offset, len(dynamic), len(dynamic), 8))
    result = bytearray(end)
    result[:64] = header
    result[phoff:phoff + len(phdrs)] = phdrs
    result[interp_offset:interp_offset + len(interp)] = interp
    result[dyn_offset:dyn_offset + len(dynamic)] = dynamic
    result[str_offset:str_offset + len(strings)] = strings
    return bytes(result)


class ReleasePackagingTests(unittest.TestCase):
    def test_pq_gate_cleanup_requires_exact_id_and_owner_and_allows_package_only(self):
        script = (ROOT / "scripts/test-pqtls-packaging.sh").read_text()
        cleanup = script.split("<<'PY_CONTAINER'\n", 1)[1].split("\nPY_CONTAINER", 1)[0]
        with tempfile.TemporaryDirectory(prefix="cicada-synthetic-cleanup-") as directory:
            root = pathlib.Path(directory)
            cid = "a" * 64
            (root / "driver.cid").write_text(cid)
            for actual_owner in ("synthetic-owner", "other-owner"):
                with self.subTest(owner=actual_owner):
                    removed = []

                    def fake_run(arguments, **kwargs):
                        self.assertEqual(arguments[0], "docker")
                        self.assertEqual(arguments[-1], cid)
                        if arguments[1] == "inspect":
                            if arguments[3] == "{{.Id}}":
                                return subprocess.CompletedProcess(arguments, 1, "")
                            return subprocess.CompletedProcess(arguments, 0, actual_owner + "\t/driver\tfalse\n")
                        self.assertEqual(arguments[1:3], ["rm", "--force"])
                        removed.append(cid)
                        return subprocess.CompletedProcess(arguments, 0, cid + "\n")

                    argv = ["cleanup", str(root), "driver", "never-created-hub", "",
                            "cicada.owner=synthetic-owner", "cicada.owner=hub", "synthetic-builder"]
                    with mock.patch.object(sys, "argv", argv), mock.patch.object(subprocess, "run", fake_run):
                        if actual_owner == "synthetic-owner":
                            exec(compile(cleanup, "pq-cleanup-fixture", "exec"), {})
                            receipt = json.loads((root / "container-cleanup.json").read_text())
                            self.assertTrue(receipt["verified_absent"])
                            self.assertEqual(len(receipt["containers"]), 1)
                            self.assertEqual(removed, [cid])
                        else:
                            with self.assertRaisesRegex(SystemExit, "exact owner receipt"):
                                exec(compile(cleanup, "pq-cleanup-fixture", "exec"), {})
                            self.assertEqual(removed, [])

    def test_arm64_legacy_interop_gate_refuses_unwired_execution(self):
        result = subprocess.run(["sh", str(ROOT / "scripts/run-pqtls-interop-test.sh")],
                                env={**os.environ, "CICADA_PQTLS_INTEROP_TARGETARCH": "arm64"},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not wired to a target runner", result.stderr)

    def test_release_workflow_uses_the_hub_image_and_runs_packaging_checks(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/test-release-packaging.py", workflow)
        self.assertIn("python3 scripts/test-release-packaging.py dist", workflow)
        self.assertIn("--source-info-only", workflow)
        self.assertIn("file: docker/Dockerfile.hub", workflow)
        for argument in (
            "CICADA_BUILD_VERSION=",
            "CICADA_BUILD_REVISION=",
            "CICADA_BUILD_DIRTY=",
            "CICADA_BUILD_SOURCE_FINGERPRINT=",
            "CICADA_BUILD_CATALOG_SHA256=",
            "CICADA_BUILD_WEBCRYPTO_MANIFEST_SHA256=",
        ):
            self.assertIn(argument, workflow)
        self.assertNotIn("file: docker/Dockerfile\n", workflow)

    def test_hub_build_preserves_and_checks_release_provenance(self):
        dockerfile = (ROOT / "docker/Dockerfile.hub").read_text(encoding="utf-8")
        helper = (ROOT / "scripts/build-hub-image.sh").read_text(encoding="utf-8")
        for value in (
            "buildinfo.Version",
            "buildinfo.Revision",
            "buildinfo.Dirty",
            "buildinfo.SourceFingerprint",
            "webcrypto-manifest-sha256",
        ):
            self.assertIn(value, dockerfile)
        self.assertIn("--source-info-only", helper)

    def test_provenance_arguments_do_not_invalidate_stable_dependency_layers(self):
        identities = ("CICADA_BUILD_VERSION", "CICADA_BUILD_REVISION",
                      "CICADA_BUILD_DIRTY", "CICADA_BUILD_SOURCE_FINGERPRINT")
        manifest = "CICADA_BUILD_WEBCRYPTO_MANIFEST_SHA256"
        for name in ("docker/Dockerfile.hub", "docker/Dockerfile.hub-pqtls"):
            with self.subTest(dockerfile=name):
                text = (ROOT / name).read_text()
                builder = text[text.index(" AS cicada-builder"):].split("\nFROM ", 1)[0]
                dependencies = builder.index("RUN go mod download")
                wasm = builder.index("./cmd/cicada-webcrypto")
                linked_identity = builder.index("-ldflags=")
                # Docker exposes an ARG to subsequent RUN instructions even
                # when their shell text never explicitly references it.
                for argument in identities:
                    declaration = builder.index("ARG " + argument + "=")
                    self.assertGreater(declaration, dependencies)
                    self.assertGreater(declaration, wasm)
                    self.assertLess(declaration, linked_identity)
                    self.assertIn("${" + argument + "}", builder[linked_identity:])
                self.assertNotIn("ARG CICADA_BUILD_CATALOG_SHA256", builder)
                self.assertGreater(builder.index("ARG " + manifest + "="), wasm)
                self.assertLess(builder.index("ARG " + manifest + "="),
                                builder.index('RUN if [ "$' + manifest + '"'))
                runtime = text[text.index(" AS hub-runtime"):]
                for argument in (*identities, manifest, "CICADA_BUILD_CATALOG_SHA256"):
                    self.assertIn("ARG " + argument + "=", runtime)
                    self.assertIn("${" + argument + "}", runtime[runtime.index("LABEL "):])
                if "RUN apk add" in runtime:
                    for argument in (*identities, manifest, "CICADA_BUILD_CATALOG_SHA256"):
                        self.assertGreater(runtime.index("ARG " + argument + "="), runtime.index("RUN apk add"))

    def test_hub_build_fails_closed_on_git_status_errors_before_and_after_build(self):
        with tempfile.TemporaryDirectory(prefix="cicada-hub-git-status-") as directory:
            temp = pathlib.Path(directory)
            source = temp / "source"
            subprocess.run(["git", "clone", "--shared", "--quiet", str(ROOT), str(source)], check=True, capture_output=True)
            shutil.copy2(ROOT / "scripts/build-hub-image.sh", source / "scripts/build-hub-image.sh")
            tools = temp / "tools"
            tools.mkdir()
            status_count = temp / "git-status-count"
            fake_git = tools / "git"
            fake_git.write_text(
                "#!/bin/sh\n"
                "if [ \"${3:-}\" = status ]; then\n"
                "  count=0\n"
                "  [ ! -f \"$SYNTHETIC_GIT_STATUS_COUNT\" ] || count=$(cat \"$SYNTHETIC_GIT_STATUS_COUNT\")\n"
                "  count=$((count + 1))\n"
                "  printf '%s\\n' \"$count\" > \"$SYNTHETIC_GIT_STATUS_COUNT\"\n"
                "  if [ \"$count\" -ge \"$SYNTHETIC_GIT_STATUS_FAIL_AT\" ]; then exit 73; fi\n"
                "fi\n"
                "exec /usr/bin/git \"$@\"\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            build_marker = temp / "docker-build-ran"
            fake_docker = tools / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "[ \"${1:-}\" = build ] || exit 91\n"
                "shift\n"
                "while [ $# -gt 0 ]; do\n"
                "  if [ \"$1\" = --iidfile ]; then printf 'sha256:synthetic\\n' > \"$2\"; break; fi\n"
                "  shift\n"
                "done\n"
                "printf 'built\\n' > \"$SYNTHETIC_DOCKER_BUILD_MARKER\"\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}",
                "SYNTHETIC_GIT_STATUS_COUNT": str(status_count),
                "SYNTHETIC_DOCKER_BUILD_MARKER": str(build_marker),
            }
            helper = source / "scripts/build-hub-image.sh"
            initial_metadata = temp / "initial-source.json"
            initial = subprocess.run(
                [str(helper), "--source-info-only", "--metadata-file", str(initial_metadata)],
                env={**environment, "SYNTHETIC_GIT_STATUS_FAIL_AT": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(initial.returncode, 0)
            self.assertIn("unable to inspect source tree status", initial.stderr)
            self.assertFalse(initial_metadata.exists())
            self.assertFalse(build_marker.exists())

            status_count.unlink()
            build_metadata = temp / "image-build.json"
            after_build = subprocess.run(
                [str(helper), "--image", "cicada:synthetic-status-failure", "--metadata-file", str(build_metadata)],
                env={**environment, "SYNTHETIC_GIT_STATUS_FAIL_AT": "2"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(after_build.returncode, 0)
            self.assertTrue(build_marker.exists())
            self.assertIn("unable to inspect source tree status", after_build.stderr)
            self.assertIn("source changed during the Docker build", after_build.stderr)
            self.assertFalse(build_metadata.exists())

    def test_release_build_includes_wasm_generation_and_provenance(self):
        build = (ROOT / "scripts/build-release.sh").read_text(encoding="utf-8")
        self.assertIn("./cmd/cicada-webcrypto", build)
        self.assertIn("write-web-panel-manifest.py", build)
        self.assertIn("internal/buildinfo.Revision", build)
        self.assertIn("internal/buildinfo.Dirty", build)
        self.assertIn("internal/buildinfo.SourceFingerprint", build)
        self.assertNotIn("docker run", build)

    def test_hub_images_copy_project_license_without_replacing_third_party_notices(self):
        for name, destination, existing in (
            ("docker/Dockerfile.hub", "/usr/share/licenses/cicada/LICENSE", "/out/licenses/"),
            ("docker/Dockerfile.hub-pqtls", "/opt/cicada-pqtls/share/licenses/cicada/LICENSE", "/out/"),
        ):
            with self.subTest(dockerfile=name):
                text = (ROOT / name).read_text()
                self.assertEqual(text.count(f"COPY LICENSE {destination}\n"), 1)
                self.assertLess(text.index(f"COPY LICENSE {destination}\n"), text.index("\nUSER "))
                self.assertIn(f"COPY --from=cicada-builder {existing}", text)

    def test_project_license_bytes_change_hub_and_pq_source_fingerprints(self):
        global_name = subprocess.run(
            ["git", "config", "--global", "--get", "user.name"],
            capture_output=True, text=True, check=False,
        )
        global_email = subprocess.run(
            ["git", "config", "--global", "--get", "user.email"],
            capture_output=True, text=True, check=False,
        )
        if (global_name.returncode != 0 or global_email.returncode != 0 or
                not global_name.stdout.strip() or not global_email.stdout.strip()):
            self.skipTest("global git user.name and user.email are required for fixture commits")
        expected_name = global_name.stdout.strip()
        expected_email = global_email.stdout.strip()
        spec = importlib.util.spec_from_file_location("license_inventory", ROOT / "scripts/hub-build-input-inventory.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory(prefix="cicada-license-inventory-") as directory:
            source = pathlib.Path(directory)
            subprocess.run(["git", "-C", str(source), "init", "-q"], check=True, capture_output=True)
            license_path = source / "LICENSE"
            license_path.write_bytes((ROOT / "LICENSE").read_bytes())
            before = helper.capture(source)
            pq_before = helper._capture_once(source, helper.PQ_SCOPE)
            license_path.write_bytes(license_path.read_bytes() + b"\nSYNTHETIC INPUT MUTATION\n")
            after = helper.capture(source)
            pq_after = helper._capture_once(source, helper.PQ_SCOPE)
            self.assertNotEqual(before["source_fingerprint_v4"], after["source_fingerprint_v4"])
            self.assertNotEqual(pq_before["fingerprint"], pq_after["fingerprint"])
            self.assertEqual([row["path"] for row in after["entries"]], ["LICENSE"])

        # Exercise the real shell/inventory equality gate before any Docker call.
        with tempfile.TemporaryDirectory(prefix="cicada-license-source-info-") as directory:
            temp = pathlib.Path(directory)
            source = temp / "source"
            source.mkdir()
            for name in ("LICENSE", "VERSION", "scripts/build-hub-image.sh",
                         "scripts/hub-build-input-inventory.py", "docker/Dockerfile.hub",
                         "cicada-go/internal/clientcontract/catalog.json"):
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, destination)
            subprocess.run(["git", "-C", str(source), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            for variable in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
                identity = subprocess.run(
                    ["git", "-C", str(source), "var", variable],
                    capture_output=True, text=True, check=True,
                ).stdout.rstrip("\n")
                self.assertTrue(
                    identity.startswith(f"{expected_name} <{expected_email}> "),
                    f"{variable} did not inherit global git user.name and user.email",
                )
            subprocess.run(["git", "-C", str(source), "commit", "-qm",
                            "synthetic source-info fixture"], check=True)
            identities = subprocess.run(
                ["git", "-C", str(source), "show", "-s",
                 "--format=%an%x00%ae%x00%cn%x00%ce", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.rstrip("\n").split("\0")
            self.assertEqual(
                identities,
                [expected_name, expected_email, expected_name, expected_email],
                "synthetic fixture commit Author/Committer did not inherit global identity",
            )
            fingerprints = []
            for ordinal in range(2):
                metadata_path = temp / f"source-info-{ordinal}.json"
                result = subprocess.run(
                    ["bash", str(source / "scripts/build-hub-image.sh"),
                     "--source-info-only", "--metadata-file", str(metadata_path)],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads(metadata_path.read_text())["source"]
                captured = helper.capture(source)
                self.assertEqual(metadata["source_fingerprint"],
                                 captured["source_fingerprint_v4"]["sha256"])
                self.assertEqual(metadata["input_inventory"], captured)
                self.assertEqual(metadata["dirty"], ordinal == 1)
                fingerprints.append(metadata["source_fingerprint"])
                license_path = source / "LICENSE"
                license_path.write_bytes(license_path.read_bytes() + b"\nSYNTHETIC INPUT MUTATION\n")
            self.assertNotEqual(*fingerprints)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cicada-installer-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.capture = self.root / "agent-args.txt"
        self.state_dir = self.root / "node-state"
        self.binary = self.root / "cicada-test-binary"
        self._write_executable(
            self.bin_dir / "hostname", "#!/bin/sh\nprintf 'test-node\\n'\n"
        )
        self._write_executable(self.bin_dir / "codex", "#!/bin/sh\nexit 0\n")
        self._write_executable(
            self.bin_dir / "id",
            "#!/bin/sh\nif [ \"${1:-}\" = -u ]; then printf '1000\\n'; else exec /usr/bin/id \"$@\"; fi\n",
        )
        self._write_executable(
            self.binary,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CICADA_TEST_CAPTURE\"\n",
        )

    @staticmethod
    def _write_executable(path, contents):
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _run_installer(self, *arguments):
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin_dir}{os.pathsep}{environment['PATH']}",
                "HOME": str(self.root / "home"),
                "CICADA_CONTROL_URL": "http://127.0.0.1:8788",
                "CICADA_MACHINE_ID": "test-node",
                "CICADA_NODE_STATE_DIR": str(self.state_dir),
                "CICADA_BINARY_PATH": str(self.binary),
                "CICADA_TEST_CAPTURE": str(self.capture),
            }
        )
        return subprocess.run(
            [str(INSTALLER), *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_default_and_explicit_relay_mode_pass_relay_only(self):
        for arguments in ((), ("--mode", "relay"), ("--mode=relay",)):
            with self.subTest(arguments=arguments):
                self.capture.unlink(missing_ok=True)
                result = self._run_installer(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--relay-only", self.capture.read_text(encoding="utf-8").splitlines())
                self.assertIn("Node mode: relay", result.stdout)

    def test_managed_mode_enables_existing_worker_agent_without_automatic_join(self):
        for arguments in (("--mode", "managed"), ("--mode=managed",)):
            with self.subTest(arguments=arguments):
                self.capture.unlink(missing_ok=True)
                result = self._run_installer(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                command = self.capture.read_text(encoding="utf-8").splitlines()
                self.assertNotIn("--relay-only", command)
                self.assertNotIn("--once", command)
                self.assertNotIn("--join", command)
                self.assertNotIn("--confirm", command)
                self.assertIn("Node mode: managed", result.stdout)

    def test_unknown_or_incomplete_mode_fails_before_starting_the_agent(self):
        for arguments in (("--mode", "automatic"), ("--mode=",), ("--mode",)):
            with self.subTest(arguments=arguments):
                self.capture.unlink(missing_ok=True)
                result = self._run_installer(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.capture.exists())

    def test_symlink_state_and_ancestor_fail_without_changing_target_or_starting_agent(self):
        target = self.root / "existing-state"
        target.mkdir(mode=0o755)
        target.chmod(0o755)  # The evidence runner itself uses private umask 077.
        marker = target / "existing-identity"
        marker.write_bytes(b"SYNTHETIC PRESERVED IDENTITY")
        for ancestor in (False, True):
            with self.subTest(ancestor=ancestor):
                link = self.root / ("ancestor-link" if ancestor else "state-link")
                link.symlink_to(target, target_is_directory=True)
                self.state_dir = link / "new-state" if ancestor else link
                result = self._run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symlink", result.stderr)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
                self.assertEqual(marker.read_bytes(), b"SYNTHETIC PRESERVED IDENTITY")
                self.assertFalse((target / "new-state").exists())
                self.assertFalse(self.capture.exists())

    def test_standard_installer_needs_no_realpath_or_new_gnu_command(self):
        for name in ("bash", "dirname", "install", "mktemp", "chmod"):
            (self.bin_dir / name).symlink_to(shutil.which(name))
        self.assertFalse((self.bin_dir / "realpath").exists())
        with mock.patch.dict(os.environ, {"PATH": str(self.bin_dir)}):
            result = self._run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.capture.exists())
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)

    def test_noncanonical_state_path_fails_before_agent_or_state_mutation(self):
        for name in ("/", str(self.root)+"//state", str(self.root)+"/./state", str(self.root)+"/../state", str(self.root)+"/state/", "relative-state"):
            with self.subTest(path=name):
                environment = os.environ.copy()
                environment.update({"PATH":str(self.bin_dir)+os.pathsep+environment["PATH"], "CICADA_CONTROL_URL":"http://127.0.0.1:8788", "CICADA_MACHINE_ID":"test-node", "CICADA_NODE_STATE_DIR":name, "CICADA_BINARY_PATH":str(self.binary), "CICADA_TEST_CAPTURE":str(self.capture)})
                result = subprocess.run([str(INSTALLER)],env=environment,text=True,capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.capture.exists())
        self.assertFalse((self.root / "state").exists())


@unittest.skipUnless(os.environ.get("CICADA_RELEASE_ARTIFACT_DIR"), "release artifacts were not supplied")
class ReleaseArtifactSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact_dir = pathlib.Path(os.environ["CICADA_RELEASE_ARTIFACT_DIR"]).resolve()
        cls.binary = cls.artifact_dir / "cicada-linux-amd64"
        cls.metadata = json.loads((cls.artifact_dir / "BUILD-METADATA.json").read_text(encoding="utf-8"))

    def test_checksums_and_embedded_hub_assets_and_provenance(self):
        checksums = subprocess.run(
            ["sha256sum", "-c", "SHA256SUMS"],
            cwd=self.artifact_dir,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checksums.returncode, 0, checksums.stdout + checksums.stderr)
        self.assertEqual((self.artifact_dir / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())
        with tarfile.open(self.artifact_dir / "LICENSE-NOTICES.tar.gz") as archive:
            self.assertEqual(archive.extractfile("standard-notices/cicada/LICENSE").read(),
                             (ROOT / "LICENSE").read_bytes())

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="cicada-release-smoke-") as state_dir:
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": state_dir,
                "CICADA_STATE_DIR": state_dir,
                "CICADA_WORKSPACE_ROOT": str(pathlib.Path(state_dir) / "workspace"),
            }
            process = subprocess.Popen(
                [str(self.binary), "serve", "--host", "127.0.0.1", "--port", str(port)],
                cwd=state_dir,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            base_url = f"http://127.0.0.1:{port}"
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        self.fail(f"release binary exited during startup with {process.returncode}")
                    try:
                        with urllib.request.urlopen(base_url + "/healthz", timeout=1) as response:
                            health = json.loads(response.read())
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() >= deadline:
                            self.fail("release binary did not start its local Hub")
                        time.sleep(0.1)

                source = self.metadata["source"]
                self.assertEqual(health["version"], self.metadata["software_version"])
                self.assertEqual(health["revision"], source["revision"])
                self.assertEqual(health["dirty"], source["dirty"])
                self.assertEqual(health["source_fingerprint"], source["source_fingerprint"])

                with urllib.request.urlopen(base_url + "/assets/panel.manifest.json", timeout=3) as response:
                    manifest_bytes = response.read()
                    manifest = json.loads(manifest_bytes)
                self.assertEqual(
                    hashlib.sha256(manifest_bytes).hexdigest(),
                    self.metadata["hub_webcrypto_manifest_sha256"],
                )
                with urllib.request.urlopen(base_url + "/assets/wasm_exec.js", timeout=3) as response:
                    wasm_exec = response.read()
                    self.assertEqual(response.headers.get_content_type(), "text/javascript")
                self.assertEqual(hashlib.sha256(wasm_exec).hexdigest(), manifest["wasm_exec_sha256"])
                with urllib.request.urlopen(base_url + "/assets/cicada-webcrypto.wasm", timeout=3) as response:
                    compressed_wasm = response.read()
                    self.assertEqual(response.headers.get("Content-Encoding"), "gzip")
                self.assertEqual(hashlib.sha256(compressed_wasm).hexdigest(), manifest["wasm_gzip_sha256"])
                raw_wasm = gzip.decompress(compressed_wasm)
                self.assertEqual(hashlib.sha256(raw_wasm).hexdigest(), manifest["wasm_sha256"])
                self.assertEqual(manifest["toolchain"], "go1.27.2")
                self.assertEqual(health["catalog_sha256"], self.metadata["catalog_sha256"])
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


class PQSelectionTests(unittest.TestCase):
    def test_standard_release_helper_only_change_has_v2_dirty_identity_and_race_guard(self):
        # Execute the real release orchestration in a disposable Git repository.
        # Fake Go writes visibly synthetic files; this is provenance QA, not a
        # compiled artifact/platform acceptance claim.
        with tempfile.TemporaryDirectory(prefix="cicada-standard-provenance-") as directory:
            temp = pathlib.Path(directory)
            source = temp / "source"
            for name in ("LICENSE", "scripts/build-release.sh", "scripts/hub-build-input-inventory.py", "scripts/write-web-panel-manifest.py"):
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            catalog = source / "cicada-go/internal/clientcontract/catalog.json"
            catalog.parent.mkdir(parents=True)
            catalog.write_text('{"SYNTHETIC": true}\n')
            (source / "cicada-go/go.mod").write_text("module synthetic.invalid/fixture\n")
            for arguments in (("init", "-q"), ("add", "--all"), ("commit", "-qm", "synthetic provenance fixture")):
                subprocess.run(["git", "-C", str(source), *arguments], check=True, capture_output=True)
            tools = temp / "tools"
            tools.mkdir()
            goroot = temp / "goroot"
            (goroot / "lib/wasm").mkdir(parents=True)
            (goroot / "lib/wasm/wasm_exec.js").write_text("// SYNTHETIC TOOLCHAIN FIXTURE\n")
            (goroot / "LICENSE").write_text("SYNTHETIC LICENSE FIXTURE, NOT DISTRIBUTABLE\n")
            (tools / "amd64.elf").write_bytes(synthetic_elf64(62, "/lib64/ld-linux-x86-64.so.2",
                                                               ("libssl.so.3", "libcrypto.so.3"), "$ORIGIN/../lib"))
            (tools / "arm64.elf").write_bytes(synthetic_elf64(183, "/lib/ld-linux-aarch64.so.1",
                                                               ("libssl.so.3", "libcrypto.so.3"), "$ORIGIN/../lib"))
            fake = tools / "go"
            fake.write_text("#!" + sys.executable + "\n" + '''import json,os,pathlib,sys
import shutil
args=sys.argv[1:]
if args[0]=='version': print('go version go1.27.2 linux/amd64')
elif args[0]=='env': print(os.environ['SYNTHETIC_GOROOT'] if args[1]=='GOROOT' else os.environ.get(args[1],{'GOOS':'linux','GOARCH':'amd64','GOHOSTOS':'linux','GOHOSTARCH':'amd64'}[args[1]]))
elif args[0]=='list': print(json.dumps({'Module':{'Main':True}}))
elif args[0]=='build':
 output=pathlib.Path(args[args.index('-o')+1])
 if output.parent.name=='bin':
  shutil.copyfile(pathlib.Path(os.environ['SYNTHETIC_ELF_DIR'])/(os.environ.get('GOARCH','amd64')+'.elf'),output);output.chmod(0o755)
 else: output.write_bytes(b'SYNTHETIC GO OUTPUT, NEVER RUN AS PRODUCT')
 if os.environ.get('SYNTHETIC_MUTATE_HELPER') and output.name=='cicada-linux-amd64':
  helper=pathlib.Path(os.environ['SYNTHETIC_MUTATE_HELPER']);helper.write_bytes(helper.read_bytes()+b'\\n# SYNTHETIC IN-BUILD MUTATION\\n')
else: sys.exit(91)
''')
            fake.chmod(0o755)
            fake_readelf = tools / "readelf"
            fake_readelf.write_text("#!/bin/sh\nif [ \"${1:-}\" = --version-info ]; then printf 'Version: GLIBC_2.34\\n'; else exec /usr/bin/readelf \"$@\"; fi\n")
            fake_readelf.chmod(0o755)
            environment = {**os.environ, "PATH":str(tools)+os.pathsep+os.environ["PATH"], "SYNTHETIC_GOROOT":str(goroot), "SYNTHETIC_ELF_DIR":str(tools), "GOOS":"linux", "GOARCH":"amd64", "CC":"gcc"}
            script = source / "scripts/build-release.sh"
            def release(name, extra=None):
                output = temp / name
                result = subprocess.run([str(script), "0.1.0-test", str(output)], env={**environment, **(extra or {})}, text=True, capture_output=True)
                return result, output
            result, output = release("baseline")
            self.assertEqual(result.returncode, 0, result.stderr)
            license_bytes = (source / "LICENSE").read_bytes()
            self.assertEqual((output / "LICENSE").read_bytes(), license_bytes)
            checksums = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=output,
                                       text=True, capture_output=True)
            self.assertEqual(checksums.returncode, 0, checksums.stdout + checksums.stderr)
            self.assertIn("  LICENSE\n", (output / "SHA256SUMS").read_text())
            with tarfile.open(output / "LICENSE-NOTICES.tar.gz") as archive:
                self.assertEqual(archive.extractfile("standard-notices/cicada/LICENSE").read(), license_bytes)
                self.assertEqual(archive.extractfile("standard-notices/go/LICENSE").read(),
                                 (goroot / "LICENSE").read_bytes())
            baseline = json.loads((output / "BUILD-METADATA.json").read_text())["source"]
            self.assertFalse(baseline["dirty"])
            descriptor = baseline["fingerprint_descriptor"]
            self.assertEqual(bytes.fromhex(descriptor["domain_hex"]), b"cicada-binary-release-inputs-v2\0")
            self.assertIn("scripts/hub-build-input-inventory.py", descriptor["scope"])
            self.assertIn("LICENSE", descriptor["scope"])
            stage = os.environ.get("CICADA_PQTLS_STAGE")
            if stage:
                stage_metadata_path = pathlib.Path(stage) / "PQTLS-STAGE-METADATA.json"
                arch = json.loads(stage_metadata_path.read_text())["target"]["goarch"] if stage_metadata_path.exists() else "amd64"
                pq_output = temp / "pq-output"
                pq = subprocess.run([str(script), "0.1.0-test", str(pq_output),
                                     "--transport", "pqtls", "--pqtls-stage", stage, "--targetarch", arch],
                                    env={**environment,"GOARCH":arch,"CC":"aarch64-linux-gnu-gcc" if arch=="arm64" else "gcc"},
                                    text=True, capture_output=True)
                self.assertEqual(pq.returncode, 0, pq.stderr)
                self.assertEqual((pq_output / "LICENSE").read_bytes(), license_bytes)
                with tarfile.open(pq_output / f"cicada-linux-{arch}-pqtls.tar.gz") as archive:
                    name = f"cicada-linux-{arch}-pqtls/share/licenses/cicada/LICENSE"
                    self.assertEqual(archive.extractfile(name).read(), license_bytes)
                    openssl = f"cicada-linux-{arch}-pqtls/share/licenses/openssl/LICENSE.txt"
                    self.assertEqual(archive.extractfile(openssl).read(),
                                     (pathlib.Path(stage) / "share/licenses/openssl/LICENSE.txt").read_bytes())
                receipt = json.loads((pq_output / "PQ-BUILD-RECEIPT.json").read_text())
                self.assertEqual(receipt["package_file_sha256"]["share/licenses/cicada/LICENSE"],
                                 hashlib.sha256(license_bytes).hexdigest())
                pq_checksums = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=pq_output,
                                              text=True, capture_output=True)
                self.assertEqual(pq_checksums.returncode, 0, pq_checksums.stdout + pq_checksums.stderr)
            license_path = source / "LICENSE"
            license_path.write_bytes(license_bytes + b"\nSYNTHETIC LICENSE INPUT CHANGE\n")
            result, output = release("license-only")
            self.assertEqual(result.returncode, 0, result.stderr)
            changed_license = json.loads((output / "BUILD-METADATA.json").read_text())["source"]
            self.assertTrue(changed_license["dirty"])
            self.assertNotEqual(changed_license["source_fingerprint"], baseline["source_fingerprint"])
            subprocess.run(["git", "-C", str(source), "checkout", "--", "LICENSE"], check=True)
            license_path.unlink()
            result, output = release("missing-project-license")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("project LICENSE is missing", result.stderr)
            self.assertFalse(output.exists())
            license_path.write_bytes(license_bytes)
            git_wrapper = tools / "git"
            git_wrapper.write_text("#!/bin/sh\nif [ \"${3:-}\" = status ]; then exit 73; fi\nexec /usr/bin/git \"$@\"\n")
            git_wrapper.chmod(0o755)
            result, output = release("git-status-failure")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unable to inspect source tree status", result.stderr)
            self.assertFalse(output.exists())
            git_wrapper.unlink()
            helper = source / "scripts/hub-build-input-inventory.py"
            helper.write_bytes(helper.read_bytes()+b"\n# SYNTHETIC HELPER-ONLY CHANGE\n")
            result, output = release("helper-only")
            self.assertEqual(result.returncode, 0, result.stderr)
            changed = json.loads((output / "BUILD-METADATA.json").read_text())["source"]
            self.assertTrue(changed["dirty"])
            self.assertNotEqual(changed["source_fingerprint"], baseline["source_fingerprint"])
            subprocess.run(["git", "-C", str(source), "checkout", "--", "scripts/hub-build-input-inventory.py"], check=True)
            result, output = release("in-build-mutation", {"SYNTHETIC_MUTATE_HELPER":str(helper)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build inputs changed during the build", result.stderr)
            self.assertFalse(output.exists())
            result, output = release("in-build-license-mutation", {"SYNTHETIC_MUTATE_HELPER": str(license_path)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build inputs changed during the build", result.stderr)
            self.assertFalse(output.exists())

    def test_packaging_only_edits_are_dirty(self):
        with tempfile.TemporaryDirectory(prefix="cicada-pq-dirty-") as directory:
            clone = pathlib.Path(directory) / "source"
            subprocess.run(["git", "clone", "--shared", "--quiet", str(ROOT), str(clone)], check=True, capture_output=True)
            command = [sys.executable, str(ROOT / "scripts/hub-build-input-inventory.py"), "dirty", "--root", str(clone)]
            self.assertEqual(subprocess.check_output(command, text=True).strip(), "false")
            for name in ("docker/Dockerfile.hub-pqtls", "scripts/hub-build-input-inventory.py"):
                with self.subTest(path=name):
                    path = clone / name
                    previous = path.read_bytes() if path.exists() else None
                    path.write_bytes((previous or b"") + b"\n# SYNTHETIC DIRTY INPUT\n")
                    self.assertEqual(subprocess.check_output(command, text=True).strip(), "true")
                    if previous is None:
                        path.unlink()
                    else:
                        path.write_bytes(previous)
                    self.assertEqual(subprocess.check_output(command, text=True).strip(), "false")

    def test_pq_installer_refuses_automatic_cgo0_build_before_go_or_agent(self):
        with tempfile.TemporaryDirectory(prefix="cicada-pq-install-") as directory:
            temp = pathlib.Path(directory)
            tools = temp / "bin"; tools.mkdir()
            for name, body in {"codex": "exit 0", "hostname": "printf 'synthetic-node\\n'", "id": "printf '1000\\n'"}.items():
                path = tools / name; path.write_text("#!/bin/sh\n" + body + "\n"); path.chmod(0o755)
            env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"], "CICADA_CONTROL_URL": "http://127.0.0.1:8788", "CICADA_NODE_PQTLS_CONFIG": str(temp / "private.json"), "CICADA_BINARY_PATH": "", "CICADA_NODE_STATE_DIR": str(temp / "state")}
            result = subprocess.run([str(INSTALLER)], env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("automatic CGO0 build is unavailable", result.stderr)
            self.assertFalse((temp / "state").exists())

    def test_pq_release_refuses_cgo0_and_other_target_before_build(self):
        with tempfile.TemporaryDirectory(prefix="cicada-pq-target-") as directory:
            tools = pathlib.Path(directory)
            fake = tools / "go"
            fake.write_text("#!/bin/sh\ncase \"$1\" in version) printf 'go version go1.27.2 linux/amd64\\n';; *) exit 91;; esac\n")
            fake.chmod(0o755)
            for extra in ({"CGO_ENABLED": "0"}, {"GOARCH": "arm64"}, {"GOOS": "darwin"}):
                with self.subTest(extra=extra):
                    env = {**os.environ, "PATH": str(tools)+os.pathsep+os.environ["PATH"], "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1", **extra}
                    result = subprocess.run([str(ROOT/"scripts/build-release.sh"),"0.1.0-dev",str(tools/"out"),"--transport","pqtls","--pqtls-stage",str(tools)],env=env,text=True,capture_output=True)
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn("PQ requires explicit architecture-matched stage, CGO1 and linux/amd64",result.stderr)
                    self.assertFalse((tools/"out").exists())


class PQELFMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("pqtls_elf_inventory", ROOT / "scripts/hub-build-input-inventory.py")
        cls.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.helper)

    def test_target_specific_machine_loader_dependencies_and_package_runpath(self):
        targets = {
            "amd64": (62, "/lib64/ld-linux-x86-64.so.2"),
            "arm64": (183, "/lib/ld-linux-aarch64.so.1"),
        }
        for arch, (machine, interpreter) in targets.items():
            with self.subTest(target=arch), tempfile.TemporaryDirectory(prefix="cicada-synthetic-elf-") as directory:
                binary = pathlib.Path(directory) / "synthetic-not-runnable-elf"
                binary.write_bytes(synthetic_elf64(machine, interpreter, ("libssl.so.3", "libcrypto.so.3"), "$ORIGIN/../lib"))
                metadata = self.helper.verify_elf_target(binary, arch, product=True)
                self.assertEqual(metadata["interpreter"], interpreter)
                self.assertEqual(set(metadata["needed"]), {"libssl.so.3", "libcrypto.so.3"})
                self.assertEqual(metadata["runpath"], ["$ORIGIN/../lib"])
                other = "arm64" if arch == "amd64" else "amd64"
                with self.assertRaisesRegex(self.helper.InventoryError, "ELF Machine"):
                    self.helper.verify_elf_target(binary, other, product=True)

    def test_rejects_mismatched_loader_missing_openssl_and_nonrelative_runpath(self):
        cases = (
            (62, "/lib/ld-linux-aarch64.so.1", ("libssl.so.3", "libcrypto.so.3"), "$ORIGIN/../lib"),
            (62, "/lib64/ld-linux-x86-64.so.2", ("libssl.so.3",), "$ORIGIN/../lib"),
            (62, "/lib64/ld-linux-x86-64.so.2", ("libssl.so.3", "libcrypto.so.3"), "/usr/lib"),
        )
        for args in cases:
            with self.subTest(case=args), tempfile.TemporaryDirectory(prefix="cicada-synthetic-elf-") as directory:
                binary = pathlib.Path(directory) / "synthetic-not-runnable-elf"
                binary.write_bytes(synthetic_elf64(*args))
                with self.assertRaises(self.helper.InventoryError):
                    self.helper.verify_elf_target(binary, "amd64", product=True)

    def test_arm64_docker_interop_refuses_direct_execution_without_a_target_runner(self):
        runner = ROOT / "scripts/run-pqtls-interop-test.sh"
        environment = {**os.environ, "CICADA_PQTLS_INTEROP_TARGETARCH": "arm64"}
        result = subprocess.run([str(runner)], env=environment, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing direct execution of the ARM64 package", result.stderr)


@unittest.skipUnless(os.environ.get("CICADA_PQTLS_STAGE"), "accepted PQ development stage was not supplied")
class PQRuntimeInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location("pqtls_packaging_inventory",ROOT/"scripts/hub-build-input-inventory.py")
        cls.helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.helper)
        cls.stage=pathlib.Path(os.environ["CICADA_PQTLS_STAGE"])

    def test_exact_runtime_and_headers_and_default_scope(self):
        data=self.helper.capture_runtime(self.stage)
        self.assertEqual(data["openssl_version"],"3.5.9")
        self.assertEqual(len(data["files"]),146)
        self.assertEqual(data["closure_sha256"],"c1257b769df15a4d34e69e934aeb6465a45b13023da09dcbc0b43002967e6638")
        self.assertIn("bin/openssl",data["files"])
        standard=self.helper.capture(ROOT)
        pq=self.helper.capture_pqtls(ROOT,self.stage)
        self.assertEqual(standard["source_fingerprint_v4"]["domain_hex"],b"cicada-hub-build-inputs-v4\0".hex())
        self.assertNotIn("source_fingerprint_v4",pq)
        self.assertIn("docker/Dockerfile.hub-pqtls",pq["source"]["scope"])
        self.assertNotIn("docker/Dockerfile.hub",pq["source"]["scope"])

    def test_corrupt_header_library_license_and_linker_alias_rejected(self):
        for name in ("include/openssl/ssl.h","lib/libssl.so.3","share/licenses/openssl/LICENSE.txt","lib/libcrypto.so"):
            with self.subTest(path=name), tempfile.TemporaryDirectory(prefix="cicada-pq-input-") as directory:
                copied=pathlib.Path(directory)/"stage"
                shutil.copytree(self.stage,copied,symlinks=True,ignore=shutil.ignore_patterns("*.a","cmake","pkgconfig","engines-3"))
                path=copied/name
                if path.is_symlink():
                    path.unlink();path.symlink_to("/usr/lib/libcrypto.so")
                else:path.write_bytes(path.read_bytes()+b"SYNTHETIC CORRUPTION")
                with self.assertRaises(self.helper.InventoryError):self.helper.capture_runtime(copied)

    def test_independent_receipt_rejects_tampered_bytes_receipt_archive_and_other_source(self):
        with tempfile.TemporaryDirectory(prefix="cicada-pq-receipt-") as directory:
            root = pathlib.Path(directory)
            package = root / "package"
            package.mkdir()
            current = self.helper.capture_pqtls(ROOT, self.stage)
            metadata = {"source": {"source_fingerprint": current["fingerprint"]["sha256"], "input_inventory": current},
                        "runtime": current["runtime"], "pqtls_available": True, "cgo_enabled": True,
                        "transport_variant": "pqtls", "targets": ["linux/amd64"],
                        "loader": {"interpreter": "/lib64/ld-linux-x86-64.so.2", "runpath": "$ORIGIN/../lib",
                                   "minimum_observed_glibc_symbol": "GLIBC_2.34"}}
            (package / "BUILD-METADATA.json").write_text(json.dumps(metadata))
            (package / "bin").mkdir()
            (package / "lib").mkdir()
            (package / "bin/cicada").write_bytes(synthetic_elf64(62, "/lib64/ld-linux-x86-64.so.2",
                                                                   ("libssl.so.3", "libcrypto.so.3"), "$ORIGIN/../lib"))
            shutil.copyfile(self.stage / "lib/libssl.so.3", package / "lib/libssl.so.3")
            shutil.copyfile(self.stage / "lib/libcrypto.so.3", package / "lib/libcrypto.so.3")
            archive = root / "cicada-linux-amd64-pqtls.tar.gz"
            archive.write_bytes(b"SYNTHETIC RECEIPT TEST ARCHIVE")
            files = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in package.rglob("*") if p.is_file()}
            receipt = root / "PQ-BUILD-RECEIPT.json"
            receipt.write_text(json.dumps({"schema_version": "cicada.pqtls-package-build-receipt.v1",
                "target_arch": "amd64", "source_fingerprint": current["fingerprint"]["sha256"], "package_file_sha256": files,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}))
            expected = hashlib.sha256(receipt.read_bytes()).hexdigest()
            args = (ROOT, self.stage, package, receipt, expected)
            self.assertEqual(self.helper.verify_distribution(*args)["source_fingerprint"], current["fingerprint"]["sha256"])
            for path in (package / "bin/cicada", package / "BUILD-METADATA.json", receipt, archive):
                with self.subTest(tamper=path.name):
                    previous = path.read_bytes()
                    path.write_bytes(previous + b" ")
                    with self.assertRaises(self.helper.InventoryError):
                        self.helper.verify_distribution(*args)
                    path.write_bytes(previous)
            clone = root / "other-source"
            subprocess.run(["git", "clone", "--shared", "--quiet", str(ROOT), str(clone)], check=True, capture_output=True)
            with self.assertRaisesRegex(self.helper.InventoryError, "current source/runtime"):
                self.helper.verify_distribution(clone, *args[1:])
            copied_stage = root / "other-stage"
            shutil.copytree(self.stage, copied_stage, symlinks=True, ignore=shutil.ignore_patterns("*.a", "cmake", "pkgconfig", "engines-3"))
            (copied_stage / "lib/libssl.so.3").write_bytes(b"SYNTHETIC WRONG STAGE")
            with self.assertRaises(self.helper.InventoryError):
                self.helper.verify_distribution(ROOT, copied_stage, *args[2:])
            image_receipt = root / "image.json"
            image = {"transport_variant": "pqtls", "image": {"dockerfile": "docker/Dockerfile.hub-pqtls", "id": "mutable:tag"}, "source": metadata["source"]}
            image_receipt.write_text(json.dumps(image))
            image_sha = hashlib.sha256(image_receipt.read_bytes()).hexdigest()
            with self.assertRaisesRegex(self.helper.InventoryError, "immutable image ID"):
                self.helper.verify_distribution(*args, image_receipt, image_sha)
            image["image"]["id"] = "sha256:" + "a" * 64
            image_receipt.write_text(json.dumps(image))
            image_sha = hashlib.sha256(image_receipt.read_bytes()).hexdigest()
            inspected = [{"Id": image["image"]["id"], "Config": {"Labels": {"org.cicada.build.source-fingerprint": "wrong", "org.cicada.transport.variant": "pqtls-linux-amd64"}}}]
            with mock.patch.object(self.helper.subprocess, "check_output", return_value=json.dumps(inspected)) as inspect:
                with self.assertRaisesRegex(self.helper.InventoryError, "actual immutable image"):
                    self.helper.verify_distribution(*args, image_receipt, image_sha)
                inspect.assert_called_once_with(["docker", "image", "inspect", image["image"]["id"]], text=True)
            with self.assertRaisesRegex(self.helper.InventoryError, "image build receipt SHA"):
                self.helper.verify_distribution(*args, image_receipt, "b" * 64)


@unittest.skipUnless(os.environ.get("CICADA_PQTLS_ARM64_STAGE"), "ARM64 OpenSSL stage was not supplied")
class PQArm64RuntimeInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location("pqtls_arm64_inventory",ROOT/"scripts/hub-build-input-inventory.py")
        cls.helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.helper)
        cls.stage=pathlib.Path(os.environ["CICADA_PQTLS_ARM64_STAGE"])

    def test_architecture_specific_stage_and_complete_runtime_closure(self):
        data=self.helper.capture_runtime(self.stage,"arm64")
        self.assertEqual(data["platform"],"linux/arm64")
        self.assertEqual(data["headers_sha256"],"3d6e0a215c0cc477ea5a2ea351f316f3ccd7150768fa99f8272a5cbbdab211ef")
        self.assertEqual(data["closure_sha256"],"230b49b91efd963d6f564a0fc26cc98746e2a6f8fa784f4355a26e1781e971c0")
        self.assertEqual(data["files"]["bin/openssl"]["sha256"],"83d4148f46a48e5d6ccdb6da2bf918ad94717ef159da8c4fef4982555fda4a01")
        self.assertEqual(data["target"]["interpreter"],"/lib/ld-linux-aarch64.so.1")
        self.assertEqual(data["target"]["elf_machine"],"AArch64")
        self.assertIsNotNone(data["stage_metadata_sha256"])


@unittest.skipUnless(os.environ.get("CICADA_PQTLS_PACKAGE_DIR"), "optional relocated PQ package was not supplied")
class PQArtifactTests(unittest.TestCase):
    def test_minimal_payload_checksums_relative_loader_and_provenance(self):
        root=pathlib.Path(os.environ["CICADA_PQTLS_PACKAGE_DIR"]).resolve()
        result=subprocess.run(["sha256sum","-c","SHA256SUMS"],cwd=root,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        expected={"bin/cicada","lib/libssl.so.3","lib/libcrypto.so.3","share/licenses/openssl/LICENSE.txt","BUILD-METADATA.json","SHA256SUMS","README.txt"}
        expected.update({"share/licenses/cicada/LICENSE", "share/licenses/go/LICENSE", "share/licenses/go/MODULES.json"})
        self.assertEqual((root / "share/licenses/cicada/LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())
        notices = json.loads((root / "share/licenses/go/MODULES.json").read_text())
        self.assertTrue(notices["modules"])
        self.assertIn("go1.27.2", notices["toolchain"])
        self.assertTrue((root / "share/licenses/go/LICENSE").read_bytes())
        for module in notices["modules"]:
            self.assertTrue(module["notices"])
            for relative, checksum in module["notices"].items():
                path = pathlib.Path("share/licenses/modules") / module["module"] / module["version"] / relative
                self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), checksum)
                expected.add(path.as_posix())
        self.assertEqual({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()},expected)
        metadata=json.loads((root/"BUILD-METADATA.json").read_text())
        self.assertIn(metadata["targets"],[['linux/amd64'],['linux/arm64']])
        self.assertTrue(metadata["pqtls_available"])
        self.assertEqual(metadata["transport_variant"],"pqtls")
        arch=metadata["targets"][0].split("/",1)[1]
        expected_interpreters={"amd64":"/lib64/ld-linux-x86-64.so.2","arm64":"/lib/ld-linux-aarch64.so.1"}
        self.assertEqual(metadata["loader"]["interpreter"],expected_interpreters[arch])
        elf=subprocess.check_output(["readelf","-Wd",str(root/"bin/cicada")],text=True)
        self.assertIn("(RUNPATH)",elf)
        self.assertIn("[$ORIGIN/../lib]",elf)
        env={k:v for k,v in os.environ.items() if k not in {"LD_LIBRARY_PATH","LD_PRELOAD"}}
        env["LD_TRACE_LOADED_OBJECTS"]="1"
        command=[str(root/"bin/cicada")]
        if arch=="arm64":
            runner=os.environ.get("CICADA_PQTLS_TARGET_RUNNER")
            self.assertTrue(runner,"arm64 package execution requires an explicit user-mode QEMU runner")
            command=[runner,*command]
        loaded=subprocess.check_output(command,env=env,text=True,cwd="/")
        for name in ("libssl.so.3","libcrypto.so.3"):
            rows=[line for line in loaded.splitlines() if line.strip().startswith(name+" =>")]
            self.assertEqual(len(rows),1,loaded)
            path=rows[0].split("=>",1)[1].split("(",1)[0].strip()
            self.assertEqual(pathlib.Path(path).resolve(),root/"lib"/name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
