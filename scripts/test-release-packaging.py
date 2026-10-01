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
import urllib.error
import urllib.request
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts" / "install-cicada-worker.sh"
if len(sys.argv) == 2 and sys.argv[1] not in {"-h", "--help"}:
    os.environ["CICADA_RELEASE_ARTIFACT_DIR"] = sys.argv.pop()


class ReleasePackagingTests(unittest.TestCase):
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

    def test_release_build_includes_wasm_generation_and_provenance(self):
        build = (ROOT / "scripts/build-release.sh").read_text(encoding="utf-8")
        self.assertIn("./cmd/cicada-webcrypto", build)
        self.assertIn("write-web-panel-manifest.py", build)
        self.assertIn("internal/buildinfo.Revision", build)
        self.assertIn("internal/buildinfo.Dirty", build)
        self.assertIn("internal/buildinfo.SourceFingerprint", build)
        self.assertNotIn("docker run", build)

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
                self.assertEqual(manifest["toolchain"], "go1.27.1")
                self.assertEqual(health["catalog_sha256"], self.metadata["catalog_sha256"])
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
