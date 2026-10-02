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
import importlib.util
import shutil
import stat
from unittest import mock


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


class PQSelectionTests(unittest.TestCase):
    def test_standard_release_helper_only_change_has_v2_dirty_identity_and_race_guard(self):
        # Execute the real release orchestration in a disposable Git repository.
        # Fake Go writes visibly synthetic files; this is provenance QA, not a
        # compiled artifact/platform acceptance claim.
        with tempfile.TemporaryDirectory(prefix="cicada-standard-provenance-") as directory:
            temp = pathlib.Path(directory)
            source = temp / "source"
            for name in ("scripts/build-release.sh", "scripts/hub-build-input-inventory.py", "scripts/write-web-panel-manifest.py"):
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
            fake = tools / "go"
            fake.write_text("#!" + sys.executable + "\n" + '''import json,os,pathlib,sys
args=sys.argv[1:]
if args[0]=='version': print('go version go1.27.1 linux/amd64')
elif args[0]=='env': print(os.environ['SYNTHETIC_GOROOT'] if args[1]=='GOROOT' else os.environ.get(args[1],{'GOOS':'linux','GOARCH':'amd64'}[args[1]]))
elif args[0]=='list': print(json.dumps({'Module':{'Main':True}}))
elif args[0]=='build':
 output=pathlib.Path(args[args.index('-o')+1]);output.write_bytes(b'SYNTHETIC GO OUTPUT, NEVER RUN AS PRODUCT')
 if os.environ.get('SYNTHETIC_MUTATE_HELPER') and output.name=='cicada-linux-amd64':
  helper=pathlib.Path(os.environ['SYNTHETIC_MUTATE_HELPER']);helper.write_bytes(helper.read_bytes()+b'\\n# SYNTHETIC IN-BUILD MUTATION\\n')
else: sys.exit(91)
''')
            fake.chmod(0o755)
            environment = {**os.environ, "PATH":str(tools)+os.pathsep+os.environ["PATH"], "SYNTHETIC_GOROOT":str(goroot), "GOOS":"linux", "GOARCH":"amd64"}
            script = source / "scripts/build-release.sh"
            def release(name, extra=None):
                output = temp / name
                result = subprocess.run([str(script), "0.1.0-test", str(output)], env={**environment, **(extra or {})}, text=True, capture_output=True)
                return result, output
            result, output = release("baseline")
            self.assertEqual(result.returncode, 0, result.stderr)
            baseline = json.loads((output / "BUILD-METADATA.json").read_text())["source"]
            self.assertFalse(baseline["dirty"])
            descriptor = baseline["fingerprint_descriptor"]
            self.assertEqual(bytes.fromhex(descriptor["domain_hex"]), b"cicada-binary-release-inputs-v2\0")
            self.assertIn("scripts/hub-build-input-inventory.py", descriptor["scope"])
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
            fake.write_text("#!/bin/sh\ncase \"$1\" in version) printf 'go version go1.27.1 linux/amd64\\n';; *) exit 91;; esac\n")
            fake.chmod(0o755)
            for extra in ({"CGO_ENABLED": "0"}, {"GOARCH": "arm64"}, {"GOOS": "darwin"}):
                with self.subTest(extra=extra):
                    env = {**os.environ, "PATH": str(tools)+os.pathsep+os.environ["PATH"], "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1", **extra}
                    result = subprocess.run([str(ROOT/"scripts/build-release.sh"),"0.1.0-dev",str(tools/"out"),"--transport","pqtls","--pqtls-stage",str(tools)],env=env,text=True,capture_output=True)
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn("PQ requires explicit accepted stage, CGO1 and linux/amd64",result.stderr)
                    self.assertFalse((tools/"out").exists())


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
        self.assertEqual(len(data["files"]),145)
        self.assertEqual(data["closure_sha256"],"f4f0969bfff33d505e542dc234b97bb5358956474dd04ad455046e5390f8a4a3")
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
                shutil.copytree(self.stage,copied,symlinks=True,ignore=shutil.ignore_patterns("bin","*.a","cmake","pkgconfig","engines-3"))
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
                        "transport_variant": "pqtls", "targets": ["linux/amd64"]}
            (package / "BUILD-METADATA.json").write_text(json.dumps(metadata))
            (package / "SYNTHETIC-FIXTURE").write_bytes(b"THIS IS A RECEIPT UNIT FIXTURE, NOT A PRODUCT BINARY")
            archive = root / "cicada-linux-amd64-pqtls.tar.gz"
            archive.write_bytes(b"SYNTHETIC RECEIPT TEST ARCHIVE")
            files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.iterdir()}
            receipt = root / "PQ-BUILD-RECEIPT.json"
            receipt.write_text(json.dumps({"schema_version": "cicada.pqtls-package-build-receipt.v1",
                "source_fingerprint": current["fingerprint"]["sha256"], "package_file_sha256": files,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}))
            expected = hashlib.sha256(receipt.read_bytes()).hexdigest()
            args = (ROOT, self.stage, package, receipt, expected)
            self.assertEqual(self.helper.verify_distribution(*args)["source_fingerprint"], current["fingerprint"]["sha256"])
            for path in (package / "SYNTHETIC-FIXTURE", package / "BUILD-METADATA.json", receipt, archive):
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
            shutil.copytree(self.stage, copied_stage, symlinks=True, ignore=shutil.ignore_patterns("bin", "*.a", "cmake", "pkgconfig", "engines-3"))
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


@unittest.skipUnless(os.environ.get("CICADA_PQTLS_PACKAGE_DIR"), "optional relocated PQ package was not supplied")
class PQArtifactTests(unittest.TestCase):
    def test_minimal_payload_checksums_relative_loader_and_provenance(self):
        root=pathlib.Path(os.environ["CICADA_PQTLS_PACKAGE_DIR"]).resolve()
        result=subprocess.run(["sha256sum","-c","SHA256SUMS"],cwd=root,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        expected={"bin/cicada","lib/libssl.so.3","lib/libcrypto.so.3","share/licenses/openssl/LICENSE.txt","BUILD-METADATA.json","SHA256SUMS","README.txt"}
        expected.update({"share/licenses/go/LICENSE", "share/licenses/go/MODULES.json"})
        notices = json.loads((root / "share/licenses/go/MODULES.json").read_text())
        self.assertTrue(notices["modules"])
        self.assertIn("go1.27.1", notices["toolchain"])
        self.assertTrue((root / "share/licenses/go/LICENSE").read_bytes())
        for module in notices["modules"]:
            self.assertTrue(module["notices"])
            for relative, checksum in module["notices"].items():
                path = pathlib.Path("share/licenses/modules") / module["module"] / module["version"] / relative
                self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), checksum)
                expected.add(path.as_posix())
        self.assertEqual({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()},expected)
        metadata=json.loads((root/"BUILD-METADATA.json").read_text())
        self.assertEqual(metadata["targets"],["linux/amd64"])
        self.assertTrue(metadata["pqtls_available"])
        self.assertEqual(metadata["transport_variant"],"pqtls")
        elf=subprocess.check_output(["readelf","-Wd",str(root/"bin/cicada")],text=True)
        self.assertIn("(RUNPATH)",elf)
        self.assertIn("[$ORIGIN/../lib]",elf)
        env={k:v for k,v in os.environ.items() if k not in {"LD_LIBRARY_PATH","LD_PRELOAD"}}
        env["LD_TRACE_LOADED_OBJECTS"]="1"
        loaded=subprocess.check_output([str(root/"bin/cicada")],env=env,text=True,cwd="/")
        for name in ("libssl.so.3","libcrypto.so.3"):
            rows=[line for line in loaded.splitlines() if line.strip().startswith(name+" =>")]
            self.assertEqual(len(rows),1,loaded)
            path=rows[0].split("=>",1)[1].split("(",1)[0].strip()
            self.assertEqual(pathlib.Path(path).resolve(),root/"lib"/name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
