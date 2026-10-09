"""Deterministic, synthetic tests for current Native source binding."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import io
import contextlib
import types
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import request_observer_binding as binding
import request_observer_run as run
import request_observer_gate as gate


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


class CurrentBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-current-binding-")
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.repo = self.root / "repo"
        self.bindings = self.evidence / "bindings"
        self.output = self.bindings / "bundle-a12345678"
        self.cli = self.evidence / "official" / "codex"
        self.cli.parent.mkdir(parents=True)
        self.cli.write_bytes(b"PUBLIC_SYNTHETIC_CODEX_ASSET")
        self.cli_sha = hashlib.sha256(self.cli.read_bytes()).hexdigest()
        self.commit = "a" * 40
        self.binary_sha = "b" * 64
        self.compiled_sha = "c" * 64
        self.runtime_id = "sha256:" + "d" * 64
        self.delivery_path = self.evidence / "delivery.NONAUTH.json"
        self.equality_path = self.evidence / "equality.NONAUTH.json"
        self.runtime_path = self.evidence / "runtime.NONAUTH.json"
        _write_json(self.delivery_path, {
            "source_repo": str(self.repo),
            "commit": self.commit,
            "source_dirty": True,
            "fingerprint": "e" * 64,
            "binary_sha256": self.binary_sha,
            "compiled_input_equality_receipt": str(self.equality_path),
        })
        _write_json(self.equality_path, {
            "status": "COMPILED_INPUTS_EXACT",
            "current_commit": self.commit,
            "product_artifact_origin_revision": self.commit,
            "product_artifact_origin_dirty": True,
            "source_dirty": True,
            "artifact_binary_sha256": self.binary_sha,
            "artifact_compiled_inputs_sha256": self.compiled_sha,
            "current_compiled_inputs_sha256": self.compiled_sha,
        })
        _write_json(self.runtime_path, {
            "schema": binding.RUNTIME_SCHEMA,
            "status": "PASS_PINNED_CLI_IMAGE_OVERLAY",
            "base_runtime_image_id": binding.BASE_RUNTIME_IMAGE_ID,
            "runtime_image_id": self.runtime_id,
            "cli_version": binding.CLI_VERSION,
            "cli_path": str(self.cli),
            "cli_sha256": self.cli_sha,
            "overlay_mode": "PINNED_CLI_IMAGE_OVERLAY",
        })
        self.patches = (
            patch.object(binding, "EVIDENCE_ROOT", self.evidence),
            patch.object(binding, "BINDING_ROOT", self.bindings),
            patch.object(binding, "REPOSITORY_ROOT", self.repo),
            patch.object(binding, "CLI_BINARY", self.cli),
            patch.object(binding, "CLI_SHA256", self.cli_sha),
        )
        for active in self.patches:
            active.start()

    def tearDown(self) -> None:
        for active in reversed(self.patches):
            active.stop()
        self.temp.cleanup()

    def test_current_pair_and_cli_overlay_are_bound(self) -> None:
        result = binding.current_bundle(self.delivery_path, self.equality_path,
                                        self.runtime_path, self.output, self.commit)
        self.assertEqual(result["current_commit"], self.commit)
        self.assertEqual(result["runtime_receipt"]["image_id"], self.runtime_id)
        self.assertEqual(result["official_cli"]["sha256"], self.cli_sha)

    def test_mismatched_expected_commit_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "CURRENT_DELIVERY_PROVENANCE"):
            binding.current_bundle(self.delivery_path, self.equality_path,
                                   self.runtime_path, self.output, "f" * 40)

    def test_compiled_equality_and_dirty_state_must_match_delivery(self) -> None:
        equality = json.loads(self.equality_path.read_text())
        equality["artifact_compiled_inputs_sha256"] = "f" * 64
        _write_json(self.equality_path, equality)
        with self.assertRaisesRegex(ValueError, "CURRENT_COMPILED_INPUT_EQUALITY"):
            binding.current_bundle(self.delivery_path, self.equality_path,
                                   self.runtime_path, self.output, self.commit)
        equality["artifact_compiled_inputs_sha256"] = self.compiled_sha
        equality["product_artifact_origin_dirty"] = False
        _write_json(self.equality_path, equality)
        with self.assertRaisesRegex(ValueError, "CURRENT_DIRTY_STATE_MISMATCH"):
            binding.current_bundle(self.delivery_path, self.equality_path,
                                   self.runtime_path, self.output, self.commit)

    def test_binding_rejects_changed_candidate_and_alias(self) -> None:
        candidate_root = self.repo / "candidate"
        candidate_root.mkdir(parents=True)
        candidate = candidate_root / "run.py"
        candidate.write_text("PUBLIC_SYNTHETIC_SOURCE\n", encoding="utf-8")
        bundle = binding.current_bundle(self.delivery_path, self.equality_path,
                                        self.runtime_path, self.output, self.commit)
        source_paths = [self.delivery_path, self.equality_path, self.runtime_path,
                        self.cli, candidate]
        rows = [binding.file_row(path) for path in source_paths]
        by_path = {row["path"]: {key: row[key] for key in ("sha256", "bytes", "rawmode")}
                   for row in rows}
        bound = {
            "schema": binding.SCHEMA,
            "authority": "NONAUTH",
            "output_parent": str(self.output),
            "current_bundle": bundle,
            "candidate_root": str(candidate_root),
            "candidate_files": {"run.py": by_path[str(candidate)]},
            "files": rows,
            "public_files": by_path,
            "effective_sources": {name: "1" * 64 for name in
                                  ("audit", "bootstrap", "command", "gate", "provider")},
        }
        path, sha = binding.write_binding_pair(bound, self.output)
        required = set(by_path)
        raw = path.read_bytes()
        binding.validate_bundle_binding(bound, binding_raw=raw, binding_path=path,
                                        expected_sha256=sha, required_paths=required,
                                        candidate_names=("run.py",))
        alias = self.output / "source-binding.json"
        alias.write_bytes(b"PUBLIC_SYNTHETIC_ALIAS_MISMATCH")
        with self.assertRaisesRegex(ValueError, "CURRENT_BINDING_ALIAS"):
            binding.validate_bundle_binding(bound, binding_raw=raw, binding_path=path,
                                            expected_sha256=sha, required_paths=required,
                                            candidate_names=("run.py",))
        alias.write_bytes(raw)
        candidate.write_text("PUBLIC_SYNTHETIC_SOURCE_CHANGED\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "CURRENT_BINDING_FILE_CHANGED"):
            binding.validate_bundle_binding(bound, binding_raw=raw, binding_path=path,
                                            expected_sha256=sha, required_paths=required,
                                            candidate_names=("run.py",))


class CurrentCommandTests(unittest.TestCase):
    def test_preflight_uses_explicit_current_binding_file_and_sha(self) -> None:
        binding_path = "/tmp/current-bundle/binding.NONAUTH.json"
        binding_sha = "a" * 64
        output = io.StringIO()
        with patch.object(run, "preflight", return_value={"status": "SYNTHETIC"}) as preflight, \
                contextlib.redirect_stdout(output):
            self.assertEqual(run.main(["--preflight", "--binding-file", binding_path,
                                       "--binding-sha", binding_sha]), 0)
        preflight.assert_called_once_with(binding_sha, binding_path)
        self.assertEqual(json.loads(output.getvalue()), {"status": "SYNTHETIC"})


class NativeBudgetTests(unittest.TestCase):
    def native_args(self, seconds=None):
        return types.SimpleNamespace(native_https=True, execute_diagnostic=True,
            scenario="g2-g3", prepare_native_zero=False, enable_io_diagnostics=False,
            response_byte_passthrough=False, native_normal_seconds=seconds)

    def test_native_budget_defaults_to_180_seconds(self) -> None:
        args = self.native_args()
        self.assertEqual(run.native_normal_seconds(args), 180)
        self.assertEqual(run.native_phase_budget(run.native_normal_seconds(args)), {
            "normal_seconds":180,"terminal_seconds":30,"cleanup_seconds":30,"total_seconds":240})

    def test_native_budget_accepts_explicit_600_seconds(self) -> None:
        args = self.native_args(600)
        self.assertEqual(run.native_normal_seconds(args), 600)
        self.assertEqual(run.native_phase_budget(run.native_normal_seconds(args)), {
            "normal_seconds":600,"terminal_seconds":30,"cleanup_seconds":30,"total_seconds":660})

    def test_native_budget_rejects_out_of_range_and_non_native_override(self) -> None:
        for seconds in (179, 601):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(PermissionError, "NATIVE_NORMAL_SECONDS"):
                run.native_normal_seconds(self.native_args(seconds))
        args = self.native_args(600)
        args.native_https = False
        with self.assertRaisesRegex(PermissionError, "NATIVE_NORMAL_SECONDS_LANE"):
            run.native_normal_seconds(args)

    def test_native_budget_rejects_bool(self) -> None:
        with self.assertRaisesRegex(PermissionError, "NATIVE_NORMAL_SECONDS"):
            run.native_normal_seconds(self.native_args(True))


class NativeProviderLifetimeTests(unittest.TestCase):
    @staticmethod
    def synthetic_binding(lifetime: int, *, max_connections: int = 16, max_active: int = 4) -> dict:
        run_id = "cicada-two-turn-synthetic000001"
        return {
            "run_id": run_id,
            "network_id": "a" * 64,
            "network_name": run_id + "-a-net",
            "network_label": run_id,
            "driver": "bridge",
            "subnet": "10.0.0.0/29",
            "gateway": "10.0.0.1",
            "clients": ["10.0.0.2"],
            "lifetime": lifetime,
            "max_connections": max_connections,
            "max_active": max_active,
            "upstream_host": "127.0.0.1",
            "upstream_port": 7890,
        }

    @staticmethod
    def synthetic_network(record: dict) -> dict:
        return {
            "Id": record["network_id"],
            "Name": record["network_name"],
            "Driver": "bridge",
            "Labels": {"org.cicada.test.run": record["run_id"]},
            "IPAM": {"Config": [{"Subnet": record["subnet"], "Gateway": record["gateway"]}]},
            "Containers": {"synthetic": {"IPv4Address": "10.0.0.2/29"}},
        }

    @staticmethod
    def transport(seconds: int) -> dict:
        module = gate.safe_module("synthetic_provider_transport",
                                  gate.OLD / "provider_transport.py")
        namespace = module.__dict__
        source = gate.provider_transport_source(seconds)
        exec(compile(source, "<synthetic-provider-transport>", "exec"), namespace)
        return namespace

    def test_default_adapter_retains_240_second_ceiling(self) -> None:
        namespace = self.transport(180)
        record = self.synthetic_binding(240)
        adapter = namespace["Forwarder"](record, self.synthetic_network(record), clock=lambda: 1.0)
        self.assertEqual(adapter.binding["lifetime"], 240)
        with self.assertRaisesRegex(ValueError, "bounded lifetime"):
            namespace["validate_binding"](self.synthetic_binding(241))

    def test_native_600_adapter_accepts_600_and_rejects_601(self) -> None:
        namespace = self.transport(600)
        record = self.synthetic_binding(600)
        adapter = namespace["Forwarder"](record, self.synthetic_network(record), clock=lambda: 1.0)
        self.assertEqual(adapter.binding["lifetime"], 600)
        with self.assertRaisesRegex(ValueError, "bounded lifetime"):
            namespace["validate_binding"](self.synthetic_binding(601))

    def test_native_lifetime_extension_preserves_connection_and_active_caps(self) -> None:
        validate = self.transport(600)["validate_binding"]
        for record in (self.synthetic_binding(600, max_connections=17),
                       self.synthetic_binding(600, max_active=5)):
            with self.subTest(record={key: record[key] for key in ("max_connections", "max_active")}), \
                    self.assertRaisesRegex(ValueError, "bounded"):
                validate(record)

    def test_transformed_forwarder_retains_pinned_module_origin(self) -> None:
        namespace = self.transport(600)
        module_name = namespace["Forwarder"].__module__
        self.assertEqual(module_name, "synthetic_provider_transport")
        module = sys.modules[module_name]
        self.assertEqual(Path(module.__file__).resolve(), gate.OLD / "provider_transport.py")

    def test_budget_specific_provider_source_is_attested(self) -> None:
        default = gate.effective_sources(180)["provider"]
        extended = gate.effective_sources(600)["provider"]
        self.assertIn("lifetime_ceiling=240", default)
        self.assertIn("lifetime_ceiling=600", extended)
        self.assertNotEqual(hashlib.sha256(default.encode()).hexdigest(),
                            hashlib.sha256(extended.encode()).hexdigest())


class CurrentComponentSelectionTests(unittest.TestCase):
    def test_go_list_selection_uses_only_current_main_module_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-g2-list-") as temporary:
            root = Path(temporary)
            module_root = root / "cicada-go"
            package_dir = module_root / "internal" / "example"
            package_dir.mkdir(parents=True)
            package = {
                "Dir": str(package_dir),
                "Module": {"Path": run.G2_CURRENT_MODULE_PATH, "Main": True},
                "GoFiles": ["example.go"],
                "EmbedFiles": ["fixture.txt"],
            }
            dependency = {
                "Dir": str(root / "modcache" / "example"),
                "Module": {"Path": "example.invalid/dep", "Main": False},
                "GoFiles": ["dep.go"],
            }
            stream = root / "go-list.json"
            stream.write_text(json.dumps(package) + "\n" + json.dumps(dependency) + "\n", encoding="utf-8")
            selected = run.g2_current_go_sources(stream, source_root=module_root, go_list_root=module_root)
            self.assertEqual(selected, {str(package_dir / "example.go"), str(package_dir / "fixture.txt")})

    def test_component_source_must_match_the_product_inventory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synthetic-g2-row-") as temporary:
            repo = Path(temporary)
            source_root = repo / "cicada-go"
            source = source_root / "internal" / "example.go"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"package example\n")
            with patch.object(run, "G2_SOURCE_ROOT", source_root), \
                    patch.object(run, "G2_CURRENT_SOURCE_ROOT", source_root), \
                    patch.object(run, "G2_CURRENT_REPOSITORY_ROOT", repo):
                row = binding.file_row(source)
                row["rawmode"] = int(row["rawmode"], 8)
                inventory = {"cicada-go/internal/example.go": {
                    "content_sha256": row["sha256"], "size_bytes": row["bytes"],
                    "raw_mode": oct(row["rawmode"]),
                }}
                run.g2_current_source_row(row, inventory=inventory)
                inventory["cicada-go/internal/example.go"]["content_sha256"] = "0" * 64
                with self.assertRaisesRegex(PermissionError, "G2_CURRENT_SOURCE_INVENTORY_ROW"):
                    run.g2_current_source_row(row, inventory=inventory)

    @unittest.skipUnless(
        (run.G2_CURRENT_EVIDENCE_ROOT / "current-peer-product-0162-20261009a" / "actual-delivery.NONAUTH.json").is_file(),
        "current product proof is not present in this workspace",
    )
    def test_emitted_current_component_proof_and_tampered_equality(self) -> None:
        root = run.G2_CURRENT_EVIDENCE_ROOT / "current-peer-product-0162-20261009a"
        delivery = json.loads((root / "actual-delivery.NONAUTH.json").read_text(encoding="utf-8"))
        equality = json.loads(Path(delivery["compiled_input_equality_receipt"]).read_text(encoding="utf-8"))
        self.assertEqual(run.g2_current_component_inputs(delivery, equality), delivery["component_proof_sha256"])
        altered = dict(equality, current_compiled_inputs_sha256="0" * 64)
        with self.assertRaisesRegex(PermissionError, "G2_CURRENT_PRODUCT_EQUALITY"):
            run.g2_current_component_inputs(delivery, altered)

    def test_refresh_dispatch_requires_explicit_current_inputs(self) -> None:
        output = io.StringIO()
        with patch.object(run, "refresh_current_binding", return_value={"status": "SYNTHETIC"}) as refresh, \
                contextlib.redirect_stdout(output):
            self.assertEqual(run.main([
                "--refresh-current-binding", "--delivery", "/tmp/delivery.json",
                "--compiled-input-equality", "/tmp/equality.json",
                "--runtime-image-receipt", "/tmp/runtime.json",
                "--expected-commit", "b" * 40,
                "--output-parent", "/tmp/request-observer-current-0162/bundle-a12345678",
            ]), 0)
        refresh.assert_called_once_with("/tmp/delivery.json", "/tmp/equality.json",
                                        "/tmp/runtime.json",
                                        "/tmp/request-observer-current-0162/bundle-a12345678",
                                        "b" * 40)
        self.assertEqual(json.loads(output.getvalue()), {"status": "SYNTHETIC"})


if __name__ == "__main__":
    unittest.main()
