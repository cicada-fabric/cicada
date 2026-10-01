"""Regression checks for the native approval test's source overlay anchors."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shlex
import unittest


ROOT = Path(__file__).resolve().parent.parent
DRIVER_PATH = ROOT / "scripts" / "test-real-node-codex-approval.py"
TARGET = ROOT / "cicada-go" / "internal" / "server" / "machine_agent_approval_integration_test.go"
SPEC = importlib.util.spec_from_file_location("native_approval_driver", DRIVER_PATH)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class NativeApprovalOverlayTests(unittest.TestCase):
    def test_overlay_tracks_current_test_and_keeps_physical_resource_coverage(self) -> None:
        source = TARGET.read_text(encoding="utf-8")
        transformed = DRIVER.replaced_test_source(source)

        self.assertIn('"resources": map[string]any{"physical_resource_id": "gpu/0"}', transformed)
        self.assertIn("CICADA_NODE_RESOURCE_ID=gpu/0", transformed)
        self.assertIn("ORDINARY_SECOND_WORKER", transformed)
        self.assertIn("quarantined-resource-worker-ran", transformed)
        self.assertIn("ResourceExecutionQuarantined", transformed)
        self.assertNotIn("fakeAppServer :=", transformed)

    def test_overlay_fails_closed_if_the_native_fixture_loses_gpu_scope(self) -> None:
        source = TARGET.read_text(encoding="utf-8")
        anchor = ',"resources":{"physical_resource_id":"gpu/0"}'
        self.assertIn(anchor, source)
        altered = source.replace(anchor, "", 1)
        with self.assertRaisesRegex(ValueError, "source_anchor_missing"):
            DRIVER.replaced_test_source(altered)

    def test_overlay_fails_closed_if_the_codex_wrapper_anchor_changes(self) -> None:
        source = TARGET.read_text(encoding="utf-8")
        anchor = 'codexBin := filepath.Join(root, "fake-codex")'
        self.assertIn(anchor, source)
        altered = source.replace(anchor, 'codexBin := filepath.Join(root, "changed")', 1)
        with self.assertRaisesRegex(ValueError, "source_anchor_missing:native_codex_wrapper"):
            DRIVER.replaced_test_source(altered)

    def test_container_mount_matches_the_node_supplied_absolute_cwd(self) -> None:
        transformed = DRIVER.replaced_test_source(TARGET.read_text(encoding="utf-8"))
        self.assertIn("if !filepath.IsAbs(nativeWorkspace)", transformed)
        self.assertIn("workspaceCWD := filepath.Clean(nativeWorkspace)", transformed)
        self.assertIn('nativeWorkspace + ":" + workspaceCWD', transformed)
        self.assertIn('nativeWorkspace + ":/workspace"', transformed)
        self.assertIn('wrapper += "-v " + quote(mount) + " "', transformed)
        self.assertIn('strings.ReplaceAll(value, "\'", "\'\\\\\'\'")', transformed)

    def test_shell_quoted_cwd_mount_is_one_argument_and_does_not_expose_marker(self) -> None:
        marker = "/tmp/work space/owner's;touch SHOULD_NOT_RUN"
        mount = marker + ":" + marker
        encoded = DRIVER.shell_quote_posix(mount)
        self.assertEqual(shlex.split("-v " + encoded), ["-v", mount])
        self.assertIn("'\\''", encoded)

    def test_failure_stage_is_reduced_to_a_fixed_enum(self) -> None:
        self.assertEqual(DRIVER.classify_go_test_stage("stage=native_approval_not_observed"),
                         "native_approval_not_observed")
        self.assertEqual(DRIVER.classify_go_test_stage(
            "stage=provider-secret-key\nraw token payload"), "go_test_or_compile")


if __name__ == "__main__":
    unittest.main()
