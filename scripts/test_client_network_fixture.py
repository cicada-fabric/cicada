"""Focused tests for Client Network fixture image pinning and safe defaults."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/client-network-fixture.sh"
CATALOG = ROOT / "cicada-go/internal/clientcontract/catalog.json"


class ClientNetworkFixtureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cicada-client-network-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog_bytes = CATALOG.read_bytes()
        self.catalog = json.loads(self.catalog_bytes)
        self.image_id = "sha256:" + "a" * 64
        self.revision = "b" * 40
        self.fingerprint = "c" * 64
        self.catalog_sha = hashlib.sha256(self.catalog_bytes).hexdigest()
        self.metadata = {
            "schema_version": "cicada.hub-build.v1",
            "source": {
                "revision": self.revision,
                "dirty": False,
                "source_fingerprint": self.fingerprint,
                "catalog_sha256": self.catalog_sha,
            },
            "image": {
                "reference": "cicada-fixture-test:unit",
                "id": self.image_id,
                "dockerfile": "docker/Dockerfile.hub",
            },
        }
        self.metadata_path = self.root / "build.json"
        self.write_metadata()

    def write_metadata(self):
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")

    def run_script(self, *args, path=None):
        env = dict(os.environ)
        if path is not None:
            env["PATH"] = str(path) + os.pathsep + env["PATH"]
        return subprocess.run(
            [str(SCRIPT), *map(str, args)], cwd=ROOT, env=env,
            text=True, capture_output=True, check=False,
        )

    def test_legacy_unpinned_setup_is_rejected(self):
        result = self.run_script("setup")
        self.assertEqual(result.returncode, 2)
        self.assertIn("setup --build-metadata PATH", result.stderr)

    def test_dirty_build_metadata_is_rejected_before_docker(self):
        self.metadata["source"]["dirty"] = True
        self.write_metadata()
        result = self.run_script("setup", "--build-metadata", self.metadata_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("metadata is dirty", result.stderr)

    def test_image_label_mismatch_is_rejected(self):
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        fake_docker = fake_bin / "docker"
        fake_docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "if sys.argv[1:] == ['info']:\n    raise SystemExit(0)\n"
            "if sys.argv[1:3] == ['image', 'inspect']:\n"
            " print(json.dumps([{'Id':'" + self.image_id + "','Architecture':'amd64',"
            "'Config':{'Labels':{'org.opencontainers.image.revision':'" + self.revision + "',"
            "'org.cicada.build.dirty':'false','org.cicada.build.source-fingerprint':'" + "d" * 64 + "',"
            "'org.cicada.client-catalog.sha256':'" + self.catalog_sha + "','org.cicada.role':'hub'}}}]))\n"
            " raise SystemExit(0)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        result = self.run_script("setup", "--build-metadata", self.metadata_path, path=fake_bin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provenance labels differ", result.stderr)

    def test_catalog_digest_mismatch_is_rejected(self):
        self.metadata["source"]["catalog_sha256"] = "0" * 64
        self.write_metadata()
        result = self.run_script("setup", "--build-metadata", self.metadata_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authoritative catalog", result.stderr)


if __name__ == "__main__":
    unittest.main()
