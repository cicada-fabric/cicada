"""Deterministic driver checks; executing these is not disposable TCP evidence."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("hub_forward_gate", Path(__file__).with_name("test-hub-restore-activation.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class HubForwardDriverTests(unittest.TestCase):
    def test_inventory_preserves_exact_bytes_modes_and_holds(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root)/".hub-restore-pending.json"
            marker.write_bytes(b"SYNTHETIC held lineage"); marker.chmod(0o600)
            before=gate.inventory(root)
            self.assertEqual(before[marker.name]["mode_raw"], stat.S_IFREG|0o600)
            marker.chmod(0o400)
            self.assertNotEqual(before,gate.inventory(root))
            marker.unlink();marker.symlink_to("missing")
            with self.assertRaises(RuntimeError):gate.inventory(root)

    def test_rejection_cannot_be_success_or_public_status(self):
        instance=object.__new__(gate.Gate)
        for code,output in ((0,b""),(1,b'{"activated":true}')):
            reply=subprocess.CompletedProcess([],code,stdout=output,stderr=b"synthetic refusal")
            with self.assertRaises(RuntimeError):instance.reject(reply)
        instance.reject(subprocess.CompletedProcess([],1,stdout=b"",stderr=b"AUTHORITY_UNPROVEN"))

    def test_timeout_records_unknown_exit(self):
        instance=object.__new__(gate.Gate);instance.repo=Path(".");instance.commands=[];instance.save=lambda:None
        with mock.patch.object(gate.subprocess,"run",side_effect=subprocess.TimeoutExpired(["docker","exec"],1)):
            with self.assertRaises(RuntimeError):instance.run(["docker","exec"],timeout=1)
        self.assertIsNone(instance.commands[0]["exit"])
        self.assertTrue(instance.commands[0]["timeout"])

    def test_every_container_launch_is_owned(self):
        instance=object.__new__(gate.Gate);instance.owner="synthetic-owner"
        seen=[];instance.run=lambda args,**kw:seen.append(args)
        instance.docker("run","--rm","--network","none","synthetic-image","true")
        self.assertEqual(seen[0][2:4],["--label",gate.LABEL+"=synthetic-owner"])

    def test_cleanup_refuses_foreign_resources(self):
        instance=object.__new__(gate.Gate);instance.owner="owned"
        instance.docker=lambda *args,**kw:subprocess.CompletedProcess([],0,stdout=json.dumps([{"Id":"synthetic","Config":{"Labels":{gate.LABEL:"foreign"}}}]).encode())
        with self.assertRaises(RuntimeError):instance.verify_owned("container","synthetic")

    def test_launch_has_no_credentials_or_runtime_mount(self):
        instance=object.__new__(gate.Gate)
        instance.binary=Path("/synthetic/cicada");instance.fixture=Path("/synthetic/fixture.test");instance.image="synthetic-image";instance.resources=[]
        calls=[];instance.docker=lambda *a,**k:calls.append(a)
        instance.launch("owned","owned-internal",Path("/synthetic/private"),["sleep","infinity"])
        args=calls[0]
        mounts=[args[i+1] for i,value in enumerate(args[:-1]) if value=="-v"]
        self.assertEqual(len(mounts),3)
        self.assertTrue(all("/synthetic/" in mount for mount in mounts))
        self.assertIn("--cap-drop",args);self.assertIn("no-new-privileges",args)
        self.assertNotIn("--privileged",args)

    def test_fixture_selector_and_paths_are_explicit(self):
        instance=object.__new__(gate.Gate);seen=[];instance.docker=lambda *a,**kw:seen.append(a)
        instance.fixture_call("owned-runner","probe","T",4,"http://owned-target:8787")
        args=seen[0]
        self.assertIn(gate.SELECTOR,args)
        self.assertIn("CICADA_SYNTHETIC_HUB_FORWARD_STATE=/synthetic/T",args)
        self.assertIn("CICADA_SYNTHETIC_HUB_FORWARD_NEXT=4",args)


if __name__ == "__main__":
    unittest.main()
