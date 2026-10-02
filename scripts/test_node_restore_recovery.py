"""Deterministic driver checks; these do not substitute for the Docker gate."""
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import subprocess

SPEC = importlib.util.spec_from_file_location("restore_gate", Path(__file__).with_name("test-node-restore-recovery.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class RestoreDriverTests(unittest.TestCase):
    def report(self, state="NOT_RECORDED"):
        status = {key: "synthetic" for key in gate.STATUS_FIELDS}
        status.update(node_id=gate.NODE, accepted_highwater=40, operations=[{
            "operation_id":"synthetic-restored-status", "sequence":7,
            "request_digest":"a"*64, "state":state}])
        return {"restore_digest":"b"*64,"plan_digest":gate.PLAN,"agent_may_start":False,"status":status}

    def test_not_recorded_and_uncertain_remain_evidence_only(self):
        for state in ("NOT_RECORDED","UNCERTAIN","COMPLETE"):
            report=gate.bounded_status(json.dumps(self.report(state)).encode(),state)
            self.assertFalse(report["agent_may_start"])
            self.assertNotIn("safe_to_retry",report)

    def test_secret_and_unbounded_metadata_rejected(self):
        report=self.report()
        report["status"]["result"]="synthetic private payload"
        with self.assertRaises(RuntimeError): gate.bounded_status(json.dumps(report).encode(),"NOT_RECORDED")
        report=self.report();report["status"]["hub_id"]="synthetic bearer"
        with self.assertRaises(RuntimeError): gate.bounded_status(json.dumps(report).encode(),"NOT_RECORDED",[b"synthetic bearer"])
        report=self.report();report["agent_may_start"]=True
        with self.assertRaises(RuntimeError): gate.bounded_status(json.dumps(report).encode(),"NOT_RECORDED")

    def test_inventory_retains_raw_special_modes_and_advisory_locks(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"synthetic.lock";path.write_bytes(b"");path.chmod(0o400)
            before=gate.inventory(root)
            self.assertEqual(before["synthetic.lock"]["mode_raw"],stat.S_IFREG|0o400)
            path.chmod(0o600)
            self.assertNotEqual(before,gate.inventory(root))
            path.unlink();path.symlink_to("missing")
            with self.assertRaises(RuntimeError): gate.inventory(root)

    def test_cleanup_refuses_foreign_resource(self):
        instance=object.__new__(gate.Gate);instance.owner="owned"
        class Reply: stdout=b'[{"Config":{"Labels":{"cicada.synthetic.restore-validation":"foreign"}}}]'
        instance.docker=lambda *a,**kw:Reply()
        with self.assertRaises(RuntimeError): instance.verify_owned("container","foreign")

    def test_timeout_is_recorded_as_unknown_exit_and_failure(self):
        instance=object.__new__(gate.Gate)
        instance.repo=Path(".");instance.commands=[];instance.save=lambda:None
        with mock.patch.object(gate.subprocess,"run",side_effect=subprocess.TimeoutExpired(["docker","run"],1)):
            with self.assertRaises(RuntimeError): instance.run(["docker","run"],timeout=1)
        self.assertIsNone(instance.commands[0]["exit"])
        self.assertTrue(instance.commands[0]["timeout"])

    def test_every_docker_launch_has_owned_label(self):
        instance=object.__new__(gate.Gate);instance.owner="synthetic-owner"
        seen=[];instance.run=lambda args,**kw:seen.append(args)
        instance.docker("run","--rm","--network","none","synthetic-image","true")
        self.assertEqual(seen[0][2:4],["--label",gate.LABEL+"=synthetic-owner"])

    def test_cleanup_discovers_unregistered_network_and_checks_owner(self):
        for owner in ("owned","foreign"):
            instance=object.__new__(gate.Gate);instance.owner="owned";instance.resources=[]
            removed=[]
            class Reply:
                def __init__(self,data):self.stdout=data
            def docker(*args,**kw):
                if args[0]=="ps":return Reply(b"")
                if args[:2]==("network","ls"):return Reply(b"network-id\n")
                if args[:2]==("network","inspect"):
                    return Reply(json.dumps([{"Name":"synthetic-network","Labels":{gate.LABEL:owner}}]).encode())
                if args[:2]==("network","rm"):removed.append(args[2]);return Reply(b"")
                self.fail("unexpected cleanup command")
            instance.docker=docker
            if owner=="owned":
                instance.cleanup();self.assertEqual(removed,["network-id"]);self.assertEqual(instance.resources,[])
            else:
                with self.assertRaises(RuntimeError):instance.cleanup()
                self.assertEqual(removed,[])

    def test_cleanup_retains_failed_owned_reference(self):
        instance=object.__new__(gate.Gate);instance.owner="owned";instance.resources=[("container","synthetic")]
        class Reply:stdout=b""
        def docker(*args,**kw):
            if args[0]=="rm":raise RuntimeError("synthetic removal failure")
            return Reply()
        instance.docker=docker;instance.verify_owned=lambda *a:None
        with self.assertRaises(RuntimeError):instance.cleanup()
        self.assertEqual(instance.resources,[("container","synthetic")])


if __name__=="__main__":
    unittest.main()
