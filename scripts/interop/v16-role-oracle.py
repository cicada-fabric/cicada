#!/usr/bin/env python3
"""Check the exact authenticated Android v1.6.1 role against an independent oracle.

Reuse the bounded in-memory state reader; no private state or ciphertext is
saved. The three regroup operations remain subject to their dedicated review
and consent API, even when present in the authenticated operation set.
"""
import importlib.util
import os
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = load('v15_role_oracle_for_v16', 'v15-role-oracle.py')
runner = load('v16_runner_for_role_oracle', 'v16-android-deterministic.py')
oracle.CONTRACT = oracle.ROOT / 'contracts/client-hub-v1.6.1-fe565b4'
oracle.CONTRACT_MANIFEST = oracle.CONTRACT / 'manifest.json'
oracle.CATALOG = oracle.CONTRACT / 'cicada-go/internal/clientcontract/catalog.json'
oracle.CONTRACT_REVISION = 'client-hub-v1.6.1'
oracle.CATALOG_SHA256 = '6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b'
oracle.CORE_REVISION = 'fe565b41bb1aa86d400a0ec98c528c856d0b9579'
regroup = {'topology.regroup_proposal', 'topology.delegation_issue', 'topology.delegation_revoke'}
oracle.LOCAL_IMPLEMENTED |= regroup | {
    'network.directory', 'topology.endpoint_admission_preview', 'link.review_policy_status',
}
oracle.DEFERRED_CONSENT = (oracle.DEFERRED_CONSENT - regroup) | {
    'space.foreign_endpoint_preview', 'network.collaboration_key_manifest',
    'network.collaboration_key_grant', 'network.collaboration_key_status',
    'link.review_policy_preview', 'link.review_policy_grant',
}
oracle.EXPECTED_COUNTS = (39, 39, 31)
oracle.SCHEMA = 'cicada.client-v161-role-oracle.v1'
oracle.load_runner = lambda: runner


if __name__ == '__main__':
    os.umask(0o077)
    oracle.main()
