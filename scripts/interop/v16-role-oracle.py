#!/usr/bin/env python3
"""Check the exact authenticated Android v1.6 role against an independent oracle.

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
oracle.CONTRACT = oracle.ROOT / 'contracts/client-hub-v1.6-4fb241b'
oracle.CONTRACT_MANIFEST = oracle.CONTRACT / 'manifest.json'
oracle.CATALOG = oracle.CONTRACT / 'cicada-go/internal/clientcontract/catalog.json'
oracle.CONTRACT_REVISION = 'client-hub-v1.6'
oracle.CATALOG_SHA256 = '1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c'
oracle.CORE_REVISION = '4fb241b5e824eb752ceb85586089f44c408e1e7e'
regroup = {'topology.regroup_proposal', 'topology.delegation_issue', 'topology.delegation_revoke'}
oracle.LOCAL_IMPLEMENTED |= regroup | {'network.directory', 'topology.endpoint_admission_preview'}
oracle.DEFERRED_CONSENT = (oracle.DEFERRED_CONSENT - regroup) | {
    'space.foreign_endpoint_preview', 'network.collaboration_key_manifest',
    'network.collaboration_key_grant', 'network.collaboration_key_status',
    'link.review_policy_manifest', 'link.review_policy_grant', 'link.review_policy_status',
}
oracle.EXPECTED_COUNTS = (38, 38, 30)
oracle.SCHEMA = 'cicada.client-v16-role-oracle.v1'
oracle.load_runner = lambda: runner


if __name__ == '__main__':
    os.umask(0o077)
    oracle.main()
