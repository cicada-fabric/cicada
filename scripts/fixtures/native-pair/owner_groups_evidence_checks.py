#!/usr/bin/env python3
"""Pure synthetic receipt mutations. No product, crypto, Docker or Host runs.

Usage: python3 scripts/fixtures/native-pair/owner_groups_evidence_checks.py NEW_DIR
The positive controls validate only the receipt classifier; they are NOT_RUN
for M1-M8. Temporary synthetic aggregate receipts are deleted after each check.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True


def run(output):
    os.umask(0o077)
    output.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[2] / 'native_pair_evidence.py'
    spec = importlib.util.spec_from_file_location('synthetic_owner_groups_oracle', source)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    plan = oracle.owner_groups_inputs()
    facts = [{'test': oracle.OWNER_GROUPS_PARENT + '/' + c['id'],
              'measurement': {'case': c['id'], 'observed': dict.fromkeys(c['observations'], True)}}
             for c in plan['cases']]
    expected = {oracle.OWNER_GROUPS_PARENT} | {f['test'] for f in facts}
    results, counts = dict.fromkeys(expected, 'pass'), dict.fromkeys(expected, 1)
    checks = []

    def check(name, actual, wanted):
        assert actual == wanted, 'SYNTHETIC_ORACLE_MISMATCH_' + name
        checks.append({'case': name, 'expected': wanted, 'observed': actual})

    check('SYNTHETIC_fact_control_NOT_PRODUCT', oracle.valid_owner_groups_facts(facts, results, counts), True)
    for index, fact in enumerate(facts):
        for field in fact['measurement']['observed']:
            value = copy.deepcopy(facts)
            value[index]['measurement']['observed'][field] = False
            check('false_' + field, oracle.valid_owner_groups_facts(value, results, counts), False)
        value = copy.deepcopy(facts)
        value[index]['measurement']['observed'][next(iter(value[index]['measurement']['observed']))] = 1
        check('non_boolean_' + str(index), oracle.valid_owner_groups_facts(value, results, counts), False)
    check('missing_case', oracle.valid_owner_groups_facts(facts[:-1], results, counts), False)
    check('duplicate_case', oracle.valid_owner_groups_facts(facts[:-1] + facts[:1], results, counts), False)
    check('no_test_execution', oracle.valid_owner_groups_facts(facts, {}, {}), False)
    value = dict(counts)
    value[oracle.OWNER_GROUPS_PARENT] = 2
    check('duplicate_terminal', oracle.valid_owner_groups_facts(facts, results, value), False)

    lease = {'clock': 'REAL_WALL_AND_MONOTONIC', 'source': 'G2_OWNER_EXPLICIT',
             'baseline_at': '2026-10-26T00:00:00Z', 'original_lease_expires_at': '2026-10-26T00:05:00Z',
             'after_boundary_at': '2026-10-26T00:05:01Z', 'renewed_lease_expires_at': '2026-10-26T00:10:00Z',
             'monotonic_elapsed_seconds': 301}
    check('SYNTHETIC_lease_control_NOT_ELAPSED', oracle.valid_owner_groups_lease(lease), True)
    for field in lease:
        value = copy.deepcopy(lease)
        del value[field]
        check('missing_lease_' + field, oracle.valid_owner_groups_lease(value), False)
    for field, item in [('clock', 'SYNTHETIC_ADVANCED_CLOCK'), ('source', 'DEFAULT_POLICY'),
                        ('monotonic_elapsed_seconds', True), ('monotonic_elapsed_seconds', 0),
                        ('monotonic_elapsed_seconds', float('nan')), ('monotonic_elapsed_seconds', 1),
                        ('after_boundary_at', '2026-10-26T00:04:59Z'),
                        ('renewed_lease_expires_at', '2026-10-26T00:05:01Z')]:
        value = copy.deepcopy(lease)
        value[field] = item
        check('invalid_lease_' + field + '_' + str(item), oracle.valid_owner_groups_lease(value), False)

    actors = [{'native_session_id': '00000000-0000-4000-8000-00000000000' + str(i),
               'endpoint_id': 'SYNTHETIC_ENDPOINT_' + str(i), 'principal_id': 'SYNTHETIC_PRINCIPAL',
               'workspace': '/SYNTHETIC_NOT_A_NATIVE_RECORD', 'node_id': 'SYNTHETIC_NODE',
               'binding_id': 'SYNTHETIC_BINDING_' + str(i), 'binding_epoch': 1,
               'endpoint_public_key_sha256': hashlib.sha256(('SYNTHETIC_NOT_A_KEY_' + str(i)).encode()).hexdigest()}
              for i in range(4)]
    identities = {'before': actors, 'after_group_operations': copy.deepcopy(actors)}
    check('SYNTHETIC_identity_control_NOT_NATIVE', oracle.valid_owner_groups_identities(identities), True)
    for field in actors[0]:
        value = copy.deepcopy(identities)
        value['after_group_operations'][0][field] = 2 if field == 'binding_epoch' else 'SYNTHETIC_CHANGED'
        check('changed_identity_' + field, oracle.valid_owner_groups_identities(value), False)
    value = copy.deepcopy(identities)
    value['before'][0]['binding_epoch'] = value['after_group_operations'][0]['binding_epoch'] = True
    check('boolean_epoch', oracle.valid_owner_groups_identities(value), False)
    value = copy.deepcopy(identities)
    value['before'][1] = value['before'][0]
    value['after_group_operations'][1] = value['after_group_operations'][0]
    check('merged_native_actors', oracle.valid_owner_groups_identities(value), False)

    base = {'events': [{'Test': n, 'Action': 'pass'} for n in sorted(expected)],
            'facts': facts, 'lease': lease, 'identities': identities,
            'exits': dict.fromkeys(('version', 'compile-cli', 'compile-tests', 'harness', 'vet'), 0),
            'source_drift': False, 'binary_drift': False, 'owned': 'false', 'runtime_pinned': True,
            'extra_lines': []}
    mutations = [
        ('SYNTHETIC_aggregate_control_NOT_PRODUCT', lambda x: None, 0),
        ('empty_execution', lambda x: x.update(events=[]), 1),
        ('duplicate_execution', lambda x: x['events'].append(copy.deepcopy(x['events'][0])), 1),
        ('missing_facts', lambda x: x.update(facts=[]), 1),
        ('missing_lease', lambda x: x.update(lease=None), 1),
        ('missing_original_identities', lambda x: x.update(identities=None), 1),
        ('source_drift', lambda x: x.update(source_drift=True), 1),
        ('binary_drift', lambda x: x.update(binary_drift=True), 1),
        ('owned_container_remains', lambda x: x.update(owned='true'), 1),
        ('Docker_unavailable_not_absence', lambda x: x.update(owned='UNKNOWN'), 1),
        ('unreviewed_runtime', lambda x: x.update(runtime_pinned=False), 1),
        ('truncated_json_stream', lambda x: x['extra_lines'].append('{'), 1),
        ('duplicate_lease', lambda x: x['extra_lines'].append(json.dumps({'Test': oracle.OWNER_GROUPS_PARENT + '/M5_IndependentRealLease', 'Action': 'output', 'Output': 'OWNER_GROUPS_LEASE ' + json.dumps(lease)})), 1),
        ('skip_is_not_pass', lambda x: x.update(events=[{'Test': oracle.OWNER_GROUPS_PARENT, 'Action': 'skip'}]), 1),
    ]
    for stage in base['exits']:
        mutations.append((stage + '_failed', lambda x, s=stage: x['exits'].update({s: 1}), 1))

    for name, mutate, wanted in mutations:
        value = copy.deepcopy(base)
        mutate(value)
        with tempfile.TemporaryDirectory(prefix='SYNTHETIC_NOT_PRODUCT-', dir=output) as scratch:
            scratch = Path(scratch)
            evidence, artifacts = scratch / 'evidence', scratch / 'artifacts'
            evidence.mkdir()
            artifacts.mkdir()
            source_before = {'head': 'SYNTHETIC_NOT_A_GIT_REVISION', 'dirty': False,
                             'harness_head': 'SYNTHETIC_NOT_A_GIT_REVISION', 'harness_dirty': False,
                             'source_root': '/SYNTHETIC_NOT_A_PRODUCT', 'harness_root': '/SYNTHETIC_NOT_A_DRIVER',
                             'manifest_sha256': '0' * 64,
                             'external_runtime_tools': {'codex': {'sha256': oracle.DIRECT_IP_CODEX_SHA256 if value['runtime_pinned'] else '0' * 64,
                                                                 'version': oracle.DIRECT_IP_CODEX_VERSION}}}
            source_after = copy.deepcopy(source_before)
            if value['source_drift']:
                source_after['manifest_sha256'] = '1' * 64
            for side, data in [('before', source_before), ('after', source_after)]:
                (evidence / ('source-' + side + '.json')).write_text(json.dumps(data))
            binaries = {}
            for binary in ('cicada', 'n3.test'):
                raw = b'SYNTHETIC_NOT_EXECUTED_' + binary.encode()
                (artifacts / binary).write_bytes(raw)
                binaries[binary] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            for side in ('before', 'after'):
                data = copy.deepcopy(binaries)
                if side == 'after' and value['binary_drift']:
                    data['cicada']['sha256'] = '0' * 64
                (evidence / ('binaries-' + side + '.json')).write_text(json.dumps(data))
            events = copy.deepcopy(value['events'])
            events += [{'Test': f['test'], 'Action': 'output', 'Output': 'OWNER_GROUPS_FACTS ' + json.dumps(f['measurement'])}
                       for f in value['facts']]
            for marker, item, test in [('OWNER_GROUPS_LEASE ', value['lease'], oracle.OWNER_GROUPS_PARENT + '/M5_IndependentRealLease'),
                                       ('OWNER_GROUPS_IDENTITIES ', value['identities'], oracle.OWNER_GROUPS_PARENT)]:
                if item is not None:
                    events.append({'Test': test, 'Action': 'output', 'Output': marker + json.dumps(item)})
            (evidence / 'harness.log').write_text('\n'.join([json.dumps(e) for e in events] + value['extra_lines']) + '\n')
            for stage, code in value['exits'].items():
                (evidence / (stage + '.exit')).write_text(str(code))
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    oracle.finish(evidence, artifacts, 'SYNTHETIC_NOT_A_DOCKER_IMAGE', value['owned'], 'owner-endpoint-groups')
                except SystemExit as e:
                    actual = e.code
            check(name, actual, wanted)

    result = {'scope': 'SYNTHETIC_RECEIPT_ORACLE_ONLY_NOT_PRODUCT', 'status': 'ORACLE_PASS', 'exit_code': 0,
              'product_status': 'NOT_RUN', 'cases': len(checks), 'checks': checks,
              'driver_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'inputs_sha256': hashlib.sha256(oracle.OWNER_GROUPS_INPUTS.read_bytes()).hexdigest(),
              'no_crypto_Hub_Node_App_Host_Docker_or_model_executed': True}
    (output / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(f'Synthetic Owner Groups oracle cases={len(checks)} exit=0 product=NOT_RUN evidence={output / "result.json"}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: owner_groups_evidence_checks.py NEW_DIR')
    run(Path(sys.argv[1]))
