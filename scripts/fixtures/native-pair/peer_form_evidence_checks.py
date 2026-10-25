#!/usr/bin/env python3
"""Synthetic receipt-oracle mutations only; never product acceptance evidence.

Usage: python3 scripts/fixtures/native-pair/peer_form_evidence_checks.py NEW_DIR
No crypto, Host, Hub, App, Node, model, Docker or native daemon is executed.
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

sys.dont_write_bytecode = True


def run(output):
    os.umask(0o077)
    output.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[2] / 'native_pair_evidence.py'
    spec = importlib.util.spec_from_file_location('synthetic_peer_oracle', source)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    runtime = {'codex': {'path': 'SYNTHETIC_NOT_EXECUTED', 'sha256': oracle.DIRECT_IP_CODEX_SHA256,
                         'version': oracle.DIRECT_IP_CODEX_VERSION}}
    native = {'scope': 'ACTUAL_HOST_FORM_NATIVE_AB_NOT_PHYSICAL_UI', 'status': 'SCOPED_PASS',
        'daemon': {'pid': 1234, 'start_ticks': 'SYNTHETIC_NOT_A_PROCESS', 'umask': '0002',
            'five_deployment_variables_absent': True, 'executable_sha256': oracle.DIRECT_IP_CODEX_SHA256},
        'actors': [{**{key: 'SYNTHETIC_' + key + '_' + str(i) for key in
            ('native_session_id', 'workspace', 'endpoint_id')}, 'node_id': 'SYNTHETIC_NODE',
            'group_id': 'SYNTHETIC_GROUP', 'binding_epoch': 1} for i in range(2)],
        'form_actions': {'accept': 2, 'decline': 1, 'cancel': 1}, 'host_calls': 12,
        'host_provider_posts': 24, 'native_queue_provider_posts': 0, 'static_provider_posts': 24,
        'real_model_turns': 0, 'literal_provider_posts': 0,
        **{field: True for field in ('cleanup_confirmed', 'App_closed_during_business',
            'selection_no_send', 'cancel_decline_no_effect', 'shared_credentials_unchanged',
            'shared_domain_network_denied', 'actual_selection_lifetime_elapsed',
            'exact_retry_one_request', 'current_revoke_denied')},
        'physical_form_UI': 'NOT_RUN', 'Windows_DPAPI_ACL': 'NOT_RUN'}
    native.update(host_approval_policy='GRANULAR_MCP_ELICITATIONS_ONLY', host_approvals_reviewer='user')
    observed = []

    def check(name, value, expected=False):
        actual = oracle.valid_peer_form_native(value, runtime)
        assert actual is expected, 'RECEIPT_MUTATION_MISCLASSIFIED_' + name
        observed.append({'case': name, 'expected_acceptance': expected, 'observed_acceptance': actual})

    check('SYNTHETIC_complete_control_NOT_ACTUAL_RUNTIME', copy.deepcopy(native), True)
    check('absent_native_evidence', None)
    for field in native:
        value = copy.deepcopy(native)
        del value[field]
        check('missing_' + field, value)
    value = copy.deepcopy(native)
    value['unexpected'] = True
    check('unknown_native_field', value)
    for field, item in native.items():
        if type(item) is bool:
            value = copy.deepcopy(native)
            value[field] = False
            check('false_' + field, value)
        elif type(item) is int:
            value = copy.deepcopy(native)
            value[field] = False
            check('boolean_instead_of_count_' + field, value)
    for action in native['form_actions']:
        value = copy.deepcopy(native)
        value['form_actions'][action] = 0
        check('missing_form_action_' + action, value)
    for field in ('native_session_id', 'workspace', 'endpoint_id'):
        value = copy.deepcopy(native)
        value['actors'][1][field] = value['actors'][0][field]
        check('merged_actor_' + field, value)
    for field, item in [('pid', True), ('umask', '0077'), ('executable_sha256', '0' * 64)]:
        value = copy.deepcopy(native)
        value['daemon'][field] = item
        check('changed_daemon_' + field, value)
    value = copy.deepcopy(native)
    value['host_provider_posts'] += 1
    value['static_provider_posts'] += 1
    check('extra_static_provider_post', value)

    # Exercise the aggregate gate too: empty/skipped/duplicated tests, failed
    # stages, source/binary drift or leftover resources must not become green.
    base = {'events': [{'Test': name, 'Action': 'pass'} for name in sorted(oracle.PEER_FORM_EXPECTED)],
        'exits': dict.fromkeys(('version', 'compile-cli', 'compile-tests', 'harness', 'vet'), 0),
        'native': native, 'source_drift': False, 'binary_drift': False, 'owned': 'false'}
    mutations = [('SYNTHETIC_aggregate_control_NOT_PRODUCT', None, 0),
        ('empty_execution', lambda x: x.update(events=[]), 1),
        ('all_skip', lambda x: [e.update(Action='skip') for e in x['events']], 1),
        ('duplicate_terminal', lambda x: x['events'].append(copy.deepcopy(x['events'][0])), 1),
        ('missing_native', lambda x: x.update(native=None), 1),
        ('source_drift', lambda x: x.update(source_drift=True), 1),
        ('binary_drift', lambda x: x.update(binary_drift=True), 1),
        ('container_remaining', lambda x: x.update(owned='true'), 1)]
    for stage in base['exits']:
        mutations.append((stage + '_failed', lambda x, s=stage: x['exits'].update({s: 1}), 1))
    for index, (name, mutate, expected) in enumerate(mutations):
        value = copy.deepcopy(base)
        if mutate:
            mutate(value)
        fixture = output / ('SYNTHETIC-' + str(index) + '-' + name)
        fixture.mkdir(mode=0o700)
        artifacts = fixture / 'artifacts'
        artifacts.mkdir(mode=0o700)
        binaries = {}
        for binary in ('cicada', 'n3.test'):
            raw = ('SYNTHETIC_NOT_EXECUTABLE_' + binary).encode()
            (artifacts / binary).write_bytes(raw)
            binaries[binary] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        before = {'head': 'SYNTHETIC_NOT_GIT', 'dirty': True, 'source_root': 'SYNTHETIC_NOT_PRODUCT',
            'harness_root': 'SYNTHETIC_NOT_PRODUCT', 'harness_head': 'SYNTHETIC_NOT_GIT', 'harness_dirty': True,
            'approved_product_freeze': None, 'manifest_sha256': '0' * 64, 'files': {'SYNTHETIC': '0' * 64},
            'external_runtime_tools': runtime}
        after, changed_binaries = copy.deepcopy(before), copy.deepcopy(binaries)
        if value['source_drift']:
            after['files']['SYNTHETIC'] = '1' * 64
        if value['binary_drift']:
            changed_binaries['cicada']['sha256'] = '1' * 64
        for filename, contents in [('source-before.json', before), ('source-after.json', after),
            ('binaries-before.json', binaries), ('binaries-after.json', changed_binaries)]:
            (fixture / filename).write_text(json.dumps(contents))
        (fixture / 'harness.log').write_text(''.join(json.dumps(e) + '\n' for e in value['events']))
        for stage, code in value['exits'].items():
            (fixture / (stage + '.exit')).write_text(str(code))
        if value['native'] is not None:
            (fixture / 'peer-form-native-public-summary.json').write_text(json.dumps(value['native']))
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                oracle.finish(fixture, artifacts, 'SYNTHETIC_NOT_DOCKER', value['owned'], 'codex-product-peer-form')
            except SystemExit as stopped:
                actual = stopped.code
            else:
                raise AssertionError('RECEIPT_ORACLE_DID_NOT_RETURN_ITS_EXIT_CODE')
        assert actual == expected, 'AGGREGATE_MUTATION_MISCLASSIFIED_' + name
        observed.append({'case': name, 'expected_exit': expected, 'observed_exit': actual})
    result = {'scope': 'SYNTHETIC_RECEIPT_ORACLE_ONLY_NO_PRODUCT_EXECUTION', 'exit_code': 0,
        'cases': observed, 'oracle_sha256': oracle.sha(source),
        'driver_sha256': oracle.sha(Path(__file__)), 'product_processes_started': 0}
    oracle.save(output / 'result.json', result)
    print(json.dumps({'scope': result['scope'], 'cases': len(observed), 'exit_code': 0,
        'result_sha256': oracle.sha(output / 'result.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(run(Path(sys.argv[1])))
