#!/usr/bin/env python3
"""Mutation checks for the new receipt oracle; no product or crypto execution.

Usage: python3 scripts/fixtures/native-pair/node_pair_trust_evidence_checks.py NEW_OUTPUT
All fixtures and their apparent PASS receipts are visibly synthetic. They must
never be cited as actual Hub/App/Node execution or deployment initialization.
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


def run(output):
    os.umask(0o077)
    sys.dont_write_bytecode = True
    output.mkdir(mode=0o700)
    repo = Path(__file__).resolve().parents[3]
    source = repo / 'scripts/native_pair_evidence.py'
    spec = importlib.util.spec_from_file_location('node_pair_oracle_under_test', source)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    digest = lambda value: hashlib.sha256(value).hexdigest()
    parent = oracle.NODE_PAIR_TRUST_PARENT
    cases = list(oracle.NODE_PAIR_TRUST_FACTS)
    first = parent + '/' + cases[0]
    measurements = [
        {'Action': 'output', 'Test': parent + '/' + name,
         'Output': 'NODE_PAIR_TRUST_FACTS ' + json.dumps({
             'case': name, 'observed': {key: True for key in sorted(facts)}})}
        for name, facts in oracle.NODE_PAIR_TRUST_FACTS.items()]
    terminals = [{'Action': 'pass', 'Test': name} for name in sorted(oracle.NODE_PAIR_TRUST_EXPECTED)]
    native = {'scope': 'ACTUAL_AUTOMATIC_PIN_EXISTING_DAEMON_PLUGIN_ZERO_MODEL', 'status': 'SCOPED_PASS',
              'codex_version': oracle.DIRECT_IP_CODEX_VERSION,
              'original_daemon': {'pid': 1234, 'start_ticks': '1234', 'umask': '0002',
                                  'five_deployment_variables_absent': True,
                                  'executable_sha256': oracle.DIRECT_IP_CODEX_SHA256},
              **{name: 'SYNTHETIC_NOT_ACTUAL_' + name for name in
                 ('hub_id', 'node_id', 'node_binding_id', 'Owner_key_id', 'native_session_id',
                  'workspace', 'endpoint_id', 'group_id', 'policy_id')},
              'binding_epoch': 1, 'MCP_tools_count': 1, 'provider_posts': 0, 'real_model_turns': 0,
              'manual_Owner_pin_used': False, 'automatic_pin': True, 'same_original_Node': True,
              'delegated_grant_verified': True, 'cleanup_confirmed': True}
    base = {'events': measurements + terminals,
            'fixture_events': [{'Action': 'pass', 'Test': name} for name in sorted(oracle.NODE_PAIR_TRUST_FIXTURE_EXPECTED)],
            'exits': dict.fromkeys(('version', 'compile-cli', 'compile-tests', 'harness', 'vet', 'node-pair-fixture'), 0),
            'source_drift': False, 'binary_drift': False, 'owned': 'false',
            'missing_binary': False, 'native_summary': native, 'native_duplicate': False,
            'runtime_tools': {'codex': {'path': 'SYNTHETIC_NOT_EXECUTABLE',
                                       'sha256': oracle.DIRECT_IP_CODEX_SHA256,
                                       'version': oracle.DIRECT_IP_CODEX_VERSION}}}
    mutations = [('complete_synthetic_control', None, 0)]

    def add(name, mutate):
        mutations.append((name, mutate, 1))

    add('empty_execution', lambda x: x.update(events=[]))
    add('parent_only', lambda x: x.update(events=[{'Action': 'pass', 'Test': parent}]))
    add('all_skip', lambda x: [e.update(Action='skip') for e in x['events'] if e['Action'] == 'pass'])
    add('one_case_fail', lambda x: next(e for e in x['events'] if e.get('Test') == first and e['Action'] == 'pass').update(Action='fail'))
    add('one_case_missing', lambda x: x.update(events=[e for e in x['events'] if e.get('Test') != first]))
    add('unexpected_case', lambda x: x['events'].append({'Action': 'pass', 'Test': parent + '/UNEXPECTED'}))
    add('duplicate_terminal', lambda x: x['events'].append({'Action': 'pass', 'Test': first}))
    add('missing_measurement', lambda x: x['events'].pop(0))
    add('duplicate_measurement', lambda x: x['events'].append(copy.deepcopy(x['events'][0])))
    add('wrong_measurement_test', lambda x: x['events'][0].update(Test=parent))
    add('malformed_measurement', lambda x: x['events'][0].update(Output='NODE_PAIR_TRUST_FACTS {'))
    add('non_output_measurement', lambda x: x['events'][0].update(Action='run'))

    def change_fact(x, value, extra=False, remove=False):
        event = x['events'][0]
        measurement = json.loads(event['Output'].split('NODE_PAIR_TRUST_FACTS ', 1)[1])
        key = next(iter(measurement['observed']))
        if remove:
            measurement['observed'].pop(key)
        else:
            measurement['observed']['unexpected' if extra else key] = value
        event['Output'] = 'NODE_PAIR_TRUST_FACTS ' + json.dumps(measurement)

    add('false_fact', lambda x: change_fact(x, False))
    add('integer_not_true', lambda x: change_fact(x, 1))
    add('missing_fact', lambda x: change_fact(x, None, remove=True))
    add('unknown_fact', lambda x: change_fact(x, True, extra=True))
    add('duplicate_JSON_field', lambda x: x['events'][0].update(
        Output=x['events'][0]['Output'].replace('"observed": {', '"observed": {}, "observed": {', 1)))
    add('unavailable_diagnostic', lambda x: x['events'].append({
        'Action': 'output', 'Test': parent, 'Output': 'NODE_PAIR_TRUST_NOT_RUN: SYNTHETIC_UNAVAILABLE'}))
    for stage in base['exits']:
        add(stage + '_failed', lambda x, name=stage: x['exits'].update({name: 1}))
    add('compile_stage_missing', lambda x: x['exits'].pop('compile-cli'))
    add('source_drift', lambda x: x.update(source_drift=True))
    add('binary_drift', lambda x: x.update(binary_drift=True))
    add('binary_missing', lambda x: x.update(missing_binary=True))
    add('container_remaining', lambda x: x.update(owned='true'))
    add('fixture_missing', lambda x: x.update(fixture_events=[]))
    add('fixture_skip', lambda x: x['fixture_events'][0].update(Action='skip'))
    add('fixture_parent_only', lambda x: x.update(fixture_events=[{'Action': 'pass', 'Test': oracle.NODE_PAIR_TRUST_FIXTURE_PARENT}]))
    add('fixture_duplicate_terminal', lambda x: x['fixture_events'].append(copy.deepcopy(x['fixture_events'][0])))
    add('native_summary_missing', lambda x: x.update(native_summary=None))
    add('native_summary_duplicate_field', lambda x: x.update(native_duplicate=True))
    add('native_summary_wrong_scope', lambda x: x['native_summary'].update(scope='SYNTHETIC_WRONG_SCOPE'))
    add('native_summary_unknown_field', lambda x: x['native_summary'].update(unknown=True))
    add('native_summary_missing_delegation', lambda x: x['native_summary'].pop('delegated_grant_verified'))
    add('native_summary_no_endpoint', lambda x: x['native_summary'].update(endpoint_id=''))
    add('native_summary_provider_request', lambda x: x['native_summary'].update(provider_posts=1))
    add('native_summary_bool_not_integer', lambda x: x['native_summary'].update(provider_posts=False))
    add('native_summary_false_pin', lambda x: x['native_summary'].update(automatic_pin=False))
    add('native_summary_manual_pin', lambda x: x['native_summary'].update(manual_Owner_pin_used=True))
    add('native_summary_cleanup_failed', lambda x: x['native_summary'].update(cleanup_confirmed=False))
    add('native_summary_daemon_wrong_hash', lambda x: x['native_summary']['original_daemon'].update(executable_sha256='0' * 64))
    add('native_summary_daemon_bool_PID', lambda x: x['native_summary']['original_daemon'].update(pid=True))
    add('runtime_missing', lambda x: x.update(runtime_tools={}))
    add('runtime_wrong_version', lambda x: x['runtime_tools']['codex'].update(version='SYNTHETIC_WRONG_VERSION'))
    observed = []
    for index, (name, mutate, expected) in enumerate(mutations):
        config = copy.deepcopy(base)
        if mutate:
            mutate(config)
        fixture = output / f'{index:02d}-{name}'
        fixture.mkdir(mode=0o700)
        artifacts = fixture / 'artifacts'
        artifacts.mkdir(mode=0o700)
        binaries = {}
        for binary in ('cicada', 'n3.test'):
            if binary == 'n3.test' and config['missing_binary']:
                continue
            raw = ('SYNTHETIC_NOT_EXECUTABLE_' + binary).encode()
            (artifacts / binary).write_bytes(raw)
            binaries[binary] = {'sha256': digest(raw), 'bytes': len(raw)}
        before = {'head': 'SYNTHETIC_NOT_A_GIT_REVISION', 'dirty': True,
                  'source_root': 'SYNTHETIC_NOT_PRODUCT', 'harness_root': 'SYNTHETIC_NOT_PRODUCT',
                  'harness_head': 'SYNTHETIC_NOT_A_GIT_REVISION', 'harness_dirty': True,
                  'approved_product_freeze': None, 'manifest_sha256': '0' * 64,
                  'files': {'SYNTHETIC': '0' * 64}, 'external_runtime_tools': config['runtime_tools']}
        after = copy.deepcopy(before)
        if config['source_drift']:
            after['files']['SYNTHETIC'] = '1' * 64
        after_binaries = copy.deepcopy(binaries)
        if config['binary_drift']:
            after_binaries['cicada']['sha256'] = '1' * 64
        for filename, value in [('source-before.json', before), ('source-after.json', after),
                                ('binaries-before.json', binaries), ('binaries-after.json', after_binaries)]:
            (fixture / filename).write_text(json.dumps(value) + '\n')
        (fixture / 'harness.log').write_text(''.join(json.dumps(e) + '\n' for e in config['events']))
        (fixture / 'node-pair-fixture.log').write_text(''.join(json.dumps(e) + '\n' for e in config['fixture_events']))
        if config['native_summary'] is not None:
            encoded = json.dumps(config['native_summary'])
            if config['native_duplicate']:
                encoded = encoded.replace('"status":', '"status": "SCOPED_PASS", "status":', 1)
            (fixture / 'node-pair-native-consumer-public-summary.json').write_text(encoded + '\n')
        for stage, code in config['exits'].items():
            (fixture / (stage + '.exit')).write_text(str(code) + '\n')
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                oracle.finish(fixture, artifacts, 'SYNTHETIC_IMAGE@sha256:' + '0' * 64, config['owned'], 'node-pair-trust')
        except SystemExit as result:
            actual = result.code
        else:
            raise AssertionError('Oracle did not return a gate exit')
        if actual != expected:
            raise AssertionError(name + ': wrong oracle exit')
        receipt = fixture / 'result.json'
        observed.append({'case': name, 'exit': actual, 'expected_exit': expected,
                         'receipt_sha256': digest(receipt.read_bytes())})
    result = {'scope': 'SYNTHETIC_RECEIPT_MUTATION_CHECKS_NOT_PRODUCT_EXECUTION',
              'status': 'PASS', 'exit_code': 0, 'count': len(observed), 'checks': observed,
              'oracle_sha256': digest(source.read_bytes()),
              'driver_sha256': digest(Path(__file__).read_bytes()),
              'Hub_App_Node_executed': False, 'product_acceptance': 'NOT_RUN'}
    (output / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(f"Synthetic node-pair receipt checks PASS count={len(observed)}; product NOT_RUN; result={output / 'result.json'}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    run(Path(sys.argv[1]))
