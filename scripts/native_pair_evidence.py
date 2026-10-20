#!/usr/bin/env python3
"""Strict, separate attribution for native-pair protocol acceptance, not N3 UI."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

EXPECTED = {'TestN3NativePair' + suffix for suffix in (
    'BootstrapAndExactReplay', 'WrongNodeScopeIsFenced', 'PrepareLossBeforeForward',
    'CompleteLossAfterCommit', 'MissingOwnerProofCannotBootstrap')}
STORE_EXPECTED = {'TestQANativePairReadCacheKeepsHistoryAcrossRateWindows',
                  'TestQANativePairFutureStatusCannotSettleOrChangeRate',
                  'TestQANativePairJoinDeadlineIsIndependentOfLiveLeaseExpiry'}
STORE_EXPECTED.update('TestQANativePairJoinDeadlineIsIndependentOfLiveLeaseExpiry/' + state + '_' + edge
                      for state in ('one_slot', 'two_slots') for edge in ('before', 'at', 'after'))
A3_EXPECTED = {'TestQANativePairA3' + name for name in (
    'FirstConsentZeroSecondUsesOriginalGrants', 'SecondGrantFailureRollsBackBothMemberships',
    'LostActivationAckRecoversAcceptedHistory', 'CurrentRequiredAndExactCoordinates')}
A3_HTTP_EXPECTED = {'TestQANativePairA3HTTPExactBodyAndAtomicRejection'}
A3_SIZE_EXPECTED = {'TestQANativePairA3DeliveryOverflowCannotPublishAuthority'}
APP_OWNER_EXPECTED = {'TestN3AppPairActionsBootstrapDualConsentAndRevoke'}
ENDPOINT_SECURITY_EXPECTED = {'TestN3HarnessMethodSpecificFaultBarrier'}
ENDPOINT_SECURITY_EXPECTED.update('TestN3EndpointSecurity' + suffix for suffix in (
    'ZeroAuthorityAndIdentityRetention', 'LeaveCASAndExactReplay',
    'RegistrationFaultRecovery', 'ConcurrentOriginalRequest'))
ENDPOINT_SECURITY_EXPECTED.update('TestN3EndpointSecurityRegistrationFaultRecovery/' + mode for mode in (
    'before-forward', 'drop-after-response', 'unsigned-403', 'corrupt-response'))
ENDPOINT_BOUNDARIES_EXPECTED = {'TestN3EndpointSecurityZeroAuthorityAndIdentityRetention',
                                'TestN3EndpointSecurityConcurrentOriginalRequest'}
ENDPOINT_APP_FIXTURE_EXPECTED = {'TestN3EndpointSecurityZeroAuthorityAndIdentityRetention'}
OWNER_DIRECTORY_EXPECTED = {'TestN3OwnerDirectory' + suffix for suffix in (
    'ActualAppReadsZeroRightsSnapshot', 'OldHubCannotStartRead', 'OriginalPendingRecovers')}
OWNER_DIRECTORY_EXPECTED.update('TestN3OwnerDirectoryOriginalPendingRecovers/' + mode for mode in (
    'before-forward', 'drop-after-response', 'unsigned-403'))
OWNER_DIRECTORY_RECOVERY_EXPECTED = {name for name in OWNER_DIRECTORY_EXPECTED
                                     if name.startswith('TestN3OwnerDirectoryOriginalPendingRecovers')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    # Every invocation owns a fresh run. Historical receipts are never rewritten.
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')


def binaries(artifacts, dest):
    save(dest, {p.name: {'sha256': sha(p), 'bytes': p.stat().st_size}
                for p in sorted(artifacts.iterdir()) if p.is_file()})


def snapshot(repo, dest, harness=None):
    # Complete Go/module tree (including embedded assets), not merely selected
    # inputs. The parent worktree is RO throughout compilation and execution.
    harness = harness or repo
    paths = [p for p in (repo / 'cicada-go').rglob('*') if p.is_file()]
    paths += [repo / 'docs' / name for name in ('hub-native-pair-contract.md', 'native-app-plan.md')]
    endpoint_contract = repo / 'docs/native-endpoint-directory-contract.md'
    if endpoint_contract.exists():
        paths.append(endpoint_contract)
    paths += [repo / 'scripts/native-pair-contract.py']
    files = {'source/' + str(p.relative_to(repo)): sha(p) for p in sorted(paths)}
    formal = None
    if os.environ.get('CICADA_NATIVE_PAIR_PRODUCT_FREEZE'):
        freeze_path = Path(os.environ['CICADA_NATIVE_PAIR_PRODUCT_FREEZE'])
        freeze = json.loads(freeze_path.read_text())
        for name, expected in freeze['files'].items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts or sha(repo / relative) != expected:
                raise ValueError('Product input differs from the approved freeze: ' + name)
            files['source/' + name] = expected
        actual_go = {str(p.relative_to(repo)) for p in paths if p.is_relative_to(repo / 'cicada-go')}
        frozen_go = {name for name in freeze['files'] if name.startswith('cicada-go/')}
        if actual_go != frozen_go:
            raise ValueError('The complete product Go tree differs from the approved freeze inventory.')
        formal = {'path': str(freeze_path), 'sha256': sha(freeze_path), 'file_count': len(freeze['files']),
                  'excluded_noninput': freeze.get('excluded_noninput_files', freeze.get('excluded_noninput_validation_record'))}
    drivers = [harness / 'scripts' / name for name in ('test-native-pair.sh', 'native_pair_evidence.py')]
    drivers += [p for p in (harness / 'scripts/fixtures/native-pair').rglob('*') if p.is_file()]
    files.update({'harness/' + str(p.relative_to(harness)): sha(p) for p in sorted(drivers)})
    save(dest, {'head': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
                'dirty': bool(subprocess.check_output(['git', '--no-optional-locks', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'])),
                'source_root': str(repo), 'harness_root': str(harness),
                'harness_head': subprocess.check_output(['git', '-C', str(harness), 'rev-parse', 'HEAD'], text=True).strip(),
                'harness_dirty': bool(subprocess.check_output(['git', '--no-optional-locks', '-C', str(harness), 'status', '--porcelain', '--untracked-files=all'])),
                'approved_product_freeze': formal,
                'manifest_sha256': hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'files': files})


def terminal_events(path):
    result = {}
    rank = {'pass': 0, 'skip': 1, 'fail': 2}
    if not path.exists():
        return result
    for line in path.read_text(errors='replace').splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        test, action = item.get('Test'), item.get('Action')
        if test and action in rank and rank[action] >= rank.get(result.get(test), -1):
            result[test] = action
    return result


def finish(run, artifacts, image, owned, mode='protocol'):
    if mode not in ('protocol', 'store', 'a3', 'a3-http', 'a3-size-store', 'app-owner', 'endpoint-security', 'endpoint-security-boundaries', 'endpoint-security-app-fixture', 'endpoint-security-owner-directory', 'endpoint-security-owner-directory-recovery'):
        raise ValueError('Only protocol and isolated core regression modes are active.')
    before, after = [json.loads((run / f'source-{side}.json').read_text()) for side in ('before', 'after')]
    results, diagnostics, metrics = {}, [], []
    rank = {'pass': 0, 'skip': 1, 'fail': 2}
    for line in (run / 'harness.log').read_text(errors='replace').splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        test, action = item.get('Test'), item.get('Action')
        if test and action in rank and rank[action] >= rank.get(results.get(test), -1):
            results[test] = action
        output = item.get('Output', '').strip()
        if 'NATIVE_PAIR_UNAVAILABLE' in output:
            diagnostics.append({'test': test, 'reason': output})
        if 'NATIVE_PAIR_HTTP ' in output:
            metrics.append({'test': test, 'measurement': output.split('NATIVE_PAIR_HTTP ', 1)[1]})
    exits = {p.stem: int(p.read_text().strip()) for p in run.glob('*.exit')}
    matched = before == after
    expected = {'store': STORE_EXPECTED, 'a3': A3_EXPECTED, 'a3-http': A3_HTTP_EXPECTED,
                'a3-size-store': A3_SIZE_EXPECTED, 'app-owner': APP_OWNER_EXPECTED,
                'endpoint-security': ENDPOINT_SECURITY_EXPECTED, 'endpoint-security-boundaries': ENDPOINT_BOUNDARIES_EXPECTED,
                'endpoint-security-app-fixture': ENDPOINT_APP_FIXTURE_EXPECTED,
                'endpoint-security-owner-directory': OWNER_DIRECTORY_EXPECTED,
                'endpoint-security-owner-directory-recovery': OWNER_DIRECTORY_RECOVERY_EXPECTED,
                'protocol': EXPECTED}[mode]
    core = mode not in ('protocol', 'app-owner', 'endpoint-security', 'endpoint-security-boundaries', 'endpoint-security-app-fixture', 'endpoint-security-owner-directory', 'endpoint-security-owner-directory-recovery')
    owner_directory = mode.startswith('endpoint-security-owner-directory')
    stages = ('version', 'compile-tests', 'compile-race', 'harness', 'race', 'vet') if core else ('version', 'compile-cli', 'compile-tests', 'harness', 'vet')
    race = terminal_events(run / 'race.log') if core else None
    race_passed = not core or (set(race) == expected and all(v == 'pass' for v in race.values()))
    binary_records = [json.loads((run / f'binaries-{side}.json').read_text())
                      if (run / f'binaries-{side}.json').exists() else {} for side in ('before', 'after')]
    expected_binaries = {'store': {'nativepair-cache.test', 'nativepair-cache-race.test'},
                         'a3': {'nativepair-a3.test', 'nativepair-a3-race.test'},
                         'a3-http': {'nativepair-a3-http.test', 'nativepair-a3-http-race.test'},
                         'a3-size-store': {'nativepair-a3-size.test', 'nativepair-a3-size-race.test'},
                         'app-owner': {'cicada', 'n3.test'},
                         'endpoint-security': {'cicada', 'n3.test'},
                         'endpoint-security-boundaries': {'cicada', 'n3.test'},
                         'endpoint-security-app-fixture': {'cicada', 'n3.test'},
                         'endpoint-security-owner-directory': {'cicada', 'n3.test'},
                         'endpoint-security-owner-directory-recovery': {'cicada', 'n3.test'},
                         'protocol': {'cicada', 'n3.test'}}[mode]
    binaries_stable = set(binary_records[0]) == expected_binaries and binary_records[0] == binary_records[1]
    passed = (all(exits.get(n) == 0 for n in stages)
              and set(results) == expected and all(v == 'pass' for v in results.values())
              and race_passed and binaries_stable and matched and owned == 'false')
    # WIRE_ONLY + actual 404 is retained as expected RED, with nonzero exit. It
    # cannot turn a missing service, absent scenario, skip, or compiler error green.
    expected_red = (mode == 'protocol' and not passed and set(results) == EXPECTED and all(v == 'fail' for v in results.values())
                    and len(diagnostics) == len(EXPECTED)
                    and all('HTTP=404 ' in d['reason'] for d in diagnostics)
                    and all(exits.get(n) == 0 for n in ('version', 'compile-cli', 'compile-tests', 'vet'))
                    and exits.get('harness') == 1 and binaries_stable and matched and owned == 'false')
    code = 0 if passed else 1
    scope = {'store': 'FOCUSED_SYNTHETIC_STORE_PQ_CACHE_AND_LEASE_REGRESSIONS_NOT_E2E',
             'a3': 'DISPOSABLE_PRODUCER_CORE_REAL_PQ_TCP_N2_N3_AND_A3_NOT_PUBLIC_SDK_APP_UI_OR_RUNTIME',
             'a3-http': 'REAL_PQ_TCP_SYNTHETIC_RELAY_DERIVED_TYPED_HTTP_BYTE_BOUNDARIES_NOT_RUNTIME',
             'a3-size-store': 'SYNTHETIC_STORE_PQ_ORIGINAL_CONSENT_ACTIVATION_SIZE_ATOMICITY_NOT_TCP_OR_RUNTIME',
             'app-owner': 'ACTUAL_APP_CORE_CHILD_PAIR_OWNER_ACTIONS_AND_SYNTHETIC_NODE_PQ_TO_PRODUCTION_HUB_NOT_GUI_OR_RUNTIME',
             'endpoint-security': 'ACTUAL_APP_CORE_NODE_APPROVAL_SYNTHETIC_NODE_PQ_TCP_ZERO_RIGHTS_ENDPOINT_CAS_EXACT_REPLAY_NOT_NATIVE_ADAPTER_OR_OWNER_DIRECTORY',
             'endpoint-security-boundaries': 'TARGETED_ACTUAL_APP_NODE_APPROVAL_ZERO_RIGHTS_AUTH_AND_CONCURRENT_EXACT_RETRY_CORRECTION_NOT_FULL_AGGREGATE',
             'endpoint-security-app-fixture': 'AFFECTED_ACTUAL_APP_CORE_NODE_APPROVAL_AND_ZERO_RIGHTS_FIXTURE_AFTER_STORAGE_CHECKPOINT_NOT_FULL_AGGREGATE',
             'endpoint-security-owner-directory': 'ACTUAL_APP_CORE_OWNER_SIGNED_ZERO_RIGHTS_DIRECTORY_AND_DURABLE_ORIGINAL_READ_RECOVERY_NOT_GUI_OR_RUNTIME',
             'endpoint-security-owner-directory-recovery': 'TARGETED_ACTUAL_APP_CORE_ORIGINAL_OWNER_READ_RECOVERY_AFTER_RESTART_NOT_FRESH_FULL_AGGREGATE',
             'protocol': 'REAL_TCP_PQ_BOOTSTRAP_AND_RECOVERY_ONLY'}[mode]
    summary = {'scope': scope,
               'status': 'SCOPED_PASS' if passed else ('EXPECTED_RED_SERVICE_UNAVAILABLE' if expected_red else 'FAIL'),
               'exit_code': code, 'exit_codes': exits, 'docker_image_reference': image,
               'docker_image_digest': image.rsplit('@', 1)[-1],
               'source_before_sha256': sha(run / 'source-before.json'),
               'source_after_sha256': sha(run / 'source-after.json'),
               'source_stable': matched, 'head': before['head'], 'dirty': before['dirty'],
               'source_root': before['source_root'], 'harness_root': before['harness_root'],
               'harness_head': before['harness_head'], 'harness_dirty': before['harness_dirty'],
               'approved_product_freeze': before['approved_product_freeze'],
               'source_manifest_sha256': before['manifest_sha256'], 'input_count': len(before['files']),
               'container_absent': owned == 'false', 'tests': results, 'race_tests': race, 'missing': sorted(expected - set(results)),
               'executed_binary_hashes_before_after_match': binaries_stable,
               'executed_binaries': binary_records,
               'diagnostics': diagnostics, 'http_measurements': metrics,
               'artifacts': {p.name: {'sha256': sha(p), 'bytes': p.stat().st_size} for p in artifacts.iterdir() if p.is_file()},
               'evidence_sha256': {p.name: sha(p) for p in run.iterdir() if p.is_file() and p.name != 'result.json'},
               'not_run': (([] if owner_directory else ['actual_App_Owner_endpoint_directory']) +
                           (['Owner_directory_foreign_scope_paging_cache_expiry_and_N2_TTL',
                             'Owner_directory_logout_revocation_wrong_Hub_capability',
                             'Owner_directory_expired_read_parking_budget'] if owner_directory else []) +
                           (['production_Node_registration_adapter',
                             'product_Hook_context_ticket_guard', 'Group_Network_scope_leave',
                             'changed_authorization_state_leave_CAS', 'distinct_Node_operation_concurrency']
                            + ['second_approved_Node_same_SID_adoption']
                            if mode.startswith('endpoint-security') else []) +
                           ([] if mode == 'app-owner' else ['production_App_native_pair'])) +
                          ['actual_Codex_dialogue', 'real_native_same_Node_sealed_Relay_consumption',
                           'native_queue_consumption', 'Windows_DPAPI', 'Windows_ACL', 'Windows_GUI'] +
                          (['full_public_availability_gate', 'actual_sender_writer_current_enforcement'] if mode in ('a3', 'a3-http') else
                           ['Node_reserved_slot_RPC', 'public_TCP_dual_consent_surface', 'actual_sender_writer_current_enforcement'] if mode == 'a3-size-store' else
                           ['native_MCP_consumer', 'actual_sender_writer_current_enforcement', 'native_App_GUI'] if mode == 'app-owner' else
                           ['Node_reserved_slot_Join', 'dual_Owner_consent']),
               'private_payloads_exported': False, 'model_turns_started': 0,
               'native_daemon_touched': False, 'public_deployment_touched': False}
    save(run / 'result.json', summary)
    print(f"Native pair {summary['status']} exit={code} evidence={run / 'result.json'}")
    raise SystemExit(code)


if __name__ == '__main__':
    if len(sys.argv) in (4, 5) and sys.argv[1] == 'snapshot':
        snapshot(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]) if len(sys.argv) == 5 else None)
    elif len(sys.argv) in (6, 7) and sys.argv[1] == 'finish':
        finish(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6] if len(sys.argv) == 7 else 'protocol')
    elif len(sys.argv) == 4 and sys.argv[1] == 'binaries':
        binaries(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit('Usage: native_pair_evidence.py snapshot REPO DEST [HARNESS] | binaries ARTIFACTS DEST | finish EVIDENCE ARTIFACTS IMAGE OWNED_PRESENT')
