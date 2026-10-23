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
CODEX_PRODUCT_GUARD_EXPECTED = {'TestN3CodexProductContextRefusesMissingAndForged',
                              'TestN3CodexProductMCPRestartRotatesConnectionNonce'}
CODEX_PRODUCT_GUARD_EXPECTED.update('TestN3CodexProductContextRefusesMissingAndForged/' + case
                                  for case in ('missing', 'nonce-only', 'wrong-nonce', 'forged-ticket', 'extra-SID'))
CODEX_PRODUCT_CLI_EXPECTED = {'TestN3CodexProductInstalledPluginLiteralTUI'}
CODEX_PRODUCT_COLD_EXPECTED = {'TestN3CodexProductColdLeaseBeforeFirstTool'}
CODEX_PRODUCT_THREE_STAGE_EXPECTED = {'TestN3CodexProductThreeStagePersistentDaemon'}
CODEX_PRODUCT_OTHER_UID_EXPECTED = {'TestN3CodexProductOtherUIDPrivateBoundary'}
LOCAL_DOMAIN_APP_EXPECTED = {'TestN3LocalDomainActualAppOwnerPolicy'}
LOCAL_DOMAIN_NATIVE_EXPECTED = {'TestN3LocalDomainNativeOriginalDaemonAB'}


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
    domain_contract = repo / 'docs/native-local-domain-contract.md'
    if domain_contract.exists():
        paths.append(domain_contract)
    paths += [repo / 'scripts/native-pair-contract.py']
    files = {'source/' + str(p.relative_to(repo)): sha(p) for p in sorted(paths)}
    files.update({'source/' + str(p.relative_to(repo)): sha(p)
                  for p in sorted((repo / '.agents/plugins').rglob('*')) if p.is_file()})
    runtime_tools = {}
    if os.environ.get('CICADA_NATIVE_PAIR_CODEX_BINARY'):
        codex = Path(os.environ['CICADA_NATIVE_PAIR_CODEX_BINARY'])
        runtime_tools['codex'] = {'path': str(codex), 'sha256': sha(codex), 'bytes': codex.stat().st_size}
    codex_package = None
    if os.environ.get('CICADA_NATIVE_PAIR_CODEX_PACKAGE'):
        directory = Path(os.environ['CICADA_NATIVE_PAIR_CODEX_PACKAGE'])
        codex_package = {'path': str(directory), 'files': {
            str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob('*')) if p.is_file()}}
    component_licenses = None
    if os.environ.get('CICADA_NATIVE_PAIR_LICENSES_DIR'):
        directory = Path(os.environ['CICADA_NATIVE_PAIR_LICENSES_DIR'])
        component_licenses = {'path': str(directory), 'files': {
            str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob('*')) if p.is_file()}}
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
                'external_runtime_tools': runtime_tools,
                'external_component_licenses': component_licenses,
                'external_codex_package': codex_package,
                'codex_daemon_parameters': {
                    'daemon_umask': os.environ.get('CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK'),
                    'fresh_threads': os.environ.get('CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS'),
                    'preparation': os.environ.get('CICADA_NATIVE_PAIR_CODEX_PREPARATION')},
                'native_domain_parameters': {
                    'wait_actual_login_expiry': os.environ.get('CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY')},
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
    if mode not in ('protocol', 'store', 'a3', 'a3-http', 'a3-size-store', 'app-owner', 'endpoint-security', 'endpoint-security-boundaries', 'endpoint-security-app-fixture', 'endpoint-security-owner-directory', 'endpoint-security-owner-directory-recovery', 'codex-product-guards', 'codex-product-cli', 'codex-product-cold', 'codex-product-three-stage', 'codex-product-other-uid', 'codex-product-domain-app', 'codex-product-domain-native'):
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
        if 'NATIVE_PAIR_UNAVAILABLE' in output or 'LOCAL_DOMAIN_NOT_RUN' in output:
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
                'codex-product-guards': CODEX_PRODUCT_GUARD_EXPECTED,
                'codex-product-cli': CODEX_PRODUCT_CLI_EXPECTED,
                'codex-product-cold': CODEX_PRODUCT_COLD_EXPECTED,
                'codex-product-three-stage': CODEX_PRODUCT_THREE_STAGE_EXPECTED,
                'codex-product-other-uid': CODEX_PRODUCT_OTHER_UID_EXPECTED,
                'codex-product-domain-app': LOCAL_DOMAIN_APP_EXPECTED,
                'codex-product-domain-native': LOCAL_DOMAIN_NATIVE_EXPECTED,
                'protocol': EXPECTED}[mode]
    core = mode not in ('protocol', 'app-owner', 'endpoint-security', 'endpoint-security-boundaries', 'endpoint-security-app-fixture', 'endpoint-security-owner-directory', 'endpoint-security-owner-directory-recovery', 'codex-product-guards', 'codex-product-cli', 'codex-product-cold', 'codex-product-three-stage', 'codex-product-other-uid', 'codex-product-domain-app', 'codex-product-domain-native')
    owner_directory = mode.startswith('endpoint-security-owner-directory')
    stages = ('version', 'compile-tests', 'compile-race', 'harness', 'race', 'vet') if core else ('version', 'compile-cli', 'compile-tests', 'harness', 'vet')
    if mode == 'codex-product-other-uid':
        stages += ('other-uid-host',)
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
                         'codex-product-guards': {'cicada', 'n3.test'},
                         'codex-product-cli': {'cicada', 'n3.test'},
                         'codex-product-cold': {'cicada', 'n3.test'},
                         'codex-product-three-stage': {'cicada', 'n3.test'},
                         'codex-product-other-uid': {'cicada', 'n3.test'},
                         'codex-product-domain-app': {'cicada', 'n3.test'},
                         'codex-product-domain-native': {'cicada', 'n3.test'},
                         'protocol': {'cicada', 'n3.test'}}[mode]
    binaries_stable = set(binary_records[0]) == expected_binaries and binary_records[0] == binary_records[1]
    runtime_tools = before.get('external_runtime_tools', {})
    runtime_tools_valid = (mode not in ('codex-product-cli', 'codex-product-cold', 'codex-product-three-stage', 'codex-product-domain-native') or
                           (set(runtime_tools) == {'codex'} and runtime_tools['codex']['sha256'] ==
                            '399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215'))
    native = None
    native_valid = mode != 'codex-product-domain-native'
    if mode == 'codex-product-domain-native' and (run / 'domain-native-public-summary.json').is_file():
        native = json.loads((run / 'domain-native-public-summary.json').read_text())
        daemon, actors = native.get('original_daemon', {}), native.get('actors', [])
        expiry = before.get('native_domain_parameters', {}).get('wait_actual_login_expiry')
        native_valid = (expiry in ('0', '1') and native.get('status') == 'SCOPED_PASS'
                        and native.get('scope') == 'ACTUAL_NATIVE_DOMAIN_MAIN_STATIC_PROVIDER_NOT_REAL_MODEL_OR_WINDOWS'
                        and native.get('actual_wall_clock_login_expiry') is (expiry == '1')
                        and native.get('literal_provider_posts') == 0
                        and native.get('host_submission_mode') == 'START_OR_STEER'
                        and type(native.get('host_calls_completed')) is int and native['host_calls_completed'] >= 8
                        and type(native.get('host_provider_posts')) is int
                        and native['host_provider_posts'] == 2 * native['host_calls_completed']
                        and type(native.get('native_queue_provider_posts')) is int and native['native_queue_provider_posts'] >= 0
                        and native.get('static_provider_posts') == native['host_provider_posts'] + native['native_queue_provider_posts']
                        and native.get('real_model_turns_started') == 0
                        and native.get('manual_independent_Owner_pin') is True
                        and native.get('Hub_and_Node_healthy_at_revoke') is True
                        and native.get('authenticated_policy_state_after_revoke') == 'REVOKED'
                        and native.get('new_business_denied_after_revoke') is True
                        and native.get('directory_filters_verified') is True
                        and native.get('directory_after_revoke_denied') is True
                        and type(daemon.get('pid')) is int and daemon['pid'] > 0
                        and bool(daemon.get('start_ticks')) and daemon.get('umask') == '0002'
                        and daemon.get('five_deployment_variables_absent') is True
                        and daemon.get('executable_sha256') == runtime_tools.get('codex', {}).get('sha256')
                        and len(actors) == (3 if expiry == '1' else 2)
                        and all(all(isinstance(a.get(n), str) and a[n] for n in
                                    ('native_session_id', 'workspace', 'node_id', 'endpoint_id', 'group_id'))
                                and type(a.get('binding_epoch')) is int and a['binding_epoch'] > 0 for a in actors)
                        and all(len({a[n] for a in actors}) == len(actors) for n in ('native_session_id', 'workspace', 'endpoint_id'))
                        and all(len({a[n] for a in actors}) == 1 for n in ('node_id', 'group_id')))
    passed = (all(exits.get(n) == 0 for n in stages)
              and set(results) == expected and all(v == 'pass' for v in results.values())
              and race_passed and binaries_stable and runtime_tools_valid and native_valid and matched and owned == 'false')
    # WIRE_ONLY + actual 404 is retained as expected RED, with nonzero exit. It
    # cannot turn a missing service, absent scenario, skip, or compiler error green.
    expected_red = (mode == 'protocol' and not passed and set(results) == EXPECTED and all(v == 'fail' for v in results.values())
                    and len(diagnostics) == len(EXPECTED)
                    and all('HTTP=404 ' in d['reason'] for d in diagnostics)
                    and all(exits.get(n) == 0 for n in ('version', 'compile-cli', 'compile-tests', 'vet'))
                    and exits.get('harness') == 1 and binaries_stable and matched and owned == 'false')
    domain_not_run = (mode in ('codex-product-domain-app', 'codex-product-domain-native') and set(results) == expected
                      and all(v == 'skip' for v in results.values()) and len(diagnostics) == len(expected)
                      and all('LOCAL_DOMAIN_NOT_RUN' in d['reason'] for d in diagnostics)
                      and all(exits.get(n) == 0 for n in stages) and binaries_stable and runtime_tools_valid and matched and owned == 'false')
    code = 0 if passed else 125 if domain_not_run else 1
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
             'codex-product-guards': 'ACTUAL_APP_APPROVED_REAL_NODE_AND_STDIO_MCP_CONTEXT_REFUSALS_NOT_INSTALLED_PLUGIN_OR_NATIVE_CLI',
             'codex-product-cli': 'ACTUAL_INSTALLED_PLUGIN_LITERAL_PTY_AND_HOST_MCP_WHOAMI_VERIFIED_CONTEXT_NOT_JOINED_NO_REAL_MODEL',
             'codex-product-cold': 'ACTUAL_APP_DUAL_CONSENT_ORIGINAL_DEFAULT_FIVE_MINUTE_COLD_LEASE_NODE_RESTART_FIRST_HOST_TOOL_AND_REVOCATION_MANUAL_OWNER_PIN',
             'codex-product-three-stage': 'ACTUAL_ORIGINAL_ENV_ZERO_CODEX_DAEMON_FILE_INSTALL_OLD_PLUGIN_UPDATE_NODE_OFFLINE_EXPLICIT_START_AND_SAME_PIN_RESTART_NO_MODEL',
             'codex-product-other-uid': 'ACTUAL_APP_APPROVED_NODE_OTHER_UID1001_GID1000_PRIVATE_FILES_AND_UNIX_IPC_ONLY_NOT_DOMAIN_CONTEXT_OR_SIGNING',
             'codex-product-domain-app': 'ACTUAL_APP_OWNER_LOCAL_POLICY_PREVIEW_ACTIVATE_OFFLINE_NODE_READ_AND_REVOKE_NOT_NATIVE_THREADS',
             'codex-product-domain-native': 'ACTUAL_ORIGINAL_0002_NATIVE_DAEMON_LITERAL_AB_NAMED_HOST_ASK_REPLY_APP_CLOSED_AND_CURRENT_REVOKE_MANUAL_OWNER_PIN',
             'protocol': 'REAL_TCP_PQ_BOOTSTRAP_AND_RECOVERY_ONLY'}[mode]
    summary = {'scope': scope,
               'status': 'SCOPED_PASS' if passed else 'NOT_RUN' if domain_not_run else ('EXPECTED_RED_SERVICE_UNAVAILABLE' if expected_red else 'FAIL'),
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
               'external_runtime_tools': runtime_tools,
               'external_component_licenses': before.get('external_component_licenses'),
               'external_codex_package': before.get('external_codex_package'),
               'codex_daemon_parameters': before.get('codex_daemon_parameters'),
               'native_domain_parameters': before.get('native_domain_parameters'),
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
    if mode == 'codex-product-guards':
        summary['not_run'] = ['actual_installed_Codex_plugin', 'actual_Codex_literal_join_peers_leave_PTY',
                              'valid_ticket_replay_cross_context_and_fork', 'real_Node_endpoint_registration_and_leave',
                              'original_operator_intent_response_loss_recovery', 'A_B_frozen_scope_heartbeat_cancellation',
                              'Node_owned_Endpoint_lease_before_first_MCP_tool', 'reserved_Pair_join_and_dual_Owner_consent',
                              'native_queue_consumption', 'real_model_provider',
                              'Windows_DPAPI', 'Windows_ACL', 'Windows_GUI', 'Android', 'public_HTTPS']
    elif mode == 'codex-product-cli':
        summary['not_run'] = ['literal_leave_same_SID_reregister_left_retention',
                              'valid_ticket_replay_cross_context_and_fork', 'direct_MCP_context_refusal_matrix',
                              'original_operator_intent_response_loss_recovery', 'A_B_frozen_scope_heartbeat_cancellation',
                              'Node_owned_Endpoint_lease_before_first_MCP_tool', 'reserved_Pair_join_and_dual_Owner_consent',
                              'ordinary_prompt_skill_plugin_passthrough', 'native_queue_consumption', 'real_model_provider',
                              'Windows_DPAPI', 'Windows_ACL', 'Windows_GUI', 'Android', 'public_HTTPS']
    elif mode == 'codex-product-cold':
        summary['not_run'] = ['automatic_FB03_Owner_key_delivery', 'literal_leave_same_SID_reregister_left_retention',
                              'A_B_frozen_scope_heartbeat_cancellation', 'actual_App_process_closed_during_cold_interval',
                              'valid_ticket_replay_cross_context_and_fork', 'original_operator_intent_response_loss_recovery',
                              'ordinary_prompt_skill_plugin_passthrough', 'native_queue_consumption', 'real_model_provider',
                              'Windows_DPAPI', 'Windows_ACL', 'Windows_GUI', 'Android', 'public_HTTPS']
    elif mode == 'codex-product-domain-app':
        if domain_not_run:
            summary['scope'] = 'ACTUAL_HUB_CAPABILITY_PREFLIGHT_ONLY_DOMAIN_APP_WORKFLOW_NOT_RUN'
        summary['not_run'] = ([] if passed else ['actual_App_local_policy_preview_activate_read_revoke',
                                               'activation_loss_original_packet_reconcile',
                                               'normal_App_Controller_Close_policy_retained']) + [
                              'actual_native_A_B_join_without_Pair', 'Host_ASK_Reply', 'new_domain_other_UID_context_signing',
                              'actual_Hub_login_TTL_and_Node_report_expiry', 'empty_policy_cache_full_pagination_recovery',
                              'stale_epoch_and_foreign_scope', 'legacy_Pair',
                              'real_model_provider', 'native_queue_consumption', 'automatic_wake', 'Windows_DPAPI',
                              'Windows_ACL', 'Windows_GUI', 'Android', 'public_HTTPS']
    elif mode == 'codex-product-domain-native':
        if domain_not_run:
            summary['scope'] = 'ACTUAL_HUB_CAPABILITY_PREFLIGHT_ONLY_NATIVE_DOMAIN_WORKFLOW_NOT_RUN'
        summary['native_domain_measurement'] = native
        summary['native_domain_measurement_valid'] = native_valid
        summary['host_calls_completed'] = native.get('host_calls_completed') if native else None
        summary['host_submission_mode'] = native.get('host_submission_mode') if native else None
        summary['model_turns_started'] = 0  # Static local provider; no real model.
        summary['native_daemon_touched'] = True if native and native.get('status') == 'SCOPED_PASS' else False if domain_not_run else 'UNKNOWN'
        summary['native_failure_location'] = ({key: native.get(key) for key in ('phase', 'label', 'failure_kind', 'failure_code',
                                                                              'hook_result', 'literal_provider_posts', 'provider_posts',
                                                                              'host_provider_posts', 'native_queue_provider_posts',
                                                                              'host_diagnostic')}
                                              if native and native.get('status') in ('FAIL', 'IN_PROGRESS') else None)
        summary['not_run'] = ([] if passed else ['actual_native_domain_main']) + (
            [] if passed and native.get('actual_wall_clock_login_expiry') is True else
            ['actual_Hub_login_expiry_AB_communication_and_new_C']) + [
            'automatic_FB03_Owner_key_delivery', 'new_domain_other_UID_context_and_signing',
            'cross_Node_Owner_Network_and_stale_epoch', 'original_business_request_response_loss_recovery',
            'empty_policy_cache_full_pagination_recovery', 'legacy_Pair_compatibility',
            'graceful_TUI_exit', 'ordinary_prompt_skill_plugin_passthrough', 'real_model_provider',
            'native_queue_model_consumption', 'real_model_automatic_wake', 'Windows_DPAPI', 'Windows_ACL',
            'Windows_GUI', 'Android', 'public_HTTPS']
    elif mode == 'codex-product-other-uid':
        summary['not_run'] = ['Node_user_Network_business_policy', 'domain_context_proof', 'domain_signed_business_request',
                              'actual_Codex_native_TUI_and_Host', 'same_UID_isolation', 'legacy_Pair',
                              'App_close_login_TTL_report_expiry_and_policy_recovery', 'real_model_provider',
                              'native_queue_consumption', 'automatic_wake', 'Windows_DPAPI', 'Windows_ACL',
                              'Windows_GUI', 'Android', 'public_HTTPS']
    elif mode == 'codex-product-three-stage':
        summary['not_run'] = ['Node_user_Network_business_policy', 'other_UID_private_IPC_keys_context_signing',
                              'domain_App_close_login_TTL_revoke_expiry_and_original_retry', 'legacy_Pair_migration',
                              'Pair', 'default_five_minute_cold_lease', 'multi_Node_ambiguity',
                              'graceful_TUI_exit', 'per_call_ticket_business_dispatch', 'cross_pin_cache_pending_outbox_faults',
                              'real_model_provider', 'native_queue_consumption', 'automatic_wake',
                              'Windows_DPAPI', 'Windows_ACL', 'Windows_GUI', 'Android', 'public_HTTPS']
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
