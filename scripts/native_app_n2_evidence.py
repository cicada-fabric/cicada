#!/usr/bin/env python3
"""Source/artifact accounting for the independent N2 gate (stdlib only)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def matrix_evidence(state):
    # States apply only to the listed layers. Physical runs and a real
    # fifteen-minute wait cannot inherit a green Linux aggregate result.
    rows = {
        1: ('TCP_APP_PREFLIGHT', ['TestN2ActivationPinAndConsentBeforeSecrets/wrong-full-pin']),
        2: ('TCP_REAL_TIME_AND_APP_PREFLIGHT', ['TestN2ActivationPinAndConsentBeforeSecrets/expired', 'TestN2ActivationExpiredProofAndCancelledMaterial/expired-real-credential']),
        3: ('TCP_PERSISTENT_PROCESSES', ['TestN2ActivationConcurrentDistinctClaimsAndExactCompletion', 'TestN2ActivationReplacementAfterFencedCancellationPreservesKeys']),
        4: ('TCP_PERSISTENT_PROCESSES_AND_RACE', ['TestN2ActivationConcurrentDistinctClaimsAndExactCompletion']),
        5: ('TCP_SERVER_NEGATIVE', ['TestN2AccountForeignScopeAndMissingDeviceProof', 'TestN2ActivationCryptographicNegativeGuards/wrong-owner-scope']),
        6: ('TCP_CRYPTO_AND_DATABASE', ['TestN2ActivationCryptographicNegativeGuards/missing-kem', 'TestN2ActivationCryptographicNegativeGuards/missing-owner-signature', 'TestN2ActivationCryptographicNegativeGuards/wrong-owner-signature']),
        7: ('TCP_CRYPTO_REAL_SHORT_EXPIRY', ['TestN2ActivationCryptographicNegativeGuards/forged-grant', 'TestN2ActivationCryptographicNegativeGuards/wrong-grant-purpose', 'TestN2ExpiredGrantChallengeCannotActivateRoot']),
        8: ('TCP_EPOCH_FAULT_AND_STORE_RESTORE_FENCE', ['TestN2ActivationHistoricalReceiptNeverRevivesCurrentAuthority', 'TestN2ActivationAppRestoreEpochSettlesOldReceiptWithoutRevival', 'TestN2RestoreFencesLeaseAndPreservesCredentialAndRoot']),
        9: ('TCP_SERVER_DEVICE_AND_DISPATCH_GUARD', ['TestN2AccountUnknownDeviceCannotUsePassword', 'TestN2ActivationCryptographicNegativeGuards/wrong-app-key', 'TestN2ClientDispatchAndCapabilitiesIntersectFiniteLease']),
        10: ('TCP_FAULT_PROXY', ['TestN2AccountProcessRecovery', 'TestN2ActivationAppProcessesAndLargeStatusRecovery']),
        11: ('SIGKILL_HUB_APP_PERSISTENT_DATABASE_VAULT', ['TestN2AccountProcessRecovery', 'TestN2ActivationAppProcessesAndLargeStatusRecovery']),
        12: ('TCP_CONFLICT_AND_NONCE_REPLAY', ['TestN2ActivationConcurrentDistinctClaimsAndExactCompletion', 'TestN2ActivationCryptographicNegativeGuards/reused-nonce']),
        13: ('TCP_HUB_APP_CORE_WITHOUT_CONTROL', ['TestN2AccountProcessRecovery', 'TestN2ActivationAppProcessesAndLargeStatusRecovery']),
        14: ('TCP_REAL_OPENSSL_IMPORT', ['TestN2ActivationLegacyImportedOwnerKeepsCredentialAndIDs']),
        15: ('APP_PROCESS_PROFILE_REOPEN_NO_CODE', ['TestN2ActivationAppProcessesAndLargeStatusRecovery', 'TestN2ActivationAppRestoreEpochSettlesOldReceiptWithoutRevival']),
        16: ('APP_REAL_FILESYSTEM_FAILURE_BEFORE_TCP', ['TestN2ActivationVaultFailureBeforeSend']),
        17: ('TWO_TCP_HUBS_ONE_VAULT_ROOT', ['TestN2ActivationTwoHubVaultScopesRemainIndependent']),
        19: ('APP_CONFIG_NOW_AND_STORE_LOGICAL_CLOCK', ['TestN2ActivationAppClockExpiryDoesNotRenewLease', 'TestN2LeaseGuardExpiryScopeAndExactHistoricalRecovery']),
        20: ('TCP_LATE_ORIGINAL_AND_DURABLE_FENCE_RACE', ['TestN2ActivationAbsentStatusKeepsPendingUntilLateOriginal', 'TestN2AccountReconcileFencesLateCorrectRequestAcrossRestart']),
        21: ('TCP_APP_AUTHENTICATED_RECONCILIATION', ['TestN2ActivationAppWrongPasswordFenceAndRelogin']),
        22: ('TCP_SESSION_REVOCATION_EPOCH_FAULT_AND_PAST_DATABASE_EXPIRY', ['TestN2ActivationAppWrongPasswordFenceAndRelogin', 'TestN2ActivationAppRestoreEpochSettlesOldReceiptWithoutRevival', 'TestN2AccountWrongPasswordAndExpiredSessionRecoverWithDurableFence']),
    }
    result = {f'N2-{i:02}': {'state': state, 'layer': layer, 'tests': tests}
              for i, (layer, tests) in rows.items()}
    result['N2-08']['limit'] = 'SQL account-epoch transition plus real Store restore fence; full backup/restore NOT_RUN.'
    result['N2-19']['limit'] = 'Actual fifteen-minute end-to-end wait NOT_RUN.'
    for i, layer in ((18, 'WINDOWS_DPAPI_ACL_GUI'), (23, 'WINDOWS_INTERACTION_VISUAL_REVIEW')):
        result[f'N2-{i:02}'] = {'state': 'NOT_RUN', 'layer': layer, 'tests': []}
    return result


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def snapshot(repo, dest):
    # Include embedded assets/fixtures as well as Go: the test binary imports
    # the actual Hub handler, whose embedded UI bytes are build inputs too.
    paths = sorted(p for p in (repo / 'cicada-go').rglob('*') if p.is_file())
    paths.extend(sorted(p for p in (repo / 'scripts').glob('*native*app*n2*') if p.is_file()))
    paths.extend(repo / 'docs' / name for name in (
        'native-app-architecture.md', 'native-app-plan.md', 'native-app-validation.md'))
    paths.extend((repo / 'README.md', repo / 'docs' / 'README.md'))
    paths.extend(p for p in (repo / 'docs').glob('*activation*') if p.is_file())
    files = {str(p.relative_to(repo)): sha(p) for p in sorted(set(paths))}
    manifest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    save(dest, {
        'head': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
        'branch': subprocess.check_output(['git', '-C', str(repo), 'branch', '--show-current'], text=True).strip(),
        'dirty': bool(subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'])),
        'manifest_sha256': manifest, 'files': files,
    })


def events(path):
    result = {}
    if not path.is_file():
        return result
    for line in path.read_text(errors='replace').splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get('Action') in ('pass', 'fail', 'skip') and 'Test' in event:
            # Keep package identity where present; the compiled binary lane has no package tag.
            key = (event.get('Package', ''), event['Test'])
            # A later duplicate pass event must not hide an earlier failure.
            rank = {'pass': 0, 'skip': 1, 'fail': 2}
            if rank[event['Action']] >= rank.get(result.get(key), -1):
                result[key] = event['Action']
    return result


def containers(dest, reference=None):
    names = set(filter(None, os.environ.get('CICADA_N2_RESIDENT_NAMES', '').split(',')))
    if reference:
        ids = [row['id'] for row in json.loads(reference.read_text())]
    else:
        ids = sorted(names) if names else subprocess.check_output(['docker', 'ps', '-q', '--no-trunc'], text=True).split()
    rows = []
    for cid in ids:
        # Ask Docker for only the necessary metadata, never its environment.
        fields = '{{.Id}} {{.Name}} {{.Image}} {{.State.Status}} {{.State.StartedAt}} {{.HostConfig.AutoRemove}}'
        proc = subprocess.run(['docker', 'inspect', '--format', fields, cid], capture_output=True, text=True)
        if proc.returncode:
            if reference or names:
                rows.append({'id': cid, 'missing': True})
            continue
        identity, name, image, state, started, auto_remove = proc.stdout.strip().split()
        name = name.lstrip('/')
        if not reference:
            if names and name not in names:
                continue
            if not names and auto_remove == 'true':
                continue
            if not names and name.startswith(('cicada-n2-', 'cicada-interop-')):
                continue
        rows.append({'id': identity, 'name': name, 'image': image, 'state': state, 'started_at': started})
    save(dest, sorted(rows, key=lambda row: row['id']))


def finish(run, artifacts, image, required, owned):
    before = json.loads((run / 'source-before.json').read_text())
    after = json.loads((run / 'source-after.json').read_text())
    lanes = {p.stem: int(p.read_text()) for p in run.glob('*.exit')}
    process = events(run / 'account-process.log')
    guards = events(run / 'existing-guards.log')
    expected_process = {
        'TestN2AccountProcessRecovery', 'TestN2AccountPinAndExpiryBeforeSecrets',
        'TestN2AccountConcurrentClaimAndConflictingReplay',
        'TestN2AccountForeignScopeAndMissingDeviceProof', 'TestN2AccountUnknownDeviceCannotUsePassword',
    }
    expected_process.update('TestN2AccountProcessRecovery/' + mode for mode in
                            ('before', 'drop', 'unsigned403', 'corrupt'))
    expected_process.update('TestN2AccountProcessRecovery/' + mode + '/' + step
                            for mode in ('before', 'drop', 'unsigned403', 'corrupt')
                            for step in ('prepare', 'complete', 'login_prepare', 'login_complete', 'inspect', 'logout'))
    expected_process.update('TestN2AccountPinAndExpiryBeforeSecrets/' + case
                            for case in ('wrong-full-pin', 'expired'))
    expected_process.update('TestN2AccountForeignScopeAndMissingDeviceProof/' + case
                            for case in ('wrong-owner', 'wrong-hub', 'missing-signature', 'forged-ciphertext'))
    expected_guards = {
        'TestControllerRealHTTPAccountFlowAndExactUncertainRecovery',
        'TestActivationAndConnectionCardBoundaries',
        'TestHubOwnerWithoutControlProvesKeysAndPreservesPermanentHistory',
        'TestOwnerDeviceGrantVerifiesExactTrustedEnrollment',
        'TestOwnerDeviceGrantRejectsTamperingNoncanonicalAndInvalidTime',
        'TestHubAccountPQHTTPFlowSurvivesRestartAndRecoversRevokedLogout',
        'TestOwnerAccountClaimCodeRoundTripAndStrictFraming',
        'TestActivationManifestMatchesWire',
        'TestActivationProofAndExactPacketRoundTrip',
        'TestActivationCodeAndLegacyExactIdentity',
        'TestActivationRejectsBindingNonceGrantAndLeaseSubstitution',
        'TestActivationChallengeCannotSettleAnotherExactPacket',
        'TestAccountReconcileAndStatusBindExactTarget',
    }
    missing = sorted(expected_process - {t for (_, t), a in process.items() if a == 'pass'})
    missing += sorted(expected_guards - {t for (_, t), a in guards.items() if a == 'pass'})
    baseline_events = list(process.values()) + list(guards.values())
    n2 = events(run / 'n2-process.log') if required else {}
    n2_guards = events(run / 'n2-guards.log') if required else {}
    n2_race = events(run / 'n2-race.log') if required else {}
    expected_n2 = {
        'TestN2ActivationCryptographicNegativeGuards',
        'TestN2ActivationConcurrentDistinctClaimsAndExactCompletion',
        'TestN2ActivationExpiredProofAndCancelledMaterial',
        'TestN2AccountReconcileFencesLateCorrectRequestAcrossRestart',
        'TestN2ActivationHistoricalReceiptNeverRevivesCurrentAuthority',
        'TestN2ActivationPinAndConsentBeforeSecrets',
        'TestN2ActivationAppClockExpiryDoesNotRenewLease',
        'TestN2ActivationVaultFailureBeforeSend',
        'TestN2ActivationTwoHubVaultScopesRemainIndependent',
        'TestN2ActivationAppProcessesAndLargeStatusRecovery',
        'TestN2ActivationAppWrongPasswordFenceAndRelogin',
        'TestN2ActivationAbsentStatusKeepsPendingUntilLateOriginal',
        'TestN2ActivationAppRestoreEpochSettlesOldReceiptWithoutRevival',
        'TestN2ActivationReplacementAfterFencedCancellationPreservesKeys',
        'TestN2ActivationLegacyImportedOwnerKeepsCredentialAndIDs',
    }
    expected_n2.update('TestN2ActivationCryptographicNegativeGuards/' + name for name in
                      ('missing-kem', 'missing-owner-signature', 'wrong-owner-signature', 'reused-nonce',
                       'stale-account-epoch', 'wrong-owner-scope', 'wrong-app-key', 'forged-grant', 'wrong-grant-purpose'))
    expected_n2.update('TestN2ActivationExpiredProofAndCancelledMaterial/' + name for name in
                      ('expired-real-credential', 'expired-real-proof-window', 'cancelled-material-and-late-request'))
    expected_n2.update('TestN2ActivationHistoricalReceiptNeverRevivesCurrentAuthority/' + name for name in
                      ('root-revoked', 'account-epoch'))
    expected_n2.update('TestN2ActivationPinAndConsentBeforeSecrets/' + name for name in
                      ('wrong-full-pin', 'expired', 'missing-finite-consent'))
    expected_n2.update('TestN2ActivationAppProcessesAndLargeStatusRecovery/' + mode + '/' + step
                      for mode in ('drop', 'unsigned403', 'corrupt') for step in ('prepare', 'complete', 'status'))
    expected_n2_guards = {
        'TestN2LegacyContinuationRetainsPendingOwnerCredentialAndDevices',
        'TestN2AccountWrongPasswordAndExpiredSessionRecoverWithDurableFence',
        'TestN2AccountReconcileRacesOriginalWithoutLateCommit',
        'TestN2ActivationAtomicProofLeaseAndRestart',
        'TestN2ConcurrentPrepareAndCompleteReserveOneTuple',
        'TestN2MissingProofReusedNonceRollbackAndCancelledEpoch',
        'TestN2ExpiredGrantChallengeCannotActivateRoot',
        'TestN2ClientDispatchAndCapabilitiesIntersectFiniteLease',
        'TestN2LeaseGuardExpiryScopeAndExactHistoricalRecovery',
        'TestN2RestoreFencesLeaseAndPreservesCredentialAndRoot',
        'TestN2DiagnosticReceiptLimitKeepsExactRetryAndTerminalFences',
    }
    expected_n2_race = {'TestN2ActivationConcurrentDistinctClaimsAndExactCompletion',
                        'TestN2AccountReconcileFencesLateCorrectRequestAcrossRestart'}
    n2_missing = []
    if required:
        for expected, actual in ((expected_n2, n2), (expected_n2_guards, n2_guards), (expected_n2_race, n2_race)):
            n2_missing += sorted(expected - {t for (_, t), a in actual.items() if a == 'pass'})
    n2_events = list(n2.values()) + list(n2_guards.values()) + list(n2_race.values())
    all_events = baseline_events + n2_events
    stable = before == after
    resident_before = json.loads((run / 'containers-before.json').read_text())
    resident_after = json.loads((run / 'containers-after.json').read_text())
    residents_unchanged = (resident_before == resident_after and
                           all(row.get('state') == 'running' and not row.get('missing') for row in resident_before))
    baseline_lanes = {'version', 'compile', 'account-process', 'existing-guards', 'vet'}
    expected_lanes = baseline_lanes | ({'n2-process', 'n2-guards', 'n2-race'} if required else set())
    baseline = (baseline_lanes <= set(lanes) and all(lanes[k] == 0 for k in baseline_lanes) and not missing
                and not any(a in ('fail', 'skip') for a in baseline_events) and stable and not owned and residents_unchanged)
    n2_pass = (required and baseline and set(lanes) == expected_lanes and all(v == 0 for v in lanes.values())
               and not n2_missing and not any(a in ('fail', 'skip') for a in n2_events))
    n2_state = 'SCOPED_PASS' if n2_pass else ('FAIL' if required else 'NOT_RUN')
    result = {
        'schema': 'cicada.native-app.n2.acceptance.v1',
        'scope': 'linux-real-hub-app-core-n2' if required else 'existing-account-and-activation-wire-baseline',
        'baseline': 'SCOPED_PASS' if baseline else 'FAIL',
        'n2_acceptance': n2_state,
        'n2_reason': 'Finite Linux protocol scope; native Windows acceptance is separate.' if n2_pass else 'Required N2 integration cases are missing, failed or not requested.',
        'source_head': before['head'], 'source_dirty': before['dirty'],
        'source_manifest_sha256': before['manifest_sha256'], 'source_stable': stable,
        'builder_image': image, 'go_version': (run / 'version.log').read_text().strip(),
        'exit_codes': lanes, 'missing_or_unpassed_tests': missing + n2_missing,
        'test_events': {a: all_events.count(a) for a in ('pass', 'fail', 'skip')},
        'n2_test_events': {a: n2_events.count(a) for a in ('pass', 'fail', 'skip')},
        'test_binary_sha256': sha(artifacts / 'n2.test') if (artifacts / 'n2.test').is_file() else None,
        'owned_container_absent': not owned,
        'resident_containers_unchanged': residents_unchanged,
        'private_fixture_state': 'Task-specific run state outside repository; not an evidence payload.',
        'windows_dpapi': 'NOT_RUN', 'windows_acl': 'NOT_RUN', 'windows_gui': 'NOT_RUN',
        'visual_review': 'NOT_RUN', 'android': 'NOT_RUN', 'native_runtime': 'NOT_RUN',
        'physical_device': 'NOT_RUN', 'public_https': 'NOT_RUN', 'native_pqtls': 'NOT_RUN',
        'standard_client_docker_interop': 'NOT_RUN_IN_THIS_LANE; integration owner runs separately',
        'expiry_layers': {'short_credential_window': 'REAL_TIME_TCP' if n2_pass else 'NOT_ACCEPTED',
                          'short_proof_window': 'REAL_TIME_TCP' if n2_pass else 'NOT_ACCEPTED',
                          'runtime_lease_guard': 'STORE_LOGICAL_CLOCK' if n2_pass else 'NOT_ACCEPTED',
                          'app_deadline': 'APP_CONFIG_NOW' if n2_pass else 'NOT_ACCEPTED',
                          'account_session': 'PAST_DATABASE_EXPIRY_TCP' if n2_pass else 'NOT_ACCEPTED',
                          'real_15_minute_wait': 'NOT_RUN'},
        'matrix': matrix_evidence(n2_state),
    }
    result['exit_code'] = 0 if baseline and (not required or n2_pass) else 1
    save(run / 'result.json', result)
    files = {str(p.relative_to(run)): sha(p) for p in sorted(run.rglob('*')) if p.is_file() and p.name != 'artifacts.sha256.json'}
    save(run / 'artifacts.sha256.json', files)
    print(f"N2 artifacts: {run}")
    print(f"baseline={result['baseline']} n2={n2_state} exit={result['exit_code']}")
    sys.exit(result['exit_code'])


if __name__ == '__main__':
    if sys.argv[1] == 'snapshot':
        snapshot(Path(sys.argv[2]), Path(sys.argv[3]))
    elif sys.argv[1] == 'finish':
        finish(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5] == 'true', sys.argv[6] == 'true')
    elif sys.argv[1] == 'containers':
        containers(Path(sys.argv[2]), Path(sys.argv[3]) if len(sys.argv) > 3 else None)
    else:
        raise SystemExit('unknown evidence operation')
