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


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def snapshot(repo, dest):
    # Include embedded assets/fixtures as well as Go: the test binary imports
    # the actual Hub handler, whose embedded UI bytes are build inputs too.
    paths = sorted(p for p in (repo / 'cicada-go').rglob('*') if p.is_file())
    paths.extend(sorted(p for p in (repo / 'scripts').glob('*native*app*n2*') if p.is_file()))
    paths.extend(repo / 'docs' / name for name in (
        'native-app-architecture.md', 'native-app-plan.md', 'native-app-validation.md'))
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
    for line in path.read_text(errors='replace').splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get('Action') in ('pass', 'fail', 'skip') and 'Test' in event:
            # Keep package identity where present; the compiled binary lane has no package tag.
            result[(event.get('Package', ''), event['Test'])] = event['Action']
    return result


def containers(dest, reference=None):
    if reference:
        ids = [row['id'] for row in json.loads(reference.read_text())]
    else:
        ids = subprocess.check_output(['docker', 'ps', '-q', '--no-trunc'], text=True).split()
    names = set(filter(None, os.environ.get('CICADA_N2_RESIDENT_NAMES', '').split(',')))
    rows = []
    for cid in ids:
        # Ask Docker for only the necessary metadata, never its environment.
        fields = '{{.Id}} {{.Name}} {{.Image}} {{.State.Status}} {{.State.StartedAt}} {{.HostConfig.AutoRemove}}'
        proc = subprocess.run(['docker', 'inspect', '--format', fields, cid], capture_output=True, text=True)
        if proc.returncode:
            if reference:
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
    all_events = list(process.values()) + list(guards.values())
    stable = before == after
    residents_unchanged = (json.loads((run / 'containers-before.json').read_text()) ==
                           json.loads((run / 'containers-after.json').read_text()))
    baseline = (set(lanes) == {'version', 'compile', 'account-process', 'existing-guards', 'vet'}
                and all(v == 0 for v in lanes.values()) and not missing
                and not any(a in ('fail', 'skip') for a in all_events) and stable and not owned and residents_unchanged)
    result = {
        'schema': 'cicada.native-app.n2.acceptance.v1',
        'scope': 'existing-account-and-activation-wire-baseline',
        'baseline': 'SCOPED_PASS' if baseline else 'FAIL',
        'n2_acceptance': 'NOT_RUN',
        'n2_reason': 'N2 server/App activation integration and full fault matrix not executed in this lane.',
        'source_head': before['head'], 'source_dirty': before['dirty'],
        'source_manifest_sha256': before['manifest_sha256'], 'source_stable': stable,
        'builder_image': image, 'exit_codes': lanes, 'missing_or_unpassed_tests': missing,
        'test_events': {a: all_events.count(a) for a in ('pass', 'fail', 'skip')},
        'test_binary_sha256': sha(artifacts / 'n2.test') if (artifacts / 'n2.test').is_file() else None,
        'owned_container_absent': not owned,
        'resident_containers_unchanged': residents_unchanged,
        'private_fixture_state': 'Task-specific run state outside repository; not an evidence payload.',
        'windows_dpapi': 'NOT_RUN', 'windows_acl': 'NOT_RUN', 'windows_gui': 'NOT_RUN',
        'visual_review': 'NOT_RUN', 'android': 'NOT_RUN', 'native_runtime': 'NOT_RUN',
        'physical_device': 'NOT_RUN', 'public_https': 'NOT_RUN', 'native_pqtls': 'NOT_RUN',
        'standard_client_docker_interop': 'NOT_RUN_IN_THIS_LANE; integration owner runs separately',
    }
    result['exit_code'] = 1 if not baseline else (3 if required else 0)
    save(run / 'result.json', result)
    files = {str(p.relative_to(run)): sha(p) for p in sorted(run.rglob('*')) if p.is_file() and p.name != 'artifacts.sha256.json'}
    save(run / 'artifacts.sha256.json', files)
    print(f"N2 artifacts: {run}")
    print(f"baseline={result['baseline']} n2=NOT_RUN exit={result['exit_code']}")
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
