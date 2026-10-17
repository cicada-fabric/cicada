#!/usr/bin/env python3
"""Strict, separate attribution for native-pair protocol acceptance, not N3 UI."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

EXPECTED = {'TestN3NativePair' + suffix for suffix in (
    'BootstrapAndExactReplay', 'WrongNodeScopeIsFenced', 'PrepareLossBeforeForward',
    'CompleteLossAfterCommit', 'MissingOwnerProofCannotBootstrap')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def snapshot(repo, dest):
    # Complete Go/module tree (including embedded assets), not merely selected
    # inputs. The parent worktree is RO throughout compilation and execution.
    paths = [p for p in (repo / 'cicada-go').rglob('*') if p.is_file()]
    paths += [repo / 'scripts' / name for name in ('test-native-pair.sh', 'native_pair_evidence.py')]
    paths += [repo / 'docs' / name for name in ('hub-native-pair-contract.md', 'native-app-plan.md')]
    files = {str(p.relative_to(repo)): sha(p) for p in sorted(paths)}
    save(dest, {'head': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
                'dirty': bool(subprocess.check_output(['git', '--no-optional-locks', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'])),
                'manifest_sha256': hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'files': files})


def finish(run, artifacts, image, owned):
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
    passed = (all(exits.get(n) == 0 for n in ('version', 'compile-cli', 'compile-tests', 'harness', 'vet'))
              and set(results) == EXPECTED and all(v == 'pass' for v in results.values())
              and matched and owned == 'false')
    # WIRE_ONLY + actual 404 is retained as expected RED, with nonzero exit. It
    # cannot turn a missing service, absent scenario, skip, or compiler error green.
    expected_red = (not passed and set(results) == EXPECTED and all(v == 'fail' for v in results.values())
                    and len(diagnostics) == len(EXPECTED)
                    and all('HTTP=404 ' in d['reason'] for d in diagnostics)
                    and all(exits.get(n) == 0 for n in ('version', 'compile-cli', 'compile-tests', 'vet'))
                    and exits.get('harness') == 1 and matched and owned == 'false')
    code = 0 if passed else 1
    summary = {'scope': 'REAL_TCP_PQ_BOOTSTRAP_AND_RECOVERY_ONLY',
               'status': 'SCOPED_PASS' if passed else ('EXPECTED_RED_SERVICE_UNAVAILABLE' if expected_red else 'FAIL'),
               'exit_code': code, 'exit_codes': exits, 'docker_image_digest': image,
               'source_before_sha256': sha(run / 'source-before.json'),
               'source_after_sha256': sha(run / 'source-after.json'),
               'source_stable': matched, 'head': before['head'], 'dirty': before['dirty'],
               'source_manifest_sha256': before['manifest_sha256'], 'input_count': len(before['files']),
               'container_absent': owned == 'false', 'tests': results, 'missing': sorted(EXPECTED - set(results)),
               'diagnostics': diagnostics, 'http_measurements': metrics,
               'artifacts': {p.name: {'sha256': sha(p), 'bytes': p.stat().st_size} for p in artifacts.iterdir() if p.is_file()},
               'evidence_sha256': {p.name: sha(p) for p in run.iterdir() if p.is_file() and p.name != 'result.json'},
               'not_run': ['production_App_native_pair', 'Node_reserved_slot_Join', 'dual_Owner_consent',
                           'actual_Codex_dialogue', 'same_Node_sealed_Relay', 'native_queue_consumption',
                           'Windows_DPAPI', 'Windows_ACL', 'Windows_GUI'],
               'private_payloads_exported': False, 'model_turns_started': 0,
               'native_daemon_touched': False, 'public_deployment_touched': False}
    save(run / 'result.json', summary)
    print(f"Native pair {summary['status']} exit={code} evidence={run / 'result.json'}")
    raise SystemExit(code)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'snapshot':
        snapshot(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 6 and sys.argv[1] == 'finish':
        finish(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])
    else:
        raise SystemExit('Usage: native_pair_evidence.py snapshot REPO DEST | finish EVIDENCE ARTIFACTS IMAGE OWNED_PRESENT')
