#!/usr/bin/env python3
"""Validate native Windows phase receipts; Python is required only on the reviewer host."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

PREFIX = 'TestN2NativeWindows'
TESTS = [PREFIX + s for s in ('Context', 'ProtectorRoundTrip', 'VaultAndACL', 'ACLRejectsTampering',
                              'CrossUserProduce', 'CrossUserVerifyA', 'CrossUserRejectB')]
TAMPER = ('directory-extra-ace', 'vault-extra-ace', 'lock-extra-ace', 'directory-inheritance')
PHASE_A = TESTS[:6]
PHASE_B = [TESTS[0], TESTS[6]]


class InvalidEvidence(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path, limit=1048576):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, 'Missing, linked or oversized evidence file')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def parse_run(text, name, run_id, exit_code):
    require(exit_code == 0, 'Nonzero native phase exit')
    expected = [name] + ([name + '/' + mode for mode in TAMPER] if name == TESTS[3] else [])
    runs, passes, receipts, complete = [], [], [], 0
    for line in text.splitlines():
        trimmed = line.lstrip()
        require(not re.match(r'--- (FAIL|SKIP):|FAIL(?:\s|$)', trimmed) and 'no tests to run' not in trimmed,
                'A failed, skipped or empty test cannot pass')
        match = re.fullmatch(r'=== RUN\s+(\S+)', trimmed)
        if match:
            runs.append(match[1])
        match = re.match(r'--- PASS: (\S+) \(', trimmed)
        if match:
            passes.append(match[1])
        if trimmed == 'PASS':
            complete += 1
        if line.startswith('N2_NATIVE_RESULT '):
            r = json.loads(line[len('N2_NATIVE_RESULT '):])
            require(r.get('schema') == 'cicada.n2.windows.native-result.v1' and r.get('run_id') == run_id,
                    'Native receipt schema/run mismatch')
            require(isinstance(r.get('sid'), str) and r['sid'].startswith('S-') and digest(r.get('machine_sha256'))
                    and re.fullmatch(r'\d+\.\d+\.\d+', r.get('windows_build', ''))
                    and type(r.get('ordinary_user')) is bool and r.get('assertions'), 'Incomplete native actor/assertions')
            receipts.append(r)
    require(sorted(runs) == sorted(expected) and sorted(passes) == sorted(expected) and complete == 1,
            'Required cases missing, duplicate or unexpected')
    require(sorted(r['test'] for r in receipts) == sorted(expected), 'Required native receipts missing or duplicate')
    return receipts


def acl_valid(a, sid):
    if a.get('owner') != sid or a.get('protected') is not True or len(a.get('entries', [])) != 2:
        return False
    flags = 3 if a.get('directory') else 0
    return (sorted(e.get('sid', '') for e in a['entries']) == sorted([sid, 'S-1-5-18'])
            and all(e.get('type') == 0 and e.get('mask') == 0x1f01ff and e.get('flags') == flags for e in a['entries']))


def verify_phase(directory, build_path):
    directory = Path(directory)
    r = load(directory / 'result.json')
    build = load(Path(build_path))
    require(build.get('schema') == 'cicada.n2.windows.native-build.v1', 'Wrong build manifest')
    require(r.get('schema') == 'cicada.n2.windows.native-phase.v1' and r.get('phase') in ('A', 'B'), 'Wrong phase schema')
    require(re.fullmatch('[0-9a-f]{32}', r.get('run_id', '')), 'Wrong run ID')
    require(r.get('build_manifest_sha256') == sha(Path(build_path)) and sha(directory / 'build-manifest.json') == sha(Path(build_path)),
            'Build provenance differs')
    require(r.get('exe_sha256') == build['files']['cicada-appvault-tests.exe'] and
            r.get('runner_sha256') == build['files']['run-native-app-n2-windows.ps1'], 'Executable/runner provenance differs')
    require(r.get('status') != 'FAIL', 'Failed native phase')
    not_run = r.get('status') == 'NOT_RUN'
    names = [TESTS[0]] if not_run else (PHASE_A if r['phase'] == 'A' else PHASE_B)
    require([case.get('name') for case in r.get('tests', [])] == names, 'Phase cases missing, duplicated or out of order')
    index = load(directory / 'artifacts.sha256.json')
    expected_files = {'result.json', 'build-manifest.json', 'test-list.log'} | {name + '.log' for name in names}
    require(set(index) == expected_files, 'Evidence index has missing or unexpected files')
    for name, value in index.items():
        require(digest(value) and sha(directory / name) == value, 'Evidence index hash differs')
    require(sorted((directory / 'test-list.log').read_text().splitlines()) == sorted(TESTS), 'Native test inventory differs')
    receipts = {}
    for case in r['tests']:
        require(case.get('log') == case['name'] + '.log' and case.get('log_sha256') == index[case['log']], 'Case log binding differs')
        parsed = parse_run((directory / case['log']).read_text(), case['name'], r['run_id'], case.get('exit_code'))
        require(parsed == case.get('receipts'), 'Parsed receipts differ from phase result')
        receipts.update({item['test']: item for item in parsed})
    context = receipts[TESTS[0]]
    require(context == r.get('context'), 'Native context differs')
    for item in receipts.values():
        require(all(item[field] == context[field] for field in ('sid', 'machine_sha256', 'windows_build', 'ordinary_user')),
                'Actor changed within native phase')
    if not_run:
        require(r['phase'] == 'B' and r.get('exit_code') == 2 and context['ordinary_user'] is False and r.get('cross_user') == 'NOT_RUN',
                'NOT_RUN is only valid for the explicit nonordinary B prerequisite')
        return r, receipts
    require(r.get('status') == 'SCOPED_PASS_PHASE_' + r['phase'] and r.get('exit_code') == 0 and not r.get('failure'), 'Wrong phase completion/exit')
    require(digest(r.get('fixture_sha256')) and digest(r.get('entropy_sha256')), 'Missing fixture/entropy binding')
    if r['phase'] == 'A':
        acls = receipts[TESTS[2]].get('acls', [])
        require({a.get('object') for a in acls} == {'directory', 'vault', 'lock'} and len(acls) == 3
                and all(acl_valid(a, context['sid']) for a in acls), 'Native positive ACL invariants differ')
        for mode in TAMPER:
            acls = receipts[TESTS[3] + '/' + mode].get('acls', [])
            require(len(acls) == 2 and acls[0] == acls[1] and not acl_valid(acls[0], context['sid']), 'Tampered ACL was accepted/repaired or evidence differs')
        for name in TESTS[4:6]:
            item = receipts[name]
            require(item.get('fixture_sha256') == r['fixture_sha256'] and item.get('entropy_sha256') == r['entropy_sha256']
                    and item.get('producer_sid') == context['sid'], 'Producer exact-transfer controls differ')
        require(receipts[TESTS[5]].get('unwrap_attempted') is True and r.get('producer_sid') == context['sid']
                and r.get('cross_user') == 'NOT_RUN', 'Missing separate-process A decryption or false cross-user claim')
    else:
        b = receipts[TESTS[6]]
        required = {'exact-transfer-bytes-read-and-hashed', 'same-entropy', 'same-host', 'different-ordinary-user-sid',
                    'consumer-own-dpapi-control', 'actual-producer-unwrap-rejected'}
        require(context['ordinary_user'] and b.get('producer_sid') != context['sid'] and b.get('producer_sid') == r.get('producer_sid')
                and b.get('unwrap_attempted') is True and b.get('fixture_sha256') == r['fixture_sha256']
                and b.get('entropy_sha256') == r['entropy_sha256'] and set(b['assertions']) == required,
                'Consumer read/hash/SID/own-control/actual-unwrap proof incomplete')
        require(r.get('cross_user') == 'CONSUMER_REJECTION_OBSERVED_REQUIRES_MATCHING_PHASE_A', 'Consumer overclaims paired acceptance')
    return r, receipts


def verify_pair(producer, consumer, build_path):
    a, _ = verify_phase(producer, build_path)
    require(a['phase'] == 'A', 'Producer receipt is not phase A')
    result = {'schema': 'cicada.n2.windows.native-review.v1', 'phase_a': 'SCOPED_PASS', 'cross_user': 'NOT_RUN',
              'exit_code': 2, 'run_id': a['run_id'], 'reason': 'No ordinary Windows B receipt supplied.'}
    if consumer is None:
        return result
    b, _ = verify_phase(consumer, build_path)
    require(b['phase'] == 'B', 'Consumer receipt is not phase B')
    require(b['run_id'] == a['run_id'] and b['context']['machine_sha256'] == a['context']['machine_sha256'],
            'Consumer prerequisite receipt belongs to another run/host')
    if b['status'] == 'NOT_RUN':
        result['reason'] = b['failure']
        return result
    require(all(a[k] == b[k] for k in ('run_id', 'exe_sha256', 'runner_sha256', 'build_manifest_sha256',
                                     'fixture_sha256', 'entropy_sha256', 'producer_sid')), 'A/B fixture, entropy or executable differs')
    require(a['context']['machine_sha256'] == b['context']['machine_sha256'] and
            a['context']['sid'] == a['producer_sid'] and a['context']['sid'] != b['context']['sid'] and b['context']['ordinary_user'],
            'A/B must be on one machine under distinct SIDs with ordinary B')
    result.update(cross_user='SCOPED_PASS', exit_code=0, reason='A separate-process control and ordinary B rejection share exact ciphertext/entropy.')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', required=True, type=Path)
    p.add_argument('--producer', required=True, type=Path)
    p.add_argument('--consumer', type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    try:
        result = verify_pair(args.producer, args.consumer, args.build)
    except (InvalidEvidence, ValueError, KeyError, OSError, TypeError) as error:
        result = {'schema': 'cicada.n2.windows.native-review.v1', 'status': 'FAIL', 'exit_code': 1, 'reason': str(error)}
    raw = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        with args.output.open('x', encoding='utf-8') as f:
            f.write(raw)
    print(raw, end='')
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
