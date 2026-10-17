#!/usr/bin/env python3
"""Attribute independent N3 gates to exact sources, actors and executed scope."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import shutil
import stat
from datetime import datetime, timezone

EXPECTED = {'TestN3HarnessRealHubReplyRecovery', 'TestN3HarnessDelayedPacketCancellation',
            'TestN3HarnessCommitBeforeReplyCrashWindow', 'TestN3HarnessActualAppBootstrapAndResume',
            'TestN3HarnessActualAppVaultCommitBarrier'}
EXPECTED.update('TestN3HarnessRealHubReplyRecovery/' + mode for mode in
                ('before-forward', 'drop-after-response', 'unsigned-403', 'corrupt-response'))
DISCOVERY_EXPECTED = {'TestN3ActualAppUnsupportedCapabilitiesSendNoSecrets'}
DISCOVERY_EXPECTED.update('TestN3ActualAppUnsupportedCapabilitiesSendNoSecrets/' + mode for mode in
                          ('actual-legacy-hub', 'unsupported-before-forward', 'unknown-profile-before-forward'))
SEED_EXPECTED = {'TestN3SeedRetainedN2Fixture'}
AUTO_EXPECTED = {'TestN3ActualAutomaticStatusKeepsScopeAndSelfCancelledNode',
                 'TestN3ActualAutomaticStatusLossFreezesTicksUntilExactRecovery'}
RUNTIME_TOP = {
    'TestN3ConcurrentPrepareConfirmAndConflictingReplay', 'TestN3ActualVaultFailureStopsBeforeSecretSend',
    'TestN3ServerRejectsIndependentProofScopeAttacks', 'TestN3ServerRejectsForgedCompletionPreservingPreview',
    'TestN3StatusContainsOnlyExactSelectedNode', 'TestN3ActualConfirmationLocalCommitCrashBoundaries',
    'TestN3ReadCacheRollingBoundsAndPermanentMutationRecovery', 'TestN3ActualAppConsentBindingRelayAndWallClockDecay',
    'TestN3ActualAppSelfCancelRequiresExplicitReadOnlyConsent', 'TestN3ActualUnconfirmedSessionReplacementAllowsNewInitial',
    'TestN3OriginalInstanceCannotBorrowNewInitialOrReadGrant', 'TestN3ActualImmediateRelayHeartbeatRetainsSubsecondOrder',
    'TestN3ActualAppUnsupportedCapabilitiesSendNoSecrets', 'TestN3ActualAppExactFaultRecoveryAndLateOriginal',
    'TestN3RealPersistedEpochAndRootSessionFences', 'TestN3RealConfirmationVersusCancellationOrders',
    'TestN3RevokedNodeCannotPublishOrReuseReadProvenance',
}
RUNTIME_EXPECTED = set(RUNTIME_TOP)
for top, cases in {
    'TestN3ServerRejectsIndependentProofScopeAttacks': ('missing-proof', 'forged-signature', 'wrong-signer', 'unauthorized-purpose', 'wrong-owner', 'wrong-account', 'wrong-origin', 'wrong-app-key', 'wrong-hub-public', 'target-substitution', 'expired-intent'),
    'TestN3ServerRejectsForgedCompletionPreservingPreview': ('missing-grant', 'forged-grant', 'wrong-owner-signature', 'broader-operations', 'head-substitution', 'candidate-key-substitution', 'missing-candidate-version'),
    'TestN3ActualConfirmationLocalCommitCrashBoundaries': ('response-durable', 'confirmation-record-durable', 'counter-state-durable'),
    'TestN3ActualUnconfirmedSessionReplacementAllowsNewInitial': ('prepared', 'active-before-confirm'),
    'TestN3ActualAppUnsupportedCapabilitiesSendNoSecrets': ('actual-legacy-hub', 'unsupported-before-forward', 'unknown-profile-before-forward'),
    'TestN3RealPersistedEpochAndRootSessionFences': ('account-epoch', 'device-epoch', 'client-session-epoch', 'account-session-revoked', 'owner-key-revoked'),
    'TestN3RealConfirmationVersusCancellationOrders': ('cancel-first', 'confirm-first', 'concurrent'),
    'TestN3RevokedNodeCannotPublishOrReuseReadProvenance': ('credential-revoked', 'owner-binding-revoked'),
}.items():
    RUNTIME_EXPECTED.update(top + '/' + case for case in cases)
RUNTIME_EXPECTED.update('TestN3ActualAppExactFaultRecoveryAndLateOriginal/' + operation + '/' + mode
                        for operation in ('owner.app_node.prepare', 'owner.app_node.complete', 'nodes.confirm', 'owner.app_node.status', 'owner.app_node.cancel')
                        for mode in ('before-forward', 'drop-after-response', 'unsigned-403', 'unsigned-429', 'unsigned-500', 'corrupt-response'))
AGED_TEST = 'TestN3ActualIdentityFlowAfterWallClockN2Expiry'

CONTRACT = {'revision': 'app-node-authority-v1',
 'types_reviewed_source': 'a545988ac6c038da180413d4f29ffbf740c402d4',
 'reviewed_source': '84d7aeefecccb4d1274d937bbaa0c07eecde5c2b',
 'runtime_reviewed_source': 'ec72bf2891bcc7bf98565beedbac54e51f35b7db',
 'ui_reviewed_source': '84d7aeefecccb4d1274d937bbaa0c07eecde5c2b',
 'status': 'HUB_NODES_ONLY',
 'packet_limits': {'n3_inner': 393216,
                   'default_inner': 262144,
                   'outer': 393216,
                   'body': 196608,
                   'original_and_receipt': 131072},
 'files': {'cicada-go/internal/appui/login_view.go': '8beb7647be81f13de15e0bea4b90a6d6a6968286f2172b16989307a410261367',
           'cicada-go/internal/appui/native/node_update.go': '98f2e8476dde6d35477e582aed55503ceb78718c101102346f4153fc9b302030',
           'cicada-go/internal/appui/native/redraw.go': '234943d3b8b53196e63fe354555aa664c3df6f7a538974327d94c36536348787',
           'cicada-go/internal/appcore/node_auto.go': '8994b0021a48830a461591440f37afffbeb425140487ff9829ca957e774b4f89',
           'cicada-go/cmd/cicada/machine_hub_context.go': '695e4e9372b9508aedc73711ec12401d882e7d5ec7b8f3a115a2bb3ae4fcbe4e',
           'cicada-go/cmd/cicada/machine_agent.go': '7e170fd423e2c61caef4043ba7a979290c4ec203e06906f255ba9362e7c6bcda',
           'cicada-go/cmd/cicada/machine_node_control_rpc.go': '97ea29bad6bba9cc46e30082b7340b9edf3d038292e6b9986e01ce99193b0276',
           'cicada-go/cmd/cicada/main.go': 'e6dab529a09bdfb1647cf241397b4725942d106c7af49ce97dca249c2b2cbd9d',
           'cicada-go/cmd/cicada/serve_hub_nodes.go': 'f8b8659ed01b054c7f63af014276ed8d5637282e858131ab22ca21bd136efdc4',
           'cicada-go/internal/appcore/controller.go': '5671900e10b59ceb2cd45fe3ee52fc977d351d02c8f331febd64430a4b3fe85b',
           'cicada-go/internal/appcore/controller_state.go': '24db2e9bf74cc23573f80c7afa1c6878aebaea63370aea32ae6c871bddcf89dc',
           'cicada-go/internal/appcore/native.go': '776317d9175a0c815133413c3d0747f8a44f89ea6b77227cf88a5d08db9183bf',
           'cicada-go/internal/appcore/node_confirm.go': '9c58d4c0e07ca66a36678b37af5c0bcacd5fdacb17fa2d2c839489ec3151fc3f',
           'cicada-go/internal/appcore/node_ops.go': 'b60d04b79b2ce91ee672d5563d19e0fd3887c3b53f23e6dc6e6ff3a30ac89320',
           'cicada-go/internal/appcore/node_recovery.go': 'ffa4b20a8d67833c44c31869d1472cec26a6bfad5c201dfa9c3cd84c94d80a37',
           'cicada-go/internal/appcore/node_responses.go': '2e920d71b3087f40ebe3f406a63ef90bfe3e4adbb121923e81f9537bf0f6cfb5',
           'cicada-go/internal/appcore/node_state.go': 'ff7d6624a58674a707f552111078082ed8665f40d6936748487665a7b29c12b0',
           'cicada-go/internal/appcore/node_transport.go': '9e6c2f242101484635ba65d322da71ceaf96874d84cb867db789d4e132a2dc2f',
           'cicada-go/internal/appcore/node_view.go': '7e4044dcb6e70b6292c153540ebb654d211602a969a46cf6b5def5f4b57c465a',
           'cicada-go/internal/appcore/profiles.go': '54a56f7af6ae304a086d4e52743580f613b1d6c8b67d7b99efe46d4138732fc7',
           'cicada-go/internal/appcore/types.go': 'd8a2483840a14dd0a7072499e42eecda68e81e2c8bcf365448a52fc88f783407',
           'cicada-go/internal/appui/errors.go': '169ad843434968662fe5f2dde99aa4b02bc24e3c7a3bb60921d40826b0b8a3ee',
           'cicada-go/internal/appui/flow.go': 'cbd4687b13164356a402db210d2de4a7bb188db864dbffe6706c7a9617449825',
           'cicada-go/internal/appui/i18n.go': 'ce9150c8656372ad9f2925b028a06656376760eaa4b115c8cb5909dae138c7cd',
           'cicada-go/internal/appui/native/node_ui.go': '41b43a20b1127b9798e69d2203af74b4901e156d2d53c6c53b1a333a79abe9fc',
           'cicada-go/internal/appui/native/ui.go': 'a73fc221fa43a79796ade4e01c6c3b7ce455ec092fed05c31c3eade1eccabae1',
           'cicada-go/internal/appui/node_flow.go': '1005cd1454f88d120977d46f8af0c339354c4108b00db45ecc58cc0fdba0aa05',
           'cicada-go/internal/clientwire/packet_limits.go': '107b0e1ae419eb4731c997fe767eb5b881fda031c4f2e1b3e74d0db5100002f5',
           'cicada-go/internal/clientwire/wire.go': 'b9bc6d4e58cdcd9c92206821d19d3baf1addeb1f06f3fd453a0c20b4434c1ba4',
           'cicada-go/internal/control/node_control_identity.go': 'ad9ce1342e098aed84d2c3fb31cd7e9b922cbeea75be3d136929c6aba87e81af',
           'cicada-go/internal/control/node_device_bindings.go': '5af1982a21a9254e3b0a1dfc9bdbe07e264b437f71a5fae073ab93424d5bbb2a',
           'cicada-go/internal/e2ee/owner_app_node_claims.go': '75f4c0e9331761a1cf93a98dfab97bab6278cc985d968dba7a50ca11caac933e',
           'cicada-go/internal/e2ee/owner_app_node_proof.go': 'dc08a7d6df1abb190f337df077ce465e8f621fa42284b2394a577edea3f5ee47',
           'cicada-go/internal/hubaccountwire/activation_validation.go': '282e984efb13618033945abd58e6f428a72bac88fb7fc286d17ce748649c6548',
           'cicada-go/internal/hubaccountwire/app-node-contract.json': '6a7c6dba95d3cf43fd84b928b190812326e280a35fab769ba4c4e5dffa4b8492',
           'cicada-go/internal/hubaccountwire/app_node_authority.go': '4a8c4b9ad99d83bdfe7d4a40a85d410ac25c391b9990e16b1d2156cf3d9d3760',
           'cicada-go/internal/hubaccountwire/app_node_authority_validation.go': 'abcd309f3f53697d46a08f6b15120951d89727fb12cc66e111f9b9e541fbbdf9',
           'cicada-go/internal/hubaccountwire/app_node_confirmation.go': 'edb51b6064d2ad5aec18589d7ba95f0c3fbfafb81c88de885ab814ee4b41d1e4',
           'cicada-go/internal/hubaccountwire/app_node_constructors.go': '75eb468c9cee886bdef5cea56045b5f80a8440bde8b16ea4f8bdff7b24c31168',
           'cicada-go/internal/hubaccountwire/app_node_live.go': 'd287f45ca1797e627cc414040d8243438bd591824abb259a7b9016ec8f1c8292',
           'cicada-go/internal/hubaccountwire/app_node_packets.go': '2b72ab0cfad190b08213a5e9d330eea0efc82fa7f41e414ecfaaa9bce0ee2296',
           'cicada-go/internal/hubaccountwire/app_node_response.go': '4f76971f2543161cf2717183d707956529539d7f57ff52718468e75d4ff48562',
           'cicada-go/internal/hubaccountwire/canonical.go': '3905d83254a4b1148a2577d74c2889f49a54fb6846c0ffd74b6014df24a27d43',
           'cicada-go/internal/hubaccountwire/packet.go': '31e3ba8500be8267b434f1b9be24897783f410d4da3c3b08197d8f822e5bf634',
           'cicada-go/internal/hubaccountwire/reconcile.go': '3a1a2f0723e8c61cd18c6d4dc661d5888695ae5635f217199230a48ea62b25f6',
           'cicada-go/internal/hubaccountwire/validation.go': '06bd7ab2719b412048017212b2149b05d7099ac010e50bfeef3accc39c2cf5dc',
           'cicada-go/internal/hubauth/app_node.go': '585a3ada3017bbe4660b996e9ac72ae91c053e84944ae82a2d62e0188c316e8f',
           'cicada-go/internal/hubauth/service.go': '0f46a246844ce77236c02a49546b0603f284bbf7797e214c9f01f749d7c76f5a',
           'cicada-go/internal/hubnodes/service.go': 'ee25863b5038428ea071d310e649ed250c7bd8ed389a8201a201149bc5219f32',
           'cicada-go/internal/nodebinding/service.go': 'e8df083f640f2917d61bcb47c54f6f18fa5eb52d62415ebd5f077eb692a5f7dd',
           'cicada-go/internal/server/hub_account.go': 'e5ec8cc5c8e5613e5105c3d8a6cc42ea3b31d0b5ab82fe3ae62579df9d9acbdc',
           'cicada-go/internal/server/hub_nodes.go': '030e5809c605a85243eaf5ea683ad29e4d2492e3224cd00ef74acf0f6920cc1a',
           'cicada-go/internal/store/client_devices_v2.go': '2fa84da06f02da7f0e84c627d33790f842d0e7184c3690a4f49867d6f0bb71e7',
           'cicada-go/internal/store/client_request_recovery_v2.go': '2beadfb3f2b24c1a83e44c0bf9c647966519470c9f159ecc00cff424a60dcb05',
           'cicada-go/internal/store/hub_account_v1.go': 'ae14f846104d9c48fd75b42dc004fb2537e2bc5f134f2535d0abdd2f1d194d21',
           'cicada-go/internal/store/hub_app_node_authority_v1.go': '36175b98b5d0edc2809b117bebcc62f4e5dbd2aa9fb06fea21874913df343714',
           'cicada-go/internal/store/hub_app_node_client_v1.go': '3c8b6138372bdf42c191b54ce327e67ba905b3595cb69ffb23e433759793cdd7',
           'cicada-go/internal/store/hub_app_node_reconcile_v1.go': 'f1a13e9e49d00ad4e729311657a0d4f7eff4b90e83c4ed08f4fca13bc57e58ec',
           'cicada-go/internal/store/hub_app_node_schema_v1.go': '47e1585f1549b353cf48f31f6401f223125e74ca6d94968753f082ed4eac5de1',
           'cicada-go/internal/store/hub_app_node_state_v1.go': 'e11b1dfaf05d2ed84cc8c3d1319cf2761a95d9fc50ee03924b42e67f27a25299',
           'cicada-go/internal/store/hub_app_node_target_v1.go': 'c89aa40590c8c62c6fae9de87cdeb8c78e17e6530166003e1c91c3fad7dcfc60',
           'cicada-go/internal/store/migrations_v2.go': 'cfcf92232e97fda8bcdc4f7c04e7c42a3c39e3a3eae29fc7b49be60f0f30d8e2',
           'cicada-go/internal/store/node_control_v1.go': 'e04f300a2d7ac3599bbab0766f42f9dca92491d777ffa7637a02d3016ab12996',
           'cicada-go/internal/store/node_device_bindings_v2.go': 'a1a35424e973f1b2cf6333fc26e4f9438c59d23e6e93ad3dfbc7733ceceb59d2',
           'cicada-go/internal/store/node_worker_jobs_v2.go': '74c3028874baea1cc7c88d455adff6ae27ea26445ef81209825e7eafb8f68891',
           'cicada-go/internal/store/state_restore_reconcile.go': '0e5aa30e74073f111dcae5345655edd864b5749175aceb685119f7606fbd3a7b',
           'docs/hub-app-node-authority-contract.md': 'e118e6232761db165d1a224434e7328dbb2273a0207789bb60dfea1db5c520bc',
           'docs/hub-nodes-only.md': '1b8960c826bd8a47d8b47e6663066348b4334aed59beaef3fb0a02f323d36767',
           'scripts/app-node-authority-contract.py': 'fd687b8777ea0506f7c367ba92d6fcc8123a7d2c0c84f0322e50645c6d8f38e1'},
 'helpers_reviewed_source': '5f509befa6065ac41abeb23451ef8d41cc2c76aa',
 'schema': 63,
 'requires_n2_client_session_epoch': 1,
 'login_required': 'No valid matching bound login; grant expiry/self-cancel alone does not require login.',
 'reviewed_app_source': '84d7aeefecccb4d1274d937bbaa0c07eecde5c2b',
 'app_phase': 'CONTROLLER_IMPLEMENTED',
 'store_reviewed_source': 'e078c58d97413f5e0457acb3c586afbef1a9d438'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def copy_aged_seed(source, dest, task_root, receipt):
    source, task_root = source.resolve(), task_root.resolve()
    if source.name != 'retained-aged-n2' or not source.is_relative_to(task_root) or dest.exists():
        raise ValueError('Only a stopped task-owned synthetic template may be copied into a new fixture.')
    seed = json.loads((source / 'synthetic-aged-n2-receipt.json').read_text())
    end = datetime.fromisoformat(seed['immutable_n2_expires_at'].replace('Z', '+00:00'))
    if (seed.get('synthetic_acceptance_only_never_deploy') is not True or not seed.get('writers_stopped_at')
            or not seed.get('seed_source_head') or datetime.now(timezone.utc) < end):
        raise ValueError('Synthetic N2 template is missing stopped provenance or has not naturally expired.')
    files = {}
    for p in sorted(source.rglob('*')):
        mode = p.lstat().st_mode
        if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            raise ValueError('Private fixture templates cannot contain symlinks or special files.')
        if p.is_file(): files[str(p.relative_to(source))] = sha(p)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    shutil.copytree(source, dest)
    dest.chmod(0o700)
    for p in dest.rglob('*'): p.chmod(0o700 if p.is_dir() else 0o600)
    if any(sha(dest / path) != expected for path, expected in files.items()):
        raise ValueError('Private fixture copy differs from its stopped source image.')
    save(receipt, {'scope': 'SYNTHETIC_ACCEPTANCE_TEMPLATE_ONLY', 'source': str(source),
                   'source_tree_sha256': digest, 'immutable_n2_expires_at': seed['immutable_n2_expires_at'],
                   'seed_source_head': seed['seed_source_head'], 'seed_writers_stopped_at': seed['writers_stopped_at'],
                   'copied_after_real_expiry': True, 'source_unmodified': True})


def snapshot(repo, dest):
    paths = [p for p in (repo / 'cicada-go').rglob('*') if p.is_file()]
    paths += [p for p in (repo / 'scripts').glob('*native*app*n3*') if p.is_file()]
    paths += [repo / 'docs' / name for name in ('native-app-plan.md', 'native-app-validation.md',
                                              'native-app-architecture.md', 'README.md')]
    paths += [p for p in (repo / 'docs').glob('*app*node*authority*') if p.is_file()]
    paths += [repo / path for path in CONTRACT['files'] if (repo / path).is_file()]
    files = {str(p.relative_to(repo)): sha(p) for p in sorted(paths)}
    save(dest, {'head': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
                'dirty': bool(subprocess.check_output(['git', '--no-optional-locks', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'])),
                'manifest_sha256': hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'files': files})


def events(path):
    result = {}
    if not path.is_file():
        return result
    rank = {'pass': 0, 'skip': 1, 'fail': 2}
    for line in path.read_text(errors='replace').splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if 'Test' in r and r.get('Action') in rank and rank[r['Action']] >= rank.get(result.get(r['Test']), -1):
            result[r['Test']] = r['Action']
    return result


def finish(run, artifacts, image, required, owned_present, mode='preparation', case=None):
    before, after = [json.loads((run / ('source-' + side + '.json')).read_text()) for side in ('before', 'after')]
    codes = {p.stem: int(p.read_text()) for p in run.glob('*.exit')}
    got = events(run / 'harness.log')
    expected = {'discovery': DISCOVERY_EXPECTED, 'seed': SEED_EXPECTED, 'auto': AUTO_EXPECTED,
                'runtime': RUNTIME_EXPECTED | ({AGED_TEST} if required else set())}.get(mode, EXPECTED)
    if mode == 'case':
        if case not in RUNTIME_TOP: raise ValueError('Unknown independent runtime case')
        expected = {name for name in RUNTIME_EXPECTED if name == case or name.startswith(case + '/')}
    missing = sorted(expected - {name for name, action in got.items() if action == 'pass'})
    lanes = {'version', 'compile-cli', 'compile-tests', 'harness', 'vet'}
    binaries = all((artifacts / name).is_file() and (artifacts / name).stat().st_size > 0 for name in ('n3.test', 'cicada'))
    contract_matches = all(before.get('files', {}).get(path) == digest for path, digest in CONTRACT['files'].items())
    passed = (set(codes) == lanes and not any(codes.values()) and before == after and not owned_present and binaries
              and contract_matches and not missing and set(got) == expected
              and all(action == 'pass' for action in got.values()))
    # A reviewed schema does not establish production N3 behavior. Remain
    # closed until the actual Hub/App/Node cases are integrated and run.
    code = (0 if mode == 'runtime' else (3 if required else 0)) if passed else 1
    result = {
        'schema': 'cicada.native-app.n3.acceptance.v1',
        'scope': {'discovery': 'actual-app-core-old-hub-discovery-no-secret-posts',
                  'seed': 'SETUP_ONLY-real-n2-private-stopped-expiry-fixture'}.get(mode,
                  'real-hub-cli-app-core-pq-tcp-process-harness-on-frozen-n2-only'),
        'harness': ('SETUP_READY' if mode == 'seed' else 'SCOPED_PASS') if passed else 'FAIL', 'n3_acceptance': 'NOT_RUN',
        'reason': 'Preparation selector only; full production N3 runtime cases are not executed by this run.',
        'reviewed_contract': CONTRACT, 'contract_pin_matches': contract_matches,
        'exit_code': code, 'exit_codes': codes,
        'source_head': before['head'], 'source_dirty': before['dirty'], 'source_manifest_sha256': before['manifest_sha256'],
        'source_stable': before == after, 'builder_image': image,
        'test_events': {a: list(got.values()).count(a) for a in ('pass', 'fail', 'skip')},
        'expected_tests': sorted(expected),
        'missing_or_unpassed_tests': missing, 'owned_container_absent': not owned_present,
        'test_binary_sha256': sha(artifacts / 'n3.test') if (artifacts / 'n3.test').is_file() else None,
        'cicada_binary_sha256': sha(artifacts / 'cicada') if (artifacts / 'cicada').is_file() else None,
        'actors': {'hub': 'ACTUAL_CLI_PROCESS' if any(name in expected and action == 'pass' for name, action in got.items()) else 'NOT_RUN',
                   'packet_client': 'OPAQUE_HARNESS_NOT_APP' if got.get('TestN3HarnessRealHubReplyRecovery') == 'pass' else 'NOT_ACCEPTED',
                   'production_app_core_n2': 'ACTUAL_PROCESS' if got.get('TestN3HarnessActualAppBootstrapAndResume') == 'pass' else 'NOT_ACCEPTED',
                   'production_app_n3': 'ACTUAL_DISCOVERY_GUARD_ONLY' if mode == 'discovery' and passed else 'NOT_RUN',
                   'production_node_n3': 'NOT_RUN'},
        'target_node': {'os': 'Ubuntu 24.04.3', 'arch': 'amd64', 'user': 'zyf', 'uid': 1000,
                        'codex_version': '0.163.0', 'evidence': 'USER_REPORTED_ENVIRONMENT'},
        'windows_native': 'NOT_RUN_IN_THIS_GATE', 'public_https': 'NOT_RUN_IN_THIS_GATE',
        'real_native_runtime': 'NOT_RUN',
        'matrix': {f'N3-{i:02}': 'NOT_RUN' for i in range(1, 28)},
    }
    if mode == 'discovery':
        result['discovery_guard'] = 'SCOPED_PASS' if passed else 'FAIL'
        result['matrix']['N3-01'] = 'PARTIAL_DISCOVERY_GUARD' if passed else 'NOT_ACCEPTED'
    if mode == 'seed':
        seed_path = artifacts / 'aged-n2-seed.json'
        result['n2_expiry_seed'] = json.loads(seed_path.read_text()) if seed_path.is_file() else None
        result['retained_fixture'] = str(run.parents[2] / 'state' / 'n3-acceptance' / run.name / 'retained-aged-n2')
        if result['n2_expiry_seed'] is None:
            passed, code = False, 1
            result['harness'], result['exit_code'] = 'FAIL', code
    if mode == 'runtime':
        result['scope'] = 'actual-linux-App-core-Hub-Node-crypto-TCP-persistent-fault-gate'
        result['n3_acceptance'] = ('SCOPED_PASS' if required else 'CORE_SCOPED_PASS_N2_WALL_EXPIRY_PENDING') if passed else 'FAIL'
        result['reason'] = 'Declared Linux actual-process scope only; physical/native/public scopes remain separate.'
        result['actors'].update({'production_app_n3': 'ACTUAL_CORE_PROCESS' if passed else 'NOT_ACCEPTED',
                                 'production_node_n3': 'ACTUAL_CLI_PROCESS' if passed else 'NOT_ACCEPTED',
                                 'wire_adversary': 'REAL_CRYPTO_INDEPENDENT_OF_APP_PREFLIGHT'})
        result['matrix'] = {f'N3-{i:02}': ('SCOPED_PASS' if passed else 'NOT_ACCEPTED') for i in range(1, 27)}
        result['matrix']['N3-27'] = 'NOT_RUN_AUTO_CORE_ENTRY'
        for row in ('N3-22', 'N3-24'): result['matrix'][row] = 'NOT_RUN_PHYSICAL_NATIVE_PUBLIC'
        result['clock_evidence'] = {
            'short_intent_expiry': 'REAL_WALL_CLOCK_TCP' if got.get('TestN3ServerRejectsIndependentProofScopeAttacks/expired-intent') == 'pass' else 'NOT_ACCEPTED',
            'heartbeat_decay_120_seconds': 'REAL_WALL_CLOCK_ACTUAL_NODE_CLI' if got.get('TestN3ActualAppConsentBindingRelayAndWallClockDecay') == 'pass' else 'NOT_ACCEPTED',
            'original_N2_15_minute_expiry': 'REAL_WALL_CLOCK_STOPPED_TEMPLATE' if got.get(AGED_TEST) == 'pass' else 'NOT_RUN',
            'App_clock_offsets': 'APP_LOGICAL_CLOCK_ONLY_NO_SERVER_EXPIRY_CLAIM',
            'outer_reconcile_cache_age': 'CONTROLLED_PERSISTED_FIXTURE_NOT_ELAPSED_WAIT',
            'N3_full_lease_wall_clock_expiry': 'NOT_RUN',
        }
        result['unaccepted_scopes'] = ['native Windows DPAPI/ACL/GUI', 'physical Ubuntu 24.04.3',
                                       'public HTTPS and strict PQTLS', 'App SSE and live canvas',
                                       'real native Runtime/Codex execution', 'Node key rotation/upgrade',
                                       'N3 full-lease natural expiry']
        if passed:
            result['matrix']['N3-09'] = 'SCOPED_SHORT_INTENT_WALL_EXPIRY_ONLY'
            result['matrix']['N3-20'] = 'SCOPED_RESTART_AND_REVOCATION_NO_KEY_ROTATION'
            result['matrix']['N3-21'] = 'SCOPED_NODE_ONLY_RUNTIME_SSE_NOT_RUN'
        if not required: result['matrix']['N3-02'] = 'PARTIAL_N2_WALL_EXPIRY_PENDING'
    if mode == 'case':
        result['scope'] = 'actual-linux-runtime-case:' + case
        result['n3_acceptance'] = 'PARTIAL_CASE' if passed else 'FAIL'
        result['reason'] = 'One explicitly selected integration case; no aggregate runtime acceptance.'
        result['case'] = case
    if mode == 'auto':
        result['scope'] = 'actual-App-core-auto-entry-selected-status-and-durable-uncertainty-only'
        result['auto_status_acceptance'] = 'SCOPED_PASS' if passed else 'FAIL'
        result['reason'] = 'Two explicit test-triggered production automatic entry cases; prior 84-case inventory and Windows timer not run by this selector.'
        result['actors'].update({'production_app_n3': 'ACTUAL_CORE_PROCESS' if passed else 'NOT_ACCEPTED',
                                 'production_node_n3': 'ACTUAL_CLI_PROCESS' if passed else 'NOT_ACCEPTED'})
        result['matrix']['N3-27'] = 'SCOPED_AUTO_CORE_ENTRY_ONLY' if passed else 'NOT_ACCEPTED'
        result['matrix']['N3-20'] = 'SCOPED_SELF_CANCEL_NODE_CLI_CONTINUITY_ONLY' if passed else 'NOT_ACCEPTED'
        result['Windows_30_second_scheduler'] = 'NOT_RUN'
        result['full_N3_lease_natural_expiry_and_Node_continuity'] = 'NOT_RUN'
    save(run / 'result.json', result)
    save(run / 'artifacts.sha256.json', {p.name: sha(p) for p in sorted(run.iterdir()) if p.is_file() and p.name != 'artifacts.sha256.json'})
    print(f'N3 harness evidence: {run}')
    print(f"harness={result['harness']} n3={result['n3_acceptance']} exit={code}")
    if mode == 'seed':
        print('Retained private synthetic fixture: ' + result['retained_fixture'])
    return code


def ubuntu_prepare(source_run, artifacts, output):
    source = json.loads((source_run / 'result.json').read_text())
    if (source.get('n3_acceptance') != 'SCOPED_PASS' or source.get('exit_code') != 0
            or not source.get('source_stable') or not source.get('expected_tests')
            or source.get('test_events', {}).get('skip') or source.get('test_events', {}).get('fail')):
        raise ValueError('Ubuntu actor lane requires the complete accepted Linux source receipt.')
    for name, key in (('n3.test', 'test_binary_sha256'), ('cicada', 'cicada_binary_sha256')):
        if not (artifacts / name).is_file() or sha(artifacts / name) != source[key]:
            raise ValueError('Ubuntu actors must reuse the exact accepted test/CLI binaries.')
    expected = source['expected_tests']
    if set(expected) != RUNTIME_EXPECTED | {AGED_TEST} or len(expected) != len(set(expected)):
        raise ValueError('Ubuntu actor source inventory is incomplete.')
    tops = {name.split('/')[0] for name in expected}
    if tops != RUNTIME_TOP | {AGED_TEST}:
        raise ValueError('Ubuntu lane cannot substitute a different runtime inventory.')
    save(output, {'linux_result_sha256': sha(source_run / 'result.json'), 'source_head': source['source_head'],
                  'source_dirty': source['source_dirty'], 'source_manifest_sha256': source['source_manifest_sha256'],
                  'expected_tests': expected, 'test_binary_sha256': source['test_binary_sha256'],
                  'cicada_binary_sha256': source['cicada_binary_sha256']})
    return '^(' + '|'.join(sorted(tops)) + ')$'


def ubuntu_finish(run, artifacts, image, owned):
    source = json.loads((run / 'input.json').read_text())
    got = events(run / 'harness.log')
    codes = {p.stem: int(p.read_text()) for p in run.glob('*.exit')}
    os_text = (run / 'container-os-release').read_text() if (run / 'container-os-release').exists() else ''
    arch = (run / 'container-machine').read_text().strip() if (run / 'container-machine').exists() else ''
    same_binaries = all((artifacts / name).is_file() and sha(artifacts / name) == source[key] for name, key in
                        (('n3.test', 'test_binary_sha256'), ('cicada', 'cicada_binary_sha256')))
    passed = (set(codes) == {'runtime', 'parse'} and not any(codes.values()) and not owned and same_binaries
              and set(got) == set(source['expected_tests']) and all(action == 'pass' for action in got.values())
              and 'VERSION_ID="24.04"' in os_text and '24.04.4' in os_text and arch == 'x86_64')
    result = {'schema': 'cicada.native-app.n3.ubuntu-actors.v1', 'scope': 'Ubuntu24.04.4-amd64-container-actual-actors-only',
              'result': 'SCOPED_PASS' if passed else 'FAIL', 'exit_code': 0 if passed else 1, 'exit_codes': codes,
              'source': source, 'execution_image': image, 'source_binaries_unchanged': same_binaries,
              'owned_container_absent': not owned, 'test_events': {a: list(got.values()).count(a) for a in ('pass', 'fail', 'skip')},
              'physical_Ubuntu_24_04_3': 'NOT_RUN', 'Windows_native': 'NOT_RUN',
              'public_HTTPS': 'NOT_RUN', 'native_Runtime': 'NOT_RUN', 'App_SSE': 'NOT_IMPLEMENTED_IN_THIS_SLICE'}
    save(run / 'result.json', result)
    save(run / 'artifacts.sha256.json', {p.name: sha(p) for p in sorted(run.iterdir()) if p.is_file() and p.name != 'artifacts.sha256.json'})
    print('Ubuntu actual actor evidence: ' + str(run))
    print(result['result'])
    return result['exit_code']


if __name__ == '__main__':
    if sys.argv[1] == 'snapshot':
        snapshot(Path(sys.argv[2]), Path(sys.argv[3]))
    elif sys.argv[1] == 'finish':
        sys.exit(finish(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5] == 'true', sys.argv[6] == 'true',
                        sys.argv[7] if len(sys.argv) > 7 else 'preparation', sys.argv[8] if len(sys.argv) > 8 else None))
    elif sys.argv[1] == 'copy-aged':
        try: copy_aged_seed(*(Path(arg) for arg in sys.argv[2:6]))
        except (ValueError, KeyError, OSError):
            print('Expired stopped task-owned synthetic seed prerequisite unavailable', file=sys.stderr)
            raise SystemExit(2)
    elif sys.argv[1] == 'runtime-selector':
        names = RUNTIME_TOP | ({AGED_TEST} if sys.argv[2] == 'true' else set())
        print('^(' + '|'.join(sorted(names)) + ')$')
    elif sys.argv[1] == 'case-selector':
        if sys.argv[2] not in RUNTIME_TOP: raise SystemExit('Unknown runtime case')
        print('^' + sys.argv[2] + '$')
    elif sys.argv[1] == 'auto-selector':
        print('^(' + '|'.join(sorted(AUTO_EXPECTED)) + ')$')
    elif sys.argv[1] == 'ubuntu-prepare':
        print(ubuntu_prepare(*(Path(arg) for arg in sys.argv[2:5])))
    elif sys.argv[1] == 'ubuntu-finish':
        sys.exit(ubuntu_finish(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5] == 'true'))
    else:
        raise SystemExit('Unknown evidence operation')
