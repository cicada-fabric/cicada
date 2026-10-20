import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : '';
}

async function moduleFromFile(file) {
  const source = await readFile(file, 'utf8');
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}

async function loadOwnerBootstrapValidator(uiDir) {
  const source = (await readFile(path.join(uiDir, 'panel-bootstrap.js'), 'utf8'))
    .replace(/^import .*;\s*$/gm, '')
    .replace(/export\s+(?=(?:async\s+)?function)/g, '');
  const context = { URL, TextEncoder };
  vm.runInNewContext(`${source}\nglobalThis.panelValidators = { validateOwnerBootstrapPublicFiles, validateOwnerDeviceGrantSummary, readOwnerPublicSPKIPem };`, context);
  return context.panelValidators;
}

async function webCryptoManifestChecks(uiDir) {
  const source = (await readFile(path.join(uiDir, 'panel-bootstrap.js'), 'utf8'))
    .replace(/^import .*;\s*$/gm, '').replace(/export\s+(?=(?:async\s+)?function)/g, '');
  for (const toolchain of ['go1.27.1', 'go1.27.2', 'go1.27.3']) {
    const context = {
      fetch: async () => ({ ok: true, json: async () => ({ toolchain,
        wasm_file: 'cicada-webcrypto.wasm.gz', wasm_sha256: 'synthetic-digest' }) }),
      document: { createElement() { throw new Error('accepted-current-manifest'); } },
    };
    vm.runInNewContext(`${source}\nglobalThis.load = loadCryptoWasm;`, context);
    await assert.rejects(context.load(), toolchain === 'go1.27.3'
      ? /accepted-current-manifest/ : /unsupported Go toolchain/);
  }
}

async function accountVaultChecks(uiDir) {
  const source = (await readFile(path.join(uiDir, 'panel-client.js'), 'utf8'))
    .replace(/^import \{[\s\S]*?\} from '\.\/panel-model\.js';\s*/m, '')
    .replace(/export\s+(?=(?:async\s+)?function)/g, '');
  const context = { URL, TextEncoder, TextDecoder, Uint8Array, crypto: webcrypto, btoa, atob };
  vm.runInNewContext(`${source}\nglobalThis.accountVault = { encryptAccountDeviceIdentity, decryptAccountDeviceIdentity,
    saveOwnerAccountFlow, compareAndSaveOwnerAccountFlow, acquireOwnerAccountLock };`, context);
  const api = context.accountVault;
  const origin = 'https://hub.synthetic.invalid';
  const hubId = 'hub_synthetic_account_vault';
  const accountId = 'account_synthetic_vault';
  const deviceId = 'accountdev_synthetic_vault';
  const identity = { id: 'pq1-synthetic-device', kem_public: 'synthetic-kem-public', signing_public: 'synthetic-sign-public' };
  const blob = 'synthetic-private-identity-blob-not-a-real-key';
  const vault = await api.encryptAccountDeviceIdentity(blob, origin, hubId, accountId, deviceId, identity);
  assert.equal(vault.format, 'cicada.owner-account-device-vault.v1');
  assert.equal(vault.wrappingKey.extractable, false, 'random device wrapping key is non-extractable');
  assert.equal(vault.wrappingKey.algorithm.name, 'AES-GCM');
  assert.deepEqual([...vault.wrappingKey.usages].sort(), ['decrypt', 'encrypt']);
  assert.equal(Object.hasOwn(vault, 'identity_blob'), false, 'the returned persisted object contains only encrypted identity bytes');
  const cloned = structuredClone(vault);
  assert.equal(await api.decryptAccountDeviceIdentity(cloned, origin, hubId, accountId, deviceId,
    { signing_public: identity.signing_public, id: identity.id, kem_public: identity.kem_public }), blob,
  'a structured-cloned IndexedDB CryptoKey can restore the exact device identity');
  await assert.rejects(api.decryptAccountDeviceIdentity(cloned, 'https://other.synthetic.invalid', hubId, accountId, deviceId, identity), /does not match/);
  await assert.rejects(api.decryptAccountDeviceIdentity(cloned, origin, 'hub_other', accountId, deviceId, identity), /does not match/);
  await assert.rejects(api.decryptAccountDeviceIdentity(cloned, origin, hubId, 'account_other', deviceId, identity), /does not match/);
  await assert.rejects(api.decryptAccountDeviceIdentity(cloned, origin, hubId, accountId, 'device_other', identity), /does not match/);
  await assert.rejects(api.decryptAccountDeviceIdentity(cloned, origin, hubId, accountId, deviceId,
    { ...identity, signing_public: 'other-signing-key' }), /does not match/);
  await assert.rejects(api.encryptAccountDeviceIdentity(blob, 'http://public.synthetic.invalid', hubId, accountId, deviceId, identity), /secure Hub origin/);
  await assert.rejects(api.decryptAccountDeviceIdentity({ ...cloned, owner_private_identity: 'forbidden' }, origin, hubId, accountId, deviceId, identity), /does not match/);
  const tampered = { ...cloned, ciphertext: `${cloned.ciphertext.slice(0, -4)}AAAA` };
  await assert.rejects(api.decryptAccountDeviceIdentity(tampered, origin, hubId, accountId, deviceId, identity), /could not be authenticated/);
  await assert.rejects(api.encryptAccountDeviceIdentity(blob, 'http://127.0.0.1:8787', hubId, accountId, deviceId, identity), /secure Hub origin/);
  const loopback = await api.encryptAccountDeviceIdentity(blob, 'http://127.0.0.1:8787', hubId, accountId, deviceId, identity, true);
  assert.equal(await api.decryptAccountDeviceIdentity(loopback, 'http://127.0.0.1:8787', hubId, accountId, deviceId, identity, true), blob,
    'plain HTTP requires explicit literal-loopback policy');
  let stored = { pin: { origin, hubId }, device: { active: true, deviceId: 'legacy-browser-device' }, legacyDraft: { retained: true } };
  const db = { transaction() {
    const tx = { objectStore() { return {
      get() { const request = {}; queueMicrotask(() => { request.result = structuredClone(stored); request.onsuccess(); }); return request; },
      put(next) { stored = structuredClone(next); queueMicrotask(() => tx.oncomplete?.()); }
    }; }, abort() { queueMicrotask(() => tx.onabort?.()); } };
    return tx;
  } };
  const profile = { origin, hubId, accountId, ownerId: 'human_synthetic_owner', deviceId,
    username: '', publicIdentity: identity, allowLoopbackHTTP: false,
    ownerPublicIdentity: null, ownerFingerprint: '' };
  const pending = { phase: 'CLAIM_PREPARE_PENDING', packet: btoa('synthetic encrypted request bytes') };
  await api.saveOwnerAccountFlow(db, profile, pending, cloned);
  assert.deepEqual(stored.ownerAccount, { profile, pending }, 'only public profile fields and exact encrypted request bytes persist');
  assert.equal(stored.accountLoginVault.format, 'cicada.owner-account-device-vault.v1');
  assert.deepEqual(stored.device, { active: true, deviceId: 'legacy-browser-device' },
    'new account flow persistence preserves the older enrolled-device state');
  assert.deepEqual(stored.legacyDraft, { retained: true });
  assert.equal(stored.accountLoginVault.ciphertext, cloned.ciphertext, 'account device remains protected by its independent encrypted vault');
  await assert.rejects(api.saveOwnerAccountFlow(db, profile, pending, { ...cloned, ciphertext: 'different' }), /already has a different/);
  assert.doesNotMatch(JSON.stringify(stored.ownerAccount), /claim.?code|password|plaintext.?nonce/i);
  await assert.rejects(api.saveOwnerAccountFlow(db, { ...profile, claimCode: 'SYNTHETIC_SECRET' }, pending), /state is invalid/,
    'claim code and unrecognized secret fields cannot be persisted');
  await assert.rejects(api.saveOwnerAccountFlow(db, { ...profile, accountId: 'account_other' }, pending), /different Owner account profile/,
    'a later claim cannot replace the exact account binding');
  await assert.rejects(api.saveOwnerAccountFlow(db, { ...profile, allowLoopbackHTTP: true }, pending), /different Owner account profile/,
    'the immutable origin transport policy cannot be changed after first request');
  await assert.rejects(api.saveOwnerAccountFlow(db, profile, { phase: 'CLAIM_CHALLENGE_SAVED', packet: pending.packet }), /state is invalid/,
    'a saved challenge must include the exact encrypted Hub response');
  await assert.rejects(api.saveOwnerAccountFlow(db, profile, { phase: 'CLAIM_COMPLETE_PENDING', packet: btoa('synthetic completion') }), /state is invalid/,
    'a completion retry must retain its exact prepare and challenge packets');
  const savedChallenge = { phase: 'CLAIM_CHALLENGE_SAVED', packet: pending.packet,
    responsePacket: btoa('synthetic encrypted response bytes') };
  await api.saveOwnerAccountFlow(db, profile, savedChallenge);
  assert.equal(stored.ownerAccount.pending.responsePacket, savedChallenge.responsePacket,
    'the exact encrypted challenge response is retained for reload recovery');
  const ownerPublicIdentity = { id: 'pq1-synthetic-owner', kem_public: 'synthetic-owner-kem', signing_public: 'synthetic-owner-sign' };
  const completion = { phase: 'CLAIM_COMPLETE_PENDING', packet: btoa('synthetic encrypted completion bytes'),
    preparePacket: savedChallenge.packet, challengePacket: savedChallenge.responsePacket,
    ownerPublicIdentity, ownerFingerprint: 'a'.repeat(64) };
  await assert.rejects(api.saveOwnerAccountFlow(db, profile, { ...completion, ownerPublicIdentity: undefined }), /state is invalid/,
    'a claim completion cannot lose the public candidate identity before receipt verification');
  await assert.rejects(api.saveOwnerAccountFlow(db, profile, { ...completion, ownerFingerprint: undefined }), /state is invalid/,
    'a claim completion cannot lose the full candidate fingerprint before receipt verification');
  await assert.rejects(api.saveOwnerAccountFlow(db, profile, { ...completion, ownerFingerprint: 'invalid' }), /state is invalid/,
    'a claim completion fingerprint must remain canonical while pending');
  await api.saveOwnerAccountFlow(db, profile, completion);
  assert.deepEqual(stored.ownerAccount.pending, completion,
    'the exact completion and authenticated challenge survive reload before send or after response loss');
  assert.equal(stored.ownerAccount.profile.ownerPublicIdentity, null,
    'a candidate is not treated as an accepted Owner association while completion is pending');
  const completedResponse = { ...completion, responsePacket: btoa('synthetic sealed receipt bytes') };
  await api.saveOwnerAccountFlow(db, profile, completedResponse);
  assert.deepEqual(stored.ownerAccount.pending, completedResponse,
    'the exact sealed receipt is durable before the WASM adapter opens it');
  await api.saveOwnerAccountFlow(db, profile, savedChallenge);
  assert.deepEqual(stored.ownerAccount.pending, savedChallenge,
    'after a definite rejection, the exact claim challenge remains reusable with corrected inputs');
  await api.saveOwnerAccountFlow(db, profile, { phase: 'CLAIM_CARD_REQUIRED' });
  assert.deepEqual(stored.ownerAccount.pending, { phase: 'CLAIM_CARD_REQUIRED' },
    'a definite claim-prepare rejection requires a new card without discarding the bound browser key');

  // Model two restored tabs racing from the same challenge snapshot. A's
  // transaction wins; B cannot replace it with a separately sealed packet,
  // and B's later 403 rollback cannot erase A's accepted or pending bytes.
  stored = { pin: { origin, hubId }, accountLoginVault: cloned };
  await api.saveOwnerAccountFlow(db, profile, savedChallenge, cloned);
  const completionA = { ...completion, packet: btoa('synthetic completion packet A') };
  const completionB = { ...completion, packet: btoa('synthetic completion packet B') };
  await api.compareAndSaveOwnerAccountFlow(db, profile, savedChallenge, completionA);
  await assert.rejects(api.compareAndSaveOwnerAccountFlow(db, profile, savedChallenge, completionB), /OWNER_ACCOUNT_STALE_PENDING/,
    'a stale restored tab cannot replace the exact completion packet already persisted by the winning tab');
  const newLogin = { phase: 'LOGIN_PREPARE_PENDING', packet: btoa('synthetic new login request') };
  await assert.rejects(api.compareAndSaveOwnerAccountFlow(db, profile, null, newLogin), /OWNER_ACCOUNT_STALE_PENDING/,
    'a new request cannot replace an UNKNOWN saved completion');
  const rollback = { phase: 'CLAIM_CHALLENGE_SAVED', packet: savedChallenge.packet,
    responsePacket: savedChallenge.responsePacket };
  await assert.rejects(api.compareAndSaveOwnerAccountFlow(db, profile, savedChallenge, rollback), /OWNER_ACCOUNT_STALE_PENDING/,
    'a late 403 from the stale tab cannot roll back the winner packet');
  assert.deepEqual(stored.ownerAccount.pending, completionA, 'the winner exact packet remains available after stale writes fail');
  const responseA = { ...completionA, responsePacket: btoa('synthetic accepted receipt packet A') };
  await api.compareAndSaveOwnerAccountFlow(db, profile, completionA, responseA);
  const acceptedProfile = { ...profile, username: 'synthetic-owner', ownerPublicIdentity,
    ownerFingerprint: 'a'.repeat(64) };
  await api.compareAndSaveOwnerAccountFlow(db, acceptedProfile, responseA, null);
  await assert.rejects(api.compareAndSaveOwnerAccountFlow(db, profile, responseA, rollback), /OWNER_ACCOUNT_STALE_PENDING/,
    'a late stale completion cannot erase a newer accepted account profile');
  assert.deepEqual(stored.ownerAccount, { profile: acceptedProfile, pending: null },
    'authenticated acceptance and its exact public key binding survive stale callbacks');

  // A fake Web Locks manager exercises the same ifAvailable lease protocol
  // used by restored tabs in the browser driver.
  let lockHeld = false;
  const fakeLocks = { request(name, options, callback) {
    assert.equal(name, `cicada-owner-account:${origin}`);
    assert.equal(options.mode, 'exclusive');
    assert.equal(options.ifAvailable, true);
    if (lockHeld) return Promise.resolve(callback(null));
    lockHeld = true;
    return Promise.resolve(callback({ name })).finally(() => { lockHeld = false; });
  } };
  const leaseA = await api.acquireOwnerAccountLock(fakeLocks, origin);
  assert.ok(leaseA, 'the first restored tab acquires the account UI lease');
  assert.equal(await api.acquireOwnerAccountLock(fakeLocks, origin), null,
    'a second tab fails closed instead of waiting or entering account mutations');
  leaseA.release();
  await new Promise(resolve => setTimeout(resolve, 0));
  const leaseB = await api.acquireOwnerAccountLock(fakeLocks, origin);
  assert.ok(leaseB, 'the second tab can acquire after the first tab releases or closes');
  leaseB.release();
  assert.doesNotMatch(JSON.stringify(stored), /session.?token|claim.?code|password|plaintext.?nonce/i,
    'persistent account state contains no session token, claim code, password or plaintext nonce');
}

async function ownerBootstrapChecks(uiDir) {
  const { validateOwnerBootstrapPublicFiles: validate, validateOwnerDeviceGrantSummary: validateGrantSummary,
    readOwnerPublicSPKIPem } =
    await loadOwnerBootstrapValidator(uiDir);
  const publicPem = '-----BEGIN PUBLIC KEY-----\nSYNTHETIC PUBLIC BYTES ONLY\n-----END PUBLIC KEY-----\n';
  const pemFile = content => {
    const calls = { prefix: 0, full: 0 };
    return { size: Buffer.byteLength(content), calls,
      slice(start, end) { calls.prefix++; return { text: async () => content.slice(start, end) }; },
      async text() { calls.full++; return content; } };
  };
  const selectedPublic = pemFile(publicPem);
  assert.equal(await readOwnerPublicSPKIPem(selectedPublic), publicPem);
  assert.deepEqual(selectedPublic.calls, { prefix: 1, full: 1 }, 'only a bounded PEM header is sniffed before reading a public file');
  const selectedPrivate = pemFile('-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC PRIVATE BYTES NEVER USED\n');
  await assert.rejects(readOwnerPublicSPKIPem(selectedPrivate), /Private key files are not accepted/);
  assert.deepEqual(selectedPrivate.calls, { prefix: 1, full: 0 }, 'private PEM contents are rejected from the bounded header alone');
  const selectedTraditionalPrivate = pemFile('-----BEGIN PRIVATE KEY-----\nSYNTHETIC PRIVATE BYTES NEVER USED\n');
  await assert.rejects(readOwnerPublicSPKIPem(selectedTraditionalPrivate), /Private key files are not accepted/);
  assert.deepEqual(selectedTraditionalPrivate.calls, { prefix: 1, full: 0 });
  const oversizedPublic = pemFile(publicPem);
  oversizedPublic.size = 16 * 1024 + 1;
  await assert.rejects(readOwnerPublicSPKIPem(oversizedPublic), /no larger than 16 KiB/);
  assert.deepEqual(oversizedPublic.calls, { prefix: 0, full: 0 });
  // Deliberately non-cryptographic test identities. The full Go WASM check
  // below repeats the acceptance case with real synthetic PQ identities.
  const hubPublic = { id: 'pq1-synthetic-hub-public', kem_public: 'synthetic-hub-kem', signing_public: 'synthetic-hub-sign' };
  const otherHubPublic = { id: 'pq1-synthetic-other-hub', kem_public: 'synthetic-other-hub-kem', signing_public: 'synthetic-other-hub-sign' };
  const ownerPublic = { id: 'pq1-synthetic-owner-public', kem_public: 'synthetic-owner-kem', signing_public: 'synthetic-owner-sign' };
  const hub = { contract: 'android-hub-v1', hub_id: 'hub_synthetic_owner_guide',
    control_public_identity: hubPublic, control_key_version: 1, suite: 'ML-KEM-768+ML-DSA-65+AES-256-GCM' };
  const connection = { format: 'cicada.hub-owner-connection.v1', version: 1,
    purpose: 'ROOT_SIGNER_BOOTSTRAP', account_id: 'account_synthetic_owner_guide',
    owner_id: 'human_synthetic_owner_guide', origin: 'https://synthetic.invalid',
    allow_loopback_http: false, hub };
  const fingerprint = 'a'.repeat(64);
  const candidate = { format: 'cicada.owner-signer-public.v1',
    account_id: connection.account_id, owner_id: connection.owner_id,
    owner_public_identity: ownerPublic, fingerprint, origin: connection.origin,
    allow_loopback_http: false, hub };
  const identities = new Set([JSON.stringify(hubPublic), JSON.stringify(otherHubPublic), JSON.stringify(ownerPublic)]);
  const cryptoApi = {
    validatePublicIdentity({ public_identity }) { return { ok: identities.has(JSON.stringify(public_identity)) }; },
    fingerprint({ public_identity }) { return { ok: JSON.stringify(public_identity) === JSON.stringify(ownerPublic), fingerprint }; }
  };
  const valid = validate(connection, candidate, connection.origin, hub, cryptoApi);
  assert.equal(valid.accountID, connection.account_id);
  assert.equal(valid.ownerID, connection.owner_id);
  assert.equal(valid.ownerKeyID, ownerPublic.id);
  assert.equal(valid.hubID, hub.hub_id);
  assert.equal(valid.fingerprint, fingerprint);
  const loopbackConnection = { ...connection, origin: 'http://127.0.0.1:8787', allow_loopback_http: true };
  const loopbackCandidate = { ...candidate, origin: loopbackConnection.origin, allow_loopback_http: true };
  assert.equal(validate(loopbackConnection, loopbackCandidate, loopbackConnection.origin, hub, cryptoApi).origin,
    loopbackConnection.origin, 'explicit literal-loopback HTTP is accepted');

  const rejected = (changedConnection, changedCandidate, pageOrigin = connection.origin, observedHub = hub) =>
    assert.throws(() => validate(changedConnection, changedCandidate, pageOrigin, observedHub, cryptoApi));
  rejected({ ...connection, purpose: 'CLIENT_CONTROL' }, candidate);
  rejected(connection, { ...candidate, account_id: 'account-other' });
  rejected(connection, { ...candidate, owner_id: 'human-other' });
  rejected(connection, { ...candidate, fingerprint: 'b'.repeat(64) });
  rejected(connection, { ...candidate, origin: 'https://other.invalid' });
  rejected(connection, candidate, 'https://other.invalid');
  rejected(connection, { ...candidate, owner_private_identity: 'PRIVATE_TEST_ONLY' });
  rejected({ ...connection, access_token: 'synthetic-token' }, candidate);
  rejected(connection, { ...candidate, owner_public_identity: { ...ownerPublic, signing_private: 'PRIVATE_TEST_ONLY' } });
  rejected(connection, { ...candidate, account_id: 'account-other' });
  rejected(connection, candidate, connection.origin, { ...hub, hub_id: 'hub-other' });
  rejected(connection, { ...candidate, hub: { ...hub, control_public_identity: otherHubPublic } });
  rejected(connection, candidate, connection.origin, { ...hub, control_public_identity: otherHubPublic });
  rejected({ ...loopbackConnection, origin: 'http://public.example:8787' },
    { ...loopbackCandidate, origin: 'http://public.example:8787' }, 'http://public.example:8787');
  rejected(loopbackConnection, { ...loopbackCandidate, allow_loopback_http: false });
  rejected(connection, { ...candidate, owner_id: 'bad owner id' });

  const grantManifest = { format: 'cicada.owner-device-enrollment.v1', hub_id: connection.hub.hub_id,
    owner_id: connection.owner_id, owner_key_id: ownerPublic.id, device_id: 'browser_synthetic',
    device_key_fingerprint: 'c'.repeat(64), purpose: 'CLIENT_CONTROL',
    device_public_identity: otherHubPublic };
  const sharedGrantSummary = { hub_id: grantManifest.hub_id, owner_id: grantManifest.owner_id,
    owner_key_id: ownerPublic.id, owner_public_identity: ownerPublic, device_id: grantManifest.device_id,
    device_key_id: otherHubPublic.id, device_key_fingerprint: grantManifest.device_key_fingerprint,
    purpose: 'CLIENT_CONTROL', issued_at: '2026-10-14T00:00:00Z',
    expires_at: '2026-10-14T01:00:00Z', grant_file: 'owner-device-grant.json' };
  const legacyGrantSummary = { ...sharedGrantSummary, format: grantManifest.format };
  const profileGrantSummary = { ...sharedGrantSummary, format: 'cicada.owner-device-grant-summary.v1', state: 'GRANT_WRITTEN' };
  assert.strictEqual(validateGrantSummary(legacyGrantSummary, grantManifest, cryptoApi), ownerPublic,
    'the established local signing summary remains importable');
  assert.strictEqual(validateGrantSummary(profileGrantSummary, grantManifest, cryptoApi), ownerPublic,
    'the authenticated local profile summary is public and importable');
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary, owner_private_identity: 'PRIVATE_TEST_ONLY' }, grantManifest, cryptoApi),
    /schema/);
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary, state: 'ACTIVE' }, grantManifest, cryptoApi),
    /schema/);
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary, device_id: 'other-device' }, grantManifest, cryptoApi),
    /manifest/);
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary, owner_key_id: 'other-owner-key' }, grantManifest, cryptoApi),
    /manifest/);
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary, issued_at: '2026-02-31T00:00:00Z' }, grantManifest, cryptoApi),
    /manifest/);
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary, issued_at: '2026-10-14T00:00:00.000Z' }, grantManifest, cryptoApi),
    /manifest/);
  assert.throws(() => validateGrantSummary({ ...profileGrantSummary,
    owner_public_identity: { ...ownerPublic, signing_private: 'PRIVATE_TEST_ONLY' } }, grantManifest, cryptoApi), /schema/);

  const panelSource = await readFile(path.join(uiDir, 'panel.js'), 'utf8');
  const entryStart = panelSource.indexOf('function renderOwnerAccountEntry(');
  const entryEnd = panelSource.indexOf('\nfunction renderOwnerBootstrapGuide(', entryStart);
  assert.ok(entryStart >= 0 && entryEnd > entryStart, 'normal Owner account page is separate from advanced setup');
  const entry = panelSource.slice(entryStart, entryEnd);
  assert.match(entry, /return renderOwnerAccount\(app, \{ db, hubIdentity, cryptoApi, onAdvanced \}\)/,
    'the normal route opens the two-page account flow and keeps advanced setup behind its explicit button');
  assert.match(entry, /pinAlreadySaved \? renderOwnerBootstrapGuide :\s*\(\) => renderPin\(hubIdentity, renderOwnerBootstrapGuide\)/,
    'first-visit advanced technical flow pins explicitly, while a previously pinned browser proceeds directly');

  const guideStart = panelSource.indexOf('function renderOwnerBootstrapGuide()');
  const guideEnd = panelSource.indexOf('\nfunction renderNewDevice(', guideStart);
  assert.ok(guideStart >= 0 && guideEnd > guideStart, 'advanced signer guide is a discrete pre-enrollment path');
  const guide = panelSource.slice(guideStart, guideEnd);
  assert.match(guide, /does not claim a Hub installation or set Owner login credentials/);
  assert.match(guide, /Open advanced browser Client device enrollment/);
  const bootStart = panelSource.indexOf('async function boot()');
  const bootEnd = panelSource.indexOf('\nboot();', bootStart);
  assert.match(panelSource.slice(bootStart, bootEnd), /await routeAfterPin\(state\)/,
    'fresh and pinned visits use the existing saved-state route decision');
  assert.doesNotMatch(panelSource.slice(bootStart, bootEnd), /renderOwnerBootstrapGuide\(\)/,
    'startup never opens the advanced flow directly');
  const routeStart = panelSource.indexOf('async function routeAfterPin(');
  const routeEnd = panelSource.indexOf('\nasync function readPublicJSONFile', routeStart);
  assert.match(panelSource.slice(routeStart, routeEnd), /switch \(savedPanelRoute\(state\)\)/,
    'account setup changes only the empty-state route, not saved enrollment handling');
  assert.match(panelSource.slice(routeStart, routeEnd), /case 'active-device':[\s\S]*renderUnlock\(state\)[\s\S]*enterWorkspace\(\)/,
    'an enrolled browser still unlocks or enters its existing Owner workspace');
  assert.match(panelSource.slice(routeStart, routeEnd), /case 'pending-enrollment':[\s\S]*renderEnrollmentRetry\(state\)/);
  assert.match(panelSource.slice(routeStart, routeEnd), /case 'device-draft':[\s\S]*renderUnlock\(state\)[\s\S]*renderGrantImport\(state\)/);
  for (const forbidden of ['fetch(', 'updateState(', 'enrollExactRequest(', 'callRPC(', 'openPanelDB(']) {
    assert.equal(guide.includes(forbidden), false, `public-file guide must not call ${forbidden}`);
  }
  assert.match(guide, /owner-connection-file/);
  assert.match(guide, /owner-public-manifest-file/);
  assert.match(guide, /does not contact an issuer/);
  assert.match(guide, /Node INITIAL enrollment is a separate later flow/);
  assert.doesNotMatch(guide, /Root is active|Root ACTIVE|signer ACTIVE/i);
  assert.doesNotMatch(guide, /field\([^\n]*['"]password['"]/i, 'guide has no passphrase field');
}

async function ownerAccountUIChecks(uiDir) {
  const account = await readFile(path.join(uiDir, 'panel-account.js'), 'utf8');
  const panel = await readFile(path.join(uiDir, 'panel.js'), 'utf8');
  const claimStart = account.slice(account.indexOf('function renderClaimStart'), account.indexOf('\nasync function beginClaim'));
  assert.ok(claimStart.includes("'validateOwnerClaimCard'"), 'claim-card verification runs in the Go adapter');
  assert.ok(claimStart.includes('fingerprint: verified.hubFingerprint'), 'the full Hub fingerprint is displayed before using the code');
  assert.ok(claimStart.includes('I independently checked this exact origin and complete fingerprint with the installer.'),
    'claim use requires an explicit independent origin and full-fingerprint review');
  assert.ok(claimStart.includes("type = 'password'"), 'installer claim JSON is hidden while entered');
  assert.ok(claimStart.includes('cardText.addEventListener(\'input\', clearVerification)'),
    'changing the claim after review invalidates the reviewed display');
  assert.ok(claimStart.includes('beginClaim(app, context, reviewedScope, selectedCard'),
    'the exact reviewed card bytes are bound to the next action');
  assert.equal(claimStart.includes('fetch('), false, 'page one does not send a request before explicit scope review');
  assert.ok(claimStart.indexOf('if (!confirmation.checked) return') < claimStart.indexOf('await savePinnedHub(context.db, context.hubIdentity)'),
    'the first local pin is not stored until the user checks the exact full-fingerprint review');
  const begin = account.slice(account.indexOf('async function beginClaim'), account.indexOf('\nasync function requestAndSaveResponse'));
  assert.ok(begin.indexOf('await persist(context, profile, { phase: \'CLAIM_PREPARE_PENDING\'') < begin.indexOf('await executeClaimPrepare'),
    'encrypted exact request and device vault are durable before first network submission');
  assert.ok(begin.includes('existing_device_id: profile.deviceId, expected_public_identity: profile.publicIdentity'),
    'a same-account claim reissue binds to the retained browser device ID and full public identity');
  const credentials = account.slice(account.indexOf('function renderClaimCredentials'), account.indexOf('\nasync function executeClaimComplete'));
  assert.ok(credentials.includes('readOwnerPublicSPKIPem'), 'credential page reads only bounded public PEMs');
  assert.ok(credentials.includes('parseOwnerPublicSPKI'), 'public keys go through the strict shared Go parser');
  assert.ok(credentials.includes('sealOwnerClaimComplete'), 'account password enters only the typed Go sealing API');
  assert.ok(credentials.includes("phase: 'CLAIM_COMPLETE_PENDING'"), 'sealed completion is saved before submission');
  assert.ok(account.includes("failure?.httpStatus === 403 && pending.preparePacket && pending.challengePacket"),
    'only a definite server rejection returns login to its saved challenge; transport loss keeps the exact completion');
  assert.ok(account.includes("if (failure?.httpStatus === 403 && pending.preparePacket && pending.challengePacket)"),
    'a definitely rejected claim completion returns to its authenticated challenge for corrected inputs');
  assert.ok(account.includes('ownerPublicIdentity: ownerKeys.owner_public_identity, ownerFingerprint: ownerKeys.owner_fingerprint'),
    'a pending candidate stays with the exact completion until the Hub receipt authenticates');
  assert.ok(account.includes("if (failure?.httpStatus === 403) {\n      const retry = { phase: 'CLAIM_CARD_REQUIRED' }"),
    'a definitely rejected claim prepare can accept a fresh card after checking the same scope');
  assert.ok(account.includes('failure?.httpStatus === 403 && createdPreparePending'),
    'a definitely rejected login prepare returns to the username form');
  assert.ok(account.includes("readOwnerPublicSPKIPem } from './panel-bootstrap.js'"),
    'the account form imports the bounded public-only PEM guard from its actual module');
  assert.equal(credentials.includes('private_key_pem'), false);
  assert.equal(credentials.includes('owner_private_identity'), false);
  assert.ok(account.includes("'/v2/owner/account/claim/prepare'"));
  assert.ok(account.includes("'/v2/owner/account/claim/complete'"));
  assert.ok(account.includes('submits only its exact saved encrypted bytes'));
  assert.ok(account.includes('acquireOwnerAccountLock(globalThis.navigator?.locks, location.origin)'),
    'the entire account UI requires a same-origin exclusive Web Lock');
  assert.ok(account.includes("section.id = 'owner-account-lock-blocked'"),
    'a busy or unsupported single-writer lease produces a stable fail-closed state');
  assert.ok(account.includes('button.disabled = true') && account.includes('await action?.(event)') &&
      account.includes('if (accountActionRunning || running || button.disabled) return'),
    'account action buttons synchronously disable and single-flight async work');
  assert.equal(account.includes('void beginClaim('), false, 'claim submission is awaited by its single-flight action');
  assert.ok(account.includes('compareAndSaveOwnerAccountFlow'), 'account transitions use IndexedDB compare-and-save');
  assert.ok(account.includes("'ACCOUNT_READY_OWNER_SIGNER_PENDING'"), 'claim receipt does not assert Root or Client manager authority');
  assert.ok(account.includes('forgetOwnerAccountSession'), 'logout clears the RAM-only opaque account session handle');
  const logoutStart = account.slice(account.indexOf("const pending = { phase: 'LOGOUT_PENDING'"), account.indexOf("section.append(actionButton(t('Advanced technical setup')", account.indexOf("const pending = { phase: 'LOGOUT_PENDING'")));
  assert.ok(logoutStart.indexOf('await persist(context, profile, pending, null, null)') < logoutStart.indexOf('await executeOwnerLogout'),
    'logout ciphertext and epochs are durable before submission');
  const logoutRecovery = account.slice(account.indexOf('async function executeOwnerLogout'), account.indexOf('\nfunction renderPendingRecovery'));
  assert.ok(logoutRecovery.includes('openOwnerLogoutReceipt'), 'logout clears local session only after authenticated receipt verification');
  assert.ok(logoutRecovery.indexOf('openOwnerLogoutReceipt') < logoutRecovery.indexOf('await persist(context, profile, null, null, answered)'),
    'the saved logout is retained until its exact receipt authenticates');
  assert.ok(account.includes("if (pending.phase === 'LOGOUT_PENDING') return await executeOwnerLogout"),
    'reload recovery reuses the exact logout packet');
  assert.ok(account.includes("latest.ownerAccount?.pending?.phase === 'LOGIN_PREPARE_PENDING'"),
    'a lost login-prepare response remains recoverable as the exact saved request');
  const boot = panel.slice(panel.indexOf('async function boot()'), panel.indexOf('\nconfigureLanguage();'));
  assert.ok(boot.includes('return renderOwnerAccountEntry(false)'), 'an empty first load goes directly to the claim-card page');
  assert.ok(boot.includes('if (state.device?.active || state.enrollment?.body || (state.deviceDraft && state.vault))'),
    'existing advanced browser state still requires its saved Hub pin before routing');
}

async function modelChecks(uiDir) {
  await accountVaultChecks(uiDir);
  const model = await moduleFromFile(path.join(uiDir, 'panel-model.js'));
  assert.equal(model.savedPanelRoute({}), 'owner-account',
    'an empty pinned profile opens the first Owner account setup page');
  assert.equal(model.savedPanelRoute({ vault: { ciphertext: 'synthetic' } }), 'owner-account',
    'a stray vault cannot be mistaken for a completed signup');
  assert.equal(model.savedPanelRoute({ device: { active: true } }), 'active-device',
    'an existing enrolled browser keeps its unlock/workspace route');
  assert.equal(model.savedPanelRoute({ enrollment: { body: 'synthetic-exact-request' } }), 'pending-enrollment',
    'an exact pending enrollment remains recoverable');
  assert.equal(model.savedPanelRoute({ deviceDraft: { device_id: 'synthetic' }, vault: { ciphertext: 'synthetic' } }), 'device-draft',
    'an existing device draft keeps its unlock/grant route');
  assert.equal(model.savedPanelRoute({ device: { active: true }, enrollment: { body: 'synthetic' } }), 'active-device',
    'a completed enrollment takes precedence over stale pending data');
  assert.equal(model.savedPanelRoute({ enrollment: { body: 'synthetic' }, deviceDraft: { device_id: 'synthetic' }, vault: {} }), 'pending-enrollment',
    'a saved exact enrollment request takes precedence over an older device draft');
  const identity = { contract: 'android-hub-v1', hub_id: 'hub-pin-test',
    control_public_identity: { id: 'pq-hub-test', kem_public: 'synthetic-kem', signing_public: 'synthetic-sign' },
    control_key_version: 1, suite: 'ML-KEM-768+ML-DSA-65+AES-256-GCM' };
  const savedPin = { origin: 'https://hub.example', hubId: identity.hub_id, keyId: 'pq-hub-test',
    keyVersion: 1, suite: identity.suite, contract: identity.contract, controlPublicIdentity: identity.control_public_identity };
  assert.equal(model.pinMatches(savedPin, identity, 'https://hub.example'), true);
  assert.equal(model.pinMatches({ ...savedPin, keyId: 'changed' }, identity, 'https://hub.example'), false);
  assert.equal(model.pinMatches({ ...savedPin, origin: 'https://other.example' }, identity, 'https://hub.example'), false);
  assert.equal(model.pinMatches(savedPin, { ...identity,
    control_public_identity: { ...identity.control_public_identity, signing_public: 'different-key' } }, 'https://hub.example'), false,
  'a matching short key ID cannot conceal a changed full Hub public identity');
  const view = { x: 19, y: -7, scale: .72 };
  const point = { x: 125, y: 87 };
  const roundTrip = model.worldPointToScreen(model.screenPointToWorld(point, view), view);
  assert.ok(Math.abs(roundTrip.x - point.x) < 1e-9 && Math.abs(roundTrip.y - point.y) < 1e-9);
  const canvasSource = (await readFile(path.join(uiDir, 'panel-canvas.js'), 'utf8'))
    .replace(/^import .*;$/gm, '').replace('export class CanvasPanel', 'class CanvasPanel');
  const canvasContext = { ...model, installCanvasControls() {}, globalThis: {},
    t: key => ({ key }), localizedIfKnown: value => value,
    setLocalizedText(element, value) { element.textContent = value?.key || value; } };
  vm.runInNewContext(`${canvasSource}\nglobalThis.CanvasPanel = CanvasPanel;`, canvasContext);
  const CanvasPanel = canvasContext.globalThis.CanvasPanel;
  const attrs = {};
  const panel = Object.create(CanvasPanel.prototype);
  panel.view = view;
  panel.selectionRect = { setAttribute(key, value) { attrs[key] = value; } };
  panel.updateSelectionRect({ x: 10, y: 20 }, { x: 40, y: 60 });
  assert.equal(attrs.x, view.x + 10 * view.scale, 'selection outline uses screen coordinates');
  assert.equal(attrs.y, view.y + 20 * view.scale);
  assert.equal(attrs.width, 30 * view.scale);
  assert.equal(attrs.height, 40 * view.scale);
  const listeners = {};
  panel.svgRoot = { addEventListener(name, callback) { listeners[name] = callback; },
    hasPointerCapture() { return false; } };
  panel.selection = new Set();
  const endpoint = { getAttribute(name) { return name === 'data-endpoint-id' ? 'keyboard-endpoint' : 'group-a'; }, focus() {} };
  panel.world = { querySelectorAll() { return [endpoint]; } };
  panel.render = panel.renderSide = panel.setMessage = () => {};
  panel.attachCanvasEvents();
  let prevented = false;
  const key = (value, shiftKey = false) => listeners.keydown({ key: value, shiftKey,
    target: { closest() { return endpoint; } }, preventDefault() { prevented = true; } });
  key('Enter');
  assert.equal(panel.selection.has('keyboard-endpoint'), true);
  assert.equal(prevented, true);
  key(' ', true);
  assert.equal(panel.selection.size, 0, 'modified Space toggles selection without a write');
  panel.drag = { pointerId: 1 };
  key('Escape');
  assert.equal(panel.drag, null, 'Escape cancels an in-flight gesture');
  const box = model.normalizeBox({ x: 50, y: 40 }, { x: 10, y: 5 });
  assert.deepEqual(box, { x: 10, y: 5, width: 40, height: 35 });
  assert.equal(model.boxContains(box, { x: 20, y: 12, width: 8, height: 8 }), true);
  assert.equal(model.boxContains(box, { x: 20, y: 12, width: 60, height: 8 }), false);

  const state = { active: true, sessionEpoch: 9, nextRequestSequence: 1, nextResponseSequence: 1, pending: null };
  const reserved = model.reserveClientRequest(state, (sequence, responseSequence) => ({
    packet: 'opaque-sealed-packet', operationId: 'op-synthetic', requestSequence: sequence, responseSequence
  }));
  assert.equal(reserved.nextRequestSequence, 2);
  assert.equal(reserved.pending.requestSequence, 1);
  assert.throws(() => model.reserveClientRequest(reserved, () => ({ packet: 'replacement', operationId: 'bad' })), /unresolved/);
  assert.throws(() => model.completeClientRequest(reserved, reserved.pending, 2), /sequence changed/);
  const completed = model.completeClientRequest(reserved, reserved.pending, 1);
  assert.equal(completed.pending, null);
  assert.equal(completed.nextResponseSequence, 2);
  assert.equal(completed.lastRequestSequence, 1);

  await ownerBootstrapChecks(uiDir);
  await ownerAccountUIChecks(uiDir);

  const writeDescriptor = model.makeSemanticWriteFence('topology.apply', 'op-uncertain-write', 'a'.repeat(64),
    { kind: 'endpoint.join_group', join_group: { endpoint_id: 'endpoint-a', group_id: 'group-a' } },
    '2026-09-30T00:00:00.000Z');
  assert.equal(writeDescriptor.operationID, 'op-uncertain-write');
  assert.deepEqual(writeDescriptor.scope, { groupIds: ['group-a'], endpointIds: ['endpoint-a'] });
  const admissionFence = model.makeSemanticWriteFence('topology.apply', 'op-uncertain-admission', 'c'.repeat(64),
    { kind: 'endpoint.admit_group', admit_endpoint: { admission: {
      network_id: 'network-a', group_id: 'group-a', endpoint_id: 'endpoint-c' } } }, '2026-09-30T00:00:00.000Z');
  assert.deepEqual(admissionFence.scope, { networkId: 'network-a', groupIds: ['group-a'], endpointIds: ['endpoint-c'] },
    'uncertain Endpoint admission keeps the exact Network/Group/Endpoint write scope fenced');
  const legacyFence = model.recoveredWriteFence({ operation: 'topology.apply', operationId: 'op-legacy-write', createdAt: 'old' }, 'b'.repeat(64));
  assert.equal(legacyFence.digestBasis, 'legacy-sealed-packet', 'pre-fence pending writes still recover into a conservative fence');
  assert.equal(legacyFence.packetSha256, 'b'.repeat(64));
  assert.equal(model.recoveredWriteFence({ operation: 'status.snapshot', operationId: 'read-op' }), null);
  const uncertainPending = { packet: 'opaque-uncertain-packet', operationId: writeDescriptor.operationID,
    operation: 'topology.apply', requestSequence: 1, writeFence: writeDescriptor };
  const uncertainDevice = model.completeClientRequest({ active: true, sessionEpoch: 9,
    nextRequestSequence: 2, nextResponseSequence: 1, pending: uncertainPending }, uncertainPending, 1,
  { errorCode: 'OUTCOME_UNCERTAIN', resolvedAt: '2026-09-30T00:01:00.000Z' });
  assert.equal(uncertainDevice.pending, null, 'authenticated uncertainty resolves the transport packet');
  assert.equal(uncertainDevice.nextResponseSequence, 2, 'authenticated uncertainty advances response sequence');
  assert.equal(uncertainDevice.writeFence.operationID, 'op-uncertain-write', 'uncertainty retains a separate semantic write fence');
  assert.throws(() => model.reserveClientRequest(uncertainDevice,
    () => ({ packet: 'replacement', operationId: 'new-write' }), 'topology.apply'), /uncertain outcome/);
  const allowedRead = model.reserveClientRequest(uncertainDevice,
    () => ({ packet: 'fresh-snapshot', operationId: 'snapshot-op' }), 'topology.snapshot');
  assert.equal(allowedRead.writeFence.operationID, 'op-uncertain-write', 'read snapshots cannot clear a write fence');
  assert.throws(() => model.authorizeWriteFenceState({ device: allowedRead }, 'op-uncertain-write', 'now'), /still unresolved/);
  const refreshed = model.completeClientRequest(allowedRead, allowedRead.pending, 2);
  const reviewed = model.authorizeWriteFenceState({ device: refreshed }, 'op-uncertain-write', '2026-09-30T00:02:00.000Z');
  assert.equal(reviewed.device.writeFence, null, 'only the explicit fence authorization clears the write guard');
  assert.equal(reviewed.device.writeFenceAcknowledgements.at(-1).bodySha256, 'a'.repeat(64));
  assert.throws(() => model.authorizeWriteFenceState({ device: refreshed }, 'different-operation', 'now'), /changed in another tab/);

  const emptyBrowser = { pin: { origin: 'https://hub.example', hubId: 'hub-pin-test' } };
  const manifest = { format: 'cicada.owner-device-enrollment.v1', hub_id: 'hub-pin-test', owner_id: 'owner-a',
    owner_key_id: 'owner-key-a', device_id: 'browser-a', device_public_identity: { id: 'device-key-a' } };
  const vault = { format: 'cicada.browser-device-vault.v1', ciphertext: 'synthetic-encrypted-data' };
  const draftState = model.createDeviceDraftState(emptyBrowser, 'https://hub.example', vault, manifest);
  assert.throws(() => model.createDeviceDraftState(draftState, 'https://hub.example', vault,
    { ...manifest, device_id: 'browser-b' }), /already created/,
  'a second tab cannot overwrite an already stored device draft');
  const enrollment = { hubId: 'hub-pin-test', ownerId: 'owner-a', ownerKeyId: 'owner-key-a',
    deviceId: 'browser-a', deviceKeyId: 'device-key-a', body: 'exact-public-request-bytes' };
  const pendingEnrollment = model.saveEnrollmentState(draftState, enrollment, 'https://hub.example');
  assert.equal(pendingEnrollment.enrollment.body, enrollment.body);
  assert.throws(() => model.saveEnrollmentState(pendingEnrollment,
    { ...enrollment, body: 'replacement-grant-or-device' }, 'https://hub.example'), /already pending/,
  'another tab cannot replace the exact enrollment request');

  const topology = { networks: [], groups: [
    { group_id: 'group-root', network_id: 'network-a', name: 'Root', state: 'active', version: 2 },
    { group_id: 'group-child', network_id: 'network-a', parent_group_id: 'group-root', name: 'Child', state: 'active', version: 1 }
  ], memberships: [{ group_id: 'group-root', principal_id: 'principal-a', status: 'active' }],
  endpoints: [{ endpoint_id: 'endpoint-a', principal_id: 'principal-a', owner_id: 'owner-a', name: 'Agent', group_ids: ['group-root', 'group-child'], network_ids: ['network-a'] }], links: [] };
  const nesting = { ...topology, networks: [{ network_id: 'network-a', state: 'active' }] };
  const rootIntent = model.groupParentGesture(nesting, 'group-child', '', 'network-a');
  assert.deepEqual(rootIntent.action, { kind: 'group.set_parent', set_parent: {
    group_id: 'group-child', parent_group_id: '', expected_group_version: 1 } });
  assert.match(rootIntent.review, /no Membership, role, permission, history/);
  assert.equal(model.groupParentGesture(nesting, 'group-child', 'group-root', 'network-a'), null);
  assert.throws(() => model.groupParentGesture(nesting, 'group-root', 'group-child', 'network-a'), /cycle/);
  assert.throws(() => model.groupParentGesture(nesting, 'group-child', 'group-child', 'network-a'), /cycle/);
  assert.throws(() => model.groupParentGesture(nesting, 'group-child', '', 'foreign'), /selected active Network/);
  assert.throws(() => model.groupParentGesture(nesting, 'missing', '', 'network-a'), /current visible/);
  for (const version of [0, -1, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => model.groupParentGesture({ ...nesting, groups: nesting.groups.map(group =>
      group.group_id === 'group-child' ? { ...group, version } : group) }, 'group-child', '', 'network-a'), /current visible/);
  }
  for (const changed of [{ network_id: 'foreign' }, { state: 'archived' }, { parent_group_id: 'missing' }]) {
    assert.throws(() => model.groupParentGesture({ ...nesting, groups: nesting.groups.map(group =>
      group.group_id === 'group-root' ? { ...group, ...changed } : group) }, 'group-child', 'group-root', 'network-a'));
  }
  const controlsSource = (await readFile(path.join(uiDir, 'panel-canvas-controls.js'), 'utf8'))
    .replace(/^import .*;$/gm, '').replace('export function', 'function');
  vm.runInNewContext(`${controlsSource}\ninstallCanvasControls(globalThis.CanvasPanel);`, canvasContext);
  const parentPanel = Object.create(CanvasPanel.prototype);
  Object.assign(parentPanel, { topology: nesting, networkId: 'network-a', generation: 0, previewSequence: 0, plan: [],
    side: { querySelector() { return null; } },
    renderSide() {}, setMessage(message) { this.message = message; } });
  parentPanel.prepareGroupParentGesture({ groupId: 'group-child', networkId: 'network-a', version: 1 }, '');
  assert.equal(parentPanel.plan[0].set_parent.expected_group_version, 1);
  parentPanel.prepareGroupParentGesture({ groupId: 'group-child', networkId: 'foreign', version: 1 }, '');
  assert.equal(parentPanel.plan.length, 0, 'scope change rejects and clears old nesting preview');
  parentPanel.prepareGroupParentGesture({ groupId: 'group-child', networkId: 'network-a', version: 2 }, '');
  assert.equal(parentPanel.plan.length, 0, 'in-flight version change cannot create a new preview');
  parentPanel.writeFence = { operationID: 'uncertain' };
  parentPanel.prepareGroupParentGesture({ groupId: 'group-child', networkId: 'network-a', version: 1 }, '');
  assert.equal(parentPanel.plan.length, 0, 'durable uncertain fence rejects valid nesting intent');
  assert.match(parentPanel.message, /uncertain outcome/);
  parentPanel.writeFence = null;
  parentPanel.prepareGroupParentGesture({ groupId: 'group-child', networkId: 'network-a', version: 1 }, 'group-root');
  assert.equal(parentPanel.plan.length, 0, 'duplicate placement remains a no-op');
  const newer = model.groupParentGesture({ ...nesting, groups: nesting.groups.map(group =>
    group.group_id === 'group-child' ? { ...group, version: 2 } : group) }, 'group-child', '', 'network-a');
  assert.equal(newer.action.set_parent.expected_group_version, 2);
  assert.equal(rootIntent.action.set_parent.expected_group_version, 1, 'saved preview never silently advances its CAS');
  assert.equal(model.groupHasMember(topology, topology.endpoints[0], 'group-root'), true);
  const scene = model.layoutTopology(topology, 'network-a');
  assert.equal(scene.endpointRefs.length, 2, 'one endpoint should have a visual reference in each Group');
  assert.notDeepEqual(scene.groupPos.get('group-root'), scene.groupPos.get('group-child'));

  const gestureTopology = { ...topology,
    groups: [...topology.groups, { group_id: 'group-new', network_id: 'network-a', name: 'New', state: 'active', context_policy: 'group_scoped' }],
    memberships: [...topology.memberships, { group_id: 'group-new', principal_id: 'principal-a', status: 'active' }],
    endpoints: [...topology.endpoints,
      { endpoint_id: 'endpoint-b', principal_id: 'principal-b', owner_id: 'owner-b', name: 'Receiver',
        group_ids: ['group-child'], network_ids: ['network-a'] }],
  };
  gestureTopology.memberships.push({ group_id: 'group-child', principal_id: 'principal-b', status: 'active' });
  const joinIntent = model.endpointJoinGesture(gestureTopology, 'endpoint-a', 'group-new', 'network-a');
  assert.deepEqual(joinIntent.action, { kind: 'endpoint.join_group',
    join_group: { endpoint_id: 'endpoint-a', group_id: 'group-new' } });
  assert.match(joinIntent.review, /preserves the Endpoint's other Group references/);
  assert.match(joinIntent.review, /Canvas position grants no access/);
  assert.throws(() => model.endpointJoinGesture(gestureTopology, 'endpoint-a', 'group-new', 'network-other'), /selected Network/);
  assert.throws(() => model.endpointJoinGesture({ ...gestureTopology,
    memberships: gestureTopology.memberships.filter(member => member.group_id !== 'group-new') },
  'endpoint-a', 'group-new', 'network-a'), /no active membership/);
  const networkOnlyEndpoint = { endpoint_id: 'endpoint-network-only', principal_id: 'principal-a', owner_id: 'owner-a',
    name: 'Network only', group_ids: [], network_ids: ['network-a'] };
  const admissionTopology = { ...gestureTopology, owner_principal_id: 'owner-a',
    endpoints: [...gestureTopology.endpoints, networkOnlyEndpoint],
    memberships: gestureTopology.memberships.filter(member => member.principal_id !== 'principal-a' || member.group_id !== 'group-new') };
  const admissionPreview = { owner_principal_id: 'owner-a', network_id: 'network-a', network_name: 'Network A',
    network_version: 3, group_id: 'group-new', group_name: 'New', group_version: 2, group_context_policy: 'group_scoped',
    endpoint_id: 'endpoint-network-only', endpoint_name: 'Network only', endpoint_principal_id: 'principal-a',
    endpoint_migration_state: 'MIGRATION_PENDING_GROUP', network_membership_revision: 4, endpoint_network_revision: 2,
    network_access_binding_id: 'access-binding', network_access_epoch: 5, native_binding_id: 'native-binding', native_binding_epoch: 7,
    membership_revision: 0, endpoint_group_revision: 0, admission_roles: ['member'], admission_grants: [],
    history_included: false, key_grant_created: false, existing_thread_memory_retained: true };
  const admissionIntent = model.endpointAdmissionGesture(admissionTopology, networkOnlyEndpoint.endpoint_id,
    'group-new', 'network-a', admissionPreview);
  assert.equal(admissionIntent.action.kind, 'endpoint.admit_group');
  assert.equal(admissionIntent.action.admit_endpoint.admission.expected_endpoint_migration_state, 'MIGRATION_PENDING_GROUP');
  assert.match(admissionIntent.review, /no Worker\/Monitor role/);
  assert.match(admissionIntent.review, /not cleared or isolated/);
  assert.throws(() => model.endpointAdmissionGesture(admissionTopology, networkOnlyEndpoint.endpoint_id,
    'group-new', 'network-a', { ...admissionPreview, membership_status: 'revoked', membership_revision: 4 }), /stale/);
  assert.throws(() => model.endpointAdmissionGesture(admissionTopology, networkOnlyEndpoint.endpoint_id,
    'group-new', 'network-a', { ...admissionPreview, admission_grants: ['worker'] }), /stale/);
  assert.throws(() => model.endpointAdmissionGesture(admissionTopology, networkOnlyEndpoint.endpoint_id,
    'group-new', 'network-a', { ...admissionPreview, group_context_policy: 'dedicated' }), /stale/);
  const linkPair = model.linkGesturePair(gestureTopology, 'endpoint-a', 'group-root',
    'endpoint-b', 'group-child', 'network-a');
  assert.equal(linkPair.sourceEndpointId, 'endpoint-a');
  assert.equal(linkPair.targetEndpointId, 'endpoint-b');
  assert.match(linkPair.review, /different Owners/);
  assert.match(linkPair.review, /does not activate routing/);
  assert.throws(() => model.linkGesturePair(gestureTopology, 'endpoint-a', 'group-root',
    'endpoint-a', 'group-child', 'network-a'), /two distinct Endpoint references/);

  const creationSnapshot = { ...admissionTopology, networks: [{ network_id: 'network-a', state: 'ACTIVE' }] };
  const selectedIds = ['endpoint-a', 'endpoint-network-only', 'endpoint-a'];
  const selection = model.groupCreationSelection(creationSnapshot, selectedIds, 'network-a');
  selectedIds.push('foreign-endpoint');
  assert.deepEqual(selection.endpointIds, ['endpoint-a', 'endpoint-network-only'], 'creation retains exact selected IDs without duplicates');
  assert.ok(Object.isFrozen(selection) && Object.isFrozen(selection.endpointIds));
  assert.throws(() => selection.endpointIds.push('injected'), TypeError);
  assert.throws(() => model.groupCreationSelection(creationSnapshot, ['foreign-endpoint'], 'network-a'), /remain visible/);
  assert.throws(() => model.groupCreationSelection(creationSnapshot, ['endpoint-a'], 'other-network'), /active Network/);
  const target = model.createdGroupTarget(creationSnapshot, 'group-new', selection);
  assert.equal(target.groupId, 'group-new', 'the authenticated Group ID determines the attachment target');
  assert.deepEqual(target.endpointIds, selection.endpointIds);
  for (const change of [{ state: 'archived' }, { network_id: 'other-network' }]) {
    assert.throws(() => model.createdGroupTarget({ ...creationSnapshot, groups: creationSnapshot.groups.map(group =>
      group.group_id === 'group-new' ? { ...group, ...change } : group) }, 'group-new', selection), /active target/);
  }
  assert.throws(() => model.createdGroupTarget({ ...creationSnapshot,
    endpoints: creationSnapshot.endpoints.filter(endpoint => endpoint.endpoint_id !== 'endpoint-network-only') },
  'group-new', selection), /remain visible/, 'a missing selected Endpoint cannot silently change the retained selection');

  const placed = { endpoints: [{ endpoint_id: 'source', node_id: 'node-one' },
    { endpoint_id: 'local', node_id: 'node-one' }, { endpoint_id: 'remote', node_id: 'node-two' }] };
  assert.equal(model.linkTransportSelection(placed, 'source', 'local', 'pinned-hub', '').transportHubId, '');
  assert.throws(() => model.linkTransportSelection(placed, 'source', 'local', 'pinned-hub', 'pinned-hub'), /same-Node/);
  for (const selectedHub of ['', 'foreign-hub']) {
    assert.throws(() => model.linkTransportSelection(placed, 'source', 'remote', 'pinned-hub', selectedHub), /Explicitly select/);
  }
  assert.throws(() => model.linkTransportSelection(placed, 'source', 'remote', '', 'pinned-hub'), /Explicitly select/);
  const transport = model.linkTransportSelection(placed, 'source', 'remote', 'pinned-hub', 'pinned-hub');
  assert.equal(transport.transportHubId, 'pinned-hub');
  assert.match(transport.review, /selection grants no permission/);
  assert.equal(model.actionSummary({ kind: 'group.create', create_group: {
    group: { name: 'Child' }, parent_group_id: 'exact-parent' } }), 'Create Group “Child” under exact-parent.');
  for (const node_id of ['', null, undefined]) {
    assert.throws(() => model.linkTransportSelection({ endpoints: placed.endpoints.map(endpoint =>
      endpoint.endpoint_id === 'remote' ? { ...endpoint, node_id } : endpoint) },
    'source', 'remote', 'pinned-hub', 'pinned-hub'), /Node placements must be known/);
  }

  const makePanel = () => Object.assign(Object.create(CanvasPanel.prototype), {
    topology: creationSnapshot, status: {}, networkId: 'network-a', pinnedHubId: 'pinned-hub', generation: 0,
    previewSequence: 0, plan: [], planContext: null, selection: new Set(selection.endpointIds),
    side: { querySelector() { return null; } },
    render() {}, renderSide() {}, cancelPointer() {}, setMessage(message) { this.message = message; }
  });
  for (const kind of ['group.create', 'endpoint.admit_group', 'membership.bind_role',
    'membership.set_broadcast_permission', 'link.propose', 'group.set_parent']) {
    const scoped = makePanel();
    const saved = scoped.captureScope();
    scoped.plan = [{ kind }]; scoped.planContext = saved; scoped.planReview = 'exact saved review';
    scoped.pendingLinkGesture = { sourceEndpointId: 'source', targetEndpointId: 'remote' };
    scoped.createdGroupIntent = target;
    scoped.resourceScopeChanged();
    assert.equal(scoped.plan.length, 0, `${kind} preview is discarded on scope invalidation`);
    assert.equal(scoped.planContext, null); assert.equal(scoped.pendingLinkGesture, null);
    assert.equal(scoped.createdGroupIntent, null); assert.equal(scoped.planReview, '');
    assert.equal(scoped.scopeIsCurrent(saved), false);
    scoped.queueAction({ kind: 'group.create', create_group: { group: { name: 'late' } } }, 'late', saved);
    assert.equal(scoped.plan.length, 0, 'a stale callback cannot enqueue another typed write');
  }
  const delayed = makePanel();
  let releasePreview;
  let previewCalls = 0;
  delayed.rpc = async operation => {
    assert.equal(operation, 'topology.endpoint_admission_preview');
    previewCalls++;
    return new Promise(resolve => { releasePreview = resolve; });
  };
  const inFlight = delayed.previewEndpointJoin('endpoint-network-only', 'group-new');
  assert.equal(previewCalls, 1);
  delayed.resourceScopeChanged();
  releasePreview(admissionPreview);
  await inFlight;
  assert.equal(delayed.plan.length, 0, 'an authenticated late admission preview cannot revive discarded scope');
  const currentPreview = delayed.previewEndpointJoin('endpoint-network-only', 'group-new');
  assert.equal(previewCalls, 2, 'the next intent obtains a separate fresh preview');
  releasePreview(admissionPreview);
  await currentPreview;
  assert.equal(delayed.plan.length, 1);
  assert.equal(delayed.plan[0].admit_endpoint.admission.endpoint_id, 'endpoint-network-only');
  assert.equal(delayed.plan[0].admit_endpoint.admission.group_id, 'group-new');
  assert.equal(delayed.scopeIsCurrent(delayed.planContext), true);

  const creating = makePanel();
  const writes = [];
  let refreshes = 0;
  creating.rpc = async (operation, action) => {
    assert.equal(operation, 'topology.apply');
    writes.push(action);
    return { group: { group_id: 'group-new' } };
  };
  creating.refresh = async () => {
    refreshes++;
    return { topology: creationSnapshot, status: {}, snapshotStartedAt: Date.now() };
  };
  const createAction = { kind: 'group.create', create_group: { group: { network_id: 'network-a', name: 'Selected Group' } } };
  creating.queueAction(createAction, 'review selected IDs', creating.captureScope(), selection);
  assert.equal(writes.length, 0, 'a local creation preview never writes');
  await creating.applyFirst();
  assert.equal(writes.length, 1, 'creation confirmation sends one typed action without automatic membership writes');
  assert.strictEqual(writes[0], createAction);
  assert.equal(refreshes, 1, 'creation refreshes authoritative snapshots before choosing a target');
  assert.equal(creating.createdGroupIntent.groupId, 'group-new');
  assert.deepEqual(creating.createdGroupIntent.endpointIds, selection.endpointIds);
  assert.equal(creating.plan.length, 0, 'attachment still needs a fresh independent preview');
  await creating.reload();
  assert.equal(creating.createdGroupIntent, null, 'an ordinary refresh discards the local selection intent');
  assert.equal(writes.length, 1, 'refresh cannot admit another selected Endpoint');

  const stopped = makePanel();
  let attempts = 0;
  stopped.rpc = async () => { attempts++; throw Object.assign(new Error('current authority denied'), { errorCode: 'SCOPE_REVOKED' }); };
  stopped.refresh = creating.refresh;
  stopped.queueAction(createAction);
  await stopped.applyFirst();
  assert.equal(attempts, 1, 'a typed refusal does not retry the action');
  assert.equal(stopped.plan.length, 0); assert.equal(stopped.createdGroupIntent, null);
  assert.match(stopped.message, /SCOPE_REVOKED: current authority denied/);
  assert.match(stopped.message, /Authoritative topology and status snapshots refreshed/,
    'reconciliation preserves the visible typed rejection');

  const refreshing = makePanel();
  const oldTopology = refreshing.topology;
  let releaseRefresh;
  refreshing.refresh = () => new Promise(resolve => { releaseRefresh = resolve; });
  refreshing.queueAction(createAction);
  const waiting = refreshing.reload();
  assert.equal(refreshing.plan.length, 0, 'a refresh discards every old action before awaiting network results');
  refreshing.networkId = 'network-b'; refreshing.invalidateIntents();
  releaseRefresh({ topology: { groups: [] }, status: {} });
  assert.equal(await waiting, false);
  assert.strictEqual(refreshing.topology, oldTopology, 'a late snapshot cannot replace a newer selected scope');
}

async function wasmChecks(wasmPath, runtimePath, uiDir) {
  const runtime = await readFile(runtimePath, 'utf8');
  globalThis.require = createRequire(import.meta.url);
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  vm.runInThisContext(runtime, { filename: runtimePath });
  assert.equal(typeof globalThis.Go, 'function', 'matching Go wasm_exec.js must expose Go');
  const go = new globalThis.Go();
  go.argv = ['cicada-webcrypto-interop-test'];
  const raw = await readFile(wasmPath);
  const bytes = raw[0] === 0x1f && raw[1] === 0x8b ? gunzipSync(raw) : raw;
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(instance);
  const deadline = Date.now() + 5000;
  while (!globalThis.cicadaWebCryptoReady && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(globalThis.cicadaWebCryptoReady, true, 'WASM facade starts');
  const api = globalThis.cicadaWebCrypto;
  const device = api.generateIdentity({});
  const hub = api.generateIdentity({});
  assert.equal(device.ok, true, device.error);
  assert.equal(hub.ok, true, hub.error);
  const accountFixture = api.makeOwnerClaimFixtureForInteropTest({ hub_handle: hub.handle });
  assert.equal(accountFixture.ok, true, accountFixture.error);
  const claimInput = { hub_identity: accountFixture.hub_identity,
    claim_card_json: accountFixture.claim_card_json, page_origin: accountFixture.page_origin };
  const verifiedClaim = api.validateOwnerClaimCard(claimInput);
  assert.equal(verifiedClaim.ok, true, verifiedClaim.error);
  assert.equal(verifiedClaim.summary.hubId, accountFixture.hub_identity.hub_id,
    'claim-card UI metadata uses the documented camelCase adapter shape');
  assert.match(verifiedClaim.summary.hubFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(verifiedClaim.summary, 'code'), false, 'claim code is excluded from the display summary');
  assert.equal(api.validateOwnerClaimCard({ ...claimInput, page_origin: 'https://other.synthetic.invalid' }).ok, false,
    'claim card is rejected when its origin differs from the pinned page');
  const claimPrepare = api.sealOwnerClaimPrepare({ handle: device.handle, ...claimInput });
  assert.equal(claimPrepare.ok, true, claimPrepare.error);
  assert.match(claimPrepare.device_id, /^accountdev_[0-9a-f]{32}$/);
  assert.equal(claimPrepare.claim.accountId, 'account_wasm_owner_account');
  assert.equal(claimPrepare.claim.hubFingerprint, verifiedClaim.summary.hubFingerprint);
  const replacementClaimPrepare = api.sealOwnerClaimPrepare({ handle: device.handle, ...claimInput,
    existing_device_id: claimPrepare.device_id, expected_public_identity: device.public_identity });
  assert.equal(replacementClaimPrepare.ok, true, replacementClaimPrepare.error);
  assert.equal(replacementClaimPrepare.device_id, claimPrepare.device_id,
    'a reissued same-scope claim keeps the exact saved browser device ID');
  assert.equal(replacementClaimPrepare.public_identity.id, device.public_identity.id);
  assert.notEqual(replacementClaimPrepare.request_id, claimPrepare.request_id,
    'a replacement claim prepare gets a fresh operation ID');
  assert.equal(api.sealOwnerClaimPrepare({ handle: device.handle, ...claimInput,
    existing_device_id: 'accountdev_ABCDEF0123456789ABCDEF0123456789',
    expected_public_identity: device.public_identity }).ok, false,
  'an existing account-device ID must be canonical lowercase hex');
  assert.equal(api.sealOwnerClaimPrepare({ handle: device.handle, ...claimInput,
    existing_device_id: claimPrepare.device_id, expected_public_identity: hub.public_identity }).ok, false,
  'the retained device ID cannot be rebound to a different local public identity');
  const claimChallenge = api.sealOwnerClaimChallengeForInteropTest({ hub_handle: hub.handle,
    hub_identity: accountFixture.hub_identity, request_packet: claimPrepare.packet });
  assert.equal(claimChallenge.ok, true, claimChallenge.error);
  const replacementClaimChallenge = api.sealOwnerClaimChallengeForInteropTest({ hub_handle: hub.handle,
    hub_identity: accountFixture.hub_identity, request_packet: replacementClaimPrepare.packet });
  assert.equal(replacementClaimChallenge.ok, true, replacementClaimChallenge.error);
  assert.equal(replacementClaimChallenge.device_id, claimChallenge.device_id);
  assert.notEqual(replacementClaimChallenge.request_id, claimChallenge.request_id);
  assert.notEqual(replacementClaimChallenge.client_nonce, claimChallenge.client_nonce,
    'replacement prepares use a fresh nonce while retaining the approved device identity');
  const claimComplete = api.sealOwnerClaimComplete({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    prepare_packet: claimPrepare.packet, challenge_packet: claimChallenge.packet,
    origin: accountFixture.page_origin, account_id: verifiedClaim.summary.accountId,
    owner_id: verifiedClaim.summary.ownerId, device_id: claimPrepare.device_id,
    username: 'synthetic-owner', password: 'Cicada synthetic 2026',
    owner_public_identity: accountFixture.owner_public_identity });
  assert.equal(claimComplete.ok, true, claimComplete.error);
  const claimReceiptPacket = api.sealOwnerClaimReceiptForInteropTest({ hub_handle: hub.handle,
    device_handle: device.handle, hub_identity: accountFixture.hub_identity,
    prepare_packet: claimPrepare.packet, challenge_packet: claimChallenge.packet,
    complete_packet: claimComplete.packet, owner_public_identity: accountFixture.owner_public_identity });
  assert.equal(claimReceiptPacket.ok, true, claimReceiptPacket.error);
  const ownerFingerprint = api.fingerprint({ public_identity: accountFixture.owner_public_identity });
  assert.equal(ownerFingerprint.ok, true, ownerFingerprint.error);
  const openedClaimReceipt = api.openOwnerClaimReceipt({ handle: device.handle,
    hub_identity: accountFixture.hub_identity, request_packet: claimComplete.packet,
    response_packet: claimReceiptPacket.packet, origin: accountFixture.page_origin,
    account_id: verifiedClaim.summary.accountId, owner_id: verifiedClaim.summary.ownerId,
    owner_public_identity: accountFixture.owner_public_identity,
    owner_key_id: accountFixture.owner_public_identity.id, owner_fingerprint: ownerFingerprint.fingerprint });
  assert.equal(openedClaimReceipt.ok, true, openedClaimReceipt.error);
  assert.equal(openedClaimReceipt.receipt.state, 'ACCOUNT_READY_OWNER_SIGNER_PENDING');
  assert.equal(openedClaimReceipt.receipt.root_active, false, 'account claim receipt cannot imply Root authority');
  const loginPrepare = api.sealOwnerLoginPrepare({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    origin: accountFixture.page_origin, account_id: verifiedClaim.summary.accountId,
    owner_id: verifiedClaim.summary.ownerId, device_id: claimPrepare.device_id, username: 'synthetic-owner' });
  assert.equal(loginPrepare.ok, true, loginPrepare.error);
  const loginChallenge = api.sealOwnerLoginChallengeForInteropTest({ hub_handle: hub.handle,
    hub_identity: accountFixture.hub_identity, request_packet: loginPrepare.packet });
  assert.equal(loginChallenge.ok, true, loginChallenge.error);
  const loginComplete = api.sealOwnerLoginComplete({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    prepare_packet: loginPrepare.packet, challenge_packet: loginChallenge.packet,
    origin: accountFixture.page_origin, account_id: verifiedClaim.summary.accountId,
    owner_id: verifiedClaim.summary.ownerId, device_id: claimPrepare.device_id,
    username: 'synthetic-owner', password: 'Cicada synthetic 2026' });
  assert.equal(loginComplete.ok, true, loginComplete.error);
  const sessionReceiptPacket = api.sealOwnerLoginReceiptForInteropTest({ hub_handle: hub.handle,
    device_handle: device.handle, hub_identity: accountFixture.hub_identity,
    prepare_packet: loginPrepare.packet, challenge_packet: loginChallenge.packet,
    request_packet: loginComplete.packet });
  assert.equal(sessionReceiptPacket.ok, true, sessionReceiptPacket.error);
  const session = api.openOwnerLoginReceipt({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    request_packet: loginComplete.packet, response_packet: sessionReceiptPacket.packet,
    origin: accountFixture.page_origin, account_id: verifiedClaim.summary.accountId,
    owner_id: verifiedClaim.summary.ownerId, device_id: claimPrepare.device_id });
  assert.equal(session.ok, true, session.error);
  assert.equal(typeof session.session_handle, 'string');
  assert.equal(Object.hasOwn(session, 'session_token'), false, 'session tokens stay behind the WASM handle');
  const inspect = api.sealOwnerSessionInspect({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    session_handle: session.session_handle });
  assert.equal(inspect.ok, true, inspect.error);
  const inspectionPacket = api.sealOwnerSessionInspectionForInteropTest({ hub_handle: hub.handle,
    hub_identity: accountFixture.hub_identity, request_packet: inspect.packet,
    owner_public_identity: accountFixture.owner_public_identity });
  assert.equal(inspectionPacket.ok, true, inspectionPacket.error);
  const inspected = api.openOwnerSessionInspection({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    session_handle: session.session_handle, request_packet: inspect.packet, response_packet: inspectionPacket.packet });
  assert.equal(inspected.ok, true, inspected.error);
  assert.equal(inspected.status.state, 'ACTIVE');
  assert.equal(inspected.status.root_active, false);
  const logout = api.sealOwnerLogout({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    session_handle: session.session_handle });
  assert.equal(logout.ok, true, logout.error);
  const logoutReceipt = api.sealOwnerLogoutReceiptForInteropTest({ hub_handle: hub.handle,
    hub_identity: accountFixture.hub_identity, request_packet: logout.packet });
  assert.equal(logoutReceipt.ok, true, logoutReceipt.error);
  const logoutBinding = { origin: session.origin, hub_id: session.hub_id, account_id: session.account_id,
    owner_id: session.owner_id, device_id: session.device_id,
    account_epoch: session.account_epoch, device_epoch: session.device_epoch };
  const loggedOut = api.openOwnerLogoutReceipt({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    session_handle: session.session_handle, request_packet: logout.packet, response_packet: logoutReceipt.packet,
    ...logoutBinding });
  assert.equal(loggedOut.ok, true, loggedOut.error);
  const recoveredLogout = api.openOwnerLogoutReceipt({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    request_packet: logout.packet, response_packet: logoutReceipt.packet, ...logoutBinding });
  assert.equal(recoveredLogout.ok, true, recoveredLogout.error,
    'a saved authenticated logout receipt can be checked after reload without restoring a plaintext session token');
  assert.equal(api.openOwnerLogoutReceipt({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    request_packet: logout.packet, response_packet: logoutReceipt.packet,
    ...logoutBinding, device_epoch: logoutBinding.device_epoch + 1 }).ok, false,
    'offline logout receipt recovery remains bound to the saved account and device epochs');
  assert.equal(api.sealOwnerLogout({ handle: device.handle, hub_identity: accountFixture.hub_identity,
    session_handle: session.session_handle }).ok, false, 'a completed logout clears the opaque session handle');
  assert.equal(api.validatePublicIdentity({ public_identity: device.public_identity }).ok, true);
  assert.equal(api.validatePublicIdentity({ public_identity: { ...device.public_identity, id: 'pq1-forged' } }).ok, false);
  const fingerprint = api.fingerprint({ public_identity: device.public_identity });
  assert.match(fingerprint.fingerprint, /^[0-9a-f]{64}$/);
  const { validateOwnerBootstrapPublicFiles: validateOwnerBootstrap,
    validateOwnerDeviceGrantSummary: validateGrantSummary } = await loadOwnerBootstrapValidator(uiDir);
  const publicHub = { contract: 'android-hub-v1', hub_id: 'hub_wasm_owner_bootstrap',
    control_public_identity: hub.public_identity, control_key_version: 1,
    suite: 'ML-KEM-768+ML-DSA-65+AES-256-GCM' };
  const ownerConnection = { format: 'cicada.hub-owner-connection.v1', version: 1,
    purpose: 'ROOT_SIGNER_BOOTSTRAP', account_id: 'account_wasm_owner_bootstrap',
    owner_id: 'human_wasm_owner_bootstrap', origin: 'https://synthetic.invalid',
    allow_loopback_http: false, hub: publicHub };
  const ownerManifest = { format: 'cicada.owner-signer-public.v1',
    account_id: ownerConnection.account_id, owner_id: ownerConnection.owner_id,
    owner_public_identity: device.public_identity, fingerprint: fingerprint.fingerprint,
    origin: ownerConnection.origin, allow_loopback_http: false, hub: publicHub };
  const ownerDraft = validateOwnerBootstrap(ownerConnection, ownerManifest,
    ownerConnection.origin, publicHub, api);
  assert.equal(ownerDraft.ownerKeyID, device.public_identity.id,
    'Owner draft validation uses the full Go WASM public-identity validator and fingerprint');
  assert.throws(() => validateOwnerBootstrap(ownerConnection,
    { ...ownerManifest, fingerprint: '0'.repeat(64) }, ownerConnection.origin, publicHub, api),
  /fingerprint/);
  const binding = { hubID: 'hub-wasm-test', ownerID: 'owner-wasm-test', deviceID: 'browser-wasm-test',
    sessionEpoch: 3, hubKeyVersion: 1, deviceKeyVersion: 1 };
  const route = { version: 1, direction: 'REQUEST', hub_id: binding.hubID,
    owner_id: binding.ownerID, device_id: binding.deviceID, session_epoch: binding.sessionEpoch,
    sequence: 1, operation_id: 'operation-wasm-test', operation: 'topology.snapshot',
    sender_key_id: device.public_identity.id, sender_key_version: 1,
    receiver_key_id: hub.public_identity.id, receiver_key_version: 1 };
  const sealed = api.sealRequest({ handle: device.handle, peer_public_identity: hub.public_identity,
    binding, route, plaintext: {} });
  assert.equal(sealed.ok, true, sealed.error);
  const opened = api.openRequestForInteropTest({ handle: hub.handle, peer_public_identity: device.public_identity,
    binding, route, packet: sealed.packet });
  assert.equal(opened.ok, true, opened.error);
  assert.equal(opened.route.operation_id, route.operation_id);
  assert.equal(opened.plaintext, '{}');
  const corruptRequest = Buffer.from(sealed.packet, 'base64');
  corruptRequest[corruptRequest.length - 5] ^= 1;
  assert.equal(api.openRequestForInteropTest({ handle: hub.handle, peer_public_identity: device.public_identity,
    binding, route, packet: corruptRequest.toString('base64') }).ok, false, 'tampered request must be rejected');

  const responseRoute = { ...route, direction: 'RESPONSE', sequence: 1,
    sender_key_id: hub.public_identity.id, receiver_key_id: device.public_identity.id,
    sender_key_version: 1, receiver_key_version: 1 };
  const response = api.sealResponseForInteropTest({ handle: hub.handle, peer_public_identity: device.public_identity,
    binding, route, response_route: responseRoute,
    plaintext: { request_id: 'request-wasm-test', operation_id: route.operation_id, ok: true, result: { wired: true } } });
  assert.equal(response.ok, true, response.error);
  const openedResponse = api.openResponse({ handle: device.handle, peer_public_identity: hub.public_identity,
    binding, route, packet: response.packet, expected_operation_id: route.operation_id,
    expected_operation: route.operation, expected_response_sequence: 1 });
  assert.equal(openedResponse.ok, true, openedResponse.error);
  assert.equal(JSON.parse(openedResponse.plaintext).result.wired, true);
  assert.equal(api.openResponse({ handle: device.handle, peer_public_identity: hub.public_identity,
    binding, route, packet: response.packet, expected_operation_id: 'other-op',
    expected_operation: route.operation, expected_response_sequence: 1 }).ok, false, 'wrong operation ID must be rejected');
  const corruptResponse = Buffer.from(response.packet, 'base64');
  corruptResponse[corruptResponse.length - 7] ^= 1;
  assert.equal(api.openResponse({ handle: device.handle, peer_public_identity: hub.public_identity,
    binding, route, packet: corruptResponse.toString('base64'), expected_operation_id: route.operation_id,
    expected_operation: route.operation, expected_response_sequence: 1 }).ok, false, 'tampered response must be rejected');

  const grantVector = api.makeGrantVectorForInteropTest({ handle: device.handle });
  assert.equal(grantVector.ok, true, grantVector.error);
  const grantInput = { owner_public_identity: grantVector.owner_public_identity,
    device_public_identity: grantVector.device_public_identity, owner_id: grantVector.owner_id,
    device_id: grantVector.device_id, hub_id: grantVector.hub_id, grant: grantVector.grant };
  const grantManifest = { format: 'cicada.owner-device-enrollment.v1', hub_id: grantVector.hub_id,
    owner_id: grantVector.owner_id, owner_key_id: grantVector.owner_public_identity.id,
    device_id: grantVector.device_id, device_key_fingerprint: api.fingerprint({
      public_identity: grantVector.device_public_identity }).fingerprint,
    purpose: 'CLIENT_CONTROL', device_public_identity: grantVector.device_public_identity };
  const verifiedGrant = api.verifyOwnerDeviceGrant(grantInput);
  const signedGrantForSummary = JSON.parse(Buffer.from(grantVector.grant, 'base64').toString('utf8'));
  const grantSummary = { format: 'cicada.owner-device-grant-summary.v1', state: 'GRANT_WRITTEN',
    hub_id: grantManifest.hub_id, owner_id: grantManifest.owner_id,
    owner_key_id: grantManifest.owner_key_id, owner_public_identity: grantVector.owner_public_identity,
    device_id: grantManifest.device_id, device_key_id: grantVector.device_public_identity.id,
    device_key_fingerprint: grantManifest.device_key_fingerprint, purpose: grantManifest.purpose,
    issued_at: signedGrantForSummary.issued_at, expires_at: verifiedGrant.expires_at,
    grant_file: 'owner-device-grant.json' };
  assert.strictEqual(validateGrantSummary(grantSummary, grantManifest, api), grantVector.owner_public_identity,
    'Go WASM validates full Owner identity in profile grant summary');
  assert.equal(api.verifyOwnerDeviceGrant({ ...grantInput, owner_public_identity:
    validateGrantSummary(grantSummary, grantManifest, api) }).ok, true,
  'Go WASM verifies the signature against the exact public Owner identity from the summary');
  assert.throws(() => validateGrantSummary({ ...grantSummary, expires_at: 'not-a-timestamp' }, grantManifest, api),
    /manifest/);
  assert.equal(api.verifyOwnerDeviceGrant(grantInput).ok, true, 'Go WASM verifies exact Owner signature/scope');
  const badGrant = Buffer.from(grantVector.grant, 'base64');
  badGrant[Math.floor(badGrant.length / 2)] ^= 1;
  assert.equal(api.verifyOwnerDeviceGrant({ ...grantInput, grant: badGrant.toString('base64') }).ok, false,
    'tampered Owner grant must fail Go WASM verification');
  api.forgetIdentity({ handle: device.handle });
  api.forgetIdentity({ handle: hub.handle });
}

async function staticChecks(uiDir) {
  const files = ['panel.js', 'panel-account.js', 'panel-bootstrap.js', 'panel-client.js', 'panel-model.js', 'panel-canvas.js',
    'panel-canvas-controls.js', 'panel-dom.js'];
  for (const name of files) {
    const source = await readFile(path.join(uiDir, name), 'utf8');
    for (const forbidden of ['innerHTML', 'localStorage', 'Authorization: Bearer', '/v1/']) {
      assert.equal(source.includes(forbidden), false, `${name} must not contain ${forbidden}`);
    }
  }
  const app = await readFile(path.join(uiDir, 'panel.js'), 'utf8');
  assert.match(app, /--summary-output owner-device-grant-summary\.json/,
    'the profile grant flow exports a separate summary without redirecting terminal review');
  assert.match(app, /validateOwnerDeviceGrantSummary\(signerSummary, manifest, cryptoApi\)/,
    'grant imports use strict local public-summary validation');
  assert.match(app, /cryptoApi\.generateIdentity\(\{\}\)/, 'WASM facade receives its required object argument');
  assert.match(app, /createDeviceDraftState\(state, location\.origin, vault, manifest\)/,
    'device creation uses the same draft guard tested for concurrent tabs');
  const canvas = await readFile(path.join(uiDir, 'panel-canvas.js'), 'utf8');
  assert.match(canvas, /Drag to Group/);
  assert.match(canvas, /Draw Link/);
  assert.match(canvas, /data-group-drop-id/);
  assert.match(canvas, /previewEndpointJoin/);
  assert.match(canvas, /topology\.endpoint_admission_preview/);
  assert.match(canvas, /endpointAdmissionGesture/);
  assert.match(canvas, /document\.elementFromPoint/);
  const controls = await readFile(path.join(uiDir, 'panel-canvas-controls.js'), 'utf8');
  assert.match(controls, /topology\.apply/);
  assert.match(controls, /Preview next selected Endpoint/);
  assert.match(controls, /network\.directory/);
  assert.match(controls, /Read-only Endpoint cards published by current Network members/);
  assert.match(controls, /Group creation and its parent relation are one versioned topology action/);
  assert.match(controls, /does not create an active route/);
}

async function main() {
  const wasmPath = option('--wasm');
  const runtimePath = option('--wasm-exec');
  const uiDir = option('--ui');
  if (uiDir) await webCryptoManifestChecks(uiDir);
  if (process.argv.includes('--model-only')) {
    if (!uiDir) throw new Error('--model-only requires --ui DIR');
    await modelChecks(uiDir); await staticChecks(uiDir); return;
  }
  if (!wasmPath || !runtimePath || !uiDir) throw new Error('usage: test-web-panel.mjs --wasm FILE --wasm-exec FILE --ui DIR');
  await modelChecks(uiDir);
  await staticChecks(uiDir);
  await wasmChecks(wasmPath, runtimePath, uiDir);
}

main().then(() => {
  process.stdout.write(process.argv.includes('--model-only') ? 'Web panel model/static checks passed; Go WASM NOT_RUN.\n' : 'Web panel model and real Go WASM PQ/Wire checks passed.\n');
  process.exit(0);
}).catch(error => {
  process.stderr.write(`Web panel check failed: ${error?.stack || error}\n`);
  process.exit(1);
});
