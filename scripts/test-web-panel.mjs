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
  vm.runInNewContext(`${source}\nglobalThis.panelValidators = { validateOwnerBootstrapPublicFiles, validateOwnerDeviceGrantSummary };`, context);
  return context.panelValidators;
}

async function ownerBootstrapChecks(uiDir) {
  const { validateOwnerBootstrapPublicFiles: validate, validateOwnerDeviceGrantSummary: validateGrantSummary } =
    await loadOwnerBootstrapValidator(uiDir);
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
  const entryStart = panelSource.indexOf('function renderOwnerAccountEntry()');
  const entryEnd = panelSource.indexOf('\nfunction renderOwnerBootstrapGuide(', entryStart);
  assert.ok(entryStart >= 0 && entryEnd > entryStart, 'normal Owner account landing is separate from advanced setup');
  const entry = panelSource.slice(entryStart, entryEnd);
  assert.match(entry, /installer-issued Hub URL and one-time claim code/);
  assert.match(entry, /Owner username and password using existing public keys/);
  assert.match(entry, /not Owner signup/);
  assert.match(entry, /openAdvanced\.disabled = true/);
  assert.match(entry, /consent\.addEventListener\('change'/);
  assert.match(entry, /if \(consent\.checked\) renderOwnerBootstrapGuide\(\)/,
    'the technical guide opens only after the explicit advanced consent checkbox');
  for (const forbidden of ['renderNewDevice(', 'fetch(', 'updateState(', 'enrollExactRequest(', 'callRPC(']) {
    assert.equal(entry.includes(forbidden), false, `normal Owner account landing must not call ${forbidden}`);
  }

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
    'unavailable signup changes only the empty-state route, not saved enrollment handling');
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

async function modelChecks(uiDir) {
  const model = await moduleFromFile(path.join(uiDir, 'panel-model.js'));
  assert.equal(model.savedPanelRoute({}), 'owner-account-setup-unavailable',
    'an empty pinned profile opens the unavailable account setup notice');
  assert.equal(model.savedPanelRoute({ vault: { ciphertext: 'synthetic' } }), 'owner-account-setup-unavailable',
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
  const identity = { hub_id: 'hub-pin-test', control_public_identity: { id: 'pq-hub-test' },
    control_key_version: 1, suite: 'ML-KEM-768+ML-DSA-65+AES-256-GCM' };
  assert.equal(model.pinMatches({ origin: 'https://hub.example', hubId: identity.hub_id, keyId: 'pq-hub-test' }, identity, 'https://hub.example'), true);
  assert.equal(model.pinMatches({ origin: 'https://hub.example', hubId: identity.hub_id, keyId: 'changed' }, identity, 'https://hub.example'), false);
  assert.equal(model.pinMatches({ origin: 'https://other.example', hubId: identity.hub_id, keyId: 'pq-hub-test' }, identity, 'https://hub.example'), false);
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
  const files = ['panel.js', 'panel-bootstrap.js', 'panel-client.js', 'panel-model.js', 'panel-canvas.js',
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
