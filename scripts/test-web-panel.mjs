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

async function modelChecks(uiDir) {
  const model = await moduleFromFile(path.join(uiDir, 'panel-model.js'));
  const identity = { hub_id: 'hub-pin-test', control_public_identity: { id: 'pq-hub-test' },
    control_key_version: 1, suite: 'ML-KEM-768+ML-DSA-65+AES-256-GCM' };
  assert.equal(model.pinMatches({ origin: 'https://hub.example', hubId: identity.hub_id, keyId: 'pq-hub-test' }, identity, 'https://hub.example'), true);
  assert.equal(model.pinMatches({ origin: 'https://hub.example', hubId: identity.hub_id, keyId: 'changed' }, identity, 'https://hub.example'), false);
  assert.equal(model.pinMatches({ origin: 'https://other.example', hubId: identity.hub_id, keyId: 'pq-hub-test' }, identity, 'https://hub.example'), false);
  const view = { x: 19, y: -7, scale: .72 };
  const point = { x: 125, y: 87 };
  const roundTrip = model.worldPointToScreen(model.screenPointToWorld(point, view), view);
  assert.ok(Math.abs(roundTrip.x - point.x) < 1e-9 && Math.abs(roundTrip.y - point.y) < 1e-9);
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
}

async function wasmChecks(wasmPath, runtimePath) {
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
  if (!wasmPath || !runtimePath || !uiDir) throw new Error('usage: test-web-panel.mjs --wasm FILE --wasm-exec FILE --ui DIR');
  await modelChecks(uiDir);
  await staticChecks(uiDir);
  await wasmChecks(wasmPath, runtimePath);
}

main().then(() => {
  process.stdout.write('Web panel model and real Go WASM PQ/Wire checks passed.\n');
  process.exit(0);
}).catch(error => {
  process.stderr.write(`Web panel check failed: ${error?.stack || error}\n`);
  process.exit(1);
});
