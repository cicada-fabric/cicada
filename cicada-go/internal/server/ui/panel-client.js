import { authorizeWriteFenceState, completeClientRequest, makeSemanticWriteFence,
  isSemanticWriteOperation, recoveredWriteFence, reserveClientRequest, saveEnrollmentState } from './panel-model.js';

const DB_NAME = 'cicada-hub-web-panel-v1';
const DB_VERSION = 1;
const STATE_KEY = 'owner-session';
const encoder = new TextEncoder();

export async function openPanelDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains('state')) request.result.createObjectStore('state');
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Browser secure storage could not be opened.'));
  });
}

export function getState(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('state', 'readonly');
    const request = tx.objectStore('state').get(STATE_KEY);
    request.onsuccess = () => resolve(request.result || {});
    request.onerror = () => reject(new Error('Browser state could not be read.'));
  });
}

export function updateState(db, update) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('state', 'readwrite');
    const store = tx.objectStore('state');
    const request = store.get(STATE_KEY);
    let next;
    request.onsuccess = () => {
      try {
        next = update(request.result || {});
        store.put(next, STATE_KEY);
      } catch (error) {
        try { tx.abort(); } catch { /* transaction has already closed */ }
        reject(error);
      }
    };
    tx.oncomplete = () => resolve(next);
    tx.onerror = () => reject(tx.error || new Error('Browser state transaction failed.'));
    tx.onabort = () => reject(tx.error || new Error('Browser state transaction was rejected.'));
  });
}

function toBase64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i += 0x8000) binary += String.fromCharCode(...view.subarray(i, i + 0x8000));
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function passwordKey(password, salt) {
  if (typeof password !== 'string' || password.length < 12) throw new Error('Choose a vault password with at least 12 characters.');
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function encryptIdentityBlob(identityBlob, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await passwordKey(password, salt);
  const plaintext = encoder.encode(identityBlob);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  plaintext.fill(0);
  return { format: 'cicada.browser-device-vault.v1', kdf: 'PBKDF2-SHA-256',
    iterations: 600000, cipher: 'AES-256-GCM', salt: toBase64(salt), iv: toBase64(iv),
    ciphertext: toBase64(ciphertext) };
}

export async function decryptIdentityBlob(vault, password) {
  if (!vault || vault.format !== 'cicada.browser-device-vault.v1' ||
      vault.kdf !== 'PBKDF2-SHA-256' || vault.iterations !== 600000 || vault.cipher !== 'AES-256-GCM') {
    throw new Error('Encrypted browser device backup has an unsupported format.');
  }
  try {
    const key = await passwordKey(password, fromBase64(vault.salt));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(vault.iv) }, key, fromBase64(vault.ciphertext));
    const bytes = new Uint8Array(plaintext);
    const value = new TextDecoder().decode(bytes);
    bytes.fill(0);
    return value;
  } catch {
    throw new Error('Vault password is wrong or the encrypted device backup is damaged.');
  }
}

export function downloadJSON(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export async function getHubIdentity() {
  const response = await fetch('/v2/client/identity', { method: 'GET', cache: 'no-store', credentials: 'omit' });
  if (!response.ok) throw new Error(`Hub identity request returned HTTP ${response.status}.`);
  return response.json();
}

export async function savePinnedHub(db, identity) {
  const pin = { origin: location.origin, hubId: identity.hub_id,
    keyId: identity.control_public_identity?.id, keyVersion: identity.control_key_version,
    suite: identity.suite, controlPublicIdentity: identity.control_public_identity };
  await updateState(db, current => {
    if (current.pin && (current.pin.origin !== pin.origin || current.pin.hubId !== pin.hubId || current.pin.keyId !== pin.keyId)) {
      throw new Error('This browser already pinned a different Hub identity for this origin. Clear this site’s browser storage only after reviewing the identity change.');
    }
    return { ...current, pin };
  });
  return pin;
}

export function enrollmentManifest(identity, ownerId, ownerKeyId, deviceId, devicePublicIdentity, fingerprint) {
  return { format: 'cicada.owner-device-enrollment.v1', hub_id: identity.hub_id,
    owner_id: ownerId, owner_key_id: ownerKeyId, device_id: deviceId,
    device_key_fingerprint: fingerprint, purpose: 'CLIENT_CONTROL',
    device_public_identity: devicePublicIdentity };
}

export async function saveExactEnrollmentRequest(db, request) {
  await updateState(db, state => saveEnrollmentState(state, request, location.origin));
}

export async function enrollExactRequest(db, request) {
  await saveExactEnrollmentRequest(db, request);
  const response = await fetch('/v2/client/devices/enroll', { method: 'POST', cache: 'no-store',
    credentials: 'omit', headers: { 'Content-Type': 'application/json' }, body: request.body });
  if (response.status !== 201) throw new Error(`Device enrollment did not complete (HTTP ${response.status}). The exact request remains saved for retry.`);
  const result = await response.json();
  if (result.owner_id !== request.ownerId || result.device_id !== request.deviceId ||
      result.state !== 'ACTIVE' || !Number.isSafeInteger(result.session_epoch) || result.session_epoch < 1 ||
      !Number.isSafeInteger(result.device_key_version) || result.device_key_version < 1) {
    throw new Error('Hub returned an unexpected device enrollment binding. The saved request remains available.');
  }
  await updateState(db, state => {
    if (state.device?.active) {
      if (state.device.ownerId === result.owner_id && state.device.deviceId === result.device_id &&
          state.device.deviceKeyId === request.deviceKeyId && state.device.sessionEpoch === result.session_epoch) return state;
      throw new Error('Another browser tab enrolled a different device. This response was not allowed to replace it.');
    }
    if (state.enrollment?.body !== request.body) throw new Error('Enrollment request changed while the Hub answered.');
    return { ...state, enrollment: null, device: { ownerId: result.owner_id,
      ownerKeyId: request.ownerKeyId, deviceId: result.device_id, deviceKeyId: request.deviceKeyId,
      sessionEpoch: result.session_epoch, deviceKeyVersion: result.device_key_version,
      nextRequestSequence: 1, nextResponseSequence: 1, active: true,
      lastRequestSequence: 0, pending: null, lastOperationId: '' } };
  });
  return result;
}

export async function createSealedRequest(db, cryptoApi, identity, operation, input) {
  let reserved;
  const operationId = crypto.randomUUID();
  const inputJSON = JSON.stringify(input);
  const inputBytes = encoder.encode(inputJSON);
  const sealedInput = JSON.parse(inputJSON);
  const digestBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', inputBytes));
  inputBytes.fill(0);
  const bodySha256 = Array.from(digestBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  await updateState(db, state => {
    const device = state.device;
    const nextDevice = reserveClientRequest(device, (sequence, responseSequence) => {
      const binding = { hubID: state.pin.hubId, ownerID: device.ownerId, deviceID: device.deviceId,
        sessionEpoch: device.sessionEpoch, hubKeyVersion: state.pin.keyVersion,
        deviceKeyVersion: device.deviceKeyVersion };
      const route = { version: 1, direction: 'REQUEST', hub_id: binding.hubID,
        owner_id: binding.ownerID, device_id: binding.deviceID, session_epoch: binding.sessionEpoch,
        sequence, operation_id: operationId, operation,
        sender_key_id: device.deviceKeyId, sender_key_version: device.deviceKeyVersion,
        receiver_key_id: state.pin.keyId, receiver_key_version: state.pin.keyVersion };
      const sealed = cryptoApi.sealRequest({ handle: identity.handle,
        peer_public_identity: state.pin.controlPublicIdentity, binding, route, plaintext: sealedInput });
      if (!sealed?.ok || typeof sealed.packet !== 'string') throw new Error(sealed?.error || 'Client Wire request could not be sealed.');
      const pending = { packet: sealed.packet, operationId, operation, requestSequence: sequence,
        responseSequence, createdAt: new Date().toISOString(),
        writeFence: makeSemanticWriteFence(operation, operationId, bodySha256, sealedInput, new Date().toISOString()) };
      reserved = { ...pending, binding, route };
      return pending;
    }, operation);
    return { ...state, device: nextDevice };
  });
  return reserved;
}

function openPacketBase64(packet) {
  const binary = atob(packet);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function readResponse(db, cryptoApi, identity, pending, body) {
  const state = await getState(db);
  const device = state.device;
  if (!device?.pending || device.pending.packet !== pending.packet || device.pending.operationId !== pending.operationId) {
    throw new Error('The stored pending operation changed in another browser tab.');
  }
  const binding = { hubID: state.pin.hubId, ownerID: device.ownerId, deviceID: device.deviceId,
    sessionEpoch: device.sessionEpoch, hubKeyVersion: state.pin.keyVersion,
    deviceKeyVersion: device.deviceKeyVersion };
  const packetBase64 = toBase64(body);
  const opened = cryptoApi.openResponse({ handle: identity.handle,
    peer_public_identity: state.pin.controlPublicIdentity, binding,
    route: { sequence: pending.requestSequence }, packet: packetBase64,
    expected_operation_id: pending.operationId, expected_operation: pending.operation,
    expected_response_sequence: pending.responseSequence });
  if (!opened?.ok) throw new Error(opened?.error || 'Encrypted Hub response could not be verified.');
  let payload;
  try { payload = JSON.parse(opened.plaintext); } catch { throw new Error('Authenticated Hub response was not valid JSON.'); }
  if (payload.operation_id !== pending.operationId || typeof payload.request_id !== 'string' ||
      !payload.request_id || typeof payload.ok !== 'boolean') {
    throw new Error('Authenticated Hub response did not match the saved operation.');
  }
  let resolvedPending = pending;
  if (payload.error_code === 'OUTCOME_UNCERTAIN' && !pending.writeFence && isSemanticWriteOperation(pending.operation)) {
    const sealedPacket = openPacketBase64(pending.packet);
    const packetDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', sealedPacket));
    sealedPacket.fill(0);
    const packetSha256 = Array.from(packetDigest, byte => byte.toString(16).padStart(2, '0')).join('');
    resolvedPending = { ...pending, writeFence: recoveredWriteFence(pending, packetSha256) };
  }
  await updateState(db, current => {
    return { ...current, device: completeClientRequest(current.device, resolvedPending, pending.responseSequence,
      { errorCode: payload.error_code, resolvedAt: new Date().toISOString() }) };
  });
  return payload;
}

export async function callRPC(db, cryptoApi, identity, operation, input) {
  const pending = await createSealedRequest(db, cryptoApi, identity, operation, input);
  const response = await fetch('/v2/client/rpc', { method: 'POST', cache: 'no-store', credentials: 'omit',
    headers: { 'Content-Type': 'application/json' }, body: openPacketBase64(pending.packet) });
  if (response.status !== 200) throw new Error(`Encrypted Client RPC returned HTTP ${response.status}. The exact request is retained; recover it before sending any other operation.`);
  return readResponse(db, cryptoApi, identity, pending, await response.arrayBuffer());
}

export async function recoverPending(db, cryptoApi, identity) {
  const state = await getState(db);
  const pending = state.device?.pending;
  if (!pending) return null;
  const response = await fetch('/v2/client/rpc/recover', { method: 'POST', cache: 'no-store', credentials: 'omit',
    headers: { 'Content-Type': 'application/json' }, body: openPacketBase64(pending.packet) });
  if (response.status !== 200) throw new Error(`Recovery returned HTTP ${response.status}. The exact sealed request is still pending; no replacement request was sent.`);
  return readResponse(db, cryptoApi, identity, pending, await response.arrayBuffer());
}

export async function authorizeNewWriteAfterReview(db, operationID) {
  await updateState(db, state => authorizeWriteFenceState(state, operationID, new Date().toISOString()));
}
