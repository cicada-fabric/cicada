import { authorizeWriteFenceState, completeClientRequest, makeSemanticWriteFence,
  isSemanticWriteOperation, recoveredWriteFence, reserveClientRequest, saveEnrollmentState } from './panel-model.js';

const DB_NAME = 'cicada-hub-web-panel-v1';
const DB_VERSION = 1;
const STATE_KEY = 'owner-session';
const encoder = new TextEncoder();
const accountVaultFormat = 'cicada.owner-account-device-vault.v1';

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

function accountVaultAAD(origin, hubId, accountId, deviceId, publicIdentity, allowLoopbackHTTP) {
  if (typeof origin !== 'string' || !origin || typeof hubId !== 'string' || !hubId ||
      typeof accountId !== 'string' || !accountId || typeof deviceId !== 'string' || !deviceId ||
      typeof allowLoopbackHTTP !== 'boolean' ||
      !publicIdentity || Object.keys(publicIdentity).sort().join(',') !== 'id,kem_public,signing_public' ||
      typeof publicIdentity.id !== 'string' || !publicIdentity.id ||
      typeof publicIdentity.kem_public !== 'string' || typeof publicIdentity.signing_public !== 'string') {
    throw new Error('Account device vault binding is invalid.');
  }
  const parsed = new URL(origin);
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
  if (parsed.origin !== origin || (parsed.protocol !== 'https:' && !(allowLoopbackHTTP && loopback))) {
    throw new Error('Account device vault requires a canonical secure Hub origin.');
  }
  return encoder.encode(`${accountVaultFormat}\n${origin}\n${hubId}\n${accountId}\n${deviceId}\n${allowLoopbackHTTP}\n${publicIdentity.id}\n${publicIdentity.kem_public}\n${publicIdentity.signing_public}`);
}

function accountVaultBytes(value, name) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Account device vault ${name} encoding is invalid.`);
  }
  const binary = atob(value);
  if (btoa(binary) !== value) throw new Error(`Account device vault ${name} encoding is invalid.`);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function sameDevicePublicIdentity(left, right) {
  return Boolean(left && right && Object.keys(left).sort().join(',') === 'id,kem_public,signing_public' &&
    Object.keys(right).sort().join(',') === 'id,kem_public,signing_public' &&
    left.id === right.id && left.kem_public === right.kem_public && left.signing_public === right.signing_public);
}

// The new Owner-account login device is protected independently from the
// account password. IndexedDB stores a non-extractable random AES key beside
// the authenticated ciphertext; this is browser-profile protection, not a
// hardware-backed secret or a password-derived vault.
export async function encryptAccountDeviceIdentity(identityBlob, origin, hubId, accountId, deviceId,
  publicIdentity, allowLoopbackHTTP = false) {
  if (typeof identityBlob !== 'string' || !identityBlob || identityBlob.length > 64 * 1024) {
    throw new Error('Generated account device identity is invalid.');
  }
  const additionalData = accountVaultAAD(origin, hubId, accountId, deviceId, publicIdentity, allowLoopbackHTTP);
  const wrappingKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(identityBlob);
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 }, wrappingKey, plaintext);
    return { format: accountVaultFormat, origin, hubId, accountId, deviceId, publicIdentity, allowLoopbackHTTP,
      wrappingKey, iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
  } finally {
    plaintext.fill(0);
  }
}

export async function decryptAccountDeviceIdentity(vault, origin, hubId, accountId, deviceId,
  expectedPublicIdentity, allowLoopbackHTTP = false) {
  const fields = ['format', 'origin', 'hubId', 'accountId', 'deviceId', 'publicIdentity', 'allowLoopbackHTTP',
    'wrappingKey', 'iv', 'ciphertext'];
  if (!vault || typeof vault !== 'object' || Object.keys(vault).sort().join(',') !== [...fields].sort().join(',') ||
      vault.format !== accountVaultFormat || vault.origin !== origin || vault.hubId !== hubId ||
      vault.accountId !== accountId || vault.deviceId !== deviceId ||
      vault.allowLoopbackHTTP !== allowLoopbackHTTP ||
      !sameDevicePublicIdentity(vault.publicIdentity, expectedPublicIdentity) ||
      vault.wrappingKey?.type !== 'secret' || vault.wrappingKey?.extractable !== false ||
      vault.wrappingKey?.algorithm?.name !== 'AES-GCM' || vault.wrappingKey?.algorithm?.length !== 256 ||
      !vault.wrappingKey.usages?.includes('decrypt') || !vault.wrappingKey.usages?.includes('encrypt')) {
    throw new Error('Saved Owner-account device vault does not match this pinned Hub and device.');
  }
  const additionalData = accountVaultAAD(origin, hubId, accountId, deviceId, expectedPublicIdentity, allowLoopbackHTTP);
  const iv = accountVaultBytes(vault.iv, 'nonce');
  const ciphertext = accountVaultBytes(vault.ciphertext, 'ciphertext');
  if (iv.byteLength !== 12 || ciphertext.byteLength < 16 || ciphertext.byteLength > 64 * 1024) {
    throw new Error('Saved Owner-account device vault is malformed.');
  }
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 },
      vault.wrappingKey, ciphertext));
    const value = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    if (!value || value.length > 64 * 1024) throw new Error('invalid identity');
    return value;
  } catch {
    throw new Error('Owner-account device vault could not be authenticated or opened.');
  } finally {
    plaintext?.fill(0);
    iv.fill(0);
    ciphertext.fill(0);
    additionalData.fill(0);
  }
}

function accountProfileMatches(left, right) {
  return Boolean(left && right && left.origin === right.origin && left.hubId === right.hubId &&
    left.accountId === right.accountId && left.ownerId === right.ownerId && left.deviceId === right.deviceId &&
    left.allowLoopbackHTTP === right.allowLoopbackHTTP &&
    left.publicIdentity?.id === right.publicIdentity?.id &&
    left.publicIdentity?.kem_public === right.publicIdentity?.kem_public &&
    left.publicIdentity?.signing_public === right.publicIdentity?.signing_public);
}

function validAccountPending(pending) {
  if (pending === null) return true;
  if (pending && typeof pending === 'object' && !Array.isArray(pending) &&
      pending.phase === 'CLAIM_CARD_REQUIRED') return Object.keys(pending).length === 1;
  const maxPacketBase64Length = 4 * Math.ceil((384 * 1024) / 3);
  const validPacket = value => typeof value === 'string' && value.length > 0 &&
    value.length <= maxPacketBase64Length &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
  if (!pending || typeof pending !== 'object' || Array.isArray(pending) ||
      !['CLAIM_PREPARE_PENDING', 'CLAIM_CHALLENGE_SAVED', 'CLAIM_COMPLETE_PENDING',
        'LOGIN_PREPARE_PENDING', 'LOGIN_CHALLENGE_SAVED', 'LOGIN_COMPLETE_PENDING', 'LOGOUT_PENDING'].includes(pending.phase) ||
      !validPacket(pending.packet)) return false;
  const allowed = new Set(['phase', 'packet', 'responsePacket', 'preparePacket', 'challengePacket',
    'ownerPublicIdentity', 'ownerFingerprint', 'accountEpoch', 'deviceEpoch']);
  if (Object.keys(pending).some(key => !allowed.has(key))) return false;
  for (const key of ['responsePacket', 'preparePacket', 'challengePacket']) {
    if (pending[key] !== undefined && !validPacket(pending[key])) return false;
  }
  if ((pending.phase === 'CLAIM_CHALLENGE_SAVED' || pending.phase === 'LOGIN_CHALLENGE_SAVED') &&
      (!validPacket(pending.responsePacket) || pending.preparePacket !== undefined || pending.challengePacket !== undefined)) return false;
  if (pending.phase === 'CLAIM_PREPARE_PENDING' || pending.phase === 'LOGIN_PREPARE_PENDING') {
    if (pending.responsePacket !== undefined || pending.preparePacket !== undefined || pending.challengePacket !== undefined) return false;
  }
  if (pending.phase === 'CLAIM_COMPLETE_PENDING' || pending.phase === 'LOGIN_COMPLETE_PENDING') {
    if (!validPacket(pending.preparePacket) || !validPacket(pending.challengePacket)) return false;
  }
  if (pending.phase === 'CLAIM_COMPLETE_PENDING' &&
      (!pending.ownerPublicIdentity || typeof pending.ownerFingerprint !== 'string')) return false;
  if (pending.phase === 'LOGOUT_PENDING' &&
      (!Number.isSafeInteger(pending.accountEpoch) || pending.accountEpoch < 1 ||
       !Number.isSafeInteger(pending.deviceEpoch) || pending.deviceEpoch < 1 ||
       pending.preparePacket !== undefined || pending.challengePacket !== undefined ||
       pending.ownerPublicIdentity !== undefined || pending.ownerFingerprint !== undefined)) return false;
  if (pending.phase !== 'LOGOUT_PENDING' && (pending.accountEpoch !== undefined || pending.deviceEpoch !== undefined)) return false;
  if (pending.ownerPublicIdentity !== undefined &&
      (pending.phase !== 'CLAIM_COMPLETE_PENDING' || !sameDevicePublicIdentity(pending.ownerPublicIdentity, pending.ownerPublicIdentity) ||
       typeof pending.ownerFingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(pending.ownerFingerprint))) return false;
  if (pending.phase !== 'CLAIM_COMPLETE_PENDING' &&
      (pending.ownerPublicIdentity !== undefined || pending.ownerFingerprint !== undefined)) return false;
  if (pending.ownerFingerprint !== undefined && pending.ownerPublicIdentity === undefined) return false;
  return true;
}

// The account flow persists only public profile metadata, the encrypted local
// device vault, and exact encrypted protocol packets/responses. The claim card,
// account password, plaintext challenges, and session token are excluded.
export async function saveOwnerAccountFlow(db, profile, pending, vault = null) {
  return saveOwnerAccountFlowChecked(db, profile, pending, vault, false, undefined);
}

// Compare-and-save is used for every asynchronous Owner-account transition.
// IndexedDB serializes the read/compare/write transaction, so a stale tab or
// late HTTP callback cannot replace a newer exact packet or accepted receipt.
export async function compareAndSaveOwnerAccountFlow(db, profile, expectedPending, pending, vault = null) {
  return saveOwnerAccountFlowChecked(db, profile, pending, vault, true, expectedPending);
}

function samePendingSnapshot(left, right) {
  if (left == null || right == null) return left == null && right == null;
  if (typeof left !== 'object' || typeof right !== 'object' || Array.isArray(left) || Array.isArray(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length || leftKeys.some((key, index) => key !== rightKeys[index])) return false;
  return leftKeys.every(key => key === 'ownerPublicIdentity' ?
    sameDevicePublicIdentity(left[key], right[key]) : left[key] === right[key]);
}

// Hold an origin-scoped Web Lock until the caller releases it. The callback
// always requests ifAvailable: contention or unsupported browsers fail closed
// rather than queuing a second account mutation behind a stale page.
export async function acquireOwnerAccountLock(lockManager, origin) {
  if (!lockManager || typeof lockManager.request !== 'function' || typeof origin !== 'string' || !origin) return null;
  let signalAcquired;
  const acquired = new Promise(resolve => { signalAcquired = resolve; });
  let releaseHold;
  const hold = new Promise(resolve => { releaseHold = resolve; });
  let gotLock = false;
  let released = false;
  try {
    const request = lockManager.request(`cicada-owner-account:${origin}`, { mode: 'exclusive', ifAvailable: true }, async lock => {
      if (!lock) {
        signalAcquired(false);
        return;
      }
      gotLock = true;
      signalAcquired(true);
      await hold;
    });
    Promise.resolve(request).catch(() => {
      if (!gotLock) signalAcquired(false);
    });
  } catch {
    signalAcquired(false);
  }
  if (!await acquired) return null;
  return { release() {
    if (released) return;
    released = true;
    releaseHold();
  } };
}

async function saveOwnerAccountFlowChecked(db, profile, pending, vault, compare, expectedPending) {
  const profileFields = ['origin', 'hubId', 'accountId', 'ownerId', 'deviceId', 'username', 'publicIdentity',
    'allowLoopbackHTTP', 'ownerPublicIdentity', 'ownerFingerprint'];
  if (!profile || typeof profile !== 'object' || Array.isArray(profile) ||
      Object.keys(profile).some(key => !profileFields.includes(key)) || !profile.origin || !profile.hubId ||
      !profile.accountId || !profile.ownerId || !profile.deviceId || typeof profile.username !== 'string' ||
      profile.username.length > 128 || typeof profile.allowLoopbackHTTP !== 'boolean' ||
      !sameDevicePublicIdentity(profile.publicIdentity, profile.publicIdentity) ||
      (profile.ownerPublicIdentity != null && !sameDevicePublicIdentity(profile.ownerPublicIdentity, profile.ownerPublicIdentity)) ||
      (profile.ownerFingerprint !== undefined && profile.ownerFingerprint !== '' && !/^[0-9a-f]{64}$/.test(profile.ownerFingerprint)) ||
      !validAccountPending(pending)) {
    throw new Error('Owner account state is invalid.');
  }
  const storedProfile = { origin: profile.origin, hubId: profile.hubId, accountId: profile.accountId,
    ownerId: profile.ownerId, deviceId: profile.deviceId, username: profile.username,
    publicIdentity: profile.publicIdentity, allowLoopbackHTTP: profile.allowLoopbackHTTP,
    ownerPublicIdentity: profile.ownerPublicIdentity || null, ownerFingerprint: profile.ownerFingerprint || '' };
  await updateState(db, state => {
    const pin = state.pin;
    if (!pin || pin.origin !== storedProfile.origin || pin.hubId !== storedProfile.hubId) {
      throw new Error('Owner account state does not match the pinned Hub.');
    }
    const current = state.ownerAccount;
    if (compare && !samePendingSnapshot(current?.pending ?? null, expectedPending)) {
      throw new Error('OWNER_ACCOUNT_STALE_PENDING');
    }
    if (current?.profile?.ownerPublicIdentity && !storedProfile.ownerPublicIdentity) {
      storedProfile.ownerPublicIdentity = current.profile.ownerPublicIdentity;
      storedProfile.ownerFingerprint = current.profile.ownerFingerprint;
    }
    if (current && (!accountProfileMatches(current.profile, storedProfile) ||
        (current.profile.ownerPublicIdentity && !sameDevicePublicIdentity(current.profile.ownerPublicIdentity, storedProfile.ownerPublicIdentity)) ||
        (current.profile.ownerFingerprint && current.profile.ownerFingerprint !== storedProfile.ownerFingerprint))) {
      throw new Error('This browser already has a different Owner account profile.');
    }
    let accountVault = state.accountLoginVault;
    if (vault) {
      if (vault.format !== accountVaultFormat || vault.origin !== storedProfile.origin || vault.hubId !== storedProfile.hubId ||
          vault.accountId !== storedProfile.accountId || vault.deviceId !== storedProfile.deviceId ||
          vault.allowLoopbackHTTP !== storedProfile.allowLoopbackHTTP ||
          !sameDevicePublicIdentity(vault.publicIdentity, storedProfile.publicIdentity)) {
        throw new Error('Encrypted account device key does not match the Owner account profile.');
      }
      if (accountVault && (accountVault.origin !== vault.origin || accountVault.hubId !== vault.hubId ||
          accountVault.allowLoopbackHTTP !== vault.allowLoopbackHTTP ||
          accountVault.accountId !== vault.accountId || accountVault.deviceId !== vault.deviceId ||
          !sameDevicePublicIdentity(accountVault.publicIdentity, vault.publicIdentity) || accountVault.ciphertext !== vault.ciphertext)) {
        throw new Error('This browser already has a different Owner account login device.');
      }
      accountVault = accountVault || vault;
    }
    if (!accountVault || accountVault.origin !== storedProfile.origin || accountVault.hubId !== storedProfile.hubId ||
        accountVault.allowLoopbackHTTP !== storedProfile.allowLoopbackHTTP ||
        accountVault.accountId !== storedProfile.accountId || accountVault.deviceId !== storedProfile.deviceId ||
        !sameDevicePublicIdentity(accountVault.publicIdentity, storedProfile.publicIdentity)) {
      throw new Error('The encrypted Owner account device key is missing or does not match.');
    }
    return { ...state, accountLoginVault: accountVault, ownerAccount: { profile: storedProfile, pending } };
  });
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
    suite: identity.suite, contract: identity.contract,
    controlPublicIdentity: identity.control_public_identity };
  await updateState(db, current => {
    const saved = current.pin;
    if (saved && (saved.origin !== pin.origin || saved.hubId !== pin.hubId || saved.keyId !== pin.keyId ||
        saved.keyVersion !== pin.keyVersion || saved.suite !== pin.suite ||
        (saved.contract !== undefined && saved.contract !== pin.contract) ||
        saved.controlPublicIdentity?.kem_public !== pin.controlPublicIdentity?.kem_public ||
        saved.controlPublicIdentity?.signing_public !== pin.controlPublicIdentity?.signing_public)) {
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
