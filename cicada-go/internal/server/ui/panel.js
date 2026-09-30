import { CanvasPanel } from './panel-canvas.js';
import { fetchAndValidateHubIdentity, loadCryptoWasm } from './panel-bootstrap.js';
import { createDeviceDraftState, pinMatches } from './panel-model.js';
import { callRPC, decryptIdentityBlob, downloadJSON, encryptIdentityBlob, enrollmentManifest,
  authorizeNewWriteAfterReview, enrollExactRequest, getState, openPanelDB,
  recoverPending, savePinnedHub, updateState } from './panel-client.js';

const app = document.querySelector('#app');
const identityLine = document.querySelector('#identity-line');
const wireState = document.querySelector('#wire-state');
let db;
let hubIdentity;
let cryptoApi;
let deviceIdentity;
let deviceDraft;
let canvas;

function node(tag, className = '', text = '') {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== '') value.textContent = String(text);
  return value;
}

function field(labelText, id, type = 'text', value = '') {
  const wrap = node('div', 'field');
  const label = node('label', '', labelText);
  label.htmlFor = id;
  const input = node('input');
  input.id = id;
  input.name = id;
  input.type = type;
  input.autocomplete = type === 'password' ? 'new-password' : 'off';
  input.value = value;
  wrap.append(label, input);
  return { wrap, input };
}

function actionButton(text, action, kind = 'btn primary') {
  const button = node('button', kind, text);
  button.type = 'button';
  button.addEventListener('click', action);
  return button;
}

function ceremony(title, description, eyebrow = 'LOCAL TRUST SETUP') {
  app.replaceChildren();
  const section = node('section', 'ceremony card');
  section.append(node('div', 'eyebrow', eyebrow), node('h1', '', title), node('p', '', description));
  app.append(section);
  return section;
}

function notice(parent, text, kind = '') {
  const box = node('div', `notice ${kind}`, text);
  parent.append(box);
  return box;
}

function setMessage(parent, message, kind = 'danger') {
  const old = parent.querySelector('[data-message]');
  if (old) old.remove();
  if (message) {
    const box = node('div', `notice ${kind}`);
    box.dataset.message = 'true';
    box.textContent = message;
    parent.append(box);
  }
}

function base64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i += 0x8000) binary += String.fromCharCode(...view.subarray(i, i + 0x8000));
  return btoa(binary);
}

function renderPin(identity) {
  const section = ceremony('Pin this Hub independently', 'The identity below came from this connection and is untrusted. Compare both values with an independent operator source before entering them. This page will not trust a first-seen Hub automatically.');
  notice(section, `Origin: ${location.origin}\nHub ID: ${identity.hub_id}\nControl key ID: ${identity.control_public_identity.id}\nSuite: ${identity.suite}`, 'danger');
  const hubId = field('Independently verified Hub ID', 'pin-hub-id');
  const keyId = field('Independently verified Control key ID', 'pin-key-id');
  const error = node('div');
  const pin = actionButton('Pin this exact Hub identity', async () => {
    error.remove();
    if (hubId.input.value.trim() !== identity.hub_id || keyId.input.value.trim() !== identity.control_public_identity.id) {
      setMessage(section, 'The typed Hub or Control key identity does not match. No trust was saved.', 'danger');
      return;
    }
    try {
      await savePinnedHub(db, identity);
      wireState.textContent = 'Hub pinned';
      await routeAfterPin();
    } catch (failure) { setMessage(section, failure.message); }
  });
  const grid = node('div', 'grid');
  grid.append(hubId.wrap, keyId.wrap);
  section.append(grid, pin);
}

async function routeAfterPin() {
  const state = await getState(db);
  if (state.device?.active) {
    if (!deviceIdentity) renderUnlock(state);
    else await enterWorkspace();
    return;
  }
  if (state.enrollment?.body) {
    renderEnrollmentRetry(state);
    return;
  }
  if (state.deviceDraft && state.vault) {
    if (!deviceIdentity) renderUnlock(state);
    else renderGrantImport(state);
    return;
  }
  renderNewDevice();
}

function renderNewDevice() {
  const section = ceremony('Create a local browser device', 'The browser generates a PQ device identity in Go WASM. The private key is stored only as password-encrypted WebCrypto data in this browser profile. Owner approval is a separate offline step.');
  const owner = field('Owner ID', 'owner-id');
  const ownerKey = field('Owner public key ID', 'owner-key-id');
  const device = field('Device ID', 'device-id');
  const password = field('Vault password (12+ characters)', 'vault-password', 'password');
  const confirm = field('Confirm vault password', 'vault-confirm', 'password');
  const grid = node('div', 'grid');
  grid.append(owner.wrap, ownerKey.wrap, device.wrap, password.wrap, confirm.wrap);
  let generated;
  section.append(grid, notice(section, 'The Hub does not receive Owner private keys. The exported manifest contains only the browser device public identity.'), actionButton('Create key and public enrollment manifest', async () => {
    try {
      if (!owner.input.value.trim() || !ownerKey.input.value.trim() || !device.input.value.trim()) throw new Error('Owner and device identifiers are required.');
      if (password.input.value !== confirm.input.value) throw new Error('Vault password confirmation does not match.');
      generated = cryptoApi.generateIdentity({});
      if (!generated?.ok) throw new Error(generated?.error || 'PQ device identity generation failed.');
      const fingerprint = cryptoApi.fingerprint({ public_identity: generated.public_identity });
      if (!fingerprint?.ok) throw new Error(fingerprint?.error || 'Device identity fingerprint failed.');
      const vault = await encryptIdentityBlob(generated.identity_blob, password.input.value);
      generated.identity_blob = '';
      const manifest = enrollmentManifest(hubIdentity, owner.input.value.trim(), ownerKey.input.value.trim(),
        device.input.value.trim(), generated.public_identity, fingerprint.fingerprint);
      await updateState(db, state => createDeviceDraftState(state, location.origin, vault, manifest));
      deviceIdentity = { handle: generated.handle, publicIdentity: generated.public_identity };
      deviceDraft = manifest;
      downloadJSON('cicada-device-enrollment.json', manifest);
      renderGrantImport(await getState(db));
    } catch (failure) {
      if (generated?.handle && !deviceDraft) cryptoApi.forgetIdentity({ handle: generated.handle });
      if (!deviceDraft) deviceIdentity = null;
      setMessage(section, failure.message);
    }
  }));
}

function renderUnlock(state) {
  const section = ceremony('Unlock the browser device key', 'The device private identity is encrypted in IndexedDB with AES-256-GCM and a PBKDF2-SHA-256 password key. It is decrypted into Go WASM memory for this session only.');
  const password = field('Vault password', 'unlock-password', 'password');
  section.append(password.wrap);
  if (state.vault) section.append(actionButton('Unlock device key', async () => {
    try {
      const fresh = await getState(db);
      if (JSON.stringify(fresh.vault) !== JSON.stringify(state.vault) ||
          !fresh.pin || !pinMatches(fresh.pin, hubIdentity, location.origin)) {
        throw new Error('Saved device vault or Hub pin changed in another tab. Reload and verify the current state.');
      }
      let blob = await decryptIdentityBlob(fresh.vault, password.input.value);
      let imported;
      try { imported = cryptoApi.importIdentity({ identity_blob: blob }); }
      finally { blob = ''; }
      if (!imported?.ok) throw new Error(imported?.error || 'Local browser device key could not be restored.');
      const expected = fresh.device?.deviceKeyId || fresh.deviceDraft?.device_public_identity?.id;
      if (!expected || imported.public_identity.id !== expected) {
        cryptoApi.forgetIdentity({ handle: imported.handle });
        throw new Error('Restored private key does not match the saved public device identity.');
      }
      deviceIdentity = { handle: imported.handle, publicIdentity: imported.public_identity };
      if (fresh.device?.active) await enterWorkspace();
      else renderGrantImport(fresh);
    } catch (failure) { setMessage(section, failure.message); }
  }));
  if (state.vault) section.append(actionButton('Download encrypted device backup', () => downloadJSON('cicada-browser-device-vault.json', state.vault), 'btn quiet'));
}

function renderGrantImport(state) {
  const manifest = state.deviceDraft || deviceDraft;
  if (!manifest || !deviceIdentity) { renderUnlock(state); return; }
  const section = ceremony('Import the offline Owner grant', 'The command-line signer approves this exact browser public key for this pinned Hub. Import its public summary and canonical grant bytes; the Hub still performs the authoritative enrollment check.');
  section.append(notice(section, `Owner: ${manifest.owner_id}\nOwner key: ${manifest.owner_key_id}\nHub: ${manifest.hub_id}\nDevice: ${manifest.device_id}\nDevice key: ${manifest.device_public_identity.id}\nFingerprint: ${manifest.device_key_fingerprint}\nPurpose: CLIENT_CONTROL\nExpires within 24 hours`, 'good'));
  const summary = field('Signer summary JSON', 'signer-summary', 'file');
  const grant = field('Canonical Owner grant file', 'grant-file', 'file');
  summary.input.accept = '.json,application/json';
  grant.input.accept = '.json,application/json';
  section.append(summary.wrap, grant.wrap,
    notice(section, 'Run `cicada owner device-grant-sign` offline using the saved manifest and an existing 0600 Owner key. Redirect its JSON summary to a separate file. Never paste or upload the Owner private key.', 'danger'),
    actionButton('Verify grant and enroll exact request', async () => {
      try {
        if (!summary.input.files?.[0] || !grant.input.files?.[0]) throw new Error('Select both signer summary and Owner grant files.');
        const signerSummary = JSON.parse(await summary.input.files[0].text());
        const grantBytes = new Uint8Array(await grant.input.files[0].arrayBuffer());
        if (signerSummary.format !== manifest.format || signerSummary.owner_id !== manifest.owner_id ||
            signerSummary.owner_key_id !== manifest.owner_key_id || signerSummary.hub_id !== manifest.hub_id ||
            signerSummary.device_id !== manifest.device_id || signerSummary.device_key_id !== manifest.device_public_identity.id ||
            signerSummary.device_key_fingerprint !== manifest.device_key_fingerprint ||
            signerSummary.purpose !== manifest.purpose || signerSummary.owner_public_identity?.id !== manifest.owner_key_id) {
          throw new Error('Signer summary does not match this Hub, Owner, and exact device manifest.');
        }
        const validOwner = cryptoApi.validatePublicIdentity({ public_identity: signerSummary.owner_public_identity });
        if (!validOwner?.ok) throw new Error('Owner public identity failed Go PQ validation.');
        const verify = cryptoApi.verifyOwnerDeviceGrant({ owner_public_identity: signerSummary.owner_public_identity,
          device_public_identity: manifest.device_public_identity, owner_id: manifest.owner_id,
          device_id: manifest.device_id, hub_id: manifest.hub_id, grant: base64(grantBytes) });
        if (!verify?.ok) throw new Error(verify?.error || 'Owner grant signature or scope verification failed.');
        const request = { hubId: manifest.hub_id, ownerId: manifest.owner_id, ownerKeyId: manifest.owner_key_id,
          deviceId: manifest.device_id, deviceKeyId: manifest.device_public_identity.id,
          body: JSON.stringify({ owner_id: manifest.owner_id, owner_key_id: manifest.owner_key_id,
            device_id: manifest.device_id, device_public_identity: manifest.device_public_identity,
            owner_device_grant: base64(grantBytes) }) };
        await enrollExactRequest(db, request);
        await routeAfterPin();
      } catch (failure) { setMessage(section, failure.message); }
    }));
}

function renderEnrollmentRetry(state) {
  const section = ceremony('Resume the saved device enrollment', 'A previous attempt may have reached the Hub even if the browser lost its response. This uses the exact saved Owner grant and device identity request; it will not create a new key or nonce.');
  section.append(notice(section, `Owner: ${state.enrollment.ownerId}\nDevice: ${state.enrollment.deviceId}\nDevice key: ${state.enrollment.deviceKeyId}`, 'warn'),
    actionButton('Retry the exact saved enrollment request', async () => {
      try { await enrollExactRequest(db, state.enrollment); await routeAfterPin(); }
      catch (failure) { setMessage(section, failure.message); }
    }));
  if (state.vault) section.append(actionButton('Unlock device and inspect saved request', async () => renderUnlock(state), 'btn quiet'));
}

async function request(operation, input = {}) {
  const response = await callRPC(db, cryptoApi, deviceIdentity, operation, input);
  if (!response.ok) {
    const failure = new Error(response.error || 'Hub rejected the encrypted operation.');
    failure.errorCode = response.error_code || '';
    failure.operationID = response.operation_id || '';
    throw failure;
  }
  return response.result;
}

async function fetchSnapshots() {
  const snapshotStartedAt = Date.now();
  const topology = await request('topology.snapshot', {});
  const status = await request('status.snapshot', {});
  const state = await getState(db);
  return { topology, status, writeFence: state.device?.writeFence || null,
    snapshotStartedAt, snapshotCompletedAt: Date.now() };
}

async function enterWorkspace() {
  const state = await getState(db);
  if (!state.device?.active || !deviceIdentity) return renderUnlock(state);
  identityLine.textContent = `Hub ${state.pin.hubId} · Owner ${state.device.ownerId} · device ${state.device.deviceId}`;
  wireState.textContent = 'PQ Client Wire v1';
  try {
    const snapshots = await fetchSnapshots();
    const rpc = (operation, input) => request(operation, input);
    canvas = new CanvasPanel(app, { db, cryptoApi, identity: deviceIdentity,
      initialSnapshots: snapshots, rpc, refresh: fetchSnapshots,
      recover: () => recoverPending(db, cryptoApi, deviceIdentity), lock: lockDevice,
      clearWriteFence: operationID => authorizeNewWriteAfterReview(db, operationID),
      pending: renderPendingRecovery });
    canvas.mount();
  } catch (failure) {
    if (await hasPending()) renderPendingRecovery(failure.message);
    else renderWorkspaceFailure(failure.message);
  }
}

async function hasPending() {
  const state = await getState(db);
  return Boolean(state.device?.pending);
}

function renderPendingRecovery(message = '') {
  const section = ceremony('Resolve the saved Client request', 'No new operation can be sent while the prior response is unknown. Recovery submits only the exact encrypted packet already stored by this browser.');
  notice(section, 'The server may have applied the operation. A verified recovery result or a fresh authoritative snapshot is required before continuing.', 'danger');
  if (message) setMessage(section, message);
  section.append(actionButton('Recover exact pending operation', async () => {
    try {
      const response = await recoverPending(db, cryptoApi, deviceIdentity);
      if (response?.error_code === 'OUTCOME_UNCERTAIN') {
        setMessage(section, 'Hub confirmed an uncertain outcome. Inspect the refreshed authoritative state before deciding what to do next.', 'warn');
      }
      await enterWorkspace();
    } catch (failure) { setMessage(section, failure.message); }
  }));
}

function renderWorkspaceFailure(message) {
  const section = ceremony('The encrypted panel needs attention', 'No unverified topology is shown. Resolve this message and reload the authoritative snapshots before changing anything.');
  setMessage(section, message);
  section.append(actionButton('Retry authoritative snapshots', enterWorkspace));
}

async function lockDevice() {
  if (deviceIdentity?.handle) cryptoApi.forgetIdentity?.({ handle: deviceIdentity.handle });
  deviceIdentity = null;
  canvas = null;
  renderUnlock(await getState(db));
}

async function boot() {
  try {
    db = await openPanelDB();
    cryptoApi = await loadCryptoWasm();
    hubIdentity = await fetchAndValidateHubIdentity(cryptoApi);
    const state = await getState(db);
    identityLine.textContent = `Untrusted identity · ${location.origin}`;
    if (state.pin && !pinMatches(state.pin, hubIdentity, location.origin)) {
      const section = ceremony('Hub identity changed', 'This browser had pinned a different Hub or Control key for this origin. CICADA refused to replace it automatically. Verify the new identity out of band and use a separate browser profile or site-data reset after reviewing the change.');
      notice(section, `Stored Hub: ${state.pin.hubId}\nStored Control key: ${state.pin.keyId}\nObserved Hub: ${hubIdentity.hub_id}\nObserved key: ${hubIdentity.control_public_identity.id}`, 'danger');
      return;
    }
    if (!state.pin) return renderPin(hubIdentity);
    identityLine.textContent = `Pinned Hub ${hubIdentity.hub_id}`;
    wireState.textContent = 'Hub pinned';
    if (state.device?.active || state.deviceDraft || state.enrollment?.body) return routeAfterPin();
    renderNewDevice();
  } catch (failure) {
    const section = ceremony('Secure Hub panel unavailable', 'The page does not fall back to a bearer-token UI or another cryptographic implementation.');
    notice(section, failure.message, 'danger');
  }
}

boot();
