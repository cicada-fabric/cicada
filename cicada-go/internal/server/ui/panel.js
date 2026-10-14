import { CanvasPanel } from './panel-canvas.js';
import { initializeLanguageSelector, localized as t, localizedIfKnown, setLocalizedAttribute, setLocalizedText } from './panel-i18n.js';
import { fetchAndValidateHubIdentity, loadCryptoWasm, validateOwnerBootstrapPublicFiles,
  validateOwnerDeviceGrantSummary } from './panel-bootstrap.js';
import { createDeviceDraftState, pinMatches, savedPanelRoute } from './panel-model.js';
import { callRPC, decryptIdentityBlob, downloadJSON, encryptIdentityBlob, enrollmentManifest,
  authorizeNewWriteAfterReview, enrollExactRequest, getState, openPanelDB,
  recoverPending, savePinnedHub, updateState } from './panel-client.js';
import { renderOwnerAccount, restoreOwnerAccountDevice } from './panel-account.js';

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
  if (text !== '') setLocalizedText(value, text);
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
  section.append(node('div', 'eyebrow', typeof eyebrow === 'string' ? t(eyebrow) : eyebrow), node('h1', '', title), node('p', '', description));
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
    const text = message?.panelText || (message instanceof Error ? localizedIfKnown(message.message) : localizedIfKnown(message));
    setLocalizedText(box, text);
    parent.append(box);
  }
}

function localError(key, values = {}) {
  const failure = new Error(t(key, values).key);
  failure.panelText = t(key, values);
  return failure;
}

function configureLanguage() {
  setLocalizedText(identityLine, t('Connecting to this Hub…'));
  setLocalizedText(wireState, t('Unverified'));
  setLocalizedAttribute(wireState, 'aria-label', t('Connection status'));
  setLocalizedText(document.querySelector('#panel-language-label'), t('Language'));
  setLocalizedText(document.querySelector('#boot-title'), t('Loading secure panel'));
  setLocalizedText(document.querySelector('#boot-message'), t('Checking the local WebCrypto build…'));
  initializeLanguageSelector(document.querySelector('#panel-language'));
}

function base64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i += 0x8000) binary += String.fromCharCode(...view.subarray(i, i + 0x8000));
  return btoa(binary);
}

function renderPin(identity, onPinned = () => routeAfterPin()) {
  const section = ceremony(t('Pin this Hub independently'), t('The identity below came from this connection and is untrusted. Compare both values with an independent operator source before entering them. This page will not trust a first-seen Hub automatically.'));
  notice(section, t('Origin: {origin}\nHub ID: {hubId}\nHub identity key ID: {keyId}\nSuite: {suite}', {
    origin: location.origin, hubId: identity.hub_id, keyId: identity.control_public_identity.id, suite: identity.suite
  }), 'danger');
  const hubId = field(t('Independently verified Hub ID'), 'pin-hub-id');
  const keyId = field(t('Independently verified Hub identity key ID'), 'pin-key-id');
  const error = node('div');
  const pin = actionButton(t('Pin this exact Hub identity'), async () => {
    error.remove();
    if (hubId.input.value.trim() !== identity.hub_id || keyId.input.value.trim() !== identity.control_public_identity.id) {
      setMessage(section, t('The typed Hub or Hub identity key does not match. No trust was saved.'), 'danger');
      return;
    }
    try {
      await savePinnedHub(db, identity);
      setLocalizedText(wireState, t('Hub pinned'));
      await onPinned();
    } catch (failure) { setMessage(section, failure); }
  });
  const grid = node('div', 'grid');
  grid.append(hubId.wrap, keyId.wrap);
  section.append(grid, pin);
}

async function routeAfterPin(state) {
  if (!state) state = await getState(db);
  switch (savedPanelRoute(state)) {
    case 'active-device':
      if (!deviceIdentity) renderUnlock(state);
      else await enterWorkspace();
      return;
    case 'pending-enrollment':
      renderEnrollmentRetry(state);
      return;
    case 'device-draft':
      if (!deviceIdentity) renderUnlock(state);
      else renderGrantImport(state);
      return;
    default:
      await renderOwnerAccountEntry();
  }
}

async function readPublicJSONFile(file, label) {
  if (!file || file.size > 64 * 1024) throw localError('{label} must be a selected JSON file no larger than 64 KiB.', { label: t(label) });
  try { return JSON.parse(await file.text()); }
  catch { throw localError('{label} is not valid JSON.', { label: t(label) }); }
}

function renderOwnerAccountEntry(pinAlreadySaved = true) {
  const onAdvanced = pinAlreadySaved ? renderOwnerBootstrapGuide :
    () => renderPin(hubIdentity, renderOwnerBootstrapGuide);
  return renderOwnerAccount(app, { db, hubIdentity, cryptoApi, onAdvanced });
}

function renderOwnerBootstrapGuide() {
  const section = ceremony(t('Advanced Owner signer and browser Client setup'),
    t('This technical path does not claim a Hub installation or set Owner login credentials. Its browser-device form creates a Client device key for separate Owner-authorized enrollment.'),
    t('ADVANCED OWNER SIGNER · TECHNICAL FLOW'));
  notice(section,
    t('Hub setup and Owner signer setup are separate. A public key alone is not approval: the Hub operator must issue one finite pairing locally, then the Owner signer must prove possession of both private-key operations. This page does not contact an issuer or read live Root status.'),
    'danger');

  const steps = node('ol', 'owner-bootstrap-steps');
  for (const step of [
    t('A local Hub operator runs `cicada hub setup` to create the stable account-to-human-Owner mapping and exports the public Hub connection file.'),
    t('The Owner configures the local signer with the existing encrypted key files and exports its public manifest. Never select a private-key file or enter a passphrase in this page.'),
    t('The Hub operator compares the complete candidate fingerprint and runs `cicada hub owner-bootstrap-issue` locally with its interactive approval.'),
    t('The Owner imports the finite pairing into the local signer and runs its bootstrap or exact recovery flow. The signer verifies the Hub receipt.'),
    t('Only afterward, use the existing Owner-signed Client grant to enroll this browser. Node INITIAL enrollment is a separate later flow.')
  ]) steps.append(node('li', '', step));
  section.append(steps,
    notice(section, t('The Hub can be configured (`HUB_READY`) while still needing its first Owner signer (`NEEDS_OWNER_SIGNER`). This page cannot determine or report either live state. A valid public-file draft is not proof of issuance, possession, registration, or manager access.'), 'warn'));

  const connection = field(t('Independent public Hub connection file'), 'owner-connection-file', 'file');
  const candidate = field(t('Local Owner signer public manifest'), 'owner-public-manifest-file', 'file');
  connection.input.accept = '.json,application/json';
  candidate.input.accept = '.json,application/json';
  const result = node('div');
  let validatedCandidate = null;
  let validatedSummary = null;
  const clearResult = () => {
    validatedCandidate = null;
    validatedSummary = null;
    result.replaceChildren();
  };
  connection.input.addEventListener('change', clearResult);
  candidate.input.addEventListener('change', clearResult);
  const verify = actionButton(t('Check public files and full fingerprint'), async () => {
    clearResult();
    try {
      const selectedConnection = connection.input.files?.[0];
      const selectedCandidate = candidate.input.files?.[0];
      const [connectionFile, manifest] = await Promise.all([
        readPublicJSONFile(selectedConnection, 'Hub connection file'),
        readPublicJSONFile(selectedCandidate, 'Owner public manifest')
      ]);
      if (connection.input.files?.[0] !== selectedConnection || candidate.input.files?.[0] !== selectedCandidate) {
        throw localError('A selected file changed while it was being checked. Select both public files again.');
      }
      validatedSummary = validateOwnerBootstrapPublicFiles(connectionFile, manifest,
        location.origin, hubIdentity, cryptoApi);
      validatedCandidate = manifest;
      const checkedSummary = validatedSummary;
      const checkedCandidate = validatedCandidate;
      result.append(notice(result,
        t('Public-file draft only — no Owner state was changed.\nAccount: {accountID}\nOwner: {ownerID}\nHub: {hubID}\nOwner public key: {ownerKeyID}\nOrigin: {origin}\nFull candidate fingerprint: {fingerprint}\n\nThe local Hub operator must still issue finite authority; the local Owner signer must complete proof and verify its receipt.', checkedSummary),
        'good'));
      result.append(actionButton(t('Download this validated public candidate'), () =>
        downloadJSON('owner-public.json', checkedCandidate), 'btn quiet'));
      result.append(actionButton(t('Continue to advanced browser Client device enrollment'), () =>
        renderNewDevice({ ownerId: checkedSummary.ownerID, ownerKeyId: checkedSummary.ownerKeyID })));
    } catch (failure) {
      result.append(notice(result, failure?.panelText || localizedIfKnown(failure.message || 'Public files could not be checked.'), 'danger'));
    }
  });
  section.append(connection.wrap, candidate.wrap,
    notice(section, t('Choose public JSON files only. The checker accepts only the documented connection and signer-manifest fields; it rejects unknown fields, including private-key, seed, credential, and secret fields. Files are read into page memory for comparison only: they are not sent to the Hub or saved in browser storage.'), 'danger'),
    verify, result,
    actionButton(t('Open advanced browser Client device enrollment'), () => renderNewDevice(), 'btn quiet'));
}

function renderNewDevice(ownerDefaults = {}) {
  const section = ceremony(t('Create an advanced browser Client device'), t('This form creates only a browser Client device key. The private key is stored as password-encrypted WebCrypto data in this browser profile; the vault password is not an Owner login password. Owner approval remains a separate step.'));
  const owner = field(t('Owner ID'), 'owner-id', 'text', ownerDefaults.ownerId || '');
  const ownerKey = field(t('Owner public key ID'), 'owner-key-id', 'text', ownerDefaults.ownerKeyId || '');
  const device = field(t('Device ID'), 'device-id');
  const password = field(t('Vault password (12+ characters)'), 'vault-password', 'password');
  const confirm = field(t('Confirm vault password'), 'vault-confirm', 'password');
  const grid = node('div', 'grid');
  grid.append(owner.wrap, ownerKey.wrap, device.wrap, password.wrap, confirm.wrap);
  let generated;
  section.append(grid, notice(section, t('This device-enrollment form does not create an Owner account. The Hub does not receive Owner private keys; the exported manifest contains only this browser Client device public identity.')), actionButton(t('Create Client device key and public enrollment manifest'), async () => {
    try {
      if (!owner.input.value.trim() || !ownerKey.input.value.trim() || !device.input.value.trim()) throw localError('Owner and device identifiers are required.');
      if (password.input.value !== confirm.input.value) throw localError('Vault password confirmation does not match.');
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
      setMessage(section, failure);
    }
  }));
}

function renderUnlock(state) {
  const section = ceremony(t('Unlock the browser device key'), t('The device private identity is encrypted in IndexedDB with AES-256-GCM and a PBKDF2-SHA-256 password key. It is decrypted into Go WASM memory for this session only.'));
  const password = field(t('Vault password'), 'unlock-password', 'password');
  section.append(password.wrap);
  if (state.vault) section.append(actionButton(t('Unlock device key'), async () => {
    try {
      const fresh = await getState(db);
      if (JSON.stringify(fresh.vault) !== JSON.stringify(state.vault) ||
          !fresh.pin || !pinMatches(fresh.pin, hubIdentity, location.origin)) {
        throw localError('Saved device vault or Hub pin changed in another tab. Reload and verify the current state.');
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
    } catch (failure) { setMessage(section, failure); }
  }));
  if (state.vault) section.append(actionButton(t('Download encrypted device backup'), () => downloadJSON('cicada-browser-device-vault.json', state.vault), 'btn quiet'));
}

function renderGrantImport(state) {
  const manifest = state.deviceDraft || deviceDraft;
  if (!manifest || !deviceIdentity) { renderUnlock(state); return; }
  const section = ceremony(t('Import the offline Owner grant'), t('The command-line signer approves this exact browser public key for this pinned Hub. Import its public summary and canonical grant bytes; the Hub still performs the authoritative enrollment check.'));
  section.append(notice(section, t('Owner: {ownerID}\nOwner key: {ownerKeyID}\nHub: {hubID}\nDevice: {deviceID}\nDevice key: {deviceKeyID}\nFingerprint: {fingerprint}\nPurpose: CLIENT_CONTROL\nExpires within 24 hours', {
    ownerID: manifest.owner_id, ownerKeyID: manifest.owner_key_id, hubID: manifest.hub_id,
    deviceID: manifest.device_id, deviceKeyID: manifest.device_public_identity.id, fingerprint: manifest.device_key_fingerprint
  }), 'good'));
  const summary = field(t('Signer summary JSON'), 'signer-summary', 'file');
  const grant = field(t('Canonical Owner grant file'), 'grant-file', 'file');
  summary.input.accept = '.json,application/json';
  grant.input.accept = '.json,application/json';
  section.append(summary.wrap, grant.wrap,
    notice(section, t('After the local Owner signer has authenticated its bootstrap receipt, run `cicada owner-signer grant --profile DIR --manifest-file cicada-device-enrollment.json --expires-at UTC_RFC3339Nano --output owner-device-grant.json --summary-output owner-device-grant-summary.json` on that signer machine. Review in the terminal; the command writes a separate public summary file. Import that summary and the grant here. Never paste, upload, or select an Owner private key or passphrase.'), 'danger'),
    actionButton(t('Verify grant and enroll exact request'), async () => {
      try {
        const summaryFile = summary.input.files?.[0];
        const grantFile = grant.input.files?.[0];
        if (!summaryFile || !grantFile) throw localError('Select both signer summary and Owner grant files.');
        if (summaryFile.size > 64 * 1024 || grantFile.size > 64 * 1024) {
          throw localError('Signer summary and Owner grant files must each be no larger than 64 KiB.');
        }
        const signerSummary = JSON.parse(await summaryFile.text());
        const grantBytes = new Uint8Array(await grantFile.arrayBuffer());
        const ownerPublicIdentity = validateOwnerDeviceGrantSummary(signerSummary, manifest, cryptoApi);
        const verify = cryptoApi.verifyOwnerDeviceGrant({ owner_public_identity: ownerPublicIdentity,
          device_public_identity: manifest.device_public_identity, owner_id: manifest.owner_id,
          device_id: manifest.device_id, hub_id: manifest.hub_id, grant: base64(grantBytes) });
        if (!verify?.ok) throw new Error(verify?.error || 'Owner grant signature or scope verification failed.');
        if (verify.expires_at !== signerSummary.expires_at) {
          throw localError('Signer summary expiry does not match the authenticated Owner grant.');
        }
        const request = { hubId: manifest.hub_id, ownerId: manifest.owner_id, ownerKeyId: manifest.owner_key_id,
          deviceId: manifest.device_id, deviceKeyId: manifest.device_public_identity.id,
          body: JSON.stringify({ owner_id: manifest.owner_id, owner_key_id: manifest.owner_key_id,
            device_id: manifest.device_id, device_public_identity: manifest.device_public_identity,
            owner_device_grant: base64(grantBytes) }) };
        await enrollExactRequest(db, request);
        await routeAfterPin();
      } catch (failure) { setMessage(section, failure); }
    }));
}

function renderEnrollmentRetry(state) {
  const section = ceremony(t('Resume the saved device enrollment'), t('A previous attempt may have reached the Hub even if the browser lost its response. This uses the exact saved Owner grant and device identity request; it will not create a new key or nonce.'));
  section.append(notice(section, t('Owner: {ownerID}\nDevice: {deviceID}\nDevice key: {deviceKeyID}', {
    ownerID: state.enrollment.ownerId, deviceID: state.enrollment.deviceId, deviceKeyID: state.enrollment.deviceKeyId
  }), 'warn'),
    actionButton(t('Retry the exact saved enrollment request'), async () => {
      try { await enrollExactRequest(db, state.enrollment); await routeAfterPin(); }
      catch (failure) { setMessage(section, failure); }
    }));
  if (state.vault) section.append(actionButton(t('Unlock device and inspect saved request'), async () => renderUnlock(state), 'btn quiet'));
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
  setLocalizedText(identityLine, t('Hub {hub} · Owner {owner} · device {device}', {
    hub: state.pin.hubId, owner: state.device.ownerId, device: state.device.deviceId
  }));
  setLocalizedText(wireState, t('PQ Client Wire v1'));
  try {
    const snapshots = await fetchSnapshots();
    const rpc = (operation, input) => request(operation, input);
    canvas = new CanvasPanel(app, { db, cryptoApi, identity: deviceIdentity,
      initialSnapshots: snapshots, pinnedHubId: state.pin.hubId, rpc, refresh: fetchSnapshots,
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
  const section = ceremony(t('Resolve the saved Client request'), t('No new operation can be sent while the prior response is unknown. Recovery submits only the exact encrypted packet already stored by this browser.'));
  notice(section, t('The server may have applied the operation. A verified recovery result or a fresh authoritative snapshot is required before continuing.'), 'danger');
  if (message) setMessage(section, message);
  section.append(actionButton(t('Recover exact pending operation'), async () => {
    try {
      const response = await recoverPending(db, cryptoApi, deviceIdentity);
      if (response?.error_code === 'OUTCOME_UNCERTAIN') {
        setMessage(section, t('Hub confirmed an uncertain outcome. Inspect the refreshed authoritative state before deciding what to do next.'), 'warn');
      }
      await enterWorkspace();
    } catch (failure) { setMessage(section, failure); }
  }));
}

function renderWorkspaceFailure(message) {
  const section = ceremony(t('The encrypted panel needs attention'), t('No unverified topology is shown. Resolve this message and reload the authoritative snapshots before changing anything.'));
  setMessage(section, message);
  section.append(actionButton(t('Retry authoritative snapshots'), enterWorkspace));
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
    setLocalizedText(identityLine, t('Untrusted identity · {origin}', { origin: location.origin }));
    if (state.pin && !pinMatches(state.pin, hubIdentity, location.origin)) {
      const section = ceremony(t('Hub identity changed'), t('This browser had pinned a different Hub or Hub identity key for this origin. CICADA refused to replace it automatically. Verify the new identity out of band and use a separate browser profile or site-data reset after reviewing the change.'));
      notice(section, t('Stored Hub: {storedHub}\nStored Hub identity key: {storedKey}\nObserved Hub: {observedHub}\nObserved Hub identity key: {observedKey}', {
        storedHub: state.pin.hubId, storedKey: state.pin.keyId,
        observedHub: hubIdentity.hub_id, observedKey: hubIdentity.control_public_identity.id
      }), 'danger');
      return;
    }
    if (!state.pin) {
      if (state.ownerAccount?.profile) {
        throw new Error('Saved Owner account state has no matching Hub pin. The panel refused to restore it.');
      }
      if (state.device?.active || state.enrollment?.body || (state.deviceDraft && state.vault)) {
        return renderPin(hubIdentity);
      }
      // A genuinely empty profile starts with the installer claim flow. The
      // claim card is checked against the full fetched identity and exact page
      // origin, then explicitly reviewed before savePinnedHub or any request.
      return renderOwnerAccountEntry(false);
    }
    setLocalizedText(identityLine, t('Pinned Hub {hub}', { hub: hubIdentity.hub_id }));
    setLocalizedText(wireState, t('Hub pinned'));
    if (state.ownerAccount?.profile) await restoreOwnerAccountDevice(db, cryptoApi, hubIdentity);
    await routeAfterPin(state);
  } catch (failure) {
    const section = ceremony(t('Secure Hub panel unavailable'), t('The page does not fall back to a bearer-token UI or another cryptographic implementation.'));
    notice(section, failure?.panelText || localizedIfKnown(failure.message), 'danger');
  }
}

configureLanguage();
boot();
