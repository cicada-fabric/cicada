import { ownerAccountPasswordFeedback } from './panel-model.js';
import { localized as t, setLocalizedText } from './panel-i18n.js';
import { decryptAccountDeviceIdentity, encryptAccountDeviceIdentity, getState,
  acquireOwnerAccountLock, compareAndSaveOwnerAccountFlow, savePinnedHub } from './panel-client.js';
import { readOwnerPublicSPKIPem } from './panel-bootstrap.js';

const encoder = new TextEncoder();
let accountDevice;
let accountSessionHandle;
let accountSessionMetadata;
let accountLease;
let accountLeasePromise;
let accountActionRunning = false;

function node(tag, className = '', text = '') {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== '') setLocalizedText(value, text);
  return value;
}

function field(labelText, id, type = 'text', value = '', autocomplete = 'off') {
  const wrap = node('div', 'field');
  const label = node('label', '', labelText);
  label.htmlFor = id;
  const input = node('input');
  input.id = id;
  input.name = id;
  input.type = type;
  input.autocomplete = autocomplete;
  input.value = value;
  wrap.append(label, input);
  return { wrap, input };
}

function actionButton(text, action, kind = 'btn primary') {
  const button = node('button', kind, text);
  button.type = 'button';
  let running = false;
  button.addEventListener('click', async event => {
    if (accountActionRunning || running || button.disabled) return;
    accountActionRunning = true;
    running = true;
    button.disabled = true;
    try { await action?.(event); }
    finally {
      accountActionRunning = false;
      running = false;
      if (button.isConnected) button.disabled = false;
    }
  });
  return button;
}

function ceremony(app, title, description, eyebrow = 'OWNER ACCOUNT SETUP') {
  app.replaceChildren();
  const section = node('section', 'ceremony card');
  section.append(node('div', 'eyebrow', t(eyebrow)), node('h1', '', title), node('p', '', description));
  app.append(section);
  return section;
}

function notice(parent, text, kind = '') {
  const box = node('div', `notice ${kind}`, text);
  parent.append(box);
  return box;
}

function showError(parent, key = 'The account setup step did not complete. Check the information and retry the saved request.') {
  const previous = parent.querySelector('[data-account-error]');
  if (previous) previous.remove();
  const box = node('div', 'notice danger', t(key));
  box.dataset.accountError = 'true';
  parent.append(box);
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

async function postPacket(path, packetText) {
  const bytes = fromBase64(packetText);
  try {
    const response = await fetch(path, { method: 'POST', cache: 'no-store', credentials: 'omit',
      headers: { 'Content-Type': 'application/json' }, body: bytes });
    if (!response.ok) {
      const failure = new Error('request');
      failure.httpStatus = response.status;
      throw failure;
    }
    return toBase64(await response.arrayBuffer());
  } catch (failure) {
    if (Number.isInteger(failure?.httpStatus)) throw failure;
    throw new Error('request');
  } finally {
    bytes.fill(0);
  }
}

function publicProfile(profile) {
  return { origin: profile.origin, hubId: profile.hubId, accountId: profile.accountId,
    ownerId: profile.ownerId, deviceId: profile.deviceId, username: profile.username,
    publicIdentity: profile.publicIdentity, allowLoopbackHTTP: profile.allowLoopbackHTTP,
    ownerPublicIdentity: profile.ownerPublicIdentity || null, ownerFingerprint: profile.ownerFingerprint || '' };
}

async function persist(appContext, profile, pending, vault, expectedPending) {
  await compareAndSaveOwnerAccountFlow(appContext.db, publicProfile(profile), expectedPending, pending, vault);
}

async function ensureOwnerAccountLease(context) {
  if (accountLease) return true;
  if (accountLeasePromise) return accountLeasePromise;
  accountLeasePromise = acquireOwnerAccountLock(globalThis.navigator?.locks, location.origin)
    .then(lease => {
      accountLeasePromise = null;
      if (!lease) return false;
      accountLease = lease;
      return true;
    }, () => {
      accountLeasePromise = null;
      return false;
    });
  return accountLeasePromise;
}

function releaseOwnerAccountLease() {
  const lease = accountLease;
  accountLease = null;
  lease?.release();
}

async function leaveOwnerAccountForAdvanced(context) {
  releaseOwnerAccountLease();
  forgetOwnerAccountDevice(context.cryptoApi);
  return context.onAdvanced?.();
}

function isStaleAccountWrite(failure) {
  return failure?.message === 'OWNER_ACCOUNT_STALE_PENDING';
}

async function showCurrentAccountState(app, context) {
  await renderOwnerAccount(app, context);
}

function renderAccountLockBlocked(app, context) {
  forgetOwnerAccountDevice(context.cryptoApi);
  const section = ceremony(app, t('Owner account setup is locked'),
    t('Owner account setup is active in another tab, or this browser cannot provide a safe single-tab lock. Close the other tab or use a supported browser, then reload.'),
    'OWNER ACCOUNT');
  section.id = 'owner-account-lock-blocked';
  section.dataset.accountLock = 'unavailable';
  section.append(actionButton(t('Reload this page'), () => location.reload(), 'btn quiet'));
}

function accountApi(context, method, values = {}) {
  const result = context.cryptoApi[method]({ hub_identity: context.hubIdentity, ...values });
  if (!result?.ok) throw new Error('crypto');
  return result;
}

export async function restoreOwnerAccountDevice(db, cryptoApi, hubIdentity) {
  const state = await getState(db);
  const ownerAccount = state.ownerAccount;
  if (!ownerAccount?.profile) return false;
  const profile = ownerAccount.profile;
  const vault = state.accountLoginVault;
  if (!vault || profile.origin !== location.origin || profile.hubId !== hubIdentity.hub_id ||
      vault.accountId !== profile.accountId || vault.deviceId !== profile.deviceId) {
    throw new Error('Saved Owner device does not match this pinned Hub. Use the original browser profile or recover it from an approved backup.');
  }
  let identityBlob = await decryptAccountDeviceIdentity(vault, profile.origin, profile.hubId,
    profile.accountId, profile.deviceId, profile.publicIdentity, profile.allowLoopbackHTTP);
  let imported;
  try { imported = cryptoApi.importIdentity({ identity_blob: identityBlob }); }
  finally { identityBlob = ''; }
  if (!imported?.ok || imported.public_identity?.id !== profile.publicIdentity?.id ||
      imported.public_identity?.kem_public !== profile.publicIdentity?.kem_public ||
      imported.public_identity?.signing_public !== profile.publicIdentity?.signing_public) {
    if (imported?.handle) cryptoApi.forgetIdentity({ handle: imported.handle });
    throw new Error('Saved Owner device identity could not be restored. It was not regenerated.');
  }
  accountDevice = { handle: imported.handle, publicIdentity: imported.public_identity };
  return true;
}

export function forgetOwnerAccountDevice(cryptoApi) {
  if (accountDevice?.handle) cryptoApi.forgetIdentity({ handle: accountDevice.handle });
  accountDevice = null;
  if (accountSessionHandle) cryptoApi.forgetOwnerAccountSession({ session_handle: accountSessionHandle });
  accountSessionHandle = null;
  accountSessionMetadata = null;
}

export async function renderOwnerAccount(app, context) {
  if (!await ensureOwnerAccountLease(context)) {
    renderAccountLockBlocked(app, context);
    return false;
  }
  try {
    const state = await getState(context.db);
    const current = state.ownerAccount;
    if (!current?.profile) return renderClaimStart(app, context);
    const pending = current.pending;
    if (pending?.phase === 'CLAIM_CARD_REQUIRED') return renderClaimStart(app, context, current.profile);
    if (pending?.phase === 'CLAIM_PREPARE_PENDING' || pending?.phase === 'CLAIM_COMPLETE_PENDING' ||
        pending?.phase === 'LOGIN_PREPARE_PENDING' || pending?.phase === 'LOGIN_COMPLETE_PENDING' ||
        pending?.phase === 'LOGOUT_PENDING') {
      return renderPendingRecovery(app, context, current.profile, pending);
    }
    if (pending?.phase === 'CLAIM_CHALLENGE_SAVED') return renderClaimCredentials(app, context, current.profile, pending);
    if (pending?.phase === 'LOGIN_CHALLENGE_SAVED') return renderAccountLogin(app, context, current.profile, pending);
    return renderAccountLogin(app, context, current.profile, null);
  } catch {
    releaseOwnerAccountLease();
    renderAccountLockBlocked(app, context);
    return false;
  }
}

function renderClaimStart(app, context, savedProfile = null) {
  const section = ceremony(app,
    savedProfile ? t('Use a new installer claim') : t('Set up the first Owner account'),
    savedProfile ?
      t('The Hub definitely rejected the previous claim request. The same browser device key and account scope are retained. Verify a new installer claim file for this exact Hub, account and Owner before retrying.') :
      t('Use the installer-issued Hub claim file. The page checks its exact origin and complete Hub fingerprint against the Hub identity before it uses the one-time code. Owner private keys stay in their local encrypted files.'),
    'OWNER ACCOUNT · PAGE 1 OF 2');
  const cardLabel = node('label', '', t('Installer claim file or JSON'));
  cardLabel.htmlFor = 'owner-claim-card';
  const cardText = node('input', 'account-card-input');
  cardText.id = 'owner-claim-card';
  cardText.name = 'owner-claim-card';
  cardText.type = 'password';
  cardText.autocomplete = 'off';
  cardText.autocapitalize = 'off';
  cardText.spellcheck = false;
  const file = field(t('Choose claim JSON file'), 'owner-claim-file', 'file');
  file.input.accept = '.json,application/json';
  let fileReadGeneration = 0;
  const clearVerification = () => {
    verified = null;
    result.replaceChildren();
  };
  file.input.addEventListener('change', async () => {
    const generation = ++fileReadGeneration;
    clearVerification();
    const selected = file.input.files?.[0];
    if (!selected || selected.size > 16 * 1024) {
      showError(section, 'The installer claim file must be a JSON file no larger than 16 KiB.');
      file.input.value = '';
      return;
    }
    try {
      const contents = await selected.text();
      if (generation === fileReadGeneration && file.input.files?.[0] === selected) cardText.value = contents;
    }
    catch { showError(section, 'The installer claim file could not be read.'); }
  });
  cardText.addEventListener('input', clearVerification);
  const result = node('div');
  let verified = null;
  const verify = actionButton(t('Verify origin and full Hub fingerprint'), () => {
    verified = null;
    result.replaceChildren();
    const value = cardText.value.trim();
    if (!value || encoder.encode(value).byteLength > 16 * 1024) {
      showError(section, 'Paste or choose the installer claim JSON before verification.');
      return;
    }
    let checked;
    try {
      checked = accountApi(context, 'validateOwnerClaimCard', {
        claim_card_json: value, page_origin: location.origin
      });
    } catch {
      showError(section, 'The installer claim is invalid or does not match this page and Hub. No account request was sent.');
      return;
    }
    if (!checked.summary || checked.summary.origin !== location.origin ||
        checked.summary.hubId !== context.hubIdentity.hub_id) {
      showError(section, 'The installer claim does not match this Hub page. No account request was sent.');
      return;
    }
    if (savedProfile && (savedProfile.origin !== checked.summary.origin || savedProfile.hubId !== checked.summary.hubId ||
        savedProfile.accountId !== checked.summary.accountId || savedProfile.ownerId !== checked.summary.ownerId ||
        savedProfile.allowLoopbackHTTP !== Boolean(checked.allow_loopback_http))) {
      showError(section, 'The replacement claim does not match the saved account, Owner, origin and transport policy. No account request was sent.');
      return;
    }
    verified = { ...checked.summary, allowLoopbackHTTP: Boolean(checked.allow_loopback_http) };
    let reviewedCardText = value;
    const reviewedScope = verified;
    notice(result, t('Verified claim scope\nOrigin: {origin}\nFull Hub fingerprint: {fingerprint}\nExpires: {expiresAt}', {
      origin: verified.origin, fingerprint: verified.hubFingerprint, expiresAt: verified.expiresAt
    }), 'good');
    const confirmation = node('input');
    confirmation.type = 'checkbox';
    confirmation.id = 'owner-claim-pin-confirm';
    const label = node('label', 'advanced-consent');
    label.htmlFor = confirmation.id;
    label.append(confirmation, node('span', '', t('I independently checked this exact origin and complete fingerprint with the installer.')));
    const next = actionButton(t('Continue to Owner credentials'), async () => {
      if (!confirmation.checked) return;
      const selectedCard = reviewedCardText;
      reviewedCardText = '';
      result.replaceChildren();
      try {
        // The installer card is the independent full-identity pin for a new
        // empty profile. Save that pin only after the user reviewed this exact
        // origin and complete fingerprint; no account packet has been sent yet.
        await savePinnedHub(context.db, context.hubIdentity);
        await beginClaim(app, context, reviewedScope, selectedCard, cardText, file.input, result);
      } catch {
        showError(section, 'The reviewed Hub identity could not be saved. No account request was sent.');
      }
    });
    next.disabled = true;
    confirmation.addEventListener('change', () => { next.disabled = !confirmation.checked; });
    result.append(label, next);
  });
  section.append(cardLabel, cardText, file.wrap,
    notice(section, t('The claim code is not displayed or saved. The encrypted first request is saved with the generated browser device key before it is sent. Refresh or a lost response resumes that exact request.'), 'warn'),
    verify, result,
    actionButton(t('Advanced technical setup'), () => leaveOwnerAccountForAdvanced(context), 'btn quiet'));
}

function sameClaimScope(prepared, verified) {
  return prepared?.claim?.origin === verified.origin && prepared?.claim?.hubId === verified.hubId &&
    prepared?.claim?.hubFingerprint === verified.hubFingerprint &&
    prepared?.claim?.accountId === verified.accountId && prepared?.claim?.ownerId === verified.ownerId &&
    prepared.allow_loopback_http === verified.allowLoopbackHTTP;
}

async function beginClaim(app, context, verified, selectedCardText, cardText, cardFile, result) {
  try {
    if (accountDevice) {
      const state = await getState(context.db);
      const profile = state.ownerAccount?.profile;
      if (!profile || profile.origin !== verified.origin || profile.hubId !== verified.hubId ||
          profile.accountId !== verified.accountId || profile.ownerId !== verified.ownerId ||
          profile.allowLoopbackHTTP !== verified.allowLoopbackHTTP) throw new Error('claim-changed');
      const prepared = accountApi(context, 'sealOwnerClaimPrepare', {
        handle: accountDevice.handle, claim_card_json: selectedCardText, page_origin: location.origin,
        existing_device_id: profile.deviceId, expected_public_identity: profile.publicIdentity
      });
      selectedCardText = '';
      if (!sameClaimScope(prepared, verified) || prepared.device_id !== profile.deviceId ||
          prepared.public_identity?.id !== profile.publicIdentity?.id ||
          prepared.public_identity?.kem_public !== profile.publicIdentity?.kem_public ||
          prepared.public_identity?.signing_public !== profile.publicIdentity?.signing_public) throw new Error('claim-changed');
      await persist(context, profile, { phase: 'CLAIM_PREPARE_PENDING', packet: prepared.packet }, null,
        state.ownerAccount.pending);
      cardText.value = '';
      cardFile.value = '';
      const latest = await getState(context.db);
      await executeClaimPrepare(app, context, profile, latest.ownerAccount.pending);
      return;
    }
    if (!accountDevice) {
      const generated = context.cryptoApi.generateIdentity({});
      if (!generated?.ok || !generated.identity_blob) throw new Error('crypto');
      let prepared;
      let vault;
      try {
        prepared = accountApi(context, 'sealOwnerClaimPrepare', {
          handle: generated.handle, claim_card_json: selectedCardText, page_origin: location.origin
        });
        selectedCardText = '';
        if (!sameClaimScope(prepared, verified)) throw new Error('claim-changed');
        vault = await encryptAccountDeviceIdentity(generated.identity_blob, location.origin, verified.hubId,
          verified.accountId, prepared.device_id, generated.public_identity, verified.allowLoopbackHTTP);
        generated.identity_blob = '';
        const profile = { origin: verified.origin, hubId: verified.hubId, accountId: verified.accountId,
          ownerId: verified.ownerId, deviceId: prepared.device_id, username: '',
          publicIdentity: generated.public_identity, allowLoopbackHTTP: verified.allowLoopbackHTTP,
          ownerPublicIdentity: null, ownerFingerprint: '' };
        await persist(context, profile, { phase: 'CLAIM_PREPARE_PENDING', packet: prepared.packet }, vault, null);
        accountDevice = { handle: generated.handle, publicIdentity: generated.public_identity };
        cardText.value = '';
        cardFile.value = '';
        const latest = await getState(context.db);
        await executeClaimPrepare(app, context, profile, latest.ownerAccount.pending);
      } catch (failure) {
        generated.identity_blob = '';
        if (generated.handle && !accountDevice) context.cryptoApi.forgetIdentity({ handle: generated.handle });
        throw failure;
      }
    }
  } catch (failure) {
    if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
    showError(result, 'The claim request could not start. The claim file was not saved; check the page and retry.');
  }
}

async function requestAndSaveResponse(context, profile, pending, endpoint, nextPhase) {
  const expectedPending = pending;
  let responsePacket = pending.responsePacket;
  if (!responsePacket) {
    responsePacket = await postPacket(endpoint, pending.packet);
    pending = { ...pending, phase: nextPhase, responsePacket };
    await persist(context, profile, pending, null, expectedPending);
  }
  return pending;
}

async function executeClaimPrepare(app, context, profile, pending) {
  try {
    const answered = await requestAndSaveResponse(context, profile, pending,
      '/v2/owner/account/claim/prepare', 'CLAIM_CHALLENGE_SAVED');
    renderClaimCredentials(app, context, profile, answered);
  } catch (failure) {
    if (failure?.httpStatus === 403) {
      const retry = { phase: 'CLAIM_CARD_REQUIRED' };
      try {
        await persist(context, profile, retry, null, pending);
        renderClaimStart(app, context, profile);
        showError(app.querySelector('section'), 'The Hub rejected that claim. Obtain a valid installer claim for the same account and verify it before retrying.');
        return;
      } catch (saveFailure) {
        if (isStaleAccountWrite(saveFailure)) return showCurrentAccountState(app, context);
      }
    }
    if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
    renderPendingRecovery(app, context, profile, pending);
  }
}

function renderClaimCredentials(app, context, originalProfile, pending) {
  const section = ceremony(app, t('Create Owner credentials'),
    t('Page 2 of 2. These credentials bind to the installer claim and the existing public ML-KEM and ML-DSA keys. Private PEM files are rejected before their contents are read.'),
    'OWNER ACCOUNT · PAGE 2 OF 2');
  notice(section, t('This browser login device is a separate PQ identity protected by a random non-extractable browser-profile key. The account password does not unlock it. Browser profile cloning or loss can still expose or remove this local device; sign in also requires the account password and PQ device key.'), 'warn');
  const username = field(t('Owner username'), 'owner-account-username', 'text', originalProfile.username, 'off');
  const password = field(t('Owner password (at least 10 characters)'), 'owner-account-password', 'password', '', 'off');
  const confirm = field(t('Confirm Owner password'), 'owner-account-password-confirm', 'password', '', 'off');
  const strength = node('div', 'password-feedback', t('Password strength appears here; the value is checked locally and never saved.'));
  const updateStrength = () => {
    const feedback = ownerAccountPasswordFeedback(password.input.value, username.input.value);
    const label = feedback.level === 'weak' ? t('Weak password') : feedback.level === 'too-short' ? t('At least 10 characters required') :
      feedback.level === 'too-long' ? t('Password exceeds the byte limit') : feedback.level === 'strong' ? t('Strong password') : t('Acceptable password');
    setLocalizedText(strength, label);
    strength.dataset.strength = feedback.level;
  };
  password.input.addEventListener('input', updateStrength);
  username.input.addEventListener('input', updateStrength);
  const kem = field(t('Existing Owner ML-KEM-768 public SPKI PEM'), 'owner-kem-public', 'file');
  const signing = field(t('Existing Owner ML-DSA-65 public SPKI PEM'), 'owner-signing-public', 'file');
  for (const input of [kem.input, signing.input]) input.accept = '.pem,.pub,text/plain,application/x-pem-file';
  section.append(username.wrap, password.wrap, confirm.wrap, strength, kem.wrap, signing.wrap,
    notice(section, t('Only public SPKI PEM files are accepted. Do not select private keys, password files, or a combined private-key bundle.'), 'danger'));
  section.append(actionButton(t('Create Owner account'), async () => {
    try {
      const name = username.input.value;
      const passwordValue = password.input.value;
      if (passwordValue !== confirm.input.value) throw new Error('mismatch');
      const feedback = ownerAccountPasswordFeedback(passwordValue, name);
      if (!feedback.meetsMinimum || feedback.level === 'weak') throw new Error('weak');
      const kemFile = kem.input.files?.[0];
      const signingFile = signing.input.files?.[0];
      const [kemPem, signingPem] = await Promise.all([readOwnerPublicSPKIPem(kemFile), readOwnerPublicSPKIPem(signingFile)]);
      const ownerKeys = context.cryptoApi.parseOwnerPublicSPKI({ kem_public_pem: kemPem, signing_public_pem: signingPem });
      if (!ownerKeys?.ok) throw new Error('public-key');
      const state = await getState(context.db);
      const current = state.ownerAccount;
      if (!current?.pending || current.pending.phase !== 'CLAIM_CHALLENGE_SAVED') throw new Error('state');
      const sealed = accountApi(context, 'sealOwnerClaimComplete', {
        handle: accountDevice.handle, prepare_packet: current.pending.packet,
        challenge_packet: current.pending.responsePacket, origin: originalProfile.origin,
        account_id: originalProfile.accountId, owner_id: originalProfile.ownerId,
        device_id: originalProfile.deviceId, username: name, password: passwordValue,
        owner_public_identity: ownerKeys.owner_public_identity
      });
      const profile = { ...originalProfile, username: name };
      const nextPending = { phase: 'CLAIM_COMPLETE_PENDING', packet: sealed.packet,
        preparePacket: current.pending.packet, challengePacket: current.pending.responsePacket,
        ownerPublicIdentity: ownerKeys.owner_public_identity, ownerFingerprint: ownerKeys.owner_fingerprint };
      await persist(context, profile, nextPending, null, current.pending);
      password.input.value = '';
      confirm.input.value = '';
      await executeClaimComplete(app, context, profile, nextPending);
    } catch (failure) {
      if (failure?.message === 'mismatch') showError(section, 'Owner password confirmation does not match.');
      else if (failure?.message === 'weak') showError(section, 'Choose a password of at least 10 characters that is not a common or username-based password.');
      else if (failure?.message === 'public-key') showError(section, 'The selected public PEM pair is invalid. Choose existing ML-KEM-768 and ML-DSA-65 SPKI PUBLIC KEY files.');
      else if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
      else showError(section, 'Owner credentials or public keys could not be checked. The claim challenge remains saved.');
    }
  }));
  section.append(actionButton(t('Back to installer claim'), () => renderClaimStart(app, context), 'btn quiet'));
}

async function executeClaimComplete(app, context, profile, pending) {
  try {
    const answered = await requestAndSaveResponse(context, profile, pending,
      '/v2/owner/account/claim/complete', 'CLAIM_COMPLETE_PENDING');
    const opened = accountApi(context, 'openOwnerClaimReceipt', { handle: accountDevice.handle,
      request_packet: answered.packet, response_packet: answered.responsePacket,
      origin: profile.origin, account_id: profile.accountId, owner_id: profile.ownerId,
      owner_public_identity: answered.ownerPublicIdentity, owner_key_id: answered.ownerPublicIdentity?.id,
      owner_fingerprint: answered.ownerFingerprint });
    if (!opened.receipt || opened.receipt.account_id !== profile.accountId || opened.receipt.owner_id !== profile.ownerId ||
        opened.receipt.root_active !== false || opened.receipt.state !== 'ACCOUNT_READY_OWNER_SIGNER_PENDING') throw new Error('receipt');
    const completedProfile = { ...profile, ownerPublicIdentity: answered.ownerPublicIdentity,
      ownerFingerprint: answered.ownerFingerprint };
    await persist(context, completedProfile, null, null, answered);
    renderAccountLogin(app, context, completedProfile, null, opened.receipt);
  } catch (failure) {
    // A 403 is a definite account-service rejection. Keep the authenticated
    // prepare/challenge pair so the user can correct credentials or public
    // keys. Network loss and server errors retain the exact completion packet.
    if (failure?.httpStatus === 403 && pending.preparePacket && pending.challengePacket) {
      const retry = { phase: 'CLAIM_CHALLENGE_SAVED', packet: pending.preparePacket,
        responsePacket: pending.challengePacket };
      try {
        await persist(context, profile, retry, null, pending);
        renderClaimCredentials(app, context, profile, retry);
        showError(app.querySelector('section'), 'The Hub rejected account completion. The saved challenge remains intact; check the account fields and public keys, then retry.');
        return;
      } catch (saveFailure) {
        if (isStaleAccountWrite(saveFailure)) return showCurrentAccountState(app, context);
      }
    }
    if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
    renderPendingRecovery(app, context, profile, pending);
  }
}

function renderAccountLogin(app, context, profile, pending, claimReceipt = null) {
  const section = ceremony(app, t('Owner account sign in'),
    t('Sign in with this browser PQ device and your Owner account password. A password alone cannot add a new device. This account page does not grant Client manager access.'),
    'OWNER ACCOUNT');
  if (claimReceipt) {
    notice(section, t('Account status: {state}\nRoot signer: {rootState}\nThe Hub accepted the first account claim. Root proof and Client enrollment are separate steps.', {
      state: claimReceipt.state, rootState: claimReceipt.root_state
    }), 'good');
  } else {
    notice(section, t('This browser has an encrypted account login device for {accountId}. Its key remains in this browser profile.', {
      accountId: profile.accountId
    }), 'warn');
  }
  const username = field(t('Owner username'), 'owner-login-username', 'text', profile.username, 'off');
  const password = field(t('Owner password'), 'owner-login-password', 'password', '', 'off');
  if (pending?.phase === 'LOGIN_CHALLENGE_SAVED') username.input.readOnly = true;
  section.append(username.wrap, password.wrap);
  section.append(actionButton(t('Sign in'), async () => {
    let createdPreparePending = null;
    try {
      const name = username.input.value;
      const secret = password.input.value;
      if (!secret) throw new Error('password');
      const state = await getState(context.db);
      let currentPending = state.ownerAccount?.pending;
      if (!currentPending) {
        const prepared = accountApi(context, 'sealOwnerLoginPrepare', { handle: accountDevice.handle,
          origin: profile.origin, account_id: profile.accountId, owner_id: profile.ownerId,
          device_id: profile.deviceId, username: name });
        const nextProfile = { ...profile, username: name };
        currentPending = { phase: 'LOGIN_PREPARE_PENDING', packet: prepared.packet };
        await persist(context, nextProfile, currentPending, null, null);
        createdPreparePending = currentPending;
        currentPending = await requestAndSaveResponse(context, nextProfile, currentPending,
          '/v2/owner/account/login/prepare', 'LOGIN_CHALLENGE_SAVED');
        profile.username = name;
      }
      if (currentPending.phase !== 'LOGIN_CHALLENGE_SAVED') throw new Error('pending');
      const completed = accountApi(context, 'sealOwnerLoginComplete', { handle: accountDevice.handle,
        prepare_packet: currentPending.packet, challenge_packet: currentPending.responsePacket,
        origin: profile.origin, account_id: profile.accountId, owner_id: profile.ownerId,
        device_id: profile.deviceId, username: profile.username, password: secret });
      const nextPending = { phase: 'LOGIN_COMPLETE_PENDING', packet: completed.packet,
        preparePacket: currentPending.packet, challengePacket: currentPending.responsePacket };
      await persist(context, profile, nextPending, null, currentPending);
      password.input.value = '';
      await executeLoginComplete(app, context, profile, nextPending);
    } catch (failure) {
      password.input.value = '';
      if (failure?.message === 'password') showError(section, 'Enter the Owner account password.');
      else {
        const latest = await getState(context.db);
        if (failure?.httpStatus === 403 && createdPreparePending) {
          try {
            await persist(context, latest.ownerAccount.profile, null, null, createdPreparePending);
            renderAccountLogin(app, context, latest.ownerAccount.profile, null);
            showError(app.querySelector('section'), 'The Hub rejected this sign-in request. Check the username and saved browser device, then try again.');
            return;
          } catch (saveFailure) {
            if (isStaleAccountWrite(saveFailure)) return showCurrentAccountState(app, context);
          }
        }
        if (latest.ownerAccount?.pending?.phase === 'LOGIN_COMPLETE_PENDING') {
          return renderPendingRecovery(app, context, latest.ownerAccount.profile, latest.ownerAccount.pending);
        }
        if (latest.ownerAccount?.pending?.phase === 'LOGIN_PREPARE_PENDING') {
          return renderPendingRecovery(app, context, latest.ownerAccount.profile, latest.ownerAccount.pending);
        }
        if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
        showError(section, 'Sign in could not complete. The saved login challenge remains available; check the password and try again.');
      }
    }
  }));
  if (pending?.phase === 'LOGIN_CHALLENGE_SAVED') {
    notice(section, t('The Hub challenge is saved as encrypted bytes. Enter the account password to finish sign in.'), 'warn');
  }
  if (accountSessionHandle) section.append(actionButton(t('Refresh account status'), () => inspectOwnerSession(app, context, profile), 'btn quiet'));
  section.append(actionButton(t('Advanced technical setup'), () => leaveOwnerAccountForAdvanced(context), 'btn quiet'));
}

async function executeLoginComplete(app, context, profile, pending) {
  try {
    const answered = await requestAndSaveResponse(context, profile, pending,
      '/v2/owner/account/login/complete', 'LOGIN_COMPLETE_PENDING');
    const opened = accountApi(context, 'openOwnerLoginReceipt', { handle: accountDevice.handle,
      request_packet: answered.packet, response_packet: answered.responsePacket,
      origin: profile.origin, account_id: profile.accountId, owner_id: profile.ownerId, device_id: profile.deviceId });
    if (accountSessionHandle) context.cryptoApi.forgetOwnerAccountSession({ session_handle: accountSessionHandle });
    accountSessionHandle = opened.session_handle;
    accountSessionMetadata = { origin: opened.origin, hubId: opened.hub_id, accountId: opened.account_id,
      ownerId: opened.owner_id, deviceId: opened.device_id, accountEpoch: opened.account_epoch,
      deviceEpoch: opened.device_epoch };
    await persist(context, profile, null, null, answered);
    await inspectOwnerSession(app, context, profile);
  } catch (failure) {
    // The account service returns 403 only when this exact request was denied.
    // In particular, a wrong password leaves the authenticated challenge
    // pending. Keep that challenge and let the user enter a corrected password;
    // transport failures and 5xx remain exact-packet recovery cases.
    if (failure?.httpStatus === 403 && pending.preparePacket && pending.challengePacket) {
      const retry = { phase: 'LOGIN_CHALLENGE_SAVED', packet: pending.preparePacket,
        responsePacket: pending.challengePacket };
      try {
        await persist(context, profile, retry, null, pending);
        renderAccountLogin(app, context, profile, retry);
        showError(app.querySelector('section'), 'The Hub rejected sign in. The saved login challenge is intact; check the password and try again.');
        return;
      } catch (saveFailure) {
        if (isStaleAccountWrite(saveFailure)) return showCurrentAccountState(app, context);
      }
    }
    if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
    renderPendingRecovery(app, context, profile, pending);
  }
}

async function inspectOwnerSession(app, context, profile) {
  try {
    if (!accountSessionHandle) throw new Error('session');
    const sealed = accountApi(context, 'sealOwnerSessionInspect', { handle: accountDevice.handle,
      session_handle: accountSessionHandle });
    const responsePacket = await postPacket('/v2/owner/account/session/inspect', sealed.packet);
    const opened = accountApi(context, 'openOwnerSessionInspection', { handle: accountDevice.handle,
      session_handle: accountSessionHandle, request_packet: sealed.packet, response_packet: responsePacket });
    const status = opened.status;
    if (status.account_id !== profile.accountId || status.owner_id !== profile.ownerId || status.state !== 'ACTIVE' ||
        status.owner_key_id !== profile.ownerPublicIdentity?.id || status.owner_fingerprint !== profile.ownerFingerprint) throw new Error('binding');
    renderAccountStatus(app, context, profile, status);
  } catch {
    if (accountSessionHandle) context.cryptoApi.forgetOwnerAccountSession({ session_handle: accountSessionHandle });
    accountSessionHandle = null;
    renderAccountLogin(app, context, profile, null);
    const section = app.querySelector('section');
    showError(section, 'Sign in succeeded but the authenticated account status could not be refreshed. Sign in again to continue.');
  }
}

function renderAccountStatus(app, context, profile, status) {
  const section = ceremony(app, t('Owner account'),
    t('This page shows authenticated account status only. Root signing and Client manager access require their separate proof and enrollment checks.'),
    'OWNER ACCOUNT');
  notice(section, t('Account: {username}\nAccount state: {state}\nRoot signer state: {rootState}\nRoot active: {rootActive}\nOwner public key: {ownerKeyID}', {
    username: status.username, state: status.state, rootState: status.root_state,
    rootActive: status.root_active ? t('Yes') : t('No'), ownerKeyID: status.owner_key_id
  }), 'good');
  if (status.root_state !== 'ROOT_ACTIVE' || !status.root_active) {
    notice(section, t('Owner signer proof is still required. This account session does not create Root authority or Client manager capabilities.'), 'warn');
  }
  section.append(actionButton(t('Sign out'), async () => {
    try {
      if (!accountSessionHandle || !accountSessionMetadata) throw new Error('session');
      const sealed = accountApi(context, 'sealOwnerLogout', { handle: accountDevice.handle, session_handle: accountSessionHandle });
      const pending = { phase: 'LOGOUT_PENDING', packet: sealed.packet,
        accountEpoch: accountSessionMetadata.accountEpoch, deviceEpoch: accountSessionMetadata.deviceEpoch };
      // Save ciphertext before HTTP. If the response is uncertain, this page
      // stays on exact recovery and never reports sign-out as complete.
      await persist(context, profile, pending, null, null);
      await executeOwnerLogout(app, context, profile, pending);
    } catch {
      showError(section, 'Sign out could not be started. The Hub has not confirmed sign out.');
    }
  }));
  section.append(actionButton(t('Advanced technical setup'), () => leaveOwnerAccountForAdvanced(context), 'btn quiet'));
}

async function executeOwnerLogout(app, context, profile, pending) {
  try {
    let answered = pending;
    if (!answered.responsePacket) {
      const responsePacket = await postPacket('/v2/owner/account/session/logout', answered.packet);
      answered = { ...answered, responsePacket };
      await persist(context, profile, answered, null, pending);
    }
    accountApi(context, 'openOwnerLogoutReceipt', {
      handle: accountDevice.handle, session_handle: accountSessionHandle || '',
      hub_identity: context.hubIdentity, origin: profile.origin, hub_id: profile.hubId,
      account_id: profile.accountId, owner_id: profile.ownerId, device_id: profile.deviceId,
      account_epoch: answered.accountEpoch, device_epoch: answered.deviceEpoch,
      request_packet: answered.packet, response_packet: answered.responsePacket
    });
    if (accountSessionHandle) context.cryptoApi.forgetOwnerAccountSession({ session_handle: accountSessionHandle });
    accountSessionHandle = null;
    accountSessionMetadata = null;
    await persist(context, profile, null, null, answered);
    renderAccountLogin(app, context, profile, null);
  } catch (failure) {
    if (isStaleAccountWrite(failure)) return showCurrentAccountState(app, context);
    renderPendingRecovery(app, context, profile, pending);
  }
}

function renderPendingRecovery(app, context, profile, pending) {
  const section = ceremony(app, t('Recover the saved account request'),
    t('The Hub may already have accepted this request. Recovery submits only its exact saved encrypted bytes; it never regenerates the device, request ID, or challenge nonce.'),
    'EXACT REQUEST RECOVERY');
  notice(section, t('Saved step: {phase}\nAccount: {accountId}\nDevice: {deviceId}', {
    phase: pending.phase, accountId: profile.accountId, deviceId: profile.deviceId
  }), 'warn');
  if (pending.phase === 'LOGOUT_PENDING') {
    notice(section, t('The Hub has not confirmed sign out. Retry this exact encrypted logout packet before starting another sign-in.'), 'danger');
  }
  section.append(actionButton(t('Recover exact encrypted request'), async () => {
    try {
      if (pending.phase === 'CLAIM_PREPARE_PENDING') return await executeClaimPrepare(app, context, profile, pending);
      if (pending.phase === 'CLAIM_COMPLETE_PENDING') return await executeClaimComplete(app, context, profile, pending);
      if (pending.phase === 'LOGIN_PREPARE_PENDING') {
        const answered = await requestAndSaveResponse(context, profile, pending,
          '/v2/owner/account/login/prepare', 'LOGIN_CHALLENGE_SAVED');
        return renderAccountLogin(app, context, profile, answered);
      }
      if (pending.phase === 'LOGIN_COMPLETE_PENDING') return await executeLoginComplete(app, context, profile, pending);
      if (pending.phase === 'LOGOUT_PENDING') return await executeOwnerLogout(app, context, profile, pending);
      throw new Error('phase');
    } catch { showError(section, 'The saved request could not be recovered. Its exact bytes remain available for retry.'); }
  }));
  if (pending.phase === 'CLAIM_CHALLENGE_SAVED') {
    section.append(actionButton(t('Continue Owner account setup'), () => renderClaimCredentials(app, context, profile, pending)));
  }
}
