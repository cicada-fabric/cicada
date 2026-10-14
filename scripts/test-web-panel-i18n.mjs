import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const uiDir = path.resolve('cicada-go/internal/server/ui');
const source = await readFile(path.join(uiDir, 'panel-i18n.js'), 'utf8');
const i18n = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

class Element {
  constructor() {
    this.dataset = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.isConnected = true;
    this.textContent = '';
    this.value = '';
    this.htmlWrites = 0;
  }
  set innerHTML(_value) { this.htmlWrites++; throw new Error('HTML parsing is forbidden in this test'); }
  get innerHTML() { return ''; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  removeAttribute(name) { this.attributes.delete(name); }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  dispatch(name) { this.listeners.get(name)?.({ target: this }); }
}

assert.deepEqual(i18n.supportedLanguages, ['en', 'zh-CN']);
const englishKeys = Object.keys(i18n.catalogs.en).sort();
const chineseKeys = Object.keys(i18n.catalogs['zh-CN']).sort();
assert.deepEqual(englishKeys, chineseKeys, 'both languages expose the same explicit catalog keys');
for (const key of englishKeys) {
  assert.equal(i18n.catalogs.en[key], key, `English catalog preserves source key: ${key}`);
  const placeholders = value => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)].map(match => match[1]).sort();
  assert.deepEqual(placeholders(i18n.catalogs['zh-CN'][key]), placeholders(key), `placeholder parity: ${key}`);
}
for (const key of [
  'Owner account setup is unavailable in this build',
  'The normal first Owner setup should start with an installer-issued Hub URL and one-time claim code, then create an Owner username and password using existing public keys. That signup flow is not available in this build; this page does not create an account or accept a claim.',
  'OWNER ACCOUNT SETUP',
  'The browser-device form is a separate advanced Client enrollment tool. It is not Owner signup and does not create Owner login credentials.',
  'Advanced technical setup',
  'The optional technical path covers Owner-signer bootstrap and browser Client-device enrollment. It requires separate operator and signer steps and does not claim a Hub installation or create an Owner username or password.',
  'I understand this is advanced signer and browser-device setup, not Owner account signup.',
  'Open advanced signer and browser-device setup',
  'Advanced Owner signer and browser Client setup',
  'This technical path does not claim a Hub installation or set Owner login credentials. Its browser-device form creates a Client device key for separate Owner-authorized enrollment.',
  'Continue to advanced browser Client device enrollment',
  'Open advanced browser Client device enrollment',
  'Create an advanced browser Client device',
  'This form creates only a browser Client device key. The private key is stored as password-encrypted WebCrypto data in this browser profile; the vault password is not an Owner login password. Owner approval remains a separate step.',
  'This device-enrollment form does not create an Owner account. The Hub does not receive Owner private keys; the exported manifest contains only this browser Client device public identity.',
  'Create Client device key and public enrollment manifest'
]) {
  assert(englishKeys.includes(key), `catalog contains the new Owner/setup boundary key: ${key}`);
  assert.notEqual(i18n.catalogs['zh-CN'][key], key, `Simplified Chinese translates the new setup boundary: ${key}`);
}

assert.equal(i18n.translate('Uncatalogued server response', {}, 'zh-CN'), 'Uncatalogued server response',
  'unknown server/user text falls back to its original value');
assert.equal(i18n.translate('Hub {hub} · Owner {owner} · device {device}',
  { hub: 'hub-一', owner: 'owner-二', device: 'device-三' }, 'zh-CN'),
'Hub hub-一 · Owner owner-二 · 设备 device-三', 'interpolation retains opaque identifiers');
assert.equal(i18n.localizedIfKnown('a user label called Network'), 'a user label called Network',
  'content that is not an exact UI key is left alone');

const languageText = new Element();
const aria = new Element();
const liveElements = new Set([languageText, aria]);
let lastTranslationQuery = [];
const documentRef = {
  documentElement: { lang: '' },
  querySelectorAll(selector) {
    assert.equal(selector, '[data-i18n-text-key], [data-i18n-attributes]',
      'language changes query only explicit i18n markers');
    lastTranslationQuery = [...liveElements].filter(element =>
      element.dataset.i18nTextKey || element.attributes.has('data-i18n-attributes'));
    return lastTranslationQuery;
  }
};
const unsentDraft = new Element();
unsentDraft.value = 'approval draft stays in the field';
unsentDraft.files = [{ name: 'selected-public-file.json' }];
const beforeFile = unsentDraft.files[0];
i18n.setLocalizedText(languageText, i18n.localized('Language'));
i18n.setLocalizedAttribute(aria, 'aria-label', i18n.localized('Hub topology canvas'));
const selector = new Element();
const writes = [];
const storage = {
  value: '',
  getItem(key) { assert.equal(key, i18n.languagePreferenceKey); return this.value; },
  setItem(key, value) { writes.push([key, value]); this.value = value; }
};
assert.equal(i18n.initializeLanguageSelector(selector, {
  documentRef, storage, browserLanguages: ['zh-Hans-CN', 'en-US']
}), 'zh-CN', 'browser language selects Simplified Chinese by default');
assert.equal(documentRef.documentElement.lang, 'zh-CN');
assert.equal(languageText.textContent, '语言');
assert.equal(aria.attributes.get('aria-label'), 'Hub 拓扑画布');
assert.equal(selector.value, 'zh-CN');

selector.value = 'en';
selector.dispatch('change');
assert.equal(documentRef.documentElement.lang, 'en');
assert.equal(languageText.textContent, 'Language');
assert.equal(aria.attributes.get('aria-label'), 'Hub topology canvas');
assert.equal(unsentDraft.value, 'approval draft stays in the field');
assert.strictEqual(unsentDraft.files[0], beforeFile, 'changing language preserves the exact selected draft file');
assert.deepEqual(writes, [
  [i18n.languagePreferenceKey, 'zh-CN'],
  [i18n.languagePreferenceKey, 'en']
], 'only the nonsecret language preference is persisted');

const oldFormLabel = new Element();
const oldFormInput = new Element();
oldFormInput.value = 'unsent-field-value-must-not-be-retained-or-cleared';
i18n.setLocalizedText(oldFormLabel, i18n.localized('Unlock the browser device key'));
i18n.setLocalizedAttribute(oldFormInput, 'aria-label', i18n.localized('Vault password'));
liveElements.add(oldFormLabel);
liveElements.add(oldFormInput);
liveElements.delete(oldFormLabel);
liveElements.delete(oldFormInput);
oldFormLabel.isConnected = false;
oldFormInput.isConnected = false;

const liveCountBeforeRenders = liveElements.size;
for (let index = 0; index < 500; index++) {
  const renderedLabel = new Element();
  i18n.setLocalizedText(renderedLabel, i18n.localized('Local layout only · {count} endpoint references · zoom {zoom}%', {
    count: index, zoom: 100
  }));
  liveElements.add(renderedLabel);
  i18n.applyTranslations('zh-CN', documentRef);
  assert.match(renderedLabel.textContent, /^仅本地布局/);
  liveElements.delete(renderedLabel);
  renderedLabel.isConnected = false;
  assert.equal(liveElements.size, liveCountBeforeRenders,
    'repeated render/removal leaves only the current DOM nodes in the test document');
}
i18n.applyTranslations('en', documentRef);
assert(!lastTranslationQuery.includes(oldFormLabel) && !lastTranslationQuery.includes(oldFormInput),
  'removed form elements are never revisited by a later language switch');
assert.equal(oldFormInput.value, 'unsent-field-value-must-not-be-retained-or-cleared');
assert.equal(oldFormInput.attributes.get('aria-label'), 'Vault password',
  'detached form fields are not rewritten after removal');
assert.doesNotMatch(source, /localizedNodes|localizedNodeReferences|WeakRef/,
  'the module has no global element registry or strong-reference fallback');
assert.match(source, /const localizedValues = new WeakMap\(\)/,
  'localized values are associated only through weak element keys');

const untrusted = new Element();
const hostile = '<img src=x onerror=alert(1)>';
i18n.setLocalizedText(untrusted, i18n.localized('Hub {hub} · Owner {owner} · device {device}', {
  hub: hostile, owner: 'owner-safe', device: 'device-safe'
}));
assert.equal(untrusted.textContent, `Hub ${hostile} · Owner owner-safe · device device-safe`,
  'interpolated values are assigned as text and never parsed as markup');
assert.equal(untrusted.htmlWrites, 0, 'no HTML sink is used');

const panelSource = await readFile(path.join(uiDir, 'panel.js'), 'utf8');
assert.match(panelSource, /initializeLanguageSelector\(document\.querySelector\('#panel-language'\)\)/,
  'the visible selector initializes the language preference without recreating the panel');
const setupStart = panelSource.indexOf('function configureLanguage()');
const setupEnd = panelSource.indexOf('\nfunction renderPin(', setupStart);
const languageSetup = panelSource.slice(setupStart, setupEnd);
assert.doesNotMatch(languageSetup, /replaceChildren|render\w*\(|fetch\s*\(|updateState|savePinnedHub|callRPC|enrollExactRequest/,
  'language selection only updates language controls and marked labels');
assert.doesNotMatch(source, /fetch\s*\(|crypto\.|\.submit\s*\(|replaceChildren\s*\(/,
  'the language module cannot issue network, cryptographic, form-submit, or rerender actions');
console.log('PASS panel i18n catalog, fallback, interpolation, text-only rendering, and draft-preserving switch');
