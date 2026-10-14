import { getHubIdentity } from './panel-client.js';

const ownerConnectionFormat = 'cicada.hub-owner-connection.v1';
const ownerManifestFormat = 'cicada.owner-signer-public.v1';
const ownerGrantSummaryFormat = 'cicada.owner-device-grant-summary.v1';
const ownerBootstrapPurpose = 'ROOT_SIGNER_BOOTSTRAP';
const ownerDeviceGrantPurpose = 'CLIENT_CONTROL';
const publicIdentityFields = ['id', 'kem_public', 'signing_public'];
const hubIdentityFields = ['contract', 'hub_id', 'control_public_identity', 'control_key_version', 'suite'];

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(value, fields) {
  return isRecord(value) && Object.keys(value).sort().join('\n') === [...fields].sort().join('\n');
}

function validOwnerID(value) {
  if (typeof value !== 'string' || !value || new TextEncoder().encode(value).length > 128 || value.trim() !== value) return false;
  return !/[\p{White_Space}\p{Cc}\p{Cf}\u002f\\]/u.test(value);
}

function samePublicIdentity(left, right) {
  return isRecord(left) && isRecord(right) && left.id === right.id &&
    left.kem_public === right.kem_public && left.signing_public === right.signing_public;
}

function sameHubIdentity(left, right) {
  return isRecord(left) && isRecord(right) && left.contract === right.contract &&
    left.hub_id === right.hub_id && left.control_key_version === right.control_key_version &&
    left.suite === right.suite && samePublicIdentity(left.control_public_identity, right.control_public_identity);
}

function isLiteralLoopback(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === '::1') return true;
  const parts = host.split('.');
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255) && Number(parts[0]) === 127;
}

function isCanonicalOwnerOrigin(origin, allowLoopbackHTTP) {
  if (typeof origin !== 'string' || !origin || typeof allowLoopbackHTTP !== 'boolean') return false;
  try {
    const parsed = new URL(origin);
    if (parsed.origin !== origin || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password) return false;
    if (parsed.protocol === 'https:') return true;
    return parsed.protocol === 'http:' && allowLoopbackHTTP && isLiteralLoopback(parsed.hostname);
  } catch { return false; }
}

function validatePublicIdentityShape(identity, cryptoApi, label) {
  if (!hasExactFields(identity, publicIdentityFields) || !validOwnerID(identity.id) ||
      typeof identity.kem_public !== 'string' || typeof identity.signing_public !== 'string') {
    throw new Error(`${label} has an invalid or unsupported public identity schema.`);
  }
  const result = cryptoApi.validatePublicIdentity({ public_identity: identity });
  if (!result?.ok) throw new Error(`${label} failed CICADA public-key validation.`);
}

function validateOwnerHubIdentity(hub, cryptoApi, label) {
  if (!hasExactFields(hub, hubIdentityFields) || hub.contract !== 'android-hub-v1' ||
      !validOwnerID(hub.hub_id) || hub.control_key_version !== 1 ||
      hub.suite !== 'ML-KEM-768+ML-DSA-65+AES-256-GCM') {
    throw new Error(`${label} has an invalid or unsupported Hub identity schema.`);
  }
  validatePublicIdentityShape(hub.control_public_identity, cryptoApi, `${label} Client-Control key`);
}

function validCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match || (match[2] && match[2].endsWith('0'))) return false;
  const wholeSeconds = `${match[1]}Z`;
  const parsed = Date.parse(wholeSeconds);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().replace('.000Z', 'Z') === wholeSeconds;
}

// Accept only the established offline signer summary or the local profile
// summary. Both are public metadata; the signed grant is verified separately.
export function validateOwnerDeviceGrantSummary(summary, manifest, cryptoApi) {
  const legacyFields = ['format', 'owner_id', 'owner_key_id', 'owner_public_identity', 'hub_id', 'device_id',
    'device_key_id', 'device_key_fingerprint', 'purpose', 'issued_at', 'expires_at', 'grant_file'];
  const profileFields = ['format', 'state', 'hub_id', 'owner_id', 'owner_key_id', 'owner_public_identity',
    'device_id', 'device_key_id', 'device_key_fingerprint', 'purpose', 'issued_at', 'expires_at', 'grant_file'];
  const isProfileSummary = isRecord(summary) && summary.format === ownerGrantSummaryFormat;
  const expectedFields = isProfileSummary ? profileFields : legacyFields;
  const expectedFormat = isProfileSummary ? ownerGrantSummaryFormat : 'cicada.owner-device-enrollment.v1';
  if (!hasExactFields(summary, expectedFields) || summary.format !== expectedFormat ||
      (isProfileSummary && summary.state !== 'GRANT_WRITTEN')) {
    throw new Error('Signer summary has an invalid or unsupported public schema.');
  }
  if (!manifest || summary.owner_id !== manifest.owner_id || summary.owner_key_id !== manifest.owner_key_id ||
      summary.hub_id !== manifest.hub_id || summary.device_id !== manifest.device_id ||
      summary.device_key_id !== manifest.device_public_identity?.id ||
      summary.device_key_fingerprint !== manifest.device_key_fingerprint ||
      summary.purpose !== ownerDeviceGrantPurpose ||
      !/^[0-9a-f]{64}$/.test(summary.device_key_fingerprint) ||
      !validCanonicalTimestamp(summary.issued_at) || !validCanonicalTimestamp(summary.expires_at) ||
      typeof summary.grant_file !== 'string' || !summary.grant_file || summary.grant_file.length > 4096) {
    throw new Error('Signer summary does not match this Hub, Owner, and exact device manifest.');
  }
  validatePublicIdentityShape(summary.owner_public_identity, cryptoApi, 'Owner signing identity');
  if (summary.owner_public_identity.id !== summary.owner_key_id) {
    throw new Error('Signer summary Owner key ID does not match its full public identity.');
  }
  return summary.owner_public_identity;
}

// This checks two locally selected public documents for consistency. It does
// not register an Owner, prove private-key possession, or report live Hub state.
export function validateOwnerBootstrapPublicFiles(connection, candidate, pageOrigin, observedHub, cryptoApi) {
  const connectionFields = ['format', 'version', 'purpose', 'account_id', 'owner_id', 'origin', 'allow_loopback_http', 'hub'];
  const candidateFields = ['format', 'account_id', 'owner_id', 'owner_public_identity', 'fingerprint', 'origin', 'allow_loopback_http', 'hub'];
  if (!hasExactFields(connection, connectionFields) || connection.format !== ownerConnectionFormat ||
      connection.version !== 1 || connection.purpose !== ownerBootstrapPurpose ||
      !validOwnerID(connection.account_id) || !validOwnerID(connection.owner_id)) {
    throw new Error('The public Hub connection file is invalid or contains unsupported fields.');
  }
  if (!hasExactFields(candidate, candidateFields) || candidate.format !== ownerManifestFormat ||
      !validOwnerID(candidate.account_id) || !validOwnerID(candidate.owner_id)) {
    throw new Error('The Owner public manifest is invalid or contains unsupported fields.');
  }
  if (typeof pageOrigin !== 'string' || connection.origin !== pageOrigin || candidate.origin !== connection.origin ||
      typeof connection.allow_loopback_http !== 'boolean' || candidate.allow_loopback_http !== connection.allow_loopback_http ||
      !isCanonicalOwnerOrigin(connection.origin, connection.allow_loopback_http)) {
    throw new Error('The origin or loopback policy does not match this page and both public files.');
  }
  if (connection.account_id !== candidate.account_id || connection.owner_id !== candidate.owner_id) {
    throw new Error('The account or Owner IDs do not match between the public files.');
  }
  validateOwnerHubIdentity(connection.hub, cryptoApi, 'Connection file');
  validateOwnerHubIdentity(candidate.hub, cryptoApi, 'Owner manifest');
  validateOwnerHubIdentity(observedHub, cryptoApi, 'Connected Hub');
  if (!sameHubIdentity(connection.hub, candidate.hub) || !sameHubIdentity(connection.hub, observedHub)) {
    throw new Error('The full Hub Client-Control identity does not match the independent connection file.');
  }
  validatePublicIdentityShape(candidate.owner_public_identity, cryptoApi, 'Owner candidate');
  if (candidate.owner_public_identity.id === connection.hub.control_public_identity.id) {
    throw new Error('The Owner candidate key must be distinct from the Hub Client-Control key.');
  }
  if (typeof candidate.fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(candidate.fingerprint)) {
    throw new Error('The Owner candidate fingerprint must be a complete lowercase SHA-256 value.');
  }
  const fingerprint = cryptoApi.fingerprint({ public_identity: candidate.owner_public_identity });
  if (!fingerprint?.ok || fingerprint.fingerprint !== candidate.fingerprint) {
    throw new Error('The Owner candidate fingerprint does not match its complete public identity.');
  }
  return { accountID: connection.account_id, ownerID: connection.owner_id,
    hubID: connection.hub.hub_id, ownerKeyID: candidate.owner_public_identity.id,
    origin: connection.origin, fingerprint: candidate.fingerprint };
}

// Check only the bounded PEM label before reading a selected file fully. The
// cryptographic parser in Go remains responsible for DER/OID/parameter checks.
export async function readOwnerPublicSPKIPem(file) {
  if (!file || !Number.isSafeInteger(file.size) || file.size <= 0 || file.size > 16 * 1024 ||
      typeof file.slice !== 'function' || typeof file.text !== 'function') {
    throw new Error('Select a bounded public SPKI PEM file no larger than 16 KiB.');
  }
  const prefix = await file.slice(0, 128).text();
  const match = /^\s*-----BEGIN ([A-Z0-9 ]+)-----/.exec(prefix);
  if (match?.[1] === 'ENCRYPTED PRIVATE KEY' || match?.[1].endsWith('PRIVATE KEY')) {
    throw new Error('Private key files are not accepted here. Select only the matching public SPKI PEM.');
  }
  if (match?.[1] !== 'PUBLIC KEY') {
    throw new Error('Expected one SPKI PUBLIC KEY PEM file.');
  }
  const pem = await file.text();
  if (typeof pem !== 'string' || pem.length > 16 * 1024 || !/^\s*-----BEGIN PUBLIC KEY-----/.test(pem)) {
    throw new Error('Selected public PEM changed or is malformed.');
  }
  return pem;
}

export async function loadCryptoWasm() {
  const manifestResponse = await fetch('/assets/panel.manifest.json', { cache: 'no-store', credentials: 'omit' });
  if (!manifestResponse.ok) throw new Error('The Hub WebCrypto build is missing. Build the Hub with scripts/build-web-panel.sh.');
  const manifest = await manifestResponse.json();
  if (manifest.toolchain !== 'go1.27.1' || manifest.wasm_file !== 'cicada-webcrypto.wasm.gz' || !manifest.wasm_sha256) {
    throw new Error('The Hub WebCrypto build manifest is invalid or uses an unsupported Go toolchain.');
  }
  const runtimeScript = document.createElement('script');
  runtimeScript.src = '/assets/wasm_exec.js';
  if (manifest.wasm_exec_sri) runtimeScript.integrity = manifest.wasm_exec_sri;
  runtimeScript.onload = () => {};
  await new Promise((resolve, reject) => {
    runtimeScript.addEventListener('load', resolve, { once: true });
    runtimeScript.addEventListener('error', () => reject(new Error('Go WebAssembly runtime could not be loaded.')), { once: true });
    document.head.append(runtimeScript);
  });
  if (typeof Go !== 'function') throw new Error('The Go WebAssembly runtime did not initialize.');
  const response = await fetch('/assets/cicada-webcrypto.wasm', { cache: 'no-store', credentials: 'omit' });
  if (!response.ok) throw new Error(`Hub WebCrypto module returned HTTP ${response.status}.`);
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength !== manifest.wasm_size) throw new Error('The Hub WebCrypto module size does not match its build manifest.');
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const digestHex = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
  if (digestHex !== manifest.wasm_sha256) throw new Error('The Hub WebCrypto module hash does not match its build manifest.');
  const go = new Go();
  const result = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(result.instance);
  const until = Date.now() + 5000;
  while (!globalThis.cicadaWebCryptoReady && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 20));
  if (!globalThis.cicadaWebCryptoReady) throw new Error('The Go Client Wire cryptography module did not start.');
  return globalThis.cicadaWebCrypto;
}

export async function fetchAndValidateHubIdentity(cryptoApi) {
  const identity = await getHubIdentity();
  if (identity.contract !== 'android-hub-v1' || !identity.hub_id ||
      !Number.isSafeInteger(identity.control_key_version) || identity.control_key_version !== 1 ||
      identity.suite !== 'ML-KEM-768+ML-DSA-65+AES-256-GCM') throw new Error('Hub identity response is incomplete or unsupported.');
  const validated = cryptoApi.validatePublicIdentity({ public_identity: identity.control_public_identity });
  if (!validated?.ok) throw new Error(validated?.error || 'Hub public identity failed Go PQ validation.');
  return identity;
}
