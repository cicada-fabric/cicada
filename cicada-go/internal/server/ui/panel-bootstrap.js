import { getHubIdentity } from './panel-client.js';

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
