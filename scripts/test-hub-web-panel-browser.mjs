#!/usr/bin/env node
// Disposable, real Chromium/CDP acceptance for the Hub browser Client.
// Uses only Node 24 built-ins; it never invokes npm or a resident deployment.

import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.umask(0o077);

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptPath = fileURLToPath(import.meta.url);
const chromiumRef = process.env.CICADA_CHROMIUM_IMAGE || 'chromedp/headless-shell:latest';
const hubRef = process.env.CICADA_HUB_IMAGE || '';
const expectedSourceFingerprint = process.env.CICADA_EXPECT_SOURCE_FINGERPRINT || '';
const metadataPath = path.resolve(repoRoot, process.env.CICADA_BUILD_METADATA || '');
const outputParent = path.join(repoRoot, '.cicada-data', 'hub-web-panel-browser');
const nodeVersion = process.versions.node;

function usage() {
  process.stdout.write(`Usage: CICADA_HUB_IMAGE=IMAGE CICADA_BUILD_METADATA=build.json CICADA_EXPECT_SOURCE_FINGERPRINT=64-lowercase-hex node scripts/test-hub-web-panel-browser.mjs\n\n` +
    `Optional: CICADA_CHROMIUM_IMAGE (default ${chromiumRef}), CICADA_BROWSER_RESULT_DIR (new evidence directory).\n`);
}

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  usage();
  process.exit(0);
}

if (!/^24\./.test(nodeVersion)) {
  process.stderr.write('BLOCKED: this browser gate requires Node 24 and its native WebSocket API.\n');
  process.exit(2);
}
if (typeof WebSocket !== 'function') {
  process.stderr.write('BLOCKED: Node 24 native WebSocket is unavailable.\n');
  process.exit(2);
}
if (!hubRef || !process.env.CICADA_BUILD_METADATA || !/^[0-9a-f]{64}$/.test(expectedSourceFingerprint)) {
  usage();
  process.stderr.write('BLOCKED: set CICADA_HUB_IMAGE, CICADA_BUILD_METADATA, and an explicit 64-character lowercase CICADA_EXPECT_SOURCE_FINGERPRINT.\n');
  process.exit(2);
}

const runStamp = new Date().toISOString().replaceAll(':', '').replaceAll('-', '').replace(/\.\d{3}Z$/, 'Z');
const suffix = `${runStamp.toLowerCase()}-${process.pid}-${randomBytes(4).toString('hex')}`;
const outputDir = path.resolve(process.env.CICADA_BROWSER_RESULT_DIR || path.join(outputParent, suffix));
const fixtureDir = path.join(outputDir, 'fixture');
const stateDir = path.join(fixtureDir, 'state');
const workspaceDir = path.join(fixtureDir, 'workspace');
const ownerPrivateDir = path.join(fixtureDir, 'owner-private');
const ownerPublicDir = path.join(fixtureDir, 'owner-public');
const hubEnvPath = path.join(fixtureDir, 'hub.env');
const browserDir = path.join(fixtureDir, 'browser');
const browserDownloads = path.join(browserDir, 'downloads');
const browserImports = path.join(browserDir, 'imports');
const hubContainer = `cicada-webpanel-${suffix}-hub`;
const browserContainer = `cicada-webpanel-${suffix}-chromium`;
const nodeContainer = `cicada-webpanel-${suffix}-node`;
const nodeStateDir = path.join(fixtureDir, 'node-state');
let nodeWasCreated = false;
let hubHostPort = '';
const dockerNetwork = `cicada-webpanel-${suffix}-net`;
const browserOriginHost = 'localhost';
const hubNetworkAlias = `cicada-webpanel-${suffix}-hub`;
const fixtureLabel = 'hub-web-panel-browser';

const result = {
  schema_version: 'cicada.hub-web-panel-browser.v1',
  gate: 'real_headless_chromium_cdp',
  status: 'FAIL',
  started_at: new Date().toISOString(),
  node_version: nodeVersion,
  scripts: {},
  hub: {},
  chromium: {},
  steps: {
    hub_fixture: 'NOT_RUN',
    manual_hub_pin_ceremony: 'NOT_RUN',
    production_go_wasm_loaded: 'NOT_RUN',
    encrypted_indexeddb_vault_and_unlock: 'NOT_RUN',
    offline_owner_grant_and_device_enrollment: 'NOT_RUN',
    encrypted_topology_status_and_canvas: 'NOT_RUN',
    topology_apply_group_visible: 'NOT_RUN',
    cross_tab_pending_request_refusal: 'NOT_RUN',
    first_tab_pending_cleared_after_release: 'NOT_RUN',
    uncertain_write_fence: 'NOT_RUN',
    response_loss_exact_recovery: 'NOT_RUN',
    canvas_pointer_keyboard_group_link_monitor: 'NOT_RUN',
    group_parent_preview_no_write: 'NOT_RUN',
    group_parent_confirm_cas: 'NOT_RUN',
    group_parent_restart_persistence: 'NOT_RUN',
    group_parent_repeat_drop_no_change: 'NOT_RUN',
    group_parent_cycle_rejected: 'NOT_RUN',
    group_parent_stale_cas_denied: 'NOT_RUN',
    group_parent_authority_unchanged: 'NOT_RUN',
    group_parent_uncertain_fence_no_write: 'NOT_RUN',
  },
  fixture_cleanup: { status: 'NOT_RUN' },
};

let phase = 'prerequisites';
let hubImageId = '';
let chromiumImageId = '';
let cdpHostPort = '';
let hubId = '';
let controlKeyId = '';
let ownerId = '';
let ownerKeyId = '';
let networkId = '';
let groupName = '';
let browserVersion = '';
let browserUserAgent = '';
let hubWasCreated = false;
let browserWasCreated = false;
let networkWasCreated = false;
let nestingFixture;
let pageA;
let pageB;
let fatal = null;

const pendingCDPSockets = new Set();
process.on('SIGINT', () => {
  fatal ||= new Error('interrupted');
  for (const connection of pendingCDPSockets) connection.close();
});
process.on('SIGTERM', () => {
  fatal ||= new Error('terminated');
  for (const connection of pendingCDPSockets) connection.close();
});

function fail(message) {
  throw new Error(message);
}

async function run(command, args, options = {}) {
  const capture = options.capture !== false;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd || repoRoot,
      env: options.env || process.env,
      stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'ignore',
    });
    let stdout = '';
    let stderr = '';
    if (capture) {
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', chunk => { if (stdout.length < 4 * 1024 * 1024) stdout += chunk; });
      child.stderr.on('data', chunk => { if (stderr.length < 4 * 1024 * 1024) stderr += chunk; });
    }
    child.on('error', reject);
    child.on('close', code => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function checked(command, args, options = {}) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    if (process.env.CICADA_BROWSER_DEBUG === '1' && result.stderr) {
      const diagnostic = result.stderr.trim().replaceAll(fixtureDir, '<fixture>').slice(0, 800);
      process.stderr.write(`${path.basename(command)} diagnostic: ${diagnostic}\n`);
    }
    fail(`${path.basename(command)} exited with status ${result.code}`);
  }
  return result.stdout;
}

async function docker(args, options = {}) {
  return checked('docker', args, options);
}

async function dockerJSON(args) {
  const text = await docker(args);
  try { return JSON.parse(text); } catch { fail('Docker returned invalid JSON for an inspect operation'); }
}

async function ensureDir(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
}

async function fileSHA256(file) {
  const hash = createHash('sha256');
  hash.update(await readFile(file));
  return hash.digest('hex');
}

function markStep(name) {
  result.steps[name] = 'PASS';
}

async function inspectImage(reference) {
  const [image] = await dockerJSON(['image', 'inspect', reference]);
  if (!image?.Id) fail(`Docker image is unavailable: ${reference}`);
  return image;
}

function portFromDocker(text) {
  const line = text.trim().split(/\r?\n/).find(Boolean);
  const match = line?.match(/:(\d+)$/);
  if (!match) fail('Docker did not publish a loopback TCP port');
  return match[1];
}

async function directJSON(url, timeoutMs = 2500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) fail(`Hub returned HTTP ${response.status} for a readiness request`);
    return await response.json();
  } finally { clearTimeout(timer); }
}

async function containerJSON(container, route) {
  const response = await run('docker', ['exec', container, 'wget', '-qO-', `http://127.0.0.1:8787${route}`]);
  if (response.code !== 0) fail('Disposable Hub did not return a local readiness response');
  try { return JSON.parse(response.stdout); } catch { fail('Disposable Hub returned invalid JSON during readiness'); }
}

async function waitHub(container, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  let lastFailure = null;
  while (Date.now() < deadline) {
    try {
      const health = await containerJSON(container, '/healthz');
      if (health.status !== 'ok') fail('Hub health response was not ready');
      const identity = await containerJSON(container, '/v2/client/identity');
      if (!identity.hub_id || !identity.control_public_identity?.id) fail('Hub identity is incomplete');
      return { health, identity };
    } catch (error) {
      lastFailure = error;
      await new Promise(resolve => setTimeout(resolve, 400));
    }
  }
  fail(`Hub did not become ready (${lastFailure?.name || 'timeout'}: ${String(lastFailure?.message || '').slice(0, 180)})`);
}

class CDP {
  constructor(socket) {
    this.socket = socket;
    this.nextID = 0;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener('message', event => this.onMessage(event.data));
    socket.addEventListener('close', () => this.rejectPending(new Error('CDP connection closed')));
    socket.addEventListener('error', () => this.rejectPending(new Error('CDP connection failed')));
  }

  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP WebSocket connection timed out')), 10000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('CDP WebSocket connection failed')); }, { once: true });
    });
    const connection = new CDP(socket);
    pendingCDPSockets.add(connection);
    return connection;
  }

  async onMessage(raw) {
    let message;
    try {
      const text = typeof raw === 'string' ? raw :
        raw instanceof ArrayBuffer ? Buffer.from(raw).toString('utf8') :
          typeof raw?.text === 'function' ? await raw.text() : String(raw);
      message = JSON.parse(text);
    }
    catch { return; }
    if (message.id) {
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.error) entry.reject(new Error(`CDP command ${entry.method} failed (${message.error.code})`));
      else entry.resolve(message.result || {});
      return;
    }
    const listeners = this.listeners.get(message.method) || [];
    for (const listener of [...listeners]) listener(message.params || {});
  }

  rejectPending(error) {
    for (const [id, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(error);
      this.pending.delete(id);
    }
  }

  send(method, params = {}, timeoutMs = 15000) {
    if (this.socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('CDP WebSocket is not open'));
    const id = ++this.nextID;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP command ${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, { method, resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  waitEvent(method, predicate = () => true, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      const listeners = this.listeners.get(method) || [];
      const listener = value => {
        if (!predicate(value)) return;
        clearTimeout(timer);
        this.listeners.set(method, listeners.filter(item => item !== listener));
        resolve(value);
      };
      const timer = setTimeout(() => {
        this.listeners.set(method, listeners.filter(item => item !== listener));
        reject(new Error(`CDP event ${method} timed out`));
      }, timeoutMs);
      listeners.push(listener);
      this.listeners.set(method, listeners);
    });
  }

  async evaluate(expression, timeoutMs = 15000) {
    const response = await this.send('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true, userGesture: true,
    }, timeoutMs);
    if (response.exceptionDetails) fail('Browser page script evaluation raised an exception');
    return response.result?.value;
  }

  close() {
    pendingCDPSockets.delete(this);
    try { this.socket.close(); } catch { /* best-effort close */ }
    this.rejectPending(new Error('CDP connection closed'));
  }
}

async function createPage(port, initialURL) {
  const response = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' });
  if (!response.ok) fail(`Chromium could not create a page target (HTTP ${response.status})`);
  const target = await response.json();
  const page = await CDP.connect(target.webSocketDebuggerUrl);
  await page.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await page.send('Page.enable');
  await page.send('Runtime.enable');
  await page.send('DOM.enable');
  await page.send('Network.enable');
  await page.send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: '/data/downloads' });
  await page.send('Page.navigate', { url: initialURL });
  return page;
}

async function evaluateUntil(page, expression, predicate = Boolean, timeoutMs = 30000, description = 'browser state') {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fatal) throw fatal;
    try {
      const value = await page.evaluate(expression, 5000);
      if (predicate(value)) return value;
    } catch (error) {
      if (error.message.includes('CDP connection')) throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  fail(`Timed out waiting for ${description}`);
}

async function buttonClick(page, label) {
  const expression = `(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === ${JSON.stringify(label)}); if (!b || b.disabled) return false; b.click(); return true; })()`;
  if (await page.evaluate(expression) !== true) fail(`Browser panel button is unavailable: ${label}`);
}

async function setInputValue(page, selector, value) {
  const expression = `(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (!e) return false; e.value = ${JSON.stringify(value)}; e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); return true; })()`;
  if (await page.evaluate(expression) !== true) fail(`Browser panel input is unavailable: ${selector}`);
}

async function setFileInput(page, selector, filePath) {
  const document = await page.send('DOM.getDocument', { depth: -1 });
  const queried = await page.send('DOM.querySelector', { nodeId: document.root.nodeId, selector });
  if (!queried.nodeId) fail(`Browser file input is unavailable: ${selector}`);
  await page.send('DOM.setFileInputFiles', { nodeId: queried.nodeId, files: [filePath] });
}

async function waitForDownload(filename, timeoutMs = 15000) {
  const target = path.join(browserDownloads, filename);
  const deadline = Date.now() + timeoutMs;
  let priorSize = -1;
  let stableCount = 0;
  while (Date.now() < deadline) {
    try {
      const info = await stat(target);
      if (info.isFile() && info.size > 0 && info.size === priorSize) stableCount++;
      else stableCount = 0;
      priorSize = info.size;
      const files = await readdir(browserDownloads);
      if (stableCount >= 2 && !files.some(file => file.endsWith('.crdownload'))) return target;
    } catch { /* download has not appeared yet */ }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  fail(`Browser download did not complete: ${filename}`);
}

async function readIndexedDBState(page) {
  const expression = `(() => new Promise((resolve,reject) => { const req=indexedDB.open('cicada-hub-web-panel-v1'); req.onerror=()=>reject(new Error('open')); req.onsuccess=()=>{ const db=req.result; const get=db.transaction('state','readonly').objectStore('state').get('owner-session'); get.onerror=()=>reject(new Error('read')); get.onsuccess=()=>{ const s=get.result||{}; const d=s.device||{}; const v=s.vault||{}; resolve({pinHubId:s.pin?.hubId||'',pinKeyId:s.pin?.keyId||'',pinOrigin:s.pin?.origin||'',active:d.active===true,ownerId:d.ownerId||'',deviceId:d.deviceId||'',nextRequestSequence:d.nextRequestSequence||0,nextResponseSequence:d.nextResponseSequence||0,pending:Boolean(d.pending),writeFence:Boolean(d.writeFence),vaultFormat:v.format||'',vaultCipher:v.cipher||'',vaultKdf:v.kdf||'',vaultIterations:v.iterations||0,ciphertextLength:(v.ciphertext||'').length,privateFieldStored:Object.keys(d).some(k=>/private|identity_blob|secret/i.test(k))||Object.keys(v).some(k=>/private|identity_blob|secret/i.test(k)),localStorageLength:localStorage.length}); db.close(); }; }; }))()`;
  return page.evaluate(expression);
}

async function checkNetworkCount(page, count) {
  return (page.rpcRequestCount || 0) >= count;
}

function emitRPCCounter(page) {
  page.rpcRequestCount = 0;
  page.listeners.set('Network.requestWillBeSent', [event => {
    if (event.request?.url?.includes('/v2/client/rpc')) page.rpcRequestCount++;
  }]);
}

async function waitForRPCCount(page, count, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fatal) throw fatal;
    if (await checkNetworkCount(page, count)) return page.rpcRequestCount;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  fail('Timed out waiting for the expected encrypted Client RPCs');
}

function fixtureLabels() {
  return [
    '--label', `org.cicada.fixture=${fixtureLabel}`,
    '--label', `org.cicada.fixture.dir=${fixtureDir}`,
  ];
}

async function startHubContainer() {
  const args = [
    'run', '-d', '--name', hubContainer,
    ...fixtureLabels(),
    '--label', `org.cicada.fixture.image-id=${hubImageId}`,
    '--network', dockerNetwork, '--network-alias', hubNetworkAlias,
    '-p', '127.0.0.1::8787',
    '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
    '--env-file', hubEnvPath,
    '-v', `${stateDir}:/state`, '-v', `${workspaceDir}:/workspace`,
    '-v', `${ownerPublicDir}:/owner-public:ro`,
    '-e', 'CICADA_STATE_DIR=/state', '-e', 'CICADA_WORKSPACE_ROOT=/workspace',
    hubImageId, 'serve', '--host', '0.0.0.0', '--port', '8787',
  ];
  await docker(args);
  hubWasCreated = true;
  hubHostPort = portFromDocker(await docker(['port', hubContainer, '8787/tcp']));
}

async function runCandidateCLI(args, mounts = []) {
  const dockerArgs = ['run', '--rm', '--network=none', '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`];
  for (const mount of mounts) dockerArgs.push('-v', mount);
  dockerArgs.push(hubImageId, ...args);
  return checked('docker', dockerArgs);
}

async function inspectOwnedContainer(name, expectedImageId) {
  const inspected = await run('docker', ['container', 'inspect', name]);
  if (inspected.code !== 0) return null;
  const [container] = JSON.parse(inspected.stdout);
  const labels = container.Config?.Labels || {};
  if (container.Image !== expectedImageId || labels['org.cicada.fixture'] !== fixtureLabel ||
      labels['org.cicada.fixture.dir'] !== fixtureDir) {
    fail(`Refusing to remove a container whose fixture ownership does not match: ${name}`);
  }
  return container;
}

async function removeOwnedContainer(name, expectedImageId) {
  const container = await inspectOwnedContainer(name, expectedImageId);
  if (!container) return false;
  await docker(['container', 'rm', '-f', name]);
  return true;
}

async function removeOwnedNetwork() {
  const inspected = await run('docker', ['network', 'inspect', dockerNetwork]);
  if (inspected.code !== 0) return false;
  const [network] = JSON.parse(inspected.stdout);
  const labels = network.Labels || {};
  if (labels['org.cicada.fixture'] !== fixtureLabel || labels['org.cicada.fixture.dir'] !== fixtureDir) {
    fail('Refusing to remove a Docker network whose fixture ownership does not match');
  }
  await docker(['network', 'rm', dockerNetwork]);
  return true;
}

async function setupHubFixture(metadata) {
  phase = 'fixture_setup';
  const suffixPart = suffix.replace(/[^a-z0-9]/g, '').slice(-18);
  ownerId = `browser_gate_owner_${suffixPart}`;
  const firstNetworkName = `Web Panel Browser ${suffixPart}`;
  await docker(['network', 'create',
    '--label', `org.cicada.fixture=${fixtureLabel}`,
    '--label', `org.cicada.fixture.dir=${fixtureDir}`, dockerNetwork]);
  networkWasCreated = true;
  phase = 'fixture_owner_key';
  const generated = await runCandidateCLI([
    'owner-key', 'generate', '--private', '/owner-private/owner-private.json',
    '--public', '/owner-public/owner-public.json',
  ], [`${ownerPrivateDir}:/owner-private`, `${ownerPublicDir}:/owner-public`]);
  let generatedSummary;
  try { generatedSummary = JSON.parse(generated); } catch { fail('Candidate Hub could not generate a synthetic Owner key'); }
  ownerKeyId = generatedSummary.key_id;
  if (!ownerKeyId) fail('Candidate Hub Owner key generation returned no key ID');
  const privateInfo = await stat(path.join(ownerPrivateDir, 'owner-private.json'));
  if (!privateInfo.isFile() || (privateInfo.mode & 0o777) !== 0o600) fail('Synthetic Owner private key was not created with mode 0600');

  phase = 'fixture_first_hub_start';
  await startHubContainer();
  let first;
  try { first = await waitHub(hubContainer); }
  catch { fail('Initial disposable Hub did not start or publish its identity'); }
  hubId = first.identity.hub_id;
  controlKeyId = first.identity.control_public_identity.id;

  phase = 'fixture_owner_network_setup';
  await docker(['stop', '--time', '10', hubContainer]);
  await runCandidateCLI([
    'owner-key', 'register', '--db', '/state/cicada.sqlite3', '--owner-id', ownerId,
    '--public', '/owner-public/owner-public.json', '--expect-key-id', ownerKeyId,
  ], [`${stateDir}:/state`, `${ownerPublicDir}:/owner-public:ro`]);
  const networkResultText = await runCandidateCLI([
    'network', 'create', '--db', '/state/cicada.sqlite3', '--hub', hubId,
    '--name', firstNetworkName, '--owner', ownerId,
  ], [`${stateDir}:/state`]);
  let networkResult;
  try { networkResult = JSON.parse(networkResultText); } catch { fail('Candidate Hub Network creation returned invalid JSON'); }
  networkId = networkResult.network_id;
  if (!networkId) fail('Candidate Hub Network creation returned no Network ID');
  const activationText = await runCandidateCLI(['network', 'activate', '--db', '/state/cicada.sqlite3'], [`${stateDir}:/state`]);
  let activation;
  try { activation = JSON.parse(activationText); } catch { fail('Candidate Hub Network activation returned invalid JSON'); }
  if (activation.phase !== 'ACTIVE') fail('Disposable owner Network did not become ACTIVE');
  phase = 'fixture_second_hub_start';
  await docker(['start', hubContainer]);
  const finalHub = await waitHub(hubContainer);
  if (finalHub.identity.hub_id !== hubId || finalHub.identity.control_public_identity.id !== controlKeyId) {
    fail('Hub identity changed across the disposable offline Owner setup');
  }
  result.hub = {
    image_reference: hubRef,
    image_id: hubImageId,
    source_revision: metadata.source.revision,
    source_dirty: metadata.source.dirty,
    source_fingerprint: metadata.source.source_fingerprint,
    catalog_sha256: metadata.source.catalog_sha256,
    hub_id: hubId,
    control_key_id: controlKeyId,
    owner_id: ownerId,
    owner_key_id: ownerKeyId,
    network_id: networkId,
    status: 'disposable_active_owner_network',
  };
  markStep('hub_fixture');
}

async function loadChromium() {
  phase = 'chromium_image';
  let inspected = await run('docker', ['image', 'inspect', chromiumRef]);
  if (inspected.code !== 0) {
    fail('Pinned Chromium image is absent; this gate does not pull images.');
  }
  if (inspected.code !== 0) fail('Disposable Chromium image could not be pulled or inspected');
  const [image] = JSON.parse(inspected.stdout);
  chromiumImageId = image.Id;
  result.chromium = {
    image_reference: chromiumRef,
    image_id: image.Id,
    repo_digests: image.RepoDigests || [],
    platform: `${image.Os}/${image.Architecture}`,
    secure_context_test_override: {
      origin: `http://${browserOriginHost}:8787`,
      routing: `Disposable Chromium socat listener at 127.0.0.1:8787 forwards to Hub alias ${hubNetworkAlias}:8787 over the fixture bridge.`,
      tls: false,
      public_https_validation: 'NOT_RUN',
    },
  };
}

async function startBrowser() {
  phase = 'browser_start';
  await docker([
    'run', '-d', '--name', browserContainer,
    ...fixtureLabels(), '--label', `org.cicada.fixture.image-id=${chromiumImageId}`,
    '--network', dockerNetwork, '-p', '127.0.0.1::9222', '--shm-size', '1g',
    '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
    '-v', `${browserDir}:/data`, chromiumRef,
    '--user-data-dir=/data/profile', '--disk-cache-dir=/data/cache',
    '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update',
  ]);
  browserWasCreated = true;
  const publishedPort = await run('docker', ['port', browserContainer, '9222/tcp']);
  if (publishedPort.code !== 0 && process.env.CICADA_BROWSER_DEBUG === '1') {
    const inspect = await run('docker', ['inspect', '--format', '{{.State.Status}} {{.State.ExitCode}} {{json .HostConfig.PortBindings}}', browserContainer]);
    const logs = await run('docker', ['logs', '--tail', '12', browserContainer]);
    process.stderr.write(`Chromium container diagnostic: ${(inspect.stdout || inspect.stderr).trim()}\n`);
    if (logs.stdout || logs.stderr) process.stderr.write(`Chromium startup log: ${(logs.stdout + logs.stderr).trim().slice(0, 1200)}\n`);
  }
  cdpHostPort = portFromDocker(publishedPort.stdout);
  const deadline = Date.now() + 30000;
  let lastFailure = null;
  while (Date.now() < deadline) {
    try {
      const version = await directJSON(`http://127.0.0.1:${cdpHostPort}/json/version`);
      browserVersion = version.Browser || '';
      if (!browserVersion.startsWith('Chrome/')) fail('Chromium DevTools identified a non-Chromium browser');
      const page = await createPage(cdpHostPort, 'about:blank');
      browserUserAgent = await page.evaluate('navigator.userAgent');
      page.close();
      result.chromium.browser_version = browserVersion;
      result.chromium.user_agent = browserUserAgent;
      const proxy = await run('docker', ['exec', '-d', browserContainer, '/usr/bin/socat',
        'TCP4-LISTEN:8787,bind=127.0.0.1,reuseaddr,fork', `TCP4:${hubNetworkAlias}:8787`]);
      if (proxy.code !== 0) fail('Could not start the disposable browser loopback-to-Hub TCP bridge');
      return;
    } catch (error) {
      lastFailure = error;
      await new Promise(resolve => setTimeout(resolve, 300));
    }
  }
  fail(`Disposable Chromium/CDP did not start (${lastFailure?.name || 'timeout'})`);
}

async function importFile(page, selector, file) {
  await setFileInput(page, selector, file);
}

async function runBrowserFlow() {
  phase = 'browser_panel_bootstrap';
  const origin = `http://${browserOriginHost}:8787`;
  pageA = await createPage(cdpHostPort, origin);
  emitRPCCounter(pageA);
  let firstText;
  try {
    firstText = await evaluateUntil(pageA, 'document.body.innerText',
      value => value.includes('Pin this Hub independently'), 45000, 'the independent Hub pin ceremony');
  } catch (error) {
    if (process.env.CICADA_BROWSER_DEBUG === '1') {
      const diagnostic = await pageA.evaluate(`({url:location.href,title:document.title,readyState:document.readyState,body:(document.body?.innerText||'').slice(0,1200)})`).catch(() => null);
      process.stderr.write(`Chromium page diagnostic: ${JSON.stringify(diagnostic)}\n`);
    }
    throw error;
  }
  if (firstText.includes('Secure Hub panel unavailable') || firstText.includes('Hub identity changed')) fail('Hub browser panel failed closed before pinning');
  const untrusted = await pageA.evaluate(`({canvas:!!document.querySelector('.workspace'),app:document.querySelector('#app')?.innerText||''})`);
  if (untrusted.canvas || !untrusted.app.includes('Pin this Hub independently')) fail('The first Hub identity was automatically trusted');
  markStep('manual_hub_pin_ceremony');
  await evaluateUntil(pageA, 'globalThis.cicadaWebCryptoReady === true && typeof globalThis.cicadaWebCrypto?.sealRequest === "function"',
    value => value === true, 45000, 'the production Go WebCrypto WASM module');
  markStep('production_go_wasm_loaded');

  await setInputValue(pageA, '#pin-hub-id', hubId);
  await setInputValue(pageA, '#pin-key-id', controlKeyId);
  await buttonClick(pageA, 'Pin this exact Hub identity');
  await evaluateUntil(pageA, 'document.querySelector("#owner-id") !== null', Boolean, 10000, 'device creation form');

  const password = `browser-only-${randomBytes(22).toString('base64url')}-24`;
  const deviceId = `browser-${suffix.slice(-18)}`;
  await setInputValue(pageA, '#owner-id', ownerId);
  await setInputValue(pageA, '#owner-key-id', ownerKeyId);
  await setInputValue(pageA, '#device-id', deviceId);
  await setInputValue(pageA, '#vault-password', password);
  await setInputValue(pageA, '#vault-confirm', password);
  await buttonClick(pageA, 'Create key and public enrollment manifest');
  await evaluateUntil(pageA, 'document.querySelector("#signer-summary") !== null', Boolean, 45000, 'Owner grant import form');
  const manifestPath = await waitForDownload('cicada-device-enrollment.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.hub_id !== hubId || manifest.owner_id !== ownerId || manifest.device_id !== deviceId ||
      manifest.owner_key_id !== ownerKeyId || manifest.purpose !== 'CLIENT_CONTROL' ||
      !/^[0-9a-f]{64}$/.test(manifest.device_key_fingerprint || '')) {
    fail('Browser enrollment manifest does not match the independently pinned disposable identities');
  }
  const indexedDB = await readIndexedDBState(pageA);
  if (indexedDB.pinHubId !== hubId || indexedDB.pinKeyId !== controlKeyId || indexedDB.pinOrigin !== origin ||
      indexedDB.vaultFormat !== 'cicada.browser-device-vault.v1' || indexedDB.vaultCipher !== 'AES-256-GCM' ||
      indexedDB.vaultKdf !== 'PBKDF2-SHA-256' || indexedDB.vaultIterations !== 600000 ||
      indexedDB.ciphertextLength < 64 || indexedDB.privateFieldStored || indexedDB.localStorageLength !== 0) {
    fail('Browser did not save a pinned Hub and password-encrypted IndexedDB device vault');
  }
  result.browser_vault = {
    indexeddb_pinned_hub_matches: true,
    aes_gcm: indexedDB.vaultCipher,
    kdf: indexedDB.vaultKdf,
    iterations: indexedDB.vaultIterations,
    ciphertext_present: true,
    plaintext_private_fields_stored: false,
    local_storage_entries: indexedDB.localStorageLength,
  };

  phase = 'offline_owner_grant';
  const expiry = new Date(Date.now() + 45 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const summaryText = await runCandidateCLI([
    'owner', 'device-grant-sign', '--private', '/owner-private/owner-private.json',
    '--manifest', '/data/downloads/cicada-device-enrollment.json',
    '--output', '/data/imports/owner-device-grant.json',
    '--expect-owner-id', ownerId, '--expect-owner-key-id', ownerKeyId,
    '--expect-hub-id', hubId, '--expect-device-id', deviceId,
    '--expect-device-key-id', manifest.device_public_identity.id,
    '--expect-device-fingerprint', manifest.device_key_fingerprint,
    '--expires-at', expiry,
  ], [`${ownerPrivateDir}:/owner-private:ro`, `${browserDir}:/data`]);
  const grantInfo = await stat(path.join(browserImports, 'owner-device-grant.json'));
  if (!grantInfo.isFile() || (grantInfo.mode & 0o777) !== 0o600) fail('Offline signer did not create a 0600 Owner grant');
  const signerSummary = path.join(browserImports, 'signer-summary.json');
  // The signer stdout is public scope information; the Owner private key never
  // enters the browser volume or its command line.
  await writeFile(signerSummary, summaryText, { mode: 0o600, flag: 'wx' });
  const signed = JSON.parse(await readFile(signerSummary, 'utf8'));
  if (signed.owner_key_id !== ownerKeyId || signed.hub_id !== hubId ||
      signed.device_key_id !== manifest.device_public_identity.id ||
      signed.device_key_fingerprint !== manifest.device_key_fingerprint ||
      !signed.owner_public_identity?.id) fail('Offline Owner signer summary did not match the public browser manifest');
  await importFile(pageA, '#signer-summary', '/data/imports/signer-summary.json');
  await importFile(pageA, '#grant-file', '/data/imports/owner-device-grant.json');
  await buttonClick(pageA, 'Verify grant and enroll exact request');
  await evaluateUntil(pageA, 'document.querySelector(".workspace") !== null && document.querySelector(".stage svg") !== null',
    Boolean, 60000, 'the encrypted Owner topology canvas');
  await waitForRPCCount(pageA, 2, 30000);
  const enrollState = await readIndexedDBState(pageA);
  if (!enrollState.active || enrollState.pending || enrollState.writeFence || enrollState.nextRequestSequence < 3 ||
      enrollState.nextResponseSequence < 3 || enrollState.deviceId !== deviceId || enrollState.privateFieldStored) {
    fail('Browser did not finish encrypted device enrollment and initial topology/status requests');
  }
  const canvasText = await pageA.evaluate('document.querySelector("#app")?.innerText || ""');
  if (!canvasText.includes('Live status snapshot') || !canvasText.includes('OWNER SESSION') || !canvasText.includes('Shared Thread memory')) {
    fail('Encrypted topology and status snapshots did not reach the live canvas view');
  }
  result.browser_vault.device_active_after_enrollment = true;
  result.browser_vault.transport_sequences_advanced = true;
  markStep('offline_owner_grant_and_device_enrollment');

  phase = 'browser_vault_unlock';
  await buttonClick(pageA, 'Lock device');
  await evaluateUntil(pageA, 'document.querySelector("#unlock-password") !== null', Boolean, 10000, 'password unlock form');
  await setInputValue(pageA, '#unlock-password', password);
  await buttonClick(pageA, 'Unlock device key');
  await evaluateUntil(pageA, 'document.querySelector(".workspace") !== null && document.querySelector(".stage svg") !== null',
    Boolean, 60000, 'Canvas after restoring the encrypted vault');
  const unlockedState = await readIndexedDBState(pageA);
  if (!unlockedState.active || unlockedState.privateFieldStored || unlockedState.localStorageLength !== 0) {
    fail('Reloaded browser device key did not unlock from the encrypted IndexedDB vault');
  }
  result.browser_vault.password_unlock_after_lock = true;
  markStep('encrypted_indexeddb_vault_and_unlock');
  markStep('encrypted_topology_status_and_canvas');

  phase = 'canvas_topology_apply';
  groupName = `Browser Gate Group ${suffix.slice(-8)}`;
  const groupFormFound = await pageA.evaluate(`(() => [...document.querySelectorAll('.side .card')].some(c => c.querySelector('h2')?.textContent.trim()==='Create Group'))()`);
  if (!groupFormFound) fail('Owner Network Group creation form is unavailable in the Canvas');
  const selectNetwork = `(() => { const c=[...document.querySelectorAll('.side .card')].find(x=>x.querySelector('h2')?.textContent.trim()==='Create Group'); const s=c?.querySelector('select'); if(!s) return false; s.value=${JSON.stringify(networkId)}; s.dispatchEvent(new Event('change',{bubbles:true})); const i=c.querySelector('input'); if(!i) return false; i.value=${JSON.stringify(groupName)}; i.dispatchEvent(new Event('input',{bubbles:true})); return true; })()`;
  if (await pageA.evaluate(selectNetwork) !== true) fail('Could not select the active Network and set the synthetic Group name');
  await buttonClick(pageA, 'Preview Group creation');
  await evaluateUntil(pageA, 'document.querySelector(".side")?.innerText || ""',
    value => value.includes('Exact action preview') && value.includes(groupName) && value.includes('group.create'),
    10000, 'the exact topology.apply Group action preview');
  await buttonClick(pageA, 'Commit this one action');
  await evaluateUntil(pageA, `([...document.querySelectorAll('text.group-label')].some(x=>x.textContent===${JSON.stringify(groupName)}))`,
    Boolean, 60000, 'the newly created Group in the server-refreshed SVG canvas');
  await waitForRPCCount(pageA, 5, 30000);
  const afterGroup = await readIndexedDBState(pageA);
  if (afterGroup.pending || afterGroup.writeFence || !afterGroup.active) fail('Successful topology change left the browser request in an unresolved state');
  result.canvas = { group_name: groupName, svg_group_visible: true, rpc_request_count: pageA.rpcRequestCount };
  markStep('topology_apply_group_visible');

  phase = 'cross_tab_pending_guard';
  pageB = await createPage(cdpHostPort, origin);
  emitRPCCounter(pageB);
  await evaluateUntil(pageB, 'document.querySelector("#unlock-password") !== null', Boolean, 45000, 'second-tab device unlock form');
  await setInputValue(pageB, '#unlock-password', password);
  await buttonClick(pageB, 'Unlock device key');
  await evaluateUntil(pageB, 'document.querySelector(".workspace") !== null && document.querySelector(".stage svg") !== null',
    Boolean, 60000, 'second-tab authoritative Canvas');
  const beforePauseState = await readIndexedDBState(pageA);
  const beforePauseRPCCount = pageA.rpcRequestCount;

  await pageA.send('Fetch.enable', { patterns: [{ urlPattern: '*://*/v2/client/rpc*', requestStage: 'Request' }] });
  const pausedRequestPromise = pageA.waitEvent('Fetch.requestPaused', event => event.request?.url?.includes('/v2/client/rpc'), 30000);
  await buttonClick(pageA, 'Refresh snapshots');
  const paused = await pausedRequestPromise;
  const pendingSeen = await evaluateUntil(pageB, `(() => new Promise(resolve=>{const o=indexedDB.open('cicada-hub-web-panel-v1');o.onsuccess=()=>{const r=o.result.transaction('state','readonly').objectStore('state').get('owner-session');r.onsuccess=()=>{resolve(Boolean(r.result?.device?.pending));o.result.close();};};}))()`,
    value => value === true, 10000, 'the first tab reserved its exact request in shared IndexedDB');
  if (!pendingSeen) fail('Paused first-tab request was not reserved before network submission');
  const beforeBlockedAttempt = pageB.rpcRequestCount;
  await buttonClick(pageB, 'Refresh snapshots');
  await evaluateUntil(pageB, 'document.querySelector("#app")?.innerText || ""',
    value => value.includes('Resolve the saved Client request') && value.includes('A Client request is unresolved'),
    15000, 'second-tab refusal while the first packet is pending');
  const afterBlockedAttempt = pageB.rpcRequestCount;
  if (afterBlockedAttempt !== beforeBlockedAttempt) fail('Second tab sent another RPC while the exact first request was pending');
  markStep('cross_tab_pending_request_refusal');
  await pageA.send('Fetch.continueRequest', { requestId: paused.requestId });
  await pageA.send('Fetch.disable');
  await waitForRPCCount(pageA, beforePauseRPCCount + 2, 15000);
  const settledStateExpression = `(() => new Promise(resolve=>{const o=indexedDB.open('cicada-hub-web-panel-v1');o.onsuccess=()=>{const r=o.result.transaction('state','readonly').objectStore('state').get('owner-session');r.onsuccess=()=>{const d=r.result?.device||{};resolve({pending:Boolean(d.pending),nextRequestSequence:d.nextRequestSequence||0,nextResponseSequence:d.nextResponseSequence||0});o.result.close();};};}))()`;
  await evaluateUntil(pageA,
    settledStateExpression,
    value => !value.pending && value.nextRequestSequence === beforePauseState.nextRequestSequence + 2 &&
      value.nextResponseSequence === beforePauseState.nextResponseSequence + 2,
    15000, 'both first-tab snapshot responses processing after releasing the exact request');
  const finalState = await readIndexedDBState(pageA);
  if (finalState.pending || finalState.writeFence ||
      finalState.nextRequestSequence !== beforePauseState.nextRequestSequence + 2 ||
      finalState.nextResponseSequence !== beforePauseState.nextResponseSequence + 2) {
    fail(`First-tab refresh did not resolve cleanly after release (request ${beforePauseState.nextRequestSequence}->${finalState.nextRequestSequence}, response ${beforePauseState.nextResponseSequence}->${finalState.nextResponseSequence}, pending=${finalState.pending})`);
  }
  markStep('first_tab_pending_cleared_after_release');
  await prepareNestingFixture(password);
  await runResponseLossAndUncertainty(password);
  await runInteractionAndFaultFlow(password);
  await runNestingFlow(password);
}

// Fixture setup uses actual PQ Owner approval and Node-authenticated APIs.
// The adapter session labels below are synthetic, never native-runtime evidence.
async function ownerFixtureRPC(password, operation, input, allowError = false) {
  return pageA.evaluate(`(async()=>{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();let key;try{const state=await c.getState(db);let blob=await c.decryptIdentityBlob(state.vault,${JSON.stringify(password)});key=cicadaWebCrypto.importIdentity({identity_blob:blob});blob='';if(!key.ok)throw Error('fixture key import');const reply=await c.callRPC(db,cicadaWebCrypto,{handle:key.handle},${JSON.stringify(operation)},${JSON.stringify(input)});if(${JSON.stringify(allowError)})return reply;if(!reply.ok)throw Error('fixture RPC denied');return reply.result;}finally{if(key?.handle)cicadaWebCrypto.forgetIdentity({handle:key.handle});db.close();}})()`, 30000);
}

async function prepareNestingFixture(password) {
  phase = 'group_parent_fixture';
  const create = async name => (await ownerFixtureRPC(password, 'topology.apply', {
    kind: 'group.create', create_group: { group: { network_id: networkId, name } }
  })).group;
  const parent = await create(`Z V66 Parent ${suffix.slice(-8)}`);
  const child = await create(`Z V66 Child ${suffix.slice(-8)}`);
  if (!parent?.group_id || !child?.group_id || child.version < 1) fail('V66 fixture lacks current Groups');
  nestingFixture = { child: child.group_id, parent: parent.group_id };
  await buttonClick(pageA, 'Refresh snapshots');
  await evaluateUntil(pageA, `document.querySelector('[data-group-drag-id="${child.group_id}"]') !== null`);
}

async function dragGroup(childId, parentId) {
  const sourceSelector = `[data-group-drag-id="${childId}"]`;
  const targetSelector = parentId ? `[data-group-drop-id="${parentId}"]` : `[data-network-root-drop-id="${networkId}"]`;
  await fitCanvasTargets([sourceSelector, targetSelector]);
  await buttonClick(pageA, 'Nest Group');
  const source = await elementBox(pageA, sourceSelector);
  const target = parentId ? await visibleGroupDropPoint(parentId) : await elementBox(pageA, targetSelector);
  if (!source || !target) fail('Group nesting pointer targets are not visible');
  const from = { x: source.x + source.width / 2, y: source.y + source.height / 2 };
  const to = parentId ? target : { x: target.x + target.width / 2, y: target.y + target.height / 2 };
  const exact = await pageA.evaluate(`document.elementFromPoint(${from.x},${from.y})?.closest('[data-group-drag-id]')?.getAttribute('data-group-drag-id')===${JSON.stringify(childId)}`);
  if (!exact) fail('Group nesting drag source is not the exact visible Group label');
  await pointerDrag(pageA, from, to, parentId);
}

async function runNestingFlow(password) {
  phase = 'group_parent_preview_and_confirm';
  const snapshot = () => ownerFixtureRPC(password, 'topology.snapshot', {});
  const group = (data, id) => data.groups.find(item => item.group_id === id);
  const authority = data => JSON.stringify({ memberships: data.memberships, endpoints: data.endpoints.map(({presence, ...endpoint}) => endpoint), links: data.links });
  const refreshNesting = async () => {
    const device = await readIndexedDBState(pageA);
    if (device.pending) fail('Nesting refresh begins with an unresolved packet');
    const requests = pageA.rpcRequestCount;
    await buttonClick(pageA, 'Refresh snapshots');
    await evaluateUntil(pageA, `(async()=>{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();try{const d=(await c.getState(db)).device;return !d?.pending&&d.nextRequestSequence===${device.nextRequestSequence + 2}&&d.nextResponseSequence===${device.nextResponseSequence + 2}&&document.querySelector('.status-banner')?.textContent==='Authoritative topology and status snapshots refreshed.';}finally{db.close();}})()`, Boolean, 30000, 'both authenticated nesting snapshots and resolved pending state');
    await waitForRPCCount(pageA, requests + 2);
    if (pageA.rpcRequestCount !== requests + 2) fail('Nesting refresh issued unexpected extra RPC');
    await pageA.evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    result.group_parent_refreshes = [...(result.group_parent_refreshes || []),
      { authenticated_snapshots: 2, pending_resolved: true, exact_request_delta: 2 }];
  };
  const before = await snapshot();
  await refreshNesting();
  await evaluateUntil(pageA, `document.querySelector('[data-group-drag-id="${nestingFixture.child}"]') !== null`);
  const count = pageA.rpcRequestCount;
  await dragGroup(nestingFixture.child, nestingFixture.parent);
  const preview = await pageA.evaluate(`(()=>{const p=document.querySelector('.side pre');return p?JSON.parse(p.textContent):null;})()`);
  result.group_parent_preview_diagnostic = { rpc_before: count, rpc_after: pageA.rpcRequestCount, preview_present: !!preview, kind_matches: preview?.kind === 'group.set_parent', child_matches: preview?.set_parent?.group_id === nestingFixture.child, parent_matches: preview?.set_parent?.parent_group_id === nestingFixture.parent, version_matches: preview?.set_parent?.expected_group_version === group(before, nestingFixture.child).version, pending: (await readIndexedDBState(pageA)).pending };
  if (pageA.rpcRequestCount !== count || preview?.kind !== 'group.set_parent' ||
      preview.set_parent.group_id !== nestingFixture.child || preview.set_parent.parent_group_id !== nestingFixture.parent ||
      preview.set_parent.expected_group_version !== group(before, nestingFixture.child).version) fail('Nesting drag lost exact scope/CAS or wrote before confirmation');
  markStep('group_parent_preview_no_write');
  await committedAction();
  let current = await snapshot();
  if (group(current, nestingFixture.child).parent_group_id !== nestingFixture.parent ||
      group(current, nestingFixture.child).version !== group(before, nestingFixture.child).version + 1) fail('Confirmed nesting did not apply one child CAS');
  markStep('group_parent_confirm_cas');
  if (nodeWasCreated) await docker(['stop', '--time', '10', nodeContainer]);
  await docker(['stop', '--time', '10', hubContainer]); await docker(['start', hubContainer]);
  const restarted = await waitHub(hubContainer);
  if (restarted.identity.hub_id !== hubId || restarted.identity.control_public_identity.id !== controlKeyId) fail('Nesting restart changed Hub pins');
  hubHostPort = portFromDocker(await docker(['port', hubContainer, '8787/tcp']));
  if (nodeWasCreated) await docker(['start', nodeContainer]);
  const persisted = await snapshot();
  if (group(persisted, nestingFixture.child).parent_group_id !== nestingFixture.parent ||
      group(persisted, nestingFixture.child).version !== group(current, nestingFixture.child).version) fail('Nesting parent/version did not persist');
  markStep('group_parent_restart_persistence');
  await refreshNesting();
  await evaluateUntil(pageA, `document.querySelector('[data-group-drag-id="${nestingFixture.child}"]') !== null`);
  const repeatCount = pageA.rpcRequestCount;
  await dragGroup(nestingFixture.child, nestingFixture.parent);
  if (pageA.rpcRequestCount !== repeatCount || await pageA.evaluate('document.querySelector(".side pre") !== null')) fail('Duplicate parent drop prepared a write');
  await ownerFixtureRPC(password, 'topology.apply', { kind: 'group.set_parent', set_parent: {
    group_id: nestingFixture.child, parent_group_id: nestingFixture.parent,
    expected_group_version: group(current, nestingFixture.child).version } });
  current = await snapshot();
  if (group(current, nestingFixture.child).version !== group(persisted, nestingFixture.child).version) fail('Same-parent current CAS was not idempotent');
  markStep('group_parent_repeat_drop_no_change');
  const cycleCount = pageA.rpcRequestCount;
  await dragGroup(nestingFixture.parent, nestingFixture.child);
  if (pageA.rpcRequestCount !== cycleCount || await pageA.evaluate('document.querySelector(".side pre") !== null')) fail('Ancestor cycle drag prepared a write');
  const cycle = await ownerFixtureRPC(password, 'topology.apply', { kind: 'group.set_parent', set_parent: {
    group_id: nestingFixture.parent, parent_group_id: nestingFixture.child,
    expected_group_version: group(current, nestingFixture.parent).version } }, true);
  if (cycle.ok !== false || cycle.error !== 'group hierarchy cycle') fail('Authoritative encrypted cycle denial was not exact');
  markStep('group_parent_cycle_rejected');
  await dragGroup(nestingFixture.child, '');
  await committedAction();
  current = await snapshot();
  if (group(current, nestingFixture.child).parent_group_id || group(current, nestingFixture.child).version !== group(persisted, nestingFixture.child).version + 1) fail('Explicit Network root drop did not apply one CAS');
  phase = 'group_parent_stale_preview_cas';
  // Capture only public failure classification; wrapper calls the original product RPC unchanged.
  await pageA.evaluate(`(async()=>{const {CanvasPanel}=await import('/assets/panel-canvas.js');const original=CanvasPanel.prototype.applyFirst;CanvasPanel.prototype.applyFirst=async function(){const rpc=this.rpc;this.rpc=async(op,input)=>{try{return await rpc(op,input);}catch(error){if(op==='topology.apply'&&input?.set_parent)globalThis.v66StaleFailure={versionConflict:error.message==='session binding version conflict',operationBound:!!error.operationID};throw error;}};try{return await original.call(this);}finally{this.rpc=rpc;}};})()`);
  await dragGroup(nestingFixture.child, nestingFixture.parent);
  const stale = await pageA.evaluate('JSON.parse(document.querySelector(".side pre").textContent)');
  const otherParent = before.groups.find(item => item.network_id === networkId && item.group_id !== nestingFixture.child && item.group_id !== nestingFixture.parent);
  if (!otherParent) fail('Current scoped alternate parent is absent');
  await ownerFixtureRPC(password, 'topology.apply', { kind: 'group.set_parent', set_parent: {
    group_id: nestingFixture.child, parent_group_id: otherParent.group_id,
    expected_group_version: stale.set_parent.expected_group_version } });
  const staleCount = pageA.rpcRequestCount;
  await committedAction();
  const denial = await pageA.evaluate('globalThis.v66StaleFailure');
  current = await snapshot();
  if (!denial?.versionConflict || !denial.operationBound || pageA.rpcRequestCount !== staleCount + 4 ||
      group(current, nestingFixture.child).parent_group_id !== otherParent.group_id ||
      group(current, nestingFixture.child).version !== stale.set_parent.expected_group_version + 1 ||
      await pageA.evaluate('document.querySelector(".side pre") !== null')) fail('Stale nesting CAS was refreshed, retried or applied');
  markStep('group_parent_stale_cas_denied');
  if (authority(current) !== authority(before)) fail('Nesting changed Membership, role/grant, Endpoint reference or Link authority');
  markStep('group_parent_authority_unchanged');
  result.group_parent = { child_id: nestingFixture.child, original_parent_id: nestingFixture.parent,
    final_parent_id: otherParent.group_id, final_child_version: group(current, nestingFixture.child).version,
    root_previewed: true, root_committed: true, stale_denial_authenticated: true, metadata_authority_unchanged: true,
    peer_decryption_denial: 'NOT_RUN', uncertain_scope: 'controlled synthetic interrupted state; not an actual kill window' };
}

async function syntheticNodeEndpoints(password) {
  phase = 'synthetic_node_owner_approval';
  const nodeID = `browser-node-${suffix.slice(-8)}`;
  await docker(['run', '-d', '--name', nodeContainer, ...fixtureLabels(),
    '--label', `org.cicada.fixture.image-id=${hubImageId}`, '--network', `container:${hubContainer}`,
    '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
    '-v', `${nodeStateDir}:/node-state`, '-e', `CICADA_HUB_ID=${hubId}`,
    hubImageId, 'machine', 'agent', '--id', nodeID, '--name', 'Synthetic browser adapter',
    '--control-url', 'http://127.0.0.1:8787', '--state-dir', '/node-state', '--interval', '1s', '--relay-only']);
  nodeWasCreated = true;
  const local = path.join(nodeStateDir, 'nodes', `node-${nodeID}`);
  let code = '';
  const deadline = Date.now() + 30000;
  while (!code && Date.now() < deadline) {
    try { code = JSON.parse(await readFile(path.join(local, 'node-control-state.json'), 'utf8')).pending_pairing_user_code || ''; }
    catch { /* Node has not published its PQ candidate yet. */ }
    if (!code) await new Promise(resolve => setTimeout(resolve, 200));
  }
  if (!code) fail('Synthetic Node did not publish a PQ pairing candidate');
  const preview = await ownerFixtureRPC(password, 'nodes.preview', { user_code: code });
  if (preview.node_id !== nodeID || !preview.candidate_digest || !preview.version) fail('Owner preview did not bind the exact synthetic Node candidate');
  const confirmed = await ownerFixtureRPC(password, 'nodes.confirm', { user_code: code,
    candidate_digest: preview.candidate_digest, candidate_version: preview.version });
  if (confirmed.node_id !== nodeID || confirmed.state !== 'ACTIVE') fail('Owner did not confirm the exact synthetic Node');
  const token = (await readFile(path.join(local, 'relay.token'), 'utf8')).trim();
  const endpoints = [];
  for (let index = 0; index < 2; index++) {
    const session = `synthetic-browser-session-${suffix.slice(-8)}-${index}`;
    const inviteName = `browser-${index}.invite`, proofName = `browser-${index}.proof`;
    const grants = 'directory.discover,directory.publish';
    await docker(['stop', '--time', '10', nodeContainer]);
    await docker(['stop', '--time', '10', hubContainer]);
    await runCandidateCLI(['network', 'invite', '--db', '/state/cicada.sqlite3', '--network', networkId,
      '--target-owner', ownerId, '--invitation-file', `/owner-private/${inviteName}`, '--grants', grants, '--ttl', '15m'],
    [`${stateDir}:/state`, `${ownerPrivateDir}:/owner-private`]);
    await runCandidateCLI(['network', 'consent-sign', '--owner-private', '/owner-private/owner-private.json',
      '--proof-file', `/owner-private/${proofName}`, '--invitation-file', `/owner-private/${inviteName}`,
      '--owner', ownerId, '--hub', hubId, '--network', networkId, '--node', nodeID,
      '--session', session, '--grants', grants, '--discoverable'], [`${ownerPrivateDir}:/owner-private`]);
    await docker(['start', hubContainer]); await waitHub(hubContainer);
    hubHostPort = portFromDocker(await docker(['port', hubContainer, '8787/tcp']));
    await docker(['start', nodeContainer]);
    const response = await fetch(`http://127.0.0.1:${hubHostPort}/v2/fabric/node/networks/join`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `CicadaNode ${token}` },
      body: JSON.stringify({ network_id: networkId, invitation_token: (await readFile(path.join(ownerPrivateDir, inviteName), 'utf8')).trim(),
        owner_join_proof: (await readFile(path.join(ownerPrivateDir, proofName), 'utf8')).trim(), harness: 'codex',
        native_session_id: session, endpoint_name: `Synthetic Browser Endpoint ${index}` }) });
    if (response.status !== 201) fail(`Synthetic Node-authenticated Network Join rejected (HTTP ${response.status})`);
    const joined = await response.json();
    if (!joined.endpoint?.endpoint_id || joined.network_id !== networkId) fail('Synthetic Network Join returned inconsistent scope');
    const bindingResponse = await fetch(`http://127.0.0.1:${hubHostPort}/v2/fabric/networks/${networkId}/direct/native-binding`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Cicada-Network-Session ${joined.session_token}` }, body: '{}' });
    if (bindingResponse.status !== 200) fail(`Directory-only native-binding registration rejected (HTTP ${bindingResponse.status})`);
    const binding = await bindingResponse.json();
    if (binding.endpoint_id !== joined.endpoint.endpoint_id || binding.node_id !== nodeID ||
        binding.native_session_id !== session || binding.status !== 'active' || !binding.binding_id || binding.epoch < 1) {
      fail('Synthetic native-binding scope did not match exact enrolled Endpoint');
    }
    endpoints.push(joined.endpoint.endpoint_id);
  }
  result.synthetic_adapter = { owner_pq_confirmed: true, network_join_protocol: 'PASS', native_binding_protocol: 'PASS',
    endpoint_ids: endpoints, native_session_verification: 'NOT_RUN', model_calls: 0 };
  return endpoints;
}

async function cardField(page, title, tag, index, value) {
  const changed = await page.evaluate(`(()=>{const c=[...document.querySelectorAll('.side .card')].find(x=>x.querySelector('h2')?.textContent===${JSON.stringify(title)});const e=c?.querySelectorAll(${JSON.stringify(tag)})[${index}];if(!e)return false;e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
  if (!changed) fail(`Canvas field missing in ${title}`);
}

async function elementBox(page, selector) {
  return page.evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return null;const b=e.getBoundingClientRect();return{x:b.x,y:b.y,width:b.width,height:b.height};})()`);
}

async function pointerDrag(page, from, to, expectedGroupID = '') {
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: from.x, y: from.y });
  await page.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: from.x, y: from.y, button: 'left', buttons: 1, clickCount: 1 });
  for (let i = 1; i <= 6; i++) await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', button: 'left',
    x: from.x + (to.x - from.x) * i / 6, y: from.y + (to.y - from.y) * i / 6, buttons: 1 });
  // CDP acknowledgements can precede delivery of coalesced pointer moves.
  await page.evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  const outline = await page.evaluate(`(()=>{const svg=document.querySelector('.stage svg');const r=svg?.querySelector('.selection-box');const b=svg?.getBoundingClientRect();return r&&b?{visible:r.getAttribute('visibility'),x:Number(r.getAttribute('x')),y:Number(r.getAttribute('y')),width:Number(r.getAttribute('width')),height:Number(r.getAttribute('height')),svgX:b.x,svgY:b.y}:null;})()`);
  if (expectedGroupID) {
    const hit = await page.evaluate(`(()=>{const e=document.elementFromPoint(${to.x},${to.y});return{type:e?.tagName||'NONE',matches_target:e?.closest('[data-group-drop-id]')?.getAttribute('data-group-drop-id')===${JSON.stringify(expectedGroupID)}};})()`);
    result.group_drop_diagnostic = [...(result.group_drop_diagnostic || []), hit];
    if (!hit.matches_target) fail('Actual Group drop point was obscured before pointer release');
  }
  await page.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: to.x, y: to.y, button: 'left', buttons: 0, clickCount: 1 });
  return outline;
}

async function visibleGroupDropPoint(groupID) {
  const box = await elementBox(pageA, `[data-group-drop-id="${groupID}"]`);
  if (!box) fail('Exact Group drop rectangle is absent');
  for (const y of [0.5, 0.7, 0.3, 0.85]) for (const x of [0.5, 0.7, 0.3, 0.85]) {
    const point = { x: box.x + box.width * x, y: box.y + box.height * y };
    const hit = await pageA.evaluate(`(()=>{const e=document.elementFromPoint(${point.x},${point.y});return{type:e?.tagName||'NONE',matches_target:e?.closest('[data-group-drop-id]')?.getAttribute('data-group-drop-id')===${JSON.stringify(groupID)}};})()`);
    if (hit.matches_target) {
      result.group_drop_diagnostic = [...(result.group_drop_diagnostic || []), hit];
      return point;
    }
  }
  fail('No visible Group drop point matches the exact target');
}

async function fitCanvasTargets(selectors) {
  await pageA.evaluate('window.scrollTo(0,0)');
  for (let attempt = 0; attempt < 12; attempt++) {
    const svg = await elementBox(pageA, '.stage svg');
    const boxes = await Promise.all(selectors.map(selector => elementBox(pageA, selector)));
    if (!svg || boxes.some(box => !box)) fail('Canvas targets are absent before a pointer gesture');
    const bounds = { left: Math.min(...boxes.map(box => box.x)), top: Math.min(...boxes.map(box => box.y)),
      right: Math.max(...boxes.map(box => box.x + box.width)), bottom: Math.max(...boxes.map(box => box.y + box.height)) };
    const visible = { left: svg.x + 15, right: svg.x + svg.width - 15,
      top: svg.y + 120, bottom: Math.min(svg.y + svg.height - 45, 985) };
    if (bounds.left >= visible.left && bounds.right <= visible.right && bounds.top >= visible.top && bounds.bottom <= visible.bottom) {
      await buttonClick(pageA, 'Select');
      return;
    }
    if (bounds.right - bounds.left > visible.right - visible.left || bounds.bottom - bounds.top > visible.bottom - visible.top) {
      await buttonClick(pageA, '−');
      continue;
    }
    const dx = Math.max(-svg.width / 3, Math.min(svg.width / 3, (visible.left + visible.right - bounds.left - bounds.right) / 2));
    const dy = Math.max(-svg.height / 3, Math.min(svg.height / 3, (visible.top + visible.bottom - bounds.top - bounds.bottom) / 2));
    await buttonClick(pageA, 'Pan');
    const from = { x: svg.x + svg.width / 2, y: svg.y + svg.height / 2 };
    await pointerDrag(pageA, from, { x: from.x + dx, y: from.y + dy });
  }
  fail('Product zoom/pan could not place all gesture targets inside the SVG viewport');
}

async function installAdmissionDiagnostic() {
  await pageA.evaluate(`(async()=>{const {CanvasPanel}=await import('/assets/panel-canvas.js');const original=CanvasPanel.prototype.previewEndpointJoin;CanvasPanel.prototype.previewEndpointJoin=async function(endpointId,groupId){const snapshot=this.topology;const endpoint=(snapshot.endpoints||[]).find(x=>x.endpoint_id===endpointId);const group=(snapshot.groups||[]).find(x=>x.group_id===groupId);const networkId=this.networkId;const rpc=this.rpc;this.rpc=async(operation,input)=>{const p=await rpc(operation,input);if(operation==='topology.endpoint_admission_preview'){globalThis.cicadaAdmissionDiagnostic={
    endpoint_visible:!!endpoint,group_visible:!!group,group_active:String(group?.state).toLowerCase()==='active',
    snapshot_network_matches:group?.network_id===networkId,endpoint_network_matches:(endpoint?.network_ids||[]).includes(networkId),
    existing_endpoint_reference:(endpoint?.group_ids||[]).includes(groupId),preview_present:!!p,
    owner_matches:p?.owner_principal_id===snapshot.owner_principal_id,network_matches:p?.network_id===networkId,
    group_matches:p?.group_id===groupId,endpoint_matches:p?.endpoint_id===endpointId,principal_matches:p?.endpoint_principal_id===endpoint?.principal_id,
    context_policy_matches:p?.group_context_policy===group?.context_policy,migration_allowed:['READY','MIGRATION_PENDING_GROUP'].includes(p?.endpoint_migration_state),
    roles_array:Array.isArray(p?.admission_roles),roles_member_only:Array.isArray(p?.admission_roles)&&p.admission_roles.length===1&&p.admission_roles[0]==='member',
    grants_array:Array.isArray(p?.admission_grants),grants_empty:Array.isArray(p?.admission_grants)&&p.admission_grants.length===0,
    no_history:p?.history_included===false,no_key_grant:p?.key_grant_created===false,memory_retained:p?.existing_thread_memory_retained===true,
    no_membership_status:!p?.membership_status,membership_revision_zero:p?.membership_revision===0,
    no_endpoint_group_status:!p?.endpoint_group_status,endpoint_group_revision_zero:p?.endpoint_group_revision===0,
    migration_enum:['READY','MIGRATION_PENDING_GROUP'].includes(p?.endpoint_migration_state)?p.endpoint_migration_state:'OTHER',
    membership_status_enum:['','active','revoked'].includes(p?.membership_status||'')?(p.membership_status||''):'OTHER',
    endpoint_group_status_enum:['','active','revoked'].includes(p?.endpoint_group_status||'')?(p.endpoint_group_status||''):'OTHER'};}return p;};try{return await original.call(this,endpointId,groupId);}finally{this.rpc=rpc;}};})()`);
}

async function committedAction() {
  const before = pageA.rpcRequestCount;
  await buttonClick(pageA, 'Commit this one action');
  await evaluateUntil(pageA, 'document.querySelector(".status-banner")?.textContent || ""',
    value => value.includes('Authoritative topology and status snapshots refreshed'), 30000, 'authenticated action and both snapshots');
  await waitForRPCCount(pageA, before + 3);
  await evaluateUntil(pageA, `(async()=>{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();try{return !(await c.getState(db)).device?.pending;}finally{db.close();}})()`, Boolean, 30000, 'exact action packet and snapshots resolved');
}

async function runInteractionAndFaultFlow(password) {
  const endpointIDs = await syntheticNodeEndpoints(password);
  phase = 'canvas_pointer_keyboard_interactions';
  await buttonClick(pageA, 'Refresh snapshots');
  await evaluateUntil(pageA, `document.querySelectorAll('[data-endpoint-id]').length`, value => value >= 2);
  await fitCanvasTargets(endpointIDs.map(id => `[data-endpoint-id="${id}"]`));
  const refs = await Promise.all(endpointIDs.map(id => elementBox(pageA, `[data-endpoint-id="${id}"]`)));
  if (refs.some(item => !item)) fail('Enrolled synthetic endpoints did not reach Owner canvas');
  const from = { x: Math.min(...refs.map(b => b.x)) - 5, y: Math.min(...refs.map(b => b.y)) - 5 };
  const to = { x: Math.max(...refs.map(b => b.x + b.width)) + 5, y: Math.max(...refs.map(b => b.y + b.height)) + 5 };
  await pageA.evaluate(`(()=>{globalThis.cicadaPointerDiagnostic=[];for(const type of ['pointerdown','pointermove','pointerup','lostpointercapture'])document.addEventListener(type,e=>{if(globalThis.cicadaPointerDiagnostic.length<32)globalThis.cicadaPointerDiagnostic.push({type:e.type,x:e.clientX,y:e.clientY,id:e.pointerId,target:e.target.tagName,buttons:e.buttons,capture:document.querySelector('.stage svg')?.hasPointerCapture(e.pointerId)});},{capture:true});})()`);
  const beforeGesture = pageA.rpcRequestCount;
  const outline = await pointerDrag(pageA, from, to);
  result.pointer_box_diagnostic = { from, to, refs, outline, events: await pageA.evaluate("globalThis.cicadaPointerDiagnostic") };
  if (!outline || outline.visible !== 'visible' || Math.abs(outline.x - (from.x - outline.svgX)) > 1 ||
      Math.abs(outline.y - (from.y - outline.svgY)) > 1 || Math.abs(outline.width - (to.x - from.x)) > 1 ||
      Math.abs(outline.height - (to.y - from.y)) > 1) fail('Box outline does not match the actual pointer rectangle at canvas scale');
  const selected = await pageA.evaluate('document.querySelectorAll(".endpoint.selected").length');
  if (selected !== 2 || pageA.rpcRequestCount !== beforeGesture) fail('Box selection changed authorization or missed visible endpoints');
  await pageA.evaluate(`document.querySelector('[data-endpoint-id="${endpointIDs[0]}"]').focus()`);
  await pageA.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await pageA.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  if (await pageA.evaluate('document.querySelectorAll(".endpoint.selected").length') !== 1) fail('Keyboard endpoint selection failed');
  await pageA.send('Input.dispatchKeyEvent', { type: 'keyDown', key: ' ', code: 'Space', windowsVirtualKeyCode: 32, modifiers: 2 });
  await pageA.send('Input.dispatchKeyEvent', { type: 'keyUp', key: ' ', code: 'Space', windowsVirtualKeyCode: 32, modifiers: 2 });
  if (await pageA.evaluate('document.querySelectorAll(".endpoint.selected").length') !== 0) fail('Modified Space did not toggle Endpoint selection');
  const canvas = await elementBox(pageA, '.stage svg');
  await pageA.evaluate("document.querySelector('.stage svg').focus()");
  await pageA.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: canvas.x + 20, y: canvas.y + 140, button: 'left', buttons: 1, clickCount: 1 });
  await pageA.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: canvas.x + 35, y: canvas.y + 155, button: 'left', buttons: 1 });
  await pageA.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await pageA.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await pageA.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: canvas.x + 35, y: canvas.y + 155, button: 'left', buttons: 0, clickCount: 1 });
  if (await pageA.evaluate('document.querySelector(".selection-box")?.getAttribute("visibility")') !== 'hidden' ||
      pageA.rpcRequestCount !== beforeGesture) fail('Escape failed to cancel a local gesture without a management write');
  result.canvas_keyboard = { enter_select: true, modified_space_toggle: true, escape_cancel: true, gesture_management_writes: 0 };
  const groupID = await pageA.evaluate(`document.querySelector('text.group-label')?.previousElementSibling?.getAttribute('data-group-drop-id')`);
  if (!groupID) fail('Created Group drop target is unavailable');
  await installAdmissionDiagnostic();
  for (const id of endpointIDs) {
    phase = `canvas_endpoint_admission_${endpointIDs.indexOf(id)}`;
    await fitCanvasTargets([`[data-endpoint-id="${id}"]`, `[data-group-drop-id="${groupID}"]`]);
    await buttonClick(pageA, 'Drag to Group');
    const source = await elementBox(pageA, `[data-endpoint-id="${id}"]`);
    const target = await visibleGroupDropPoint(groupID);
    const start = { x: source.x + source.width / 2, y: source.y + source.height / 2 };
    const startHit = await pageA.evaluate(`(()=>{const e=document.elementFromPoint(${start.x},${start.y});return{type:e?.tagName||'NONE',matches_target:e?.closest('[data-endpoint-id]')?.getAttribute('data-endpoint-id')===${JSON.stringify(id)}};})()`);
    result.endpoint_drag_start_diagnostic = [...(result.endpoint_drag_start_diagnostic || []), startHit];
    if (!startHit.matches_target) fail('Actual Endpoint drag start does not match its visible reference');
    await pointerDrag(pageA, start, target, groupID);
    await evaluateUntil(pageA, 'document.querySelector(".side")?.innerText || ""', value => value.includes('endpoint.admit_group'));
    await committedAction();
    if (!await elementBox(pageA, `[data-endpoint-id="${id}"][data-group-ref="${groupID}"]`)) fail('Admission did not add exact Group reference');
  }
  phase = 'canvas_link_proposal';
  await fitCanvasTargets(endpointIDs.map(id => `[data-endpoint-id="${id}"][data-group-ref="${groupID}"]`));
  await buttonClick(pageA, 'Draw Link');
  const a = await elementBox(pageA, `[data-endpoint-id="${endpointIDs[0]}"][data-group-ref="${groupID}"]`);
  const b = await elementBox(pageA, `[data-endpoint-id="${endpointIDs[1]}"][data-group-ref="${groupID}"]`);
  const beforeLink = pageA.rpcRequestCount;
  await pointerDrag(pageA, { x: a.x + a.width / 2, y: a.y + a.height / 2 }, { x: b.x + b.width / 2, y: b.y + b.height / 2 });
  await evaluateUntil(pageA, "document.querySelector('.status-banner')?.textContent || ''", value => value.includes('Propose a Link between'), 30000, 'pointer Link pair prepared for review');
  if (pageA.rpcRequestCount !== beforeLink) fail('Drawing a Link submitted a write before review');
  await buttonClick(pageA, 'Preview Link proposal');
  await evaluateUntil(pageA, 'document.querySelector(".side")?.innerText || ""', value => value.includes('link.propose'));
  await committedAction();
  await evaluateUntil(pageA, 'document.querySelector(".side")?.innerText || ""', value => value.includes('PROPOSED'));
  const linkSnapshot = await ownerFixtureRPC(password, 'topology.snapshot', {});
  const proposedLinks = linkSnapshot.links.filter(link => link.source_endpoint_id === endpointIDs[0] && link.target_endpoint_id === endpointIDs[1] &&
    link.source_group_id === groupID && link.target_group_id === groupID);
  if (proposedLinks.length !== 1 || proposedLinks[0].state !== 'PROPOSED' || proposedLinks[0].version < 1 ||
      proposedLinks[0].direction !== 'bidirectional' || !proposedLinks[0].actions.includes('send') || !proposedLinks[0].data_scopes.includes('thread.message')) {
    fail('Reviewed Link did not remain a single inactive scoped proposal');
  }
  result.canvas_link = { exact_scoped_proposal: true, inactive: true, pointer_prepared_review: true };
  phase = 'canvas_monitor_role_and_permission';
  const memberships = await ownerFixtureRPC(password, 'topology.snapshot', {});
  const member = memberships.memberships.find(item => item.principal_id === memberships.endpoints.find(e => e.endpoint_id === endpointIDs[0]).principal_id && item.group_id === groupID);
  await cardField(pageA, 'Membership & Monitor settings', 'select', 0, member.membership_id);
  await cardField(pageA, 'Membership & Monitor settings', 'select', 1, 'monitor');
  await buttonClick(pageA, 'Preview role update'); await committedAction();
  const afterRole = await ownerFixtureRPC(password, 'topology.snapshot', {});
  const roleMember = afterRole.memberships.find(item => item.membership_id === member.membership_id);
  if (!roleMember || roleMember.role !== 'monitor' || !roleMember.roles?.includes('monitor') ||
      roleMember.broadcast_permission_enabled !== false || roleMember.version <= member.version) fail('Monitor role implicitly granted broadcast or failed to persist with a new CAS version');
  await cardField(pageA, 'Membership & Monitor settings', 'select', 0, member.membership_id);
  await cardField(pageA, 'Membership & Monitor settings', 'select', 2, 'true');
  await buttonClick(pageA, 'Preview permission change'); await committedAction();
  const afterPermission = await ownerFixtureRPC(password, 'topology.snapshot', {});
  const permissionMember = afterPermission.memberships.find(item => item.membership_id === member.membership_id);
  if (!permissionMember || permissionMember.role !== 'monitor' || !permissionMember.roles?.includes('monitor') ||
      permissionMember.broadcast_permission_enabled !== true || permissionMember.version <= roleMember.version) fail('Explicit broadcast permission did not persist separately with a new CAS version');
  result.canvas_monitor = { role_persisted: true, role_change_broadcast_disabled: true, explicit_broadcast_enabled: true, distinct_cas_versions: true };
  markStep('canvas_pointer_keyboard_group_link_monitor');
}

async function pendingFingerprint() {
  return pageA.evaluate(`(async()=>{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();try{const p=(await c.getState(db)).device?.pending;if(!p)return null;const bytes=Uint8Array.from(atob(p.packet),x=>x.charCodeAt(0));const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));return{operationId:p.operationId,operation:p.operation,requestSequence:p.requestSequence,responseSequence:p.responseSequence,packetSha256:Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('')};}finally{db.close();}})()`);
}

async function loseGroupResponse(name) {
  await cardField(pageA, 'Create Group', 'input', 0, name);
  await buttonClick(pageA, 'Preview Group creation');
  await pageA.send('Fetch.enable', { patterns: [{ urlPattern: '*://*/v2/client/rpc', requestStage: 'Response' }] });
  const responsePromise = pageA.waitEvent('Fetch.requestPaused', event => event.responseStatusCode === 200, 30000);
  await buttonClick(pageA, 'Commit this one action');
  const response = await responsePromise;
  const pending = await pendingFingerprint();
  if (!pending || pending.operation !== 'topology.apply') fail('Committed response loss did not retain the exact management packet');
  await pageA.send('Fetch.failRequest', { requestId: response.requestId, errorReason: 'ConnectionClosed' });
  await pageA.send('Fetch.disable');
  await evaluateUntil(pageA, 'document.querySelector("#app")?.innerText || ""', value => value.includes('Resolve the saved Client request'));
  const retained = await pendingFingerprint();
  if (JSON.stringify(retained) !== JSON.stringify(pending)) fail('Lost response replaced the original packet or sequence');
  return pending;
}

async function fixtureRequestState(pending, interrupt = false) {
  // Only the exact run-owned, completed request can be interrupted. All crypto,
  // device authority, digest, response reservation and sequence counters remain.
  const code = `import sqlite3,json,sys\ndb=sqlite3.connect(sys.argv[1]);db.execute('PRAGMA foreign_keys=ON');row=db.execute('SELECT id,status,ciphertext_digest,sequence FROM client_device_requests_v2 WHERE owner_id=? AND operation_id=?',(sys.argv[2],sys.argv[3])).fetchone()\nassert row and row[1]=='COMPLETED' and row[2]==sys.argv[4] and row[3]==int(sys.argv[5])\nreservation=db.execute('SELECT reserved_response_sequence FROM client_device_request_recovery_v2 WHERE request_id=?',(row[0],)).fetchone();assert reservation and reservation[0]==int(sys.argv[6])\nif sys.argv[7]=='interrupt':\n db.execute(\"UPDATE client_device_requests_v2 SET status='PROCESSING',response_packet=NULL WHERE id=? AND status='COMPLETED'\",(row[0],));assert db.execute('SELECT changes()').fetchone()[0]==1;db.commit()\nprint(json.dumps({'matched_exact_request':True,'response_reservation_preserved':True,'interrupted_state_injected':sys.argv[7]=='interrupt'}));db.close()`;
  const output = await checked('python3', ['-B', '-c', code, path.join(stateDir, 'cicada.sqlite3'),
    ownerId, pending.operationId, pending.packetSha256, String(pending.requestSequence),
    String(pending.responseSequence), interrupt ? 'interrupt' : 'observe']);
  return JSON.parse(output);
}

async function runResponseLossAndUncertainty(password) {
  phase = 'committed_response_loss_exact_recovery';
  const lostName = `Lost Response ${suffix.slice(-8)}`;
  const pending = await loseGroupResponse(lostName);
  await fixtureRequestState(pending);
  const recoveryRequests = [];
  pageA.listeners.get('Network.requestWillBeSent').push(event => {
    if (event.request?.url?.endsWith('/v2/client/rpc/recover')) recoveryRequests.push(event.requestId);
  });
  await buttonClick(pageA, 'Recover exact pending operation');
  await evaluateUntil(pageA, 'document.querySelector(".workspace") !== null && !document.querySelector(".fence-card")');
  const recovered = await readIndexedDBState(pageA);
  if (recovered.pending || recovered.writeFence || recoveryRequests.length !== 1) fail('Lost completed response did not recover exactly once');
  if (await pageA.evaluate(`[...document.querySelectorAll('text.group-label')].filter(e=>e.textContent===${JSON.stringify(lostName)}).length`) !== 1) fail('Lost response created zero or duplicate Groups');
  result.response_loss = { original_packet_sha256: pending.packetSha256, exact_recovery_requests: 1,
    group_count_after_recovery: 1, replacement_management_write: false };
  markStep('response_loss_exact_recovery');

  phase = 'durable_interrupted_state_uncertainty';
  const uncertainName = `Uncertain Response ${suffix.slice(-8)}`;
  const interrupted = await loseGroupResponse(uncertainName);
  if (nodeWasCreated) await docker(['stop', '--time', '10', nodeContainer]);
  await docker(['stop', '--time', '10', hubContainer]);
  result.uncertain_fault = await fixtureRequestState(interrupted, true);
  result.uncertain_fault.scope = 'controlled synthetic durable interrupted-state injection after response loss; not an actual kill-window proof';
  await docker(['start', hubContainer]); await waitHub(hubContainer);
    hubHostPort = portFromDocker(await docker(['port', hubContainer, '8787/tcp']));
  if (nodeWasCreated) await docker(['start', nodeContainer]);
  if (JSON.stringify(await pendingFingerprint()) !== JSON.stringify(interrupted)) fail('Hub restart changed browser pending ciphertext');
  await buttonClick(pageA, 'Recover exact pending operation');
  await evaluateUntil(pageA, 'document.querySelector(".fence-card") !== null');
  const fenced = await readIndexedDBState(pageA);
  if (fenced.pending || !fenced.writeFence) fail('Authenticated uncertainty did not separate durable semantic fence from resolved packet');
  const fenceGestureCount = pageA.rpcRequestCount;
  await dragGroup(nestingFixture.child, nestingFixture.parent);
  if (pageA.rpcRequestCount !== fenceGestureCount || await pageA.evaluate('document.querySelector(".side pre") !== null')) fail('Uncertain fence allowed a Group nesting gesture to prepare/write');
  markStep('group_parent_uncertain_fence_no_write');
  const writesBefore = pageA.rpcRequestCount;
  await cardField(pageA, 'Create Group', 'input', 0, 'Must not be written');
  await buttonClick(pageA, 'Preview Group creation');
  if (pageA.rpcRequestCount !== writesBefore || await pageA.evaluate('document.querySelector(".side")?.innerText.includes("Exact action preview")')) fail('Uncertain fence allowed a replacement write');
  await pageA.send('Page.reload');
  await evaluateUntil(pageA, 'document.querySelector("#unlock-password") !== null');
  await setInputValue(pageA, '#unlock-password', password); await buttonClick(pageA, 'Unlock device key');
  await evaluateUntil(pageA, 'document.querySelector(".fence-card") !== null');
  if (!(await readIndexedDBState(pageA)).writeFence) fail('Uncertain fence was lost on reload/unlock');
  await pageB.send('Page.reload');
  await evaluateUntil(pageB, 'document.querySelector("#unlock-password") !== null');
  await setInputValue(pageB, '#unlock-password', password); await buttonClick(pageB, 'Unlock device key');
  await evaluateUntil(pageB, 'document.querySelector(".fence-card") !== null');
  const secondTabBefore = pageB.rpcRequestCount;
  await cardField(pageB, 'Create Group', 'input', 0, 'Second tab must not write');
  await buttonClick(pageB, 'Preview Group creation');
  if (pageB.rpcRequestCount !== secondTabBefore) fail('Second tab bypassed the durable uncertain write fence');
  const authorizedLabel = 'I reviewed this state; authorize a new write';
  if (!await pageA.evaluate(`([...document.querySelectorAll('button')].find(e=>e.textContent===${JSON.stringify(authorizedLabel)}))?.disabled`)) fail('Fence authorization was enabled without explicit fresh review');
  const beforeReview = pageA.rpcRequestCount;
  await buttonClick(pageA, 'Refresh topology and status for review');
  await evaluateUntil(pageA, `([...document.querySelectorAll('button')].find(e=>e.textContent===${JSON.stringify(authorizedLabel)}))?.disabled === false`);
  if (pageA.rpcRequestCount !== beforeReview + 2 || !(await readIndexedDBState(pageA)).writeFence) fail('Both snapshots did not preserve the uncertain fence for explicit review');
  const dialogPromise = pageA.waitEvent('Page.javascriptDialogOpening');
  // Runtime.evaluate does not return while a modal is open; dispatch concurrently.
  const click = buttonClick(pageA, authorizedLabel);
  const dialog = await dialogPromise;
  if (dialog.type !== 'confirm' || !dialog.message.includes(interrupted.operationId)) fail('Explicit authorization dialog lost exact uncertain operation');
  await pageA.send('Page.handleJavaScriptDialog', { accept: true }); await click;
  await evaluateUntil(pageA, 'document.querySelector(".fence-card") === null');
  if ((await readIndexedDBState(pageA)).writeFence || pageA.rpcRequestCount !== beforeReview + 2) fail('Review authorization replayed a write or failed to clear the semantic fence');
  if (await pageA.evaluate(`[...document.querySelectorAll('text.group-label')].filter(e=>e.textContent===${JSON.stringify(uncertainName)}).length`) !== 1) fail('Uncertain recovery duplicated the original Group');
  result.uncertain_fault = { ...result.uncertain_fault, original_packet_sha256: interrupted.packetSha256,
    authenticated_uncertain_response: true, reload_and_cross_tab_fence: true,
    review_snapshots: 2, explicit_review_authorization: true, authorization_replayed_write: false };
  markStep('uncertain_write_fence');
}

async function cleanup() {
  phase = 'cleanup';
  const cleaned = { hub_container_removed: false, chromium_container_removed: false,
    docker_network_removed: false, fixture_directory_removed: false };
  try { pageA?.close(); } catch { /* best effort */ }
  try { pageB?.close(); } catch { /* best effort */ }
  cleaned.node_container_removed = !nodeWasCreated || await removeOwnedContainer(nodeContainer, hubImageId);
  if (browserWasCreated) cleaned.chromium_container_removed = await removeOwnedContainer(browserContainer, chromiumImageId);
  if (hubWasCreated) cleaned.hub_container_removed = await removeOwnedContainer(hubContainer, hubImageId);
  if (networkWasCreated) cleaned.docker_network_removed = await removeOwnedNetwork();
  await rm(fixtureDir, { recursive: true, force: true });
  const fixtureCheck = await run('test', ['-e', fixtureDir]);
  cleaned.fixture_directory_removed = fixtureCheck.code !== 0;
  const cleanupOkay = cleaned.node_container_removed && (!browserWasCreated || cleaned.chromium_container_removed) &&
    (!hubWasCreated || cleaned.hub_container_removed) && (!networkWasCreated || cleaned.docker_network_removed) &&
    cleaned.fixture_directory_removed;
  result.fixture_cleanup = { status: cleanupOkay ? 'PASS' : 'FAIL', ...cleaned };
  if (!cleanupOkay && result.status === 'PASS') result.status = 'FAIL';
}

async function main() {
  await ensureDir(path.dirname(outputDir));
  try { await mkdir(outputDir, { mode: 0o700 }); }
  catch { fail('Evidence directory already exists or cannot be created; refusing to overwrite it'); }
  await chmod(outputDir, 0o700);
  await ensureDir(fixtureDir);
  for (const directory of [stateDir, workspaceDir, ownerPrivateDir, ownerPublicDir, browserDownloads, browserImports, nodeStateDir]) await ensureDir(directory);
  await writeFile(hubEnvPath, `CICADA_API_TOKEN=synthetic-${randomBytes(32).toString('hex')}\n`, { mode: 0o600, flag: 'wx' });

  result.scripts.browser_gate_sha256 = await fileSHA256(scriptPath);
  result.desktop_viewport = { width: 1440, height: 1000, device_scale_factor: 1, mobile: false };
  const buildMetadata = JSON.parse(await readFile(metadataPath, 'utf8'));
  if (!buildMetadata.image?.id || !buildMetadata.source?.source_fingerprint) fail('Build metadata is missing candidate image or source fingerprint');
  const hubImage = await inspectImage(hubRef);
  hubImageId = hubImage.Id;
  const hubLabels = hubImage.Config?.Labels || {};
  if (buildMetadata.source.source_fingerprint !== expectedSourceFingerprint ||
      hubLabels['org.cicada.build.source-fingerprint'] !== expectedSourceFingerprint ||
      hubImageId !== buildMetadata.image.id ||
      hubLabels['org.opencontainers.image.revision'] !== buildMetadata.source.revision ||
      hubLabels['org.cicada.client-catalog.sha256'] !== buildMetadata.source.catalog_sha256 ||
      hubLabels['org.cicada.build.dirty'] !== String(buildMetadata.source.dirty)) {
    fail('Candidate Hub image and build metadata do not both match the caller-supplied expected source fingerprint and provenance');
  }
  result.scripts.build_metadata_sha256 = await fileSHA256(metadataPath);
  result.hub = { image_reference: hubRef, image_id: hubImageId,
    source_revision: buildMetadata.source.revision, source_dirty: buildMetadata.source.dirty,
    source_fingerprint: buildMetadata.source.source_fingerprint,
    catalog_sha256: buildMetadata.source.catalog_sha256 };

  const dockerInfo = await run('docker', ['info', '--format', '{{.ServerVersion}}']);
  if (dockerInfo.code !== 0) fail('Docker daemon is unavailable');
  await loadChromium();
  await setupHubFixture(buildMetadata);
  await startBrowser();
  await runBrowserFlow();
  result.status = 'PASS';
  result.completed_at = new Date().toISOString();
  result.chromium.browser_version = browserVersion;
  result.chromium.user_agent = browserUserAgent;
  result.fixture_cleanup.status = 'PENDING';
}

let topFailure = null;
try {
  await main();
} catch (error) {
  topFailure = error;
  result.status = phase === 'prerequisites' || phase === 'chromium_image' ? 'BLOCKED' : 'FAIL';
  result.failure = { phase, reason: error?.message || 'unknown failure' };
  if (pageA) { try { result.admission_diagnostic = await pageA.evaluate('globalThis.cicadaAdmissionDiagnostic || null'); } catch { /* browser may have closed */ } }
  if (pageA) { try { result.failure.canvas_banner = await pageA.evaluate("document.querySelector('.status-banner')?.textContent || ''"); } catch { /* browser may have closed */ } }
} finally {
  try { await cleanup(); }
  catch (error) {
    result.status = 'FAIL';
    result.fixture_cleanup = { status: 'FAIL', reason: error?.message || 'cleanup failed' };
  }
  result.completed_at = new Date().toISOString();
  const evidencePath = path.join(outputDir, 'result.json');
  try { await writeFile(evidencePath, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600, flag: 'wx' }); }
  catch (error) {
    process.stderr.write(`FAIL: could not write redacted browser evidence (${error?.code || 'write error'}).\n`);
    process.exitCode = 1;
  }
}

if (result.status !== 'PASS') {
  process.stderr.write(`${result.status}: real headless Chromium web-panel gate failed in phase ${result.failure?.phase || 'cleanup'}; redacted result: ${path.join(outputDir, 'result.json')}\n`);
  if (topFailure && process.env.CICADA_BROWSER_DEBUG === '1') process.stderr.write(`${topFailure.stack}\n`);
  process.exitCode = process.exitCode || 1;
} else {
  process.stdout.write(`PASS: real headless Chromium Web Panel gate; redacted evidence: ${path.join(outputDir, 'result.json')}\n`);
}
