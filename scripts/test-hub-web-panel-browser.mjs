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
    uncertain_write_fence: 'NOT_RUN_NO_FAULT_INJECTION',
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
    '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
    '--env-file', hubEnvPath,
    '-v', `${stateDir}:/state`, '-v', `${workspaceDir}:/workspace`,
    '-v', `${ownerPublicDir}:/owner-public:ro`,
    '-e', 'CICADA_STATE_DIR=/state', '-e', 'CICADA_WORKSPACE_ROOT=/workspace',
    hubImageId, 'serve', '--host', '0.0.0.0', '--port', '8787',
  ];
  await docker(args);
  hubWasCreated = true;
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
    await docker(['pull', chromiumRef], { capture: false });
    inspected = await run('docker', ['image', 'inspect', chromiumRef]);
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
}

async function cleanup() {
  phase = 'cleanup';
  const cleaned = { hub_container_removed: false, chromium_container_removed: false,
    docker_network_removed: false, fixture_directory_removed: false };
  try { pageA?.close(); } catch { /* best effort */ }
  try { pageB?.close(); } catch { /* best effort */ }
  if (browserWasCreated) cleaned.chromium_container_removed = await removeOwnedContainer(browserContainer, chromiumImageId);
  if (hubWasCreated) cleaned.hub_container_removed = await removeOwnedContainer(hubContainer, hubImageId);
  if (networkWasCreated) cleaned.docker_network_removed = await removeOwnedNetwork();
  await rm(fixtureDir, { recursive: true, force: true });
  const fixtureCheck = await run('test', ['-e', fixtureDir]);
  cleaned.fixture_directory_removed = fixtureCheck.code !== 0;
  const cleanupOkay = (!browserWasCreated || cleaned.chromium_container_removed) &&
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
  for (const directory of [stateDir, workspaceDir, ownerPrivateDir, ownerPublicDir, browserDownloads, browserImports]) await ensureDir(directory);
  await writeFile(hubEnvPath, `CICADA_API_TOKEN=synthetic-${randomBytes(32).toString('hex')}\n`, { mode: 0o600, flag: 'wx' });

  result.scripts.browser_gate_sha256 = await fileSHA256(scriptPath);
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
