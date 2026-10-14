#!/usr/bin/env node
// Disposable Chromium acceptance for the first Hub Owner account flow.
// Uses Node 24 built-ins, a caller-supplied current Hub image, and only
// synthetic local test material. It never contacts a resident Hub.

import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.umask(0o077);

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptPath = fileURLToPath(import.meta.url);
const hubRef = process.env.CICADA_HUB_IMAGE || '';
const chromiumRef = process.env.CICADA_CHROMIUM_IMAGE || 'chromedp/headless-shell:latest';
const expectedFingerprint = process.env.CICADA_EXPECT_SOURCE_FINGERPRINT || '';
const metadataPath = path.resolve(repoRoot, process.env.CICADA_BUILD_METADATA || '');
const opensslPath = process.env.CICADA_ACCOUNT_TEST_OPENSSL ||
  '/home/zyf/CICADA_pqtls/.cicada-data/pqtls-openssl-accepted-build/stage/opt/cicada-openssl/3.5.9/bin/openssl';
const opensslLib = process.env.CICADA_ACCOUNT_TEST_OPENSSL_LD_LIBRARY_PATH ||
  path.resolve(path.dirname(opensslPath), '../lib');
const outputParent = path.join(repoRoot, '.cicada-data', 'hub-owner-account-browser');
const nodeVersion = process.versions.node;
const fixtureLabel = 'hub-owner-account-browser';
const browserOrigin = 'http://127.0.0.1:8787';

function fail(message) { throw new Error(message); }

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  process.stdout.write('Usage: CICADA_HUB_IMAGE=IMAGE CICADA_BUILD_METADATA=build.json CICADA_EXPECT_SOURCE_FINGERPRINT=64-hex node scripts/test-hub-owner-account-browser.mjs\n' +
    'Optional: CICADA_CHROMIUM_IMAGE (default chromedp/headless-shell:latest), CICADA_ACCOUNT_TEST_OPENSSL (accepted OpenSSL 3.5+ executable), CICADA_ACCOUNT_BROWSER_RESULT_DIR (new directory under .cicada-data/hub-owner-account-browser).\n');
  process.exit(0);
}

if (!/^24\./.test(nodeVersion) || typeof WebSocket !== 'function') {
  process.stderr.write('BLOCKED: this browser gate requires Node 24 native WebSocket.\n');
  process.exit(2);
}
if (!hubRef || !process.env.CICADA_BUILD_METADATA || !/^[0-9a-f]{64}$/.test(expectedFingerprint)) {
  process.stderr.write('BLOCKED: set CICADA_HUB_IMAGE, CICADA_BUILD_METADATA, and an explicit lowercase 64-character CICADA_EXPECT_SOURCE_FINGERPRINT.\n');
  process.exit(2);
}
if (!path.isAbsolute(opensslPath)) {
  process.stderr.write('BLOCKED: CICADA_ACCOUNT_TEST_OPENSSL must be an absolute path.\n');
  process.exit(2);
}

const stamp = new Date().toISOString().replaceAll(':', '').replaceAll('-', '').replace(/\.\d{3}Z$/, 'Z').toLowerCase();
const suffix = `${stamp}-${process.pid}-${randomBytes(4).toString('hex')}`;
const outputDir = path.resolve(process.env.CICADA_ACCOUNT_BROWSER_RESULT_DIR || path.join(outputParent, suffix));
const fixtureDir = path.join(outputDir, 'fixture');
const stateDir = path.join(fixtureDir, 'state');
const workspaceDir = path.join(fixtureDir, 'workspace');
const publicDir = path.join(fixtureDir, 'public');
const privateKeysDir = path.join(fixtureDir, 'synthetic-private-keys');
const browserDir = path.join(fixtureDir, 'browser');
const hubContainer = `cicada-account-${suffix}-hub`;
const browserContainer = `cicada-account-${suffix}-chromium`;
const setupContainer = `cicada-account-${suffix}-setup`;
const claimContainer = `cicada-account-${suffix}-claim`;
const dockerNetwork = `cicada-account-${suffix}-net`;
const hubNetworkAlias = `cicada-account-${suffix}-hub`;
const fixtureLabels = ['--label', `org.cicada.fixture=${fixtureLabel}`, '--label', `org.cicada.fixture.dir=${fixtureDir}`];
const uid = process.getuid?.() ?? 1000;
const gid = process.getgid?.() ?? 1000;

const result = {
  schema_version: 'cicada.hub-owner-account-browser.v1',
  gate: 'real_headless_chromium_hub_only_account_flow',
  status: 'FAIL',
  started_at: new Date().toISOString(),
  node_version: nodeVersion,
  fixture_run_id: `cicada-account-${suffix}`,
  build: {},
  openssl: {},
  chromium: {},
  hub: {},
  steps: {
    build_metadata_and_image_pin: 'NOT_RUN',
    synthetic_owner_public_spki: 'NOT_RUN',
    local_hub_setup_and_claim_issue: 'NOT_RUN',
    hub_only_startup: 'NOT_RUN',
    fresh_first_page_claim_flow: 'NOT_RUN',
    first_claim_prepare_lost_response_exact_retry: 'NOT_RUN',
    account_complete_lost_response_exact_retry: 'NOT_RUN',
    two_tab_claim_writer_lock_recovery: 'NOT_RUN',
    first_account_claim_committed_pending_root: 'NOT_RUN',
    first_account_pending_root_no_manager: 'NOT_RUN',
    wrong_password_ui_retains_saved_challenge: 'NOT_RUN',
    login_complete_lost_response_exact_retry: 'NOT_RUN',
    logout_lost_response_reload_exact_retry: 'NOT_RUN',
    encrypted_browser_device_vault_reload: 'NOT_RUN',
    unknown_device_rejected: 'NOT_RUN',
    wrong_password_rejected: 'NOT_RUN',
    hub_restart_preserves_account_and_pending_root: 'NOT_RUN',
    manager_rpc_unavailable_in_hub_only: 'NOT_RUN',
  },
  request_recovery: {},
  fixture_cleanup: { status: 'NOT_RUN' },
  owned_fixture: {
    containers: [hubContainer, browserContainer, setupContainer, claimContainer],
    networks: [dockerNetwork],
    images: [],
    scratch_path: fixtureDir,
  },
};

let phase = 'prerequisites';
let hubImageId = '';
let chromiumImageId = '';
let hubPort = '';
let cdpPort = '';
let hubWasCreated = false;
let browserWasCreated = false;
let networkWasCreated = false;
let page = null;
let fatal = null;
const cdpConnections = new Set();

process.on('SIGINT', () => { fatal ||= new Error('interrupted'); for (const cdp of cdpConnections) cdp.close(); });
process.on('SIGTERM', () => { fatal ||= new Error('terminated'); for (const cdp of cdpConnections) cdp.close(); });

async function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd || repoRoot,
      env: options.env || process.env,
      stdio: options.input === undefined ? ['ignore', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs || 60000);
    timeout.unref?.();
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { if (stdout.length < 2 * 1024 * 1024) stdout += chunk; });
    child.stderr.on('data', chunk => { if (stderr.length < 2 * 1024 * 1024) stderr += chunk; });
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('close', code => { clearTimeout(timeout); resolve({ code: code ?? 1, stdout, stderr, timedOut }); });
    if (options.input !== undefined) child.stdin.end(options.input);
  });
}

async function checked(command, args, options = {}) {
  const response = await run(command, args, options);
  if (response.code !== 0) {
    if (process.env.CICADA_ACCOUNT_BROWSER_DEBUG === '1' && response.stderr) {
      process.stderr.write(`${path.basename(command)} diagnostic: ${response.stderr.trim().replaceAll(fixtureDir, '<fixture>').slice(0, 700)}\n`);
    }
    fail(response.timedOut ? `${path.basename(command)} exceeded the 60-second command limit` :
      `${path.basename(command)} exited with status ${response.code}`);
  }
  return response.stdout;
}

async function docker(args, options = {}) { return checked('docker', args, options); }
async function dockerJSON(args) {
  try { return JSON.parse(await docker(args)); }
  catch { fail('Docker returned invalid JSON for an image/container inspection'); }
}

async function ensureDir(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
}

async function hashFile(file) {
  const hash = createHash('sha256');
  hash.update(await readFile(file));
  return hash.digest('hex');
}

function mark(name) { result.steps[name] = 'PASS'; }
function within(parent, child) { return child === parent || child.startsWith(parent + path.sep); }

function portFromDocker(text) {
  const match = text.trim().split(/\r?\n/).find(Boolean)?.match(/:(\d+)$/);
  if (!match) fail('Docker did not publish a loopback TCP port');
  return match[1];
}

async function inspectImage(reference) {
  const [image] = await dockerJSON(['image', 'inspect', reference]);
  if (!image?.Id) fail(`Required local Docker image is unavailable: ${reference}`);
  return image;
}

async function directJSON(url, timeoutMs = 3000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) fail(`Hub readiness request returned HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); }
}

async function waitHub(timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const health = await directJSON(`http://127.0.0.1:${hubPort}/healthz`);
      const identity = await directJSON(`http://127.0.0.1:${hubPort}/v2/client/identity`);
      if (health.status !== 'ok' || health.service !== 'cicada-hub' || !identity.hub_id || !identity.control_public_identity?.id) {
        fail('Hub-only readiness identity did not match the expected public shape');
      }
      return { health, identity };
    } catch (error) {
      last = error;
      await new Promise(resolve => setTimeout(resolve, 350));
    }
  }
  fail(`Hub-only service did not become ready (${last?.name || 'timeout'})`);
}

async function runOwnedCLI(name, args, mounts) {
  const options = ['run', '--name', name, '--network=none', '--user', `${uid}:${gid}`,
    ...fixtureLabels, '--label', 'org.cicada.fixture.role=local-cli', '--label', `org.cicada.fixture.image-id=${hubImageId}`];
  for (const mount of mounts) options.push('-v', mount);
  options.push('-e', 'CICADA_STATE_DIR=/state', '-e', 'CICADA_WORKSPACE_ROOT=/workspace', hubImageId, ...args);
  const response = await run('docker', options);
  if (response.code !== 0) {
    if (process.env.CICADA_ACCOUNT_BROWSER_DEBUG === '1' && response.stderr) {
      process.stderr.write(`local CLI diagnostic: ${response.stderr.trim().replaceAll(fixtureDir, '<fixture>').slice(0, 700)}\n`);
    }
    fail(`owned local Hub setup command failed with status ${response.code}`);
  }
  return response.stdout;
}

async function inspectOwnedContainer(name, expectedImageId, expectedRole) {
  const inspected = await run('docker', ['container', 'inspect', name]);
  if (inspected.code !== 0) return null;
  let container;
  try { [container] = JSON.parse(inspected.stdout); } catch { fail('Docker returned malformed owned-container metadata'); }
  const labels = container.Config?.Labels || {};
  if (container.Image !== expectedImageId || labels['org.cicada.fixture'] !== fixtureLabel ||
      labels['org.cicada.fixture.dir'] !== fixtureDir || labels['org.cicada.fixture.role'] !== expectedRole) {
    fail(`Refusing to remove a container that is outside this run: ${name}`);
  }
  return container;
}

async function removeOwnedContainer(name, expectedImageId, expectedRole) {
  if (!await inspectOwnedContainer(name, expectedImageId, expectedRole)) return true;
  const removed = await run('docker', ['container', 'rm', '-f', name]);
  return removed.code === 0;
}

async function removeOwnedNetwork() {
  const inspected = await run('docker', ['network', 'inspect', dockerNetwork]);
  if (inspected.code !== 0) return true;
  let network;
  try { [network] = JSON.parse(inspected.stdout); } catch { fail('Docker returned malformed owned-network metadata'); }
  const labels = network.Labels || {};
  if (labels['org.cicada.fixture'] !== fixtureLabel || labels['org.cicada.fixture.dir'] !== fixtureDir ||
      labels['org.cicada.fixture.role'] !== 'bridge') {
    fail('Refusing to remove a Docker network outside this run');
  }
  return (await run('docker', ['network', 'rm', dockerNetwork])).code === 0;
}

async function generateSyntheticPublicSPKI() {
  phase = 'synthetic_public_identity';
  const executable = await stat(opensslPath).catch(() => null);
  if (!executable?.isFile() || (executable.mode & 0o111) === 0) fail('Accepted OpenSSL executable is missing or not executable');
  const opensslEnv = { ...process.env, OPENSSL_CONF: '/dev/null', LD_LIBRARY_PATH: opensslLib };
  const version = (await checked(opensslPath, ['version'], { env: opensslEnv })).trim();
  if (!/^OpenSSL 3\.[5-9]\./.test(version)) fail('Synthetic PQ key fixture requires OpenSSL 3.5 or later');
  result.openssl = { executable_sha256: await hashFile(opensslPath), version, private_fixture: 'synthetic_only_removed_before_browser_launch' };
  for (const [algorithm, base] of [['ML-KEM-768', 'kem'], ['ML-DSA-65', 'signing']]) {
    const privatePath = path.join(privateKeysDir, `${base}-synthetic-encrypted.pem`);
    const publicPath = path.join(publicDir, `${base}-synthetic-public.pem`);
    const passphrase = `CICADA-SYNTHETIC-ONLY-${base}-${randomBytes(16).toString('hex')}\n`;
    await checked(opensslPath, ['genpkey', '-algorithm', algorithm, '-aes-256-cbc', '-pass', 'stdin', '-out', privatePath],
      { env: opensslEnv, input: passphrase });
    await chmod(privatePath, 0o600);
    await checked(opensslPath, ['pkey', '-in', privatePath, '-passin', 'stdin', '-pubout', '-out', publicPath],
      { env: opensslEnv, input: passphrase });
    await chmod(publicPath, 0o644);
    const pem = await readFile(publicPath, 'utf8');
    if (!pem.startsWith('-----BEGIN PUBLIC KEY-----') || pem.includes('PRIVATE KEY')) fail('OpenSSL did not emit a public SPKI PEM');
    await rm(privatePath, { force: true });
  }
  mark('synthetic_owner_public_spki');
}

async function provisionHub(metadata) {
  phase = 'hub_setup';
  const suffixPart = suffix.replace(/[^a-z0-9]/g, '').slice(-16);
  const networkResult = await docker(['network', 'create', ...fixtureLabels,
    '--label', 'org.cicada.fixture.role=bridge', dockerNetwork]);
  if (!networkResult.trim()) fail('Could not create the owned Docker bridge');
  networkWasCreated = true;

  const mounts = [`${stateDir}:/state`, `${workspaceDir}:/workspace`, `${publicDir}:/public`];
  await runOwnedCLI(setupContainer, ['hub', 'setup', '--owner-label', `Synthetic browser Owner ${suffixPart}`,
    '--origin', browserOrigin, '--public-config', '/public/hub-connection.json', '--allow-loopback-http',
    '--state-dir', '/state', '--workspace-root', '/workspace'], mounts);
  await runOwnedCLI(claimContainer, ['hub', 'account-claim-issue', '--claim-file', '/public/owner-account-claim.json', '--state-dir', '/state'], mounts);
  const claimFile = path.join(publicDir, 'owner-account-claim.json');
  const claimStat = await stat(claimFile);
  if (!claimStat.isFile() || (claimStat.mode & 0o777) !== 0o600) fail('Local one-use claim file is not protected mode 0600');
  const connection = JSON.parse(await readFile(path.join(publicDir, 'hub-connection.json'), 'utf8'));
  if (connection.format !== 'cicada.hub-owner-connection.v1' || connection.origin !== browserOrigin ||
      connection.allow_loopback_http !== true || !connection.account_id || !connection.owner_id || !connection.hub?.hub_id) {
    fail('Local Hub setup did not write the expected public connection identity');
  }
  mark('local_hub_setup_and_claim_issue');

  phase = 'hub_start';
  await docker(['run', '-d', '--name', hubContainer, ...fixtureLabels,
    '--label', 'org.cicada.fixture.role=hub', '--label', `org.cicada.fixture.image-id=${hubImageId}`,
    '--network', dockerNetwork, '--network-alias', hubNetworkAlias,
    '-p', '127.0.0.1::8787', '--user', `${uid}:${gid}`,
    '-v', `${stateDir}:/state`, '-v', `${workspaceDir}:/workspace`,
    '-e', 'CICADA_STATE_DIR=/state', '-e', 'CICADA_WORKSPACE_ROOT=/workspace',
    hubImageId, 'serve', '--hub-only', '--host', '0.0.0.0', '--port', '8787']);
  hubWasCreated = true;
  hubPort = portFromDocker(await docker(['port', hubContainer, '8787/tcp']));
  const hub = await waitHub();
  if (hub.identity.hub_id !== connection.hub.hub_id ||
      JSON.stringify(hub.identity.control_public_identity) !== JSON.stringify(connection.hub.control_public_identity)) {
    fail('Hub-only startup identity differs from the independently exported local connection file');
  }
  const current = await inspectOwnedContainer(hubContainer, hubImageId, 'hub');
  const mountedSources = (current?.Mounts || []).map(m => path.resolve(m.Source));
  if (mountedSources.includes(path.resolve(publicDir)) || mountedSources.includes(path.resolve(privateKeysDir))) {
    fail('Hub container unexpectedly received browser claim or Owner-key fixture files');
  }
  result.hub = {
    image_reference: hubRef, image_id: hubImageId,
    source_revision: metadata.source.revision, source_dirty: metadata.source.dirty,
    source_fingerprint: metadata.source.source_fingerprint, catalog_sha256: metadata.source.catalog_sha256,
    hub_id: hub.identity.hub_id, hub_key_id: hub.identity.control_public_identity.id,
    account_id: connection.account_id, owner_id: connection.owner_id,
    mode: 'hub-only', local_mounts_excluded_claim_and_owner_public_fixture: true,
  };
  mark('hub_only_startup');
}

class CDP {
  constructor(socket) {
    this.socket = socket;
    this.nextID = 0;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener('message', event => this.onMessage(event.data));
    socket.addEventListener('close', () => this.rejectAll(new Error('CDP closed')));
    socket.addEventListener('error', () => this.rejectAll(new Error('CDP failed')));
  }
  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP connection timeout')), 10000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('CDP connection failed')); }, { once: true });
    });
    const client = new CDP(socket);
    cdpConnections.add(client);
    return client;
  }
  on(method, fn) {
    const listeners = this.listeners.get(method) || [];
    listeners.push(fn);
    this.listeners.set(method, listeners);
    return () => this.listeners.set(method, (this.listeners.get(method) || []).filter(value => value !== fn));
  }
  async onMessage(raw) {
    let message;
    try { message = JSON.parse(typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8')); } catch { return; }
    if (message.id) {
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.error) entry.reject(new Error(`CDP ${entry.method} failed (${message.error.code})`));
      else entry.resolve(message.result || {});
      return;
    }
    for (const listener of [...(this.listeners.get(message.method) || [])]) {
      try { await listener(message.params || {}); } catch (error) { this.lastListenerError = error; }
    }
  }
  rejectAll(error) {
    for (const [id, entry] of this.pending) { clearTimeout(entry.timer); entry.reject(error); this.pending.delete(id); }
  }
  send(method, params = {}, timeoutMs = 15000) {
    if (this.socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('CDP socket is closed'));
    const id = ++this.nextID;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP ${method} timeout`)); }, timeoutMs);
      this.pending.set(id, { method, resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }
  close() { cdpConnections.delete(this); try { this.socket.close(); } catch { /* best effort */ } this.rejectAll(new Error('CDP closed')); }
}

async function createPage(port, initialURL = browserOrigin) {
  const created = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' });
  if (!created.ok) fail(`Chromium could not create a page (${created.status})`);
  const target = await created.json();
  const cdp = await CDP.connect(target.webSocketDebuggerUrl);
  cdp.targetId = target.id;
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('DOM.enable');
  await cdp.send('Network.enable');
  await cdp.send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: '/data' });
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await cdp.send('Page.navigate', { url: initialURL });
  return cdp;
}

async function closeBrowserPage(cdp, timeoutMs = 12000) {
  const targetId = cdp?.targetId;
  if (typeof targetId !== 'string' || !targetId) fail('Chromium page target ID is unavailable for bounded close');
  const deadline = Date.now() + timeoutMs;
  const targetExists = async () => {
    const response = await fetch(`http://127.0.0.1:${cdpPort}/json/list`, { cache: 'no-store' });
    if (!response.ok) throw new Error('Chromium target list is unavailable');
    const targets = await response.json();
    return targets.some(target => target.id === targetId);
  };
  try { await cdp.send('Page.close', {}, 4000); } catch { /* target close may drop its own CDP socket */ }
  while (Date.now() < deadline) {
    try {
      if (!await targetExists()) {
        cdp.close();
        return;
      }
    } catch { /* retry until the bounded close deadline */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  // Page.close can be delayed by a browser/page shutdown path. Use the owned
  // Chromium debug endpoint as a bounded fallback, then verify target removal.
  try { await fetch(`http://127.0.0.1:${cdpPort}/json/close/${encodeURIComponent(targetId)}`, { cache: 'no-store' }); }
  catch { /* the target may already be closing */ }
  const fallbackDeadline = Date.now() + 5000;
  while (Date.now() < fallbackDeadline) {
    try {
      if (!await targetExists()) {
        cdp.close();
        return;
      }
    } catch { /* retry until the bounded fallback deadline */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  cdp.close();
  fail('Chromium did not confirm closure of the original account page target');
}

async function evaluateUntil(cdp, expression, predicate = Boolean, timeoutMs = 45000, description = 'browser state') {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fatal) throw fatal;
    try {
      const response = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true }, 10000);
      if (response.exceptionDetails) fail(`Browser evaluation failed while waiting for ${description}`);
      if (predicate(response.result?.value)) return response.result.value;
    } catch (error) { if (error.message.startsWith('CDP socket')) throw error; }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  fail(`Timed out waiting for ${description}`);
}

async function evaluate(cdp, expression, timeoutMs = 15000) {
  const response = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true }, timeoutMs);
  if (response.exceptionDetails) fail('Browser action raised an exception');
  return response.result?.value;
}

async function buttonClick(cdp, label) {
  const clicked = await evaluate(cdp, `(() => { const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()===${JSON.stringify(label)}); if(!b||b.disabled)return false; b.click(); return true; })()`);
  if (clicked !== true) fail(`Expected browser action is unavailable: ${label}`);
}

async function setValue(cdp, selector, value) {
  const changed = await evaluate(cdp, `(() => { const e=document.querySelector(${JSON.stringify(selector)}); if(!e)return false; e.value=${JSON.stringify(value)}; e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); return true; })()`);
  if (changed !== true) fail(`Expected browser input is unavailable: ${selector}`);
}

function countRequests(cdp, route) {
  let count = 0;
  const remove = cdp.on('Network.requestWillBeSent', params => {
    try { if (new URL(params.request?.url || '').pathname === route) count++; } catch { /* ignore non-URL events */ }
  });
  return { get count() { return count; }, stop: remove };
}

async function setFile(cdp, selector, file) {
  const root = await cdp.send('DOM.getDocument', { depth: -1 });
  const found = await cdp.send('DOM.querySelector', { nodeId: root.root.nodeId, selector });
  if (!found.nodeId) fail(`Expected browser file input is unavailable: ${selector}`);
  await cdp.send('DOM.setFileInputFiles', { nodeId: found.nodeId, files: [file] });
}

async function installResponseLoss(cdp, route, dropFirst = true) {
  let resolveFirst;
  const firstPromise = new Promise(resolve => { resolveFirst = resolve; });
  const state = { route, events: [], resolveFirst, firstPromise, dropFirst };
  const listener = async params => {
    let requestPath = '';
    try { requestPath = new URL(params.request?.url || '').pathname; } catch { return; }
    if (requestPath !== route || !Number.isInteger(params.responseStatusCode)) return;
    let postData = params.request?.postData || '';
    if (!postData && params.networkId) {
      try { postData = (await cdp.send('Network.getRequestPostData', { requestId: params.networkId })).postData || ''; } catch { /* event may have no post body */ }
    }
    const bodyHash = postData ? createHash('sha256').update(postData).digest('hex') : '';
    const event = { status: params.responseStatusCode, body_hash: bodyHash };
    state.events.push(event);
    if (!bodyHash) state.captureError = 'The browser inspector did not expose a request body hash';
    if (state.events.length === 1 && state.dropFirst) {
      try {
        await cdp.send('Fetch.failRequest', { requestId: params.requestId, errorReason: 'Failed' });
        state.resolveFirst(event);
      } catch (error) { state.captureError = 'Chromium could not simulate the lost response'; state.resolveFirst(event); }
    } else {
      await cdp.send('Fetch.continueRequest', { requestId: params.requestId });
      if (state.events.length === 1) state.resolveFirst(event);
    }
  };
  cdp.on('Fetch.requestPaused', listener);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `*${route}`, requestStage: 'Response' }] });
  state.disable = async () => {
    try { await cdp.send('Fetch.disable'); } catch { /* connection may already be closing */ }
  };
  return state;
}

async function retryLostResponse(cdp, route, doAction, stepName) {
  const loss = await installResponseLoss(cdp, route);
  try {
    await doAction();
    let timeout;
    let first;
    try {
      first = await Promise.race([loss.firstPromise,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('lost-response interception timeout')), 60000); })]);
    } finally { clearTimeout(timeout); }
    if (first.status !== 200 || !first.body_hash || loss.captureError) fail(`Could not record the accepted ${route} response loss`);
    await evaluateUntil(cdp, `document.querySelector('#app')?.innerText || ''`, text => text.includes('Recover the saved account request'), 30000,
      `${route} exact recovery screen`);
    await cdp.send('Page.reload', { ignoreCache: true }, 10000);
    await evaluateUntil(cdp, `document.querySelector('#app')?.innerText || ''`, text => text.includes('Recover the saved account request'), 45000,
      `${route} recovery after reload`);
    await buttonClick(cdp, 'Recover exact encrypted request');
    const deadline = Date.now() + 60000;
    while (loss.events.length < 2 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 100));
    if (loss.events.length < 2) fail(`Exact ${route} retry did not reach the Hub`);
    const second = loss.events[1];
    if (second.status !== 200 || !second.body_hash || second.body_hash !== first.body_hash) {
      fail(`Exact ${route} retry changed its encrypted request bytes or did not return HTTP 200`);
    }
    await loss.disable();
    result.request_recovery[stepName] = { accepted_response_lost: true, retry_same_body_sha256: second.body_hash,
      initial_status: first.status, retry_status: second.status };
    mark(stepName);
  } finally { await loss.disable(); }
}

async function readAccountSnapshot(cdp) {
  const expression = `(() => new Promise(async(resolve,reject)=>{try{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();const s=await c.getState(db);db.close();const a=s.ownerAccount||{};const p=a.profile||{};const v=s.accountLoginVault||{};const packet=a.pending?.packet||'';const packetBytes=packet?Uint8Array.from(atob(packet),x=>x.charCodeAt(0)):new Uint8Array();const packetHash=packetBytes.length?Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',packetBytes)),x=>x.toString(16).padStart(2,'0')).join(''):'';packetBytes.fill(0);const walk=(value,seen=new Set())=>{if(!value||typeof value!=='object'||seen.has(value))return[];seen.add(value);let out=[];for(const k of Object.keys(value)){out.push(k);try{out.push(...walk(value[k],seen))}catch{}}return out};const names=walk(s);resolve({pin:s.pin?{origin:s.pin.origin,hubId:s.pin.hubId,keyId:s.pin.keyId}:null,profile:a.profile?{origin:p.origin,hubId:p.hubId,accountId:p.accountId,ownerId:p.ownerId,deviceId:p.deviceId,username:p.username,ownerKeyId:p.ownerPublicIdentity?.id||'',ownerFingerprint:p.ownerFingerprint||''}:null,pendingPhase:a.pending?.phase||'',pendingPacketSha256:packetHash,vaultFormat:v.format||'',vaultCiphertextLength:(v.ciphertext||'').length,localStorageKeys:Array.from({length:localStorage.length},(_,i)=>localStorage.key(i)).filter(x=>/session|token|password|claim|code/i.test(x||'')),sensitiveFieldNames:names.filter(x=>/password|passphrase|claim.?code|session.?token|identity.?blob|private.?key/i.test(x)),localStorageLength:localStorage.length})}catch{reject(new Error('snapshot'))}}))()`;
  return evaluate(cdp, expression, 20000);
}

async function recoverClaimCompletionAcrossTabs(cdp) {
  const route = '/v2/owner/account/claim/complete';
  const loss = await installResponseLoss(cdp, route);
  const requestCount = countRequests(cdp, route);
  let secondPage = null;
  try {
    const submit = await evaluate(cdp, `(() => {const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()==='Create Owner account');if(!b||b.disabled)return {found:false};b.click();const disabledAfterFirst=b.disabled;b.click();return {found:true,disabledAfterFirst}})()`);
    if (!submit?.found || submit.disabledAfterFirst !== true) fail('Owner account submit button did not enter single-flight disabled state on the first click');
    let timeout;
    let first;
    try {
      first = await Promise.race([loss.firstPromise,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('claim completion lost-response interception timeout')), 60000); })]);
    } finally { clearTimeout(timeout); }
    if (first.status !== 200 || !first.body_hash || loss.captureError) fail('Could not record the accepted claim completion response loss');
    await evaluateUntil(cdp, `document.querySelector('#app')?.innerText || ''`, text => text.includes('Recover the saved account request'), 30000,
      'claim completion exact recovery screen');
    await new Promise(resolve => setTimeout(resolve, 350));
    if (requestCount.count !== 1 || loss.events.length !== 1) fail('Double-click initiated more than one claim-completion request');

    const original = await readAccountSnapshot(cdp);
    if (original.pendingPhase !== 'CLAIM_COMPLETE_PENDING' || !original.pendingPacketSha256) {
      fail('Accepted claim completion packet was not retained as exact pending encrypted state');
    }

    secondPage = await createPage(cdpPort);
    await evaluateUntil(secondPage, `Boolean(document.querySelector('#owner-account-lock-blocked') &&
      document.querySelector('#owner-account-lock-blocked').dataset.accountLock === 'unavailable')`, Boolean, 45000,
      'second-tab account writer lock notice');
    const blocked = await evaluate(secondPage, `(() => ({
      notice:document.querySelector('#owner-account-lock-blocked')?.textContent||'',
      claimForm:Boolean(document.querySelector('#owner-account-username')),
      loginForm:Boolean(document.querySelector('#owner-login-username')),
      activeSubmit:[...document.querySelectorAll('button')].some(b=>!b.disabled&&/Create Owner account|Recover exact encrypted request|Sign in/.test(b.textContent.trim()))
    }))()`);
    if (!blocked.notice || blocked.claimForm || blocked.loginForm || blocked.activeSubmit) {
      fail('Second restored tab was not visibly read-only while the first tab owned the account lock');
    }
    const secondSnapshot = await readAccountSnapshot(secondPage);
    if (secondSnapshot.pendingPhase !== original.pendingPhase ||
        secondSnapshot.pendingPacketSha256 !== original.pendingPacketSha256) {
      fail('Second tab changed the exact accepted pending claim packet while showing the writer lock');
    }

    // Closing the first page releases its Web Lock. Reload the blocked page so
    // it takes the lease and recovers the same persisted encrypted request.
    await closeBrowserPage(cdp);
    page = secondPage;
    secondPage = null;
    await reloadPage(page);
    await evaluateUntil(page, `document.querySelector('#app')?.innerText || ''`, text => text.includes('Recover the saved account request'),
      45000, 'claim completion recovery after first tab closes');
    const beforeRetry = await readAccountSnapshot(page);
    if (beforeRetry.pendingPhase !== original.pendingPhase ||
        beforeRetry.pendingPacketSha256 !== original.pendingPacketSha256) {
      fail('Claim completion pending bytes changed after releasing and reacquiring the account lock');
    }

    const retry = await installResponseLoss(page, route, false);
    try {
      await buttonClick(page, 'Recover exact encrypted request');
      let retryResponse;
      let retryTimeout;
      try {
        retryResponse = await Promise.race([retry.firstPromise,
          new Promise((_, reject) => { retryTimeout = setTimeout(() => reject(new Error('claim completion exact retry timeout')), 60000); })]);
      } finally { clearTimeout(retryTimeout); }
      if (retry.events.length !== 1 || retryResponse.status !== 200 || retryResponse.body_hash !== first.body_hash) {
        fail('Second tab did not recover with the exact encrypted completion request accepted by the Hub');
      }
      await evaluateUntil(page, `Boolean(document.querySelector('#owner-login-password'))`, Boolean, 45000,
        'Owner login form after cross-tab exact recovery');
      result.request_recovery.account_complete_lost_response_exact_retry = {
        accepted_response_lost: true, retry_same_body_sha256: retryResponse.body_hash,
        initial_status: first.status, retry_status: retryResponse.status,
        double_submit_requests_before_recovery: requestCount.count,
        blocked_second_tab_pending_packet_sha256: original.pendingPacketSha256,
      };
      mark('account_complete_lost_response_exact_retry');
      mark('two_tab_claim_writer_lock_recovery');
    } finally { await retry.disable(); }
  } finally {
    requestCount.stop();
    await loss.disable();
    try { secondPage?.close(); } catch { /* best effort */ }
  }
}

async function waitForHeadingOrInput(cdp, selector, description) {
  await evaluateUntil(cdp, `Boolean(document.querySelector(${JSON.stringify(selector)}))`, Boolean, 45000, description);
}

async function reloadPage(cdp) {
  await cdp.send('Page.reload', { ignoreCache: true }, 10000);
  await evaluateUntil(cdp, 'document.readyState', state => state === 'complete', 45000, 'panel reload');
}

function identityForWASM(info) {
  return `{contract:${JSON.stringify(info.contract)},hub_id:${JSON.stringify(info.hub_id)},control_public_identity:${JSON.stringify(info.control_public_identity)},control_key_version:${info.control_key_version},suite:${JSON.stringify(info.suite)}}`;
}

async function directAccountNegative(cdp, kind) {
  const hubJSON = await directJSON(`http://127.0.0.1:${hubPort}/v2/client/identity`);
  const hubExpression = identityForWASM(hubJSON);
  const expression = kind === 'unknown-device' ? ` (async()=>{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();const s=await c.getState(db);db.close();const p=s.ownerAccount.profile;const id=cicadaWebCrypto.generateIdentity({});if(!id?.ok)throw Error('gen');try{const hub=${hubExpression};const suffix=Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,'0')).join('');const req=cicadaWebCrypto.sealOwnerLoginPrepare({handle:id.handle,hub_identity:hub,origin:location.origin,account_id:p.accountId,owner_id:p.ownerId,device_id:'accountdev_'+suffix,username:p.username});if(!req?.ok)throw Error('seal');const bytes=Uint8Array.from(atob(req.packet),x=>x.charCodeAt(0));const res=await fetch('/v2/owner/account/login/prepare',{method:'POST',cache:'no-store',credentials:'omit',headers:{'Content-Type':'application/json'},body:bytes});return {status:res.status};}finally{id.identity_blob='';cicadaWebCrypto.forgetIdentity({handle:id.handle})}})()` : ` (async()=>{const c=await import('/assets/panel-client.js');const db=await c.openPanelDB();const s=await c.getState(db);db.close();const p=s.ownerAccount.profile;const v=s.accountLoginVault;let blob=await c.decryptAccountDeviceIdentity(v,p.origin,p.hubId,p.accountId,p.deviceId,p.publicIdentity,p.allowLoopbackHTTP);const id=cicadaWebCrypto.importIdentity({identity_blob:blob});blob='';if(!id?.ok)throw Error('import');try{const hub=${hubExpression};const prep=cicadaWebCrypto.sealOwnerLoginPrepare({handle:id.handle,hub_identity:hub,origin:location.origin,account_id:p.accountId,owner_id:p.ownerId,device_id:p.deviceId,username:p.username});if(!prep?.ok)throw Error('prepare');const reqBytes=Uint8Array.from(atob(prep.packet),x=>x.charCodeAt(0));const prepared=await fetch('/v2/owner/account/login/prepare',{method:'POST',cache:'no-store',credentials:'omit',headers:{'Content-Type':'application/json'},body:reqBytes});if(prepared.status!==200)return {prepare_status:prepared.status,complete_status:0};const challenge=btoa(String.fromCharCode(...new Uint8Array(await prepared.arrayBuffer())));const complete=cicadaWebCrypto.sealOwnerLoginComplete({handle:id.handle,hub_identity:hub,prepare_packet:prep.packet,challenge_packet:challenge,origin:p.origin,account_id:p.accountId,owner_id:p.ownerId,device_id:p.deviceId,username:p.username,password:'definitely-wrong-synthetic-test-password'});if(!complete?.ok)throw Error('complete');const body=Uint8Array.from(atob(complete.packet),x=>x.charCodeAt(0));const rejected=await fetch('/v2/owner/account/login/complete',{method:'POST',cache:'no-store',credentials:'omit',headers:{'Content-Type':'application/json'},body});return {prepare_status:prepared.status,complete_status:rejected.status};}finally{cicadaWebCrypto.forgetIdentity({handle:id.handle})}})()`;
  return evaluate(cdp, expression, 60000);
}

async function restartHub(identityBefore) {
  phase = 'hub_restart';
  await docker(['stop', '--time', '10', hubContainer]);
  await docker(['start', hubContainer]);
  const priorPort = hubPort;
  hubPort = portFromDocker(await docker(['port', hubContainer, '8787/tcp']));
  result.hub.restart_published_port_reassigned = priorPort !== hubPort;
  let after;
  try {
    after = await waitHub();
  } catch {
    const container = await inspectOwnedContainer(hubContainer, hubImageId, 'hub');
    const state = container?.State || {};
    result.hub.restart_readiness = { container_status: state.Status || 'UNKNOWN', exit_code: state.ExitCode ?? null,
      oom_killed: state.OOMKilled === true };
    fail(`Hub-only service did not become ready after restart (owned container ${state.Status || 'UNKNOWN'}, exit ${state.ExitCode ?? 'unknown'})`);
  }
  if (after.identity.hub_id !== identityBefore.hub_id ||
      JSON.stringify(after.identity.control_public_identity) !== JSON.stringify(identityBefore.control_public_identity)) {
    fail('Hub restart changed its stable public identity');
  }
  result.hub.restart_identity_stable = true;
}

async function startBrowser() {
  phase = 'browser_start';
  const [image] = await dockerJSON(['image', 'inspect', chromiumRef]);
  chromiumImageId = image.Id;
  result.chromium = { image_reference: chromiumRef, image_id: chromiumImageId, repo_digests: image.RepoDigests || [],
    origin: browserOrigin, transport: 'literal loopback HTTP, explicitly enabled for this disposable fixture', public_https: 'NOT_RUN' };
  await docker(['run', '-d', '--name', browserContainer, ...fixtureLabels,
    '--label', 'org.cicada.fixture.role=chromium', '--label', `org.cicada.fixture.image-id=${chromiumImageId}`,
    '--network', dockerNetwork, '-p', '127.0.0.1::9222', '--shm-size', '1g', '--pids-limit', '256',
    '--user', `${uid}:${gid}`, '-v', `${browserDir}:/data`, '-v', `${publicDir}:/public:ro`,
    chromiumImageId, '--user-data-dir=/data/profile', '--disk-cache-dir=/data/cache',
    '--lang=en-US',
    '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update']);
  browserWasCreated = true;
  cdpPort = portFromDocker(await docker(['port', browserContainer, '9222/tcp']));
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const version = await directJSON(`http://127.0.0.1:${cdpPort}/json/version`);
      if (!String(version.Browser || '').startsWith('Chrome/')) fail('Disposable browser is not Chromium');
      result.chromium.browser_version = version.Browser;
      result.chromium.user_agent = await (async () => {
        const probe = await createPage(cdpPort, 'about:blank');
        const agent = await evaluate(probe, 'navigator.userAgent');
        probe.close();
        return agent;
      })();
      const proxy = await run('docker', ['exec', '-d', browserContainer, '/usr/bin/socat',
        'TCP4-LISTEN:8787,bind=127.0.0.1,reuseaddr,fork', `TCP4:${hubNetworkAlias}:8787`]);
      if (proxy.code !== 0) fail('Disposable Chromium image does not provide the local TCP bridge needed for the exact test origin');
      page = await createPage(cdpPort);
      await evaluateUntil(page, "document.querySelector('#app')?.innerText || ''", text => text.includes('Set up the first Owner account'),
        60000, 'first Owner account claim page');
      return;
    } catch (error) {
      if (error.message.startsWith('Disposable browser is not')) throw error;
      await new Promise(resolve => setTimeout(resolve, 300));
    }
  }
  fail('Disposable Chromium/CDP did not start');
}

async function ownerAccountBrowserFlow() {
  phase = 'browser_first_claim_page';
  const first = await evaluate(page, `({claim:Boolean(document.querySelector('#owner-claim-card')), pin:Boolean(document.querySelector('#pin-hub-id')), title:document.querySelector('#app h1')?.textContent||'', body:document.querySelector('#app')?.innerText||''})`);
  if (!first.claim || first.pin || !first.body.includes('PAGE 1 OF 2')) {
    fail('Fresh Hub page must begin with the installer claim, not a separate first-visitor pin or identity form');
  }
  mark('fresh_first_page_claim_flow');

  await setFile(page, '#owner-claim-file', '/public/owner-account-claim.json');
  await evaluateUntil(page, "Boolean(document.querySelector('#owner-claim-card')?.value)", Boolean, 10000, 'selected installer claim JSON');
  await buttonClick(page, 'Verify origin and full Hub fingerprint');
  await evaluateUntil(page, "document.querySelector('#owner-claim-pin-confirm') !== null", Boolean, 10000, 'installer identity confirmation');
  const reviewed = await evaluate(page, `(() => {const x=document.querySelector('#app')?.innerText||'';return {hasOrigin:x.includes(${JSON.stringify(browserOrigin)}),hasFullFingerprint:/[0-9a-f]{64}/.test(x),hasSecret:x.includes('code:')}})()`);
  if (!reviewed.hasOrigin || !reviewed.hasFullFingerprint || reviewed.hasSecret) fail('Claim review did not independently display only safe origin/full-fingerprint metadata');
  await evaluate(page, "document.querySelector('#owner-claim-pin-confirm').checked=true;document.querySelector('#owner-claim-pin-confirm').dispatchEvent(new Event('change',{bubbles:true}));true");

  phase = 'claim_prepare_response_loss';
  await retryLostResponse(page, '/v2/owner/account/claim/prepare',
    () => buttonClick(page, 'Continue to Owner credentials'), 'first_claim_prepare_lost_response_exact_retry');
  await waitForHeadingOrInput(page, '#owner-account-username', 'Owner account credential page');
  const pageTwo = await evaluate(page, "document.querySelector('#app')?.innerText || ''");
  if (!pageTwo.includes('PAGE 2 OF 2')) fail('Account credential setup is not the documented second page');

  await setValue(page, '#owner-account-username', 'synthetic-owner-browser');
  await setValue(page, '#owner-account-password', 'synthetic-account-password-2026!');
  await setValue(page, '#owner-account-password-confirm', 'synthetic-account-password-2026!');
  await setFile(page, '#owner-kem-public', '/public/kem-synthetic-public.pem');
  await setFile(page, '#owner-signing-public', '/public/signing-synthetic-public.pem');

  phase = 'claim_complete_response_loss';
  await recoverClaimCompletionAcrossTabs(page);
  await waitForHeadingOrInput(page, '#owner-login-password', 'Owner account login page after claim');
  const claimed = await readAccountSnapshot(page);
  if (!claimed.profile || claimed.profile.username !== 'synthetic-owner-browser' || !claimed.profile.ownerKeyId ||
      claimed.pendingPhase || claimed.vaultFormat !== 'cicada.owner-account-device-vault.v1' || claimed.sensitiveFieldNames.length ||
      claimed.localStorageKeys.length) fail('Browser did not persist only the public account profile and encrypted device vault');
  result.hub.account_device_id = claimed.profile.deviceId;
  result.hub.pending_owner_key_id = claimed.profile.ownerKeyId;
  result.hub.account_claim_state = 'ACCOUNT_READY_OWNER_SIGNER_PENDING';
  mark('first_account_claim_committed_pending_root');

  phase = 'unknown_device';
  const unknown = await directAccountNegative(page, 'unknown-device');
  if (unknown.status !== 403) fail(`Unknown account device must be rejected with generic HTTP 403 (got ${unknown.status})`);
  mark('unknown_device_rejected');

  await setValue(page, '#owner-login-username', 'synthetic-owner-browser');
  await setValue(page, '#owner-login-password', 'synthetic-wrong-account-password-2026!');
  const loginPrepareCount = countRequests(page, '/v2/owner/account/login/prepare');
  await buttonClick(page, 'Sign in');
  await waitForHeadingOrInput(page, '#owner-login-password', 'login form after rejected synthetic password');
  await evaluateUntil(page, "document.querySelector('#app')?.innerText || ''",
    text => text.includes('saved login challenge is intact'), 45000, 'saved login challenge after wrong password');
  const rejectedLogin = await readAccountSnapshot(page);
  if (rejectedLogin.pendingPhase !== 'LOGIN_CHALLENGE_SAVED') fail('Wrong password did not preserve the accepted login challenge');
  mark('wrong_password_rejected');
  mark('wrong_password_ui_retains_saved_challenge');

  await setValue(page, '#owner-login-password', 'synthetic-account-password-2026!');
  phase = 'login_complete_response_loss';
  await retryLostResponse(page, '/v2/owner/account/login/complete',
    () => buttonClick(page, 'Sign in'), 'login_complete_lost_response_exact_retry');
  if (loginPrepareCount.count !== 1) fail('Correct password did not reuse the saved challenge from the rejected login');
  loginPrepareCount.stop();
  await evaluateUntil(page, "document.querySelector('#app')?.innerText || ''", text => text.includes('Root signer state:') && text.includes('PENDING_PROOF'),
    45000, 'authenticated pending Root status');
  const status = await evaluate(page, "document.querySelector('#app')?.innerText || ''");
  if (!status.includes('Root active: No') || !status.includes('PENDING_PROOF') || !status.includes('does not create Root authority')) {
    fail('Authenticated account status implied an active Root or manager authority');
  }
  mark('login_complete_lost_response_exact_retry');

  phase = 'manager_rpc_guard';
  const managerStatus = await evaluate(page, `(async()=>{const r=await fetch('/v2/client/rpc',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:'{}'});return r.status})()`);
  const caps = await directJSON(`http://127.0.0.1:${hubPort}/v2/client/capabilities`);
  if (managerStatus !== 503 || caps.status !== 'not_ready' || caps.topology_management !== false || caps.control_intents !== false) {
    fail('Hub-only manager API/capabilities became available to an Owner account login');
  }
  mark('manager_rpc_unavailable_in_hub_only');
  mark('first_account_pending_root_no_manager');

  phase = 'logout_response_loss';
  await retryLostResponse(page, '/v2/owner/account/session/logout',
    () => buttonClick(page, 'Sign out'), 'logout_lost_response_reload_exact_retry');
  await waitForHeadingOrInput(page, '#owner-login-password', 'signed-out Owner account login form');
  const signedOut = await readAccountSnapshot(page);
  if (signedOut.pendingPhase) fail('Recovered logout left an account request pending');
  phase = 'reload_vault';
  await reloadPage(page);
  await waitForHeadingOrInput(page, '#owner-login-password', 'login after browser reload');
  const afterReload = await readAccountSnapshot(page);
  if (afterReload.profile?.accountId !== claimed.profile.accountId || afterReload.profile?.deviceId !== claimed.profile.deviceId ||
      afterReload.vaultFormat !== claimed.vaultFormat || afterReload.sensitiveFieldNames.length ||
      (await evaluate(page, "Boolean(document.querySelector('#owner-account-password'))"))) {
    fail('Reload did not restore the same encrypted account device or incorrectly persisted an authenticated session');
  }
  mark('encrypted_browser_device_vault_reload');

  // Restart the actual Hub-only process with the exact same owned state volume.
  const identityBefore = await directJSON(`http://127.0.0.1:${hubPort}/v2/client/identity`);
  await restartHub(identityBefore);
  await reloadPage(page);
  await waitForHeadingOrInput(page, '#owner-login-password', 'account login after Hub restart');
  await setValue(page, '#owner-login-username', 'synthetic-owner-browser');
  await setValue(page, '#owner-login-password', 'synthetic-account-password-2026!');
  await buttonClick(page, 'Sign in');
  await evaluateUntil(page, "document.querySelector('#app')?.innerText || ''", text => text.includes('Root signer state:') && text.includes('PENDING_PROOF'),
    60000, 'authenticated account after Hub restart');
  const afterRestart = await readAccountSnapshot(page);
  if (afterRestart.profile?.accountId !== claimed.profile.accountId || afterRestart.profile?.ownerId !== claimed.profile.ownerId ||
      afterRestart.profile?.deviceId !== claimed.profile.deviceId) fail('Account, Owner, or login-device IDs changed after Hub restart');
  mark('hub_restart_preserves_account_and_pending_root');

  try {
    const stats = await run('docker', ['stats', '--no-stream', '--format', '{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.PIDs}}', hubContainer]);
    const statsLine = stats.stdout.trim().split(/\r?\n/)[0] || '';
    if (stats.code === 0 && statsLine.split('|').length === 4) {
      result.hub.container_usage_snapshot = { captured_at: new Date().toISOString(), values: statsLine.split('|'),
        meaning: 'single docker stats --no-stream point-in-time snapshot; not a peak measurement or stress benchmark' };
    } else {
      result.hub.container_usage_snapshot = { status: 'UNAVAILABLE' };
    }
  } catch {
    result.hub.container_usage_snapshot = { status: 'UNAVAILABLE' };
  }
  result.hub.current_root_state = 'PENDING_PROOF';
}

async function cleanup() {
  const cleaned = { chromium_container_removed: true, hub_container_removed: true,
    setup_cli_container_removed: true, claim_cli_container_removed: true,
    network_removed: true, fixture_directory_removed: true };
  try { page?.close(); } catch { /* best effort */ }
  cleaned.chromium_container_removed = await removeOwnedContainer(browserContainer, chromiumImageId, 'chromium');
  cleaned.hub_container_removed = await removeOwnedContainer(hubContainer, hubImageId, 'hub');
  cleaned.setup_cli_container_removed = await removeOwnedContainer(setupContainer, hubImageId, 'local-cli');
  cleaned.claim_cli_container_removed = await removeOwnedContainer(claimContainer, hubImageId, 'local-cli');
  cleaned.network_removed = await removeOwnedNetwork();
  const resourcesStopped = cleaned.chromium_container_removed && cleaned.hub_container_removed &&
    cleaned.setup_cli_container_removed && cleaned.claim_cli_container_removed && cleaned.network_removed;
  if (resourcesStopped && within(outputDir, fixtureDir)) await rm(fixtureDir, { recursive: true, force: true });
  cleaned.fixture_directory_removed = (await run('test', ['-e', fixtureDir])).code !== 0;
  const okay = Object.values(cleaned).every(value => value === true);
  result.fixture_cleanup = { status: okay ? 'PASS' : 'FAIL', ...cleaned };
  if (!okay && result.status === 'PASS') result.status = 'FAIL';
}

async function main() {
  if (!within(outputParent, outputDir) || outputDir === outputParent) fail('Evidence directory must be a new child of the owned browser evidence directory');
  await ensureDir(outputParent);
  await mkdir(outputDir, { mode: 0o700 });
  await chmod(outputDir, 0o700);
  await ensureDir(fixtureDir);
  for (const directory of [stateDir, workspaceDir, publicDir, privateKeysDir, browserDir]) await ensureDir(directory);
  await writeFile(path.join(outputDir, 'cleanup-plan.json'), `${JSON.stringify(result.owned_fixture, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  result.scripts = { driver_sha256: await hashFile(scriptPath) };

  phase = 'metadata';
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
  const image = await inspectImage(hubRef);
  hubImageId = image.Id;
  const labels = image.Config?.Labels || {};
  if (!metadata.image?.id || metadata.image.id !== hubImageId || !metadata.source?.source_fingerprint ||
      metadata.source.source_fingerprint !== expectedFingerprint || labels['org.cicada.build.source-fingerprint'] !== expectedFingerprint ||
      labels['org.opencontainers.image.revision'] !== metadata.source.revision ||
      labels['org.cicada.client-catalog.sha256'] !== metadata.source.catalog_sha256 ||
      labels['org.cicada.build.dirty'] !== String(metadata.source.dirty)) {
    fail('Hub image ID, build metadata, labels, and explicit source fingerprint do not match');
  }
  result.build = { metadata_sha256: await hashFile(metadataPath), image_reference: hubRef, image_id: hubImageId,
    source_revision: metadata.source.revision, source_dirty: metadata.source.dirty,
    source_fingerprint: metadata.source.source_fingerprint, catalog_sha256: metadata.source.catalog_sha256 };
  mark('build_metadata_and_image_pin');
  const dockerInfo = await run('docker', ['info', '--format', '{{.ServerVersion}}']);
  if (dockerInfo.code !== 0) fail('Docker daemon is unavailable');

  await generateSyntheticPublicSPKI();
  await provisionHub(metadata);
  await startBrowser();
  await ownerAccountBrowserFlow();
  result.status = 'PASS';
}

let failure = null;
try { await main(); }
catch (error) {
  failure = error;
  result.status = phase === 'prerequisites' || phase === 'metadata' ? 'BLOCKED' : 'FAIL';
  result.failure = { phase, reason: error?.message || 'unknown failure' };
}
finally {
  try { await cleanup(); }
  catch (error) { result.fixture_cleanup = { status: 'FAIL', reason: error?.message || 'cleanup failed' }; result.status = 'FAIL'; }
  result.completed_at = new Date().toISOString();
  try {
    await writeFile(path.join(outputDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await chmod(path.join(outputDir, 'result.json'), 0o600);
  } catch (error) {
    process.stderr.write(`FAIL: could not write redacted result JSON (${error?.code || 'write error'}).\n`);
    result.status = 'FAIL';
  }
}

if (result.status === 'PASS') {
  process.stdout.write(`PASS: disposable Hub-only Owner account browser gate; redacted result ${path.join(outputDir, 'result.json')}\n`);
} else {
  process.stderr.write(`${result.status}: Hub-only Owner account browser gate failed in ${result.failure?.phase || phase}; redacted result ${path.join(outputDir, 'result.json')}\n`);
  if (failure && process.env.CICADA_ACCOUNT_BROWSER_DEBUG === '1') process.stderr.write(`${failure.stack}\n`);
  process.exitCode = 1;
}
