import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

function take(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker);
  assert.ok(start >= 0 && end > start, 'source markers must exist in order');
  assert.equal(source.indexOf(startMarker, start + startMarker.length), -1, 'start marker must be unique');
  assert.equal(source.indexOf(endMarker, end + endMarker.length), -1, 'end marker must be unique');
  return source.slice(start, end);
}

export async function runChecks(source, sourceURL) {
  let cases = 0;
  assert.equal(take('START body END', 'START', 'END'), 'START body ');
  cases++;
  for (const [text, start, end] of [
    ['body END', 'START', 'END'],
    ['START body', 'START', 'END'],
    ['START START END', 'START', 'END'],
    ['START END END', 'START', 'END'],
    ['END body START', 'START', 'END'],
    ['START body', 'START', 'START'],
  ]) {
    assert.throws(() => take(text, start, end));
    cases++;
  }

  const ctx = vm.createContext({
    hubContainer: 'owned-hub', hubImageId: 'hub-image',
    browserContainer: 'owned-chrome', chromiumImageId: 'chrome-image',
    result: { chromium: {} },
    fail: message => { throw new Error(message); },
    AbortController, setTimeout, clearTimeout,
  });
  vm.runInContext(take(source, 'async function directJSON(', 'async function waitHub(') + '\n' +
    take(source, 'const browserPidsLimit =', 'async function startBrowser('), ctx);
  const rootLine = take(source, 'const repoRoot =', 'const scriptPath =');
  for (const [url, expected] of [
    [sourceURL, path.dirname(path.dirname(fileURLToPath(sourceURL)))],
    ['file:///opt/cicada/scripts/test-hub-web-panel-browser.mjs', '/opt/cicada'],
    ['file:///tmp/with%20space/scripts/test-hub-web-panel-browser.mjs', '/tmp/with space'],
  ]) {
    const actual = vm.runInNewContext(rootLine.replace('import.meta.url', JSON.stringify(url)) +
      '\nrepoRoot;', { path, fileURLToPath });
    assert.equal(actual, expected);
    cases++;
  }

  vm.runInContext(take(source, 'async function inspectOwnedContainer(', 'async function removeOwnedContainer('), ctx);
  Object.assign(ctx, { fixtureLabel: 'owned-label', fixtureDir: '/synthetic-fixture' });
  const labels = {
    'org.cicada.fixture': 'owned-label',
    'org.cicada.fixture.dir': '/synthetic-fixture',
  };
  ctx.run = async () => ({ code: 0, stdout: JSON.stringify([
    { Image: 'hub-image', Config: { Labels: labels } },
  ]) });
  assert.equal((await ctx.inspectOwnedContainer('owned-hub', 'hub-image')).Image, 'hub-image');
  cases++;
  for (const row of [
    { Image: 'other-image', Config: { Labels: labels } },
    { Image: 'hub-image', Config: { Labels: { ...labels, 'org.cicada.fixture': 'other' } } },
    { Image: 'hub-image', Config: { Labels: { ...labels, 'org.cicada.fixture.dir': '/other' } } },
  ]) {
    ctx.run = async () => ({ code: 0, stdout: JSON.stringify([row]) });
    await assert.rejects(ctx.inspectOwnedContainer('owned-hub', 'hub-image'));
    cases++;
  }
  ctx.run = async () => ({ code: 1, stdout: '' });
  assert.equal(await ctx.inspectOwnedContainer('owned-hub', 'hub-image'), null);
  cases++;

  for (const route of ['/healthz', '/v2/client/identity']) {
    assert.equal(ctx.hubReadinessURL('owned-hub', route, '127.0.0.1:32123\n'),
      'http://127.0.0.1:32123' + route);
    cases++;
  }
  for (const [name, route, port] of [
    ['other', '/healthz', '127.0.0.1:1234'],
    ['owned-hub', '/v1/goals', '127.0.0.1:1234'],
    ['owned-hub', '/healthz?extra=1', '127.0.0.1:1234'],
    ['owned-hub', '/healthz', '0.0.0.0:1234'],
    ['owned-hub', '/healthz', '[::1]:1234'],
    ['owned-hub', '/healthz', '127.0.0.1:0'],
    ['owned-hub', '/healthz', '127.0.0.1:65536'],
    ['owned-hub', '/healthz', '127.0.0.1:12\n127.0.0.1:13'],
  ]) {
    assert.throws(() => ctx.hubReadinessURL(name, route, port));
    cases++;
  }

  let fetches = 0;
  let inspected = 0;
  ctx.inspectOwnedContainer = async (name, image) => {
    inspected++;
    assert.equal(name, 'owned-hub');
    assert.equal(image, 'hub-image');
    return {};
  };
  ctx.docker = async args => {
    assert.deepEqual(Array.from(args), ['port', 'owned-hub', '8787/tcp']);
    return '127.0.0.1:54321';
  };
  ctx.fetch = async url => {
    fetches++;
    assert.equal(url, 'http://127.0.0.1:54321/healthz');
    return { ok: true, json: async () => ({ status: 'ok' }) };
  };
  assert.equal((await ctx.containerJSON('owned-hub', '/healthz')).status, 'ok');
  assert.equal(inspected, 1);
  cases++;
  await assert.rejects(ctx.containerJSON('other', '/healthz'));
  assert.equal(fetches, 1);
  cases++;
  ctx.inspectOwnedContainer = async () => null;
  await assert.rejects(ctx.containerJSON('owned-hub', '/healthz'));
  assert.equal(fetches, 1);
  cases++;
  ctx.fetch = async () => ({ ok: false, status: 503 });
  await assert.rejects(ctx.directJSON('http://127.0.0.1:1/healthz'));
  cases++;
  ctx.fetch = async () => ({ ok: true, json: async () => { throw new SyntaxError('synthetic'); } });
  await assert.rejects(ctx.directJSON('http://127.0.0.1:1/healthz'));
  cases++;
  ctx.fetch = async (url, { signal }) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('synthetic timeout')));
  });
  await assert.rejects(ctx.directJSON('http://127.0.0.1:1/healthz', 1));
  cases++;

  ctx.inspectOwnedContainer = async (name, image) => {
    assert.equal(name, 'owned-chrome');
    assert.equal(image, 'chrome-image');
    return { HostConfig: { PidsLimit: 256 } };
  };
  await ctx.verifyBrowserPidsLimit();
  assert.equal(ctx.result.chromium.pids_limit, 256);
  cases++;
  for (const value of [128, 0, -1, null, '256']) {
    ctx.inspectOwnedContainer = async () => ({ HostConfig: { PidsLimit: value } });
    await assert.rejects(ctx.verifyBrowserPidsLimit());
    cases++;
  }
  const start = take(source, 'async function startBrowser()', 'async function importFile(');
  const argsLiteral = take(start, 'await docker([', '\n  ]);').slice('await docker('.length) + '\n  ]';
  Object.assign(ctx, {
    fixtureLabels: () => [], dockerNetwork: 'network', browserDir: '/data', chromiumRef: 'chrome-image',
    process: { getuid: () => 1000, getgid: () => 1000 },
  });
  const argv = vm.runInContext(argsLiteral, ctx);
  assert.equal(argv.filter(value => value === '--pids-limit').length, 1);
  assert.equal(argv[argv.indexOf('--pids-limit') + 1], '256');
  cases++;
  return { status: 'PASS_PURE_BROWSER_QA_CONFIG', cases, Docker_browser_network_models: 0 };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sourceURL = new URL('./test-hub-web-panel-browser.mjs', import.meta.url);
  console.log(JSON.stringify(await runChecks(await readFile(sourceURL, 'utf8'), sourceURL.href)));
}
