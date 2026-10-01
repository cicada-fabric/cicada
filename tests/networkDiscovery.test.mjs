import test from 'node:test';
import assert from 'node:assert/strict';
import {
  appendNetworkDirectoryPage, emptyNetworkDirectoryView, NetworkDiscoveryLifecycle,
  networkDiscoveryScopeKey,
} from '../src/platform/networkDiscovery.ts';
import {networkDirectoryPageFromRpc} from '../src/platform/networkTopology.ts';

const scope = (overrides = {}) => Object.assign({
  profileId: 'profile-a', selectionGeneration: 8, networkId: 'network-a', hubId: 'hub-a',
  ownerId: 'owner-a', deviceId: 'device-a', sessionEpoch: 3,
  authorityRevision: 'v1.6:manager:directory', fenceRevision: 'ready', networkVersion: 2,
}, overrides);

const endpoint = (id, alias = id) => ({
  network_id: 'network-a', endpoint_id: id, alias, presence: 'UNKNOWN',
});

const page = (endpoints, next_cursor) => {
  const result = {network_id: 'network-a', endpoints};
  if (next_cursor) result.next_cursor = next_cursor;
  return result;
};

test('discovery scope changes when profile, selected Network, or read authority changes', () => {
  const initial = networkDiscoveryScopeKey(scope());
  assert.notEqual(networkDiscoveryScopeKey(scope({profileId: 'profile-b'})), initial);
  assert.notEqual(networkDiscoveryScopeKey(scope({selectionGeneration: 9})), initial);
  assert.notEqual(networkDiscoveryScopeKey(scope({networkId: 'network-b'})), initial);
  assert.notEqual(networkDiscoveryScopeKey(scope({authorityRevision: 'v1.6:external:no-directory'})), initial);
  assert.notEqual(networkDiscoveryScopeKey(scope({fenceRevision: 'fenced'})), initial);
});

test('old read callbacks stop matching after a profile or authority lifecycle invalidation', () => {
  const lifecycle = new NetworkDiscoveryLifecycle();
  const originalScope = networkDiscoveryScopeKey(scope());
  const token = lifecycle.capture(originalScope);
  assert.equal(lifecycle.isCurrent(token, originalScope), true);
  assert.equal(lifecycle.isCurrent(token, networkDiscoveryScopeKey(scope({networkId: 'network-b'}))), false);
  lifecycle.invalidate();
  assert.equal(lifecycle.isCurrent(token, originalScope), false);
});

test('directory pagination deduplicates Endpoint references and stops a repeated cursor', () => {
  const first = networkDirectoryPageFromRpc(page([endpoint('endpoint-a'), endpoint('endpoint-b')], 'endpoint-b'),
    'network-a', 64);
  assert.ok(first);
  let view = appendNetworkDirectoryPage(emptyNetworkDirectoryView(), first);
  assert.deepEqual(view.endpoints.map(item => item.endpoint_id), ['endpoint-a', 'endpoint-b']);
  assert.equal(view.nextCursor, 'endpoint-b');

  const second = networkDirectoryPageFromRpc(page([
    endpoint('endpoint-b', 'duplicate copy'), endpoint('endpoint-c'),
  ], 'endpoint-b'), 'network-a', 64);
  assert.ok(second);
  view = appendNetworkDirectoryPage(view, second, 'endpoint-b');
  assert.deepEqual(view.endpoints.map(item => item.endpoint_id), ['endpoint-a', 'endpoint-b', 'endpoint-c']);
  assert.equal(view.endpoints[1].alias, 'endpoint-b');
  assert.equal(view.cursorLoop, true);
  assert.equal(view.nextCursor, undefined);
});

test('untrusted directory pages with unknown fields, wrong Network, or excess cards are rejected', () => {
  assert.equal(networkDirectoryPageFromRpc(Object.assign(page([endpoint('endpoint-a')]), {private_locator: 'hidden'}),
    'network-a', 64), null);
  assert.equal(networkDirectoryPageFromRpc(page([endpoint('endpoint-a'), endpoint('endpoint-b')]),
    'network-a', 1), null);
  assert.equal(networkDirectoryPageFromRpc(page([Object.assign(endpoint('endpoint-a'), {node_id: 'must-not-leak'})]),
    'network-a', 64), null);
  assert.equal(networkDirectoryPageFromRpc(page([endpoint('endpoint-a')]), 'network-b', 64), null);
});
