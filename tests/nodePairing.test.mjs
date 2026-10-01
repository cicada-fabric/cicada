import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NodePairingLifecycle, nodeControlKeyCandidateFromRpc, nodePairingOperationAllowed,
  nodePairingScopeKey, sameNodeControlKeyCandidate,
} from '../src/platform/nodePairing.ts';
import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from '../src/platform/clientHubContract.ts';

const now = Date.parse('2026-10-01T12:00:00.000Z');
const candidate = (overrides = {}) => ({
  request_id: 'request-1', version: 4, mode: 'INITIAL', hub_id: 'hub-a',
  node_id: 'agent-principal-a', node_name: 'Build Node', node_key_id: 'node-key-1',
  node_key_fingerprint: 'a'.repeat(64), hub_node_control_key_id: 'hub-node-control-2',
  hub_node_control_key_version: 2, hub_node_control_fingerprint: 'b'.repeat(64),
  node_key_epoch: 6, candidate_digest: 'c'.repeat(64),
  expires_at: '2026-10-01T12:05:00Z', state: 'PENDING',
  ...overrides,
});
const operations = ['nodes.preview', 'nodes.confirm'];
const status = (overrides = {}) => ({
  profileId: 'profile-a', selectionGeneration: 8, activeNetworkId: 'network-a',
  nativeAvailable: true, pinned: true, enrolled: true, sessionCapabilitiesReady: true,
  remoteEnabled: true, authFenced: false, recoveryBlocked: false,
  enrollmentRecoveryRequired: false, uncertainNeedsReconciliation: false,
  pendingOperationId: undefined, hubId: 'hub-a', ownerId: 'owner-human-a',
  deviceId: 'phone-a', sessionEpoch: 3, allowedOperations: operations,
  ...overrides,
});
const publicCaps = (overrides = {}) => ({
  contract_revision: CLIENT_HUB_REVISION, catalog_sha256: CLIENT_HUB_CATALOG_SHA256,
  client_control_pq_e2ee: true, authenticated_client_session: true, device_binding: true,
  available_rpc_operations: operations, external_rpc_operations: operations,
  ...overrides,
});
const sessionCaps = (overrides = {}) => ({
  owner_id: 'owner-human-a', role: 'manager', contract_revision: CLIENT_HUB_REVISION,
  catalog_sha256: CLIENT_HUB_CATALOG_SHA256, available_rpc_operations: operations,
  ...overrides,
});
const apiScope = {profileId: 'profile-a', selectionGeneration: 8};

test('candidate parser accepts exact INITIAL and UPGRADE metadata without equating Owner and Node principal', () => {
  const initial = nodeControlKeyCandidateFromRpc(candidate(), 'hub-a', now);
  assert.ok(initial);
  assert.equal(initial.node_id, 'agent-principal-a');
  assert.notEqual(initial.node_id, 'owner-human-a');
  assert.equal(initial.node_key_fingerprint, 'a'.repeat(64));
  assert.equal(initial.hub_node_control_fingerprint, 'b'.repeat(64));
  assert.ok(nodeControlKeyCandidateFromRpc(candidate({mode: 'UPGRADE', binding_id: 'binding-1',
    binding_version: 9}), 'hub-a', now));
});

test('candidate parser rejects unknown, malformed, stale, or incomplete binding metadata', () => {
  const invalid = [
    candidate({private_key: 'must-not-be-present'}),
    candidate({hub_id: 'hub-other'}),
    candidate({state: 'ACTIVE'}),
    candidate({mode: 'ROTATE'}),
    candidate({version: Number.MAX_SAFE_INTEGER + 1}),
    candidate({node_key_fingerprint: `sha256:${'a'.repeat(64)}`}),
    candidate({candidate_digest: 'A'.repeat(64)}),
    candidate({expires_at: '2026-10-01T11:59:59Z'}),
    candidate({expires_at: 'not-a-date'}),
    candidate({expires_at: '2026-02-31T12:05:00Z'}),
    candidate({expires_at: '2026-10-01T12:05:00+24:00'}),
    candidate({binding_id: 'binding-without-version'}),
    candidate({binding_version: 2}),
  ];
  for (const value of invalid) assert.equal(nodeControlKeyCandidateFromRpc(value, 'hub-a', now), null);
  assert.equal(nodeControlKeyCandidateFromRpc(candidate(), ' ', now), null);
});

test('confirmation review requires exact candidate equality across digest, version, and identity fields', () => {
  const reviewed = nodeControlKeyCandidateFromRpc(candidate(), 'hub-a', now);
  assert.ok(reviewed);
  assert.equal(sameNodeControlKeyCandidate(reviewed,
    nodeControlKeyCandidateFromRpc(candidate(), 'hub-a', now)), true);
  for (const change of [
    {candidate_digest: 'd'.repeat(64)}, {version: 5}, {node_key_id: 'node-key-2'},
    {hub_node_control_key_version: 3}, {expires_at: '2026-10-01T12:06:00Z'},
  ]) {
    const fresh = nodeControlKeyCandidateFromRpc(candidate(change), 'hub-a', now);
    assert.ok(fresh);
    assert.equal(sameNodeControlKeyCandidate(reviewed, fresh), false);
  }
});

test('operation permission requires current pinned Owner session and both public and encrypted grants', () => {
  const allowed = (overrides = {}) => nodePairingOperationAllowed(
    status(overrides.status), publicCaps(overrides.public), sessionCaps(overrides.session),
    overrides.scope || apiScope, overrides.operation || 'nodes.preview');
  assert.equal(allowed(), true);
  assert.equal(allowed({operation: 'nodes.confirm'}), true);
  for (const patch of [
    {status: {pinned: false}}, {status: {enrolled: false}}, {status: {authFenced: true}},
    {status: {pendingOperationId: 'original-rpc'}}, {status: {recoveryBlocked: true}},
    {public: {device_binding: false}},
    {public: {available_rpc_operations: ['nodes.preview']}, operation: 'nodes.confirm'},
    {session: {available_rpc_operations: ['nodes.preview']}, operation: 'nodes.confirm'},
    {session: {owner_id: 'another-owner'}}, {session: {role: 'agent'}},
    {scope: {profileId: 'profile-b', selectionGeneration: 8}},
  ]) assert.equal(allowed(patch), false);
  assert.equal(allowed({status: {uncertainNeedsReconciliation: true}, operation: 'nodes.preview'}), true);
  assert.equal(allowed({status: {uncertainNeedsReconciliation: true}, operation: 'nodes.confirm'}), false);
  assert.equal(allowed({public: {external_rpc_operations: ['nodes.preview']},
    session: {role: 'external'}}), true);
  assert.equal(allowed({public: {external_rpc_operations: []}, session: {role: 'external'}}), false);
});

test('review scope changes and lifecycle invalidation make old callbacks stale', () => {
  const original = nodePairingScopeKey(status(), publicCaps(), sessionCaps(), apiScope);
  for (const change of [
    {status: status({profileId: 'profile-b'})},
    {status: status({selectionGeneration: 9})},
    {status: status({activeNetworkId: 'network-b'})},
    {status: status({deviceId: 'phone-b'})},
    {status: status({sessionEpoch: 4})},
    {status: status({pendingOperationId: 'pending-rpc'})},
    {public: publicCaps({device_binding: false})},
    {session: sessionCaps({role: 'external'})},
  ]) assert.notEqual(nodePairingScopeKey(change.status || status(),
    change.public || publicCaps(), change.session || sessionCaps(), apiScope), original);

  const lifecycle = new NodePairingLifecycle();
  const token = lifecycle.capture(original);
  assert.equal(lifecycle.isCurrent(token, original), true);
  assert.equal(lifecycle.isCurrent(token, nodePairingScopeKey(status({activeNetworkId: 'network-b'}),
    publicCaps(), sessionCaps(), apiScope)), false);
  lifecycle.invalidate();
  assert.equal(lifecycle.isCurrent(token, original), false);
});
