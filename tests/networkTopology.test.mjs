import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NETWORK_CATALOG_SHA256, NETWORK_CONTRACT_REVISION, NETWORK_KEY_REQUIRED_OPERATIONS,
  createGroupRequest, endpointsInNetwork, explicitActiveNetwork, groupsInNetwork,
  networkKeyConsentAllows,
} from '../src/platform/networkTopology.ts';

const snapshot = () => ({
  contract_version: 2, owner_principal_id: 'owner-a', captured_at: '2026-09-30T00:00:00Z',
  read_consistency: 'best_effort', networks_truncated: false, network_endpoints_truncated: false,
  networks: [
    {network_id: 'network-a', name: 'Shared name', state: 'ACTIVE', version: 1, can_create_group: true},
    {network_id: 'network-b', name: 'Shared name', state: 'ACTIVE', version: 1, can_create_group: false},
    {network_id: 'network-paused', name: 'Paused', state: 'PAUSED', version: 1, can_create_group: false},
  ],
  groups: [
    {group_id: 'group-a', network_id: 'network-a', name: 'Parent', state: 'ACTIVE'},
    {group_id: 'group-b', network_id: 'network-b', name: 'Parent', state: 'ACTIVE'},
    {group_id: 'legacy', name: 'Unmapped', state: 'ACTIVE'},
  ],
  memberships: [], links: [],
  endpoints: [
    {endpoint_id: 'only-network', network_ids: ['network-a'], group_ids: []},
    {endpoint_id: 'both-networks', network_ids: ['network-a', 'network-b'], group_ids: ['group-b']},
    {endpoint_id: 'only-group', network_ids: [], group_ids: ['group-a'], binding_id: 'group-binding'},
    {endpoint_id: 'legacy', group_ids: ['group-a']},
  ],
});

test('requires an exact explicit ACTIVE Network ID even when names are identical', () => {
  const data = snapshot();
  assert.equal(explicitActiveNetwork(data, undefined), null);
  assert.equal(explicitActiveNetwork(data, ''), null);
  assert.equal(explicitActiveNetwork(data, 'Shared name'), null);
  assert.equal(explicitActiveNetwork(data, 'network-paused'), null);
  assert.equal(explicitActiveNetwork(data, 'network-unknown'), null);
  assert.equal(explicitActiveNetwork(data, ' network-a '), null);
  assert.equal(explicitActiveNetwork(data, 'network-a').network_id, 'network-a');
  assert.equal(explicitActiveNetwork({...data, contract_version: 1}, 'network-a'), null);
  assert.equal(explicitActiveNetwork({...data, networks: [...data.networks, data.networks[0]]}, 'network-a'), null);
  assert.equal(explicitActiveNetwork({...data, networks: [
    {...data.networks[0], version: Number.MAX_SAFE_INTEGER + 1},
  ]}, 'network-a'), null);
});

test('bounded truncated projection permits a present explicit scope and never infers missing cards', () => {
  const data = {...snapshot(), networks_truncated: true, network_endpoints_truncated: true};
  assert.ok(explicitActiveNetwork(data, 'network-a'));
  assert.equal(explicitActiveNetwork(data, 'missing-on-next-page'), null);
  assert.throws(() => createGroupRequest(data, 'missing-on-next-page', 'New group'));
  assert.equal(data.networks_truncated, true);
  assert.equal(data.network_endpoints_truncated, true);
  const cards = Array.from({length: 101}, (_, index) => ({
    network_id: `network-${index}`, name: 'Synthetic', state: 'ACTIVE', version: 1, can_create_group: true,
  }));
  assert.equal(explicitActiveNetwork({...data, networks: cards}, 'network-0'), null);
  assert.equal(explicitActiveNetwork({...data, networks_truncated: 'false'}, 'network-a'), null);
});

test('Network-only Endpoints are visible and Group bindings never grant a Network scope', () => {
  assert.deepEqual(groupsInNetwork(snapshot(), 'network-a').map(group => group.group_id), ['group-a']);
  assert.deepEqual(endpointsInNetwork(snapshot(), 'network-a').map(endpoint => endpoint.endpoint_id),
    ['only-network', 'both-networks']);
  assert.deepEqual(endpointsInNetwork(snapshot(), 'network-b').map(endpoint => endpoint.endpoint_id), ['both-networks']);
  assert.deepEqual(endpointsInNetwork(snapshot(), undefined), []);
  assert.deepEqual(groupsInNetwork(snapshot(), 'network-paused'), []);
});

test('creation binds exact Network and parent without adding caller identity or invented CAS', () => {
  assert.deepEqual(createGroupRequest(snapshot(), 'network-a', '  New group  ', 'group-a'), {
    kind: 'group.create', create_group: {group: {network_id: 'network-a', name: 'New group'}, parent_group_id: 'group-a'},
  });
  assert.deepEqual(createGroupRequest(snapshot(), 'network-a', 'Root'), {
    kind: 'group.create', create_group: {group: {network_id: 'network-a', name: 'Root'}},
  });
  for (const id of [undefined, '', 'Shared name', 'network-paused', 'network-b']) {
    assert.throws(() => createGroupRequest(snapshot(), id, 'New group'));
  }
  for (const parent of ['group-b', 'legacy', 'missing']) {
    assert.throws(() => createGroupRequest(snapshot(), 'network-a', 'New group', parent));
  }
  assert.throws(() => createGroupRequest(snapshot(), 'network-a', ' \n '));
  const ambiguous = snapshot();
  ambiguous.groups.push({...ambiguous.groups[0]});
  assert.throws(() => createGroupRequest(ambiguous, 'network-a', 'New group', 'group-a'));
});

const publicCapabilities = () => ({
  contract_revision: NETWORK_CONTRACT_REVISION, catalog_sha256: NETWORK_CATALOG_SHA256,
  client_control_pq_e2ee: true, authenticated_client_session: true,
  available_rpc_operations: [...NETWORK_KEY_REQUIRED_OPERATIONS],
  external_rpc_operations: [...NETWORK_KEY_REQUIRED_OPERATIONS],
});
const session = () => ({
  owner_id: 'owner-a', role: 'manager', contract_revision: NETWORK_CONTRACT_REVISION,
  catalog_sha256: NETWORK_CATALOG_SHA256, available_rpc_operations: [...NETWORK_KEY_REQUIRED_OPERATIONS],
});
const status = () => ({
  ownerId: 'owner-a', activeNetworkId: 'network-a', nativeAvailable: true, pinned: true,
  enrolled: true, remoteEnabled: true, sessionCapabilitiesReady: true,
  allowedOperations: [...NETWORK_KEY_REQUIRED_OPERATIONS],
});
const allows = (caps = publicCapabilities(), grant = session(), state = status(), ready = true,
  topology = snapshot(), operation = 'network.key_grant') =>
  networkKeyConsentAllows(caps, grant, state, ready, topology, operation);

test('exact public catalog, current encrypted Owner grant and local verifier must all permit consent', () => {
  assert.equal(allows(), true);
  assert.equal(allows(publicCapabilities(), {...session(), role: 'external'}), true);
  assert.equal(allows({...publicCapabilities(), contract_revision: 'client-hub-v1.3'}), false);
  assert.equal(allows({...publicCapabilities(), catalog_sha256: 'wrong'}), false);
  assert.equal(allows(publicCapabilities(), {...session(), owner_id: 'owner-other'}), false);
  assert.equal(allows(publicCapabilities(), {...session(), role: 'network-admin'}), false);
  assert.equal(allows(publicCapabilities(), session(), status(), false), false);
  assert.equal(allows(publicCapabilities(), session(), status(), true, {...snapshot(), owner_principal_id: 'owner-other'}), false);
  for (const item of NETWORK_KEY_REQUIRED_OPERATIONS) {
    assert.equal(allows({...publicCapabilities(), available_rpc_operations:
      NETWORK_KEY_REQUIRED_OPERATIONS.filter(operation => operation !== item)}), false);
    assert.equal(allows({...publicCapabilities(), external_rpc_operations:
      NETWORK_KEY_REQUIRED_OPERATIONS.filter(operation => operation !== item)}, {...session(), role: 'external'}), false);
    assert.equal(allows(publicCapabilities(), {...session(), available_rpc_operations:
      NETWORK_KEY_REQUIRED_OPERATIONS.filter(operation => operation !== item)}), false);
    assert.equal(allows(publicCapabilities(), session(), {...status(), allowedOperations:
      NETWORK_KEY_REQUIRED_OPERATIONS.filter(operation => operation !== item)}), false);
  }
});

test('pending or fenced sessions disable operations; uncertainty permits only authoritative reads', () => {
  for (const overrides of [
    {pendingOperationId: 'original-request'}, {authFenced: true}, {recoveryBlocked: true},
    {enrollmentRecoveryRequired: true}, {nativeAvailable: false}, {pinned: false},
    {enrolled: false}, {remoteEnabled: false}, {sessionCapabilitiesReady: false},
    {activeNetworkId: undefined}, {activeNetworkId: 'network-paused'},
  ]) assert.equal(allows(publicCapabilities(), session(), {...status(), ...overrides}), false);
  const uncertain = {...status(), uncertainNeedsReconciliation: true};
  assert.equal(allows(publicCapabilities(), session(), uncertain), false);
  assert.equal(allows(publicCapabilities(), session(), uncertain, true, snapshot(), 'network.key_status'), true);
  const snapshotReconciled = {...status(), uncertainNeedsReconciliation: false,
    networkGrantReconciliationRequired: true};
  assert.equal(allows(publicCapabilities(), session(), snapshotReconciled), false);
  assert.equal(allows(publicCapabilities(), session(), snapshotReconciled, true, snapshot(), 'network.key_status'), true);
});
