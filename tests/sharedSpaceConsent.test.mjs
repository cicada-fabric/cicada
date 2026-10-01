import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFERRED_CLIENT_CONSENT_OPERATIONS, DEFERRED_V16_RPC_OPERATIONS,
  IMPLEMENTED_CLIENT_RPC_OPERATIONS,
  UNVERIFIED_LINK_KEY_OPERATIONS, clientHubOperationAllowed, isImplementedClientRpcOperation,
} from '../src/platform/clientHubOperationPolicy.ts';
import {
  NETWORK_CATALOG_SHA256, NETWORK_CONTRACT_REVISION,
} from '../src/platform/networkTopology.ts';
import {
  SHARED_SPACE_CLOSED_OPERATIONS, captureSharedSpaceCallback,
  createSharedSpaceReviewDraft, deriveSharedSpaceScope, markSharedSpaceReviewIntent,
  sharedSpaceAuthority, sharedSpaceCallbackIsCurrent, sharedSpaceDraftIsCurrent,
} from '../src/platform/sharedSpaceConsent.ts';

const blockedOperations = [
  'space.foreign_member_admit', 'space.foreign_member_revoke', 'space.foreign_endpoint_join',
  'space.key_manifest_v2', 'space.key_consent_v2', 'space.key_admission_v2', 'space.key_status_v2',
  'topology.delegation_issue', 'topology.delegation_revoke', 'topology.regroup_proposal',
  'space.foreign_endpoint_preview', 'network.collaboration_key_manifest',
  'network.collaboration_key_grant', 'network.collaboration_key_status',
  'link.review_policy_preview', 'link.review_policy_grant', 'link.review_policy_status',
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
];

const topology = (overrides = {}) => ({
  contract_version: 2,
  owner_principal_id: 'owner-a',
  captured_at: '2026-09-30T10:00:00Z',
  read_consistency: 'best_effort',
  networks_truncated: false,
  network_endpoints_truncated: false,
  networks: [{network_id: 'network-a', name: 'Production', state: 'ACTIVE', version: 4, can_create_group: true}],
  groups: [{group_id: 'group-a', network_id: 'network-a', name: 'Ops', state: 'ACTIVE', version: 9}],
  memberships: [],
  endpoints: [
    {endpoint_id: 'endpoint-foreign', owner_id: 'owner-b', name: 'External Node',
      network_ids: ['network-a'], group_ids: [], binding_id: 'binding-b', binding_epoch: 3},
    {endpoint_id: 'endpoint-local', owner_id: 'owner-a', name: 'Local Node',
      network_ids: ['network-a'], group_ids: ['group-a']},
  ],
  links: [],
  ...overrides,
});

const status = (overrides = {}) => ({
  profileId: 'profile-a', selectionGeneration: 12, activeNetworkId: 'network-a',
  nativeAvailable: true, pinned: true, enrolled: true, sessionCapabilitiesReady: true,
  remoteEnabled: true, authFenced: false, recoveryBlocked: false, enrollmentRecoveryRequired: false,
  hubId: 'hub-a', ownerId: 'owner-a', deviceId: 'device-a', sessionEpoch: 7,
  allowedOperations: ['topology.snapshot', ...blockedOperations],
  ...overrides,
});

const capabilities = (overrides = {}) => ({
  contract_revision: NETWORK_CONTRACT_REVISION,
  catalog_sha256: NETWORK_CATALOG_SHA256,
  client_control_pq_e2ee: true,
  authenticated_client_session: true,
  topology_management: true,
  available_rpc_operations: ['topology.snapshot', ...blockedOperations],
  external_rpc_operations: ['topology.snapshot', ...blockedOperations],
  ...overrides,
});

const sessionCapabilities = (overrides = {}) => ({
  owner_id: 'owner-a', role: 'manager', contract_revision: NETWORK_CONTRACT_REVISION,
  catalog_sha256: NETWORK_CATALOG_SHA256,
  available_rpc_operations: ['topology.snapshot', ...blockedOperations],
  ...overrides,
});

const readyInput = (overrides = {}) => ({
  status: status(), capabilities: capabilities(), sessionCapabilities: sessionCapabilities(),
  topology: topology(), ...overrides,
});

const readyAuthority = () => sharedSpaceAuthority(readyInput());
const endpointScope = (authority = readyAuthority()) => {
  const result = deriveSharedSpaceScope(authority, 'group-a', 'endpoint-foreign');
  assert.ok(result.scope, result.reason);
  return result.scope;
};

test('all 20 deferred v1.5 and v1.6 consent/proof operations stay closed when advertised', () => {
  assert.deepEqual([...SHARED_SPACE_CLOSED_OPERATIONS].sort(), [...blockedOperations].sort());
  assert.equal(SHARED_SPACE_CLOSED_OPERATIONS.length, 20);
  const state = status({allowedOperations: [
    ...IMPLEMENTED_CLIENT_RPC_OPERATIONS, ...DEFERRED_CLIENT_CONSENT_OPERATIONS,
    ...DEFERRED_V16_RPC_OPERATIONS,
    ...UNVERIFIED_LINK_KEY_OPERATIONS,
  ]});
  for (const operation of blockedOperations) {
    assert.equal(isImplementedClientRpcOperation(operation), false, operation);
    assert.equal(clientHubOperationAllowed(state, operation), false, operation);
  }
});

test('review scope uses the current encrypted Owner projection and exact ACTIVE Network/Group/Endpoint IDs', () => {
  const authority = readyAuthority();
  assert.equal(authority.ready, true);
  const scope = endpointScope(authority);
  assert.deepEqual({
    profileId: scope.profileId, selectionGeneration: scope.selectionGeneration,
    hubId: scope.hubId, ownerId: scope.ownerId, deviceId: scope.deviceId,
    sessionEpoch: scope.sessionEpoch, networkId: scope.networkId,
    networkVersion: scope.networkVersion, groupId: scope.groupId,
    groupVersion: scope.groupVersion, endpointId: scope.endpointId,
    endpointOwnerId: scope.endpointOwnerId, endpointBindingId: scope.endpointBindingId,
    endpointBindingEpoch: scope.endpointBindingEpoch,
  }, {
    profileId: 'profile-a', selectionGeneration: 12, hubId: 'hub-a', ownerId: 'owner-a',
    deviceId: 'device-a', sessionEpoch: 7, networkId: 'network-a', networkVersion: 4,
    groupId: 'group-a', groupVersion: 9, endpointId: 'endpoint-foreign',
    endpointOwnerId: 'owner-b', endpointBindingId: 'binding-b', endpointBindingEpoch: 3,
  });
  assert.equal(scope.endpointOwnerId, 'owner-b');
  assert.equal(scope.topologyCapturedAt, '2026-09-30T10:00:00Z');
  assert.equal(deriveSharedSpaceScope(authority, 'Group name', 'endpoint-foreign').scope, undefined);
  assert.equal(deriveSharedSpaceScope(authority, 'group-a', 'endpoint-local').scope, undefined);
});

test('missing, mismatched or stale authority never produces a scope', () => {
  for (const input of [
    readyInput({topology: null}),
    readyInput({topology: topology({owner_principal_id: 'owner-other'})}),
    readyInput({status: status({ownerId: 'owner-other'})}),
    readyInput({status: status({activeNetworkId: undefined})}),
    readyInput({topology: topology({networks: topology().networks.map(item => ({...item, state: 'PAUSED'}))})}),
    readyInput({status: status({pinned: false})}),
    readyInput({status: status({authFenced: true})}),
    readyInput({status: status({pendingOperationId: 'pending-1'})}),
    readyInput({status: status({uncertainNeedsReconciliation: true})}),
    readyInput({status: status({sessionEpoch: undefined})}),
    readyInput({sessionCapabilities: sessionCapabilities({owner_id: 'owner-other'})}),
    readyInput({capabilities: capabilities({catalog_sha256: 'wrong'})}),
    readyInput({sessionCapabilities: sessionCapabilities({available_rpc_operations: []})}),
  ]) {
    const authority = sharedSpaceAuthority(input);
    assert.equal(authority.ready, false);
    assert.equal(deriveSharedSpaceScope(authority, 'group-a', 'endpoint-foreign').scope, undefined);
  }

  const missingEndpointOwner = sharedSpaceAuthority(readyInput({
    topology: topology({endpoints: [{endpoint_id: 'endpoint-foreign', network_ids: ['network-a']}]}),
  }));
  const result = deriveSharedSpaceScope(missingEndpointOwner, 'group-a', 'endpoint-foreign');
  assert.equal(result.scope, undefined);
  assert.match(result.reason, /owner_id/);
});

test('profile, generation, Hub, Owner, Device, Network, Group, Endpoint or topology changes stale drafts and callbacks', () => {
  const scope = endpointScope();
  const draft = createSharedSpaceReviewDraft(scope);
  const callback = captureSharedSpaceCallback(scope);
  const changed = [
    {profileId: 'profile-b'}, {selectionGeneration: 13}, {hubId: 'hub-b'},
    {ownerId: 'owner-c'}, {deviceId: 'device-b'}, {sessionEpoch: 8},
    {networkId: 'network-b'}, {networkVersion: 5}, {groupId: 'group-b'},
    {groupVersion: 10}, {endpointId: 'endpoint-b'}, {endpointOwnerId: 'owner-c'},
    {endpointBindingId: 'binding-c'}, {endpointBindingEpoch: 4},
    {topologyCapturedAt: '2026-09-30T10:01:00Z'},
  ];
  for (const change of changed) {
    const nextScope = {...scope, ...change};
    assert.equal(sharedSpaceDraftIsCurrent(draft, nextScope), false, JSON.stringify(change));
    assert.equal(sharedSpaceCallbackIsCurrent(callback, nextScope), false, JSON.stringify(change));
    assert.equal(markSharedSpaceReviewIntent(draft, nextScope), null, JSON.stringify(change));
  }
});

test('stale proof-verification callbacks cannot change the current draft and no proof is retained', () => {
  const scope = endpointScope();
  const draft = createSharedSpaceReviewDraft(scope);
  const capturedBeforeVerifier = captureSharedSpaceCallback(scope);
  const nextScope = {...scope, endpointBindingEpoch: 4};
  // The future native proof verifier may finish late; only its scope fence is retained here.
  assert.equal(sharedSpaceCallbackIsCurrent(capturedBeforeVerifier, nextScope), false);
  assert.equal(sharedSpaceDraftIsCurrent(draft, nextScope), false);
  assert.deepEqual(Object.keys(draft).sort(), ['intent', 'reviewed', 'scope', 'scopeKey']);
  assert.equal('proof' in draft, false);
  assert.equal('signedProof' in draft, false);
});

test('explicit phone intent marks review only and never becomes authority or executable approval', () => {
  const scope = endpointScope();
  const draft = createSharedSpaceReviewDraft(scope);
  assert.equal(draft.intent, 'review-only');
  assert.equal(draft.reviewed, false);
  assert.equal(sharedSpaceDraftIsCurrent(draft, scope), true);
  const reviewed = markSharedSpaceReviewIntent(draft, scope);
  assert.ok(reviewed);
  assert.equal(reviewed.reviewed, true);
  assert.equal(reviewed.intent, 'review-only');
  assert.equal(sharedSpaceDraftIsCurrent(reviewed, scope), true);
  for (const field of ['approved', 'authorized', 'signature', 'signedProof', 'operation', 'request']) {
    assert.equal(field in reviewed, false, field);
  }
});
