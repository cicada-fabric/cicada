import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REGROUP_ISSUE_OPERATION, REGROUP_REVOKE_OPERATION, REGROUP_READ_OPERATIONS,
  captureRegroupDelegationCallback, regroupDelegationAuthority,
  regroupDelegationCallbackIsCurrent, regroupDelegationExpiryAllowed,
  regroupProposalFromRpc, regroupProposalTopologyStatus, suggestedRegroupDelegationExpiry,
} from '../src/platform/regroupDelegation.ts';
import {NETWORK_CATALOG_SHA256, NETWORK_CONTRACT_REVISION} from '../src/platform/networkTopology.ts';

const now = Date.parse('2026-10-01T12:00:00.000Z');
const topology = (overrides = {}) => ({
  contract_version: 2,
  owner_principal_id: 'owner-human',
  captured_at: '2026-10-01T11:55:00Z',
  read_consistency: 'best_effort',
  networks_truncated: false,
  network_endpoints_truncated: false,
  networks: [{network_id: 'network-a', name: 'Operations', state: 'ACTIVE', version: 5, can_create_group: true}],
  groups: [
    {group_id: 'group-source', network_id: 'network-a', state: 'ACTIVE', version: 7},
    {group_id: 'group-target', network_id: 'network-a', state: 'ACTIVE', version: 12},
  ],
  memberships: [
    {membership_id: 'membership-source-monitor', principal_id: 'principal-agent', group_id: 'group-source',
      role: 'monitor', roles: ['monitor'], broadcast_permission_enabled: false, status: 'active', version: 3},
    {membership_id: 'membership-target-member', principal_id: 'principal-agent', group_id: 'group-target',
      role: 'member', roles: ['member'], broadcast_permission_enabled: false, status: 'active', version: 8},
  ],
  endpoints: [{endpoint_id: 'endpoint-monitor', name: 'Monitor', principal_id: 'principal-agent',
    group_ids: ['group-source', 'group-target'], network_ids: ['network-a'], presence: 'ONLINE'}],
  links: [],
  ...overrides,
});
const allOperations = () => [...REGROUP_READ_OPERATIONS, REGROUP_ISSUE_OPERATION, REGROUP_REVOKE_OPERATION];
const status = (overrides = {}) => ({
  profileId: 'profile-a', selectionGeneration: 9, activeNetworkId: 'network-a',
  nativeAvailable: true, pinned: true, enrolled: true, remoteEnabled: true,
  sessionCapabilitiesReady: true, authFenced: false, recoveryBlocked: false,
  enrollmentRecoveryRequired: false, uncertainNeedsReconciliation: false,
  regroupReconciliationRequired: false, pendingOperationId: undefined,
  hubId: 'hub-a', ownerId: 'owner-human', deviceId: 'phone-a', sessionEpoch: 3,
  allowedOperations: allOperations(),
  ...overrides,
});
const caps = (overrides = {}) => ({
  contract_revision: NETWORK_CONTRACT_REVISION,
  catalog_sha256: NETWORK_CATALOG_SHA256,
  client_control_pq_e2ee: true,
  authenticated_client_session: true,
  available_rpc_operations: allOperations(),
  external_rpc_operations: allOperations(),
  ...overrides,
});
const session = (overrides = {}) => ({
  owner_id: 'owner-human', role: 'manager',
  contract_revision: NETWORK_CONTRACT_REVISION,
  catalog_sha256: NETWORK_CATALOG_SHA256,
  available_rpc_operations: allOperations(),
  ...overrides,
});
const apiScope = {profileId: 'profile-a', selectionGeneration: 9};
const authority = (overrides = {}) => regroupDelegationAuthority({
  apiScope, status: status(), publicCapabilities: caps(), sessionCapabilities: session(),
  topology: topology(), ...overrides,
});
const proposal = (overrides = {}) => ({
  proposal_id: 'rgrp-proposal-a',
  hub_id: 'hub-a',
  owner_id: 'owner-human',
  endpoint_id: 'endpoint-monitor',
  principal_id: 'principal-agent',
  binding_id: 'node-binding-monitor',
  binding_epoch: 4,
  input: {
    operation_id: 'monitor-op-1', network_id: 'network-a',
    source_group_id: 'group-source', target_group_id: 'group-target',
    action: 'SET_PARENT', expected_source_version: 7, expected_target_version: 12,
  },
  state: 'PROPOSED', created_at: '2026-10-01T10:00:00Z',
  expires_at: '2026-10-02T10:00:00Z',
  ...overrides,
});
const read = (value = proposal(), scope = authority().scope, reviewId = 'review-a', expectedId = 'rgrp-proposal-a') =>
  regroupProposalFromRpc(value, reviewId, scope, expectedId);

test('read authority requires exact pinned v1.6 Owner scope and public plus encrypted operation grants', () => {
  const current = authority();
  assert.equal(current.ready, true);
  assert.equal(current.canRead, true);
  assert.equal(current.canIssue, true);
  assert.equal(current.canRevoke, true);
  assert.equal(current.scope.networkId, 'network-a');

  for (const input of [
    {apiScope: {profileId: 'profile-other', selectionGeneration: 9}},
    {apiScope: {profileId: 'profile-a', selectionGeneration: 10}},
    {status: status({pinned: false})},
    {status: status({enrolled: false})},
    {status: status({authFenced: true})},
    {status: status({pendingOperationId: 'pending-original'})},
    {status: status({activeNetworkId: undefined})},
    {publicCapabilities: caps({catalog_sha256: 'wrong'})},
    {sessionCapabilities: session({owner_id: 'owner-other'})},
    {sessionCapabilities: session({role: 'network-admin'})},
    {topology: topology({owner_principal_id: 'owner-other'})},
    {topology: topology({networks: [{network_id: 'network-a', name: 'Ops', state: 'PAUSED', version: 5}]})},
  ]) assert.equal(authority(input).ready, false);
});

test('uncertain reads may inspect a proposal, while issue and revoke stay fenced', () => {
  const unresolved = authority({status: status({uncertainNeedsReconciliation: true})});
  assert.equal(unresolved.ready, true);
  assert.equal(unresolved.canRead, true);
  assert.equal(unresolved.canIssue, false);
  assert.equal(unresolved.canRevoke, false);

  const regroupFence = authority({status: status({regroupReconciliationRequired: true})});
  assert.equal(regroupFence.canRead, true);
  assert.equal(regroupFence.canIssue, false);
  assert.equal(regroupFence.canRevoke, false);
  assert.match(regroupFence.reason, /不会解除写入锁/);

  const originalStillPending = authority({status: status({pendingOperationId: 'regroup-op-original',
    regroupReconciliationRequired: true})});
  assert.equal(originalStillPending.ready, false);

  for (const operation of allOperations()) {
    assert.equal(authority({status: status({allowedOperations: allOperations().filter(item => item !== operation)})}).ready,
      operation === REGROUP_ISSUE_OPERATION || operation === REGROUP_REVOKE_OPERATION);
  }
  assert.equal(authority({sessionCapabilities: session({available_rpc_operations: ['topology.snapshot']})}).ready, false);
  assert.equal(authority({publicCapabilities: caps({external_rpc_operations: ['topology.snapshot']})}).ready, true);
  assert.equal(authority({publicCapabilities: caps({available_rpc_operations: ['topology.snapshot']})}).ready, false);
});

test('proposal result is bounded and bound to the current Hub, Human Owner, Network and Monitor identity', () => {
  const current = authority();
  const parsed = read(proposal(), current.scope);
  assert.ok(parsed);
  assert.equal(parsed.proposal.endpoint_id, 'endpoint-monitor');
  assert.equal(parsed.proposal.principal_id, 'principal-agent');
  assert.equal(parsed.versionsCurrent, true);
  assert.equal(parsed.issueMembershipsCurrent, true);
  assert.deepEqual(parsed.sourceMembership, {membershipId: 'membership-source-monitor', version: 3});
  assert.deepEqual(parsed.targetMembership, {membershipId: 'membership-target-member', version: 8});
  assert.equal(read(proposal({hub_id: 'hub-other'}), current.scope), null);
  assert.equal(read(proposal({owner_id: 'owner-other'}), current.scope), null);
  assert.equal(read(proposal({principal_id: 'owner-human'}), current.scope), null);
  assert.equal(read(proposal(), current.scope, 'review-a', 'rgrp-proposal-other'), null);
  assert.equal(read(proposal({input: {...proposal().input, network_id: 'network-other'}}), current.scope), null);
  assert.equal(read(proposal({extra_native_locator: '/private/thread'}), current.scope), null);
  assert.equal(read(proposal({binding_epoch: 0}), current.scope), null);
  assert.equal(read(proposal({state: 'EXPIRED'}), current.scope), null);
  assert.equal(read(proposal(), current.scope, ' '), null);
});

test('proposal action and CAS versions are validated against current ACTIVE Group cards', () => {
  const current = authority();
  assert.equal(read(proposal(), current.scope).versionsCurrent, true);
  const stale = read(proposal({input: {...proposal().input, expected_target_version: 11}}), current.scope);
  assert.equal(stale.versionsCurrent, false);
  assert.equal(stale.targetGroupCurrent, true);
  assert.equal(read(proposal({input: {...proposal().input, action: 'MOVE'}}), current.scope), null);
  assert.equal(read(proposal({input: {...proposal().input, target_group_id: 'group-source'}}), current.scope), null);
  assert.equal(read(proposal({input: {...proposal().input, expected_source_version: 0}}), current.scope), null);
  assert.equal(read(proposal({input: {...proposal().input, new_group_name: 'unexpected'}}), current.scope), null);

  const child = proposal({input: {...proposal().input, action: 'CREATE_CHILD',
    source_group_id: 'group-source', target_group_id: 'group-source',
    expected_target_version: 7, new_group_name: 'New child'}});
  assert.equal(read(child, current.scope).proposal.input.action, 'CREATE_CHILD');
  assert.equal(read(proposal({input: {...child.input, new_group_name: ' '.repeat(2)}}), current.scope), null);
  const duplicateGroup = read(child, authority({topology: topology({groups: [
    ...topology().groups, topology().groups[0],
  ]})}).scope);
  assert.equal(duplicateGroup.sourceGroupCurrent, false);
  assert.equal(read(proposal(), authority({topology: topology({groups: [
    {...topology().groups[0], state: 'PAUSED'}, topology().groups[1],
  ]})}).scope).sourceGroupCurrent, false);
});

test('issue eligibility requires one current Endpoint plus explicit active Memberships in both Groups', () => {
  const current = authority();
  const reviewed = read(proposal(), current.scope);
  assert.ok(reviewed);
  assert.equal(reviewed.issueMembershipsCurrent, true);
  const base = current.scope.topology;
  const check = (changes = {}) => regroupProposalTopologyStatus(reviewed.proposal, {...base, ...changes});
  assert.equal(check({endpoints: []}).issueMembershipsCurrent, false);
  assert.equal(check({endpoints: [{...base.endpoints[0], endpoint_id: 'other-endpoint'}]}).issueMembershipsCurrent, false);
  assert.equal(check({endpoints: [{...base.endpoints[0], principal_id: 'other-principal'}]}).issueMembershipsCurrent, false);
  assert.equal(check({endpoints: [{...base.endpoints[0], group_ids: ['group-source']}]}).issueMembershipsCurrent, false);
  assert.equal(check({memberships: base.memberships.filter(item => item.group_id !== 'group-target')})
    .issueMembershipsCurrent, false);
  assert.equal(check({memberships: base.memberships.map(item => item.group_id === 'group-target' ?
    {...item, status: 'revoked'} : item)}).issueMembershipsCurrent, false);
  assert.equal(check({memberships: base.memberships.map(item => item.group_id === 'group-target' ?
    {...item, version: 0} : item)}).issueMembershipsCurrent, false);
  assert.equal(check({memberships: [...base.memberships, {...base.memberships[1], membership_id: 'duplicate-target'}]})
    .issueMembershipsCurrent, false);
  assert.equal(check({memberships: base.memberships.map(item => item.group_id === 'group-source' ?
    {...item, role: 'member', roles: ['member']} : item)}).issueMembershipsCurrent, false);

  const child = read(proposal({input: {...proposal().input, action: 'CREATE_CHILD',
    source_group_id: 'group-source', target_group_id: 'group-source', expected_target_version: 7,
    new_group_name: 'Child'}}), current.scope);
  assert.ok(child);
  const deduped = regroupProposalTopologyStatus(child.proposal, {...base,
    endpoints: [{...base.endpoints[0], group_ids: ['group-source']}],
    memberships: [base.memberships[0]],
  });
  assert.equal(deduped.issueMembershipsCurrent, true);
  assert.deepEqual(deduped.sourceMembership, deduped.targetMembership);
});

test('proposal and optional delegation DTOs reject extra fields, mismatched scope and invalid lifetime', () => {
  const current = authority();
  const base = proposal();
  assert.equal(read({...base, expires_at: '2026-10-03T10:00:00Z'}, current.scope), null);
  assert.equal(read({...base, expires_at: 'not-a-time'}, current.scope), null);
  assert.equal(read({...base, input: {...base.input, extra: true}}, current.scope), null);
  const active = {
    delegation_id: 'rdlg-a', proposal_id: base.proposal_id, hub_id: base.hub_id,
    owner_id: base.owner_id, network_id: base.input.network_id,
    source_group_id: base.input.source_group_id, target_group_id: base.input.target_group_id,
    action: base.input.action, expected_source_version: 7, expected_target_version: 12,
    expires_at: '2026-10-01T18:00:00Z', max_uses: 1, use_count: 0,
    state: 'ACTIVE', version: 1, created_at: '2026-10-01T11:00:00Z',
  };
  assert.equal(read({...base, delegation: active}, current.scope).proposal.delegation.state, 'ACTIVE');
  assert.equal(read({...base, delegation: {...active, owner_id: 'owner-other'}}, current.scope), null);
  assert.equal(read({...base, delegation: {...active, expected_target_version: 99}}, current.scope), null);
  assert.equal(read({...base, delegation: {...active, expires_at: '2026-10-03T10:00:00Z'}}, current.scope), null);
  assert.equal(read({...base, delegation: {...active, extra_secret: 'x'}}, current.scope), null);
});

test('expiry is future, no later than proposal expiry, and at most 24 hours from issue', () => {
  const proposalExpiry = '2026-10-02T10:00:00Z';
  assert.equal(regroupDelegationExpiryAllowed('2026-10-01T13:00:00Z', proposalExpiry, now), true);
  assert.equal(regroupDelegationExpiryAllowed('2026-10-01T11:59:59Z', proposalExpiry, now), false);
  assert.equal(regroupDelegationExpiryAllowed('2026-10-02T10:00:01Z', proposalExpiry, now), false);
  assert.equal(regroupDelegationExpiryAllowed('2026-10-03T10:00:00Z', '2026-10-03T10:00:00Z', now), false);
  assert.equal(regroupDelegationExpiryAllowed('bad-time', proposalExpiry, now), false);
  assert.equal(suggestedRegroupDelegationExpiry(proposalExpiry, now), '2026-10-01T13:00:00.000Z');
});

test('late callbacks are ignored after profile selection changes or app background', () => {
  const scope = authority().scope;
  const callback = captureRegroupDelegationCallback(scope, 4);
  assert.equal(regroupDelegationCallbackIsCurrent(callback, scope, 4, true), true);
  assert.equal(regroupDelegationCallbackIsCurrent(callback, scope, 5, true), false);
  assert.equal(regroupDelegationCallbackIsCurrent(callback, {...scope, scopeKey: 'other'}, 4, true), false);
  assert.equal(regroupDelegationCallbackIsCurrent(callback, scope, 4, false), false);
  assert.equal(regroupDelegationCallbackIsCurrent(callback, null, 4, true), false);
});
