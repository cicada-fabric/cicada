import test from 'node:test';
import assert from 'node:assert/strict';
import {
  GROUP_DIRECTORY_PERMISSION_ACTION, GROUP_DIRECTORY_PERMISSION_READY,
  GROUP_DIRECTORY_PERMISSION_RELEASE, GroupDirectoryPermissionLifecycle,
  candidateGroupDirectoryPermissionAuthority, createGroupDirectoryPermissionReview,
  directoryPermissionActionRequested, groupDirectoryPermissionAuthority,
  groupDirectoryPermissionSnapshotFromRpc,
  parseGroupDirectoryPermissionSnapshot, validateGroupDirectoryPermissionResult,
} from '../src/platform/groupDirectoryPermission.ts';

const catalogSha256 = 'ef5f525f14b77c8190a1fcbd3f86b8206e329708188d320854ab0651754a15ac';
const operationList = ['topology.snapshot', 'topology.apply'];
const descriptor = () => ({verified: true, synthetic_test_only: true,
  contract_revision: 'client-hub-v1.6.2', catalog_sha256: catalogSha256,
  source_revision: 'a'.repeat(40), hub_schema_version: 55, wire_version: 1,
  rpc_operations: operationList, topology_actions: [GROUP_DIRECTORY_PERMISSION_ACTION]});

const membership = (overrides = {}) => ({membership_id: 'membership-a', principal_id: 'principal-a',
  group_id: 'group-a', role: 'member', broadcast_permission_enabled: false,
  directory_permission_enabled: false, status: 'active', version: 7,
  roles: ['member'], display_name: 'Member A', ...overrides});
const endpoint = (overrides = {}) => ({endpoint_id: 'endpoint-a', name: 'Endpoint A',
  principal_id: 'principal-a', group_ids: ['group-a'], network_ids: ['network-a'], presence: 'UNKNOWN',
  ...overrides});
const topology = (overrides = {}) => ({contract_version: 2, owner_principal_id: 'owner-a',
  captured_at: '2026-10-02T10:00:00Z', read_consistency: 'best_effort',
  networks: [{network_id: 'network-a', name: 'Network A', state: 'ACTIVE', version: 3,
    can_create_group: true}], networks_truncated: false, network_endpoints_truncated: false,
  groups: [{group_id: 'group-a', network_id: 'network-a', name: 'Group A', state: 'ACTIVE',
    context_policy: 'default', version: 5}], memberships: [membership()],
  endpoints: [endpoint(), endpoint({endpoint_id: 'endpoint-b', name: 'Endpoint B'}),
    endpoint({endpoint_id: 'endpoint-other', principal_id: 'principal-b', name: 'Other principal'})],
  links: [], ...overrides});
const status = (overrides = {}) => ({profileId: 'profile-a', selectionGeneration: 2,
  activeNetworkId: 'network-a', nativeAvailable: true, pinned: true, enrolled: true,
  sessionCapabilitiesReady: true, remoteEnabled: true, authFenced: false, recoveryBlocked: false,
  enrollmentRecoveryRequired: false, hubId: 'hub-a', ownerId: 'owner-a', deviceId: 'device-a',
  sessionEpoch: 6, role: 'manager', allowedOperations: [...operationList], ...overrides});
const publicCapabilities = (overrides = {}) => ({contract_revision: 'client-hub-v1.6.2',
  catalog_sha256: catalogSha256, client_control_pq_e2ee: true, authenticated_client_session: true,
  topology_management: true, available_rpc_operations: [...operationList],
  external_rpc_operations: [...operationList], ...overrides});
const sessionCapabilities = (overrides = {}) => ({owner_id: 'owner-a', role: 'manager',
  contract_revision: 'client-hub-v1.6.2', catalog_sha256: catalogSha256,
  available_rpc_operations: [...operationList], ...overrides});
const authorityInput = (overrides = {}) => ({status: status(), publicCapabilities: publicCapabilities(),
  sessionCapabilities: sessionCapabilities(), topology: topology(),
  apiScope: {profileId: 'profile-a', selectionGeneration: 2}, bridgeReady: true, ...overrides});
const authority = (overrides = {}) => candidateGroupDirectoryPermissionAuthority(
  authorityInput(overrides), descriptor());
const target = (authorityValue = authority(), snapshot = topology(), groupId = 'group-a',
  membershipId = 'membership-a') => parseGroupDirectoryPermissionSnapshot(
  snapshot, authorityValue, groupId, membershipId);

test('v1.6.1 production readiness stays closed even with advertised candidate v1.6.2 capabilities', () => {
  assert.equal(GROUP_DIRECTORY_PERMISSION_RELEASE, null);
  assert.equal(GROUP_DIRECTORY_PERMISSION_READY, false);
  const input = authorityInput();
  const production = groupDirectoryPermissionAuthority(input);
  assert.equal(production.ready, false);
  assert.equal(production.canRead, false);
  assert.equal(production.canApply, false);
  assert.equal(createGroupDirectoryPermissionReview(production, target(authority()), true), null);
});

test('snapshot reader unwraps the actual native envelope and rejects failure, wrong Owner and unknown fields', () => {
  const snapshot = topology();
  const response = {requestId: 'request-a', operationId: 'operation-a', ok: true, result: snapshot};
  assert.equal(groupDirectoryPermissionSnapshotFromRpc(response, 'owner-a'), snapshot);
  assert.equal(groupDirectoryPermissionSnapshotFromRpc(snapshot, 'owner-a'), null);
  for (const invalid of [
    {...response, ok: false}, {...response, requestId: ''},
    {...response, owner_id: 'owner-a'}, {...response, result: {snapshot}},
    {...response, result: topology({owner_principal_id: 'owner-b'})},
  ]) assert.equal(groupDirectoryPermissionSnapshotFromRpc(invalid, 'owner-a'), null);
  assert.equal(groupDirectoryPermissionSnapshotFromRpc(response, 'owner-b'), null);
  const cappedMemberships = [membership(), ...Array.from({length: 999}, (_, index) =>
    membership({membership_id: `other-${index}`, principal_id: `principal-other-${index}`}))];
  assert.equal(target(authority(), topology({memberships: cappedMemberships})), null);
  const cappedEndpoints = Array.from({length: 1000}, (_, index) => endpoint({endpoint_id: `endpoint-${index}`}));
  assert.equal(target(authority(), topology({endpoints: cappedEndpoints})), null);
});

test('only topology.apply carrying the action kind or own payload field is intercepted', () => {
  assert.equal(directoryPermissionActionRequested('topology.apply', {
    kind: GROUP_DIRECTORY_PERMISSION_ACTION,
  }), true);
  assert.equal(directoryPermissionActionRequested('topology.apply', {set_directory_permission: null}), true);
  assert.equal(directoryPermissionActionRequested('topology.apply', {set_directory_permission: {wrong: true}}), true);
  assert.equal(directoryPermissionActionRequested('topology.apply', {kind: 'membership.other'}), false);
  assert.equal(directoryPermissionActionRequested('topology.snapshot', {
    kind: GROUP_DIRECTORY_PERMISSION_ACTION,
  }), false);
  const inherited = Object.create({set_directory_permission: {}});
  assert.equal(directoryPermissionActionRequested('topology.apply', inherited), false);
});

test('candidate authority requires same Owner, active selected Network, and public plus encrypted grants', () => {
  assert.equal(authority().ready, true);
  assert.equal(authority({sessionCapabilities: sessionCapabilities({role: 'external'}),
    status: status({role: 'external'})}).ready, true);
  for (const patch of [
    {status: status({profileId: 'profile-b'})},
    {apiScope: {profileId: 'profile-b', selectionGeneration: 2}},
    {status: status({selectionGeneration: 3})},
    {status: status({hubId: ''})},
    {status: status({ownerId: 'owner-b'})},
    {status: status({deviceId: ''})},
    {status: status({sessionEpoch: 0})},
    {status: status({role: 'external'})},
    {sessionCapabilities: sessionCapabilities({owner_id: 'owner-b'})},
    {sessionCapabilities: sessionCapabilities({role: 'agent'})},
    {sessionCapabilities: sessionCapabilities({available_rpc_operations: ['topology.snapshot']})},
    {publicCapabilities: publicCapabilities({available_rpc_operations: ['topology.snapshot']})},
    {publicCapabilities: publicCapabilities({topology_management: false})},
    {publicCapabilities: publicCapabilities({catalog_sha256: 'b'.repeat(64)})},
    {status: status({allowedOperations: ['topology.snapshot']})},
    {status: status({activeNetworkId: 'network-b'})},
    {bridgeReady: false},
    {topology: topology({owner_principal_id: 'owner-b'})},
    {topology: topology({networks: [{...topology().networks[0], state: 'PAUSED'}]})},
    {topology: topology({networks: [{...topology().networks[0], can_create_group: false}]})},
  ]) assert.equal(authority(patch).ready, false, JSON.stringify(patch));

  const externalWithoutRoleCatalog = authority({
    status: status({role: 'external'}),
    sessionCapabilities: sessionCapabilities({role: 'external'}),
    publicCapabilities: publicCapabilities({external_rpc_operations: ['topology.snapshot']}),
  });
  assert.equal(externalWithoutRoleCatalog.ready, false);
});

test('pending, uncertain, revoked, or recovering sessions cannot preview a write', () => {
  for (const patch of [
    {status: status({pinned: false})},
    {status: status({enrolled: false})},
    {status: status({remoteEnabled: false})},
    {status: status({authFenced: true})},
    {status: status({recoveryBlocked: true})},
    {status: status({enrollmentRecoveryRequired: true})},
    {status: status({pendingOperationId: 'pending-a'})},
    {status: status({uncertainNeedsReconciliation: true})},
    {status: status({networkGrantReconciliationRequired: true})},
    {status: status({regroupReconciliationRequired: true})},
  ]) assert.equal(authority(patch).ready, false, JSON.stringify(patch));

  const reconciled = authority({status: status({outcomeUncertainOperationId: 'old-request',
    uncertainNeedsReconciliation: false})});
  assert.equal(reconciled.ready, true,
    'a retained historical operation ID alone is not an active uncertainty fence');
  assert.notEqual(reconciled.scope.scopeKey, authority().scope.scopeKey,
    'the historical ID remains in callback provenance');
});

test('strict snapshot parser requires one active Group and exact unique active Membership with explicit boolean', () => {
  const ready = authority();
  const parsed = target(ready);
  assert.ok(parsed);
  assert.deepEqual(parsed.subjectEndpointIds, ['endpoint-a', 'endpoint-b']);
  assert.equal(parsed.principalId, 'principal-a');
  assert.equal(parsed.membershipVersion, 7);
  assert.equal(parsed.currentEnabled, false);

  const bad = [
    topology({owner_principal_id: 'owner-b'}),
    topology({networks_truncated: true}),
    topology({network_endpoints_truncated: true}),
    topology({groups: [...topology().groups, topology().groups[0]]}),
    topology({groups: [{...topology().groups[0], state: 'PAUSED'}]}),
    topology({groups: [{...topology().groups[0], network_id: 'network-b'}]}),
    topology({memberships: [membership({directory_permission_enabled: undefined})]}),
    topology({memberships: [membership({directory_permission_enabled: null})]}),
    topology({memberships: [membership({directory_permission_enabled: 'false'})]}),
    topology({memberships: [membership({status: 'revoked'})]}),
    topology({memberships: [membership({version: 0})]}),
    topology({memberships: [membership({version: Number.MAX_SAFE_INTEGER})]}),
    topology({memberships: [membership({unexpected_owner_override: 'owner-b'})]}),
    topology({memberships: [membership(), membership({membership_id: 'membership-b'})]}),
    topology({memberships: [membership(), membership({membership_id: 'membership-b'})],
      endpoints: topology().endpoints}),
    topology({endpoints: [endpoint(), endpoint()]}),
    topology({endpoints: [endpoint({principal_id: undefined})]}),
    topology({endpoints: [endpoint({group_ids: ['group-a'], network_ids: ['network-b']})]}),
  ];
  for (const snapshot of bad) assert.equal(target(ready, snapshot), null);
  assert.equal(target(ready, topology(), 'Group A'), null, 'names cannot select Groups');
  assert.equal(target(ready, topology(), 'group-a', 'missing-membership'), null);
});

test('preview builds only the exact four-field action and never toggles from a nonboolean or same-state request', () => {
  const ready = authority();
  const selected = target(ready);
  assert.ok(selected);
  const review = createGroupDirectoryPermissionReview(ready, selected, true);
  assert.ok(review);
  assert.deepEqual(review.action, {
    kind: GROUP_DIRECTORY_PERMISSION_ACTION,
    set_directory_permission: {
      group_id: 'group-a', membership_id: 'membership-a', enabled: true,
      expected_membership_version: 7,
    },
  });
  assert.equal(Object.hasOwn(review.action.set_directory_permission, 'owner_id'), false);
  assert.equal(Object.hasOwn(review.action.set_directory_permission, 'approved'), false);
  assert.equal(createGroupDirectoryPermissionReview(ready, selected, false), null);
  assert.equal(createGroupDirectoryPermissionReview(ready, selected, null), null);
  assert.equal(createGroupDirectoryPermissionReview(groupDirectoryPermissionAuthority(authorityInput()), selected, true), null);
});

test('fresh confirmation accepts current CAS, and exact result confirms enable without optimistic mutation', () => {
  const ready = authority();
  const selected = target(ready);
  assert.ok(selected);
  const review = createGroupDirectoryPermissionReview(ready, selected, true);
  assert.ok(review);
  const lifecycle = new GroupDirectoryPermissionLifecycle();
  const capture = lifecycle.capture(review);
  assert.ok(capture);
  assert.equal(lifecycle.isCurrent(capture, ready.scope.scopeKey, review.reviewId, true), true);

  const laterSnapshot = topology({captured_at: '2026-10-02T10:05:00Z'});
  const attempt = lifecycle.confirm(review, capture, ready, laterSnapshot, review.reviewId, true);
  assert.ok(attempt);
  assert.equal(attempt.expectedMembershipVersion, 7);
  assert.equal(attempt.action.set_directory_permission.enabled, true);
  assert.equal(selected.currentEnabled, false, 'preview object was not optimistically changed');

  const result = {ok: true, result: {contract_version: 2,
    action: GROUP_DIRECTORY_PERMISSION_ACTION, changed: true,
    membership: membership({directory_permission_enabled: true, version: 8})},
    requestId: 'request-123', operationId: 'operation-123'};
  assert.equal(validateGroupDirectoryPermissionResult(attempt, result), true);
  assert.equal(lifecycle.confirm(review, capture, ready, laterSnapshot, review.reviewId, true), null,
    'one review may create only one attempt');
});

test('a current true permission can be revoked with false and the same CAS discipline', () => {
  const currentSnapshot = topology({memberships: [membership({directory_permission_enabled: true, version: 11})]});
  const ready = authority({topology: currentSnapshot});
  const selected = target(ready, currentSnapshot);
  assert.ok(selected);
  const review = createGroupDirectoryPermissionReview(ready, selected, false);
  assert.ok(review);
  assert.equal(review.action.set_directory_permission.enabled, false);
  assert.equal(review.action.set_directory_permission.expected_membership_version, 11);
  const lifecycle = new GroupDirectoryPermissionLifecycle();
  const capture = lifecycle.capture(review);
  assert.ok(capture);
  const attempt = lifecycle.confirm(review, capture, ready, currentSnapshot, review.reviewId, true);
  assert.ok(attempt);
  assert.equal(validateGroupDirectoryPermissionResult(attempt, {ok: true, result: {
    contract_version: 2, action: GROUP_DIRECTORY_PERMISSION_ACTION, changed: true,
    membership: membership({directory_permission_enabled: false, version: 12}),
  }}), true);
});

test('fresh reread rejects stale version, changed current flag, scope, or endpoint set', () => {
  const ready = authority();
  const selected = target(ready);
  assert.ok(selected);
  const review = createGroupDirectoryPermissionReview(ready, selected, true);
  assert.ok(review);
  const staleSnapshots = [
    topology({memberships: [membership({version: 8})]}),
    topology({memberships: [membership({directory_permission_enabled: true})]}),
    topology({groups: [{...topology().groups[0], version: 6}]}),
    topology({endpoints: [endpoint(), endpoint({endpoint_id: 'endpoint-c'})]}),
  ];
  for (const fresh of staleSnapshots) {
    const lifecycle = new GroupDirectoryPermissionLifecycle();
    const capture = lifecycle.capture(review);
    assert.ok(capture);
    assert.equal(lifecycle.confirm(review, capture, ready, fresh, review.reviewId, true), null);
  }
});

test('abandoned, backgrounded, or old-scope callbacks cannot create an attempt', () => {
  const ready = authority();
  const selected = target(ready);
  assert.ok(selected);
  const review = createGroupDirectoryPermissionReview(ready, selected, true);
  assert.ok(review);
  const lifecycle = new GroupDirectoryPermissionLifecycle();
  const capture = lifecycle.capture(review);
  assert.ok(capture);
  lifecycle.invalidate();
  assert.equal(lifecycle.isCurrent(capture, ready.scope.scopeKey, review.reviewId, true), false);
  assert.equal(lifecycle.confirm(review, capture, ready, topology(), review.reviewId, true), null);

  const nextReview = createGroupDirectoryPermissionReview(ready, selected, true);
  assert.ok(nextReview);
  const nextCapture = lifecycle.capture(nextReview);
  assert.ok(nextCapture);
  assert.equal(lifecycle.isCurrent(nextCapture, ready.scope.scopeKey, nextReview.reviewId, false), false);
  assert.equal(lifecycle.confirm(nextReview, nextCapture, ready, topology(), nextReview.reviewId, false), null);
  assert.equal(lifecycle.confirm(nextReview, nextCapture, ready, topology(), 'another-review', true), null);
});

test('result validation requires exact accepted action, identity, explicit flag, and one-step version result', () => {
  const ready = authority();
  const selected = target(ready);
  assert.ok(selected);
  const review = createGroupDirectoryPermissionReview(ready, selected, true);
  assert.ok(review);
  const lifecycle = new GroupDirectoryPermissionLifecycle();
  const capture = lifecycle.capture(review);
  assert.ok(capture);
  const attempt = lifecycle.confirm(review, capture, ready, topology(), review.reviewId, true);
  assert.ok(attempt);
  const good = {ok: true, result: {contract_version: 2,
    action: GROUP_DIRECTORY_PERMISSION_ACTION, changed: true,
    membership: membership({directory_permission_enabled: true, version: 8})}};
  assert.equal(validateGroupDirectoryPermissionResult(attempt, {
    ...good, requestId: 'request-123', operationId: 'operation-123',
  }), true);
  const invalid = [
    {ok: true, result: {...good.result, action: 'membership.set_broadcast_permission'}},
    {ok: true, result: {...good.result, changed: false}},
    {ok: true, result: {...good.result, membership: membership({membership_id: 'other',
      directory_permission_enabled: true, version: 8})}},
    {ok: true, result: {...good.result, membership: membership({principal_id: 'other',
      directory_permission_enabled: true, version: 8})}},
    {ok: true, result: {...good.result, membership: membership({group_id: 'other',
      directory_permission_enabled: true, version: 8})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: false, version: 8})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: true, version: 7})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: true,
      version: 8, role: 'monitor'})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: true,
      version: 8, broadcast_permission_enabled: true})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: true,
      version: 8, roles: ['member', 'monitor']})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: null, version: 8})}},
    {ok: true, result: {...good.result, membership: membership({directory_permission_enabled: true,
      version: 8, approval: true})}},
    {...good, forgedOwner: 'owner-b'},
    {ok: false, result: good.result},
    {ok: true, result: {...good.result, owner_id: 'owner-b'}},
  ];
  for (const response of invalid) assert.equal(validateGroupDirectoryPermissionResult(attempt, response), false);
});
