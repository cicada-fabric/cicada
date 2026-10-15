import test from 'node:test';
import assert from 'node:assert/strict';
import {
  linkReviewPolicyStatusCanRead, linkReviewPolicyStatusFromRpc, linkReviewPolicyStatusSupported,
  linkReviewPolicyStatusScopeKey, LinkReviewPolicyStatusLifecycle,
} from '../src/platform/linkReviewPolicyStatus.ts';
import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from '../src/platform/clientHubContract.ts';

const operation = 'link.review_policy_status';
const nonePolicy = () => ({mode: 'NONE', reviewers: [], max_failovers: 0,
  reviewer_lease_seconds: 0, max_review_age_seconds: 0});
const statusDto = (overrides = {}) => ({link_id: 'link-a', link_version: 7,
  policy_version: 0, policy_digest: '', policy: nonePolicy(), current: true,
  accepted_sides: [], ...overrides});
const metadataPolicy = () => ({mode: 'METADATA', reviewers: [
  {endpoint_id: 'review-endpoint', group_id: 'review-group'},
], max_failovers: 0, reviewer_lease_seconds: 300, max_review_age_seconds: 3600});
const status = (overrides = {}) => ({profileId: 'profile-a', selectionGeneration: 3,
  nativeAvailable: true, pinned: true, enrolled: true, sessionCapabilitiesReady: true,
  remoteEnabled: true, authFenced: false, recoveryBlocked: false,
  enrollmentRecoveryRequired: false, uncertainNeedsReconciliation: false,
  hubId: 'hub-a', ownerId: 'owner-a', deviceId: 'phone-a', sessionEpoch: 5,
  allowedOperations: [operation], ...overrides});
const publicCapabilities = (overrides = {}) => ({
  contract_revision: CLIENT_HUB_REVISION, catalog_sha256: CLIENT_HUB_CATALOG_SHA256,
  client_control_pq_e2ee: true, authenticated_client_session: true,
  available_rpc_operations: [operation], external_rpc_operations: [operation],
  ...overrides,
});
const sessionCapabilities = (overrides = {}) => ({
  owner_id: 'owner-a', role: 'manager', contract_revision: CLIENT_HUB_REVISION,
  catalog_sha256: CLIENT_HUB_CATALOG_SHA256, available_rpc_operations: [operation],
  ...overrides,
});
const apiScope = {profileId: 'profile-a', selectionGeneration: 3};
const authorityInput = (overrides = {}) => ({
  status: status(), publicCapabilities: publicCapabilities(),
  sessionCapabilities: sessionCapabilities(), apiScope, linkId: 'link-a',
  linkVersion: 7, listGeneration: 4, bridgeReady: true, ...overrides,
});

test('strict parser recognizes the pinned unconfigured default as NONE version zero', () => {
  const parsed = linkReviewPolicyStatusFromRpc(statusDto(), 'link-a', 7);
  assert.ok(parsed);
  assert.equal(parsed.unconfigured, true);
  assert.equal(parsed.policy.mode, 'NONE');
  assert.equal(parsed.policy_version, 0);
  assert.equal(parsed.policy_digest, '');
  assert.deepEqual(parsed.accepted_sides, []);
  assert.equal(parsed.current, true);
});

test('versioned NONE policy is metadata, not an unconfigured state or an approval claim', () => {
  const parsed = linkReviewPolicyStatusFromRpc(statusDto({
    policy_version: 1, policy_digest: 'd'.repeat(64),
  }), 'link-a', 7);
  assert.ok(parsed);
  assert.equal(parsed.unconfigured, false);
  assert.equal(parsed.policy.mode, 'NONE');
  assert.deepEqual(parsed.accepted_sides, []);
  assert.equal(Object.hasOwn(parsed, 'approved'), false);
});

test('strict parser accepts bounded metadata policy without implying message permission', () => {
  const parsed = linkReviewPolicyStatusFromRpc(statusDto({
    policy_version: 2, policy_digest: 'a'.repeat(64), policy: metadataPolicy(),
    current: false, accepted_sides: ['SOURCE'], expires_at: '2026-10-01T12:00:00Z',
  }), 'link-a', 7);
  assert.ok(parsed);
  assert.equal(parsed.unconfigured, false);
  assert.equal(parsed.current, false);
  assert.deepEqual(parsed.accepted_sides, ['SOURCE']);
  assert.equal(parsed.policy.reviewers[0].endpoint_id, 'review-endpoint');
});

test('parser rejects malformed, unknown, stale, wrong-link, or noncanonical metadata', () => {
  const invalid = [
    statusDto({private_key: 'not allowed'}),
    statusDto({link_id: 'link-other'}),
    statusDto({link_version: 8}),
    statusDto({policy: {...nonePolicy(), prompt: 'not allowed'}}),
    statusDto({policy: {...nonePolicy(), reviewers: [{endpoint_id: 'e', group_id: 'g', key: 'x'}]}}),
    statusDto({policy: {...nonePolicy(), mode: ['NONE']}}),
    statusDto({policy: {...nonePolicy(), mode: {toString: () => 'NONE'}}}),
    statusDto({policy: {...nonePolicy(), mode: 'METADATA'}}),
    statusDto({policy: {...metadataPolicy(), reviewers: [
      ...metadataPolicy().reviewers, {endpoint_id: 'review-endpoint', group_id: 'other-group'},
    ]}, policy_version: 1, policy_digest: 'b'.repeat(64)}),
    statusDto({policy_version: 1, policy_digest: 'SHA256:' + 'a'.repeat(64)}),
    statusDto({policy_version: 1, policy_digest: 'a'.repeat(64), expires_at: '2026-02-31T12:00:00Z'}),
    statusDto({accepted_sides: ['SOURCE', 'SOURCE']}),
    statusDto({accepted_sides: ['OWNER']}),
    statusDto({policy_version: 1, policy_digest: ''}),
    statusDto({policy_version: 0, policy_digest: '', current: false}),
    statusDto({policy_version: 0, policy_digest: '', expires_at: '2026-10-01T12:00:00Z'}),
  ];
  for (const value of invalid) assert.equal(linkReviewPolicyStatusFromRpc(value, 'link-a', 7), null);
  assert.equal(linkReviewPolicyStatusFromRpc(statusDto(), 'link-a', 8), null);
  assert.equal(linkReviewPolicyStatusFromRpc(statusDto(), ' ', 7), null);
});

test('read permission requires one current pinned Owner session and both exact capability grants', () => {
  const allowed = (patch = {}) => linkReviewPolicyStatusCanRead(
    patch.status || status(), patch.public || publicCapabilities(),
    patch.session || sessionCapabilities(), patch.scope || apiScope,
    patch.bridgeReady ?? true);
  assert.equal(allowed(), true);
  for (const patch of [
    {status: status({profileId: 'profile-other'})},
    {scope: {profileId: 'profile-other', selectionGeneration: 3}},
    {status: status({selectionGeneration: 4})},
    {status: status({ownerId: 'owner-other'})},
    {status: status({hubId: ''})},
    {status: status({deviceId: ''})},
    {status: status({sessionEpoch: 0})},
    {status: status({authFenced: true})},
    {status: status({recoveryBlocked: true})},
    {status: status({pendingOperationId: 'original-request'})},
    {status: status({remoteEnabled: false})},
    {bridgeReady: false},
    {public: publicCapabilities({catalog_sha256: 'wrong'})},
    {public: publicCapabilities({authenticated_client_session: false})},
    {public: publicCapabilities({available_rpc_operations: []})},
    {session: sessionCapabilities({owner_id: 'owner-other'})},
    {session: sessionCapabilities({available_rpc_operations: []})},
    {session: sessionCapabilities({role: 'agent'})},
    {status: status({allowedOperations: []})},
  ]) assert.equal(allowed(patch), false);
  assert.equal(allowed({session: sessionCapabilities({role: 'external'}),
    public: publicCapabilities({external_rpc_operations: [operation]})}), true);
  assert.equal(allowed({session: sessionCapabilities({role: 'external'}),
    public: publicCapabilities({external_rpc_operations: []})}), false);
  assert.equal(allowed({status: status({hubId: 'hub-b'})}), true);
  assert.equal(allowed({status: status({deviceId: 'phone-b'})}), true);
});

test('status section is hidden unless bridge, contract, Owner scope, and both capability catalogs support it', () => {
  const supported = (patch = {}) => linkReviewPolicyStatusSupported(
    patch.status || status(), patch.public || publicCapabilities(),
    patch.session || sessionCapabilities(), patch.scope || apiScope,
    patch.bridgeReady ?? true);
  assert.equal(supported(), true);
  for (const patch of [
    {bridgeReady: false},
    {status: status({profileId: 'profile-other'})},
    {status: status({selectionGeneration: 4})},
    {status: status({hubId: ''})},
    {status: status({ownerId: 'owner-other'})},
    {scope: {profileId: 'profile-other', selectionGeneration: 3}},
    {public: publicCapabilities({contract_revision: 'v1.6.0'})},
    {public: publicCapabilities({client_control_pq_e2ee: false})},
    {public: publicCapabilities({authenticated_client_session: false})},
    {public: publicCapabilities({available_rpc_operations: []})},
    {public: publicCapabilities({external_rpc_operations: []}),
      session: sessionCapabilities({role: 'external'})},
    {session: sessionCapabilities({owner_id: 'owner-other'})},
    {session: sessionCapabilities({available_rpc_operations: []})},
    {session: sessionCapabilities({role: 'agent'})},
    {status: status({role: 'manager'}), session: sessionCapabilities({role: 'external'})},
  ]) assert.equal(supported(patch), false);
  assert.equal(supported({status: status({pendingOperationId: 'recovery-pending', authFenced: true})}), true,
    'transient session fences disable the read action without presenting an unsupported API');
});

test('scope and list generations invalidate Hub-switch, recovery, and old async callbacks', () => {
  const original = linkReviewPolicyStatusScopeKey(authorityInput());
  for (const patch of [
    {status: status({profileId: 'profile-b'})},
    {status: status({selectionGeneration: 4})},
    {status: status({hubId: 'hub-b'})},
    {status: status({ownerId: 'owner-b'})},
    {status: status({deviceId: 'phone-b'})},
    {status: status({sessionEpoch: 6})},
    {status: status({pendingOperationId: 'recovery-pending'})},
    {status: status({uncertainNeedsReconciliation: true})},
    {publicCapabilities: publicCapabilities({available_rpc_operations: []})},
    {sessionCapabilities: sessionCapabilities({available_rpc_operations: []})},
    {listGeneration: 5},
    {linkVersion: 8},
    {bridgeReady: false},
  ]) assert.notEqual(linkReviewPolicyStatusScopeKey(authorityInput(patch)), original);

  const lifecycle = new LinkReviewPolicyStatusLifecycle();
  const capture = lifecycle.capture(original);
  assert.equal(lifecycle.isCurrent(capture, original, true), true);
  assert.equal(lifecycle.isCurrent(capture,
    linkReviewPolicyStatusScopeKey(authorityInput({status: status({hubId: 'hub-b'})})), true), false);
  assert.equal(lifecycle.isCurrent(capture, original, false), false);
  lifecycle.invalidate();
  assert.equal(lifecycle.isCurrent(capture, original, true), false);
});
