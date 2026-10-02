import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LINK_CONSENT_OPERATIONS, LINK_CONSENT_READY, LINK_CONSENT_RELEASE,
  LinkConsentPendingOperation, captureLinkConsentReview, linkConsentCanRelease,
  linkConsentOperationRequested, linkConsentRequestFromRpc, linkConsentResponseFromRpc,
  linkConsentReviewIsCurrent, linkConsentReviewScopeKey, markLinkConsentReviewed,
} from '../src/platform/linkConsent.ts';

const operations = [
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
  'link.review_policy_preview', 'link.review_policy_grant',
];

const nonePolicy = () => ({mode: 'NONE', reviewers: [], max_failovers: 0,
  reviewer_lease_seconds: 0, max_review_age_seconds: 0});
const metadataPolicy = () => ({mode: 'METADATA', reviewers: [
  {endpoint_id: 'reviewer-a', group_id: 'group-source'},
], max_failovers: 0, reviewer_lease_seconds: 60, max_review_age_seconds: 600});

const kemPublic = () => Buffer.alloc(1184, 0x51).toString('base64');
const signingPublic = () => Buffer.alloc(1952, 0x62).toString('base64');
const publicIdentity = () => ({id: `pq1-${'a'.repeat(32)}`,
  kem_public: kemPublic(), signing_public: signingPublic()});
const manifestSide = (overrides = {}) => ({
  endpoint_id: 'endpoint-source', group_id: 'group-source', principal_id: 'principal-source',
  owner_id: 'owner-a', node_id: 'node-source', binding_id: 'binding-source',
  binding_epoch: 3, candidate_version: 4, key_id: publicIdentity().id,
  key_fingerprint: `sha256:${'b'.repeat(64)}`, proof_digest: 'c'.repeat(64),
  public_identity: publicIdentity(), attestation: Buffer.from('synthetic-proof-bytes').toString('base64'),
  ...overrides,
});
const manifest = (overrides = {}) => ({version: 2, link_id: 'link-a', link_version: 7,
  contract_digest: 'd'.repeat(64), contract_canonical: Buffer.from('{}').toString('base64'),
  source: manifestSide(), target: manifestSide({endpoint_id: 'endpoint-target', group_id: 'group-target',
    principal_id: 'principal-target', owner_id: 'owner-b', node_id: 'node-target', binding_id: 'binding-target'}),
  digest: 'e'.repeat(64), ...overrides});
const noneStatus = () => ({link_id: 'link-a', link_version: 7, policy_version: 0,
  policy_digest: '', policy: nonePolicy(), current: true, accepted_sides: [], unconfigured: true});
const noneStatusWire = () => ({link_id: 'link-a', link_version: 7, policy_version: 0,
  policy_digest: '', policy: nonePolicy(), current: true, accepted_sides: []});
const endpointAuthority = (side, overrides = {}) => side === 'SOURCE' ? ({
  endpointId: 'endpoint-source', groupId: 'group-source', principalId: 'principal-source',
  ownerId: 'owner-a', nodeId: 'node-source', bindingId: 'binding-source',
  bindingEpoch: 3, candidateVersion: 4, membershipRevision: 2, joinRevision: 3, groupVersion: 4,
  ...overrides,
}) : ({
  endpointId: 'endpoint-target', groupId: 'group-target', principalId: 'principal-target',
  ownerId: 'owner-b', nodeId: 'node-target', bindingId: 'binding-target',
  bindingEpoch: 3, candidateVersion: 4, membershipRevision: 5, joinRevision: 6, groupVersion: 7,
  ...overrides,
});
const reviewScope = (overrides = {}) => ({
  profileId: 'profile-a', selectionGeneration: 2, hubId: 'hub-a', ownerId: 'owner-a',
  deviceId: 'device-a', sessionEpoch: 5, linkId: 'link-a', linkVersion: 7,
  linkState: 'PROPOSED', linkListGeneration: 3, topologyGeneration: 4, side: 'SOURCE',
  manifest: manifest(), ownerKey: {ownerId: 'owner-a', keyId: publicIdentity().id,
    publicIdentity: publicIdentity(), state: 'ACTIVE', version: 1},
  sourceAuthority: endpointAuthority('SOURCE'), targetAuthority: endpointAuthority('TARGET'),
  selectedPolicy: nonePolicy(), currentPolicyStatus: noneStatus(), expectedPolicyVersion: 0,
  reviewerAuthorities: [], ...overrides,
});
const grantStatus = (side, overrides = {}) => ({link_id: 'link-a', side,
  owner_id: side === 'SOURCE' ? 'owner-a' : 'owner-b', accepted: true,
  current_status: 'ACCEPTED', key_id: publicIdentity().id, manifest_digest: 'e'.repeat(64),
  accepted_at: '2026-10-01T12:00:00Z', ...overrides});

// These shape-only public values exercise DTO and review freshness code. The
// synthetic attestation and key bytes are never treated as cryptographically verified.

test('all five Link consent operations stay closed while the candidate release gate is false', () => {
  assert.equal(LINK_CONSENT_READY, false);
  assert.equal(LINK_CONSENT_RELEASE, null);
  assert.deepEqual([...LINK_CONSENT_OPERATIONS], operations);
  for (const operation of operations) assert.equal(linkConsentOperationRequested(operation), true);
  for (const operation of ['link.list', 'link.review_policy_status', 'topology.snapshot', 'link.unknown']) {
    assert.equal(linkConsentOperationRequested(operation), false, operation);
  }
});

test('the five request DTOs accept only the pinned v1.6.1 field shapes', () => {
  // `AQ==` is only an opaque syntactic base64 sample; these functions do not
  // verify a signature or claim that this payload is an Owner proof.
  const valid = [
    ['link.key_manifest', {link_id: 'link-a'}],
    ['link.key_grants', {link_id: 'link-a'}],
    ['link.key_grant', {link_id: 'link-a', side: 'SOURCE', owner_key_id: 'pq1-key',
      signed_proof: 'AQ=='}],
    ['link.review_policy_preview', {link_id: 'link-a', policy: nonePolicy()}],
    ['link.review_policy_grant', {link_id: 'link-a', owner_key_id: 'pq1-key',
      expected_policy_version: 0, policy: nonePolicy(), signed_proof: 'AQ=='}],
  ];
  for (const [operation, body] of valid) {
    assert.ok(linkConsentRequestFromRpc(operation, body), operation);
    assert.equal(linkConsentRequestFromRpc(operation, {...body, unexpected: true}), null, operation);
  }

  assert.equal(linkConsentRequestFromRpc('link.key_grant', {
    link_id: 'link-a', side: 'SOURCE', owner_key_id: 'pq1-key', signed_proof: 'AQ',
  }), null, 'proof bytes require standard padded base64');
  assert.equal(linkConsentRequestFromRpc('link.key_grant', {
    link_id: 'link-a', side: 'SOURCE', owner_key_id: 'pq1-key', signed_proof: 'AR==',
  }), null, 'noncanonical base64 pad bits are rejected');
  assert.equal(linkConsentRequestFromRpc('link.key_grant', {
    link_id: 'link-a', side: 'BOTH', owner_key_id: 'pq1-key', signed_proof: 'AQ==',
  }), null);
  assert.equal(linkConsentRequestFromRpc('link.review_policy_grant', {
    link_id: 'link-a', owner_key_id: 'pq1-key', expected_policy_version: Number.MAX_SAFE_INTEGER + 1,
    policy: nonePolicy(), signed_proof: 'AQ==',
  }), null, 'CAS versions must remain JavaScript-safe integers');
  assert.equal(linkConsentRequestFromRpc('link.review_policy_grant', {
    link_id: 'link-a', owner_key_id: 'pq1-key', expected_policy_version: 0.5,
    policy: nonePolicy(), signed_proof: 'AQ==',
  }), null, 'CAS versions must be integers');
  assert.equal(linkConsentRequestFromRpc('link.review_policy_preview', {
    link_id: 'link-a', policy: {...nonePolicy(), prompt: 'unexpected'},
  }), null, 'nested policy DTO fields are exact too');
  assert.equal(linkConsentRequestFromRpc('link.key_grants', {
    link_id: 'link-a', side: 'SOURCE', owner_key_id: 'pq1-key', signed_proof: 'AQ==',
  }), null, 'a grant body cannot be repurposed as a read request');
});

test('v1.6.1 key-grant status remains unverified metadata and rejects candidate-only evidence', () => {
  const response = linkConsentResponseFromRpc('link.key_grants', [
    grantStatus('SOURCE'), grantStatus('TARGET'),
  ], 'link-a');
  assert.ok(response);
  assert.equal(response.operation, 'link.key_grants');
  assert.deepEqual(response.result.map(item => item.bilateralVerification), ['UNVERIFIED', 'UNVERIFIED']);
  assert.equal(response.result[0].wire.accepted, true);
  assert.equal('signed_proof' in response.result[0].wire, false);
  assert.equal('evidence' in response.result[0].wire, false);

  assert.equal(linkConsentResponseFromRpc('link.key_grants', [
    grantStatus('SOURCE'), grantStatus('TARGET', {evidence: {signed_proof: 'AQ=='}}),
  ], 'link-a'), null, 'the isolated v1.6.3 evidence extension is outside the pinned DTO');
  const stale = linkConsentResponseFromRpc('link.key_grants', [
    grantStatus('SOURCE', {current_status: 'KEY_BINDING_STALE'}), grantStatus('TARGET'),
  ], 'link-a');
  assert.ok(stale, 'historical acceptance and a stale current status are valid metadata');
  assert.equal(stale.result[0].wire.current_status, 'KEY_BINDING_STALE');
  assert.equal(stale.result[0].bilateralVerification, 'UNVERIFIED');
  assert.equal(linkConsentResponseFromRpc('link.key_grants', [
    grantStatus('TARGET'), grantStatus('SOURCE'),
  ], 'link-a'), null, 'status order is bound to SOURCE then TARGET');
});

test('manifest and review previews bind exact Link version and strict wire DTO bounds', () => {
  const keyManifest = manifest();
  const parsedManifest = linkConsentResponseFromRpc('link.key_manifest', keyManifest, 'link-a', 7);
  assert.ok(parsedManifest);
  assert.equal(parsedManifest.result.link_version, 7);
  assert.equal(linkConsentResponseFromRpc('link.key_manifest', keyManifest, 'link-a', 8), null);
  assert.equal(linkConsentResponseFromRpc('link.key_manifest', manifest({unexpected: true}), 'link-a', 7), null);
  assert.equal(linkConsentResponseFromRpc('link.key_manifest', manifest({
    link_version: Number.MAX_SAFE_INTEGER + 1,
  }), 'link-a', 7), null);
  assert.equal(linkConsentResponseFromRpc('link.key_manifest', manifest({
    source: manifestSide({public_identity: {
      ...publicIdentity(), kem_public: 'A'.repeat(1_580),
    }}),
  }), 'link-a', 7), null, 'encoded character count cannot substitute for decoded ML-KEM byte length');

  const preview = {link_id: 'link-a', side: 'SOURCE', owner_id: 'owner-a',
    contract_digest: 'd'.repeat(64), link_version: 7, expected_policy_version: 0,
    policy_version: 1, policy_digest: 'f'.repeat(64), policy: nonePolicy(),
    maximum_proof_expires_at: '2026-10-02T12:00:00Z'};
  assert.ok(linkConsentResponseFromRpc('link.review_policy_preview', preview, 'link-a', 7));
  assert.equal(linkConsentResponseFromRpc('link.review_policy_preview', preview, 'link-a', 8), null);
  assert.equal(linkConsentResponseFromRpc('link.review_policy_preview', {
    ...preview, expected_policy_version: Number.MAX_SAFE_INTEGER,
  }, 'link-a', 7), null);
  assert.ok(linkConsentResponseFromRpc('link.review_policy_grant', noneStatusWire(), 'link-a', 7));
  assert.equal(linkConsentResponseFromRpc('link.review_policy_grant', noneStatusWire(), 'link-a', 8), null,
    'policy status result must match the freshly selected Link version');
});

test('explicit review is tied to one deeply captured current scope and never releases consent', () => {
  const scope = reviewScope({selectedPolicy: metadataPolicy(), reviewerAuthorities: [{
    endpointId: 'reviewer-a', groupId: 'group-source', ownerId: 'owner-c',
    principalId: 'principal-c', membershipRevision: 2, endpointVersion: 3,
    bindingId: 'binding-c', bindingEpoch: 4, active: true, hasLinkReviewPermission: true,
  }]});
  const scopeKey = linkConsentReviewScopeKey(scope);
  assert.equal(typeof scopeKey, 'string');
  const capture = captureLinkConsentReview(scope);
  assert.ok(capture);
  assert.equal(capture.explicitlyReviewed, false);
  assert.equal(markLinkConsentReviewed(capture, scope, false), null);

  const reviewed = markLinkConsentReviewed(capture, scope, true);
  assert.ok(reviewed, 'current user review should create a reviewed capture');
  assert.equal(markLinkConsentReviewed(capture, scope, true), null,
    'the original capture is consumed on first explicit review');
  assert.equal(linkConsentReviewIsCurrent(reviewed, scope), true);
  assert.equal(markLinkConsentReviewed(reviewed, scope, true), null,
    'an already-reviewed capture cannot be reviewed or consumed twice');
  assert.equal(linkConsentCanRelease(reviewed, scope, true), false);
  assert.equal(linkConsentCanRelease(reviewed, scope, false), false);

  const changes = [
    {profileId: 'profile-b'}, {selectionGeneration: 3}, {hubId: 'hub-b'},
    {ownerId: 'owner-b'}, {deviceId: 'device-b'}, {sessionEpoch: 6},
    {linkListGeneration: 4}, {topologyGeneration: 5},
    {linkVersion: 8, manifest: manifest({link_version: 8})},
    {side: 'TARGET'},
    {ownerKey: {...scope.ownerKey, version: 2}},
    {manifest: {...scope.manifest, source: manifestSide({binding_epoch: 4})}},
    {sourceAuthority: {...scope.sourceAuthority, membershipRevision: 8}},
    {targetAuthority: {...scope.targetAuthority, joinRevision: 8}},
    {reviewerAuthorities: [{...scope.reviewerAuthorities[0], bindingEpoch: 5}]},
  ];
  for (const patch of changes) {
    assert.equal(linkConsentReviewIsCurrent(reviewed, {...scope, ...patch}), false,
      `review survived scope change ${Object.keys(patch).join(',')}`);
  }
  assert.equal(captureLinkConsentReview({...scope, ownerKey: {...scope.ownerKey, state: 'REVOKED'}}), null,
    'a revoked Owner key cannot enter the review scope');
  assert.equal(captureLinkConsentReview({...scope, reviewerAuthorities: []}), null,
    'selected reviewers require exact active current permission evidence');
  assert.equal(captureLinkConsentReview({...scope, sourceAuthority: {
    ...scope.sourceAuthority, endpointId: 'endpoint-other',
  }}), null, 'independent current Endpoint scope must match the manifest side');
  assert.equal(captureLinkConsentReview({...scope, expectedPolicyVersion: 1}), null,
    'fresh policy head must match the expected CAS version');
  assert.equal(captureLinkConsentReview({...scope, reviewerAuthorities: [{
    ...scope.reviewerAuthorities[0], hasLinkReviewPermission: false,
  }]}), null, 'reviewer permission must still be current and explicit');
});

test('synthetic pending model retains the original packet for correlated recovery, never RPC resend', () => {
  const exact = Object.freeze({operation: 'link.key_grant', operationId: 'operation-a',
    sequence: 17, packet: 'opaque-encrypted-packet-test-only'});
  const pending = new LinkConsentPendingOperation(exact);
  assert.equal(pending.state, 'PENDING');
  assert.equal(pending.fenced, true);
  assert.deepEqual(pending.retainedPacket(), exact);
  assert.deepEqual(pending.recoveryPacket(), null, 'initial submit is not a retry path');

  assert.equal(pending.responseLost(), 'UNCERTAIN');
  assert.deepEqual(pending.recoveryPacket(), exact,
    'only the original opaque packet/correlation may be supplied to /rpc/recover');
  assert.equal(pending.observeRecovery({operationId: 'operation-other', sequence: 17,
    state: 'STILL_PROCESSING'}), false);
  assert.equal(pending.observeRecovery({operationId: 'operation-a', sequence: 18,
    state: 'STILL_PROCESSING'}), false);
  assert.equal(pending.observeRecovery({operationId: 'operation-a', sequence: 17,
    state: 'UNRECOGNIZED'}), false, 'runtime recovery states are allowlisted');
  assert.equal(pending.state, 'UNCERTAIN');
  assert.equal(pending.observeRecovery({operationId: 'operation-a', sequence: 17,
    state: 'STILL_PROCESSING'}), true);
  assert.equal(pending.state, 'STILL_PROCESSING');
  assert.deepEqual(pending.recoveryPacket(), exact);

  assert.equal(pending.observeRecovery({operationId: 'operation-a', sequence: 17,
    state: 'RECOVERY_UNAVAILABLE'}), true);
  assert.equal(pending.state, 'RECOVERY_UNAVAILABLE');
  assert.equal(pending.fenced, true);
  assert.equal(pending.recoveryPacket(), null,
    'RECOVERY_UNAVAILABLE preserves evidence but never resubmits the original consent RPC');
  assert.deepEqual(pending.retainedPacket(), exact);
  assert.equal(pending.observeRecovery({operationId: 'operation-a', sequence: 17,
    state: 'ACCEPTED'}), false, 'terminal recovery fence cannot be cleared by later generic input');
  assert.equal(pending.observeSnapshot({accepted: true, operation_id: 'operation-a'}), 'RECOVERY_UNAVAILABLE');
  assert.equal(pending.fenced, true);
});

test('synthetic pending model keeps terminal uncertainty and revocation fenced across snapshots', () => {
  const exact = {operation: 'link.review_policy_grant', operationId: 'operation-b',
    sequence: 21, packet: 'another-opaque-encrypted-packet-test-only'};
  const uncertain = new LinkConsentPendingOperation(exact);
  uncertain.responseLost();
  // This exercises only the pure state transition. It does not assert that this synthetic object
  // came from, or was authenticated by, the native encrypted-RPC verifier.
  assert.equal(uncertain.observeRecovery({operationId: 'operation-b', sequence: 21,
    state: 'OUTCOME_UNCERTAIN'}), true);
  assert.equal(uncertain.state, 'TERMINAL_UNCERTAIN');
  assert.equal(uncertain.fenced, true);
  assert.equal(uncertain.recoveryPacket(), null);
  assert.equal(uncertain.observeSnapshot({current_policy_version: 22, accepted_sides: ['SOURCE', 'TARGET']}),
    'TERMINAL_UNCERTAIN');
  assert.equal(uncertain.observeRecovery({operationId: 'operation-b', sequence: 21,
    state: 'ACCEPTED'}), false);

  const revoked = new LinkConsentPendingOperation(exact);
  assert.equal(revoked.revoke(), 'REVOKED');
  assert.equal(revoked.observeSnapshot({accepted: true}), 'REVOKED');
  assert.equal(revoked.fenced, true);
  assert.equal(revoked.recoveryPacket(), null);
});
