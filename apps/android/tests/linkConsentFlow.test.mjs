import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createLinkConsentApi, linkConsentReviewFromNative, linkOwnerProofInputValid,
  linkConsentUiScope, LinkConsentReviewLifecycle,
  linkKeyGrantReceiptFromNative,
  linkConsentCapabilitiesAllow, LINK_CONSENT_PREPARE_STAGES, linkConsentPrepareStatus,
} from '../src/platform/linkConsentFlow.ts';
import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from '../src/platform/clientHubContract.ts';
import {LINK_CONSENT_OPERATIONS} from '../src/platform/linkConsent.ts';

const now = Date.parse('2026-10-02T12:30:00Z');
const qualification = () => ({endpointId: 'reviewer-a', groupId: 'group-a',
  membershipRevision: '9223372036854775807', joinRevision: '2', groupVersion: '3',
  bindingId: 'binding-a', bindingEpoch: '4', leaseExpiresAt: '2026-10-02T13:30:00Z', action: 'link.review'});
const review = () => ({reviewId: 'review-a', consentDigest: 'a'.repeat(64), linkId: 'link-a',
  linkVersion: '7', side: 'SOURCE', manifestDigest: 'b'.repeat(64), contractDigest: 'c'.repeat(64),
  sourceEndpointId: 'source-endpoint', sourceGroupId: 'source-group',
  targetEndpointId: 'target-endpoint', targetGroupId: 'target-group', direction: 'SOURCE_TO_TARGET',
  actions: ['message.send'], dataScopes: ['metadata'], expiresAt: '2026-10-02T14:00:00Z',
  sourceKeyFingerprint: `sha256:${'1'.repeat(64)}`, targetKeyFingerprint: `sha256:${'2'.repeat(64)}`,
  policyDigest: 'd'.repeat(64), policyVersion: '3', maximumProofExpiresAt: '2026-10-02T14:00:00Z',
  ownerKeyId: 'pq1-synthetic', ownerKeyFingerprint: `sha256:${'e'.repeat(64)}`,
  peerOwnerKeyFingerprint: `sha256:${'f'.repeat(64)}`, qualifications: [qualification()],
  signingRequestJson: '{"synthetic":true}'});

test('an absent or incomplete dedicated bridge cannot touch native transport', async () => {
  let calls = 0;
  const method = async () => { calls += 1; };
  for (const native of [undefined, {}, {prepareLinkConsent: method, confirmLinkOwnerPin: method,
    submitLinkConsent: method, readLinkKeyGrants: method}]) {
    const api = createLinkConsentApi(native);
    assert.equal(api.linkConsentReady, false);
    await assert.rejects(api.prepareLinkConsent({}), /VERIFIED_LINK_CONSENT_FLOW_NOT_READY/);
    await assert.rejects(api.recoverLinkConsent(), /VERIFIED_LINK_CONSENT_FLOW_NOT_READY/);
  }
  assert.equal(calls, 0);
});

test('preparation accessibility status uses only fixed stages and sanitized product text', () => {
  assert.deepEqual(LINK_CONSENT_PREPARE_STAGES, [
    'PREPARING', 'REVIEW_READY', 'PREPARE_API_REJECTED', 'DTO_REJECTED', 'REVIEW_INVALIDATED',
  ]);
  for (const stage of LINK_CONSENT_PREPARE_STAGES) {
    const status = linkConsentPrepareStatus(stage);
    assert.equal(status.accessibilityLabel, `CICADA_LINK_PREPARE:${stage}`);
    assert.ok(status.text.length > 0);
    assert.doesNotMatch(status.text, /secret|review-a|link-a|Error:/i);
  }
  assert.notEqual(linkConsentPrepareStatus('PREPARE_API_REJECTED').text,
    linkConsentPrepareStatus('DTO_REJECTED').text);
  assert.equal(linkConsentPrepareStatus('Error: secret API payload'), null);
});

test('preparation status sanitizer rejects exception and native payload objects', () => {
  const privateDetail = 'private-response-review-id-and-proof';
  for (const untrusted of [
    new Error(privateDetail),
    {code: 'NATIVE_FAILURE', message: privateDetail, response: {payload: privateDetail}},
    {stage: 'PREPARE_API_REJECTED', message: privateDetail},
    `PREPARE_API_REJECTED:${privateDetail}`,
    null,
    7,
  ]) assert.equal(linkConsentPrepareStatus(untrusted), null);

  const apiRejected = linkConsentPrepareStatus('PREPARE_API_REJECTED');
  const dtoRejected = linkConsentPrepareStatus('DTO_REJECTED');
  assert.deepEqual(Object.keys(apiRejected).sort(), ['accessibilityLabel', 'text']);
  assert.deepEqual(Object.keys(dtoRejected).sort(), ['accessibilityLabel', 'text']);
  assert.equal(JSON.stringify([apiRejected, dtoRejected]).includes(privateDetail), false);
});

test('native status display never promotes a single Owner or stale grant to bilateral verification', () => {
  const sourceStatus = {side: 'SOURCE', currentStatus: 'ACCEPTED', accepted: true};
  const targetStatus = {side: 'TARGET', currentStatus: 'MISSING', accepted: false};
  const receipt = {linkId: 'link-a', linkVersion: '7', sourceStatus, targetStatus, bilateralVerified: false};
  assert.equal(linkKeyGrantReceiptFromNative(receipt, 'link-a', 7).bilateralVerified, false);
  assert.equal(linkKeyGrantReceiptFromNative({...receipt, bilateralVerified: true}, 'link-a', 7), null);
  assert.equal(linkKeyGrantReceiptFromNative({...receipt, targetStatus: {...targetStatus,
    currentStatus: 'KEY_BINDING_STALE', accepted: true}, bilateralVerified: true}, 'link-a', 7), null);
  assert.equal(linkKeyGrantReceiptFromNative({...receipt, linkVersion: '8'}, 'link-a', 7), null);
});

test('dedicated flow visibility requires fixed public and encrypted Owner capabilities', () => {
  const operations = [...LINK_CONSENT_OPERATIONS, 'link.review_policy_status'];
  const scope = {profileId: 'profile-a', selectionGeneration: 1};
  const status = {...scope, nativeAvailable: true, pinned: true, enrolled: true,
    sessionCapabilitiesReady: true, ownerId: 'owner-a', role: 'external', allowedOperations: operations};
  const capabilities = {contract_revision: CLIENT_HUB_REVISION, catalog_sha256: CLIENT_HUB_CATALOG_SHA256,
    client_control_pq_e2ee: true, authenticated_client_session: true, link_key_consent: true,
    external_thread_links: false, available_rpc_operations: operations, external_rpc_operations: operations};
  const session = {owner_id: 'owner-a', role: 'external', contract_revision: CLIENT_HUB_REVISION,
    catalog_sha256: CLIENT_HUB_CATALOG_SHA256, available_rpc_operations: operations};
  assert.equal(linkConsentCapabilitiesAllow(status, capabilities, session, scope, true), true);
  const retiredPins = {contract_revision: 'client-hub-v1.6.4',
    catalog_sha256: '953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d'};
  assert.equal(linkConsentCapabilitiesAllow(status, {...capabilities, ...retiredPins}, session, scope, true), false);
  assert.equal(linkConsentCapabilitiesAllow(status, capabilities, {...session, ...retiredPins}, scope, true), false);
  assert.equal(linkConsentCapabilitiesAllow(status, {...capabilities, ...retiredPins}, {...session, ...retiredPins}, scope, true), false);
  assert.equal(linkConsentCapabilitiesAllow(status, capabilities, session, scope, false), false);
  assert.equal(linkConsentCapabilitiesAllow(status, capabilities, {...session, owner_id: 'other'}, scope, true), false);
  assert.equal(linkConsentCapabilitiesAllow(status, {...capabilities, catalog_sha256: '0'.repeat(64)}, session, scope, true), false);
  assert.equal(linkConsentCapabilitiesAllow(status, capabilities, {...session, available_rpc_operations: operations.slice(1)}, scope, true), false);
  assert.equal(linkConsentCapabilitiesAllow(status, capabilities, session, {...scope, selectionGeneration: 2}, true), false);
});

test('retained policy display requires exact current bilateral evidence receipt', () => {
  const currentPolicyStatus = {policyVersion: '2', digest: 'f'.repeat(64), current: true,
    sourceStatus: 'VERIFIED', targetStatus: 'VERIFIED', bilateralVerified: true};
  assert.equal(linkConsentReviewFromNative({...review(), currentPolicyStatus}, 'link-a', 7).currentPolicyStatus.policyVersion, '2');
  for (const change of [{current: false}, {targetStatus: 'MISSING'}, {policyVersion: '0'},
    {policyVersion: 2}, {signed_proof: 'must remain native'}]) {
    assert.equal(linkConsentReviewFromNative({...review(), currentPolicyStatus: {...currentPolicyStatus, ...change}}, 'link-a', 7), null);
  }
});

test('native display DTO preserves Int64 revisions and rejects lossy or malformed variants', () => {
  assert.equal(linkConsentReviewFromNative(review(), 'link-a', 7).qualifications[0].membershipRevision,
    '9223372036854775807');
  for (const change of [
    {linkVersion: 7}, {linkVersion: '07'}, {linkId: 'other-link'},
    {qualifications: [{...qualification(), membershipRevision: '9223372036854775808'}]},
    {qualifications: [{...qualification(), bindingEpoch: 4}]},
    {qualifications: [{...qualification(), action: 'message.broadcast'}]},
    {qualifications: [qualification(), qualification()]},
    {policyVersion: undefined}, {signingRequestJson: 'a'.repeat(16_385)},
    {maximumProofExpiresAt: '2026-10-02T14:00:00+00:00'},
    {signing_private: 'must never reach this display model'},
  ]) assert.equal(linkConsentReviewFromNative({...review(), ...change}, 'link-a', 7), null);
});

test('bounded external proof input preserves the exact Base64 spelling', () => {
  const proof = Buffer.alloc(16_384, 1).toString('base64');
  assert.equal(linkOwnerProofInputValid(proof), true);
  for (const bad of ['', `${proof}\n`, ` ${proof}`, proof.replace(/=+$/, ''),
    Buffer.alloc(16_385, 1).toString('base64'), 'AR==']) {
    assert.equal(linkOwnerProofInputValid(bad), false);
  }
});

test('profile or list changes and background invalidation reject old asynchronous reviews', () => {
  const lifecycle = new LinkConsentReviewLifecycle();
  const original = linkConsentUiScope({profileId: 'profile-a', selectionGeneration: 1}, 'link-a', 7, 2);
  const next = linkConsentUiScope({profileId: 'profile-b', selectionGeneration: 2}, 'link-a', 7, 2);
  const generation = lifecycle.capture();
  assert.equal(lifecycle.receive(generation, original, next, review()), false);
  lifecycle.invalidate();
  assert.equal(lifecycle.receive(generation, original, original, review()), false);
  assert.equal(lifecycle.consume(original, 'review-a', 'a'.repeat(64), now), null);
});

test('explicit UI confirmation is single use and cannot cross a changed consent digest', () => {
  const lifecycle = new LinkConsentReviewLifecycle();
  assert.equal(lifecycle.receive(lifecycle.capture(), 'scope-a', 'scope-a', review()), true);
  assert.equal(lifecycle.consume('scope-a', 'review-a', 'changed', now), null);
  assert.ok(lifecycle.consume('scope-a', 'review-a', 'a'.repeat(64), now));
  assert.equal(lifecycle.consume('scope-a', 'review-a', 'a'.repeat(64), now), null);
});

test('expired reviewer lease prevents UI confirmation even before Owner proof expiry', () => {
  const lifecycle = new LinkConsentReviewLifecycle();
  lifecycle.receive(lifecycle.capture(), 'scope-a', 'scope-a', review());
  assert.equal(lifecycle.consume('scope-a', 'review-a', 'a'.repeat(64),
    Date.parse('2026-10-02T13:30:00Z')), null);
  assert.equal(lifecycle.consume('scope-a', 'review-a', 'a'.repeat(64), Number.NaN), null);
});
