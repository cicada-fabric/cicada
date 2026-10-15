import test from 'node:test';
import assert from 'node:assert/strict';
import {LINK_CONSENT_OPERATIONS, linkConsentOperationRequested} from '../src/platform/linkConsent.ts';

test('generic RPC identifies every dedicated consent operation and no unrelated route', () => {
  assert.deepEqual([...LINK_CONSENT_OPERATIONS], ['link.key_manifest', 'link.key_grants',
    'link.key_grant', 'link.review_policy_preview', 'link.review_policy_grant']);
  for (const operation of LINK_CONSENT_OPERATIONS) assert.equal(linkConsentOperationRequested(operation), true);
  for (const operation of ['link.list', 'link.review_policy_status', 'topology.snapshot',
    'link.unknown', ' link.key_grant', '', null, {}, ['link.key_grant']]) {
    assert.equal(linkConsentOperationRequested(operation), false);
  }
});
