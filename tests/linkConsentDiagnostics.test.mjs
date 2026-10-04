import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LINK_CONSENT_DIAGNOSTIC_STAGES, observeLinkConsentDiagnosticSafely,
  sanitizeLinkConsentDiagnosticStage,
} from '../src/platform/linkConsentDiagnosticEvents.ts';

test('diagnostic sanitizer accepts only the fixed stage allowlist', () => {
  assert.deepEqual(LINK_CONSENT_DIAGNOSTIC_STAGES, [
    'CONFIRM_OPENED', 'CALLBACK_ENTERED', 'SCOPE_GUARD_PASSED', 'SCOPE_GUARD_REJECTED',
    'REVIEW_CONSUMED', 'REVIEW_INVALIDATED', 'UI_SUBMIT_DISPATCHED', 'UI_RESPONSE_RETURNED',
    'UI_SUBMIT_REJECTED', 'RESPONSE_SCOPE_CHANGED',
  ]);
  for (const stage of LINK_CONSENT_DIAGNOSTIC_STAGES) {
    assert.equal(sanitizeLinkConsentDiagnosticStage(stage), stage);
  }
  for (const invalid of [
    null, undefined, 1, new Error('private error'), {stage: 'UI_SUBMIT_REJECTED'},
    'UI_SUBMIT_REJECTED:private detail', ' UI_SUBMIT_REJECTED', 'NATIVE_REJECTED',
  ]) assert.equal(sanitizeLinkConsentDiagnosticStage(invalid), null);
});

test('enabled observation forwards only the sanitized stage and never disrupts business flow', () => {
  const observed = [];
  let businessActionRan = false;
  observeLinkConsentDiagnosticSafely('UI_SUBMIT_DISPATCHED', true, stage => observed.push(stage));
  observeLinkConsentDiagnosticSafely('UI_SUBMIT_REJECTED:proof', true, stage => observed.push(stage));
  businessActionRan = true;
  assert.deepEqual(observed, ['UI_SUBMIT_DISPATCHED']);
  assert.equal(businessActionRan, true);

  assert.doesNotThrow(() => observeLinkConsentDiagnosticSafely('CALLBACK_ENTERED', true));
  assert.doesNotThrow(() => observeLinkConsentDiagnosticSafely('CALLBACK_ENTERED', true, () => {
    throw new Error('diagnostic recorder failure');
  }));
});

test('only the exact native true gate calls the recorder', () => {
  let calls = 0;
  for (const gate of [undefined, false, null, 0, 1, 'true', {}]) {
    observeLinkConsentDiagnosticSafely('CONFIRM_OPENED', gate, () => { calls += 1; });
  }
  assert.equal(calls, 0);

  observeLinkConsentDiagnosticSafely('CONFIRM_OPENED', true, () => { calls += 1; });
  assert.equal(calls, 1);
});
