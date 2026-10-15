import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LINK_LIST_DIAGNOSTIC_STATES,
  linkListDiagnosticStateForFailure,
  linkListDiagnosticTestId,
} from '../src/platform/linkListDiagnostics.ts';

test('link list status maps to the exact finite testID contract', () => {
  assert.deepEqual(LINK_LIST_DIAGNOSTIC_STATES, [
    'IDLE', 'LOADING', 'OK_EMPTY', 'OK_NONEMPTY', 'ERROR_RPC_REJECTED',
    'ERROR_INVALID_RESPONSE', 'ERROR_REQUEST_FAILED',
  ]);
  for (const state of LINK_LIST_DIAGNOSTIC_STATES) {
    assert.equal(linkListDiagnosticTestId(state), `link-list-state-${state}`);
  }
});

test('only known failure categories map to their fixed status states', () => {
  assert.equal(linkListDiagnosticStateForFailure('RPC_REJECTED'), 'ERROR_RPC_REJECTED');
  assert.equal(linkListDiagnosticStateForFailure('INVALID_RESPONSE'), 'ERROR_INVALID_RESPONSE');
  assert.equal(linkListDiagnosticStateForFailure('REQUEST_FAILED'), 'ERROR_REQUEST_FAILED');
  assert.equal(linkListDiagnosticTestId('ERROR_RPC_REJECTED'), 'link-list-state-ERROR_RPC_REJECTED');
});

test('unknown objects and strings never flow into status testIDs', () => {
  const privateDetail = 'raw response body / proof / private-id';
  assert.equal(linkListDiagnosticStateForFailure(new Error(privateDetail)), 'ERROR_REQUEST_FAILED');
  assert.equal(linkListDiagnosticStateForFailure(privateDetail), 'ERROR_REQUEST_FAILED');
  assert.equal(linkListDiagnosticTestId({message: privateDetail}), 'link-list-state-ERROR_REQUEST_FAILED');
  assert.equal(linkListDiagnosticTestId(`ERROR_RPC_REJECTED:${privateDetail}`),
    'link-list-state-ERROR_REQUEST_FAILED');
  assert.doesNotMatch(linkListDiagnosticTestId(privateDetail), /raw response|proof|private-id/);
});
