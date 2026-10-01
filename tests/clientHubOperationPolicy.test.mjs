import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  DEFERRED_CLIENT_CONSENT_OPERATIONS, DEFERRED_V16_RPC_OPERATIONS,
  IMPLEMENTED_CLIENT_RPC_OPERATIONS,
  UNVERIFIED_LINK_KEY_OPERATIONS, clientHubOperationAllowed, isImplementedClientRpcOperation,
} from '../src/platform/clientHubOperationPolicy.ts';

const catalog = JSON.parse(readFileSync(new URL(
  '../contracts/client-hub-v1.6-f4e4725/cicada-go/internal/clientcontract/catalog.json', import.meta.url,
)));
const session = () => ({
  nativeAvailable: true, remoteEnabled: true, sessionCapabilitiesReady: true,
  allowedOperations: [...IMPLEMENTED_CLIENT_RPC_OPERATIONS, ...DEFERRED_CLIENT_CONSENT_OPERATIONS,
    ...DEFERRED_V16_RPC_OPERATIONS, ...UNVERIFIED_LINK_KEY_OPERATIONS],
});

test('local operation policy accounts for every operation in the independently imported v1.6 catalog', () => {
  const expected = catalog.operations.map(value => value.id).sort();
  const actual = session().allowedOperations.sort();
  assert.equal(expected.length, 55);
  assert.equal(new Set(actual).size, 55);
  assert.deepEqual(actual, expected);
  assert.equal(IMPLEMENTED_CLIENT_RPC_OPERATIONS.length, 35);
  assert.equal(DEFERRED_CLIENT_CONSENT_OPERATIONS.length, 10);
  assert.equal(DEFERRED_V16_RPC_OPERATIONS.length, 7);
});

test('advertised permission never enables unimplemented consent, delegation or link key flows', () => {
  for (const op of [...DEFERRED_CLIENT_CONSENT_OPERATIONS, ...DEFERRED_V16_RPC_OPERATIONS,
    ...UNVERIFIED_LINK_KEY_OPERATIONS,
    'future.unknown_operation', '', ' space.key_consent_v2']) {
    assert.equal(isImplementedClientRpcOperation(op), false);
    assert.equal(clientHubOperationAllowed(session(), op), false, op);
  }
  for (const value of [null, {}, ['topology.apply'], 1]) {
    assert.equal(isImplementedClientRpcOperation(value), false);
  }
});

test('a locally implemented operation still requires its encrypted session permission', () => {
  assert.equal(clientHubOperationAllowed(session(), 'topology.snapshot'), true);
  assert.equal(clientHubOperationAllowed({...session(), allowedOperations: ['status.snapshot']},
    'topology.snapshot'), false);
});

test('pending packets and authentication or recovery fences refuse every new operation', () => {
  for (const fence of [
    {nativeAvailable: false}, {remoteEnabled: false}, {sessionCapabilitiesReady: false},
    {authFenced: true}, {recoveryBlocked: true}, {pendingOperationId: 'original-operation'},
  ]) {
    for (const op of IMPLEMENTED_CLIENT_RPC_OPERATIONS) {
      assert.equal(clientHubOperationAllowed({...session(), ...fence}, op), false, op);
    }
  }
});

test('OUTCOME_UNCERTAIN permits authoritative reads and refuses management mutations', () => {
  const state = {...session(), uncertainNeedsReconciliation: true};
  for (const op of ['status.snapshot', 'topology.snapshot', 'intent.status', 'goal.result']) {
    assert.equal(clientHubOperationAllowed(state, op), true, op);
  }
  for (const op of ['topology.apply', 'intent.submit', 'approvals.decide', 'network.key_grant',
    'group.key_grant', 'monitor.broadcast_prepare', 'monitor.broadcast_confirm']) {
    assert.equal(clientHubOperationAllowed(state, op), false, op);
  }
});

test('Network reconciliation fence survives generic reconciliation and preserves read access', () => {
  const state = {...session(), networkGrantReconciliationRequired: true,
    uncertainNeedsReconciliation: false};
  assert.equal(clientHubOperationAllowed(state, 'network.key_grant'), false);
  assert.equal(clientHubOperationAllowed(state, 'network.key_status'), true);
  assert.equal(clientHubOperationAllowed(state, 'status.snapshot'), true);
});
