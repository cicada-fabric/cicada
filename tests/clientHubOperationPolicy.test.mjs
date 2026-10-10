import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  DEFERRED_CLIENT_CONSENT_OPERATIONS, DEFERRED_V16_RPC_OPERATIONS,
  IMPLEMENTED_CLIENT_RPC_OPERATIONS,
  clientHubOperationAllowed, isImplementedClientRpcOperation,
} from '../src/platform/clientHubOperationPolicy.ts';

const catalog = JSON.parse(readFileSync(new URL(
  '../contracts/client-hub-v1.6.5-c6887f4/cicada-go/internal/clientcontract/catalog.json', import.meta.url,
)));
const session = () => ({
  nativeAvailable: true, remoteEnabled: true, sessionCapabilitiesReady: true,
  allowedOperations: [...IMPLEMENTED_CLIENT_RPC_OPERATIONS, ...DEFERRED_CLIENT_CONSENT_OPERATIONS,
    ...DEFERRED_V16_RPC_OPERATIONS],
});

test('local operation policy accounts for every operation in the independently imported v1.6.5 catalog', () => {
  const expected = catalog.operations.map(value => value.id).sort();
  const actual = session().allowedOperations.sort();
  assert.equal(expected.length, 55);
  assert.equal(new Set(actual).size, 55);
  assert.deepEqual(actual, expected);
  assert.equal(IMPLEMENTED_CLIENT_RPC_OPERATIONS.length, 44);
  assert.equal(DEFERRED_CLIENT_CONSENT_OPERATIONS.length, 7);
  assert.equal(DEFERRED_V16_RPC_OPERATIONS.length, 4);
});

test('advertised permission never enables unimplemented consent, delegation or link key flows', () => {
  for (const op of [...DEFERRED_CLIENT_CONSENT_OPERATIONS, ...DEFERRED_V16_RPC_OPERATIONS,
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

test('link review-policy status is a read gated by its exact current encrypted session capability', () => {
  const operation = 'link.review_policy_status';
  assert.equal(isImplementedClientRpcOperation(operation), true);
  assert.equal(DEFERRED_V16_RPC_OPERATIONS.includes(operation), false);
  assert.equal(clientHubOperationAllowed(session(), operation), true);

  // A locally supported read does not infer permission when session.capabilities omits it.
  assert.equal(clientHubOperationAllowed({...session(), allowedOperations: []}, operation), false);
  assert.equal(clientHubOperationAllowed({...session(), sessionCapabilitiesReady: false}, operation), false);

  for (const fence of [
    {nativeAvailable: false}, {authFenced: true}, {recoveryBlocked: true},
    {pendingOperationId: 'original-operation'},
  ]) {
    assert.equal(clientHubOperationAllowed({...session(), ...fence}, operation), false,
      JSON.stringify(fence));
  }

  // Read-only status remains available for reconciliation after an uncertain outcome.
  assert.equal(clientHubOperationAllowed({...session(), uncertainNeedsReconciliation: true},
    operation), true);
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
  for (const op of ['status.snapshot', 'topology.snapshot', 'intent.status', 'goal.result',
    'link.review_policy_status']) {
    assert.equal(clientHubOperationAllowed(state, op), true, op);
  }
  for (const op of ['topology.apply', 'intent.submit', 'approvals.decide', 'network.key_grant',
    'group.key_grant', 'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
    'topology.delegation_issue', 'topology.delegation_revoke']) {
    assert.equal(clientHubOperationAllowed(state, op), false, op);
  }
});

test('a Link consent fence survives generic reconciliation and blocks fresh mutations', () => {
  const state = {...session(), linkConsentReconciliationRequired: true, uncertainNeedsReconciliation: false};
  for (const op of ['status.snapshot', 'link.list', 'link.review_policy_status']) {
    assert.equal(clientHubOperationAllowed(state, op), true);
  }
  for (const op of ['topology.apply', 'intent.submit', 'approvals.decide', 'group.key_grant',
    'network.key_grant', 'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
    'topology.delegation_issue', 'topology.delegation_revoke']) {
    assert.equal(clientHubOperationAllowed(state, op), false, op);
  }
});

test('delegation business fence survives a generic snapshot and permits only proposal inspection', () => {
  const state = {...session(), regroupReconciliationRequired: true, uncertainNeedsReconciliation: false};
  assert.equal(clientHubOperationAllowed(state, 'topology.delegation_issue'), false);
  assert.equal(clientHubOperationAllowed(state, 'topology.delegation_revoke'), false);
  assert.equal(clientHubOperationAllowed(state, 'topology.regroup_proposal'), true);
  assert.equal(clientHubOperationAllowed(state, 'status.snapshot'), true);
});

test('Network reconciliation fence survives generic reconciliation and preserves read access', () => {
  const state = {...session(), networkGrantReconciliationRequired: true,
    uncertainNeedsReconciliation: false};
  assert.equal(clientHubOperationAllowed(state, 'network.key_grant'), false);
  assert.equal(clientHubOperationAllowed(state, 'network.key_status'), true);
  assert.equal(clientHubOperationAllowed(state, 'status.snapshot'), true);
});
