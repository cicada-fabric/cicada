import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MONITOR_BROADCAST_BODY_MAX_BYTES,
  MONITOR_PREFLIGHT_OPERATIONS,
  MONITOR_REQUIRED_ALLOWED_OPERATIONS,
  MONITOR_RPC_OPERATIONS,
  inspectMonitorBody,
  membershipAllowsBroadcast,
  membershipHasMonitorRole,
  monitorApprovalStatusText,
  monitorCatalogAllows,
  monitorBodyUtf8ByteLength,
  monitorOperationValidUntil,
  monitorPreviewConfirmationCutoffMs,
  monitorPreviewConfirmationExpiryReason,
  monitorPreviewConfirmationIsExpired,
  monitorPreviewIsExpired,
  monitorPreviewResultFromNative,
  monitorPreviewStaleReason,
  monitorRecipientOutcomeText,
  monitorConfirmResultFromNative,
  monitorStatusResultFromNative,
} from '../src/platform/monitorBroadcast.ts';

const revision = 'client-hub-v1.3';
const catalog = '808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377';

const goodStatus = () => ({
  nativeAvailable: true,
  remoteEnabled: true,
  sessionCapabilitiesReady: true,
  authFenced: false,
  ownerId: 'owner-a',
  allowedOperations: [...MONITOR_REQUIRED_ALLOWED_OPERATIONS],
});

test('counts exact UTF-8 bytes without trimming or changing the body', () => {
  const exact = ' 你好😀\n  ';
  const measured = inspectMonitorBody(exact);
  assert.equal(measured.exactBody, exact);
  assert.equal(measured.byteLength, 14);
  assert.equal(monitorBodyUtf8ByteLength('x\n'), 2);
  assert.equal(monitorBodyUtf8ByteLength('😀'), 4);
  assert.ok(measured.withinLimit);
  assert.equal(MONITOR_BROADCAST_BODY_MAX_BYTES, 16_384);
});

test('rejects malformed UTF-16 instead of silently replacing a surrogate', () => {
  assert.equal(monitorBodyUtf8ByteLength('\ud800'), null);
  assert.equal(monitorBodyUtf8ByteLength('\udc00'), null);
  assert.equal(inspectMonitorBody('a\ud800b').validUtf8, false);
});

test('Monitor role and message.broadcast are independent membership facts', () => {
  const monitorWithoutGrant = {role: 'monitor', broadcast_permission_enabled: false};
  assert.ok(membershipHasMonitorRole(monitorWithoutGrant));
  assert.equal(membershipAllowsBroadcast(monitorWithoutGrant), false);
  assert.equal(membershipAllowsBroadcast({
    role: 'member', roles: ['member', 'monitor'], broadcast_permission_enabled: true,
  }), true);
  assert.equal(membershipAllowsBroadcast({
    role: 'monitor', broadcast_permission_enabled: 'true',
  }), false);
});

test('requires the exact public and encrypted v1.3 Monitor operation allowlists', () => {
  const capabilities = {
    contract_revision: revision,
    catalog_sha256: catalog,
    client_control_pq_e2ee: true,
    authenticated_client_session: true,
    available_rpc_operations: [...MONITOR_REQUIRED_ALLOWED_OPERATIONS],
    external_rpc_operations: [...MONITOR_REQUIRED_ALLOWED_OPERATIONS],
  };
  const session = {
    owner_id: 'owner-a', role: 'manager', contract_revision: revision,
    catalog_sha256: catalog,
    available_rpc_operations: [...MONITOR_REQUIRED_ALLOWED_OPERATIONS],
  };
  assert.equal(monitorCatalogAllows(capabilities, session, goodStatus(), true, revision, catalog), true);
  const externalSession = {...session, role: 'external'};
  assert.equal(monitorCatalogAllows(capabilities, externalSession, goodStatus(), true,
    revision, catalog), true);
  assert.equal(monitorCatalogAllows(capabilities, {...session,
    available_rpc_operations: MONITOR_RPC_OPERATIONS.slice(1)}, goodStatus(), true,
  revision, catalog), false);
  assert.equal(monitorCatalogAllows({...capabilities, catalog_sha256: 'stale'}, session,
    goodStatus(), true, revision, catalog), false);
  assert.equal(monitorCatalogAllows(capabilities, session, goodStatus(), false,
    revision, catalog), false);

  for (const operation of MONITOR_PREFLIGHT_OPERATIONS) {
    assert.equal(monitorCatalogAllows({...capabilities,
      available_rpc_operations: capabilities.available_rpc_operations.filter(item => item !== operation)},
    session, goodStatus(), true, revision, catalog), false,
      `manager public allowlist must include ${operation}`);
    assert.equal(monitorCatalogAllows({...capabilities,
      external_rpc_operations: capabilities.external_rpc_operations.filter(item => item !== operation)},
    externalSession, goodStatus(), true, revision, catalog), false,
      `external public allowlist must include ${operation}`);
    assert.equal(monitorCatalogAllows(capabilities, {...session,
      available_rpc_operations: session.available_rpc_operations.filter(item => item !== operation)},
    goodStatus(), true, revision, catalog), false,
      `encrypted session allowlist must include ${operation}`);
    assert.equal(monitorCatalogAllows(capabilities, session, {...goodStatus(),
      allowedOperations: goodStatus().allowedOperations.filter(item => item !== operation)},
    true, revision, catalog), false, `native allowlist must include ${operation}`);
  }
});

const endpoint = (id, principal, binding, membershipRevision) => ({
  endpointId: id,
  principalId: principal,
  ownerId: 'owner-a',
  nodeId: `node-${id}`,
  membershipRevision,
  groupJoinRevision: 1,
  bindingId: binding,
  bindingEpoch: 1,
  keyId: `key-${id}`,
  keyVersion: 1,
  keyFingerprint: `sha256:${'a'.repeat(64)}`,
  keyProofDigest: 'b'.repeat(64),
});

const currentTopology = () => ({
  groups: [{group_id: 'group-a', state: 'ACTIVE', version: 3}],
  memberships: [
    {membership_id: 'm-source', principal_id: 'principal-source', group_id: 'group-a',
      role: 'monitor', status: 'ACTIVE', broadcast_permission_enabled: true, version: 4},
    {membership_id: 'm-recipient', principal_id: 'principal-recipient', group_id: 'group-a',
      role: 'member', status: 'ACTIVE', broadcast_permission_enabled: false, version: 2},
  ],
  endpoints: [
    {endpoint_id: 'endpoint-source', principal_id: 'principal-source', group_ids: ['group-a'],
      node_id: 'node-endpoint-source', binding_id: 'binding-source', binding_epoch: 1,
      binding_status: 'leased'},
    {endpoint_id: 'endpoint-recipient', principal_id: 'principal-recipient', group_ids: ['group-a'],
      node_id: 'node-endpoint-recipient', binding_id: 'binding-recipient', binding_epoch: 1,
      binding_status: 'leased'},
  ],
});

const currentPreview = () => ({
  operationId: 'op-a', previewId: 'preview-a', broadcastId: 'broadcast-a', status: 'PREPARED',
  groupId: 'group-a', monitorEndpointId: 'endpoint-source', bodySha256: 'c'.repeat(64),
  snapshotDigest: 'd'.repeat(64), expiresAt: '2030-01-01T00:05:00Z',
  grantExpiresAt: '2030-01-01T00:10:00Z', validUntil: '2030-01-01T00:05:00Z',
  monitorKeyId: 'key-endpoint-source',
  monitorBindingId: 'binding-source', monitorBindingEpoch: 1, consentDigest: 'e'.repeat(64),
  groupRevision: 3, source: endpoint('endpoint-source', 'principal-source', 'binding-source', 4),
  recipients: [endpoint('endpoint-recipient', 'principal-recipient', 'binding-recipient', 2)],
});

test('accepts only current same-owner consent revisions and roster', () => {
  assert.equal(monitorPreviewStaleReason(currentPreview(), currentTopology(), 'owner-a'), null);
  const divergentCasVersions = currentTopology();
  divergentCasVersions.groups[0].version = 20;
  divergentCasVersions.memberships[0].version = 30;
  divergentCasVersions.memberships[1].version = 40;
  assert.equal(monitorPreviewStaleReason(currentPreview(), divergentCasVersions, 'owner-a'), null);

  const inactiveGroup = currentTopology();
  inactiveGroup.groups[0].state = 'PAUSED';
  assert.match(monitorPreviewStaleReason(currentPreview(), inactiveGroup, 'owner-a'), /Group/);
  const invalidGroupCas = currentTopology();
  invalidGroupCas.groups[0].version = 0;
  assert.match(monitorPreviewStaleReason(currentPreview(), invalidGroupCas, 'owner-a'), /Group/);

  const revokedPermission = currentTopology();
  revokedPermission.memberships[0].broadcast_permission_enabled = false;
  assert.match(monitorPreviewStaleReason(currentPreview(), revokedPermission, 'owner-a'), /权限/);
  const removedMonitorRole = currentTopology();
  removedMonitorRole.memberships[0].role = 'member';
  removedMonitorRole.memberships[0].roles = ['member'];
  assert.match(monitorPreviewStaleReason(currentPreview(), removedMonitorRole, 'owner-a'), /角色/);

  const changedBinding = currentTopology();
  changedBinding.endpoints[0].binding_id = 'binding-replaced';
  assert.match(monitorPreviewStaleReason(currentPreview(), changedBinding, 'owner-a'), /Endpoint 绑定/);
  const unleasedEndpoint = currentTopology();
  unleasedEndpoint.endpoints[1].binding_status = 'revoked';
  assert.match(monitorPreviewStaleReason(currentPreview(), unleasedEndpoint, 'owner-a'), /Endpoint 绑定/);

  const changedRoster = currentTopology();
  changedRoster.endpoints.push({endpoint_id: 'endpoint-new', principal_id: 'principal-new',
    node_id: 'node-new', group_ids: ['group-a'], binding_id: 'binding-new', binding_epoch: 1,
    binding_status: 'leased'});
  assert.match(monitorPreviewStaleReason(currentPreview(), changedRoster, 'owner-a'), /roster/);
  assert.match(monitorPreviewStaleReason(currentPreview(), currentTopology(), 'owner-b'), /Owner/);
});

test('expiry is closed at the boundary and invalid timestamps fail closed', () => {
  const now = Date.parse('2030-01-01T00:05:00Z');
  assert.equal(monitorPreviewIsExpired('2030-01-01T00:05:01Z', now), false);
  assert.equal(monitorPreviewIsExpired('2030-01-01T00:05:00Z', now), true);
  assert.equal(monitorPreviewIsExpired('invalid', now), true);
});

test('confirmation cutoff uses the earlier verified preview or Group grant expiry', () => {
  const now = Date.parse('2030-01-01T00:02:00Z');
  const grantExpiresFirst = {...currentPreview(),
    grantExpiresAt: '2030-01-01T00:03:00Z', validUntil: '2030-01-01T00:03:00Z'};
  assert.equal(monitorPreviewConfirmationCutoffMs(grantExpiresFirst),
    Date.parse('2030-01-01T00:03:00Z'));
  assert.equal(monitorPreviewConfirmationIsExpired(grantExpiresFirst, now), false);
  assert.equal(monitorPreviewConfirmationExpiryReason(grantExpiresFirst, now), null);
  assert.match(monitorPreviewConfirmationExpiryReason(grantExpiresFirst,
    Date.parse('2030-01-01T00:03:00Z')), /Group 授权已到期/);

  const previewExpiresFirst = {...currentPreview(),
    grantExpiresAt: '2030-01-01T00:10:00Z', validUntil: '2030-01-01T00:05:00Z'};
  assert.equal(monitorPreviewConfirmationCutoffMs(previewExpiresFirst),
    Date.parse('2030-01-01T00:05:00Z'));
  assert.match(monitorPreviewConfirmationExpiryReason(previewExpiresFirst,
    Date.parse('2030-01-01T00:05:00Z')), /预览已过期/);
});

test('fresh preview cutoff metadata fails closed; old operation indexes fall back to expiresAt', () => {
  const preview = currentPreview();
  assert.equal(monitorPreviewConfirmationCutoffMs({...preview, validUntil: ''}), null);
  assert.equal(monitorPreviewConfirmationIsExpired({...preview,
    validUntil: '2030-01-01T00:04:00Z'}, Date.parse('2030-01-01T00:02:00Z')), true);
  assert.match(monitorPreviewConfirmationExpiryReason({...preview, grantExpiresAt: ''}), /无效/);
  assert.equal(monitorOperationValidUntil({expiresAt: '2030-01-01T00:05:00Z'}),
    '2030-01-01T00:05:00Z');
  assert.equal(monitorOperationValidUntil({expiresAt: 'old', validUntil: 'new'}), 'new');
});

test('delivery text never calls persistence model consumption', () => {
  const nodeReported = monitorRecipientOutcomeText({
    ordinal: 0, endpointId: 'endpoint-recipient', state: 'ACCEPTED', evidence: 'NODE_REPORTED',
  });
  const relayPersisted = monitorRecipientOutcomeText({
    ordinal: 0, endpointId: 'endpoint-recipient', state: 'ACCEPTED', evidence: 'RELAY_PERSISTED',
  });
  assert.match(nodeReported, /不代表 Runtime 或模型已消费/);
  assert.match(relayPersisted, /不代表 Runtime 或模型已消费/);
  assert.equal(monitorApprovalStatusText('DISPATCH_AUTHORIZED'), '已授权分发，接收结果仍待读取');
});

const nativeConfirmFixture = () => ({
  requestId: 'request-confirm-a',
  operationId: 'operation-confirm-a',
  ok: true,
  result: {
    preview_id: 'preview-a',
    broadcast_id: 'broadcast-a',
    status: 'APPROVED',
    group_id: 'group-a',
    monitor_endpoint_id: 'endpoint-source',
    body_sha256: 'c'.repeat(64),
    snapshot_digest: 'd'.repeat(64),
    expires_at: '2030-01-01T00:05:00Z',
    approved_at: '2030-01-01T00:01:00Z',
    sealed_payload_digest: 'f'.repeat(64),
  },
  previewId: 'preview-a',
  confirmed: true,
});

const nativeVerifiedPreviewFixture = () => ({
  operationId: 'op-a',
  previewId: 'preview-a',
  broadcastId: 'broadcast-a',
  groupId: 'group-a',
  monitorEndpointId: 'endpoint-source',
  bodySha256: 'c'.repeat(64),
  snapshotDigest: 'd'.repeat(64),
  expiresAt: '2030-01-01T00:05:00Z',
  grantExpiresAt: '2030-01-01T00:10:00Z',
  validUntil: '2030-01-01T00:05:00Z',
  status: 'PREPARED',
  groupRevision: 3,
  consentDigest: 'e'.repeat(64),
  source: endpoint('endpoint-source', 'principal-source', 'binding-source', 4),
  recipients: [endpoint('endpoint-recipient', 'principal-recipient', 'binding-recipient', 2)],
  monitorKeyId: 'key-endpoint-source',
  monitorBindingId: 'binding-source',
  monitorBindingEpoch: 1,
  canConfirm: true,
  verified: true,
});

const nativeStatusFixture = () => ({
  requestId: 'request-status-a',
  operationId: 'operation-status-a',
  ok: true,
  result: {
    preview_id: 'preview-a',
    broadcast_id: 'broadcast-a',
    group_id: 'group-a',
    approval_status: 'DISPATCH_AUTHORIZED',
    expires_at: '2030-01-01T00:05:00Z',
    recipients: [
      {ordinal: 0, endpoint_id: 'endpoint-recipient', state: 'ACCEPTED',
        evidence: 'NODE_REPORTED', message_id: 'message-a', reported_at: '2030-01-01T00:02:00Z'},
      {ordinal: 1, endpoint_id: 'endpoint-recipient-2', state: 'FAILED',
        failure_code: 'DELIVERY_REJECTED'},
    ],
  },
});

test('adapts actual native Confirm envelope and contract snake_case result to UI DTO', () => {
  assert.deepEqual(monitorConfirmResultFromNative(nativeConfirmFixture(), 'preview-a'), {
    previewId: 'preview-a',
    broadcastId: 'broadcast-a',
    status: 'APPROVED',
    groupId: 'group-a',
    monitorEndpointId: 'endpoint-source',
    bodySha256: 'c'.repeat(64),
    snapshotDigest: 'd'.repeat(64),
    expiresAt: '2030-01-01T00:05:00Z',
    approvedAt: '2030-01-01T00:01:00Z',
    dispatchAuthorizedAt: undefined,
    sealedPayloadDigest: 'f'.repeat(64),
  });

  const missingConfirmMarker = nativeConfirmFixture();
  delete missingConfirmMarker.confirmed;
  assert.throws(() => monitorConfirmResultFromNative(missingConfirmMarker, 'preview-a'),
    error => error.code === 'INVALID_MONITOR_NATIVE_RESULT');
  const wrongPreview = nativeConfirmFixture();
  wrongPreview.result.preview_id = 'other-preview';
  assert.throws(() => monitorConfirmResultFromNative(wrongPreview, 'preview-a'),
    error => error.code === 'INVALID_MONITOR_NATIVE_RESULT');
});

test('accepts only native-verified flat Prepare/Recover previews and preserves raw failures', () => {
  const preview = nativeVerifiedPreviewFixture();
  const mapped = monitorPreviewResultFromNative(preview, {
    operationId: 'op-a', groupId: 'group-a', monitorEndpointId: 'endpoint-source',
  });
  assert.equal(mapped.previewId, 'preview-a');
  assert.equal(mapped.recipients[0].endpointId, 'endpoint-recipient');
  assert.equal('verified' in mapped, false);
  assert.throws(() => monitorPreviewResultFromNative({...preview, verified: false}),
    error => error.code === 'INVALID_MONITOR_NATIVE_RESULT');

  assert.throws(() => monitorPreviewResultFromNative({
    ok: false, error: 'user-through-Monitor broadcast is temporarily busy',
    monitorOperationId: 'op-a',
  }, {operationId: 'op-a'}), error =>
    error.message === 'user-through-Monitor broadcast is temporarily busy' &&
    error.operationId === 'op-a');

  assert.throws(() => monitorPreviewResultFromNative({
    operationId: 'op-a', outcomeUncertain: true, recoveryRequired: true,
    errorCode: 'OUTCOME_UNCERTAIN',
  }, {operationId: 'op-a'}), error =>
    error.code === 'OUTCOME_UNCERTAIN' && error.operationId === 'op-a');
  assert.throws(() => monitorPreviewResultFromNative({
    operationId: 'lookup-op', monitorOperationId: 'op-a', ok: false,
    recoveryUnresolved: true, errorCode: 'OUTCOME_UNCERTAIN',
  }, {operationId: 'op-a'}), error =>
    error.code === 'OUTCOME_UNCERTAIN' && error.operationId === 'op-a');

  assert.throws(() => monitorPreviewResultFromNative({
    operationId: 'op-a', previewId: 'preview-a', broadcastId: 'broadcast-a',
    status: 'PREPARED', expiresAt: '2029-12-31T23:59:00Z', grantExpiresAt: '2030-01-01T00:10:00Z',
    validUntil: '2029-12-31T23:59:00Z', recoveryResolved: true,
    canConfirm: false, statusAvailable: true,
  }, {operationId: 'op-a'}), error =>
    error.code === 'MONITOR_PREVIEW_NOT_CONFIRMABLE' &&
    error.operationId === 'op-a' && error.previewId === 'preview-a');
  assert.throws(() => monitorPreviewResultFromNative({
    operationId: 'op-a', state: 'REJECTED', recoveryResolved: true, canConfirm: false,
  }, {operationId: 'op-a'}), error =>
    error.code === 'MONITOR_PREPARE_REJECTED' && error.operationId === 'op-a');
});

test('adapts actual native Status envelope and exact bounded recipient DTO fields', () => {
  assert.deepEqual(monitorStatusResultFromNative(nativeStatusFixture(), 'preview-a'), {
    previewId: 'preview-a',
    broadcastId: 'broadcast-a',
    groupId: 'group-a',
    approvalStatus: 'DISPATCH_AUTHORIZED',
    expiresAt: '2030-01-01T00:05:00Z',
    recipients: [
      {ordinal: 0, endpointId: 'endpoint-recipient', state: 'ACCEPTED',
        evidence: 'NODE_REPORTED', messageId: 'message-a', failureCode: undefined,
        reportedAt: '2030-01-01T00:02:00Z'},
      {ordinal: 1, endpointId: 'endpoint-recipient-2', state: 'FAILED', evidence: undefined,
        messageId: undefined, failureCode: 'DELIVERY_REJECTED', reportedAt: undefined},
    ],
  });

  const wrongState = nativeStatusFixture();
  wrongState.result.recipients[0].state = 'CONSUMED';
  assert.throws(() => monitorStatusResultFromNative(wrongState, 'preview-a'),
    error => error.code === 'INVALID_MONITOR_NATIVE_RESULT');
  assert.throws(() => monitorStatusResultFromNative(nativeStatusFixture(), 'other-preview'),
    error => error.code === 'INVALID_MONITOR_NATIVE_RESULT');
});

test('native Monitor rejections stay errors and preserve OUTCOME_UNCERTAIN code', () => {
  const uncertainConfirm = {
    operationId: 'operation-confirm-a', previewId: 'preview-a',
    outcomeUncertain: true, statusRequired: true, errorCode: 'OUTCOME_UNCERTAIN',
  };
  assert.throws(() => monitorConfirmResultFromNative(uncertainConfirm, 'preview-a'),
    error => error.code === 'OUTCOME_UNCERTAIN' && error.operationId === 'operation-confirm-a');

  const uncertainStatus = {
    requestId: 'request-status-a', operationId: 'operation-status-a', ok: false,
    errorCode: 'OUTCOME_UNCERTAIN', recovery: {state: 'UNCERTAIN'},
  };
  assert.throws(() => monitorStatusResultFromNative(uncertainStatus, 'preview-a'),
    error => error.code === 'OUTCOME_UNCERTAIN');

  assert.throws(() => monitorConfirmResultFromNative({
    operationId: 'operation-confirm-a', previewId: 'preview-a', ok: false,
    error: 'Monitor approval was rejected',
  }, 'preview-a'), error => error.message === 'Monitor approval was rejected');
});
