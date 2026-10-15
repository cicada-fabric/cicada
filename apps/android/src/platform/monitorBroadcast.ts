export type MonitorJsonObject = Record<string, unknown>;

export const MONITOR_BROADCAST_BODY_MAX_BYTES = 16_384;
export const MONITOR_BROADCAST_MAX_RECIPIENTS = 32;
export const MONITOR_RPC_OPERATIONS = [
  'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
  'monitor.broadcast_recover', 'monitor.broadcast_status',
] as const;

/** Read-only RPCs required by the native preflight before sealing a Confirm. */
export const MONITOR_PREFLIGHT_OPERATIONS = [
  'topology.snapshot', 'group.key_status',
] as const;

/** Operations that must be granted for the complete Monitor UI flow. */
export const MONITOR_REQUIRED_ALLOWED_OPERATIONS = [
  ...MONITOR_RPC_OPERATIONS, ...MONITOR_PREFLIGHT_OPERATIONS,
] as const;

export interface MonitorCapabilityAdvertisement {
  contract_revision?: string;
  catalog_sha256?: string;
  client_control_pq_e2ee?: boolean;
  authenticated_client_session?: boolean;
  available_rpc_operations?: string[];
  external_rpc_operations?: string[];
}

export interface MonitorSessionGrant {
  owner_id?: string;
  role?: string;
  contract_revision?: string;
  catalog_sha256?: string;
  available_rpc_operations?: string[];
}

export interface MonitorSessionStatus {
  nativeAvailable?: boolean;
  remoteEnabled?: boolean;
  sessionCapabilitiesReady?: boolean;
  authFenced?: boolean;
  ownerId?: string;
  pendingOperationId?: string;
  allowedOperations?: string[];
}

/** Exact v1.3 public catalog + encrypted per-device grant gate for Monitor operations. */
export function monitorCatalogAllows(
  capabilities: MonitorCapabilityAdvertisement | null,
  session: MonitorSessionGrant | null,
  status: MonitorSessionStatus,
  nativeBridgeReady: boolean,
  contractRevision: string,
  catalogSha256: string,
): boolean {
  const publicOperations = session?.role === 'external' ?
    capabilities?.external_rpc_operations : capabilities?.available_rpc_operations;
  return Boolean(nativeBridgeReady && capabilities && session &&
    capabilities.contract_revision === contractRevision &&
    capabilities.catalog_sha256 === catalogSha256 &&
    capabilities.client_control_pq_e2ee === true &&
    capabilities.authenticated_client_session === true &&
    session.contract_revision === contractRevision &&
    session.catalog_sha256 === catalogSha256 &&
    (!status.ownerId || status.ownerId === session.owner_id) &&
    MONITOR_REQUIRED_ALLOWED_OPERATIONS.every(operation =>
      capabilities.available_rpc_operations?.includes(operation) ||
      capabilities.external_rpc_operations?.includes(operation)) &&
    MONITOR_REQUIRED_ALLOWED_OPERATIONS.every(operation => publicOperations?.includes(operation)) &&
    MONITOR_REQUIRED_ALLOWED_OPERATIONS.every(operation => session.available_rpc_operations?.includes(operation)) &&
    status.nativeAvailable === true && status.remoteEnabled === true &&
    status.sessionCapabilitiesReady === true && status.authFenced !== true &&
    !status.pendingOperationId &&
    MONITOR_REQUIRED_ALLOWED_OPERATIONS.every(operation => status.allowedOperations?.includes(operation)));
}

export interface MonitorConsentEndpoint {
  endpointId: string;
  principalId: string;
  ownerId: string;
  nodeId: string;
  membershipRevision: number;
  groupJoinRevision: number;
  bindingId: string;
  bindingEpoch: number;
  keyId: string;
  keyVersion: number;
  keyFingerprint: string;
  keyProofDigest: string;
}

export interface MonitorBroadcastPreview {
  operationId: string;
  previewId: string;
  broadcastId: string;
  status: 'PREPARED' | 'APPROVED' | 'DISPATCH_AUTHORIZED' | string;
  groupId: string;
  monitorEndpointId: string;
  bodySha256: string;
  snapshotDigest: string;
  /** Hub preview expiry as returned by the verified native bridge. */
  expiresAt: string;
  /** Signed Group authorization cutoff, which may precede the preview expiry. */
  grantExpiresAt: string;
  /** Exclusive confirmation deadline: the earlier of preview and Group grant expiry. */
  validUntil: string;
  monitorKeyId: string;
  monitorBindingId: string;
  monitorBindingEpoch: number;
  consentDigest: string;
  groupRevision: number;
  source: MonitorConsentEndpoint;
  recipients: MonitorConsentEndpoint[];
  canConfirm?: boolean;
}

export interface MonitorBroadcastOperation {
  operationId: string;
  groupId: string;
  monitorEndpointId: string;
  bodySha256: string;
  state: string;
  previewId?: string;
  snapshotDigest?: string;
  consentDigest?: string;
  expiresAt?: string;
  grantExpiresAt?: string;
  validUntil?: string;
  confirmAttempted: boolean;
  confirmStatusReconciled: boolean;
  confirmOperationId?: string;
}

export interface MonitorRecipientOutcome {
  ordinal: number;
  endpointId: string;
  state: 'PENDING' | 'FAILED' | 'UNKNOWN' | 'ACCEPTED' | string;
  evidence?: 'NODE_REPORTED' | 'RELAY_PERSISTED' | string;
  messageId?: string;
  failureCode?: string;
  reportedAt?: string;
}

export interface MonitorBroadcastStatus {
  previewId: string;
  broadcastId: string;
  groupId: string;
  approvalStatus: 'PREPARED' | 'APPROVED' | 'DISPATCH_AUTHORIZED' | string;
  expiresAt: string;
  recipients: MonitorRecipientOutcome[];
}

export interface MonitorBroadcastConfirmResult {
  previewId: string;
  broadcastId: string;
  status: 'APPROVED' | 'DISPATCH_AUTHORIZED' | string;
  groupId: string;
  monitorEndpointId: string;
  bodySha256: string;
  snapshotDigest: string;
  expiresAt: string;
  approvedAt?: string;
  dispatchAuthorizedAt?: string;
  sealedPayloadDigest?: string;
}

/** A native Monitor result failed its fixed v1.3 bridge contract. */
export class MonitorBroadcastNativeResultError extends Error {
  readonly code?: string;
  readonly operationId?: string;
  readonly previewId?: string;

  constructor(message: string, code?: string, operationId?: string, previewId?: string) {
    super(message);
    this.name = 'MonitorBroadcastNativeResultError';
    this.code = code;
    this.operationId = operationId;
    this.previewId = previewId;
  }
}

const nativeObject = (value: unknown): MonitorJsonObject | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ?
    value as MonitorJsonObject : null;

const hasOwn = (object: MonitorJsonObject, key: string) =>
  Object.prototype.hasOwnProperty.call(object, key);

function invalidNativeMonitorResult(): never {
  throw new MonitorBroadcastNativeResultError(
    'Android 安全桥返回了不符合 Client Hub v1.3 的 Monitor 结果。',
    'INVALID_MONITOR_NATIVE_RESULT',
  );
}

function nativeString(object: MonitorJsonObject, key: string): string {
  const value = object[key];
  if (typeof value !== 'string' || value.length === 0) invalidNativeMonitorResult();
  return value;
}

function optionalNativeString(object: MonitorJsonObject, key: string): string | undefined {
  if (!hasOwn(object, key)) return undefined;
  return nativeString(object, key);
}

function throwNativeMonitorRejection(
  raw: MonitorJsonObject,
  expectedPreviewId: string,
  confirm: boolean,
): never {
  const operationId = typeof raw.operationId === 'string' ? raw.operationId : undefined;
  const previewId = typeof raw.previewId === 'string' ? raw.previewId : undefined;
  const code = typeof raw.errorCode === 'string' && raw.errorCode.length > 0 ?
    raw.errorCode : undefined;

  if (code === 'OUTCOME_UNCERTAIN') {
    if (confirm && (raw.outcomeUncertain !== true || raw.statusRequired !== true ||
        previewId !== expectedPreviewId || !operationId)) invalidNativeMonitorResult();
    if (!confirm && raw.ok !== false) invalidNativeMonitorResult();
    throw new MonitorBroadcastNativeResultError(
      'Monitor 操作结果待核实；只能读取同一预览的状态。',
      code,
      operationId,
      previewId || expectedPreviewId,
    );
  }

  if (raw.ok !== false) invalidNativeMonitorResult();
  if (confirm && previewId !== expectedPreviewId) invalidNativeMonitorResult();
  const message = nativeString(raw, 'error');
  throw new MonitorBroadcastNativeResultError(message, code, operationId, previewId);
}

function monitorConsentEndpointFromNative(value: unknown): MonitorConsentEndpoint {
  const endpoint = nativeObject(value);
  if (!endpoint) return invalidNativeMonitorResult();
  const positiveInteger = (key: string) => {
    const number = endpoint[key];
    if (!Number.isSafeInteger(number) || (number as number) < 1) invalidNativeMonitorResult();
    return number as number;
  };
  return {
    endpointId: nativeString(endpoint, 'endpointId'),
    principalId: nativeString(endpoint, 'principalId'),
    ownerId: nativeString(endpoint, 'ownerId'),
    nodeId: nativeString(endpoint, 'nodeId'),
    membershipRevision: positiveInteger('membershipRevision'),
    groupJoinRevision: positiveInteger('groupJoinRevision'),
    bindingId: nativeString(endpoint, 'bindingId'),
    bindingEpoch: positiveInteger('bindingEpoch'),
    keyId: nativeString(endpoint, 'keyId'),
    keyVersion: positiveInteger('keyVersion'),
    keyFingerprint: nativeString(endpoint, 'keyFingerprint'),
    keyProofDigest: nativeString(endpoint, 'keyProofDigest'),
  };
}

/** Accept only a flattened success view marked verified by the native verifier. */
export function monitorPreviewResultFromNative(
  value: unknown,
  expected: {operationId?: string; groupId?: string; monitorEndpointId?: string} = {},
): MonitorBroadcastPreview {
  const raw = nativeObject(value);
  if (!raw) return invalidNativeMonitorResult();
  const nativeOperationId = typeof raw.monitorOperationId === 'string' ?
    raw.monitorOperationId : typeof raw.operationId === 'string' ? raw.operationId : undefined;
  const code = typeof raw.errorCode === 'string' && raw.errorCode.length > 0 ?
    raw.errorCode : undefined;
  if (code === 'OUTCOME_UNCERTAIN') {
    const prepareUncertain = raw.outcomeUncertain === true && raw.recoveryRequired === true &&
      typeof raw.operationId === 'string' && raw.operationId.length > 0;
    const recoveryUncertain = raw.ok === false && raw.recoveryUnresolved === true &&
      typeof raw.monitorOperationId === 'string' && raw.monitorOperationId.length > 0;
    if ((!prepareUncertain && !recoveryUncertain) ||
        (expected.operationId && nativeOperationId !== expected.operationId)) {
      return invalidNativeMonitorResult();
    }
    throw new MonitorBroadcastNativeResultError(
      'Monitor Prepare 结果待核实；只能使用原 operation ID 做只读恢复。',
      code,
      nativeOperationId,
    );
  }
  if (raw.ok === false) {
    const message = nativeString(raw, 'error');
    if (expected.operationId && nativeOperationId && nativeOperationId !== expected.operationId) {
      return invalidNativeMonitorResult();
    }
    throw new MonitorBroadcastNativeResultError(message, code, nativeOperationId);
  }
  if (raw.recoveryResolved === true && raw.canConfirm === false && raw.state === 'REJECTED') {
    if (!nativeOperationId || (expected.operationId && nativeOperationId !== expected.operationId)) {
      return invalidNativeMonitorResult();
    }
    throw new MonitorBroadcastNativeResultError(
      '原 Prepare 已被 Hub 拒绝；该 operation 不包含可审核预览。',
      'MONITOR_PREPARE_REJECTED',
      nativeOperationId,
    );
  }
  if (raw.recoveryResolved === true && raw.statusAvailable === true &&
      raw.canConfirm === false && raw.status === 'PREPARED') {
    if (!nativeOperationId || (expected.operationId && nativeOperationId !== expected.operationId)) {
      return invalidNativeMonitorResult();
    }
    const previewId = nativeString(raw, 'previewId');
    nativeString(raw, 'broadcastId');
    nativeString(raw, 'expiresAt');
    throw new MonitorBroadcastNativeResultError(
      '原 Prepare 预览已过期；只能查询此预览状态。',
      'MONITOR_PREVIEW_NOT_CONFIRMABLE',
      nativeOperationId,
      previewId,
    );
  }
  if (raw.verified !== true || (raw.canConfirm !== true && raw.canConfirm !== false)) {
    return invalidNativeMonitorResult();
  }

  const operationId = nativeString(raw, 'operationId');
  const groupId = nativeString(raw, 'groupId');
  const monitorEndpointId = nativeString(raw, 'monitorEndpointId');
  const status = nativeString(raw, 'status');
  const recipientsValue = raw.recipients;
  if ((expected.operationId && operationId !== expected.operationId) ||
      (expected.groupId && groupId !== expected.groupId) ||
      (expected.monitorEndpointId && monitorEndpointId !== expected.monitorEndpointId) ||
      !['PREPARED', 'APPROVED', 'DISPATCH_AUTHORIZED'].includes(status) ||
      !Array.isArray(recipientsValue) || recipientsValue.length > MONITOR_BROADCAST_MAX_RECIPIENTS ||
      (raw.canConfirm === true && status !== 'PREPARED')) {
    return invalidNativeMonitorResult();
  }
  const source = monitorConsentEndpointFromNative(raw.source);
  const recipients = recipientsValue.map(monitorConsentEndpointFromNative);
  const recipientIds = new Set(recipients.map(endpoint => endpoint.endpointId));
  if (recipientIds.size !== recipients.length) return invalidNativeMonitorResult();

  return {
    operationId,
    previewId: nativeString(raw, 'previewId'),
    broadcastId: nativeString(raw, 'broadcastId'),
    status,
    groupId,
    monitorEndpointId,
    bodySha256: nativeString(raw, 'bodySha256'),
    snapshotDigest: nativeString(raw, 'snapshotDigest'),
    expiresAt: nativeString(raw, 'expiresAt'),
    grantExpiresAt: nativeString(raw, 'grantExpiresAt'),
    validUntil: nativeString(raw, 'validUntil'),
    monitorKeyId: nativeString(raw, 'monitorKeyId'),
    monitorBindingId: nativeString(raw, 'monitorBindingId'),
    monitorBindingEpoch: (() => {
      const number = raw.monitorBindingEpoch;
      if (!Number.isSafeInteger(number) || (number as number) < 1) invalidNativeMonitorResult();
      return number as number;
    })(),
    consentDigest: nativeString(raw, 'consentDigest'),
    groupRevision: (() => {
      const number = raw.groupRevision;
      if (!Number.isSafeInteger(number) || (number as number) < 1) invalidNativeMonitorResult();
      return number as number;
    })(),
    source,
    recipients,
    canConfirm: raw.canConfirm,
  };
}

/** Adapt the Android bridge's verified RPC envelope to the UI's camelCase DTO. */
export function monitorConfirmResultFromNative(
  value: unknown,
  expectedPreviewId: string,
): MonitorBroadcastConfirmResult {
  const raw = nativeObject(value);
  if (!raw) return invalidNativeMonitorResult();
  if (raw.errorCode === 'OUTCOME_UNCERTAIN' || raw.ok === false) {
    return throwNativeMonitorRejection(raw, expectedPreviewId, true);
  }
  if (raw.ok !== true || raw.confirmed !== true || raw.previewId !== expectedPreviewId) {
    return invalidNativeMonitorResult();
  }
  nativeString(raw, 'requestId');
  nativeString(raw, 'operationId');
  const result = nativeObject(raw.result);
  if (!result) return invalidNativeMonitorResult();

  const previewId = nativeString(result, 'preview_id');
  const status = nativeString(result, 'status');
  if (previewId !== expectedPreviewId || raw.previewId !== previewId ||
      !['APPROVED', 'DISPATCH_AUTHORIZED'].includes(status)) {
    return invalidNativeMonitorResult();
  }

  return {
    previewId,
    broadcastId: nativeString(result, 'broadcast_id'),
    status,
    groupId: nativeString(result, 'group_id'),
    monitorEndpointId: nativeString(result, 'monitor_endpoint_id'),
    bodySha256: nativeString(result, 'body_sha256'),
    snapshotDigest: nativeString(result, 'snapshot_digest'),
    expiresAt: nativeString(result, 'expires_at'),
    approvedAt: optionalNativeString(result, 'approved_at'),
    dispatchAuthorizedAt: optionalNativeString(result, 'dispatch_authorized_at'),
    sealedPayloadDigest: optionalNativeString(result, 'sealed_payload_digest'),
  };
}

/** Adapt the Android bridge's raw status RPC envelope and bounded snake_case rows. */
export function monitorStatusResultFromNative(
  value: unknown,
  expectedPreviewId: string,
): MonitorBroadcastStatus {
  const raw = nativeObject(value);
  if (!raw) return invalidNativeMonitorResult();
  if (raw.errorCode === 'OUTCOME_UNCERTAIN' || raw.ok === false) {
    return throwNativeMonitorRejection(raw, expectedPreviewId, false);
  }
  if (raw.ok !== true) return invalidNativeMonitorResult();
  nativeString(raw, 'requestId');
  nativeString(raw, 'operationId');
  const result = nativeObject(raw.result);
  if (!result) return invalidNativeMonitorResult();

  const previewId = nativeString(result, 'preview_id');
  const approvalStatus = nativeString(result, 'approval_status');
  if (previewId !== expectedPreviewId ||
      !['PREPARED', 'APPROVED', 'DISPATCH_AUTHORIZED'].includes(approvalStatus) ||
      !Array.isArray(result.recipients) || result.recipients.length > MONITOR_BROADCAST_MAX_RECIPIENTS) {
    return invalidNativeMonitorResult();
  }

  const seenOrdinals = new Set<number>();
  const seenEndpoints = new Set<string>();
  const recipients = result.recipients.map(item => {
    const outcome = nativeObject(item);
    if (!outcome) return invalidNativeMonitorResult();
    const ordinal = outcome.ordinal;
    const endpointId = nativeString(outcome, 'endpoint_id');
    const state = nativeString(outcome, 'state');
    if (!Number.isSafeInteger(ordinal) || (ordinal as number) < 0 ||
        (ordinal as number) >= MONITOR_BROADCAST_MAX_RECIPIENTS ||
        seenOrdinals.has(ordinal as number) || seenEndpoints.has(endpointId) ||
        !['PENDING', 'FAILED', 'UNKNOWN', 'ACCEPTED'].includes(state)) {
      return invalidNativeMonitorResult();
    }
    seenOrdinals.add(ordinal as number);
    seenEndpoints.add(endpointId);
    const evidence = optionalNativeString(outcome, 'evidence');
    if (evidence !== undefined && (state !== 'ACCEPTED' ||
        !['NODE_REPORTED', 'RELAY_PERSISTED'].includes(evidence))) {
      return invalidNativeMonitorResult();
    }
    return {
      ordinal: ordinal as number,
      endpointId,
      state,
      evidence,
      messageId: optionalNativeString(outcome, 'message_id'),
      failureCode: optionalNativeString(outcome, 'failure_code'),
      reportedAt: optionalNativeString(outcome, 'reported_at'),
    };
  });

  return {
    previewId,
    broadcastId: nativeString(result, 'broadcast_id'),
    groupId: nativeString(result, 'group_id'),
    approvalStatus,
    expiresAt: nativeString(result, 'expires_at'),
    recipients,
  };
}

/** Exact UTF-8 byte count; null means malformed UTF-16 was found and must be rejected. */
export function monitorBodyUtf8ByteLength(value: string): number | null {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first <= 0x7f) {
      bytes += 1;
    } else if (first <= 0x7ff) {
      bytes += 2;
    } else if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(index + 1);
      if (second >= 0xdc00 && second <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        return null;
      }
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return null;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

export function inspectMonitorBody(value: string) {
  const byteLength = monitorBodyUtf8ByteLength(value);
  return {
    exactBody: value,
    byteLength,
    validUtf8: byteLength !== null,
    withinLimit: byteLength !== null && byteLength <= MONITOR_BROADCAST_BODY_MAX_BYTES,
  };
}

export function monitorPreviewIsExpired(expiresAt: string, now = Date.now()): boolean {
  const expiry = Date.parse(expiresAt);
  return !Number.isFinite(expiry) || expiry <= now;
}

/**
 * Validate the independently verified preview and Group grant cutoffs.
 * A fresh native preview must carry both and validUntil must be their minimum.
 */
export function monitorPreviewConfirmationCutoffMs(preview: Pick<
  MonitorBroadcastPreview, 'expiresAt' | 'grantExpiresAt' | 'validUntil'>,
): number | null {
  const previewExpiry = Date.parse(preview.expiresAt);
  const grantExpiry = Date.parse(preview.grantExpiresAt);
  const validUntil = Date.parse(preview.validUntil);
  if (!Number.isFinite(previewExpiry) || !Number.isFinite(grantExpiry) ||
      !Number.isFinite(validUntil) || validUntil !== Math.min(previewExpiry, grantExpiry)) {
    return null;
  }
  return validUntil;
}

export function monitorPreviewConfirmationExpiryReason(
  preview: Pick<MonitorBroadcastPreview, 'expiresAt' | 'grantExpiresAt' | 'validUntil'>,
  now = Date.now(),
): string | null {
  const validUntil = monitorPreviewConfirmationCutoffMs(preview);
  if (validUntil === null) {
    return '安全桥返回的预览或 Group 授权到期信息无效；已关闭确认。';
  }
  if (validUntil > now) return null;

  const previewExpiry = Date.parse(preview.expiresAt);
  const grantExpiry = Date.parse(preview.grantExpiresAt);
  if (grantExpiry <= now && grantExpiry <= previewExpiry) {
    return 'Group 授权已到期；此预览不能确认，请重新读取授权与拓扑。';
  }
  return '此 Monitor 预览已过期；只能读取状态，不能确认。';
}

/** Missing or malformed cutoff metadata fails closed for a fresh preview. */
export function monitorPreviewConfirmationIsExpired(
  preview: Pick<MonitorBroadcastPreview, 'expiresAt' | 'grantExpiresAt' | 'validUntil'>,
  now = Date.now(),
): boolean {
  const validUntil = monitorPreviewConfirmationCutoffMs(preview);
  return validUntil === null || validUntil <= now;
}

/** Older locally persisted operation indexes only had the preview expiresAt. */
export function monitorOperationValidUntil(operation: Pick<
  MonitorBroadcastOperation, 'expiresAt' | 'validUntil'>,
): string {
  return operation.validUntil || operation.expiresAt || '';
}

export function membershipHasMonitorRole(membership: MonitorJsonObject): boolean {
  const roles = Array.isArray(membership.roles) ? membership.roles : [];
  return String(membership.role || '').toLowerCase() === 'monitor' ||
    roles.some(role => typeof role === 'string' && role.toLowerCase() === 'monitor');
}

export function membershipAllowsBroadcast(membership: MonitorJsonObject): boolean {
  return membership.broadcast_permission_enabled === true;
}

export function membershipIsActive(membership: MonitorJsonObject): boolean {
  const state = String(membership.status || '').toUpperCase();
  return state === 'ACTIVE';
}

export function monitorRecipientOutcomeText(outcome: MonitorRecipientOutcome): string {
  if (outcome.state === 'PENDING') return '等待接收结果';
  if (outcome.state === 'FAILED') {
    return outcome.failureCode === 'DELIVERY_REJECTED' ? '投递被拒绝' : '投递失败';
  }
  if (outcome.state === 'UNKNOWN') return '结果待核实';
  if (outcome.state === 'ACCEPTED' && outcome.evidence === 'NODE_REPORTED') {
    return 'Node 已报告接收；这是持久化证据，不代表 Runtime 或模型已消费';
  }
  if (outcome.state === 'ACCEPTED' && outcome.evidence === 'RELAY_PERSISTED') {
    return 'Relay 已持久化；这是持久化证据，不代表 Runtime 或模型已消费';
  }
  if (outcome.state === 'ACCEPTED') return '已接受；消费状态未知';
  return outcome.state || '状态未知';
}

export function monitorApprovalStatusText(status: string): string {
  if (status === 'PREPARED') return '已准备，尚未批准';
  if (status === 'APPROVED') return '已批准，等待分发状态';
  if (status === 'DISPATCH_AUTHORIZED') return '已授权分发，接收结果仍待读取';
  return '状态待核实';
}

const stringField = (object: MonitorJsonObject, key: string) =>
  typeof object[key] === 'string' ? object[key] as string : '';

const positiveIntField = (object: MonitorJsonObject, key: string) =>
  Number.isSafeInteger(object[key]) && Number(object[key]) > 0 ? Number(object[key]) : 0;

const stringListField = (object: MonitorJsonObject, key: string) =>
  Array.isArray(object[key]) ? object[key].filter((item): item is string =>
    typeof item === 'string') : [];

/**
 * Reconcile a native-verified preview against the latest owner topology. The Hub
 * remains authoritative; this local check only prevents presenting known stale
 * consent for confirmation.
 */
export function monitorPreviewStaleReason(
  preview: MonitorBroadcastPreview,
  topology: {groups?: MonitorJsonObject[]; memberships?: MonitorJsonObject[];
    endpoints?: MonitorJsonObject[]} | null,
  ownerId: string,
): string | null {
  if (!ownerId || preview.source.ownerId !== ownerId ||
      preview.recipients.some(recipient => recipient.ownerId !== ownerId)) {
    return '预览包含与当前 Owner 不一致的身份；请丢弃并重新读取拓扑。';
  }
  if (preview.recipients.length > MONITOR_BROADCAST_MAX_RECIPIENTS) {
    return '预览成员超过协议上限；不能确认。';
  }
  if (!topology) return '尚未读取最新 Hub 拓扑；请先刷新后再确认。';

  const group = (topology.groups || []).find(item =>
    stringField(item, 'group_id') === preview.groupId);
  if (!group || positiveIntField(group, 'version') < 1) {
    return 'Group 不存在或当前版本无效；此预览已失效。';
  }
  if (stringField(group, 'state').toUpperCase() !== 'ACTIVE') {
    return 'Group 当前不是活跃状态；此预览已失效。';
  }

  const cards = [preview.source, ...preview.recipients];
  const seen = new Set<string>();
  for (const card of cards) {
    if (!card.endpointId || seen.has(card.endpointId)) {
      return '预览 Endpoint 身份重复或无效；不能确认。';
    }
    seen.add(card.endpointId);
    const membershipMatches = (topology.memberships || []).filter(item =>
      stringField(item, 'group_id') === preview.groupId &&
      stringField(item, 'principal_id') === card.principalId &&
      membershipIsActive(item));
    if (membershipMatches.length !== 1 ||
        positiveIntField(membershipMatches[0], 'version') < 1) {
      return '成员关系不存在、重复或当前版本无效；此预览已失效。';
    }
    const endpointMatches = (topology.endpoints || []).filter(item =>
      stringField(item, 'endpoint_id') === card.endpointId &&
      stringField(item, 'principal_id') === card.principalId);
    if (endpointMatches.length !== 1) {
      return 'Endpoint 身份缺失或重复；此预览已失效。';
    }
    const endpoint = endpointMatches[0];
    if (!stringListField(endpoint, 'group_ids').includes(preview.groupId) ||
        stringField(endpoint, 'node_id') !== card.nodeId ||
        stringField(endpoint, 'binding_id') !== card.bindingId ||
        positiveIntField(endpoint, 'binding_epoch') !== card.bindingEpoch ||
        stringField(endpoint, 'binding_status').toLowerCase() !== 'leased') {
      return 'Endpoint 绑定或 Group 成员关系已变化；此预览已失效。';
    }
  }

  const sourceMembership = (topology.memberships || []).find(item =>
    stringField(item, 'group_id') === preview.groupId &&
    stringField(item, 'principal_id') === preview.source.principalId &&
    membershipIsActive(item));
  if (!sourceMembership || !membershipHasMonitorRole(sourceMembership) ||
      !membershipAllowsBroadcast(sourceMembership)) {
    return 'Monitor 角色或独立 message.broadcast 权限已变化；此预览已失效。';
  }

  const currentGroupEndpointIds = (topology.endpoints || []).filter(item =>
    stringListField(item, 'group_ids').includes(preview.groupId)).map(item =>
    stringField(item, 'endpoint_id')).filter(Boolean).sort();
  const previewEndpointIds = cards.map(card => card.endpointId).sort();
  if (currentGroupEndpointIds.length && (currentGroupEndpointIds.length !== previewEndpointIds.length ||
      currentGroupEndpointIds.some((id, index) => id !== previewEndpointIds[index]))) {
    return 'Group 的 Endpoint roster 已变化；此预览已失效。';
  }
  return null;
}
