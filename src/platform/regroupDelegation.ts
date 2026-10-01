import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus, ClientRpcOperation, HubProfileScope,
} from './clientHub.ts';
import {
  NETWORK_CATALOG_SHA256, NETWORK_CONTRACT_REVISION, explicitActiveNetwork,
} from './networkTopology.ts';
import type {NetworkTopologyRecord, NetworkTopologySnapshot} from './networkTopology';

export const REGROUP_READ_OPERATIONS = ['topology.snapshot', 'topology.regroup_proposal'] as const;
export const REGROUP_ISSUE_OPERATION = 'topology.delegation_issue' as const;
export const REGROUP_REVOKE_OPERATION = 'topology.delegation_revoke' as const;
export const REGROUP_MAX_TTL_MS = 24 * 60 * 60 * 1000;

export type RegroupAction = 'SET_PARENT' | 'CREATE_CHILD';
export type RegroupDelegationState = 'ACTIVE' | 'REVOKED' | 'EXHAUSTED';

export interface RegroupProposalInput {
  operation_id: string;
  network_id: string;
  source_group_id: string;
  target_group_id: string;
  action: RegroupAction;
  new_group_name?: string;
  expected_source_version: number;
  expected_target_version: number;
}

export interface RegroupDelegation {
  delegation_id: string;
  proposal_id: string;
  hub_id: string;
  owner_id: string;
  network_id: string;
  source_group_id: string;
  target_group_id: string;
  action: RegroupAction;
  expected_source_version: number;
  expected_target_version: number;
  expires_at: string;
  max_uses: 1;
  use_count: 0 | 1;
  state: RegroupDelegationState;
  version: number;
  created_at: string;
}

export interface RegroupProposal {
  proposal_id: string;
  hub_id: string;
  owner_id: string;
  endpoint_id: string;
  principal_id: string;
  binding_id: string;
  binding_epoch: number;
  input: RegroupProposalInput;
  state: 'PROPOSED' | 'APPLIED';
  created_at: string;
  expires_at: string;
  delegation?: RegroupDelegation;
}

export interface RegroupProposalReview {
  readonly reviewId: string;
  readonly proposal: RegroupProposal;
  readonly sourceGroupCurrent: boolean;
  readonly targetGroupCurrent: boolean;
  readonly versionsCurrent: boolean;
  readonly sourceMembership: RegroupMembershipReference | null;
  readonly targetMembership: RegroupMembershipReference | null;
  readonly issueMembershipsCurrent: boolean;
  readonly issueMembershipReason?: string;
}

export interface RegroupMembershipReference {
  readonly membershipId: string;
  /** Positive ClientTopologyMember.version from topology.snapshot; not the DB revision. */
  readonly version: number;
}

export interface RegroupProposalTopologyStatus {
  readonly sourceGroupCurrent: boolean;
  readonly targetGroupCurrent: boolean;
  readonly versionsCurrent: boolean;
  readonly sourceMembership: RegroupMembershipReference | null;
  readonly targetMembership: RegroupMembershipReference | null;
  readonly issueMembershipsCurrent: boolean;
  readonly issueMembershipReason?: string;
}

export interface RegroupDelegationRpcResponse {
  ok: boolean;
  result?: unknown;
  error?: string;
  errorCode?: string;
  error_code?: string;
  [key: string]: unknown;
}

/** Local structural contract; the UI does not depend on the evolving central facade type. */
export interface RegroupDelegationApi {
  readonly scope: HubProfileScope;
  previewRegroupDelegation(input: {proposalId: string}): Promise<{reviewId: string; proposal: unknown}>;
  issueRegroupDelegation(input: {
    reviewId: string; expiresAt: string; confirmed: true;
  }): Promise<unknown>;
  revokeRegroupDelegation(input: {
    reviewId: string; delegationId: string; expectedVersion: number; confirmed: true;
  }): Promise<unknown>;
}

export interface RegroupDelegationAuthorityInput {
  status: ClientHubStatus & {regroupReconciliationRequired?: boolean};
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  topology: NetworkTopologySnapshot | null;
  apiScope: HubProfileScope;
}

export interface RegroupDelegationScope {
  readonly profileId: string;
  readonly selectionGeneration: number;
  readonly hubId: string;
  readonly ownerId: string;
  readonly deviceId: string;
  readonly sessionEpoch: number;
  readonly networkId: string;
  readonly networkName: string;
  readonly networkVersion: number;
  readonly topology: NetworkTopologySnapshot;
  readonly scopeKey: string;
}

export type RegroupDelegationAuthority = {
  ready: true;
  canRead: boolean;
  canIssue: boolean;
  canRevoke: boolean;
  writesFenced: boolean;
  reason?: string;
  scope: RegroupDelegationScope;
} | {
  ready: false;
  canRead: false;
  canIssue: false;
  canRevoke: false;
  writesFenced: true;
  reason: string;
};

const object = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = (value: unknown, maxLength = 256): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= maxLength && value === value.trim();
const safeInteger = (value: unknown, min: number): value is number =>
  Number.isSafeInteger(value) && Number(value) >= min;
const timestamp = (value: unknown): value is string => typeof value === 'string' && value.length <= 40 &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value) &&
  Number.isFinite(Date.parse(value));
const exactKeys = (value: NetworkTopologyRecord, required: readonly string[], optional: readonly string[] = []) => {
  const allowed = new Set([...required, ...optional]);
  return required.every(key => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every(key => allowed.has(key));
};
const operationArrayHas = (value: unknown, operation: string): boolean =>
  Array.isArray(value) && value.includes(operation);
const noReady = (reason: string): RegroupDelegationAuthority => ({
  ready: false, canRead: false, canIssue: false, canRevoke: false, writesFenced: true, reason,
});

function scopeKey(scope: Omit<RegroupDelegationScope, 'scopeKey' | 'topology'>): string {
  return JSON.stringify([
    scope.profileId, scope.selectionGeneration, scope.hubId, scope.ownerId,
    scope.deviceId, scope.sessionEpoch, scope.networkId, scope.networkVersion,
  ]);
}

/**
 * Requires a pinned, enrolled encrypted Owner session and exact current v1.6
 * operation grants. Read is allowed while business uncertainty is visible;
 * writes remain fenced until both general and regroup-specific reconciliation clear.
 */
export function regroupDelegationAuthority(input: RegroupDelegationAuthorityInput): RegroupDelegationAuthority {
  const {status, publicCapabilities, sessionCapabilities, topology, apiScope} = input;
  if (!identifier(status.profileId) || !safeInteger(status.selectionGeneration, 1) ||
      apiScope.profileId !== status.profileId || apiScope.selectionGeneration !== status.selectionGeneration) {
    return noReady('当前 Hub 配置代次与操作 API 不匹配；请在当前配置重新读取。');
  }
  if (!identifier(status.hubId) || !identifier(status.ownerId) || !identifier(status.deviceId) ||
      !safeInteger(status.sessionEpoch, 1)) {
    return noReady('Hub、Owner、Device 或会话 epoch 尚未由当前已登记会话确认。');
  }
  if (status.nativeAvailable !== true || status.pinned !== true || status.enrolled !== true ||
      status.remoteEnabled !== true || status.sessionCapabilitiesReady !== true || status.authFenced === true ||
      status.recoveryBlocked === true || status.enrollmentRecoveryRequired === true || status.pendingOperationId) {
    return noReady('需要当前固定并登记的 Client-Control 加密会话，且不能有待恢复原请求。');
  }
  if (!publicCapabilities || publicCapabilities.contract_revision !== NETWORK_CONTRACT_REVISION ||
      publicCapabilities.catalog_sha256 !== NETWORK_CATALOG_SHA256 ||
      publicCapabilities.client_control_pq_e2ee !== true ||
      publicCapabilities.authenticated_client_session !== true || !sessionCapabilities ||
      sessionCapabilities.contract_revision !== NETWORK_CONTRACT_REVISION ||
      sessionCapabilities.catalog_sha256 !== NETWORK_CATALOG_SHA256 ||
      sessionCapabilities.owner_id !== status.ownerId ||
      !['manager', 'external'].includes(sessionCapabilities.role)) {
    return noReady('Hub 与加密 session.capabilities 未确认同一 v1.6 Owner 和目录。');
  }
  if (!topology || topology.contract_version !== 2 || topology.owner_principal_id !== status.ownerId ||
      !identifier(topology.captured_at) || !Array.isArray(topology.groups)) {
    return noReady('尚无当前 Owner 的真实 topology.snapshot；不从本地 fixture 推断重组范围。');
  }
  const network = explicitActiveNetwork(topology, status.activeNetworkId);
  if (!network || !safeInteger(network.version, 1)) {
    return noReady('请先在当前 Hub 配置中选择由权威拓扑确认的 ACTIVE Network。');
  }
  const publicOperations = sessionCapabilities.role === 'external' ?
    publicCapabilities.external_rpc_operations : publicCapabilities.available_rpc_operations;
  const granted = (operation: ClientRpcOperation) => operationArrayHas(publicOperations, operation) &&
    operationArrayHas(sessionCapabilities.available_rpc_operations, operation) &&
    status.allowedOperations.includes(operation);
  const canRead = REGROUP_READ_OPERATIONS.every(granted);
  if (!canRead) return noReady('当前公开角色目录或加密 session.capabilities 未授权 topology.snapshot 与 regroup proposal 读取。');

  const scopeWithoutKey = {
    profileId: status.profileId,
    selectionGeneration: status.selectionGeneration,
    hubId: status.hubId,
    ownerId: status.ownerId,
    deviceId: status.deviceId,
    sessionEpoch: status.sessionEpoch,
    networkId: network.network_id,
    networkName: network.name,
    networkVersion: network.version,
    topology,
  };
  const scope = Object.freeze({...scopeWithoutKey, scopeKey: scopeKey(scopeWithoutKey)});
  const writesFenced = status.uncertainNeedsReconciliation === true ||
    status.regroupReconciliationRequired === true;
  return {
    ready: true,
    canRead: true,
    canIssue: !writesFenced && granted(REGROUP_ISSUE_OPERATION),
    canRevoke: !writesFenced && granted(REGROUP_REVOKE_OPERATION),
    writesFenced,
    ...(writesFenced ? {reason: status.regroupReconciliationRequired ?
      '原 regroup 请求仍需专门对账；读取提案可检查 delegation，但不会解除写入锁。' :
      '存在未解决的加密写入结果；先读取权威状态完成恢复。'} : {}),
    scope,
  };
}

function parseInput(value: unknown): RegroupProposalInput | null {
  if (!object(value) || !exactKeys(value,
    ['operation_id', 'network_id', 'source_group_id', 'target_group_id', 'action',
      'expected_source_version', 'expected_target_version'], ['new_group_name'])) return null;
  if (![value.operation_id, value.network_id, value.source_group_id, value.target_group_id]
    .every(item => identifier(item)) ||
      (value.action !== 'SET_PARENT' && value.action !== 'CREATE_CHILD') ||
      !safeInteger(value.expected_source_version, 1) || !safeInteger(value.expected_target_version, 1)) return null;
  if (value.action === 'SET_PARENT') {
    if (value.source_group_id === value.target_group_id || value.new_group_name !== undefined) return null;
  } else if (!identifier(value.new_group_name, 80) || value.new_group_name.trim().length === 0) return null;
  const operationId = value.operation_id as string;
  const networkId = value.network_id as string;
  const sourceGroupId = value.source_group_id as string;
  const targetGroupId = value.target_group_id as string;
  const action = value.action as RegroupAction;
  return {
    operation_id: operationId,
    network_id: networkId,
    source_group_id: sourceGroupId,
    target_group_id: targetGroupId,
    action,
    ...(typeof value.new_group_name === 'string' ? {new_group_name: value.new_group_name} : {}),
    expected_source_version: value.expected_source_version as number,
    expected_target_version: value.expected_target_version as number,
  };
}

function parseDelegation(value: unknown, proposal: Omit<RegroupProposal, 'delegation'>): RegroupDelegation | null {
  if (!object(value) || !exactKeys(value,
    ['delegation_id', 'proposal_id', 'hub_id', 'owner_id', 'network_id', 'source_group_id',
      'target_group_id', 'action', 'expected_source_version', 'expected_target_version',
      'expires_at', 'max_uses', 'use_count', 'state', 'version', 'created_at'])) return null;
  if (![value.delegation_id, value.proposal_id, value.hub_id, value.owner_id, value.network_id,
    value.source_group_id, value.target_group_id].every(item => identifier(item)) ||
      !['SET_PARENT', 'CREATE_CHILD'].includes(String(value.action)) ||
      !safeInteger(value.expected_source_version, 1) || !safeInteger(value.expected_target_version, 1) ||
      !timestamp(value.expires_at) || value.max_uses !== 1 || ![0, 1].includes(Number(value.use_count)) ||
      !['ACTIVE', 'REVOKED', 'EXHAUSTED'].includes(String(value.state)) ||
      !safeInteger(value.version, 1) || !timestamp(value.created_at)) return null;
  const input = proposal.input;
  if (value.proposal_id !== proposal.proposal_id || value.hub_id !== proposal.hub_id ||
      value.owner_id !== proposal.owner_id || value.network_id !== input.network_id ||
      value.source_group_id !== input.source_group_id || value.target_group_id !== input.target_group_id ||
      value.action !== input.action || value.expected_source_version !== input.expected_source_version ||
      value.expected_target_version !== input.expected_target_version ||
      Date.parse(value.expires_at) > Date.parse(proposal.expires_at)) return null;
  return value as unknown as RegroupDelegation;
}

function groupVersion(topology: NetworkTopologySnapshot, networkId: string,
  groupId: string): number | null {
  if (!Array.isArray(topology.groups)) return null;
  const matches = topology.groups.filter(group => object(group) && group.group_id === groupId &&
    group.network_id === networkId);
  if (matches.length !== 1 || matches[0].state !== 'ACTIVE' || !safeInteger(matches[0].version, 1)) return null;
  return matches[0].version as number;
}

const TOPOLOGY_ENDPOINT_FIELDS = [
  'endpoint_id', 'name', 'principal_id', 'group_ids', 'network_ids', 'presence',
] as const;
const TOPOLOGY_ENDPOINT_OPTIONAL_FIELDS = [
  'node_id', 'harness', 'native_session_id', 'binding_id', 'binding_epoch', 'binding_status',
] as const;
const TOPOLOGY_MEMBERSHIP_FIELDS = [
  'membership_id', 'principal_id', 'group_id', 'role', 'broadcast_permission_enabled', 'status', 'version',
] as const;
const TOPOLOGY_MEMBERSHIP_OPTIONAL_FIELDS = ['display_name', 'roles'] as const;

function topologyMembership(
  topology: NetworkTopologySnapshot,
  groupId: string,
  principalId: string,
): {membership: RegroupMembershipReference | null; record: NetworkTopologyRecord | null; reason?: string} {
  if (!Array.isArray(topology.memberships)) {
    return {membership: null, record: null, reason: '当前 topology.snapshot 没有可核对的 Group Membership 列表。'};
  }
  const matches = topology.memberships.filter(item => object(item) &&
    item.group_id === groupId && item.principal_id === principalId);
  if (matches.length !== 1) {
    return {membership: null, record: null, reason: matches.length === 0 ?
      `当前 topology.snapshot 未找到 Group ${groupId} 的显式 Principal Membership。` :
      `当前 topology.snapshot 对 Group ${groupId} 返回重复 Principal Membership；签发关闭。`};
  }
  const candidate = matches[0];
  if (!exactKeys(candidate, TOPOLOGY_MEMBERSHIP_FIELDS, TOPOLOGY_MEMBERSHIP_OPTIONAL_FIELDS) ||
      !identifier(candidate.membership_id) || !identifier(candidate.principal_id) ||
      !identifier(candidate.group_id) || typeof candidate.role !== 'string' ||
      (candidate.display_name !== undefined && typeof candidate.display_name !== 'string') ||
      (candidate.roles !== undefined && (!Array.isArray(candidate.roles) ||
        !candidate.roles.every(role => typeof role === 'string'))) ||
      typeof candidate.broadcast_permission_enabled !== 'boolean') {
    return {membership: null, record: null,
      reason: `Group ${groupId} 的 Membership 不符合 pinned ClientTopologyMember DTO；签发关闭。`};
  }
  if (candidate.status !== 'active' || !safeInteger(candidate.version, 1)) {
    return {membership: null, record: null,
      reason: `Group ${groupId} 的 Membership 当前不是 ACTIVE 或没有正数 DTO version；签发关闭。`};
  }
  return {
    membership: Object.freeze({membershipId: candidate.membership_id, version: candidate.version as number}),
    record: candidate,
  };
}

/** Re-evaluate proposal Groups and explicit Endpoint Memberships against a supplied current snapshot. */
export function regroupProposalTopologyStatus(
  proposal: RegroupProposal,
  topology: NetworkTopologySnapshot,
): RegroupProposalTopologyStatus {
  const {input} = proposal;
  const sourceVersion = groupVersion(topology, input.network_id, input.source_group_id);
  const targetVersion = groupVersion(topology, input.network_id, input.target_group_id);
  const sourceGroupCurrent = sourceVersion !== null;
  const targetGroupCurrent = targetVersion !== null;
  const versionsCurrent = sourceVersion === input.expected_source_version &&
    targetVersion === input.expected_target_version;
  const base = {
    sourceGroupCurrent,
    targetGroupCurrent,
    versionsCurrent,
    sourceMembership: null as RegroupMembershipReference | null,
    targetMembership: null as RegroupMembershipReference | null,
    issueMembershipsCurrent: false,
  };

  if (!Array.isArray(topology.endpoints)) {
    return Object.freeze({...base,
      issueMembershipReason: '当前 topology.snapshot 没有可核对的 Monitor Endpoint 列表。'});
  }
  const endpoints = topology.endpoints.filter(item => object(item) && item.endpoint_id === proposal.endpoint_id);
  if (endpoints.length !== 1) {
    return Object.freeze({...base,
      issueMembershipReason: endpoints.length === 0 ?
        '当前 topology.snapshot 未找到提案中的唯一 Monitor Endpoint；签发关闭。' :
        '当前 topology.snapshot 对提案 Endpoint 返回重复记录；签发关闭。'});
  }
  const endpoint = endpoints[0];
  if (!exactKeys(endpoint, TOPOLOGY_ENDPOINT_FIELDS, TOPOLOGY_ENDPOINT_OPTIONAL_FIELDS) ||
      endpoint.principal_id !== proposal.principal_id || !identifier(endpoint.endpoint_id) ||
      !identifier(endpoint.principal_id) || typeof endpoint.name !== 'string' ||
      typeof endpoint.presence !== 'string' || !Array.isArray(endpoint.group_ids) ||
      !endpoint.group_ids.every(id => typeof id === 'string') || !Array.isArray(endpoint.network_ids) ||
      !endpoint.network_ids.every(id => typeof id === 'string') ||
      (endpoint.node_id !== undefined && typeof endpoint.node_id !== 'string') ||
      (endpoint.harness !== undefined && typeof endpoint.harness !== 'string') ||
      (endpoint.native_session_id !== undefined && typeof endpoint.native_session_id !== 'string') ||
      (endpoint.binding_id !== undefined && typeof endpoint.binding_id !== 'string') ||
      (endpoint.binding_epoch !== undefined && !safeInteger(endpoint.binding_epoch, 1)) ||
      (endpoint.binding_status !== undefined && typeof endpoint.binding_status !== 'string')) {
    return Object.freeze({...base,
      issueMembershipReason: '当前 topology.snapshot 中 Endpoint 与 proposal Principal 不匹配或 DTO 无效；签发关闭。'});
  }

  const groupIds = [...new Set([input.source_group_id, input.target_group_id])];
  const endpointGroupIds = endpoint.group_ids;
  if (groupIds.some(groupId => !endpointGroupIds.includes(groupId))) {
    return Object.freeze({...base,
      issueMembershipReason: '提案 Monitor Endpoint 未关联到 source 与 target Group；签发关闭。'});
  }

  const source = topologyMembership(topology, input.source_group_id, proposal.principal_id);
  const target = input.target_group_id === input.source_group_id ? source :
    topologyMembership(topology, input.target_group_id, proposal.principal_id);
  const sourceRoles = source.record && Array.isArray(source.record.roles) ? source.record.roles : [];
  const sourceIsMonitor = source.record !== null &&
    (source.record.role === 'monitor' || sourceRoles.includes('monitor'));
  const issueMembershipsCurrent = source.membership !== null && target.membership !== null && sourceIsMonitor;
  const issueMembershipReason = issueMembershipsCurrent ? undefined :
    source.reason || target.reason || (!sourceIsMonitor ?
      'source Group 的当前 Principal Membership 未授予 monitor role；签发关闭。' :
      'source 与 target 必须都有当前显式 ACTIVE Endpoint Principal Membership；签发关闭。');
  return Object.freeze({
    ...base,
    sourceMembership: source.membership,
    targetMembership: target.membership,
    issueMembershipsCurrent,
    ...(issueMembershipReason ? {issueMembershipReason} : {}),
  });
}

/** Validates the exact Owner-scoped response and compares its CAS versions to current topology. */
export function regroupProposalFromRpc(
  value: unknown,
  reviewId: string,
  scope: RegroupDelegationScope,
  expectedProposalId: string,
): RegroupProposalReview | null {
  const required = ['proposal_id', 'hub_id', 'owner_id', 'endpoint_id', 'principal_id', 'binding_id',
    'binding_epoch', 'input', 'state', 'created_at', 'expires_at'];
  if (!identifier(reviewId) || !identifier(expectedProposalId) || !object(value) ||
      !exactKeys(value, required, ['delegation']) || value.proposal_id !== expectedProposalId) return null;
  const input = parseInput(value.input);
  if (!input || ![value.proposal_id, value.hub_id, value.owner_id, value.endpoint_id,
    value.principal_id, value.binding_id].every(item => identifier(item)) ||
      value.hub_id !== scope.hubId || value.owner_id !== scope.ownerId ||
      value.principal_id === value.owner_id || !safeInteger(value.binding_epoch, 1) ||
      !['PROPOSED', 'APPLIED'].includes(String(value.state)) ||
      !timestamp(value.created_at) || !timestamp(value.expires_at) ||
      Date.parse(value.expires_at) <= Date.parse(value.created_at) ||
      Date.parse(value.expires_at) - Date.parse(value.created_at) > REGROUP_MAX_TTL_MS ||
      input.network_id !== scope.networkId) return null;
  const base = {
    proposal_id: value.proposal_id as string,
    hub_id: value.hub_id as string,
    owner_id: value.owner_id as string,
    endpoint_id: value.endpoint_id as string,
    principal_id: value.principal_id as string,
    binding_id: value.binding_id as string,
    binding_epoch: value.binding_epoch as number,
    input,
    state: value.state as RegroupProposal['state'],
    created_at: value.created_at,
    expires_at: value.expires_at,
  };
  const delegation = value.delegation === undefined ? undefined : parseDelegation(value.delegation, base);
  if (value.delegation !== undefined && !delegation) return null;
  const topologyStatus = regroupProposalTopologyStatus(base, scope.topology);
  return Object.freeze({
    reviewId,
    proposal: Object.freeze({...base, ...(delegation ? {delegation} : {})}),
    ...topologyStatus,
  });
}

export function regroupDelegationExpiryAllowed(
  expiresAt: string,
  proposalExpiresAt: string,
  now = Date.now(),
): boolean {
  if (!timestamp(expiresAt) || !timestamp(proposalExpiresAt) || !Number.isFinite(now)) return false;
  const expires = Date.parse(expiresAt);
  return expires > now && expires <= Date.parse(proposalExpiresAt) && expires <= now + REGROUP_MAX_TTL_MS;
}

export function suggestedRegroupDelegationExpiry(proposalExpiresAt: string, now = Date.now()): string {
  if (!timestamp(proposalExpiresAt) || !Number.isFinite(now)) return '';
  const suggested = Math.min(now + 60 * 60 * 1000, Date.parse(proposalExpiresAt), now + REGROUP_MAX_TTL_MS);
  return suggested > now ? new Date(suggested).toISOString() : '';
}

export interface RegroupDelegationCallback {
  readonly scopeKey: string;
  readonly generation: number;
}

export function captureRegroupDelegationCallback(scope: RegroupDelegationScope,
  generation: number): RegroupDelegationCallback {
  return Object.freeze({scopeKey: scope.scopeKey, generation});
}

export function regroupDelegationCallbackIsCurrent(
  callback: RegroupDelegationCallback,
  currentScope: RegroupDelegationScope | null,
  currentGeneration: number,
  foreground: boolean,
): boolean {
  return foreground && Boolean(currentScope) && callback.scopeKey === currentScope?.scopeKey &&
    callback.generation === currentGeneration;
}

export function regroupDelegationActionLabel(proposal: RegroupProposal): string {
  return proposal.input.action === 'SET_PARENT' ? '将源 Group 设置到目标 Group 下' :
    `在目标 Group 下创建子 Group「${proposal.input.new_group_name}」`;
}

export function regroupDelegationFailureMessage(error: unknown): string {
  const code = object(error) ? String(error.errorCode || error.error_code || error.code || '') : '';
  switch (code) {
    case 'STILL_PROCESSING': return 'Hub 仍在处理原始加密请求；保留原密文与计数，先完成精确恢复。';
    case 'OUTCOME_UNCERTAIN': return '原请求结果不确定。请保留待恢复请求；重新读取同一提案只能检查 delegation，不能解除对账锁。';
    case 'RECOVERY_UNAVAILABLE': return 'Hub 无法恢复原请求；不要重发新写入。请保留本机待恢复状态并进行专门权威对账。';
    case 'PENDING_RECOVERY_REQUIRED': return '请先恢复原始加密请求；当前不会创建新的 issue 或 revoke 请求。';
    case 'REGROUP_RECONCILIATION_REQUIRED': return '原 regroup 写入仍待专门对账；提案读取只显示当前状态，不会解除写入锁。';
    case 'HUB_PROFILE_SCOPE_CHANGED': return 'Hub 配置、选择代次或 Network 已改变；请在当前会话重新读取。';
    case 'REGROUP_VERSION_CONFLICT': return '提案中的 Group 版本已过期；请重新读取当前权威拓扑与提案。';
    default: return '未取得可验证的 Hub 结果；待恢复密文与序号保持原样。';
  }
}

export function regroupGroupRecord(topology: NetworkTopologySnapshot, networkId: string,
  groupId: string): NetworkTopologyRecord | null {
  const matches = topology.groups.filter(group => object(group) && group.group_id === groupId &&
    group.network_id === networkId && group.state === 'ACTIVE');
  return matches.length === 1 ? matches[0] : null;
}
