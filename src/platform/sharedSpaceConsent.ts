import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
} from './clientHub';
import {
  DEFERRED_CLIENT_CONSENT_OPERATIONS, DEFERRED_V16_RPC_OPERATIONS,
} from './clientHubOperationPolicy.ts';
import {
  NETWORK_CATALOG_SHA256, NETWORK_CONTRACT_REVISION,
  endpointsInNetwork, explicitActiveNetwork, groupsInNetwork,
} from './networkTopology.ts';
import type {
  NetworkTopologyRecord, NetworkTopologySnapshot,
} from './networkTopology.ts';

/** Operations whose complete proof/current-authority or consent flow is not implemented. */
export const SHARED_SPACE_CLOSED_OPERATIONS = [
  ...DEFERRED_CLIENT_CONSENT_OPERATIONS,
  ...DEFERRED_V16_RPC_OPERATIONS,
] as const;

export type SharedSpaceClosedOperation = typeof SHARED_SPACE_CLOSED_OPERATIONS[number];

export interface SharedSpaceScope {
  readonly profileId: string;
  readonly selectionGeneration: number;
  readonly hubId: string;
  readonly ownerId: string;
  readonly deviceId: string;
  readonly sessionEpoch: number;
  readonly networkId: string;
  readonly networkName: string;
  readonly networkVersion: number;
  readonly groupId: string;
  readonly groupName: string;
  readonly groupVersion: number;
  readonly endpointId: string;
  readonly endpointName: string;
  readonly endpointOwnerId: string;
  readonly endpointBindingId: string;
  readonly endpointBindingEpoch: number | null;
  readonly topologyCapturedAt: string;
}

/** This model records only on-device review intent. It contains no proof or approval data. */
export interface SharedSpaceReviewDraft {
  readonly scope: SharedSpaceScope;
  readonly scopeKey: string;
  readonly intent: 'review-only';
  readonly reviewed: boolean;
}

export interface SharedSpaceScopeCallback {
  readonly scopeKey: string;
}

export interface SharedSpaceAuthorityInput {
  status: ClientHubStatus;
  capabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  topology: NetworkTopologySnapshot | null;
}

export type SharedSpaceAuthority = {
  ready: true;
  profileId: string;
  selectionGeneration: number;
  hubId: string;
  ownerId: string;
  deviceId: string;
  sessionEpoch: number;
  topology: NetworkTopologySnapshot;
  network: NonNullable<ReturnType<typeof explicitActiveNetwork>>;
} | {
  ready: false;
  reason: string;
};

const identifier = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value === value.trim();
const object = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const stringField = (value: NetworkTopologyRecord, key: string): string =>
  typeof value[key] === 'string' && identifier(value[key]) ? value[key] as string : '';
const positiveIntegerField = (value: NetworkTopologyRecord, key: string): number | null =>
  Number.isSafeInteger(value[key]) && Number(value[key]) > 0 ? Number(value[key]) : null;

/**
 * Shared-space review is available only when the current encrypted v1.6 session
 * authorized a real topology snapshot for this profile, Hub, Owner and ACTIVE Network.
 */
export function sharedSpaceAuthority(input: SharedSpaceAuthorityInput): SharedSpaceAuthority {
  const {status, capabilities, sessionCapabilities, topology} = input;
  if (!identifier(status.profileId) || !Number.isSafeInteger(status.selectionGeneration) ||
      Number(status.selectionGeneration) < 0) {
    return {ready: false, reason: '当前 Hub 配置与选择代次不可用。'};
  }
  if (!identifier(status.hubId) || !identifier(status.ownerId) || !identifier(status.deviceId) ||
      !Number.isSafeInteger(status.sessionEpoch) || Number(status.sessionEpoch) < 1) {
    return {ready: false, reason: '当前 Hub、Owner、Device 或会话 epoch 尚未由已固定并登记的会话确认。'};
  }
  if (status.nativeAvailable !== true || status.pinned !== true || status.enrolled !== true ||
      status.remoteEnabled !== true || status.sessionCapabilitiesReady !== true ||
      status.authFenced === true || status.recoveryBlocked === true ||
      status.enrollmentRecoveryRequired === true || status.pendingOperationId ||
      status.uncertainNeedsReconciliation === true) {
    return {ready: false, reason: '需要当前可用的已固定 Hub、OwnerDeviceGrant 与加密会话；待恢复、撤权或不确定状态会关闭范围预览。'};
  }
  if (!capabilities || capabilities.contract_revision !== NETWORK_CONTRACT_REVISION ||
      capabilities.catalog_sha256 !== NETWORK_CATALOG_SHA256 ||
      capabilities.client_control_pq_e2ee !== true ||
      capabilities.authenticated_client_session !== true ||
      capabilities.topology_management !== true || !sessionCapabilities ||
      sessionCapabilities.contract_revision !== NETWORK_CONTRACT_REVISION ||
      sessionCapabilities.catalog_sha256 !== NETWORK_CATALOG_SHA256 ||
      sessionCapabilities.owner_id !== status.ownerId ||
      !['manager', 'external'].includes(sessionCapabilities.role)) {
    return {ready: false, reason: 'Hub v1.6 固定目录或加密 session.capabilities 未确认当前 Owner 的拓扑读取权限。'};
  }
  const publicOperations = sessionCapabilities.role === 'external' ?
    capabilities.external_rpc_operations : capabilities.available_rpc_operations;
  if (!publicOperations?.includes('topology.snapshot') ||
      !sessionCapabilities.available_rpc_operations.includes('topology.snapshot') ||
      !status.allowedOperations.includes('topology.snapshot')) {
    return {ready: false, reason: '当前加密会话没有授权 topology.snapshot。'};
  }
  if (!topology || topology.contract_version !== 2 ||
      topology.owner_principal_id !== status.ownerId || !identifier(topology.captured_at)) {
    return {ready: false, reason: '尚无当前 Owner 的真实 topology.snapshot；不使用开发数据推测空间范围。'};
  }
  const network = explicitActiveNetwork(topology, status.activeNetworkId);
  if (!network) {
    return {ready: false, reason: '请在当前 Hub 配置中明确选择一个由真实 topology.snapshot 确认的 ACTIVE Network。'};
  }
  return {
    ready: true,
    profileId: status.profileId,
    selectionGeneration: Number(status.selectionGeneration),
    hubId: status.hubId,
    ownerId: status.ownerId,
    deviceId: status.deviceId,
    sessionEpoch: Number(status.sessionEpoch),
    topology,
    network,
  };
}

export function sharedSpaceGroups(authority: SharedSpaceAuthority): NetworkTopologyRecord[] {
  if (!authority.ready) return [];
  return groupsInNetwork(authority.topology, authority.network.network_id)
    .filter(group => group.state === 'ACTIVE');
}

export function sharedSpaceEndpoints(authority: SharedSpaceAuthority): NetworkTopologyRecord[] {
  if (!authority.ready) return [];
  return endpointsInNetwork(authority.topology, authority.network.network_id);
}

/** Return a review scope only for one exact current-Owner Group and a known foreign Endpoint Owner. */
export function deriveSharedSpaceScope(
  authority: SharedSpaceAuthority,
  groupId: string,
  endpointId: string,
): {scope: SharedSpaceScope; reason?: never} | {scope?: never; reason: string} {
  if (!authority.ready) return {reason: authority.reason};
  const matchingGroups = groupsInNetwork(authority.topology, authority.network.network_id)
    .filter(group => object(group) && group.group_id === groupId && group.state === 'ACTIVE');
  if (matchingGroups.length !== 1) {
    return {reason: '请从当前 ACTIVE Network 的唯一权威 Group 列表中选择 Group。'};
  }
  const group = matchingGroups[0];
  const groupVersion = positiveIntegerField(group, 'version');
  if (!groupVersion) return {reason: '当前 Group 没有可核对的正版本号。'};

  const matchingEndpoints = endpointsInNetwork(authority.topology, authority.network.network_id)
    .filter(endpoint => object(endpoint) && endpoint.endpoint_id === endpointId);
  if (matchingEndpoints.length !== 1) {
    return {reason: '请从当前 ACTIVE Network 的唯一权威 Endpoint 列表中选择 Endpoint。'};
  }
  const endpoint = matchingEndpoints[0];
  const endpointOwnerId = stringField(endpoint, 'owner_id');
  if (!endpointOwnerId) {
    return {reason: '拓扑没有提供所选 Endpoint 的精确 owner_id；不能推测或开始跨 Owner 流程。'};
  }
  if (endpointOwnerId === authority.ownerId) {
    return {reason: '所选 Endpoint 属于当前 Group Owner；它不是跨 Owner Shared Space 候选。'};
  }

  const endpointBindingEpoch = positiveIntegerField(endpoint, 'binding_epoch');
  const scope: SharedSpaceScope = Object.freeze({
    profileId: authority.profileId,
    selectionGeneration: authority.selectionGeneration,
    hubId: authority.hubId,
    ownerId: authority.ownerId,
    deviceId: authority.deviceId,
    sessionEpoch: authority.sessionEpoch,
    networkId: authority.network.network_id,
    networkName: authority.network.name,
    networkVersion: authority.network.version,
    groupId: String(group.group_id),
    groupName: stringField(group, 'name') || String(group.group_id),
    groupVersion,
    endpointId: String(endpoint.endpoint_id),
    endpointName: stringField(endpoint, 'name') || String(endpoint.endpoint_id),
    endpointOwnerId,
    endpointBindingId: stringField(endpoint, 'binding_id'),
    endpointBindingEpoch,
    topologyCapturedAt: authority.topology.captured_at,
  });
  return {scope};
}

export function sharedSpaceScopeKey(scope: SharedSpaceScope): string {
  return JSON.stringify([
    scope.profileId, scope.selectionGeneration, scope.hubId, scope.ownerId,
    scope.deviceId, scope.sessionEpoch, scope.networkId, scope.networkVersion,
    scope.groupId, scope.groupVersion,
    scope.endpointId, scope.endpointOwnerId, scope.endpointBindingId,
    scope.endpointBindingEpoch, scope.topologyCapturedAt,
  ]);
}

export function createSharedSpaceReviewDraft(scope: SharedSpaceScope): SharedSpaceReviewDraft {
  return Object.freeze({scope, scopeKey: sharedSpaceScopeKey(scope), intent: 'review-only', reviewed: false});
}

/** Explicitly records that the user read this exact scope; it never signifies approval. */
export function markSharedSpaceReviewIntent(
  draft: SharedSpaceReviewDraft,
  currentScope: SharedSpaceScope | null,
): SharedSpaceReviewDraft | null {
  if (!currentScope || draft.scopeKey !== sharedSpaceScopeKey(currentScope)) return null;
  return Object.freeze({...draft, reviewed: true});
}

export function sharedSpaceDraftIsCurrent(
  draft: SharedSpaceReviewDraft | null,
  currentScope: SharedSpaceScope | null,
): draft is SharedSpaceReviewDraft {
  return Boolean(draft && currentScope && draft.scopeKey === sharedSpaceScopeKey(currentScope));
}

/** Capture before any deferred work; callers must compare it before applying a callback. */
export function captureSharedSpaceCallback(scope: SharedSpaceScope): SharedSpaceScopeCallback {
  return Object.freeze({scopeKey: sharedSpaceScopeKey(scope)});
}

export function sharedSpaceCallbackIsCurrent(
  callback: SharedSpaceScopeCallback,
  currentScope: SharedSpaceScope | null,
): boolean {
  return Boolean(currentScope && callback.scopeKey === sharedSpaceScopeKey(currentScope));
}
