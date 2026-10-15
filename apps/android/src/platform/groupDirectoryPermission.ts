import type {ClientHubStatus, HubProfileScope} from './clientHub.ts';
import type {NetworkTopologyRecord, NetworkTopologySnapshot} from './networkTopology.ts';

export const GROUP_DIRECTORY_PERMISSION_ACTION = 'membership.set_directory_permission' as const;
export const GROUP_DIRECTORY_PERMISSION_OPERATION = 'topology.apply' as const;

/** No v1.6.1 release descriptor exists for this candidate action. */
export interface GroupDirectoryPermissionReleaseDescriptor {
  readonly contract_revision: 'client-hub-v1.6.2';
  readonly catalog_sha256: string;
  readonly source_revision: string;
  readonly hub_schema_version: 55;
  readonly wire_version: 1;
}

export const GROUP_DIRECTORY_PERMISSION_RELEASE: GroupDirectoryPermissionReleaseDescriptor | null = null;
export const GROUP_DIRECTORY_PERMISSION_READY = GROUP_DIRECTORY_PERMISSION_RELEASE !== null;

export interface CandidateGroupDirectoryPermissionContractDescriptor {
  readonly verified: true;
  readonly synthetic_test_only: true;
  readonly contract_revision: 'client-hub-v1.6.2';
  readonly catalog_sha256: string;
  readonly source_revision: string;
  readonly hub_schema_version: 55;
  readonly wire_version: 1;
  readonly rpc_operations: readonly string[];
  readonly topology_actions: readonly string[];
}

interface CandidatePublicCapabilities {
  readonly contract_revision?: string;
  readonly catalog_sha256?: string;
  readonly client_control_pq_e2ee?: boolean;
  readonly authenticated_client_session?: boolean;
  readonly topology_management?: boolean;
  readonly available_rpc_operations?: readonly string[];
  readonly external_rpc_operations?: readonly string[];
}

interface CandidateSessionCapabilities {
  readonly owner_id?: string;
  readonly role?: string;
  readonly contract_revision?: string;
  readonly catalog_sha256?: string;
  readonly available_rpc_operations?: readonly string[];
}

export interface GroupDirectoryPermissionAuthorityInput {
  readonly status: ClientHubStatus;
  readonly publicCapabilities: CandidatePublicCapabilities | null;
  readonly sessionCapabilities: CandidateSessionCapabilities | null;
  readonly topology: NetworkTopologySnapshot | null;
  readonly apiScope: HubProfileScope;
  readonly bridgeReady: boolean;
}

export interface GroupDirectoryPermissionScope {
  readonly profileId: string;
  readonly selectionGeneration: number;
  readonly hubId: string;
  readonly ownerId: string;
  readonly deviceId: string;
  readonly sessionEpoch: number;
  readonly role: 'manager' | 'external';
  readonly contractRevision: 'client-hub-v1.6.2';
  readonly catalogSha256: string;
  readonly networkId: string;
  readonly networkVersion: number;
  readonly scopeKey: string;
}

export type GroupDirectoryPermissionAuthority = {
  readonly ready: true;
  readonly canRead: true;
  readonly canApply: true;
  readonly writesFenced: false;
  readonly scope: GroupDirectoryPermissionScope;
} | {
  readonly ready: false;
  readonly canRead: false;
  readonly canApply: false;
  readonly writesFenced: true;
  readonly reason: string;
};

export interface GroupDirectoryPermissionTarget {
  readonly scope: GroupDirectoryPermissionScope;
  readonly groupId: string;
  readonly groupName: string;
  readonly groupVersion: number;
  readonly membershipId: string;
  readonly principalId: string;
  readonly membershipRole: string;
  readonly membershipRoles?: readonly string[];
  readonly displayName?: string;
  readonly broadcastPermissionEnabled: boolean;
  readonly membershipVersion: number;
  readonly currentEnabled: boolean;
  readonly subjectEndpointIds: readonly string[];
  readonly targetKey: string;
}

export interface GroupDirectoryPermissionAction {
  readonly kind: typeof GROUP_DIRECTORY_PERMISSION_ACTION;
  readonly set_directory_permission: {
    readonly group_id: string;
    readonly membership_id: string;
    readonly enabled: boolean;
    readonly expected_membership_version: number;
  };
}

export interface GroupDirectoryPermissionReview {
  readonly reviewId: string;
  readonly scopeKey: string;
  readonly targetKey: string;
  readonly target: GroupDirectoryPermissionTarget;
  readonly enabled: boolean;
  readonly action: GroupDirectoryPermissionAction;
}

export interface GroupDirectoryPermissionCapture {
  readonly reviewId: string;
  readonly scopeKey: string;
  readonly generation: number;
}

export interface GroupDirectoryPermissionAttempt {
  readonly reviewId: string;
  readonly scopeKey: string;
  readonly groupId: string;
  readonly membershipId: string;
  readonly principalId: string;
  readonly membershipRole: string;
  readonly membershipRoles?: readonly string[];
  readonly displayName?: string;
  readonly broadcastPermissionEnabled: boolean;
  readonly enabled: boolean;
  readonly expectedMembershipVersion: number;
  readonly action: GroupDirectoryPermissionAction;
}

const hasControl = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
};
const identifier = (value: unknown, maxLength = 256): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= maxLength &&
  value === value.trim() && !hasControl(value);
const safeInteger = (value: unknown, minimum: number): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
const object = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const hasExactKeys = (value: NetworkTopologyRecord, required: readonly string[], optional: readonly string[] = []): boolean => {
  const allowed = new Set([...required, ...optional]);
  return required.every(key => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every(key => allowed.has(key));
};
const hasOperation = (value: unknown, operation: string): value is readonly string[] =>
  Array.isArray(value) && value.every(item => typeof item === 'string') && value.includes(operation);

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 64) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText,
    offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const offsetHour = Number(offsetHourText || 0);
  const offsetMinute = Number(offsetMinuteText || 0);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return year > 0 && month >= 1 && month <= 12 && day >= 1 && day <= monthDays[month - 1] &&
    hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59 &&
    Number.isFinite(Date.parse(value));
}

const noAuthority = (reason: string): GroupDirectoryPermissionAuthority => ({
  ready: false, canRead: false, canApply: false, writesFenced: true, reason,
});

/**
 * The app is pinned to v1.6.1. Candidate capabilities and caller claims cannot
 * replace this compiled release gate or make the panel available.
 */
export function groupDirectoryPermissionAuthority(
  _input: GroupDirectoryPermissionAuthorityInput,
): GroupDirectoryPermissionAuthority {
  return noAuthority('Group directory permission is not part of the pinned Client contract.');
}

function candidateDescriptorIsValid(
  value: CandidateGroupDirectoryPermissionContractDescriptor,
): boolean {
  const item = value as unknown as NetworkTopologyRecord;
  return object(item) && hasExactKeys(item, [
    'verified', 'synthetic_test_only', 'contract_revision', 'catalog_sha256', 'source_revision',
    'hub_schema_version', 'wire_version', 'rpc_operations', 'topology_actions',
  ]) && item.verified === true && item.synthetic_test_only === true &&
    item.contract_revision === 'client-hub-v1.6.2' &&
    typeof item.catalog_sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.catalog_sha256) &&
    typeof item.source_revision === 'string' && /^[0-9a-f]{40}$/.test(item.source_revision) &&
    item.hub_schema_version === 55 && item.wire_version === 1 &&
    hasOperation(item.rpc_operations, 'topology.snapshot') &&
    hasOperation(item.rpc_operations, 'topology.apply') &&
    Array.isArray(item.topology_actions) && item.topology_actions.every(action => typeof action === 'string') &&
    item.topology_actions.includes(GROUP_DIRECTORY_PERMISSION_ACTION);
}

function sortedStrings(value: unknown): string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string') ? [...value].sort() : [];
}

function authorityScopeKey(input: GroupDirectoryPermissionAuthorityInput,
  contract: CandidateGroupDirectoryPermissionContractDescriptor,
  networkId: string, networkVersion: number, role: 'manager' | 'external',
  publicOperations: readonly string[]): string {
  const {status, publicCapabilities, sessionCapabilities, apiScope} = input;
  return JSON.stringify([
    apiScope.profileId, apiScope.selectionGeneration, status.profileId, status.selectionGeneration,
    status.hubId, status.ownerId, status.deviceId, status.sessionEpoch, status.role,
    status.activeNetworkId, status.nativeAvailable, status.pinned, status.enrolled, status.remoteEnabled,
    status.sessionCapabilitiesReady, status.authFenced, status.recoveryBlocked,
    status.enrollmentRecoveryRequired, status.pendingOperationId || '',
    status.outcomeUncertainOperationId || '', status.uncertainNeedsReconciliation,
    status.networkGrantReconciliationRequired, status.regroupReconciliationRequired,
    sortedStrings(status.allowedOperations), role, contract.contract_revision, contract.catalog_sha256,
    publicCapabilities?.contract_revision || '', publicCapabilities?.catalog_sha256 || '',
    publicCapabilities?.client_control_pq_e2ee, publicCapabilities?.authenticated_client_session,
    publicCapabilities?.topology_management, sortedStrings(publicOperations),
    sessionCapabilities?.owner_id || '', sessionCapabilities?.role || '',
    sessionCapabilities?.contract_revision || '', sessionCapabilities?.catalog_sha256 || '',
    sortedStrings(sessionCapabilities?.available_rpc_operations), networkId, networkVersion,
  ]);
}

/**
 * Candidate-only authority evaluator for isolated DTO tests. Production UI and
 * facade code must call `groupDirectoryPermissionAuthority`, never this helper.
 */
export function candidateGroupDirectoryPermissionAuthority(
  input: GroupDirectoryPermissionAuthorityInput,
  candidateContract: CandidateGroupDirectoryPermissionContractDescriptor,
): GroupDirectoryPermissionAuthority {
  const {status, publicCapabilities, sessionCapabilities, topology, apiScope} = input;
  if (!candidateDescriptorIsValid(candidateContract)) {
    return noAuthority('The synthetic candidate contract descriptor is invalid.');
  }
  if (!identifier(status.profileId) || !safeInteger(status.selectionGeneration, 1) ||
      apiScope.profileId !== status.profileId || apiScope.selectionGeneration !== status.selectionGeneration) {
    return noAuthority('The selected profile generation does not match the Hub facade.');
  }
  if (!identifier(status.hubId) || !identifier(status.ownerId) || !identifier(status.deviceId) ||
      !safeInteger(status.sessionEpoch, 1) ||
      (status.role !== 'manager' && status.role !== 'external')) {
    return noAuthority('The enrolled Owner session scope is incomplete.');
  }
  if (input.bridgeReady !== true || status.nativeAvailable !== true || status.pinned !== true ||
      status.enrolled !== true || status.remoteEnabled !== true || status.sessionCapabilitiesReady !== true ||
      status.authFenced !== false || status.recoveryBlocked === true ||
      status.enrollmentRecoveryRequired === true || Boolean(status.pendingOperationId) ||
      status.uncertainNeedsReconciliation === true ||
      status.networkGrantReconciliationRequired === true || status.regroupReconciliationRequired === true) {
    return noAuthority('The current authenticated session is fenced, pending, or uncertain.');
  }
  if (!publicCapabilities || publicCapabilities.contract_revision !== candidateContract.contract_revision ||
      publicCapabilities.catalog_sha256 !== candidateContract.catalog_sha256 ||
      publicCapabilities.client_control_pq_e2ee !== true ||
      publicCapabilities.authenticated_client_session !== true ||
      publicCapabilities.topology_management !== true || !sessionCapabilities ||
      sessionCapabilities.contract_revision !== candidateContract.contract_revision ||
      sessionCapabilities.catalog_sha256 !== candidateContract.catalog_sha256 ||
      sessionCapabilities.owner_id !== status.ownerId || sessionCapabilities.role !== status.role) {
    return noAuthority('Public metadata and encrypted session capabilities do not describe the same Owner contract.');
  }
  const role = sessionCapabilities.role as 'manager' | 'external';
  const publicOperations = role === 'external' ? publicCapabilities.external_rpc_operations :
    publicCapabilities.available_rpc_operations;
  const requiredOperations = ['topology.snapshot', 'topology.apply'] as const;
  if (!publicOperations || !requiredOperations.every(operation => hasOperation(publicOperations, operation)) ||
      !requiredOperations.every(operation => hasOperation(sessionCapabilities.available_rpc_operations, operation)) ||
      !requiredOperations.every(operation => status.allowedOperations.includes(operation as never))) {
    return noAuthority('The public role catalog, encrypted Owner grant, and native status must all allow topology snapshot and apply.');
  }
  if (!topology || !validSnapshotShape(topology) || topology.owner_principal_id !== status.ownerId) {
    return noAuthority('A current encrypted topology snapshot for this Owner is required.');
  }
  const activeNetworks = topology.networks.filter(network => object(network) &&
    network.network_id === status.activeNetworkId);
  if (activeNetworks.length !== 1 || !isActiveNetwork(activeNetworks[0])) {
    return noAuthority('Select one exact ACTIVE Network from the current topology snapshot.');
  }
  const network = activeNetworks[0];
  const scope: GroupDirectoryPermissionScope = Object.freeze({
    profileId: status.profileId,
    selectionGeneration: status.selectionGeneration as number,
    hubId: status.hubId,
    ownerId: status.ownerId,
    deviceId: status.deviceId,
    sessionEpoch: status.sessionEpoch as number,
    role,
    contractRevision: 'client-hub-v1.6.2',
    catalogSha256: candidateContract.catalog_sha256,
    networkId: network.network_id as string,
    networkVersion: network.version as number,
    scopeKey: authorityScopeKey(input, candidateContract, network.network_id as string,
      network.version as number, role, publicOperations),
  });
  return {ready: true, canRead: true, canApply: true, writesFenced: false, scope};
}

function validSnapshotShape(value: unknown): value is NetworkTopologySnapshot {
  const snapshot = value as unknown as NetworkTopologyRecord;
  return object(snapshot) && hasExactKeys(snapshot, [
    'contract_version', 'owner_principal_id', 'captured_at', 'read_consistency', 'networks',
    'networks_truncated', 'network_endpoints_truncated', 'groups', 'memberships', 'endpoints', 'links',
  ]) && snapshot.contract_version === 2 && identifier(snapshot.owner_principal_id) &&
    timestamp(snapshot.captured_at) && snapshot.read_consistency === 'best_effort' &&
    Array.isArray(snapshot.networks) && Array.isArray(snapshot.groups) &&
    Array.isArray(snapshot.memberships) && Array.isArray(snapshot.endpoints) && Array.isArray(snapshot.links) &&
    snapshot.networks.length <= 100 && snapshot.groups.length <= 10000 &&
    snapshot.memberships.length <= 10000 && snapshot.endpoints.length <= 10000 && snapshot.links.length <= 10000 &&
    typeof snapshot.networks_truncated === 'boolean' && typeof snapshot.network_endpoints_truncated === 'boolean';
}

/** Unwraps the verified native RPC envelope without treating it as a topology DTO. */
export function groupDirectoryPermissionSnapshotFromRpc(
  value: unknown,
  expectedOwnerId: string,
): NetworkTopologySnapshot | null {
  if (!object(value) || !hasExactKeys(value, ['ok', 'result'], ['requestId', 'operationId']) ||
      value.ok !== true || !identifier(expectedOwnerId) ||
      (value.requestId !== undefined && !identifier(value.requestId)) ||
      (value.operationId !== undefined && !identifier(value.operationId)) ||
      !validSnapshotShape(value.result) || value.result.owner_principal_id !== expectedOwnerId) return null;
  return value.result;
}

function isActiveNetwork(value: unknown): value is NetworkTopologyRecord {
  return object(value) && hasExactKeys(value, [
    'network_id', 'name', 'state', 'version', 'can_create_group',
  ]) && identifier(value.network_id) && typeof value.name === 'string' && value.name.length <= 256 &&
    value.state === 'ACTIVE' &&
    safeInteger(value.version, 1) && value.can_create_group === true;
}

function membershipDto(value: unknown): NetworkTopologyRecord | null {
  if (!object(value) || !hasExactKeys(value, [
    'membership_id', 'principal_id', 'group_id', 'role', 'broadcast_permission_enabled',
    'directory_permission_enabled', 'status', 'version',
  ], ['display_name', 'roles']) || !identifier(value.membership_id) || !identifier(value.principal_id) ||
      !identifier(value.group_id) || !identifier(value.role, 128) ||
      typeof value.broadcast_permission_enabled !== 'boolean' ||
      typeof value.directory_permission_enabled !== 'boolean' || typeof value.status !== 'string' ||
      value.status.length > 32 || !safeInteger(value.version, 1) ||
      (value.display_name !== undefined && (typeof value.display_name !== 'string' || value.display_name.length > 256)) ||
      (value.roles !== undefined && (!Array.isArray(value.roles) ||
        !value.roles.every(role => typeof role === 'string' && identifier(role, 128))))) return null;
  return value;
}

function groupDto(value: unknown): NetworkTopologyRecord | null {
  if (!object(value) || !hasExactKeys(value,
    ['group_id', 'name', 'state', 'context_policy', 'version'], ['network_id', 'parent_group_id']) ||
      !identifier(value.group_id) || typeof value.name !== 'string' || value.name.length > 256 ||
      typeof value.state !== 'string' || value.state.length > 32 ||
      typeof value.context_policy !== 'string' || value.context_policy.length > 256 || !safeInteger(value.version, 1) ||
      (value.network_id !== undefined && !identifier(value.network_id)) ||
      (value.parent_group_id !== undefined && !identifier(value.parent_group_id))) return null;
  return value;
}

function endpointDto(value: unknown): NetworkTopologyRecord | null {
  const optional = [
    'node_id', 'harness', 'native_session_id', 'binding_id', 'binding_epoch', 'binding_status',
  ];
  if (!object(value) || !hasExactKeys(value,
    ['endpoint_id', 'name', 'principal_id', 'group_ids', 'network_ids', 'presence'], optional) ||
      !identifier(value.endpoint_id) || typeof value.name !== 'string' || value.name.length > 256 ||
      !identifier(value.principal_id) ||
      !Array.isArray(value.group_ids) || !value.group_ids.every(item => identifier(item)) ||
      new Set(value.group_ids).size !== value.group_ids.length ||
      !Array.isArray(value.network_ids) || !value.network_ids.every(item => identifier(item)) ||
      new Set(value.network_ids).size !== value.network_ids.length || typeof value.presence !== 'string' ||
      value.presence.length > 64 ||
      (value.node_id !== undefined && !identifier(value.node_id)) ||
      (value.harness !== undefined && (typeof value.harness !== 'string' || value.harness.length > 128)) ||
      (value.native_session_id !== undefined &&
        (typeof value.native_session_id !== 'string' || value.native_session_id.length > 256)) ||
      (value.binding_id !== undefined && !identifier(value.binding_id)) ||
      (value.binding_epoch !== undefined && !safeInteger(value.binding_epoch, 0)) ||
      (value.binding_status !== undefined &&
        (typeof value.binding_status !== 'string' || value.binding_status.length > 64))) return null;
  return value;
}

function directoryTargetKey(
  scope: GroupDirectoryPermissionScope,
  groupId: string,
  groupName: string,
  groupVersion: number,
  membershipId: string,
  principalId: string,
  membershipRole: string,
  membershipRoles: readonly string[] | undefined,
  displayName: string | undefined,
  broadcastPermissionEnabled: boolean,
  membershipVersion: number,
  currentEnabled: boolean,
  subjectEndpointIds: readonly string[],
): string {
  return JSON.stringify([
    scope.scopeKey, groupId, groupName, groupVersion, membershipId, principalId,
    membershipRole, membershipRoles ?? null, displayName ?? null, broadcastPermissionEnabled,
    membershipVersion, currentEnabled, [...subjectEndpointIds].sort(),
  ]);
}

/** Strictly binds one selected active Membership and all of its joined Group Endpoints. */
export function parseGroupDirectoryPermissionSnapshot(
  value: unknown,
  authority: GroupDirectoryPermissionAuthority,
  groupId: string,
  membershipId: string,
): GroupDirectoryPermissionTarget | null {
  if (!authority.ready || !authority.canRead || !identifier(groupId) || !identifier(membershipId) ||
      !validSnapshotShape(value)) return null;
  const snapshot = value;
  const scope = authority.scope;
  if (snapshot.owner_principal_id !== scope.ownerId || snapshot.networks_truncated !== false ||
      snapshot.network_endpoints_truncated !== false) return null;

  const networks = snapshot.networks.filter(item => object(item) && item.network_id === scope.networkId);
  if (networks.length !== 1 || !isActiveNetwork(networks[0]) ||
      networks[0].version !== scope.networkVersion) return null;

  const allGroups: NetworkTopologyRecord[] = [];
  for (const raw of snapshot.groups) {
    const group = groupDto(raw);
    if (!group) return null;
    allGroups.push(group);
  }
  if (allGroups.filter(group => group.group_id === groupId).length !== 1) return null;
  const groups = allGroups.filter(group => group.group_id === groupId &&
    group.network_id === scope.networkId && group.state === 'ACTIVE');
  if (groups.length !== 1) return null;
  const group = groups[0];

  const targetMemberships: NetworkTopologyRecord[] = [];
  let selectedMembershipCount = 0;
  for (const raw of snapshot.memberships) {
    const rawRecord = object(raw) ? raw : null;
    if (!rawRecord) return null;
    if (rawRecord.group_id !== groupId && rawRecord.membership_id !== membershipId) continue;
    const candidate = membershipDto(rawRecord);
    if (!candidate) return null;
    if (candidate.membership_id === membershipId) {
      selectedMembershipCount += 1;
      if (candidate.group_id !== groupId) return null;
    }
    if (candidate.group_id === groupId) targetMemberships.push(candidate);
  }
  // The candidate producer caps each Group projection at 1000 without a per-Group truncation flag.
  if (selectedMembershipCount !== 1 || targetMemberships.length >= 1000) return null;
  const selected = targetMemberships.filter(member => member.membership_id === membershipId);
  if (selected.length !== 1) return null;
  const member = selected[0];
  if (member.status !== 'active' || !safeInteger(member.version, 1) ||
      member.version >= Number.MAX_SAFE_INTEGER ||
      targetMemberships.filter(candidate => candidate.status === 'active' &&
        candidate.principal_id === member.principal_id).length !== 1) return null;

  const allEndpoints: NetworkTopologyRecord[] = [];
  const endpointIds = new Set<string>();
  for (const raw of snapshot.endpoints) {
    const endpoint = endpointDto(raw);
    if (!endpoint || endpointIds.has(endpoint.endpoint_id as string)) return null;
    endpointIds.add(endpoint.endpoint_id as string);
    allEndpoints.push(endpoint);
  }
  const groupEndpoints: string[] = [];
  let groupEndpointCount = 0;
  for (const endpoint of allEndpoints) {
    const joinedGroup = (endpoint.group_ids as string[]).includes(groupId);
    if (joinedGroup && ++groupEndpointCount >= 1000) return null;
    if (joinedGroup && !(endpoint.network_ids as string[]).includes(scope.networkId)) return null;
    if (joinedGroup && endpoint.principal_id === member.principal_id) {
      groupEndpoints.push(endpoint.endpoint_id as string);
    }
  }
  groupEndpoints.sort();

  const membershipRoles = Array.isArray(member.roles) ? Object.freeze([...member.roles] as string[]) : undefined;
  const details = {
    groupId,
    groupName: group.name as string,
    groupVersion: group.version as number,
    membershipId,
    principalId: member.principal_id as string,
    membershipRole: member.role as string,
    ...(membershipRoles ? {membershipRoles} : {}),
    ...(typeof member.display_name === 'string' ? {displayName: member.display_name} : {}),
    broadcastPermissionEnabled: member.broadcast_permission_enabled as boolean,
    membershipVersion: member.version as number,
    currentEnabled: member.directory_permission_enabled as boolean,
    subjectEndpointIds: Object.freeze(groupEndpoints),
  };
  return Object.freeze({
    scope,
    ...details,
    targetKey: directoryTargetKey(scope, details.groupId, details.groupName, details.groupVersion,
      details.membershipId, details.principalId, details.membershipRole, details.membershipRoles,
      details.displayName, details.broadcastPermissionEnabled, details.membershipVersion,
      details.currentEnabled, details.subjectEndpointIds),
  });
}

let nextReviewSequence = 0;

export function createGroupDirectoryPermissionReview(
  authority: GroupDirectoryPermissionAuthority,
  target: GroupDirectoryPermissionTarget,
  enabled: boolean,
): GroupDirectoryPermissionReview | null {
  if (!authority.ready || !authority.canApply || !target ||
      target.scope.scopeKey !== authority.scope.scopeKey || typeof enabled !== 'boolean' ||
      target.currentEnabled === enabled || !safeInteger(target.membershipVersion, 1) ||
      target.membershipVersion >= Number.MAX_SAFE_INTEGER) return null;
  const action: GroupDirectoryPermissionAction = Object.freeze({
    kind: GROUP_DIRECTORY_PERMISSION_ACTION,
    set_directory_permission: Object.freeze({
      group_id: target.groupId,
      membership_id: target.membershipId,
      enabled,
      expected_membership_version: target.membershipVersion,
    }),
  });
  nextReviewSequence += 1;
  return Object.freeze({
    reviewId: `group-directory-permission-review-${nextReviewSequence}`,
    scopeKey: authority.scope.scopeKey,
    targetKey: target.targetKey,
    target,
    enabled,
    action,
  });
}

export class GroupDirectoryPermissionLifecycle {
  private generation = 0;
  private readonly consumedReviewIds = new Set<string>();

  capture(review: GroupDirectoryPermissionReview): GroupDirectoryPermissionCapture | null {
    if (!review || this.consumedReviewIds.has(review.reviewId)) return null;
    return Object.freeze({reviewId: review.reviewId, scopeKey: review.scopeKey, generation: this.generation});
  }

  invalidate(): void {
    this.generation += 1;
  }

  isCurrent(capture: GroupDirectoryPermissionCapture, currentScopeKey: string,
    currentReviewId: string | null, foreground: boolean): boolean {
    return foreground === true && capture.generation === this.generation &&
      capture.scopeKey === currentScopeKey && capture.reviewId === currentReviewId &&
      !this.consumedReviewIds.has(capture.reviewId);
  }

  /** A review is consumed on its first confirmation attempt, including stale attempts. */
  confirm(
    review: GroupDirectoryPermissionReview,
    capture: GroupDirectoryPermissionCapture,
    currentAuthority: GroupDirectoryPermissionAuthority,
    freshSnapshot: unknown,
    currentReviewId: string | null,
    foreground: boolean,
  ): GroupDirectoryPermissionAttempt | null {
    if (!review || this.consumedReviewIds.has(review.reviewId)) return null;
    this.consumedReviewIds.add(review.reviewId);
    if (!currentAuthority.ready || !currentAuthority.canApply || !foreground ||
        capture.reviewId !== review.reviewId || capture.scopeKey !== review.scopeKey ||
        capture.generation !== this.generation || currentReviewId !== review.reviewId ||
        currentAuthority.scope.scopeKey !== review.scopeKey) return null;
    const latest = parseGroupDirectoryPermissionSnapshot(freshSnapshot, currentAuthority,
      review.target.groupId, review.target.membershipId);
    if (!latest || latest.targetKey !== review.targetKey || latest.targetKey !== review.target.targetKey ||
        latest.membershipVersion !== review.action.set_directory_permission.expected_membership_version ||
        latest.currentEnabled === review.enabled) return null;
    return Object.freeze({
      reviewId: review.reviewId,
      scopeKey: review.scopeKey,
      groupId: review.target.groupId,
      membershipId: review.target.membershipId,
      principalId: review.target.principalId,
      membershipRole: review.target.membershipRole,
      ...(review.target.membershipRoles ? {membershipRoles: review.target.membershipRoles} : {}),
      ...(review.target.displayName !== undefined ? {displayName: review.target.displayName} : {}),
      broadcastPermissionEnabled: review.target.broadcastPermissionEnabled,
      enabled: review.enabled,
      expectedMembershipVersion: review.target.membershipVersion,
      action: review.action,
    });
  }
}

/** Validates the exact topology.apply projection; transport success alone is not mutation success. */
export function validateGroupDirectoryPermissionResult(
  attempt: GroupDirectoryPermissionAttempt,
  value: unknown,
): boolean {
  const envelope = object(value) ? value : null;
  if (!attempt || !envelope || !hasExactKeys(envelope, ['ok', 'result'], ['requestId', 'operationId']) ||
      envelope.ok !== true ||
      !object(envelope.result)) return false;
  if ((envelope.requestId !== undefined && !identifier(envelope.requestId)) ||
      (envelope.operationId !== undefined && !identifier(envelope.operationId))) return false;
  const result = envelope.result;
  if (!hasExactKeys(result, ['contract_version', 'action', 'changed', 'membership']) ||
      result.contract_version !== 2 || result.action !== GROUP_DIRECTORY_PERMISSION_ACTION ||
      result.changed !== true) return false;
  const membership = membershipDto(result.membership);
  return Boolean(membership && membership.membership_id === attempt.membershipId &&
    membership.principal_id === attempt.principalId && membership.group_id === attempt.groupId &&
    membership.status === 'active' && membership.directory_permission_enabled === attempt.enabled &&
    membership.version === attempt.expectedMembershipVersion + 1 &&
    membership.role === attempt.membershipRole &&
    membership.broadcast_permission_enabled === attempt.broadcastPermissionEnabled &&
    (attempt.membershipRoles === undefined ? membership.roles === undefined :
      Array.isArray(membership.roles) && JSON.stringify(membership.roles) === JSON.stringify(attempt.membershipRoles)) &&
    (attempt.displayName === undefined ? membership.display_name === undefined :
      membership.display_name === attempt.displayName));
}

/** Blocks candidate actions before they can reach the generic native RPC transport. */
export function directoryPermissionActionRequested(operation: unknown, body: unknown): boolean {
  if (operation !== GROUP_DIRECTORY_PERMISSION_OPERATION || !object(body)) return false;
  return body.kind === GROUP_DIRECTORY_PERMISSION_ACTION ||
    Object.prototype.hasOwnProperty.call(body, 'set_directory_permission');
}
