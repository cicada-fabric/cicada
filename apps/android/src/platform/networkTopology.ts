import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from './clientHubContract.ts';

/** Metadata from the owner-scoped Client topology v2 projection. */
export type NetworkTopologyRecord = Record<string, unknown>;

export interface NetworkTopologyCard {
  network_id: string;
  name: string;
  state: string;
  version: number;
  can_create_group: boolean;
}

export interface NetworkTopologySnapshot {
  contract_version: 2;
  owner_principal_id: string;
  captured_at: string;
  read_consistency: 'best_effort';
  networks: NetworkTopologyCard[];
  networks_truncated: boolean;
  network_endpoints_truncated: boolean;
  groups: NetworkTopologyRecord[];
  memberships: NetworkTopologyRecord[];
  endpoints: NetworkTopologyRecord[];
  links: NetworkTopologyRecord[];
}

export const NETWORK_CONTRACT_REVISION = CLIENT_HUB_REVISION;
export const NETWORK_CATALOG_SHA256 = CLIENT_HUB_CATALOG_SHA256;
export const NETWORK_KEY_OPERATIONS = [
  'network.key_manifest', 'network.key_grant', 'network.key_status',
] as const;
export const NETWORK_KEY_REQUIRED_OPERATIONS = ['topology.snapshot', ...NETWORK_KEY_OPERATIONS] as const;
export const NETWORK_DIRECTORY_REQUIRED_OPERATIONS = ['topology.snapshot', 'network.directory'] as const;
export const ENDPOINT_ADMISSION_PREVIEW_REQUIRED_OPERATIONS = [
  'topology.snapshot', 'topology.endpoint_admission_preview',
] as const;
export const NETWORK_CARD_LIMIT = 100;
export const NETWORK_ENDPOINT_ENROLLMENT_LIMIT = 1000;

export interface NetworkDirectoryEndpoint {
  network_id: string;
  endpoint_id: string;
  alias: string;
  presence: 'ACCESS_RECENT' | 'UNKNOWN';
}

export interface NetworkDirectoryPage {
  network_id: string;
  endpoints: NetworkDirectoryEndpoint[];
  next_cursor?: string;
}

export interface EndpointAdmissionPreview {
  owner_principal_id: string;
  network_id: string;
  network_name: string;
  network_version: number;
  group_id: string;
  group_name: string;
  group_version: number;
  group_context_policy: string;
  endpoint_id: string;
  endpoint_name: string;
  endpoint_principal_id: string;
  endpoint_migration_state: 'READY' | 'MIGRATION_PENDING_GROUP';
  network_membership_revision: number;
  endpoint_network_revision: number;
  network_access_binding_id: string;
  network_access_epoch: number;
  native_binding_id: string;
  native_binding_epoch: number;
  existing_group_binding_id?: string;
  existing_group_binding_epoch?: number;
  membership_status?: string;
  membership_revision: number;
  endpoint_group_status?: string;
  endpoint_group_revision: number;
  admission_roles: ['member'];
  admission_grants: [];
  history_included: false;
  key_grant_created: false;
  existing_thread_memory_retained: true;
}

const record = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value === value.trim();

const exactFields = (value: NetworkTopologyRecord, required: readonly string[], optional: readonly string[] = []): boolean => {
  const allowed = new Set([...required, ...optional]);
  return Object.keys(value).every(key => allowed.has(key)) &&
    required.every(key => Object.prototype.hasOwnProperty.call(value, key));
};

const safeInteger = (value: unknown, minimum: number): value is number =>
  Number.isSafeInteger(value) && Number(value) >= minimum;

/** Validate the bounded wire page before UI code can treat cards as discovery references. */
export function networkDirectoryPageFromRpc(
  value: unknown,
  networkId: string,
  requestedLimit = 64,
): NetworkDirectoryPage | null {
  if (!record(value) || !exactFields(value, ['network_id', 'endpoints'], ['next_cursor']) ||
      value.network_id !== networkId || !identifier(networkId) ||
      !Array.isArray(value.endpoints) || value.endpoints.length > 64 ||
      !Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 64 ||
      value.endpoints.length > requestedLimit) return null;
  if (value.next_cursor !== undefined &&
      (typeof value.next_cursor !== 'string' || value.next_cursor.length > 256)) return null;
  const seen = new Set<string>();
  const endpoints: NetworkDirectoryEndpoint[] = [];
  for (const candidate of value.endpoints) {
    if (!record(candidate) || !exactFields(candidate,
      ['network_id', 'endpoint_id', 'alias', 'presence']) ||
        candidate.network_id !== networkId || !identifier(candidate.endpoint_id) ||
        typeof candidate.alias !== 'string' || candidate.alias.length > 256 ||
        !['ACCESS_RECENT', 'UNKNOWN'].includes(String(candidate.presence)) ||
        seen.has(candidate.endpoint_id)) return null;
    seen.add(candidate.endpoint_id);
    endpoints.push({
      network_id: networkId,
      endpoint_id: candidate.endpoint_id,
      alias: candidate.alias,
      presence: candidate.presence as NetworkDirectoryEndpoint['presence'],
    });
  }
  return {
    network_id: networkId,
    endpoints,
    ...(typeof value.next_cursor === 'string' ? {next_cursor: value.next_cursor} : {}),
  };
}

/** Validate the exact same-Owner preview and bind its displayed identities/versions to topology. */
export function endpointAdmissionPreviewFromRpc(
  value: unknown,
  topology: NetworkTopologySnapshot | null,
  networkId: string,
  groupId: string,
  endpointId: string,
): EndpointAdmissionPreview | null {
  const required = [
    'owner_principal_id', 'network_id', 'network_name', 'network_version', 'group_id', 'group_name',
    'group_version', 'group_context_policy', 'endpoint_id', 'endpoint_name', 'endpoint_principal_id',
    'endpoint_migration_state', 'network_membership_revision', 'endpoint_network_revision',
    'network_access_binding_id', 'network_access_epoch', 'native_binding_id', 'native_binding_epoch',
    'membership_revision', 'endpoint_group_revision', 'admission_roles', 'admission_grants',
    'history_included', 'key_grant_created', 'existing_thread_memory_retained',
  ];
  const optional = [
    'existing_group_binding_id', 'existing_group_binding_epoch', 'membership_status', 'endpoint_group_status',
  ];
  if (!record(value) || !exactFields(value, required, optional) || !topology ||
      !identifier(networkId) || !identifier(groupId) || !identifier(endpointId) ||
      value.owner_principal_id !== topology.owner_principal_id || value.network_id !== networkId ||
      value.group_id !== groupId || value.endpoint_id !== endpointId ||
      typeof value.network_name !== 'string' || typeof value.group_name !== 'string' ||
      typeof value.group_context_policy !== 'string' || typeof value.endpoint_name !== 'string' ||
      !identifier(value.endpoint_principal_id) ||
      !['READY', 'MIGRATION_PENDING_GROUP'].includes(String(value.endpoint_migration_state)) ||
      !safeInteger(value.network_version, 1) || !safeInteger(value.group_version, 1) ||
      !safeInteger(value.network_membership_revision, 1) || !safeInteger(value.endpoint_network_revision, 1) ||
      !safeInteger(value.network_access_epoch, 1) || !safeInteger(value.native_binding_epoch, 1) ||
      !safeInteger(value.membership_revision, 0) || !safeInteger(value.endpoint_group_revision, 0) ||
      !identifier(value.network_access_binding_id) || !identifier(value.native_binding_id) ||
      !Array.isArray(value.admission_roles) || value.admission_roles.length !== 1 ||
      value.admission_roles[0] !== 'member' || !Array.isArray(value.admission_grants) ||
      value.admission_grants.length !== 0 || value.history_included !== false ||
      value.key_grant_created !== false || value.existing_thread_memory_retained !== true) return null;
  if (value.existing_group_binding_id !== undefined && !identifier(value.existing_group_binding_id)) return null;
  if (value.existing_group_binding_epoch !== undefined && !safeInteger(value.existing_group_binding_epoch, 0)) return null;
  if (value.membership_status !== undefined && typeof value.membership_status !== 'string') return null;
  if (value.endpoint_group_status !== undefined && typeof value.endpoint_group_status !== 'string') return null;

  const network = explicitActiveNetwork(topology, networkId);
  const groups = groupsInNetwork(topology, networkId).filter(group => group.group_id === groupId);
  const endpoints = endpointsInNetwork(topology, networkId).filter(endpoint => endpoint.endpoint_id === endpointId);
  if (!network || groups.length !== 1 || endpoints.length !== 1) return null;
  const group = groups[0];
  const endpoint = endpoints[0];
  if (group.state !== 'ACTIVE' || endpoint.principal_id !== value.endpoint_principal_id ||
      network.name !== value.network_name || network.version !== value.network_version ||
      group.name !== value.group_name || group.version !== value.group_version ||
      group.context_policy !== value.group_context_policy || endpoint.name !== value.endpoint_name) return null;
  return value as unknown as EndpointAdmissionPreview;
}

function hasNetworkProjection(snapshot: NetworkTopologySnapshot | null): snapshot is NetworkTopologySnapshot {
  return Boolean(snapshot && snapshot.contract_version === 2 &&
    identifier(snapshot.owner_principal_id) && Array.isArray(snapshot.networks) &&
    snapshot.networks.length <= NETWORK_CARD_LIMIT &&
    typeof snapshot.networks_truncated === 'boolean' &&
    typeof snapshot.network_endpoints_truncated === 'boolean');
}

/** Select by exact ID only; names and the first visible card never select a scope. */
export function explicitActiveNetwork(
  snapshot: NetworkTopologySnapshot | null,
  selectedId: string | null | undefined,
): NetworkTopologyCard | null {
  if (!hasNetworkProjection(snapshot) || !identifier(selectedId)) return null;
  const cards = snapshot.networks.filter(card => record(card) && card.network_id === selectedId);
  if (cards.length !== 1) return null;
  const card = cards[0];
  return card.state === 'ACTIVE' && typeof card.name === 'string' &&
    Number.isSafeInteger(card.version) && card.version > 0 &&
    typeof card.can_create_group === 'boolean' ? card : null;
}

export function groupsInNetwork(
  snapshot: NetworkTopologySnapshot | null,
  selectedId: string | null | undefined,
): NetworkTopologyRecord[] {
  if (!explicitActiveNetwork(snapshot, selectedId) || !Array.isArray(snapshot?.groups)) return [];
  return snapshot.groups.filter(group => record(group) && identifier(group.group_id) &&
    group.network_id === selectedId);
}

/** Network membership is explicit; Group membership/binding does not substitute for it. */
export function endpointsInNetwork(
  snapshot: NetworkTopologySnapshot | null,
  selectedId: string | null | undefined,
): NetworkTopologyRecord[] {
  if (!explicitActiveNetwork(snapshot, selectedId) || !Array.isArray(snapshot?.endpoints)) return [];
  return snapshot.endpoints.filter(endpoint => record(endpoint) && identifier(endpoint.endpoint_id) &&
    Array.isArray(endpoint.network_ids) && endpoint.network_ids.includes(selectedId));
}

interface NetworkReadCapabilityAdvertisement {
  contract_revision?: string;
  catalog_sha256?: string;
  client_control_pq_e2ee?: boolean;
  authenticated_client_session?: boolean;
  topology_management?: boolean;
  available_rpc_operations?: string[];
  external_rpc_operations?: string[];
}
interface NetworkReadSessionGrant {
  owner_id?: string;
  role?: string;
  contract_revision?: string;
  catalog_sha256?: string;
  available_rpc_operations?: string[];
}
interface NetworkReadSessionStatus {
  nativeAvailable?: boolean;
  pinned?: boolean;
  enrolled?: boolean;
  remoteEnabled?: boolean;
  sessionCapabilitiesReady?: boolean;
  authFenced?: boolean;
  recoveryBlocked?: boolean;
  enrollmentRecoveryRequired?: boolean;
  ownerId?: string;
  activeNetworkId?: string;
  pendingOperationId?: string;
  allowedOperations?: string[];
}

/** Both v1.6 reads require fresh public and encrypted permission in the selected Owner scope. */
export function ownerNetworkReadAllows(
  capabilities: NetworkReadCapabilityAdvertisement | null,
  session: NetworkReadSessionGrant | null,
  status: NetworkReadSessionStatus,
  topology: NetworkTopologySnapshot | null,
  operation: 'network.directory' | 'topology.endpoint_admission_preview',
): boolean {
  const required = operation === 'network.directory' ? NETWORK_DIRECTORY_REQUIRED_OPERATIONS :
    ENDPOINT_ADMISSION_PREVIEW_REQUIRED_OPERATIONS;
  const publicOperations = session?.role === 'external' ? capabilities?.external_rpc_operations :
    session?.role === 'manager' ? capabilities?.available_rpc_operations : undefined;
  const network = explicitActiveNetwork(topology, status.activeNetworkId);
  return Boolean(network && capabilities && session &&
    capabilities.contract_revision === NETWORK_CONTRACT_REVISION &&
    capabilities.catalog_sha256 === NETWORK_CATALOG_SHA256 &&
    capabilities.client_control_pq_e2ee === true &&
    capabilities.authenticated_client_session === true && capabilities.topology_management === true &&
    session.contract_revision === NETWORK_CONTRACT_REVISION &&
    session.catalog_sha256 === NETWORK_CATALOG_SHA256 &&
    session.owner_id === status.ownerId && topology?.owner_principal_id === status.ownerId &&
    ['manager', 'external'].includes(session.role ?? '') &&
    status.nativeAvailable === true && status.pinned === true && status.enrolled === true &&
    status.remoteEnabled === true && status.sessionCapabilitiesReady === true &&
    status.authFenced !== true && status.recoveryBlocked !== true &&
    status.enrollmentRecoveryRequired !== true && !status.pendingOperationId &&
    required.every(item => publicOperations?.includes(item)) &&
    required.every(item => session.available_rpc_operations?.includes(item)) &&
    required.every(item => status.allowedOperations?.includes(item)));
}

export interface NetworkGroupCreateRequest {
  kind: 'group.create';
  create_group: {group: {network_id: string; name: string}; parent_group_id?: string};
}

/** A visible card is a UI hint. The encrypted device request and Hub Guard authorize creation. */
export function createGroupRequest(
  snapshot: NetworkTopologySnapshot | null,
  selectedId: string | null | undefined,
  name: string,
  parentId?: string,
): NetworkGroupCreateRequest {
  const network = explicitActiveNetwork(snapshot, selectedId);
  if (!network || !network.can_create_group) {
    throw new Error('请明确选择当前 Owner 可建组的 ACTIVE Network。');
  }
  const groupName = name.trim();
  if (!groupName) throw new Error('请输入 Group 名称。');
  const parent = parentId?.trim();
  if (parent) {
    const matches = Array.isArray(snapshot?.groups) ? snapshot.groups.filter(group =>
      record(group) && group.group_id === parent) : [];
    if (matches.length !== 1 || matches[0].network_id !== network.network_id ||
        matches[0].state !== 'ACTIVE') {
      throw new Error('父 Group 必须是当前 Network 中唯一可见的 ACTIVE Group。');
    }
  }
  return {kind: 'group.create', create_group: {
    group: {network_id: network.network_id, name: groupName},
    ...(parent ? {parent_group_id: parent} : {}),
  }};
}

interface NetworkCapabilityAdvertisement {
  contract_revision?: string;
  catalog_sha256?: string;
  client_control_pq_e2ee?: boolean;
  authenticated_client_session?: boolean;
  available_rpc_operations?: string[];
  external_rpc_operations?: string[];
}
interface NetworkSessionGrant {
  owner_id?: string;
  role?: string;
  contract_revision?: string;
  catalog_sha256?: string;
  available_rpc_operations?: string[];
}
interface NetworkSessionStatus {
  nativeAvailable?: boolean;
  pinned?: boolean;
  enrolled?: boolean;
  remoteEnabled?: boolean;
  sessionCapabilitiesReady?: boolean;
  authFenced?: boolean;
  recoveryBlocked?: boolean;
  enrollmentRecoveryRequired?: boolean;
  uncertainNeedsReconciliation?: boolean;
  networkGrantReconciliationRequired?: boolean;
  ownerId?: string;
  activeNetworkId?: string;
  pendingOperationId?: string;
  allowedOperations?: string[];
}

/** Require independent implementation availability and the current encrypted Owner scope. */
export function networkKeyConsentAllows(
  capabilities: NetworkCapabilityAdvertisement | null,
  session: NetworkSessionGrant | null,
  status: NetworkSessionStatus,
  nativeVerifierReady: boolean,
  topology: NetworkTopologySnapshot | null,
  operation: typeof NETWORK_KEY_OPERATIONS[number] = 'network.key_grant',
): boolean {
  const publicOperations = session?.role === 'external' ? capabilities?.external_rpc_operations :
    session?.role === 'manager' ? capabilities?.available_rpc_operations : undefined;
  return Boolean(nativeVerifierReady && capabilities && session &&
    capabilities.contract_revision === NETWORK_CONTRACT_REVISION &&
    capabilities.catalog_sha256 === NETWORK_CATALOG_SHA256 &&
    capabilities.client_control_pq_e2ee === true && capabilities.authenticated_client_session === true &&
    session.contract_revision === NETWORK_CONTRACT_REVISION &&
    session.catalog_sha256 === NETWORK_CATALOG_SHA256 &&
    identifier(status.ownerId) && session.owner_id === status.ownerId &&
    topology?.owner_principal_id === status.ownerId &&
    explicitActiveNetwork(topology, status.activeNetworkId) &&
    status.nativeAvailable === true && status.pinned === true && status.enrolled === true &&
    status.remoteEnabled === true && status.sessionCapabilitiesReady === true &&
    status.authFenced !== true && status.recoveryBlocked !== true &&
    status.enrollmentRecoveryRequired !== true && !status.pendingOperationId &&
    (operation !== 'network.key_grant' || (status.uncertainNeedsReconciliation !== true &&
      status.networkGrantReconciliationRequired !== true)) &&
    NETWORK_KEY_REQUIRED_OPERATIONS.every(item => publicOperations?.includes(item)) &&
    NETWORK_KEY_REQUIRED_OPERATIONS.every(item => session.available_rpc_operations?.includes(item)) &&
    NETWORK_KEY_REQUIRED_OPERATIONS.every(item => status.allowedOperations?.includes(item)));
}
