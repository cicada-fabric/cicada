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
export const NETWORK_CARD_LIMIT = 100;
export const NETWORK_ENDPOINT_ENROLLMENT_LIMIT = 1000;

const record = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value === value.trim();

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
