import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus, HubProfileScope,
} from './clientHub';
import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from './clientHubContract.ts';
import {clientHubOperationAllowed} from './clientHubOperationPolicy.ts';

export interface NodeControlKeyCandidate {
  request_id: string;
  version: number;
  mode: 'INITIAL' | 'UPGRADE';
  hub_id: string;
  node_id: string;
  node_name: string;
  node_key_id: string;
  node_key_fingerprint: string;
  hub_node_control_key_id: string;
  hub_node_control_key_version: number;
  hub_node_control_fingerprint: string;
  node_key_epoch: number;
  candidate_digest: string;
  expires_at: string;
  state: 'PENDING';
  binding_id?: string;
  binding_version?: number;
}

export type NodePairingOperation = 'nodes.preview' | 'nodes.confirm';

const candidateFields = [
  'request_id', 'version', 'mode', 'hub_id', 'node_id', 'node_name', 'node_key_id',
  'node_key_fingerprint', 'hub_node_control_key_id', 'hub_node_control_key_version',
  'hub_node_control_fingerprint', 'node_key_epoch', 'candidate_digest', 'expires_at', 'state',
] as const;
const optionalCandidateFields = ['binding_id', 'binding_version'] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const hasOnlyFields = (value: Record<string, unknown>, allowed: readonly string[], required: readonly string[]) =>
  Object.keys(value).every(key => allowed.includes(key)) && required.every(key =>
    Object.prototype.hasOwnProperty.call(value, key));
const hasControl = (value: string): boolean => [...value].some(character => {
  const code = character.charCodeAt(0);
  return code < 0x20 || code === 0x7f;
});
const safeToken = (value: unknown): value is string => typeof value === 'string' &&
  value.length > 0 && value.length <= 256 && value === value.trim() &&
  !/[\\/\s]/.test(value) && !hasControl(value);
const safeVersion = (value: unknown): value is number =>
  Number.isSafeInteger(value) && Number(value) > 0;
const lowerHex256 = (value: unknown): value is string =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const safeName = (value: unknown): value is string => typeof value === 'string' &&
  value.length > 0 && value.length <= 256 && value === value.trim() &&
  !hasControl(value);
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;

function isFutureRfc3339(value: unknown, nowMs: number): value is string {
  if (typeof value !== 'string' || value.length > 64) return false;
  const match = RFC3339.exec(value);
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
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > monthDays[month - 1] ||
      hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && time > nowMs;
}

/** Validate only the documented encrypted Node-Control preview DTO. */
export function nodeControlKeyCandidateFromRpc(
  value: unknown,
  expectedHubId: string,
  nowMs = Date.now(),
): NodeControlKeyCandidate | null {
  if (!isRecord(value) || !hasOnlyFields(value, [...candidateFields, ...optionalCandidateFields], candidateFields) ||
      !safeToken(expectedHubId) || value.hub_id !== expectedHubId ||
      !safeToken(value.request_id) || !safeVersion(value.version) ||
      !['INITIAL', 'UPGRADE'].includes(String(value.mode)) ||
      !safeToken(value.hub_id) || !safeToken(value.node_id) || !safeName(value.node_name) ||
      !safeToken(value.node_key_id) || !lowerHex256(value.node_key_fingerprint) ||
      !safeToken(value.hub_node_control_key_id) || !safeVersion(value.hub_node_control_key_version) ||
      !lowerHex256(value.hub_node_control_fingerprint) || !safeVersion(value.node_key_epoch) ||
      !lowerHex256(value.candidate_digest) || !Number.isFinite(nowMs) ||
      !isFutureRfc3339(value.expires_at, nowMs) || value.state !== 'PENDING') return null;

  const hasBindingId = Object.prototype.hasOwnProperty.call(value, 'binding_id');
  const hasBindingVersion = Object.prototype.hasOwnProperty.call(value, 'binding_version');
  if (hasBindingId !== hasBindingVersion || (hasBindingId &&
      (!safeToken(value.binding_id) || !safeVersion(value.binding_version)))) return null;

  return {
    request_id: value.request_id,
    version: value.version,
    mode: value.mode as NodeControlKeyCandidate['mode'],
    hub_id: value.hub_id,
    node_id: value.node_id,
    node_name: value.node_name,
    node_key_id: value.node_key_id,
    node_key_fingerprint: value.node_key_fingerprint,
    hub_node_control_key_id: value.hub_node_control_key_id,
    hub_node_control_key_version: value.hub_node_control_key_version,
    hub_node_control_fingerprint: value.hub_node_control_fingerprint,
    node_key_epoch: value.node_key_epoch,
    candidate_digest: value.candidate_digest,
    expires_at: value.expires_at,
    state: 'PENDING',
    ...(hasBindingId ? {
      binding_id: value.binding_id as string,
      binding_version: value.binding_version as number,
    } : {}),
  };
}

/** Require byte-for-byte stable documented candidate fields before CAS confirm. */
export function sameNodeControlKeyCandidate(
  left: NodeControlKeyCandidate,
  right: NodeControlKeyCandidate,
): boolean {
  return [...candidateFields, ...optionalCandidateFields].every(key => left[key] === right[key]);
}

function sorted(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string').slice().sort() : [];
}

/** All authority and fence inputs that invalidate a pending Node pairing review. */
export function nodePairingScopeKey(
  status: ClientHubStatus,
  publicCapabilities: ClientHubCapabilities | null,
  sessionCapabilities: ClientHubSessionCapabilities | null,
  apiScope: HubProfileScope,
): string {
  return JSON.stringify([
    apiScope.profileId, apiScope.selectionGeneration,
    status.profileId, status.selectionGeneration, status.activeNetworkId ?? '',
    status.hubId ?? '', status.ownerId ?? '', status.deviceId ?? '', status.sessionEpoch ?? null,
    status.nativeAvailable, status.pinned, status.enrolled, status.remoteEnabled,
    status.sessionCapabilitiesReady, status.authFenced, status.recoveryBlocked === true,
    status.enrollmentRecoveryRequired === true, status.pendingOperationId ?? '',
    status.uncertainNeedsReconciliation === true,
    status.networkGrantReconciliationRequired === true,
    status.regroupReconciliationRequired === true,
    sorted(status.allowedOperations),
    publicCapabilities?.contract_revision ?? '', publicCapabilities?.catalog_sha256 ?? '',
    publicCapabilities?.client_control_pq_e2ee === true,
    publicCapabilities?.authenticated_client_session === true,
    publicCapabilities?.device_binding === true,
    sorted(publicCapabilities?.available_rpc_operations),
    sorted(publicCapabilities?.external_rpc_operations),
    sessionCapabilities?.owner_id ?? '', sessionCapabilities?.role ?? '',
    sessionCapabilities?.contract_revision ?? '', sessionCapabilities?.catalog_sha256 ?? '',
    sorted(sessionCapabilities?.available_rpc_operations),
  ]);
}

/** Public device_binding metadata, encrypted session grants, and local policy must all agree. */
export function nodePairingOperationAllowed(
  status: ClientHubStatus,
  publicCapabilities: ClientHubCapabilities | null,
  sessionCapabilities: ClientHubSessionCapabilities | null,
  apiScope: HubProfileScope,
  operation: NodePairingOperation,
): boolean {
  if (!publicCapabilities || !sessionCapabilities ||
      publicCapabilities.contract_revision !== CLIENT_HUB_REVISION ||
      publicCapabilities.catalog_sha256 !== CLIENT_HUB_CATALOG_SHA256 ||
      publicCapabilities.client_control_pq_e2ee !== true ||
      publicCapabilities.authenticated_client_session !== true ||
      publicCapabilities.device_binding !== true ||
      sessionCapabilities.contract_revision !== CLIENT_HUB_REVISION ||
      sessionCapabilities.catalog_sha256 !== CLIENT_HUB_CATALOG_SHA256 ||
      !['manager', 'external'].includes(sessionCapabilities.role) ||
      !safeToken(status.profileId) || status.profileId !== apiScope.profileId ||
      !Number.isSafeInteger(status.selectionGeneration) ||
      status.selectionGeneration !== apiScope.selectionGeneration ||
      !safeToken(status.hubId) || !safeToken(status.ownerId) || !safeToken(status.deviceId) ||
      !safeVersion(status.sessionEpoch) || sessionCapabilities.owner_id !== status.ownerId ||
      status.nativeAvailable !== true || status.pinned !== true || status.enrolled !== true ||
      status.remoteEnabled !== true || status.sessionCapabilitiesReady !== true ||
      status.authFenced === true || status.recoveryBlocked === true ||
      status.enrollmentRecoveryRequired === true || Boolean(status.pendingOperationId)) return false;

  const publicOperations = sessionCapabilities.role === 'external' ?
    publicCapabilities.external_rpc_operations : publicCapabilities.available_rpc_operations;
  return publicOperations.includes(operation) &&
    sessionCapabilities.available_rpc_operations.includes(operation) &&
    status.allowedOperations.includes(operation) &&
    clientHubOperationAllowed(status, operation);
}

export interface NodePairingRequestToken {
  readonly generation: number;
  readonly scopeKey: string;
}

/** Invalidates callbacks when profile, authority, Network, or lifecycle context changes. */
export class NodePairingLifecycle {
  private generation = 0;

  capture(scopeKey: string): NodePairingRequestToken {
    return {generation: this.generation, scopeKey};
  }

  invalidate(): void {
    this.generation += 1;
  }

  isCurrent(token: NodePairingRequestToken, scopeKey: string): boolean {
    return token.generation === this.generation && token.scopeKey === scopeKey;
  }
}
