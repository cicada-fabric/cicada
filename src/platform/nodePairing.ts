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

function isValidRfc3339(value: unknown): value is string {
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
  return Number.isFinite(Date.parse(value));
}

function isFutureRfc3339(value: unknown, nowMs: number): value is string {
  return isValidRfc3339(value) && Date.parse(value) > nowMs;
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
    status.hubId ?? '', status.ownerId ?? '', status.ownerKeyId ?? '', status.deviceId ?? '', status.sessionEpoch ?? null,
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
      !safeToken(status.ownerKeyId) ||
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

export interface NodeControlKeyBinding {
  owner_binding_id: string;
  owner_id: string;
  hub_id: string;
  node_id: string;
  node_name: string;
  client_device_id: string;
  owner_key_id: string;
  node_credential_version: number;
  binding_version: number;
  node_key_id: string;
  node_public_identity: {id: string; kem_public: string; signing_public: string};
  node_key_fingerprint: string;
  node_key_version: number;
  node_key_epoch: number;
  hub_key_id: string;
  hub_public_identity: {id: string; kem_public: string; signing_public: string};
  hub_key_fingerprint: string;
  hub_key_version: number;
  approved_request_id: string;
  approved_request_version: number;
  approved_candidate_digest: string;
  approved_owner_device_id: string;
  approved_owner_key_id: string;
  approved_at: string;
  state: 'ACTIVE';
  version: number;
}

export interface NodeDeviceBinding {
  id: string;
  owner_id: string;
  hub_id: string;
  node_id: string;
  node_name: string;
  client_device_id: string;
  owner_key_id: string;
  node_credential_version: number;
  state: 'ACTIVE' | 'REVOKED';
  authorized: boolean;
  version: number;
  created_at: string;
  updated_at: string;
  revoked_at?: string;
}

const nodeControlBindingFields = [
  'owner_binding_id', 'owner_id', 'hub_id', 'node_id', 'node_name', 'client_device_id', 'owner_key_id',
  'node_credential_version', 'binding_version', 'node_key_id', 'node_public_identity',
  'node_key_fingerprint', 'node_key_version', 'node_key_epoch', 'hub_key_id', 'hub_public_identity',
  'hub_key_fingerprint', 'hub_key_version', 'approved_request_id', 'approved_request_version',
  'approved_candidate_digest', 'approved_owner_device_id', 'approved_owner_key_id', 'approved_at',
  'state', 'version',
] as const;
const nodeDeviceBindingFields = [
  'id', 'owner_id', 'hub_id', 'node_id', 'node_name', 'client_device_id', 'owner_key_id',
  'node_credential_version', 'state', 'authorized', 'version', 'created_at', 'updated_at',
] as const;
const nodeBindingRevokedField = ['revoked_at'] as const;
const MAX_NODE_LIST_BINDINGS = 1024;

function publicIdentityFromRpc(
  value: unknown,
  expectedId: string,
): NodeControlKeyBinding['node_public_identity'] | null {
  if (!isRecord(value) || !hasOnlyFields(value, ['id', 'kem_public', 'signing_public'],
    ['id', 'kem_public', 'signing_public']) || value.id !== expectedId) return null;
  const safePublicBytes = (part: unknown): part is string => typeof part === 'string' && part.length > 0 &&
    part.length <= 16384 && part.length % 4 === 0 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(part);
  if (!safePublicBytes(value.kem_public) || !safePublicBytes(value.signing_public)) return null;
  return {id: expectedId, kem_public: value.kem_public, signing_public: value.signing_public};
}

/**
 * Parse the pinned v1.6.1 nodes.confirm NodeControlKeyBinding result and bind
 * its public approval evidence to the exact fresh preview and current native
 * Hub/Owner/device/key session. Native code separately verifies the public
 * identities and their nodewire fingerprints before accepting the RPC result.
 */
export function nodeControlKeyBindingFromConfirmRpc(
  value: unknown,
  candidate: NodeControlKeyCandidate,
  status: ClientHubStatus,
): NodeControlKeyBinding | null {
  const required = nodeControlBindingFields as readonly string[];
  if (!isRecord(value) || !hasOnlyFields(value, [...required, ...nodeBindingRevokedField], required)) return null;
  const {hubId, ownerId, ownerKeyId, deviceId} = status;
  if (!safeToken(hubId) || !safeToken(ownerId) || !safeToken(ownerKeyId) || !safeToken(deviceId) ||
      !safeVersion(status.sessionEpoch) || candidate.hub_id !== hubId ||
      !safeToken(value.owner_binding_id) || !safeToken(value.owner_id) || value.owner_id !== ownerId ||
      !safeToken(value.hub_id) || value.hub_id !== hubId ||
      !safeToken(value.node_id) || value.node_id !== candidate.node_id ||
      !safeName(value.node_name) || value.node_name !== candidate.node_name ||
      !safeToken(value.client_device_id) || value.client_device_id !== deviceId ||
      !safeToken(value.owner_key_id) || value.owner_key_id !== ownerKeyId ||
      !safeVersion(value.node_credential_version) || !safeVersion(value.binding_version) ||
      !safeToken(value.node_key_id) || value.node_key_id !== candidate.node_key_id ||
      !lowerHex256(value.node_key_fingerprint) || value.node_key_fingerprint !== candidate.node_key_fingerprint ||
      !safeVersion(value.node_key_version) || !safeVersion(value.node_key_epoch) ||
      value.node_key_epoch !== candidate.node_key_epoch ||
      !safeToken(value.hub_key_id) || value.hub_key_id !== candidate.hub_node_control_key_id ||
      !lowerHex256(value.hub_key_fingerprint) || value.hub_key_fingerprint !== candidate.hub_node_control_fingerprint ||
      !safeVersion(value.hub_key_version) || value.hub_key_version !== candidate.hub_node_control_key_version ||
      !safeToken(value.approved_request_id) || value.approved_request_id !== candidate.request_id ||
      !safeVersion(value.approved_request_version) || value.approved_request_version !== candidate.version ||
      !lowerHex256(value.approved_candidate_digest) || value.approved_candidate_digest !== candidate.candidate_digest ||
      !safeToken(value.approved_owner_device_id) || value.approved_owner_device_id !== deviceId ||
      !safeToken(value.approved_owner_key_id) || value.approved_owner_key_id !== ownerKeyId ||
      !isValidRfc3339(value.approved_at) || Date.parse(value.approved_at) > Date.parse(candidate.expires_at) ||
      value.state !== 'ACTIVE' || !safeVersion(value.version) ||
      (Object.prototype.hasOwnProperty.call(value, 'revoked_at') && value.revoked_at !== '')) return null;

  if (candidate.mode === 'UPGRADE') {
    if (!candidate.binding_id || !safeVersion(candidate.binding_version) ||
        value.owner_binding_id !== candidate.binding_id ||
        candidate.binding_version >= Number.MAX_SAFE_INTEGER ||
        value.binding_version !== candidate.binding_version + 1) return null;
  } else if (value.binding_version !== 1) {
    return null;
  }
  const nodeIdentity = publicIdentityFromRpc(value.node_public_identity, candidate.node_key_id);
  const hubIdentity = publicIdentityFromRpc(value.hub_public_identity, candidate.hub_node_control_key_id);
  if (!nodeIdentity || !hubIdentity) return null;

  return {
    owner_binding_id: value.owner_binding_id as string,
    owner_id: ownerId,
    hub_id: hubId,
    node_id: candidate.node_id,
    node_name: candidate.node_name,
    client_device_id: deviceId,
    owner_key_id: ownerKeyId,
    node_credential_version: value.node_credential_version as number,
    binding_version: value.binding_version as number,
    node_key_id: candidate.node_key_id,
    node_public_identity: nodeIdentity,
    node_key_fingerprint: candidate.node_key_fingerprint,
    node_key_version: value.node_key_version as number,
    node_key_epoch: candidate.node_key_epoch,
    hub_key_id: candidate.hub_node_control_key_id,
    hub_public_identity: hubIdentity,
    hub_key_fingerprint: candidate.hub_node_control_fingerprint,
    hub_key_version: candidate.hub_node_control_key_version,
    approved_request_id: candidate.request_id,
    approved_request_version: candidate.version,
    approved_candidate_digest: candidate.candidate_digest,
    approved_owner_device_id: deviceId,
    approved_owner_key_id: ownerKeyId,
    approved_at: value.approved_at as string,
    state: 'ACTIVE',
    version: value.version as number,
  };
}

function nodeDeviceBindingFromRpc(value: unknown): NodeDeviceBinding | null {
  const required = nodeDeviceBindingFields as readonly string[];
  if (!isRecord(value) || !hasOnlyFields(value, [...required, ...nodeBindingRevokedField], required) ||
      !safeToken(value.id) || !safeToken(value.owner_id) || !safeToken(value.hub_id) ||
      !safeToken(value.node_id) || !safeName(value.node_name) || !safeToken(value.client_device_id) ||
      !safeToken(value.owner_key_id) || !safeVersion(value.node_credential_version) ||
      !['ACTIVE', 'REVOKED'].includes(String(value.state)) || typeof value.authorized !== 'boolean' ||
      !safeVersion(value.version) ||
      !isValidRfc3339(value.created_at) || !isValidRfc3339(value.updated_at) ||
      (Object.prototype.hasOwnProperty.call(value, 'revoked_at') && value.revoked_at !== '' &&
        !isValidRfc3339(value.revoked_at))) return null;
  return {
    id: value.id, owner_id: value.owner_id, hub_id: value.hub_id, node_id: value.node_id,
    node_name: value.node_name, client_device_id: value.client_device_id, owner_key_id: value.owner_key_id,
    node_credential_version: value.node_credential_version, state: value.state as NodeDeviceBinding['state'],
    authorized: value.authorized, version: value.version, created_at: value.created_at,
    updated_at: value.updated_at,
    ...(typeof value.revoked_at === 'string' ? {revoked_at: value.revoked_at} : {}),
  };
}

/** Match the separate owner credential projection returned by nodes.list. */
export function nodeDeviceBindingFromList(
  value: unknown,
  confirmed: NodeControlKeyBinding,
  status: ClientHubStatus,
): NodeDeviceBinding | null {
  if (!Array.isArray(value) || value.length > MAX_NODE_LIST_BINDINGS ||
      !safeToken(status.ownerId) || !safeToken(status.hubId) || !safeToken(status.ownerKeyId) ||
      !safeToken(status.deviceId) || !safeVersion(status.sessionEpoch) ||
      confirmed.owner_id !== status.ownerId || confirmed.hub_id !== status.hubId ||
      confirmed.owner_key_id !== status.ownerKeyId || confirmed.client_device_id !== status.deviceId) return null;
  const seen = new Set<string>();
  let match: NodeDeviceBinding | null = null;
  for (const raw of value) {
    const binding = nodeDeviceBindingFromRpc(raw);
    if (!binding || seen.has(binding.id)) return null;
    seen.add(binding.id);
    if (binding.id === confirmed.owner_binding_id) match = binding;
  }
  if (!match || match.owner_id !== confirmed.owner_id || match.hub_id !== confirmed.hub_id ||
      match.node_id !== confirmed.node_id || match.node_name !== confirmed.node_name ||
      match.client_device_id !== confirmed.client_device_id || match.owner_key_id !== confirmed.owner_key_id ||
      match.node_credential_version !== confirmed.node_credential_version ||
      match.version !== confirmed.binding_version || match.state !== 'ACTIVE' || !match.authorized) return null;
  return match;
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
