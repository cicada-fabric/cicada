import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus, HubProfileScope,
} from './clientHub.ts';
import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from './clientHubContract.ts';

export const LINK_REVIEW_POLICY_STATUS_OPERATION = 'link.review_policy_status' as const;

export interface LinkReviewPolicyReviewer {
  readonly endpoint_id: string;
  readonly group_id: string;
}

export interface LinkReviewPolicy {
  readonly mode: 'NONE' | 'METADATA';
  readonly reviewers: readonly LinkReviewPolicyReviewer[];
  readonly max_failovers: number;
  readonly reviewer_lease_seconds: number;
  readonly max_review_age_seconds: number;
}

export interface LinkReviewPolicyStatus {
  readonly link_id: string;
  readonly link_version: number;
  readonly policy_version: number;
  readonly policy_digest: string;
  readonly policy: LinkReviewPolicy;
  readonly current: boolean;
  readonly accepted_sides: readonly ('SOURCE' | 'TARGET')[];
  readonly expires_at?: string;
  readonly unconfigured: boolean;
}

export interface LinkReviewPolicyAuthorityInput {
  readonly status: ClientHubStatus;
  readonly publicCapabilities: ClientHubCapabilities | null;
  readonly sessionCapabilities: ClientHubSessionCapabilities | null;
  readonly apiScope: HubProfileScope;
  readonly linkId: string;
  readonly linkVersion: number;
  readonly listGeneration: number;
  readonly bridgeReady: boolean;
}

export interface LinkReviewPolicyStatusCapture {
  readonly scopeKey: string;
  readonly generation: number;
}

const record = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ?
    value as Record<string, unknown> : null;
const hasControl = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
};
const identifier = (value: unknown): value is string => typeof value === 'string' &&
  value.length > 0 && value.length <= 256 && value === value.trim() && !hasControl(value);
const safeInteger = (value: unknown, min: number, max: number): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
const exactKeys = (value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) => {
  const allowed = new Set([...required, ...optional]);
  return required.every(key => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every(key => allowed.has(key));
};
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
function policyFromRpc(value: unknown): LinkReviewPolicy | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'mode', 'reviewers', 'max_failovers', 'reviewer_lease_seconds', 'max_review_age_seconds',
  ]) || (item.mode !== 'NONE' && item.mode !== 'METADATA') || !Array.isArray(item.reviewers) ||
      item.reviewers.length > 8 || !safeInteger(item.max_failovers, 0, 8) ||
      !safeInteger(item.reviewer_lease_seconds, 0, 3600) ||
      !safeInteger(item.max_review_age_seconds, 0, 86400)) return null;
  const reviewers: LinkReviewPolicyReviewer[] = [];
  const reviewerEndpointIds = new Set<string>();
  for (const raw of item.reviewers) {
    const reviewer = record(raw);
    if (!reviewer || !exactKeys(reviewer, ['endpoint_id', 'group_id']) ||
        !identifier(reviewer.endpoint_id) || !identifier(reviewer.group_id)) return null;
    if (reviewerEndpointIds.has(reviewer.endpoint_id)) return null;
    reviewerEndpointIds.add(reviewer.endpoint_id);
    reviewers.push({endpoint_id: reviewer.endpoint_id, group_id: reviewer.group_id});
  }
  if (item.mode === 'NONE' && (reviewers.length !== 0 || item.max_failovers !== 0 ||
      item.reviewer_lease_seconds !== 0 || item.max_review_age_seconds !== 0)) return null;
  if (item.mode === 'METADATA' && (reviewers.length === 0 ||
      item.max_failovers > reviewers.length - 1 || item.reviewer_lease_seconds < 30 ||
      item.max_review_age_seconds < 60)) return null;
  return {
    mode: item.mode as LinkReviewPolicy['mode'], reviewers,
    max_failovers: item.max_failovers, reviewer_lease_seconds: item.reviewer_lease_seconds,
    max_review_age_seconds: item.max_review_age_seconds,
  };
}

/** Parses only the pinned v1.6.1 public metadata DTO and binds it to one fresh link.list row. */
export function linkReviewPolicyStatusFromRpc(value: unknown, expectedLinkId: string,
  expectedLinkVersion: number): LinkReviewPolicyStatus | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'link_id', 'link_version', 'policy_version', 'policy_digest', 'policy', 'current', 'accepted_sides',
  ], ['expires_at']) || !identifier(expectedLinkId) || !safeInteger(expectedLinkVersion, 1, Number.MAX_SAFE_INTEGER) ||
      !identifier(item.link_id) || item.link_id !== expectedLinkId ||
      !safeInteger(item.link_version, 1, Number.MAX_SAFE_INTEGER) || item.link_version !== expectedLinkVersion ||
      !safeInteger(item.policy_version, 0, Number.MAX_SAFE_INTEGER) ||
      typeof item.policy_digest !== 'string' || item.policy_digest.length > 64 ||
      typeof item.current !== 'boolean' || !Array.isArray(item.accepted_sides) || item.accepted_sides.length > 2 ||
      (Object.prototype.hasOwnProperty.call(item, 'expires_at') && !timestamp(item.expires_at))) return null;
  const policy = policyFromRpc(item.policy);
  if (!policy) return null;
  const acceptedSides: ('SOURCE' | 'TARGET')[] = [];
  for (const side of item.accepted_sides) {
    if ((side !== 'SOURCE' && side !== 'TARGET') || acceptedSides.includes(side)) return null;
    acceptedSides.push(side);
  }

  const unconfigured = item.policy_version === 0;
  if (unconfigured) {
    if (item.policy_digest !== '' || policy.mode !== 'NONE' || !item.current || acceptedSides.length !== 0 ||
        Object.prototype.hasOwnProperty.call(item, 'expires_at')) return null;
  } else if (!/^[0-9a-f]{64}$/.test(item.policy_digest)) return null;

  return {
    link_id: item.link_id, link_version: item.link_version,
    policy_version: item.policy_version, policy_digest: item.policy_digest,
    policy, current: item.current, accepted_sides: acceptedSides,
    ...(typeof item.expires_at === 'string' ? {expires_at: item.expires_at} : {}),
    unconfigured,
  };
}

const operationHas = (value: unknown, operation: string): boolean =>
  Array.isArray(value) && value.includes(operation);

/** Exact public + encrypted capability gate for this read-only metadata operation. */
export function linkReviewPolicyStatusCanRead(status: ClientHubStatus,
  publicCapabilities: ClientHubCapabilities | null,
  sessionCapabilities: ClientHubSessionCapabilities | null,
  apiScope: HubProfileScope, bridgeReady: boolean): boolean {
  if (!linkReviewPolicyStatusSupported(status, publicCapabilities, sessionCapabilities, apiScope, bridgeReady) ||
      status.nativeAvailable !== true || status.pinned !== true || status.enrolled !== true ||
      status.remoteEnabled !== true || status.sessionCapabilitiesReady !== true || status.authFenced === true ||
      status.recoveryBlocked === true || status.enrollmentRecoveryRequired === true || Boolean(status.pendingOperationId)) {
    return false;
  }
  return status.allowedOperations.includes(LINK_REVIEW_POLICY_STATUS_OPERATION);
}

/** Capability/API availability controls whether the section exists at all. */
export function linkReviewPolicyStatusSupported(status: ClientHubStatus,
  publicCapabilities: ClientHubCapabilities | null,
  sessionCapabilities: ClientHubSessionCapabilities | null,
  apiScope: HubProfileScope, bridgeReady: boolean): boolean {
  if (bridgeReady !== true || !identifier(status.profileId) ||
      !safeInteger(status.selectionGeneration, 1, Number.MAX_SAFE_INTEGER) ||
      apiScope.profileId !== status.profileId || apiScope.selectionGeneration !== status.selectionGeneration ||
      !identifier(status.hubId) || !identifier(status.ownerId) || !identifier(status.deviceId) ||
      !safeInteger(status.sessionEpoch, 1, Number.MAX_SAFE_INTEGER) ||
      !publicCapabilities || publicCapabilities.contract_revision !== CLIENT_HUB_REVISION ||
      publicCapabilities.catalog_sha256 !== CLIENT_HUB_CATALOG_SHA256 ||
      publicCapabilities.client_control_pq_e2ee !== true || publicCapabilities.authenticated_client_session !== true ||
      !sessionCapabilities || sessionCapabilities.contract_revision !== CLIENT_HUB_REVISION ||
      sessionCapabilities.catalog_sha256 !== CLIENT_HUB_CATALOG_SHA256 ||
      sessionCapabilities.owner_id !== status.ownerId || !['manager', 'external'].includes(sessionCapabilities.role)) {
    return false;
  }
  const publicOperations = sessionCapabilities.role === 'external' ?
    publicCapabilities.external_rpc_operations : publicCapabilities.available_rpc_operations;
  return (!status.role || status.role === sessionCapabilities.role) &&
    operationHas(publicOperations, LINK_REVIEW_POLICY_STATUS_OPERATION) &&
    operationHas(sessionCapabilities.available_rpc_operations, LINK_REVIEW_POLICY_STATUS_OPERATION);
}

function sortedStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string').slice().sort() : [];
}

/** Scope is intentionally broader than link_id: old callbacks cannot cross profile, device, cap, or list changes. */
export function linkReviewPolicyStatusScopeKey(input: LinkReviewPolicyAuthorityInput): string {
  const {status, publicCapabilities, sessionCapabilities, apiScope, linkId, linkVersion,
    listGeneration, bridgeReady} = input;
  const role = sessionCapabilities?.role;
  const publicOperations = role === 'external' ? publicCapabilities?.external_rpc_operations :
    publicCapabilities?.available_rpc_operations;
  return JSON.stringify([
    apiScope.profileId, apiScope.selectionGeneration, status.profileId, status.selectionGeneration,
    status.hubId, status.ownerId, status.deviceId, status.sessionEpoch, status.role,
    status.nativeAvailable, status.pinned, status.enrolled, status.remoteEnabled,
    status.sessionCapabilitiesReady, status.authFenced, status.recoveryBlocked,
    status.enrollmentRecoveryRequired, status.pendingOperationId || '', status.uncertainNeedsReconciliation,
    status.outcomeUncertainOperationId || '', sortedStrings(status.allowedOperations),
    publicCapabilities?.contract_revision || '', publicCapabilities?.catalog_sha256 || '',
    publicCapabilities?.client_control_pq_e2ee, publicCapabilities?.authenticated_client_session,
    sortedStrings(publicOperations), sessionCapabilities?.owner_id || '', role || '',
    sessionCapabilities?.contract_revision || '', sessionCapabilities?.catalog_sha256 || '',
    sortedStrings(sessionCapabilities?.available_rpc_operations),
    linkId, linkVersion, listGeneration, bridgeReady,
  ]);
}

/** Synchronous generation fence for async reads and app backgrounding. */
export class LinkReviewPolicyStatusLifecycle {
  private generation = 0;

  capture(scopeKey: string): LinkReviewPolicyStatusCapture {
    return {scopeKey, generation: this.generation};
  }

  invalidate(): void {
    this.generation += 1;
  }

  isCurrent(capture: LinkReviewPolicyStatusCapture, scopeKey: string, foreground: boolean): boolean {
    return foreground && capture.generation === this.generation && capture.scopeKey === scopeKey;
  }
}
