import type {
  LinkReviewPolicy, LinkReviewPolicyStatus,
} from './linkReviewPolicyStatus.ts';
import {linkReviewPolicyStatusFromRpc} from './linkReviewPolicyStatus.ts';

/** This candidate has no accepted native proof/current-authority path. */
export const LINK_CONSENT_READY = false as const;
/** Explicit release gate for consumers; no production authority is accepted in this slice. */
export const LINK_CONSENT_RELEASE: null = null;

/** These five pinned RPCs remain rejected by the generic Client Hub facade. */
export const LINK_CONSENT_OPERATIONS = [
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
  'link.review_policy_preview', 'link.review_policy_grant',
] as const;

export type LinkConsentOperation = typeof LINK_CONSENT_OPERATIONS[number];
export type LinkConsentSide = 'SOURCE' | 'TARGET';

const operationSet = new Set<string>(LINK_CONSENT_OPERATIONS);
const statusSet = new Set([
  'MISSING', 'ACCEPTED', 'KEY_BINDING_STALE', 'OWNER_KEY_REVOKED',
  'PROOF_EXPIRED', 'INVALID', 'LEGACY_KEY_UNBOUND',
]);
const sha256Hex = /^[0-9a-f]{64}$/;
function hasControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}
const identifier = (value: unknown, max = 256): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= max &&
  value === value.trim() && !hasControlCharacters(value);
const safeInteger = (value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
const record = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ?
    value as Record<string, unknown> : null;
const exactKeys = (value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) => {
  const allowed = new Set([...required, ...optional]);
  return required.every(key => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every(key => allowed.has(key));
};

/**
 * Checks standard padded Base64 spelling only. It does not decode, authenticate,
 * hash, or cryptographically verify the enclosed bytes.
 */
export function canonicalBase64(value: unknown, maxCharacters = 65_536): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxCharacters ||
      value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return false;
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  if (value.endsWith('==')) return alphabet.indexOf(value[value.length - 3]) % 16 === 0;
  if (value.endsWith('=')) return alphabet.indexOf(value[value.length - 2]) % 4 === 0;
  return true;
}

function base64DecodedByteLength(value: string): number | null {
  if (!canonicalBase64(value)) return null;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

export function linkConsentOperationRequested(operation: unknown): operation is LinkConsentOperation {
  return typeof operation === 'string' && operationSet.has(operation);
}

export interface LinkConsentPublicIdentityWire {
  readonly id: string;
  readonly kem_public: string;
  readonly signing_public: string;
}

/** Wire shape only. It contains no native verification receipt. */
export interface LinkKeyManifestSideWire {
  readonly endpoint_id: string;
  readonly group_id: string;
  readonly principal_id: string;
  readonly owner_id: string;
  readonly node_id: string;
  readonly binding_id: string;
  readonly binding_epoch: number;
  readonly candidate_version: number;
  readonly key_id: string;
  readonly key_fingerprint: string;
  readonly proof_digest: string;
  readonly public_identity: LinkConsentPublicIdentityWire;
  readonly attestation: string;
}

/** Pinned v1.6.1 `link.key_manifest` DTO, still unverified after parsing. */
export interface LinkKeyManifestWire {
  readonly version: 2;
  readonly link_id: string;
  readonly link_version: number;
  readonly contract_digest: string;
  readonly contract_canonical: string;
  readonly source: LinkKeyManifestSideWire;
  readonly target: LinkKeyManifestSideWire;
  readonly digest: string;
}

export type LinkKeyGrantCurrentStatus =
  'MISSING' | 'ACCEPTED' | 'KEY_BINDING_STALE' | 'OWNER_KEY_REVOKED' |
  'PROOF_EXPIRED' | 'INVALID' | 'LEGACY_KEY_UNBOUND';

/** Exact pinned v1.6.1 metadata DTO; it has no retained Owner proof. */
export interface LinkKeyGrantStatusWire {
  readonly link_id: string;
  readonly side: LinkConsentSide;
  readonly owner_id: string;
  readonly key_id?: string;
  readonly manifest_digest?: string;
  readonly accepted: boolean;
  readonly accepted_at?: string;
  readonly current_status: LinkKeyGrantCurrentStatus;
}

/** Internal interpretation is explicit: status metadata alone is not bilateral proof. */
export interface LinkKeyGrantStatusModel {
  readonly wire: LinkKeyGrantStatusWire;
  readonly bilateralVerification: 'UNVERIFIED';
}

export interface LinkReviewPolicyPreviewWire {
  readonly link_id: string;
  readonly side: LinkConsentSide;
  readonly owner_id: string;
  readonly contract_digest: string;
  readonly link_version: number;
  readonly expected_policy_version: number;
  readonly policy_version: number;
  readonly policy_digest: string;
  readonly policy: LinkReviewPolicy;
  readonly maximum_proof_expires_at: string;
}

export type LinkConsentRequest =
  | {readonly operation: 'link.key_manifest'; readonly body: {readonly link_id: string}}
  | {readonly operation: 'link.key_grants'; readonly body: {readonly link_id: string}}
  | {readonly operation: 'link.key_grant'; readonly body: {
      readonly link_id: string; readonly side: LinkConsentSide;
      readonly owner_key_id: string; readonly signed_proof: string;
    }}
  | {readonly operation: 'link.review_policy_preview'; readonly body: {
      readonly link_id: string; readonly policy: LinkReviewPolicy;
    }}
  | {readonly operation: 'link.review_policy_grant'; readonly body: {
      readonly link_id: string; readonly owner_key_id: string;
      readonly expected_policy_version: number; readonly policy: LinkReviewPolicy;
      readonly signed_proof: string;
    }};

export type LinkConsentResponse =
  | {readonly operation: 'link.key_manifest'; readonly result: LinkKeyManifestWire}
  | {readonly operation: 'link.key_grants'; readonly result: readonly LinkKeyGrantStatusModel[]}
  | {readonly operation: 'link.key_grant'; readonly result: LinkKeyGrantStatusModel}
  | {readonly operation: 'link.review_policy_preview'; readonly result: LinkReviewPolicyPreviewWire}
  | {readonly operation: 'link.review_policy_grant'; readonly result: LinkReviewPolicyStatus};

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

function publicIdentityFromRpc(value: unknown): LinkConsentPublicIdentityWire | null {
  const item = record(value);
  if (!item || !exactKeys(item, ['id', 'kem_public', 'signing_public']) ||
      typeof item.id !== 'string' || !/^pq1-[0-9a-f]{32}$/.test(item.id) ||
      !canonicalBase64(item.kem_public, 1_580) || item.kem_public.length !== 1_580 ||
      base64DecodedByteLength(item.kem_public) !== 1_184 ||
      !canonicalBase64(item.signing_public, 2_604) || item.signing_public.length !== 2_604 ||
      base64DecodedByteLength(item.signing_public) !== 1_952) return null;
  return {id: item.id, kem_public: item.kem_public, signing_public: item.signing_public};
}

function keyManifestSideFromRpc(value: unknown): LinkKeyManifestSideWire | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'endpoint_id', 'group_id', 'principal_id', 'owner_id', 'node_id', 'binding_id',
    'binding_epoch', 'candidate_version', 'key_id', 'key_fingerprint', 'proof_digest',
    'public_identity', 'attestation',
  ])) return null;
  const identity = publicIdentityFromRpc(item.public_identity);
  if (!identity || !identifier(item.endpoint_id) || !identifier(item.group_id) ||
      !identifier(item.principal_id) || !identifier(item.owner_id) || !identifier(item.node_id) ||
      !identifier(item.binding_id) || !safeInteger(item.binding_epoch, 1) ||
      !safeInteger(item.candidate_version, 1) || item.key_id !== identity.id ||
      typeof item.key_fingerprint !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(item.key_fingerprint) ||
      typeof item.proof_digest !== 'string' || !sha256Hex.test(item.proof_digest) ||
      !canonicalBase64(item.attestation, 43_692)) return null;
  return {
    endpoint_id: item.endpoint_id, group_id: item.group_id, principal_id: item.principal_id,
    owner_id: item.owner_id, node_id: item.node_id, binding_id: item.binding_id,
    binding_epoch: item.binding_epoch, candidate_version: item.candidate_version,
    key_id: item.key_id, key_fingerprint: item.key_fingerprint, proof_digest: item.proof_digest,
    public_identity: identity, attestation: item.attestation,
  };
}

function keyManifestFromRpc(value: unknown, expectedLinkId: string,
  expectedLinkVersion?: number): LinkKeyManifestWire | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'version', 'link_id', 'link_version', 'contract_digest', 'contract_canonical',
    'source', 'target', 'digest',
  ]) || item.version !== 2 || !identifier(expectedLinkId) ||
      !identifier(item.link_id) || item.link_id !== expectedLinkId ||
      !safeInteger(item.link_version, 1) ||
      (expectedLinkVersion !== undefined && item.link_version !== expectedLinkVersion) ||
      typeof item.contract_digest !== 'string' || !sha256Hex.test(item.contract_digest) ||
      !canonicalBase64(item.contract_canonical, 43_692) ||
      typeof item.digest !== 'string' || !sha256Hex.test(item.digest)) return null;
  const source = keyManifestSideFromRpc(item.source);
  const target = keyManifestSideFromRpc(item.target);
  if (!source || !target || source.endpoint_id === target.endpoint_id) return null;
  return {
    version: 2, link_id: item.link_id, link_version: item.link_version,
    contract_digest: item.contract_digest, contract_canonical: item.contract_canonical,
    source, target, digest: item.digest,
  };
}

function keyGrantStatusFromRpc(value: unknown, expectedLinkId: string): LinkKeyGrantStatusWire | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'link_id', 'side', 'owner_id', 'accepted', 'current_status',
  ], ['key_id', 'manifest_digest', 'accepted_at']) ||
      !identifier(expectedLinkId) || item.link_id !== expectedLinkId ||
      (item.side !== 'SOURCE' && item.side !== 'TARGET') || !identifier(item.owner_id) ||
      typeof item.accepted !== 'boolean' || typeof item.current_status !== 'string' ||
      !statusSet.has(item.current_status) ||
      (Object.prototype.hasOwnProperty.call(item, 'key_id') && !identifier(item.key_id)) ||
      (Object.prototype.hasOwnProperty.call(item, 'manifest_digest') &&
        (typeof item.manifest_digest !== 'string' || !sha256Hex.test(item.manifest_digest))) ||
      (Object.prototype.hasOwnProperty.call(item, 'accepted_at') && !timestamp(item.accepted_at))) return null;
  if (item.current_status === 'ACCEPTED' && item.accepted !== true) return null;
  return {
    link_id: item.link_id, side: item.side, owner_id: item.owner_id,
    ...(typeof item.key_id === 'string' ? {key_id: item.key_id} : {}),
    ...(typeof item.manifest_digest === 'string' ? {manifest_digest: item.manifest_digest} : {}),
    accepted: item.accepted,
    ...(typeof item.accepted_at === 'string' ? {accepted_at: item.accepted_at} : {}),
    current_status: item.current_status as LinkKeyGrantCurrentStatus,
  };
}

function grantStatusModel(wire: LinkKeyGrantStatusWire): LinkKeyGrantStatusModel {
  return Object.freeze({wire: Object.freeze({...wire}), bilateralVerification: 'UNVERIFIED'});
}

function policyFromRpc(value: unknown): LinkReviewPolicy | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'mode', 'reviewers', 'max_failovers', 'reviewer_lease_seconds', 'max_review_age_seconds',
  ]) || (item.mode !== 'NONE' && item.mode !== 'METADATA') || !Array.isArray(item.reviewers) ||
      item.reviewers.length > 8 || !safeInteger(item.max_failovers, 0, 8) ||
      !safeInteger(item.reviewer_lease_seconds, 0, 3_600) ||
      !safeInteger(item.max_review_age_seconds, 0, 86_400)) return null;
  const reviewers: {endpoint_id: string; group_id: string}[] = [];
  const seen = new Set<string>();
  for (const raw of item.reviewers) {
    const reviewer = record(raw);
    if (!reviewer || !exactKeys(reviewer, ['endpoint_id', 'group_id']) ||
        !identifier(reviewer.endpoint_id) || !identifier(reviewer.group_id) ||
        seen.has(reviewer.endpoint_id)) return null;
    seen.add(reviewer.endpoint_id);
    reviewers.push({endpoint_id: reviewer.endpoint_id, group_id: reviewer.group_id});
  }
  if (item.mode === 'NONE' && (reviewers.length > 0 || item.max_failovers !== 0 ||
      item.reviewer_lease_seconds !== 0 || item.max_review_age_seconds !== 0)) return null;
  if (item.mode === 'METADATA' && (reviewers.length === 0 ||
      item.max_failovers > reviewers.length - 1 || item.reviewer_lease_seconds < 30 ||
      item.max_review_age_seconds < 60)) return null;
  return Object.freeze({
    mode: item.mode, reviewers: Object.freeze(reviewers), max_failovers: item.max_failovers,
    reviewer_lease_seconds: item.reviewer_lease_seconds,
    max_review_age_seconds: item.max_review_age_seconds,
  });
}

/** Strict request DTO parser for the five pinned operations; never seals or sends. */
export function linkConsentRequestFromRpc(
  operation: unknown,
  body: unknown,
): LinkConsentRequest | null {
  if (!linkConsentOperationRequested(operation)) return null;
  const item = record(body);
  if (!item) return null;
  if (operation === 'link.key_manifest' || operation === 'link.key_grants') {
    if (!exactKeys(item, ['link_id']) || !identifier(item.link_id)) return null;
    return Object.freeze({operation, body: Object.freeze({link_id: item.link_id})});
  }
  if (operation === 'link.key_grant') {
    if (!exactKeys(item, ['link_id', 'side', 'owner_key_id', 'signed_proof']) ||
        !identifier(item.link_id) || (item.side !== 'SOURCE' && item.side !== 'TARGET') ||
        !identifier(item.owner_key_id) || !canonicalBase64(item.signed_proof, 21_848)) return null;
    return Object.freeze({operation, body: Object.freeze({
      link_id: item.link_id, side: item.side, owner_key_id: item.owner_key_id,
      signed_proof: item.signed_proof,
    })});
  }
  if (operation === 'link.review_policy_preview') {
    const policy = policyFromRpc(item.policy);
    if (!exactKeys(item, ['link_id', 'policy']) || !identifier(item.link_id) || !policy) return null;
    return Object.freeze({operation, body: Object.freeze({link_id: item.link_id, policy})});
  }
  const policy = policyFromRpc(item.policy);
  if (!exactKeys(item, [
    'link_id', 'owner_key_id', 'expected_policy_version', 'policy', 'signed_proof',
  ]) || !identifier(item.link_id) || !identifier(item.owner_key_id) ||
      !safeInteger(item.expected_policy_version, 0, Number.MAX_SAFE_INTEGER - 1) || !policy ||
      !canonicalBase64(item.signed_proof)) return null;
  return Object.freeze({operation, body: Object.freeze({
    link_id: item.link_id, owner_key_id: item.owner_key_id,
    expected_policy_version: item.expected_policy_version, policy,
    signed_proof: item.signed_proof,
  })});
}

function reviewPolicyPreviewFromRpc(value: unknown, expectedLinkId: string,
  expectedLinkVersion?: number): LinkReviewPolicyPreviewWire | null {
  const item = record(value);
  if (!item || !exactKeys(item, [
    'link_id', 'side', 'owner_id', 'contract_digest', 'link_version',
    'expected_policy_version', 'policy_version', 'policy_digest', 'policy',
    'maximum_proof_expires_at',
  ]) || !identifier(expectedLinkId) || item.link_id !== expectedLinkId ||
      (item.side !== 'SOURCE' && item.side !== 'TARGET') || !identifier(item.owner_id) ||
      typeof item.contract_digest !== 'string' || !sha256Hex.test(item.contract_digest) ||
      !safeInteger(item.link_version, 1) ||
      (expectedLinkVersion !== undefined && item.link_version !== expectedLinkVersion) ||
      !safeInteger(item.expected_policy_version, 0, Number.MAX_SAFE_INTEGER - 1) ||
      !safeInteger(item.policy_version, 1) || item.policy_version !== item.expected_policy_version + 1 ||
      typeof item.policy_digest !== 'string' || !sha256Hex.test(item.policy_digest) ||
      !timestamp(item.maximum_proof_expires_at)) return null;
  const policy = policyFromRpc(item.policy);
  if (!policy) return null;
  return Object.freeze({
    link_id: item.link_id, side: item.side, owner_id: item.owner_id,
    contract_digest: item.contract_digest, link_version: item.link_version,
    expected_policy_version: item.expected_policy_version, policy_version: item.policy_version,
    policy_digest: item.policy_digest, policy,
    maximum_proof_expires_at: item.maximum_proof_expires_at,
  });
}

/** Strict pinned-v1.6.1 result parser. No field here claims ML-DSA verification. */
export function linkConsentResponseFromRpc(
  operation: unknown,
  value: unknown,
  expectedLinkId: string,
  expectedLinkVersion?: number,
  expectedSide?: LinkConsentSide,
): LinkConsentResponse | null {
  if (!linkConsentOperationRequested(operation) || !identifier(expectedLinkId)) return null;
  if (operation === 'link.key_manifest') {
    const result = keyManifestFromRpc(value, expectedLinkId, expectedLinkVersion);
    return result ? Object.freeze({operation, result}) : null;
  }
  if (operation === 'link.key_grants') {
    if (!Array.isArray(value) || value.length !== 2) return null;
    const source = keyGrantStatusFromRpc(value[0], expectedLinkId);
    const target = keyGrantStatusFromRpc(value[1], expectedLinkId);
    if (!source || !target || source.side !== 'SOURCE' || target.side !== 'TARGET' ||
        (source.manifest_digest && target.manifest_digest &&
          source.manifest_digest !== target.manifest_digest)) return null;
    return Object.freeze({operation, result: Object.freeze([
      grantStatusModel(source), grantStatusModel(target),
    ])});
  }
  if (operation === 'link.key_grant') {
    const result = keyGrantStatusFromRpc(value, expectedLinkId);
    return result && (expectedSide === undefined || result.side === expectedSide) ?
      Object.freeze({operation, result: grantStatusModel(result)}) : null;
  }
  if (operation === 'link.review_policy_preview') {
    const result = reviewPolicyPreviewFromRpc(value, expectedLinkId, expectedLinkVersion);
    return result ? Object.freeze({operation, result}) : null;
  }
  if (expectedLinkVersion === undefined || !safeInteger(expectedLinkVersion, 1)) return null;
  const result = linkReviewPolicyStatusFromRpc(value, expectedLinkId, expectedLinkVersion);
  return result ? Object.freeze({operation, result}) : null;
}

export interface LinkConsentOwnerKeyReview {
  readonly ownerId: string;
  readonly keyId: string;
  readonly publicIdentity: LinkConsentPublicIdentityWire;
  readonly state: 'ACTIVE';
  readonly version: number;
}

export interface LinkConsentReviewerAuthority {
  readonly endpointId: string;
  readonly groupId: string;
  readonly ownerId: string;
  readonly principalId: string;
  readonly membershipRevision: number;
  readonly endpointVersion: number;
  readonly bindingId: string;
  readonly bindingEpoch: number;
  readonly active: boolean;
  readonly hasLinkReviewPermission: boolean;
}

export interface LinkConsentEndpointAuthority {
  readonly endpointId: string;
  readonly groupId: string;
  readonly principalId: string;
  readonly ownerId: string;
  readonly nodeId: string;
  readonly bindingId: string;
  readonly bindingEpoch: number;
  readonly candidateVersion: number;
  readonly membershipRevision: number;
  readonly joinRevision: number;
  readonly groupVersion: number;
}

/** Internal review context. It is not an RPC DTO and contains no fake native-verification fields. */
export interface LinkConsentReviewScope {
  readonly profileId: string;
  readonly selectionGeneration: number;
  readonly hubId: string;
  readonly ownerId: string;
  readonly deviceId: string;
  readonly sessionEpoch: number;
  readonly linkId: string;
  readonly linkVersion: number;
  readonly linkState: 'PROPOSED';
  readonly linkListGeneration: number;
  readonly topologyGeneration: number;
  readonly side: LinkConsentSide;
  readonly manifest: LinkKeyManifestWire;
  readonly sourceAuthority: LinkConsentEndpointAuthority;
  readonly targetAuthority: LinkConsentEndpointAuthority;
  readonly ownerKey: LinkConsentOwnerKeyReview;
  readonly selectedPolicy: LinkReviewPolicy;
  readonly currentPolicyStatus: LinkReviewPolicyStatus;
  readonly expectedPolicyVersion: number;
  readonly reviewerAuthorities: readonly LinkConsentReviewerAuthority[];
}

export interface LinkConsentReviewCapture {
  readonly scope: LinkConsentReviewScope;
  readonly scopeKey: string;
  readonly explicitlyReviewed: boolean;
}

const genuineReviewCaptures = new WeakSet<object>();

function policyIsValid(policy: LinkReviewPolicy): boolean {
  const parsed = policyFromRpc(policy);
  return parsed !== null;
}

function reviewScopeIsValid(scope: LinkConsentReviewScope): boolean {
  if (!record(scope) || !exactKeys(scope as unknown as Record<string, unknown>, [
    'profileId', 'selectionGeneration', 'hubId', 'ownerId', 'deviceId', 'sessionEpoch',
    'linkId', 'linkVersion', 'linkState', 'linkListGeneration', 'topologyGeneration', 'side',
    'manifest', 'sourceAuthority', 'targetAuthority', 'ownerKey', 'selectedPolicy',
    'currentPolicyStatus', 'expectedPolicyVersion', 'reviewerAuthorities',
  ]) || !identifier(scope.profileId) || !safeInteger(scope.selectionGeneration, 1) ||
      !identifier(scope.hubId) || !identifier(scope.ownerId) || !identifier(scope.deviceId) ||
      !safeInteger(scope.sessionEpoch, 1) || !identifier(scope.linkId) ||
      !safeInteger(scope.linkVersion, 1) || scope.linkState !== 'PROPOSED' ||
      !safeInteger(scope.linkListGeneration, 1) || !safeInteger(scope.topologyGeneration, 1) ||
      (scope.side !== 'SOURCE' && scope.side !== 'TARGET') ||
      !policyIsValid(scope.selectedPolicy) || !Array.isArray(scope.reviewerAuthorities) ||
      !safeInteger(scope.expectedPolicyVersion, 0, Number.MAX_SAFE_INTEGER - 1)) return false;
  const manifest = keyManifestFromRpc(scope.manifest, scope.linkId, scope.linkVersion);
  if (!manifest || manifest.source.endpoint_id === manifest.target.endpoint_id ||
      (scope.side === 'SOURCE' ? manifest.source.owner_id : manifest.target.owner_id) !== scope.ownerId) return false;
  const source = scope.sourceAuthority;
  const target = scope.targetAuthority;
  const endpointAuthorityMatches = (authority: LinkConsentEndpointAuthority,
    side: LinkKeyManifestSideWire) => authority &&
      exactKeys(authority as unknown as Record<string, unknown>, [
        'endpointId', 'groupId', 'principalId', 'ownerId', 'nodeId', 'bindingId',
        'bindingEpoch', 'candidateVersion', 'membershipRevision', 'joinRevision', 'groupVersion',
      ]) && authority.endpointId === side.endpoint_id && authority.groupId === side.group_id &&
      authority.principalId === side.principal_id && authority.ownerId === side.owner_id &&
      authority.nodeId === side.node_id && authority.bindingId === side.binding_id &&
      authority.bindingEpoch === side.binding_epoch && authority.candidateVersion === side.candidate_version &&
      identifier(authority.endpointId) && identifier(authority.groupId) &&
      identifier(authority.principalId) && identifier(authority.ownerId) && identifier(authority.nodeId) &&
      identifier(authority.bindingId) && safeInteger(authority.bindingEpoch, 1) &&
      safeInteger(authority.candidateVersion, 1) && safeInteger(authority.membershipRevision, 1) &&
      safeInteger(authority.joinRevision, 1) && safeInteger(authority.groupVersion, 1);
  if (!endpointAuthorityMatches(source, manifest.source) || !endpointAuthorityMatches(target, manifest.target)) {
    return false;
  }
  const ownerKey = scope.ownerKey;
  if (!ownerKey || !exactKeys(ownerKey as unknown as Record<string, unknown>, [
    'ownerId', 'keyId', 'publicIdentity', 'state', 'version',
  ]) || ownerKey.ownerId !== scope.ownerId || ownerKey.state !== 'ACTIVE' ||
      !safeInteger(ownerKey.version, 1) || !identifier(ownerKey.keyId) ||
      ownerKey.keyId !== ownerKey.publicIdentity?.id ||
      !publicIdentityFromRpc(ownerKey.publicIdentity)) return false;
  const status = scope.currentPolicyStatus;
  if (!status || !exactKeys(status as unknown as Record<string, unknown>, [
    'link_id', 'link_version', 'policy_version', 'policy_digest', 'policy', 'current',
    'accepted_sides', 'unconfigured',
  ], ['expires_at']) || status.link_id !== scope.linkId || status.link_version !== scope.linkVersion ||
      status.policy_version !== scope.expectedPolicyVersion || !status.current) return false;
  const parsedStatus = linkReviewPolicyStatusFromRpc({
    link_id: status.link_id, link_version: status.link_version,
    policy_version: status.policy_version, policy_digest: status.policy_digest,
    policy: status.policy, current: status.current, accepted_sides: status.accepted_sides,
    ...(status.expires_at ? {expires_at: status.expires_at} : {}),
  }, scope.linkId, scope.linkVersion);
  if (!parsedStatus || parsedStatus.unconfigured !== status.unconfigured) return false;

  const selected = scope.selectedPolicy.reviewers;
  if (scope.reviewerAuthorities.length !== selected.length) return false;
  const endpointIds = new Set<string>();
  for (let index = 0; index < selected.length; index += 1) {
    const reviewer = selected[index];
    const authority = scope.reviewerAuthorities[index];
    if (!authority || !exactKeys(authority as unknown as Record<string, unknown>, [
      'endpointId', 'groupId', 'ownerId', 'principalId', 'membershipRevision',
      'endpointVersion', 'bindingId', 'bindingEpoch', 'active', 'hasLinkReviewPermission',
    ]) || authority.endpointId !== reviewer.endpoint_id || authority.groupId !== reviewer.group_id ||
        !identifier(authority.endpointId) || !identifier(authority.groupId) ||
        !identifier(authority.ownerId) || !identifier(authority.principalId) ||
        !safeInteger(authority.membershipRevision, 1) || !safeInteger(authority.endpointVersion, 1) ||
        !identifier(authority.bindingId) || !safeInteger(authority.bindingEpoch, 1) ||
        authority.active !== true || authority.hasLinkReviewPermission !== true ||
        (authority.groupId !== manifest.source.group_id && authority.groupId !== manifest.target.group_id) ||
        endpointIds.has(authority.endpointId)) return false;
    endpointIds.add(authority.endpointId);
  }
  return true;
}

function policyKey(policy: LinkReviewPolicy): unknown[] {
  return [policy.mode, policy.reviewers.map(item => [item.endpoint_id, item.group_id]),
    policy.max_failovers, policy.reviewer_lease_seconds, policy.max_review_age_seconds];
}

function endpointKey(side: LinkKeyManifestSideWire): unknown[] {
  return [side.endpoint_id, side.group_id, side.principal_id, side.owner_id, side.node_id,
    side.binding_id, side.binding_epoch, side.candidate_version, side.key_id,
    side.key_fingerprint, side.proof_digest, side.public_identity.id,
    side.public_identity.kem_public, side.public_identity.signing_public, side.attestation];
}

/** Full capture key. It includes both Endpoint proofs and all reviewer/CAS inputs. */
export function linkConsentReviewScopeKey(scope: LinkConsentReviewScope): string | null {
  if (!reviewScopeIsValid(scope)) return null;
  const status = scope.currentPolicyStatus;
  const endpointAuthorityKey = (item: LinkConsentEndpointAuthority) => [
    item.endpointId, item.groupId, item.principalId, item.ownerId, item.nodeId, item.bindingId,
    item.bindingEpoch, item.candidateVersion, item.membershipRevision, item.joinRevision,
    item.groupVersion,
  ];
  const authority = scope.reviewerAuthorities.map(item => [
    item.endpointId, item.groupId, item.ownerId, item.principalId, item.membershipRevision,
    item.endpointVersion, item.bindingId, item.bindingEpoch, item.active, item.hasLinkReviewPermission,
  ]);
  return JSON.stringify([
    scope.profileId, scope.selectionGeneration, scope.hubId, scope.ownerId, scope.deviceId,
    scope.sessionEpoch, scope.linkId, scope.linkVersion, scope.linkState,
    scope.linkListGeneration, scope.topologyGeneration, scope.side,
    scope.manifest.version, scope.manifest.contract_digest, scope.manifest.contract_canonical,
    scope.manifest.digest, endpointKey(scope.manifest.source), endpointKey(scope.manifest.target),
    endpointAuthorityKey(scope.sourceAuthority), endpointAuthorityKey(scope.targetAuthority),
    scope.ownerKey.ownerId, scope.ownerKey.keyId, scope.ownerKey.publicIdentity.id,
    scope.ownerKey.publicIdentity.kem_public, scope.ownerKey.publicIdentity.signing_public,
    scope.ownerKey.state, scope.ownerKey.version, policyKey(scope.selectedPolicy),
    status.link_id, status.link_version, status.policy_version, status.policy_digest,
    policyKey(status.policy), status.current, [...status.accepted_sides], status.expires_at || '',
    status.unconfigured, scope.expectedPolicyVersion, authority,
  ]);
}

function copyManifest(value: LinkKeyManifestWire): LinkKeyManifestWire {
  const copySide = (side: LinkKeyManifestSideWire): LinkKeyManifestSideWire => Object.freeze({
    ...side, public_identity: Object.freeze({...side.public_identity}),
  });
  return Object.freeze({
    ...value, source: copySide(value.source), target: copySide(value.target),
  });
}

function copyPolicy(value: LinkReviewPolicy): LinkReviewPolicy {
  return Object.freeze({
    ...value,
    reviewers: Object.freeze(value.reviewers.map(reviewer => Object.freeze({...reviewer}))),
  });
}

function copyReviewStatus(value: LinkReviewPolicyStatus): LinkReviewPolicyStatus {
  return Object.freeze({
    ...value, policy: copyPolicy(value.policy), accepted_sides: Object.freeze([...value.accepted_sides]),
  });
}

function copyReviewScope(value: LinkConsentReviewScope): LinkConsentReviewScope {
  return Object.freeze({
    ...value, manifest: copyManifest(value.manifest),
    sourceAuthority: Object.freeze({...value.sourceAuthority}),
    targetAuthority: Object.freeze({...value.targetAuthority}),
    ownerKey: Object.freeze({
      ...value.ownerKey, publicIdentity: Object.freeze({...value.ownerKey.publicIdentity}),
    }),
    selectedPolicy: copyPolicy(value.selectedPolicy),
    currentPolicyStatus: copyReviewStatus(value.currentPolicyStatus),
    reviewerAuthorities: Object.freeze(value.reviewerAuthorities.map(item => Object.freeze({...item}))),
  });
}

export function captureLinkConsentReview(scope: LinkConsentReviewScope): LinkConsentReviewCapture | null {
  const scopeKey = linkConsentReviewScopeKey(scope);
  if (!scopeKey) return null;
  const capture = Object.freeze({scope: copyReviewScope(scope), scopeKey, explicitlyReviewed: false});
  genuineReviewCaptures.add(capture);
  return capture;
}

/** Records only that the exact captured scope was reviewed; it is not approval. */
export function markLinkConsentReviewed(
  capture: LinkConsentReviewCapture,
  currentScope: LinkConsentReviewScope,
  explicitReview: boolean,
): LinkConsentReviewCapture | null {
  if (explicitReview !== true || !genuineReviewCaptures.has(capture) ||
      capture.explicitlyReviewed !== false) return null;
  genuineReviewCaptures.delete(capture);
  if (!captureScopeMatches(capture, currentScope)) return null;
  const reviewed = Object.freeze({...capture, explicitlyReviewed: true});
  genuineReviewCaptures.add(reviewed);
  return reviewed;
}

function captureScopeMatches(
  capture: LinkConsentReviewCapture,
  currentScope: LinkConsentReviewScope,
): boolean {
  const freshKey = linkConsentReviewScopeKey(currentScope);
  return freshKey !== null && freshKey === capture.scopeKey;
}

export function linkConsentReviewIsCurrent(
  capture: LinkConsentReviewCapture,
  currentScope: LinkConsentReviewScope,
): boolean {
  return Boolean(capture && capture.explicitlyReviewed === true &&
    genuineReviewCaptures.has(capture) && captureScopeMatches(capture, currentScope));
}

/**
 * Requires the separate final confirmation and a just-refreshed identical scope.
 * This candidate still cannot release production authority, so the result is always false.
 */
export function linkConsentCanRelease(
  capture: LinkConsentReviewCapture,
  freshScope: LinkConsentReviewScope,
  explicitConfirmation: boolean,
): false {
  const freshAndReviewed = linkConsentReviewIsCurrent(capture, freshScope);
  const confirmed = explicitConfirmation === true;
  return (LINK_CONSENT_READY && freshAndReviewed && confirmed) as false;
}

export type LinkConsentPendingState =
  | 'PENDING' | 'STILL_PROCESSING' | 'UNCERTAIN' | 'RECOVERY_UNAVAILABLE'
  | 'TERMINAL_UNCERTAIN' | 'REVOKED';

/** Opaque encrypted packet plus original operation correlation; never rebuild it after loss. */
export interface LinkConsentExactPacket {
  readonly operation: LinkConsentOperation;
  readonly operationId: string;
  readonly sequence: number;
  readonly packet: string;
}

export interface LinkConsentRecoveryResult {
  readonly operationId: string;
  readonly sequence: number;
  readonly state: 'STILL_PROCESSING' | 'UNCERTAIN' | 'RECOVERY_UNAVAILABLE' |
    'OUTCOME_UNCERTAIN';
}

const terminalFenceStates = new Set<LinkConsentPendingState>([
  'RECOVERY_UNAVAILABLE', 'TERMINAL_UNCERTAIN', 'REVOKED',
]);
const recoveryResultStates = new Set([
  'STILL_PROCESSING', 'UNCERTAIN', 'RECOVERY_UNAVAILABLE',
  'OUTCOME_UNCERTAIN',
]);

/**
 * Pure offline transition model only. The JS object is neither durable pending
 * custody nor authenticated recovery authority; the existing native Session
 * owns those guarantees. This class is not wired to an RPC or bridge.
 */
export class LinkConsentPendingOperation {
  private _state: LinkConsentPendingState = 'PENDING';
  private readonly exact: LinkConsentExactPacket;

  constructor(exact: LinkConsentExactPacket) {
    if (!linkConsentOperationRequested(exact.operation) || !identifier(exact.operationId) ||
        !safeInteger(exact.sequence, 1) || typeof exact.packet !== 'string' ||
        exact.packet.length === 0 || exact.packet.length > 256_000) {
      throw new TypeError('Invalid exact Link consent packet');
    }
    this.exact = Object.freeze({...exact});
  }

  get state(): LinkConsentPendingState { return this._state; }
  get fenced(): boolean { return true; }
  get operationId(): string { return this.exact.operationId; }
  get sequence(): number { return this.exact.sequence; }

  responseLost(): LinkConsentPendingState {
    if (this._state === 'PENDING' || this._state === 'STILL_PROCESSING') this._state = 'UNCERTAIN';
    return this._state;
  }

  /**
   * Applies only a fail-closed model classification. This function does not
   * authenticate Hub/native data, accepts no success state or verification
   * receipt, and can never clear the pending fence. Any future integration must
   * pass classifications only after the native verified adapter accepts them.
   */
  observeRecovery(value: unknown): boolean {
    const result = record(value);
    if (!result || !exactKeys(result, ['operationId', 'sequence', 'state']) ||
        !identifier(result.operationId) || !safeInteger(result.sequence, 1) ||
        typeof result.state !== 'string' || !recoveryResultStates.has(result.state) ||
        result.operationId !== this.exact.operationId || result.sequence !== this.exact.sequence ||
        terminalFenceStates.has(this._state)) return false;
    if (result.state === 'OUTCOME_UNCERTAIN') {
      this._state = 'TERMINAL_UNCERTAIN';
    } else if (result.state === 'STILL_PROCESSING' || result.state === 'UNCERTAIN' ||
        result.state === 'RECOVERY_UNAVAILABLE') {
      this._state = result.state;
    } else {
      return false;
    }
    return true;
  }

  /** Read-only retained bytes for persistence/evidence; callers must never resubmit this consent RPC. */
  retainedPacket(): LinkConsentExactPacket {
    return this.exact;
  }

  /**
   * Exact original correlation/packet for `/rpc/recover` only. This does not
   * authorize resubmitting the original consent RPC after a lost response.
   */
  recoveryPacket(): LinkConsentExactPacket | null {
    if (this._state !== 'STILL_PROCESSING' && this._state !== 'UNCERTAIN') return null;
    return this.exact;
  }

  terminalUncertain(): LinkConsentPendingState {
    this._state = 'TERMINAL_UNCERTAIN';
    return this._state;
  }

  revoke(): LinkConsentPendingState {
    this._state = 'REVOKED';
    return this._state;
  }

  /** A read-only UI snapshot is informational and cannot clear any pending/fenced state. */
  observeSnapshot(_snapshot: unknown): LinkConsentPendingState {
    return this._state;
  }
}
