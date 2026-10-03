import {LINK_CONSENT_READY, LINK_CONSENT_OPERATIONS, canonicalBase64} from './linkConsent.ts';
import {CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION} from './clientHubContract.ts';
import type {LinkReviewPolicy} from './linkReviewPolicyStatus.ts';
import type {ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus, HubProfileScope} from './clientHub.ts';

export type LinkConsentKind = 'KEY' | 'REVIEW_POLICY';

/** Fixed, sanitized preparation outcomes for the Link consent UI and UI automation. */
export const LINK_CONSENT_PREPARE_STAGES = [
  'PREPARING',
  'REVIEW_READY',
  'PREPARE_API_REJECTED',
  'DTO_REJECTED',
  'REVIEW_INVALIDATED',
] as const;

export type LinkConsentPrepareStage = typeof LINK_CONSENT_PREPARE_STAGES[number];

export interface LinkConsentPrepareStatus {
  readonly accessibilityLabel: `CICADA_LINK_PREPARE:${LinkConsentPrepareStage}`;
  readonly text: string;
}

const linkConsentPrepareStatusByStage: Record<LinkConsentPrepareStage, LinkConsentPrepareStatus> = {
  PREPARING: {
    accessibilityLabel: 'CICADA_LINK_PREPARE:PREPARING',
    text: '正在读取当前证明…',
  },
  REVIEW_READY: {
    accessibilityLabel: 'CICADA_LINK_PREPARE:REVIEW_READY',
    text: '当前证明已读取，请核对双方身份、范围与到期时间。',
  },
  PREPARE_API_REJECTED: {
    accessibilityLabel: 'CICADA_LINK_PREPARE:PREPARE_API_REJECTED',
    text: '未获得可确认的证明。请核对双方 Owner 公钥固定和当前 Endpoint 绑定后重新读取。',
  },
  DTO_REJECTED: {
    accessibilityLabel: 'CICADA_LINK_PREPARE:DTO_REJECTED',
    text: '无法安全确认当前证明。请核对双方 Owner 公钥固定和当前 Endpoint 绑定后重新读取。',
  },
  REVIEW_INVALIDATED: {
    accessibilityLabel: 'CICADA_LINK_PREPARE:REVIEW_INVALIDATED',
    text: '当前证明已失效，请重新读取。',
  },
};

/** Unknown values, including exception text, never become UI or accessibility output. */
export function linkConsentPrepareStatus(stage: unknown): LinkConsentPrepareStatus | null {
  return typeof stage === 'string' && Object.prototype.hasOwnProperty.call(linkConsentPrepareStatusByStage, stage) ?
    linkConsentPrepareStatusByStage[stage as LinkConsentPrepareStage] : null;
}

/** Native Long values cross this boundary as canonical decimal strings. */
export interface LinkReviewerQualification {
  readonly endpointId: string;
  readonly groupId: string;
  readonly membershipRevision: string;
  readonly joinRevision: string;
  readonly groupVersion: string;
  readonly bindingId: string;
  readonly bindingEpoch: string;
  readonly leaseExpiresAt: string;
  readonly action: 'link.review';
}

/** Display receipt from the native verifier; JavaScript does not verify Owner proofs. */
export interface LinkConsentReview {
  readonly reviewId: string;
  readonly consentDigest: string;
  readonly linkId: string;
  readonly linkVersion: string;
  readonly side: 'SOURCE' | 'TARGET';
  readonly manifestDigest: string;
  readonly contractDigest: string;
  readonly sourceEndpointId: string;
  readonly sourceGroupId: string;
  readonly targetEndpointId: string;
  readonly targetGroupId: string;
  readonly direction: string;
  readonly actions: readonly string[];
  readonly dataScopes: readonly string[];
  readonly expiresAt: string;
  readonly sourceKeyFingerprint: string;
  readonly targetKeyFingerprint: string;
  readonly policyDigest?: string;
  readonly policyVersion?: string;
  readonly maximumProofExpiresAt: string;
  readonly ownerKeyId: string;
  readonly ownerKeyFingerprint: string;
  readonly peerOwnerKeyFingerprint: string;
  readonly qualifications: readonly LinkReviewerQualification[];
  readonly signingRequestJson: string;
  readonly currentPolicyStatus?: {
    readonly policyVersion: string;
    readonly digest: string;
    readonly current: boolean;
    readonly sourceStatus: string;
    readonly targetStatus: string;
    readonly bilateralVerified: boolean;
  };
}

export interface LinkConsentNativeApi {
  prepareLinkConsent(input: {linkId: string; expectedLinkVersion: number;
    kind: LinkConsentKind; policy?: LinkReviewPolicy}): Promise<unknown>;
  confirmLinkOwnerPin(input: {ownerId: string; publicIdentityJson: string;
    expectedFingerprint: string; confirmed: true}): Promise<unknown>;
  submitLinkConsent(input: {reviewId: string; consentDigest: string;
    signedProofBase64: string; confirmed: true}): Promise<unknown>;
  readLinkKeyGrants(input: {linkId: string; expectedLinkVersion: number}): Promise<unknown>;
  recoverLinkConsent(): Promise<unknown>;
}

export interface LinkConsentApi extends LinkConsentNativeApi {
  readonly linkConsentReady: boolean;
}

/** Capability claims cannot open a closed build or cross a selected profile. */
export function linkConsentCapabilitiesAllow(status: ClientHubStatus,
  capabilities: ClientHubCapabilities | null, session: ClientHubSessionCapabilities | null,
  scope: HubProfileScope, nativeReady: boolean): boolean {
  if (!nativeReady || status.nativeAvailable !== true || !status.pinned || !status.enrolled ||
      !status.sessionCapabilitiesReady || status.authFenced ||
      status.profileId !== scope.profileId || status.selectionGeneration !== scope.selectionGeneration ||
      !capabilities || capabilities.contract_revision !== CLIENT_HUB_REVISION ||
      capabilities.catalog_sha256 !== CLIENT_HUB_CATALOG_SHA256 ||
      capabilities.client_control_pq_e2ee !== true || capabilities.authenticated_client_session !== true ||
      capabilities.link_key_consent !== true || !session || session.contract_revision !== CLIENT_HUB_REVISION ||
      session.catalog_sha256 !== CLIENT_HUB_CATALOG_SHA256 || session.owner_id !== status.ownerId ||
      !['manager', 'external'].includes(session.role) || status.role !== session.role) return false;
  const advertised = session.role === 'external' ? capabilities.external_rpc_operations :
    capabilities.available_rpc_operations;
  return ([...LINK_CONSENT_OPERATIONS, 'link.review_policy_status'] as const).every(operation =>
    advertised?.includes(operation) && session.available_rpc_operations?.includes(operation) &&
    status.allowedOperations.includes(operation));
}

/** A closed release cannot be opened by bridge presence or Hub capability claims. */
export function createLinkConsentApi(native: Partial<LinkConsentNativeApi> | undefined): LinkConsentApi {
  const unavailable = (): Promise<never> => Promise.reject(new Error('VERIFIED_LINK_CONSENT_FLOW_NOT_READY'));
  const methods = ['prepareLinkConsent', 'confirmLinkOwnerPin', 'submitLinkConsent',
    'readLinkKeyGrants', 'recoverLinkConsent'] as const;
  const ready = LINK_CONSENT_READY && Boolean(native && methods.every(name => typeof native[name] === 'function'));
  return {
    linkConsentReady: ready,
    prepareLinkConsent: input => ready && native?.prepareLinkConsent ? native.prepareLinkConsent(input) : unavailable(),
    confirmLinkOwnerPin: input => ready && native?.confirmLinkOwnerPin ? native.confirmLinkOwnerPin(input) : unavailable(),
    submitLinkConsent: input => ready && native?.submitLinkConsent ? native.submitLinkConsent(input) : unavailable(),
    readLinkKeyGrants: input => ready && native?.readLinkKeyGrants ? native.readLinkKeyGrants(input) : unavailable(),
    recoverLinkConsent: () => ready && native?.recoverLinkConsent ? native.recoverLinkConsent() : unavailable(),
  };
}

const object = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ?
    value as Record<string, unknown> : null;
const identifier = (value: unknown): value is string => typeof value === 'string' &&
  value.length > 0 && value.length <= 256 && value === value.trim() &&
  !Array.from(value).some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
const decimal = (value: unknown): value is string => typeof value === 'string' &&
  /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 9223372036854775807n;
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const fingerprint = (value: unknown): value is string =>
  typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const utc = (value: unknown): value is string => typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.[0-9]{1,9})?Z$/.test(value) &&
  Number.isFinite(Date.parse(value));
const exactFields = (row: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) =>
  required.every(key => Object.prototype.hasOwnProperty.call(row, key)) &&
  Object.keys(row).every(key => required.includes(key) || optional.includes(key));

/** Only a bounded display DTO. Its origin must be the dedicated native method. */
export function linkConsentReviewFromNative(value: unknown, expectedLinkId: string,
  expectedLinkVersion: number): LinkConsentReview | null {
  const row = object(value);
  if (!row || !exactFields(row, ['reviewId', 'consentDigest', 'linkId', 'linkVersion', 'side',
      'manifestDigest', 'contractDigest', 'sourceEndpointId', 'sourceGroupId', 'targetEndpointId',
      'targetGroupId', 'direction', 'actions', 'dataScopes', 'expiresAt', 'sourceKeyFingerprint',
      'targetKeyFingerprint', 'maximumProofExpiresAt', 'ownerKeyId', 'ownerKeyFingerprint',
      'peerOwnerKeyFingerprint', 'qualifications', 'signingRequestJson'], ['policyDigest', 'policyVersion', 'currentPolicyStatus']) ||
      !Number.isSafeInteger(expectedLinkVersion) || expectedLinkVersion < 1 ||
      !identifier(row.reviewId) || !digest(row.consentDigest) || row.linkId !== expectedLinkId ||
      !decimal(row.linkVersion) || row.linkVersion !== String(expectedLinkVersion) ||
      !['SOURCE', 'TARGET'].includes(String(row.side)) || !digest(row.manifestDigest) ||
      !digest(row.contractDigest) || !utc(row.maximumProofExpiresAt) ||
      !identifier(row.sourceEndpointId) || !identifier(row.sourceGroupId) ||
      !identifier(row.targetEndpointId) || !identifier(row.targetGroupId) || !identifier(row.direction) ||
      !Array.isArray(row.actions) || !row.actions.length || row.actions.length > 32 || !row.actions.every(identifier) ||
      !Array.isArray(row.dataScopes) || !row.dataScopes.length || row.dataScopes.length > 32 || !row.dataScopes.every(identifier) ||
      !utc(row.expiresAt) || !fingerprint(row.sourceKeyFingerprint) || !fingerprint(row.targetKeyFingerprint) ||
      !identifier(row.ownerKeyId) || !fingerprint(row.ownerKeyFingerprint) ||
      !fingerprint(row.peerOwnerKeyFingerprint) || !Array.isArray(row.qualifications) ||
      row.qualifications.length > 8 || typeof row.signingRequestJson !== 'string' ||
      row.signingRequestJson.length === 0 || row.signingRequestJson.length > 16_384 ||
      (row.policyDigest !== undefined && !digest(row.policyDigest)) ||
      (row.policyVersion !== undefined && !decimal(row.policyVersion)) ||
      (row.policyDigest === undefined) !== (row.policyVersion === undefined)) return null;
  if (row.currentPolicyStatus !== undefined) {
    const head = object(row.currentPolicyStatus);
    const states = ['MISSING', 'VERIFIED', 'OWNER_KEY_REVOKED', 'PROOF_EXPIRED', 'SCOPE_STALE', 'INVALID'];
    if (!head || row.policyVersion === undefined ||
        !exactFields(head, ['policyVersion', 'digest', 'current', 'sourceStatus', 'targetStatus', 'bilateralVerified']) ||
        (head.policyVersion !== '0' && !decimal(head.policyVersion)) ||
        (head.policyVersion === '0' ? head.digest !== '' : !digest(head.digest)) ||
        typeof head.current !== 'boolean' || typeof head.bilateralVerified !== 'boolean' ||
        !states.includes(String(head.sourceStatus)) || !states.includes(String(head.targetStatus)) ||
        (head.bilateralVerified && (!head.current || head.sourceStatus !== 'VERIFIED' ||
          head.targetStatus !== 'VERIFIED' || head.policyVersion === '0'))) return null;
  }
  const qualifications: LinkReviewerQualification[] = [];
  const endpoints = new Set<string>();
  for (const raw of row.qualifications) {
    const q = object(raw);
    if (!q || !exactFields(q, ['endpointId', 'groupId', 'membershipRevision', 'joinRevision',
        'groupVersion', 'bindingId', 'bindingEpoch', 'leaseExpiresAt', 'action']) ||
        !identifier(q.endpointId) || !identifier(q.groupId) ||
        endpoints.has(q.endpointId) || !decimal(q.membershipRevision) || !decimal(q.joinRevision) ||
        !decimal(q.groupVersion) || !identifier(q.bindingId) || !decimal(q.bindingEpoch) ||
        !utc(q.leaseExpiresAt) || q.action !== 'link.review') return null;
    endpoints.add(q.endpointId);
    qualifications.push({...q} as unknown as LinkReviewerQualification);
  }
  return {...row, qualifications} as unknown as LinkConsentReview;
}

export interface LinkKeyGrantReceipt {
  readonly linkId: string;
  readonly linkVersion: string;
  readonly sourceStatus: {readonly side: 'SOURCE'; readonly currentStatus: string; readonly accepted: boolean};
  readonly targetStatus: {readonly side: 'TARGET'; readonly currentStatus: string; readonly accepted: boolean};
  readonly bilateralVerified: boolean;
}

export function linkKeyGrantReceiptFromNative(value: unknown, linkId: string,
  linkVersion: number): LinkKeyGrantReceipt | null {
  const row = object(value);
  const source = object(row?.sourceStatus);
  const target = object(row?.targetStatus);
  const states = new Set(['MISSING', 'ACCEPTED', 'KEY_BINDING_STALE', 'OWNER_KEY_REVOKED',
    'PROOF_EXPIRED', 'INVALID', 'LEGACY_KEY_UNBOUND']);
  if (!row || row.linkId !== linkId || row.linkVersion !== String(linkVersion) ||
      typeof row.bilateralVerified !== 'boolean' || !source || !target ||
      source.side !== 'SOURCE' || target.side !== 'TARGET' ||
      typeof source.accepted !== 'boolean' || typeof target.accepted !== 'boolean' ||
      !states.has(String(source.currentStatus)) || !states.has(String(target.currentStatus)) ||
      (row.bilateralVerified && (source.currentStatus !== 'ACCEPTED' || target.currentStatus !== 'ACCEPTED' ||
        !source.accepted || !target.accepted))) return null;
  return row as unknown as LinkKeyGrantReceipt;
}

/** Bounded external proof only; no signing key material is accepted by this flow. */
export function linkOwnerProofInputValid(proof: string): boolean {
  return canonicalBase64(proof, 21_848) &&
    proof.length / 4 * 3 - (proof.endsWith('==') ? 2 : proof.endsWith('=') ? 1 : 0) <= 16_384;
}

export function linkConsentUiScope(scope: HubProfileScope, linkId: string,
  linkVersion: number, listGeneration: number): string {
  return JSON.stringify([scope.profileId, scope.selectionGeneration, linkId, linkVersion, listGeneration]);
}

/** UI freshness only. Pending ciphertext and uncertain outcomes remain in native custody. */
export class LinkConsentReviewLifecycle {
  private generation = 0;
  private active: {generation: number; scope: string; review: LinkConsentReview} | null = null;

  capture(): number { return this.generation; }
  invalidate(): void { this.generation += 1; this.active = null; }
  receive(generation: number, scope: string, currentScope: string, review: LinkConsentReview): boolean {
    if (generation !== this.generation || scope !== currentScope) return false;
    this.active = {generation, scope, review};
    return true;
  }
  consume(scope: string, reviewId: string, consentDigest: string, now: number): LinkConsentReview | null {
    const active = this.active;
    if (!active || active.generation !== this.generation || active.scope !== scope ||
        active.review.reviewId !== reviewId || active.review.consentDigest !== consentDigest ||
        !Number.isFinite(now) || now >= Date.parse(active.review.maximumProofExpiresAt) ||
        active.review.qualifications.some(q => now >= Date.parse(q.leaseExpiresAt))) return null;
    this.invalidate();
    return active.review;
  }
}
