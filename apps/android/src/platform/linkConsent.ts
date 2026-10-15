/** Dedicated Link consent flow; native proof and capability gates still apply. */
export const LINK_CONSENT_READY = true as const;

/** Generic RPC must refuse these operations even in an enabled native build. */
export const LINK_CONSENT_OPERATIONS = [
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
  'link.review_policy_preview', 'link.review_policy_grant',
] as const;

export type LinkConsentOperation = typeof LINK_CONSENT_OPERATIONS[number];
const operations = new Set<string>(LINK_CONSENT_OPERATIONS);

export function linkConsentOperationRequested(operation: unknown): operation is LinkConsentOperation {
  return typeof operation === 'string' && operations.has(operation);
}

/** Padded Base64, including canonical unused bits; preserves signed input. */
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
