/** Fixed, payload-free stages for Link consent diagnostics. */
export const LINK_CONSENT_DIAGNOSTIC_STAGES = Object.freeze([
  'CONFIRM_OPENED',
  'CALLBACK_ENTERED',
  'SCOPE_GUARD_PASSED',
  'SCOPE_GUARD_REJECTED',
  'REVIEW_CONSUMED',
  'REVIEW_INVALIDATED',
  'UI_SUBMIT_DISPATCHED',
  'UI_RESPONSE_RETURNED',
  'UI_SUBMIT_REJECTED',
  'RESPONSE_SCOPE_CHANGED',
] as const);

export type LinkConsentDiagnosticStage = typeof LINK_CONSENT_DIAGNOSTIC_STAGES[number];
export type LinkConsentDiagnosticRecorder = (stage: LinkConsentDiagnosticStage) => unknown;

const allowedStages: ReadonlySet<string> = new Set(LINK_CONSENT_DIAGNOSTIC_STAGES);

/** Accept only exact fixed stage strings; never forward caller-supplied details. */
export function sanitizeLinkConsentDiagnosticStage(value: unknown): LinkConsentDiagnosticStage | null {
  return typeof value === 'string' && allowedStages.has(value) ? value as LinkConsentDiagnosticStage : null;
}

/** Diagnostic delivery is best effort and cannot affect the caller's business flow. */
export function observeLinkConsentDiagnosticSafely(value: unknown, enabled: unknown,
  recorder?: LinkConsentDiagnosticRecorder): void {
  if (enabled !== true) return;
  const stage = sanitizeLinkConsentDiagnosticStage(value);
  if (stage === null || typeof recorder !== 'function') return;
  try { recorder(stage); } catch { /* Diagnostics must not affect consent handling. */ }
}
