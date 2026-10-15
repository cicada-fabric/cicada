/** Fixed accessibility test IDs for the existing Link list status message. */
export const LINK_LIST_DIAGNOSTIC_STATES = Object.freeze([
  'IDLE', 'LOADING', 'OK_EMPTY', 'OK_NONEMPTY', 'ERROR_RPC_REJECTED',
  'ERROR_INVALID_RESPONSE', 'ERROR_REQUEST_FAILED',
] as const);

export type LinkListDiagnosticState = typeof LINK_LIST_DIAGNOSTIC_STATES[number];
export type LinkListDiagnosticFailureKind = 'RPC_REJECTED' | 'INVALID_RESPONSE' | 'REQUEST_FAILED';

const knownStates: ReadonlySet<string> = new Set(LINK_LIST_DIAGNOSTIC_STATES);

/** Map only fixed failure categories; unknown values never pass into the UI identifier. */
export function linkListDiagnosticStateForFailure(kind: unknown): LinkListDiagnosticState {
  if (kind === 'RPC_REJECTED') return 'ERROR_RPC_REJECTED';
  if (kind === 'INVALID_RESPONSE') return 'ERROR_INVALID_RESPONSE';
  return 'ERROR_REQUEST_FAILED';
}

/** Return an exact stable identifier, reducing unexpected input to a fixed safe fallback. */
export function linkListDiagnosticTestId(state: unknown): string {
  const safeState = typeof state === 'string' && knownStates.has(state)
    ? state as LinkListDiagnosticState : 'ERROR_REQUEST_FAILED';
  return `link-list-state-${safeState}`;
}
