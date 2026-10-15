export interface ProfileSelection {
  readonly profileId: string;
  readonly selectionGeneration: number;
}

/** Never consult a mutable active selection when a deferred callback finally runs. */
export function captureProfileMethod<T>(selection: ProfileSelection,
  method: (options: Record<string, unknown>) => Promise<T>):
  (input?: Record<string, unknown>) => Promise<T> {
  const scope = Object.freeze({...selection});
  return (input = {}) => method({...input, scope});
}

/** Late STT results may complete after a profile switch; only the initiating recording owns them. */
export function speechEventBelongsToSession(sessionId: string, event: unknown): boolean {
  return Boolean(sessionId && event && typeof event === 'object' &&
    'sessionId' in event && event.sessionId === sessionId);
}
