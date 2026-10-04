import {NativeModules} from 'react-native';
import {
  observeLinkConsentDiagnosticSafely, type LinkConsentDiagnosticStage,
} from './linkConsentDiagnosticEvents';

export {
  LINK_CONSENT_DIAGNOSTIC_STAGES, sanitizeLinkConsentDiagnosticStage,
  observeLinkConsentDiagnosticSafely,
} from './linkConsentDiagnosticEvents';
export type {LinkConsentDiagnosticStage, LinkConsentDiagnosticRecorder} from './linkConsentDiagnosticEvents';

interface LinkConsentDiagnosticNativeModule {
  linkConsentDiagnosticsEnabled?: unknown;
  recordLinkConsentDiagnosticStage?: (stage: LinkConsentDiagnosticStage) => unknown;
}

/** Best-effort observer gated by the native debug build and active test observer. */
export function observeLinkConsentDiagnostic(value: unknown): void {
  try {
    const native = NativeModules.CicadaClientHub as LinkConsentDiagnosticNativeModule | undefined;
    observeLinkConsentDiagnosticSafely(value, native?.linkConsentDiagnosticsEnabled, stage => {
      const recorder = native?.recordLinkConsentDiagnosticStage;
      if (typeof recorder === 'function') recorder.call(native, stage);
    });
  } catch { /* Diagnostics must not affect consent handling. */ }
}
