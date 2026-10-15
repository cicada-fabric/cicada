import {NativeModules, Platform} from 'react-native';

export interface SpeechModel {
  id: string;
  name: string;
  engine: string;
  languages: string;
  capabilities: string;
  source: string;
  license: string;
  licenseUrl: string;
  downloadBytes: number;
  installed: boolean;
  selected: boolean;
}

export interface SpeechDevice {
  getModels(): Promise<SpeechModel[]>;
  installModel(id: string): Promise<string>;
  removeModel(id: string): Promise<string>;
  selectModel(id: string): Promise<void>;
  startListening(sessionId: string): Promise<void>;
  stopListening(): Promise<void>;
}

const native = NativeModules.CicadaSpeech as SpeechDevice | undefined;

/** Other operating systems add adapters here without changing screens or state contracts. */
export const speechDevice: SpeechDevice | null =
  Platform.OS === 'android' && native ? native : null;
