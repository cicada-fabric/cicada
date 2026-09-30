import {NativeModules, Platform} from 'react-native';
import type {
  MonitorBroadcastConfirmResult, MonitorBroadcastOperation, MonitorBroadcastPreview,
  MonitorBroadcastStatus,
} from './monitorBroadcast';
import {
  monitorConfirmResultFromNative, monitorPreviewResultFromNative,
  monitorStatusResultFromNative,
} from './monitorBroadcast';

import {CLIENT_HUB_REVISION} from './clientHubContract';
import {captureProfileMethod} from './hubProfileScope';
export {CLIENT_HUB_REVISION, CLIENT_HUB_CATALOG_SHA256} from './clientHubContract';

export interface HubProfileScope {
  readonly profileId: string;
  readonly selectionGeneration: number;
}

export interface HubProfileSummary {
  profileId: string;
  label: string;
  pinned: boolean;
  enrolled: boolean;
  hubId?: string;
  baseUrl?: string;
  activeNetworkId?: string;
  pendingOperationId?: string;
  enrollmentRecoveryRequired?: boolean;
  uncertainNeedsReconciliation?: boolean;
  networkGrantReconciliationRequired?: boolean;
  networkGrantUncertainOperationId?: string;
}

export interface HubProfileRegistry {
  profiles: HubProfileSummary[];
  activeScope: HubProfileScope;
}

export interface NetworkKeyPreviewRequest {
  networkId: string;
  endpointId: string;
  ownerKeyId: string;
}
export interface NetworkKeyGrantRequest extends NetworkKeyPreviewRequest {
  expectedDigest: string;
  signedProofBase64: string;
}
export interface VerifiedNetworkManifest {
  ok: boolean;
  verified: true;
  result: Record<string, unknown>;
}
export interface NetworkKeyResponse {
  ok: boolean;
  result?: Record<string, unknown>;
}

export type ClientRpcOperation =
  | 'session.capabilities'
  | 'status.snapshot'
  | 'status.changes'
  | 'goal.lifecycle'
  | 'goal.result'
  | 'topology.snapshot'
  | 'topology.apply'
  | 'devices.list'
  | 'devices.revoke'
  | 'nodes.preview'
  | 'nodes.confirm'
  | 'nodes.list'
  | 'nodes.revoke'
  | 'approvals.list'
  | 'approvals.decide'
  | 'intent.get'
  | 'intent.status'
  | 'intent.list'
  | 'intent.submit'
  | 'link.list'
  | 'link.invite_create'
  | 'link.invite_preview'
  | 'link.invite_accept'
  | 'group.key_manifest'
  | 'group.key_grant'
  | 'group.key_status'
  | 'network.key_manifest'
  | 'network.key_grant'
  | 'network.key_status'
  | 'link.key_manifest'
  | 'link.key_grants'
  | 'link.key_grant'
  | 'monitor.broadcast_prepare'
  | 'monitor.broadcast_confirm'
  | 'monitor.broadcast_recover'
  | 'monitor.broadcast_status';
export type MonitorBroadcastRpcOperation = Extract<ClientRpcOperation,
  'monitor.broadcast_prepare' | 'monitor.broadcast_confirm' |
  'monitor.broadcast_recover' | 'monitor.broadcast_status'>;
export type ClientHubGenericRpcOperation = Exclude<ClientRpcOperation,
  MonitorBroadcastRpcOperation | 'network.key_manifest' | 'network.key_grant' | 'network.key_status'>;

// Link key consent remains unavailable until its separate contract is verified.
export type ClientHubAdvertisedOperation = ClientRpcOperation;

export interface ClientHubCapabilities {
  contract: string;
  contract_revision: typeof CLIENT_HUB_REVISION;
  catalog_sha256: string;
  status: 'partial' | 'not_ready' | string;
  planned_platform: string;
  legacy_management_api_available: boolean;
  client_control_pq_e2ee: boolean;
  authenticated_client_session: boolean;
  status_snapshot: boolean;
  topology_management: boolean;
  status_events: boolean;
  status_changes_partial: boolean;
  control_intents: boolean;
  device_binding: boolean;
  external_thread_links: boolean;
  external_link_invites: boolean;
  external_client_sessions: boolean;
  link_key_consent: boolean;
  group_endpoint_key_grants: boolean;
  client_device_enrollment: boolean;
  client_device_management: boolean;
  approval_read_and_decide: boolean;
  queued_goal_lifecycle: boolean;
  available_rpc_operations: ClientHubAdvertisedOperation[];
  external_rpc_operations: ClientHubAdvertisedOperation[];
}

export interface ClientHubPublicIdentity {
  id: string;
  kem_public: string;
  signing_public: string;
}

export interface ClientHubIdentity {
  contract: 'android-hub-v1';
  hub_id: string;
  control_public_identity: ClientHubPublicIdentity;
  control_key_version: 1;
  suite: 'ML-KEM-768+ML-DSA-65+AES-256-GCM';
}

export interface ClientHubCandidate {
  trusted: false;
  capabilities: ClientHubCapabilities;
  identity: ClientHubIdentity;
}

export interface ClientHubDeviceIdentity {
  id: string;
  kem_public: string;
  signing_public: string;
}

export interface ClientHubEnrollment {
  ownerId: string;
  deviceId: string;
  sessionEpoch: number;
  deviceKeyVersion: number;
  state: 'ACTIVE' | string;
}

export interface ClientGoalResultRequest {
  intent_id: string;
}

export interface ClientGoalResultWorker {
  worker_id: string;
  status: string;
  attempt: number;
  summary?: string;
}

export interface ClientGoalArtifactReference {
  artifact_id: string;
  name: string;
  kind: string;
  digest?: string;
  status: string;
}

export interface ClientGoalResult {
  intent_id: string;
  intent_status: string;
  goal_id?: string;
  goal_status?: string;
  outcome?: string;
  summary?: string;
  workers: ClientGoalResultWorker[];
  artifacts: ClientGoalArtifactReference[];
  workers_truncated: boolean;
  artifacts_truncated: boolean;
}

export interface ClientHubSessionCapabilities {
  owner_id: string;
  role: 'manager' | 'external' | string;
  contract_revision: typeof CLIENT_HUB_REVISION;
  catalog_sha256: string;
  rpc_recovery?: boolean;
  available_rpc_operations: ClientHubAdvertisedOperation[];
}

export interface ClientHubStatus {
  profileId?: string;
  selectionGeneration?: number;
  activeNetworkId?: string;
  nativeAvailable: boolean;
  pinned: boolean;
  enrolled: boolean;
  sessionCapabilitiesReady: boolean;
  remoteEnabled: boolean;
  authFenced: boolean;
  recoveryBlocked?: boolean;
  enrollmentRecoveryRequired?: boolean;
  pendingEnrollmentOwnerId?: string;
  pendingEnrollmentDeviceId?: string;
  sessionError?: string;
  baseUrl?: string;
  hubId?: string;
  ownerId?: string;
  deviceId?: string;
  sessionEpoch?: number;
  role?: 'manager' | 'external' | string;
  nextSequence?: number;
  pendingOperationId?: string;
  pendingOperation?: ClientRpcOperation;
  outcomeUncertainOperationId?: string;
  uncertainNeedsReconciliation?: boolean;
  networkGrantReconciliationRequired?: boolean;
  networkGrantUncertainOperationId?: string;
  allowedOperations: ClientRpcOperation[];
  error?: string;
}

export interface NativeClientHubStatus {
  profileId?: string;
  selectionGeneration?: number;
  activeNetworkId?: string;
  pinned: boolean;
  enrolled: boolean;
  sessionCapabilitiesReady: boolean;
  remoteEnabled: boolean;
  authFenced: boolean;
  recoveryBlocked?: boolean;
  enrollmentRecoveryRequired?: boolean;
  pendingEnrollmentOwnerId?: string;
  pendingEnrollmentDeviceId?: string;
  sessionError?: string;
  baseUrl?: string;
  hubId?: string;
  ownerId?: string;
  deviceId?: string;
  role?: string;
  nextSequence?: number;
  pendingOperationId?: string;
  pendingOperation?: string;
  outcomeUncertainOperationId?: string;
  uncertainNeedsReconciliation?: boolean;
  networkGrantReconciliationRequired?: boolean;
  networkGrantUncertainOperationId?: string;
  allowedOperations: string[];
}

export interface ClientHubNativeBridge {
  getStatus(): Promise<NativeClientHubStatus>;
  fetchHubMetadata(input: {baseUrl: string}): Promise<ClientHubCandidate>;
  pinHub(input: {
    baseUrl: string;
    hubId: string;
    controlPublicIdentityJson: string;
  }): Promise<{pinned: true; hubId: string; baseUrl: string; controlKeyId: string}>;
  createDeviceIdentity(): Promise<{devicePublicIdentity: ClientHubDeviceIdentity}>;
  startNewDeviceEnrollment(): Promise<{
    devicePublicIdentity: ClientHubDeviceIdentity;
    previousDeviceMayRemainOnHub: boolean;
  }>;
  enroll(input: {
    ownerId: string;
    ownerKeyId: string;
    ownerPublicIdentityJson: string;
    deviceId: string;
    ownerDeviceGrantBase64: string;
  }): Promise<ClientHubEnrollment>;
  recoverEnrollment(): Promise<ClientHubEnrollment>;
  rpc(input: {
    operation: ClientRpcOperation;
    body: Record<string, unknown>;
    operationId?: string;
  }): Promise<unknown>;
  recoverPending(): Promise<unknown>;
  retryPendingExact(): Promise<unknown>;
  previewGroupKey(input: {groupId: string; endpointId: string; ownerKeyId: string}): Promise<{
    ok: boolean; verified: true; result: Record<string, unknown>;
  }>;
  grantGroupKey(input: {groupId: string; endpointId: string; ownerKeyId: string;
    expectedDigest: string; signedProofBase64: string}): Promise<unknown>;
  getGroupKeyStatus(input: {groupId: string; endpointId: string}): Promise<{
    ok: boolean; result?: Record<string, unknown>;
  }>;
  previewNetworkKey(input: NetworkKeyPreviewRequest): Promise<VerifiedNetworkManifest>;
  previewNetworkKeyGrant(input: NetworkKeyGrantRequest): Promise<VerifiedNetworkManifest>;
  grantNetworkKey(input: NetworkKeyGrantRequest): Promise<NetworkKeyResponse>;
  getNetworkKeyStatus(input: {networkId: string; endpointId: string}): Promise<NetworkKeyResponse>;
  getMonitorBroadcastOperations?(): Promise<{operations: MonitorBroadcastOperation[]}>;
  monitorBroadcastPrepare?(input: {operationId?: string; groupId: string;
    monitorEndpointId: string; body: string}): Promise<unknown>;
  monitorBroadcastRecover?(input: {operationId: string}): Promise<unknown>;
  monitorBroadcastBodyMatches?(input: {previewId: string; body: string}):
    Promise<{matches: boolean; bodySha256: string}>;
  monitorBroadcastConfirm?(input: {previewId: string; body: string;
    consentDigest: string}): Promise<unknown>;
  monitorBroadcastStatus?(input: {previewId: string}): Promise<unknown>;
}

export interface ClientHubApi extends Omit<ClientHubNativeBridge,
  'getStatus' | 'getGroupKeyStatus' | 'rpc' | 'getMonitorBroadcastOperations' |
  'getNetworkKeyStatus' |
  'monitorBroadcastPrepare' | 'monitorBroadcastRecover' |
  'monitorBroadcastBodyMatches' |
  'monitorBroadcastConfirm' | 'monitorBroadcastStatus'> {
  getStatus(): Promise<ClientHubStatus>;
  rpc(input: {operation: ClientHubGenericRpcOperation; body: Record<string, unknown>;
    operationId?: string}): Promise<unknown>;
  goalResult(input: ClientGoalResultRequest): Promise<ClientGoalResult>;
  groupKeyStatus(input: {groupId: string; endpointId: string}): Promise<{
    ok: boolean; result?: Record<string, unknown>;
  }>;
  readonly monitorBroadcastReady: boolean;
  readonly networkKeyConsentReady: boolean;
  readonly scope: HubProfileScope;
  networkKeyStatus(input: {networkId: string; endpointId: string}): Promise<NetworkKeyResponse>;
  getMonitorBroadcastOperations(): Promise<{operations: MonitorBroadcastOperation[]}>;
  monitorBroadcastPrepare(input: {operationId?: string; groupId: string;
    monitorEndpointId: string; body: string}): Promise<MonitorBroadcastPreview>;
  monitorBroadcastRecover(input: {operationId: string}): Promise<MonitorBroadcastPreview>;
  monitorBroadcastBodyMatches(input: {previewId: string; body: string}):
    Promise<{matches: boolean; bodySha256: string}>;
  monitorBroadcastConfirm(input: {previewId: string; body: string;
    consentDigest: string}): Promise<MonitorBroadcastConfirmResult>;
  monitorBroadcastStatus(input: {previewId: string}): Promise<MonitorBroadcastStatus>;
}

type RawProfileBridge = {
  listHubProfiles(): Promise<HubProfileRegistry>;
  createHubProfile(input: {label: string; scope: HubProfileScope}): Promise<HubProfileRegistry>;
  activateHubProfile(input: {profileId: string; scope: HubProfileScope}): Promise<HubProfileRegistry>;
  removeHubProfile(input: {profileId: string; scope: HubProfileScope}): Promise<HubProfileRegistry>;
  setActiveNetwork(input: {networkId: string; scope: HubProfileScope}): Promise<HubProfileRegistry>;
};
const rawNative = NativeModules.CicadaClientHub as
  (ClientHubNativeBridge & RawProfileBridge) | undefined;

export const clientHubBridgeReadiness = Object.freeze({
  monitorBroadcastReady: Boolean(rawNative?.getMonitorBroadcastOperations &&
    rawNative.monitorBroadcastPrepare && rawNative.monitorBroadcastRecover &&
    rawNative.monitorBroadcastBodyMatches && rawNative.monitorBroadcastConfirm &&
    rawNative.monitorBroadcastStatus),
  networkKeyConsentReady: ['previewNetworkKey', 'previewNetworkKeyGrant',
    'grantNetworkKey', 'getNetworkKeyStatus'].every(name => rawNative &&
      typeof rawNative[name as keyof ClientHubNativeBridge] === 'function'),
});

/** Each facade captures its selection. Old callbacks cannot target a newly selected Hub or Network. */
function bindNativeProfile(scope: HubProfileScope): ClientHubNativeBridge | undefined {
  if (Platform.OS !== 'android' || !rawNative) return undefined;
  const methods = [
    'getStatus', 'fetchHubMetadata', 'pinHub', 'createDeviceIdentity',
    'startNewDeviceEnrollment', 'enroll', 'recoverEnrollment', 'rpc',
    'recoverPending', 'retryPendingExact', 'previewGroupKey', 'grantGroupKey',
    'getGroupKeyStatus', 'previewNetworkKey', 'previewNetworkKeyGrant',
    'grantNetworkKey', 'getNetworkKeyStatus', 'getMonitorBroadcastOperations',
    'monitorBroadcastPrepare', 'monitorBroadcastRecover', 'monitorBroadcastBodyMatches',
    'monitorBroadcastConfirm', 'monitorBroadcastStatus',
  ] as const;
  return Object.fromEntries(methods.filter(name => typeof rawNative[name] === 'function')
    .map(name => [name, captureProfileMethod(scope, input => {
      const method = rawNative[name] as unknown as
        (options: Record<string, unknown>) => Promise<unknown>;
      return method.call(rawNative, input);
    })])) as unknown as ClientHubNativeBridge;
}

export const hubProfiles = {
  available: Boolean(Platform.OS === 'android' && rawNative?.listHubProfiles),
  list: (): Promise<HubProfileRegistry> => rawNative ? rawNative.listHubProfiles() :
    Promise.resolve({profiles: [{profileId: 'unavailable', label: 'Hub', pinned: false,
      enrolled: false}], activeScope: {profileId: 'unavailable', selectionGeneration: 1}}),
  create: (label: string, scope: HubProfileScope) => rawNative ?
    rawNative.createHubProfile({label, scope: {...scope}}) : unavailable(),
  activate: (profileId: string, scope: HubProfileScope) => rawNative ?
    rawNative.activateHubProfile({profileId, scope: {...scope}}) : unavailable(),
  remove: (profileId: string, scope: HubProfileScope) => rawNative ?
    rawNative.removeHubProfile({profileId, scope: {...scope}}) : unavailable(),
  selectNetwork: (networkId: string, scope: HubProfileScope) => rawNative ?
    rawNative.setActiveNetwork({networkId, scope: {...scope}}) : unavailable(),
};

const unavailableStatus: ClientHubStatus = {
  nativeAvailable: false,
  pinned: false,
  enrolled: false,
  sessionCapabilitiesReady: false,
  remoteEnabled: false,
  authFenced: false,
  allowedOperations: [],
  error: '此 Android 构建尚未提供经验证的 Client-Control PQ 加密桥接。远程操作已关闭。',
};

const unavailable = async (): Promise<never> => {
  throw new Error(unavailableStatus.error);
};

const operationNames: ClientRpcOperation[] = [
  'session.capabilities', 'status.snapshot', 'status.changes', 'goal.lifecycle', 'goal.result',
  'topology.snapshot', 'topology.apply', 'devices.list', 'devices.revoke',
  'nodes.preview', 'nodes.confirm', 'nodes.list', 'nodes.revoke', 'approvals.list',
  'approvals.decide', 'intent.get', 'intent.status', 'intent.list', 'intent.submit',
  'link.list',
  'link.invite_create', 'link.invite_preview', 'link.invite_accept',
  'group.key_manifest', 'group.key_grant', 'group.key_status',
  'network.key_manifest', 'network.key_grant', 'network.key_status',
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
  'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
  'monitor.broadcast_recover', 'monitor.broadcast_status',
];
const isRpcOperation = (value: string): value is ClientRpcOperation =>
  operationNames.includes(value as ClientRpcOperation);
const normalizeStatus = (value: NativeClientHubStatus): ClientHubStatus => ({
  ...value,
  nativeAvailable: true,
  allowedOperations: value.allowedOperations.filter(isRpcOperation),
  pendingOperation: value.pendingOperation && isRpcOperation(value.pendingOperation) ?
    value.pendingOperation : undefined,
});

/**
 * Narrow platform boundary for Client ↔ Hub. All sensitive RPC sealing,
 * sequence persistence, response verification and private-key handling stay
 * inside the Android bridge. This facade never exposes a /v1 bearer route.
 */
export function createClientHubApi(selection: HubProfileScope): ClientHubApi {
  const scope = Object.freeze({...selection});
  const native = bindNativeProfile(scope);
  return Platform.OS === 'android' && native ? {
  scope,
  networkKeyConsentReady: clientHubBridgeReadiness.networkKeyConsentReady,
  monitorBroadcastReady: Boolean(native.getMonitorBroadcastOperations &&
    native.monitorBroadcastPrepare && native.monitorBroadcastRecover &&
    native.monitorBroadcastBodyMatches && native.monitorBroadcastConfirm &&
    native.monitorBroadcastStatus),
  getStatus: async () => normalizeStatus(await native.getStatus()),
  fetchHubMetadata: input => native.fetchHubMetadata(input),
  pinHub: input => native.pinHub(input),
  createDeviceIdentity: () => native.createDeviceIdentity(),
  startNewDeviceEnrollment: () => native.startNewDeviceEnrollment(),
  enroll: input => native.enroll(input),
  recoverEnrollment: () => native.recoverEnrollment(),
  goalResult: async input => {
    const status = normalizeStatus(await native.getStatus());
    if (!operationAllowed(status, 'goal.result')) {
      throw new Error('当前加密 session.capabilities 未授权 goal.result');
    }
    return native.rpc({operation: 'goal.result', body: {intent_id: input.intent_id}}) as Promise<ClientGoalResult>;
  },
  rpc: input => native.rpc(input),
  recoverPending: () => native.recoverPending(),
  retryPendingExact: () => native.retryPendingExact(),
  previewGroupKey: input => native.previewGroupKey(input),
  grantGroupKey: input => native.grantGroupKey(input),
  groupKeyStatus: input => native.getGroupKeyStatus(input),
  previewNetworkKey: input => native.previewNetworkKey(input),
  previewNetworkKeyGrant: input => native.previewNetworkKeyGrant(input),
  grantNetworkKey: input => native.grantNetworkKey(input),
  networkKeyStatus: input => native.getNetworkKeyStatus(input),
  getMonitorBroadcastOperations: async () => {
    if (!native.getMonitorBroadcastOperations) return unavailable();
    return native.getMonitorBroadcastOperations();
  },
  monitorBroadcastPrepare: async input => {
    if (!native.monitorBroadcastPrepare) return unavailable();
    return monitorPreviewResultFromNative(await native.monitorBroadcastPrepare(input), {
      operationId: input.operationId,
      groupId: input.groupId,
      monitorEndpointId: input.monitorEndpointId,
    });
  },
  monitorBroadcastRecover: async input => {
    if (!native.monitorBroadcastRecover) return unavailable();
    return monitorPreviewResultFromNative(await native.monitorBroadcastRecover(input), {
      operationId: input.operationId,
    });
  },
  monitorBroadcastBodyMatches: async input => {
    if (!native.monitorBroadcastBodyMatches) return unavailable();
    return native.monitorBroadcastBodyMatches(input);
  },
  monitorBroadcastConfirm: async input => {
    if (!native.monitorBroadcastConfirm) return unavailable();
    return monitorConfirmResultFromNative(
      await native.monitorBroadcastConfirm(input), input.previewId,
    );
  },
  monitorBroadcastStatus: async input => {
    if (!native.monitorBroadcastStatus) return unavailable();
    return monitorStatusResultFromNative(
      await native.monitorBroadcastStatus(input), input.previewId,
    );
  },
} : {
  scope,
  networkKeyConsentReady: false,
  monitorBroadcastReady: false,
  getStatus: async () => unavailableStatus,
  fetchHubMetadata: () => unavailable(),
  pinHub: () => unavailable(),
  createDeviceIdentity: () => unavailable(),
  startNewDeviceEnrollment: () => unavailable(),
  enroll: () => unavailable(),
  recoverEnrollment: () => unavailable(),
  goalResult: () => unavailable(),
  rpc: () => unavailable(),
  recoverPending: () => unavailable(),
  retryPendingExact: () => unavailable(),
  previewGroupKey: () => unavailable(),
  grantGroupKey: () => unavailable(),
  groupKeyStatus: () => unavailable(),
  previewNetworkKey: () => unavailable(),
  previewNetworkKeyGrant: () => unavailable(),
  grantNetworkKey: () => unavailable(),
  networkKeyStatus: () => unavailable(),
  getMonitorBroadcastOperations: () => unavailable(),
  monitorBroadcastPrepare: () => unavailable(),
  monitorBroadcastRecover: () => unavailable(),
  monitorBroadcastBodyMatches: () => unavailable(),
  monitorBroadcastConfirm: () => unavailable(),
  monitorBroadcastStatus: () => unavailable(),
};
}

export function operationAllowed(
  status: ClientHubStatus,
  operation: ClientRpcOperation,
): boolean {
  if (operation === 'network.key_grant' && status.networkGrantReconciliationRequired) return false;
  if (status.uncertainNeedsReconciliation && [
    'goal.lifecycle', 'topology.apply', 'devices.revoke', 'nodes.confirm',
    'nodes.revoke', 'approvals.decide', 'intent.submit', 'link.invite_create',
    'link.invite_accept', 'group.key_grant', 'network.key_grant', 'monitor.broadcast_prepare',
    'monitor.broadcast_confirm',
  ].includes(operation)) return false;
  return status.nativeAvailable && status.remoteEnabled &&
    status.sessionCapabilitiesReady && !status.pendingOperationId &&
    status.allowedOperations.includes(operation);
}
