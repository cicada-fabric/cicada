import React, {useEffect, useMemo, useRef, useState} from 'react';
import {
  Alert, AppState, DeviceEventEmitter, KeyboardAvoidingView, Linking, Modal, PermissionsAndroid,
  Platform, Pressable, ScrollView, StatusBar, StyleSheet, Text, TextInput, View,
} from 'react-native';
import {SafeAreaProvider, SafeAreaView} from 'react-native-safe-area-context';
import {speechDevice} from './src/platform/speech';
import type {SpeechModel} from './src/platform/speech';
import {
  CLIENT_HUB_CATALOG_SHA256, CLIENT_HUB_REVISION,
  clientHubBridgeReadiness, operationAllowed,
} from './src/platform/clientHub';
import {HubConnections} from './src/components/HubConnections';
import type {HubConnection} from './src/components/HubConnections';
import {NetworkKeyConsentPanel} from './src/components/NetworkKeyConsentPanel';
import {NetworkDiscoveryPanel} from './src/components/NetworkDiscoveryPanel';
import {GroupDirectoryPermissionPanel} from './src/components/GroupDirectoryPermissionPanel';
import {RegroupDelegationPanel} from './src/components/RegroupDelegationPanel';
import {NodePairingPanel} from './src/components/NodePairingPanel';
import {SharedSpaceConsentPanel} from './src/components/SharedSpaceConsentPanel';
import {LinkReviewPolicyStatusPanel} from './src/components/LinkReviewPolicyStatusPanel';
import {LinkConsentPanel} from './src/components/LinkConsentPanel';
import {linkConsentCapabilitiesAllow} from './src/platform/linkConsentFlow';
import type {LinkConsentApi} from './src/platform/linkConsentFlow';
import {linkListDiagnosticStateForFailure, linkListDiagnosticTestId} from './src/platform/linkListDiagnostics';
import type {LinkListDiagnosticFailureKind, LinkListDiagnosticState} from './src/platform/linkListDiagnostics';
import {createGroupRequest, explicitActiveNetwork, groupsInNetwork} from './src/platform/networkTopology';
import type {NetworkTopologySnapshot} from './src/platform/networkTopology';
import {speechEventBelongsToSession} from './src/platform/hubProfileScope';
import type {
  ClientGoalArtifactReference, ClientGoalResult, ClientGoalResultWorker,
  ClientHubGenericRpcOperation,
  ClientHubCandidate, ClientHubCapabilities, ClientHubSessionCapabilities,
  ClientHubStatus, ClientRpcOperation, HubProfileScope,
} from './src/platform/clientHub';
import {
  MONITOR_BROADCAST_BODY_MAX_BYTES, MONITOR_BROADCAST_MAX_RECIPIENTS,
  MONITOR_RPC_OPERATIONS, inspectMonitorBody, monitorCatalogAllows,
  membershipAllowsBroadcast, membershipHasMonitorRole, membershipIsActive,
  monitorApprovalStatusText, monitorBodyUtf8ByteLength, monitorPreviewIsExpired,
  monitorPreviewConfirmationCutoffMs, monitorPreviewConfirmationExpiryReason,
  monitorOperationValidUntil,
  monitorPreviewStaleReason as getMonitorPreviewStaleReason,
  monitorRecipientOutcomeText,
} from './src/platform/monitorBroadcast';
import type {
  MonitorBroadcastOperation, MonitorBroadcastPreview, MonitorBroadcastStatus,
  MonitorConsentEndpoint,
  MonitorRecipientOutcome,
} from './src/platform/monitorBroadcast';

const c = {
  white: '#FFFFFF', ink: '#1A2D2B', green: '#186A63', muted: '#697974',
  border: '#E1E7E3', pale: '#F7F8F6', mint: '#E8F3EF',
  amber: '#AE7025', cream: '#FFF5E3',
};
type Tab = 'today' | 'nodes' | 'work' | 'panel' | 'settings';
type Detail = {title: string; body: string};
type JsonObject = Record<string, unknown>;
type StatusObservation = {
  state?: string; known?: boolean; observed_at?: string; source?: string; stale?: boolean;
};
type ClientStatusSnapshot = {
  captured_at?: string; read_consistency?: string; source?: string;
  nodes?: JsonObject[]; endpoints?: JsonObject[]; workers?: JsonObject[];
  goals?: JsonObject[]; groups?: JsonObject[]; tasks?: JsonObject[];
};
type ClientTopologySnapshot = NetworkTopologySnapshot;
type StatusChange = {id?: string; change_type?: string; entity_type?: string;
  entity_id?: string; state?: unknown; observed_at?: string; created_at?: string};
type StatusChangesPage = {completeness?: string; events?: StatusChange[];
  cursor?: string; has_more?: boolean; excluded_change_sources?: string[]};
type HubIntentStatus = JsonObject;
type IntentOperation = Extract<ClientRpcOperation, 'intent.get' | 'intent.list' | 'intent.status' | 'intent.submit'>;
type GoalResult = ClientGoalResult;
const tabs: {id: Tab; name: string}[] = [
  {id: 'today', name: '概览'}, {id: 'nodes', name: '节点'},
  {id: 'work', name: '工作'}, {id: 'panel', name: '管理'},
  {id: 'settings', name: '我的'},
];
const sizeLabel = (bytes: number) => bytes >= 1_000_000_000 ?
  (bytes / 1_000_000_000).toFixed(1) + ' GB' :
  Math.round(bytes / 1_000_000) + ' MB';
const errorMessage = (error: unknown) => error instanceof Error ? error.message :
  String(error || '未知错误');
class ClientHubRpcError extends Error {}
const safeHubError = (error: unknown) => {
  if (error instanceof ClientHubRpcError) return error.message;
  const code = typeof error === 'object' && error !== null && 'code' in error ?
    String((error as {code?: unknown}).code || '') : '';
  if (/STILL_PROCESSING/i.test(code)) {
    return 'Hub 仍在处理原始请求；原签名密文已保留。稍后可再次调用安全恢复，新业务操作继续关闭。';
  }
  if (/RECOVERY_UNAVAILABLE/i.test(code)) {
    return 'Hub 无法恢复这条旧请求；原始密文与计数仍保留。不要重发新操作，请由 Hub 管理员对账。';
  }
  if (/RECOVERY_REJECTED/i.test(code)) {
    return 'Hub 确认恢复端没有这条请求的记录。原包可由你显式选择重发；若请求从未到达 Hub，重发会执行原操作。';
  }
  if (/OUTCOME_UNCERTAIN/i.test(code)) {
    return 'Hub 已验证原请求结果不确定。业务结果保持待核实；未创建重试操作。';
  }
  if (/409|UNCERTAIN|PENDING/i.test(code)) {
    return 'Hub 请求结果尚未确定。不会重发新写入；先恢复原始密文请求并重新读取权威状态。';
  }
  if (/403|FENCED|REVOK/i.test(code)) {
    return 'Hub 已隔离此设备会话；远程功能关闭。请核对授权状态后再继续。';
  }
  if (code === 'PROFILE_HUB_ID_MISMATCH') return '此连接已固定其他 Hub；请新建独立连接，保留原设备身份与待恢复请求。';
  return code ? `安全连接操作失败（${code}）。请检查身份固定和网络，再读取 Hub 权威状态。` :
    '安全连接操作未成功。请检查配置和网络，再读取 Hub 权威状态。';
};
const hubErrorCode = (error: unknown) => {
  if (typeof error !== 'object' || error === null || !('code' in error)) return '';
  return String((error as {code?: unknown}).code || '').toUpperCase();
};
const hubErrorOperationId = (error: unknown) => {
  if (typeof error !== 'object' || error === null) return '';
  const value = error as {operationId?: unknown; operation_id?: unknown};
  return typeof value.operationId === 'string' ? value.operationId :
    typeof value.operation_id === 'string' ? value.operation_id : '';
};
const asObject = (value: unknown): JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ?
    value as JsonObject : {};
const field = (value: JsonObject, key: string) => {
  const result = value[key];
  return typeof result === 'string' || typeof result === 'number' ? String(result) : '';
};
const stateOf = (value: unknown) => field(asObject(value), 'state');
const observation = (value: unknown): StatusObservation => asObject(value) as StatusObservation;
const intentStatusLabel = (status: string) => ({
  pending: '待 Control 处理', resolved: 'Intent 已解决',
  failed: 'Intent 失败', needs_input: '需要补充输入',
}[status] || status || '状态未知');
const intentJobStatusLabel = (status: string) => ({
  QUEUED: '排队中', RUNNING: '执行中', DONE: 'Intent 流程结束 · 业务结果待核验',
  UNCERTAIN: '结果待核实', FAILED: '执行失败',
}[status] || status || '尚未读取分发状态');
const boundedText = (value: unknown, limit: number) =>
  typeof value === 'string' ? value.slice(0, limit) : undefined;
const parseGoalResult = (value: unknown): GoalResult => {
  const result = asObject(value);
  const workers = Array.isArray(result.workers) ? result.workers.slice(0, 8) : [];
  const artifacts = Array.isArray(result.artifacts) ? result.artifacts.slice(0, 16) : [];
  const cleanWorkers: ClientGoalResultWorker[] = workers.map(entry => {
    const worker = asObject(entry);
    return {
      worker_id: boundedText(worker.worker_id, 128) || '未知 Worker',
      status: boundedText(worker.status, 64) || 'UNKNOWN',
      attempt: Number.isSafeInteger(worker.attempt) && Number(worker.attempt) >= 0 ?
        Number(worker.attempt) : 0,
      summary: boundedText(worker.summary, 1024),
    };
  });
  const cleanArtifacts: ClientGoalArtifactReference[] = artifacts.map(entry => {
    const artifact = asObject(entry);
    return {
      artifact_id: boundedText(artifact.artifact_id, 128) || '未知引用',
      name: boundedText(artifact.name, 128) || '未命名 Artifact',
      kind: boundedText(artifact.kind, 64) || '未知类型',
      digest: boundedText(artifact.digest, 128),
      status: boundedText(artifact.status, 64) || 'UNKNOWN',
    };
  });
  return {
    intent_id: boundedText(result.intent_id, 128) || '',
    intent_status: boundedText(result.intent_status, 64) || 'UNKNOWN',
    goal_id: boundedText(result.goal_id, 128),
    goal_status: boundedText(result.goal_status, 64),
    outcome: boundedText(result.outcome, 256),
    summary: boundedText(result.summary, 2048),
    workers: cleanWorkers,
    artifacts: cleanArtifacts,
    workers_truncated: result.workers_truncated === true ||
      (Array.isArray(result.workers) && result.workers.length > 8),
    artifacts_truncated: result.artifacts_truncated === true ||
      (Array.isArray(result.artifacts) && result.artifacts.length > 16),
  };
};
const observationLabel = (value: unknown) => {
  const item = observation(value);
  if (!item.known || !item.state || item.state === 'unknown') return '未知';
  const labels: Record<string, string> = {
    connected: '在线', stale: '数据过期', offline: '离线', online: '在线', idle: '空闲',
    busy: '忙碌', left: '已离开', known: '已知', joined: '已加入', binding_lost: '绑定失效',
    queued: '排队中', running: '运行中', recovering: '恢复中', verifying: '待验证',
    completed: '已完成', failed: '失败', cancelled: '已取消', blocked: '受阻', paused: '已暂停',
    DRAFT: '草稿', ACTIVE: '活跃', PAUSED: '已暂停', QUIESCING: '收敛中', ARCHIVED: '已归档',
    READY: '就绪', CLAIMED: '已领取', RUNNING: '运行中', RESULT_SUBMITTED: '结果已提交',
    COMPLETED: '已完成', BLOCKED: '受阻', NEEDS_REVISION: '需修改', CANCELLED: '已取消',
  };
  return (labels[item.state] || item.state) + (item.stale ? ' · 数据过期' : '');
};
const observationMeta = (value: unknown) => {
  const item = observation(value);
  return `来源：${item.source || 'Hub'} · 观察：${item.observed_at || '时间未知'}`;
};
const indexWorkersById = (workers: JsonObject[]) => {
  const index = new Map<string, JsonObject>();
  workers.forEach(worker => {
    const id = field(worker, 'worker_id');
    if (id) index.set(id, worker);
  });
  return index;
};
const queuedGoalAction = (goal: JsonObject,
  workersById: Map<string, JsonObject>): 'pause' | 'resume' | null => {
  const lifecycle = observation(goal.goal_lifecycle);
  const nodeId = field(goal, 'node_id');
  const version = Number(goal.lifecycle_version);
  const ids = Array.isArray(goal.worker_ids) ? goal.worker_ids.filter(
    (id): id is string => typeof id === 'string' && id.length > 0) : [];
  if (!lifecycle.known || lifecycle.stale || !Number.isSafeInteger(version) || version < 1 || !nodeId ||
    nodeId === 'worker-local' || nodeId === 'control-local' || ids.length === 0 ||
    ids.length !== (Array.isArray(goal.worker_ids) ? goal.worker_ids.length : 0)) return null;
  const allQueued = ids.every(id => {
    const worker = workersById.get(id);
    const execution = observation(worker?.worker_execution);
    return worker && execution.known && !execution.stale && execution.state === 'queued';
  });
  if (!allQueued) return null;
  return lifecycle.state === 'queued' ? 'pause' : lifecycle.state === 'paused' ? 'resume' : null;
};
const capsAllows = (caps: ClientHubCapabilities | null, capability: keyof ClientHubCapabilities,
  operation: ClientRpcOperation, status: ClientHubStatus) =>
  Boolean(caps?.client_control_pq_e2ee === true && caps.authenticated_client_session === true &&
    caps[capability] === true && operationAllowed(status, operation));
const hubCatalogMatches = (caps: ClientHubCapabilities | null) => Boolean(
  caps?.contract_revision === CLIENT_HUB_REVISION &&
  caps.catalog_sha256 === CLIENT_HUB_CATALOG_SHA256 &&
  caps.client_control_pq_e2ee === true && caps.authenticated_client_session === true);
const monitorOperationAllowed = (caps: ClientHubCapabilities | null,
  session: ClientHubSessionCapabilities | null, status: ClientHubStatus,
  operation: typeof MONITOR_RPC_OPERATIONS[number]) => {
  return monitorCatalogAllows(caps, session, status, clientHubBridgeReadiness.monitorBroadcastReady,
    CLIENT_HUB_REVISION, CLIENT_HUB_CATALOG_SHA256) &&
    hubCatalogMatches(caps) && operationAllowed(status, operation);
};
const monitorSessionBlocksWrites = (status: ClientHubStatus) => Boolean(
  status.pendingOperationId || status.uncertainNeedsReconciliation || status.recoveryBlocked ||
  status.authFenced || status.remoteEnabled !== true || status.sessionCapabilitiesReady !== true);
const monitorFeatureAvailable = (caps: ClientHubCapabilities | null,
  session: ClientHubSessionCapabilities | null, status: ClientHubStatus) =>
  monitorCatalogAllows(caps, session, status, clientHubBridgeReadiness.monitorBroadcastReady,
    CLIENT_HUB_REVISION, CLIENT_HUB_CATALOG_SHA256);

function App(): React.JSX.Element {
  return <SafeAreaProvider><StatusBar barStyle="dark-content" />
    <HubConnections>{connection => <Client
      key={connection.api.scope.profileId + ':' + connection.api.scope.selectionGeneration}
      connection={connection} />}</HubConnections></SafeAreaProvider>;
}

function Client({connection}: {connection: HubConnection}): React.JSX.Element {
  const clientHub = connection.api;
  const setVoiceBusy = connection.setVoiceBusy;
  const mountedRef = useRef(true);
  const voiceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const voiceSessionRef = useRef('');
  useEffect(() => () => {
    mountedRef.current = false;
    if (voiceTimerRef.current) clearTimeout(voiceTimerRef.current);
  }, []);
  const [tab, setTab] = useState<Tab>('today');
  const pageScrollRef = useRef<React.ElementRef<typeof ScrollView>>(null);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [compose, setCompose] = useState(false);
  const [draft, setDraft] = useState('');
  const [voiceStatus, setVoiceStatus] = useState('');
  const [recording, setRecording] = useState(false);
  const [models, setModels] = useState<SpeechModel[]>([]);
  const [modelBusyId, setModelBusyId] = useState<string | null>(null);
  const [modelActionId, setModelActionId] = useState<string | null>(null);
  const [modelStatus, setModelStatus] = useState('');
  const [hubStatus, setHubStatus] = useState<ClientHubStatus>({
    nativeAvailable: false, pinned: false, enrolled: false,
    sessionCapabilitiesReady: false, remoteEnabled: false, authFenced: false,
    allowedOperations: [],
  });
  const [hubCandidate, setHubCandidate] = useState<ClientHubCandidate | null>(null);
  const [hubCapabilities, setHubCapabilities] = useState<ClientHubCapabilities | null>(null);
  const [sessionCapabilities, setSessionCapabilities] = useState<ClientHubSessionCapabilities | null>(null);
  const [hubUrl, setHubUrl] = useState('https://');
  const [trustedHubId, setTrustedHubId] = useState('');
  const [trustedControlIdentity, setTrustedControlIdentity] = useState('');
  const [ownerId, setOwnerId] = useState('');
  const [ownerKeyId, setOwnerKeyId] = useState('');
  const [ownerPublicIdentity, setOwnerPublicIdentity] = useState('');
  const [deviceId, setDeviceId] = useState(() => 'phone-android-' + Date.now().toString(36));
  const [ownerDeviceGrant, setOwnerDeviceGrant] = useState('');
  const [deviceIdentityJson, setDeviceIdentityJson] = useState('');
  const [hubBusy, setHubBusy] = useState(false);
  const [hubMessage, setHubMessage] = useState('');
  const [statusSnapshot, setStatusSnapshot] = useState<ClientStatusSnapshot | null>(null);
  const [snapshotVerifiedAt, setSnapshotVerifiedAt] = useState(0);
  const [statusSyncError, setStatusSyncError] = useState('');
  const [clockNow, setClockNow] = useState(Date.now());
  const [topologySnapshot, setTopologySnapshot] = useState<ClientTopologySnapshot | null>(null);
  const [showMonitorPanel, setShowMonitorPanel] = useState(false);
  const [monitorGroupId, setMonitorGroupId] = useState('');
  const [monitorEndpointId, setMonitorEndpointId] = useState('');
  const [monitorBody, setMonitorBody] = useState('');
  const [monitorPreview, setMonitorPreview] = useState<MonitorBroadcastPreview | null>(null);
  const [monitorPreparedBody, setMonitorPreparedBody] = useState<string | null>(null);
  const [monitorNeedsBodyReentry, setMonitorNeedsBodyReentry] = useState(false);
  const [monitorPreviewStaleReason, setMonitorPreviewStaleReason] = useState('');
  const [monitorStatus, setMonitorStatus] = useState<MonitorBroadcastStatus | null>(null);
  const [monitorOperations, setMonitorOperations] = useState<MonitorBroadcastOperation[]>([]);
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [monitorMessage, setMonitorMessage] = useState('');
  const [monitorConfirmAttempted, setMonitorConfirmAttempted] = useState(false);
  const monitorConfirmAttemptedRef = useRef(false);
  const [monitorNow, setMonitorNow] = useState(Date.now());
  const [monitorStatusPreviewId, setMonitorStatusPreviewId] = useState('');
  const [statusChanges, setStatusChanges] = useState<StatusChange[]>([]);
  const statusCursorRef = useRef<string | undefined>(undefined);
  const lastFullReconcileAt = useRef(0);
  const lastManagementReconcileAt = useRef(0);
  const statusChangesMaxPagesPerRefresh = 5;
  const [nodesList, setNodesList] = useState<JsonObject[]>([]);
  const [clientDevices, setClientDevices] = useState<JsonObject[]>([]);
  const [clientDevicesLoaded, setClientDevicesLoaded] = useState(false);
  const [clientDevicesBusy, setClientDevicesBusy] = useState(false);
  const [clientDevicesMessage, setClientDevicesMessage] = useState('');
  const [recoveredInvite, setRecoveredInvite] = useState<JsonObject | null>(null);
  const clientDevicesGeneration = useRef(0);
  const [approvals, setApprovals] = useState<JsonObject[]>([]);
  const [intentHistory, setIntentHistory] = useState<JsonObject[]>([]);
  const [intentHistoryVisibleCount, setIntentHistoryVisibleCount] = useState(8);
  const [intentHistoryBusy, setIntentHistoryBusy] = useState(false);
  const [intentHistoryMessage, setIntentHistoryMessage] = useState('');
  const [intentProgress, setIntentProgress] = useState<Record<string, HubIntentStatus>>({});
  const [goalResults, setGoalResults] = useState<Record<string, GoalResult>>({});
  const [expandedIntentId, setExpandedIntentId] = useState('');
  const intentHistoryGeneration = useRef(0);
  const [groupName, setGroupName] = useState('');
  const [keyGroupId, setKeyGroupId] = useState('');
  const [keyEndpointId, setKeyEndpointId] = useState('');
  const [keyOwnerId, setKeyOwnerId] = useState('');
  const [keySignedProof, setKeySignedProof] = useState('');
  const [verifiedKeyManifest, setVerifiedKeyManifest] = useState<JsonObject | null>(null);
  const [keyGrantStatus, setKeyGrantStatus] = useState<JsonObject | null>(null);
  const [keyConsentBusy, setKeyConsentBusy] = useState(false);
  const [parentGroupId, setParentGroupId] = useState('');
  const [joinEndpointId, setJoinEndpointId] = useState('');
  const [joinGroupId, setJoinGroupId] = useState('');
  const [leaveEndpointId, setLeaveEndpointId] = useState('');
  const [leaveGroupId, setLeaveGroupId] = useState('');
  const [leaveBindingId, setLeaveBindingId] = useState('');
  const [leaveBindingEpoch, setLeaveBindingEpoch] = useState('');
  const [roleMembershipId, setRoleMembershipId] = useState('');
  const [roleGroupId, setRoleGroupId] = useState('');
  const [roleValue, setRoleValue] = useState('member');
  const [linkSourceEndpointId, setLinkSourceEndpointId] = useState('');
  const [linkSourceGroupId, setLinkSourceGroupId] = useState('');
  const [linkTargetEndpointId, setLinkTargetEndpointId] = useState('');
  const [linkTargetGroupId, setLinkTargetGroupId] = useState('');
  const [linkScopes, setLinkScopes] = useState('');
  const [linkExpiresAt, setLinkExpiresAt] = useState('');
  const [topologyActionBusy, setTopologyActionBusy] = useState(false);
  const [goalLifecycleBusy, setGoalLifecycleBusy] = useState<string | null>(null);
  const [showCreateGroupForm, setShowCreateGroupForm] = useState(false);
  const [showTopologyEditor, setShowTopologyEditor] = useState(false);
  const workersById = useMemo(() => indexWorkersById(statusSnapshot?.workers || []),
    [statusSnapshot?.workers]);
  const workersPerNode = useMemo(() => {
    const counts = new Map<string, number>();
    (statusSnapshot?.workers || []).forEach(worker => {
      const id = field(worker, 'node_id');
      if (id) counts.set(id, (counts.get(id) || 0) + 1);
    });
    return counts;
  }, [statusSnapshot?.workers]);
  const selectedModel = models.find(model => model.selected);
  const realSession = hubStatus.nativeAvailable && hubStatus.remoteEnabled &&
    hubStatus.sessionCapabilitiesReady;
  const activeNetwork = explicitActiveNetwork(topologySnapshot, hubStatus.activeNetworkId);
  const selectedNetworkGroups = groupsInNetwork(topologySnapshot, hubStatus.activeNetworkId);
  const monitorOwnerId = sessionCapabilities?.owner_id || hubStatus.ownerId || ownerId;
  const monitorBodyInspection = inspectMonitorBody(monitorBody);
  const monitorBodyBytes = monitorBodyInspection.byteLength;
  const monitorActiveGroups = selectedNetworkGroups.filter(group =>
    field(group, 'state').toUpperCase() === 'ACTIVE');
  const selectedMonitorGroup = monitorActiveGroups.find(group =>
    field(group, 'group_id') === monitorGroupId);
  const selectedMonitorMembers = (topologySnapshot?.memberships || []).filter(member =>
    field(member, 'group_id') === monitorGroupId && membershipIsActive(member));
  const selectedMonitorEndpoints = (topologySnapshot?.endpoints || []).filter(endpoint =>
    Array.isArray(endpoint.group_ids) &&
    (endpoint.group_ids as unknown[]).includes(monitorGroupId) &&
    Number.isSafeInteger(endpoint.binding_epoch) && Number(endpoint.binding_epoch) > 0 &&
    Boolean(field(endpoint, 'binding_id')));
  const eligibleMonitorEndpoints = selectedMonitorEndpoints.filter(endpoint =>
    selectedMonitorMembers.some(member =>
      field(member, 'principal_id') === field(endpoint, 'principal_id') &&
      membershipHasMonitorRole(member) && membershipAllowsBroadcast(member)) &&
    Boolean(monitorOwnerId));
  const monitorTopologyApplyAllowed = Boolean(hubCatalogMatches(hubCapabilities) &&
    sessionCapabilities?.contract_revision === CLIENT_HUB_REVISION &&
    sessionCapabilities.catalog_sha256 === CLIENT_HUB_CATALOG_SHA256 &&
    sessionCapabilities.available_rpc_operations.includes('topology.apply') &&
    capsAllows(hubCapabilities, 'topology_management', 'topology.apply', hubStatus));
  const monitorFeatureReady = monitorFeatureAvailable(
    hubCapabilities, sessionCapabilities, hubStatus);
  const show = (title: string, body: string) => setDetail({title, body});
  const refreshModels = async () => {
    if (speechDevice) {
      try { setModels(await speechDevice.getModels()); }
      catch { setModelStatus('无法读取本地模型状态'); }
    }
  };

  const refreshHubStatus = async () => {
    const current = await clientHub.getStatus();
    setHubStatus(current);
    if (current.baseUrl) setHubUrl(current.baseUrl);
    if (current.ownerId) setOwnerId(current.ownerId);
    if (current.deviceId) setDeviceId(current.deviceId);
    return current;
  };
  const rpc = async (operation: ClientHubGenericRpcOperation,
    body: Record<string, unknown>) => {
    const current = await clientHub.getStatus();
    if (operation === 'session.capabilities') {
      if (!current.pinned || !current.enrolled) throw new Error('请先固定 Hub 身份并登记此设备');
    } else if (!operationAllowed(current, operation)) {
      throw new Error('当前加密会话未授权此操作');
    }
    let rawResponse: unknown;
    try { rawResponse = await clientHub.rpc({operation, body}); }
    catch (error) {
      const latest = await clientHub.getStatus().catch(() => null);
      if (latest) {
        setHubStatus(latest);
        if (latest.authFenced) {
          setSessionCapabilities(null);
          setStatusSnapshot(null);
          setSnapshotVerifiedAt(0);
          setStatusSyncError('');
          setTopologySnapshot(null);
          lastManagementReconcileAt.current = 0;
          setApprovals([]);
          setNodesList([]);
          clearClientDeviceMemory();
          clearIntentMemory();
          clearMonitorMemory();
          setRecoveredInvite(null);
          setHubMessage(latest.sessionError || '设备授权已隔离；远程功能已关闭。请重新核对授权。');
        }
      }
      throw error;
    }
    const response = asObject(rawResponse);
    if (response.ok !== true) {
      throw new ClientHubRpcError(typeof response.error === 'string' ? response.error : 'Hub 拒绝了加密请求');
    }
    return response.result;
  };
  const rpcIfAllowed = async (capability: keyof ClientHubCapabilities,
    operation: ClientHubGenericRpcOperation, body: Record<string, unknown> = {},
    capabilities = hubCapabilities) => {
    const current = await clientHub.getStatus();
    if (!capsAllows(capabilities, capability, operation, current)) return undefined;
    return rpc(operation, body);
  };
  const clearIntentMemory = () => {
    intentHistoryGeneration.current += 1;
    setIntentHistory([]);
    setIntentHistoryVisibleCount(8);
    setIntentHistoryBusy(false);
    setIntentHistoryMessage('');
    setIntentProgress({});
    setGoalResults({});
    setExpandedIntentId('');
  };
  const clearClientDeviceMemory = () => {
    clientDevicesGeneration.current += 1;
    setClientDevices([]);
    setClientDevicesLoaded(false);
    setClientDevicesBusy(false);
    setClientDevicesMessage('');
  };
  const clearMonitorMemory = () => {
    setMonitorGroupId('');
    setMonitorEndpointId('');
    setMonitorBody('');
    setMonitorPreview(null);
    setMonitorPreparedBody(null);
    setMonitorNeedsBodyReentry(false);
    setMonitorPreviewStaleReason('');
    setMonitorStatus(null);
    setMonitorStatusPreviewId('');
    setMonitorOperations([]);
    setMonitorMessage('');
    setMonitorConfirmAttempted(false);
    monitorConfirmAttemptedRef.current = false;
  };
  const intentOperationAvailable = (operation: IntentOperation,
    capabilities = hubCapabilities, session = sessionCapabilities, status = hubStatus) =>
    Boolean(capsAllows(capabilities, 'control_intents', operation, status) &&
      session?.available_rpc_operations.includes(operation));
  const goalResultAvailable = (capabilities = hubCapabilities,
    session = sessionCapabilities, status = hubStatus) => Boolean(
    session?.role === 'manager' && session.contract_revision === CLIENT_HUB_REVISION &&
    capabilities?.contract_revision === CLIENT_HUB_REVISION &&
    session.catalog_sha256 === capabilities.catalog_sha256 &&
    capsAllows(capabilities, 'control_intents', 'goal.result', status) &&
    session.available_rpc_operations.includes('goal.result'));
  const intentRpc = async (operation: IntentOperation, body: Record<string, unknown>,
    capabilities = hubCapabilities, session = sessionCapabilities) => {
    const current = await clientHub.getStatus();
    setHubStatus(current);
    if (!intentOperationAvailable(operation, capabilities, session, current)) {
      throw new Error(`当前加密会话未授权 ${operation}`);
    }
    return rpc(operation, body);
  };
  const rememberIntent = (intent: JsonObject) => {
    const id = field(intent, 'id');
    if (!id) return;
    setIntentHistory(previous => {
      const existingIndex = previous.findIndex(item => field(item, 'id') === id);
      if (existingIndex < 0) return [intent, ...previous].slice(0, 200);
      return previous.map((item, index) => index === existingIndex ? intent : item);
    });
  };
  const rememberIntentProgress = (value: unknown) => {
    const progress = asObject(value);
    const intent = asObject(progress.intent);
    const id = field(intent, 'id');
    if (!id) return;
    rememberIntent(intent);
    setIntentProgress(previous => ({...previous, [id]: progress}));
  };
  const refreshGoalResult = async (intentId: string,
    capabilities = hubCapabilities, session = sessionCapabilities) => {
    const current = await clientHub.getStatus();
    setHubStatus(current);
    if (!goalResultAvailable(capabilities, session, current)) return undefined;
    const value = await clientHub.goalResult({intent_id: intentId});
    const parsed = parseGoalResult(value);
    if (parsed.intent_id !== intentId) throw new Error('goal.result 返回了不同的 intent_id');
    setGoalResults(previous => ({...previous, [intentId]: parsed}));
    return parsed;
  };
  const refreshIntentStatus = async (intentId: string,
    capabilities = hubCapabilities, session = sessionCapabilities) => {
    const value = await intentRpc('intent.status', {intent_id: intentId}, capabilities, session);
    rememberIntentProgress(value);
    const goalResult = await refreshGoalResult(intentId, capabilities, session);
    if (!goalResult) {
      setGoalResults(previous => {
        const next = {...previous};
        delete next[intentId];
        return next;
      });
    }
    return asObject(value);
  };
  const fetchIntentHistory = async () => {
    const generation = intentHistoryGeneration.current;
    setIntentHistoryBusy(true);
    setIntentHistoryMessage('正在通过加密会话读取本人 Intent 历史…');
    try {
      const value = await intentRpc('intent.list', {});
      if (generation !== intentHistoryGeneration.current) return;
      if (!Array.isArray(value)) throw new Error('Hub intent.list 返回格式无效');
      const items = value.map(asObject).slice(0, 200);
      setIntentHistory(items);
      setIntentProgress({});
      setGoalResults({});
      setExpandedIntentId('');
      setIntentHistoryVisibleCount(8);
      setIntentHistoryMessage(items.length === 0 ? 'Hub 中暂无本人 Intent 记录。' :
        `已从 Hub 读取 ${items.length} 条本人记录；正文仅保留在当前内存中。`);
    } catch (error) {
      if (generation === intentHistoryGeneration.current) {
        setIntentHistoryMessage('历史读取失败：' + safeHubError(error));
      }
    } finally {
      if (generation === intentHistoryGeneration.current) setIntentHistoryBusy(false);
    }
  };
  const reconcileVerifiedRecoveryRejection = async (response: JsonObject,
    suppliedCapabilities = hubCapabilities, pendingOperation?: string) => {
    const reason = field(response, 'error') || 'Hub 拒绝了此加密请求';
    const errorCode = field(response, 'errorCode') || field(response, 'error_code');
    const recovery = asObject(response.recovery);
    const outcomeUncertain = errorCode === 'OUTCOME_UNCERTAIN' &&
      field(recovery, 'state') === 'UNCERTAIN';
    if (outcomeUncertain && pendingOperation === 'intent.submit') {
      setTab('work');
      setExpandedIntentId('');
      setIntentHistoryMessage('此 intent.submit 的业务结果仍待核实。Hub 没有返回可验证 intent_id；不会猜测对应记录或重发请求。');
    }
    let reconciliation = '';
    try {
      const current = await refreshHubStatus();
      if (current.pendingOperationId) {
        throw new Error('仍存在未确定的原始密文请求');
      }
      let capabilities = suppliedCapabilities;
      if (!capabilities && current.baseUrl) {
        const candidate = await clientHub.fetchHubMetadata({baseUrl: current.baseUrl});
        capabilities = candidate.capabilities;
        setHubCandidate(candidate);
        setHubCapabilities(candidate.capabilities);
      }
      const session = asObject(await rpc('session.capabilities', {})) as
        unknown as ClientHubSessionCapabilities;
      setSessionCapabilities(session);
      const refreshed = await refreshHubStatus();
      const snapshot = capabilities ? await refreshRemoteData(capabilities) : undefined;
      reconciliation = snapshot ?
        '已重读 session.capabilities 和 Hub 权威状态快照。' :
        '已重读 session.capabilities；当前公开能力或会话授权未提供 status.snapshot，未取得新快照。';
      if (outcomeUncertain && pendingOperation === 'intent.submit' &&
          session.role === 'manager' && session.available_rpc_operations.includes('intent.list') &&
          capsAllows(capabilities || null, 'control_intents', 'intent.list', refreshed)) {
        const intents = await intentRpc('intent.list', {}, capabilities, session);
        if (Array.isArray(intents)) {
          setIntentHistory(intents.map(asObject).slice(0, 200));
          setIntentProgress({});
          setIntentHistoryVisibleCount(8);
          setIntentHistoryMessage('原始 intent.submit 返回 OUTCOME_UNCERTAIN；已重读 Hub Intent 历史。无法从不确定响应推断 intent_id，因此未查询 goal.result，也未重发请求。');
        }
      }
    } catch (error) {
      reconciliation = '已尝试重读 session.capabilities 和权威快照，但对账未完整：' +
        safeHubError(error);
    }
    setHubMessage(outcomeUncertain ?
      `Hub 已验证 OUTCOME_UNCERTAIN：此业务操作保持待核实，没有创建新的 operation。${reconciliation}` :
      `Hub 已验证并拒绝原始加密请求：${reason}。${reconciliation}`);
  };
  /**
   * Drop the optimistic UI attempt lock only when fresh native metadata proves
   * no Confirm packet was durably recorded. Unknown metadata and any outstanding
   * request or uncertain outcome remain fail-closed.
   */
  const reconcileMonitorConfirmAttemptLock = async (operationId: string): Promise<boolean> => {
    try {
      const current = await clientHub.getStatus();
      setHubStatus(current);
      setMonitorNow(Date.now());
      const index = await clientHub.getMonitorBroadcastOperations();
      if (!Array.isArray(index.operations)) return false;
      const operations = index.operations;
      setMonitorOperations(operations.slice(0, 64));
      const operation = operations.find(item => item.operationId === operationId);
      if (!operation || operation.confirmAttempted !== false ||
          monitorSessionBlocksWrites(current) ||
          operations.some(item => item.confirmAttempted && item.confirmStatusReconciled !== true) ||
          /CONFIRM_(PENDING|UNCERTAIN)/.test(String(operation.state).toUpperCase()) ||
          ['APPROVED', 'DISPATCH_AUTHORIZED'].includes(String(operation.state).toUpperCase()) ||
          operation.confirmOperationId != null ||
          !monitorPreview?.previewId || monitorPreview.operationId !== operationId ||
          operation.previewId !== monitorPreview.previewId) {
        return false;
      }
      monitorConfirmAttemptedRef.current = false;
      setMonitorConfirmAttempted(false);
      return true;
    } catch {
      // A failed status or operation-index read must never unlock confirmation.
      return false;
    }
  };
  const acceptRecoveredResponse = async (current: ClientHubStatus, response: JsonObject,
    source: 'recover' | 'exact_retry') => {
    if (response.ok === false) {
      await reconcileVerifiedRecoveryRejection(response, hubCapabilities, current.pendingOperation);
      if (monitorConfirmAttemptedRef.current && monitorPreview) {
        await reconcileMonitorConfirmAttemptLock(monitorPreview.operationId);
      }
      return;
    }
    if (response.ok !== true) {
      setHubMessage('原始请求尚未得到可验证响应；保持同一 pending 密文并阻断新 RPC。');
      return;
    }
    const operation = current.pendingOperation;
    const result = asObject(response.result);
    const session = asObject(await rpc('session.capabilities', {})) as
      unknown as ClientHubSessionCapabilities;
    setSessionCapabilities(session);
    if (operation === 'intent.submit') {
      rememberIntent(result);
      const intentId = field(result, 'id');
      if (intentId) {
        setTab('work');
        setExpandedIntentId(intentId);
        setIntentHistoryMessage('原始 intent.submit 已由 Hub 加密确认接受；正在读取 Intent、Goal 与 Worker 权威状态。');
        if (session.available_rpc_operations.includes('intent.status')) {
          await refreshIntentStatus(intentId, hubCapabilities, session);
        } else await refreshGoalResult(intentId, hubCapabilities, session);
      }
    }
    if (operation === 'link.invite_create') setRecoveredInvite(result);
    await refreshHubStatus();
    await refreshRemoteData();
    if (monitorConfirmAttemptedRef.current && monitorPreview) {
      await reconcileMonitorConfirmAttemptLock(monitorPreview.operationId);
    }
    setHubMessage(operation === 'link.invite_create' ?
      `已验证原始密文响应；一次性邀请 token 仅在管理页当前内存显示。来源：${source}。` :
      operation === 'link.invite_accept' ?
        `Hub 已确认原始邀请接受请求；请重读 link.list 核对 PROPOSED 提案。来源：${source}。` :
        `已验证原始签名密文响应；权威状态已重新读取。来源：${source}。`);
  };
  const refreshStatusChanges = async (capabilities = hubCapabilities) => {
    const current = await clientHub.getStatus();
    setHubStatus(current);
    if (!current.remoteEnabled || !current.sessionCapabilitiesReady) return;
    if (current.pendingOperationId) {
      setHubMessage('存在未确定的原始加密请求；请先恢复该请求，再发送新 RPC。');
      return;
    }
    if (!capabilities?.status_changes_partial || !operationAllowed(current, 'status.changes')) return;
    let cursor = statusCursorRef.current;
    for (let page = 0; page < statusChangesMaxPagesPerRefresh; page++) {
      const changes = await rpc('status.changes', {
        ...(cursor ? {cursor} : {}), limit: 100,
      }) as StatusChangesPage;
      const events = changes.events || [];
      setStatusChanges(previous => {
        const combined = [...events, ...previous];
        const seen = new Set<string>();
        return combined.filter((item, index) => {
          const key = item.id || `${item.entity_type || ''}/${item.entity_id || ''}/${item.created_at || item.observed_at || index}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        }).slice(0, 500);
      });
      const nextCursor = changes.cursor || cursor;
      const advanced = nextCursor !== cursor;
      cursor = nextCursor;
      statusCursorRef.current = cursor;
      if (!changes.has_more || !advanced) break;
    }
  };
  const refreshRemoteData = async (capabilities = hubCapabilities,
    includeManagement = tab === 'panel') => {
    const current = await clientHub.getStatus();
    setHubStatus(current);
    if (!current.remoteEnabled || !current.sessionCapabilitiesReady) return;
    if (current.pendingOperationId) {
      setHubMessage('存在未确定的原始加密请求；请先恢复该请求，再发送新 RPC。');
      return;
    }
    try {
      const nextSnapshot = await rpcIfAllowed('status_snapshot', 'status.snapshot', {}, capabilities) as
        ClientStatusSnapshot | undefined;
      setStatusSnapshot(nextSnapshot || null);
      setSnapshotVerifiedAt(nextSnapshot ? Date.now() : 0);
      setStatusSyncError('');
      if (nextSnapshot) await refreshHubStatus();
      if (includeManagement) {
        const nextTopology = await rpcIfAllowed('topology_management', 'topology.snapshot', {}, capabilities) as
          ClientTopologySnapshot | undefined;
        setTopologySnapshot(nextTopology || null);
        const nextNodes = await rpcIfAllowed('client_device_management', 'nodes.list', {}, capabilities) as
          JsonObject[] | undefined;
        setNodesList(nextNodes || []);
        lastManagementReconcileAt.current = Date.now();
      }
      if (capabilities?.approval_read_and_decide && current.role === 'manager') {
        const nextApprovals = await rpcIfAllowed('approval_read_and_decide', 'approvals.list',
          {pending_only: true}, capabilities) as JsonObject[] | undefined;
        setApprovals(nextApprovals || []);
      } else setApprovals([]);
      lastFullReconcileAt.current = Date.now();
      await refreshStatusChanges(capabilities);
      return nextSnapshot || undefined;
    } catch (error) {
      setStatusSyncError('最近一次 Hub 同步失败：' + safeHubError(error));
      throw error;
    }
  };
  const fetchHubCandidate = async () => {
    setHubBusy(true);
    setHubMessage('正在读取公开能力与 Hub 身份；尚未建立信任');
    try {
      const candidate = await clientHub.fetchHubMetadata({baseUrl: hubUrl.trim()});
      setHubCandidate(candidate);
      setHubCapabilities(candidate.capabilities);
      setHubMessage('已读到未受信任的 Hub 候选。请从独立可信渠道逐项核对完整身份后再固定。');
    } catch (error) { setHubMessage('读取 Hub 信息失败：' + safeHubError(error)); }
    finally { setHubBusy(false); }
  };
  const pinHub = async () => {
    setHubBusy(true);
    setHubMessage('正在核对独立提供的 Hub ID 和 Control 公钥');
    try {
      await clientHub.pinHub({baseUrl: hubUrl.trim(), hubId: trustedHubId.trim(),
        controlPublicIdentityJson: trustedControlIdentity.trim()});
      setSessionCapabilities(null);
      clearMonitorMemory();
      clearIntentMemory();
      setStatusSnapshot(null);
      setSnapshotVerifiedAt(0);
      setStatusSyncError('');
      setTopologySnapshot(null);
      setStatusChanges([]);
      statusCursorRef.current = undefined;
      lastFullReconcileAt.current = 0;
      lastManagementReconcileAt.current = 0;
      setApprovals([]);
      setNodesList([]);
      clearClientDeviceMemory();
      setRecoveredInvite(null);
      const current = await refreshHubStatus();
      setHubMessage(current.pinned ? 'Hub 身份已按独立信任输入固定；此时尚未登记设备。'
        : 'Hub 身份尚未固定');
    } catch (error) { setHubMessage('无法固定 Hub：' + safeHubError(error)); }
    finally { setHubBusy(false); }
  };
  const createDeviceIdentity = async () => {
    if (!hubStatus.pinned) {
      setHubMessage('请先固定 Hub 的独立可信身份。');
      return;
    }
    setHubBusy(true);
    try {
      const result = await clientHub.createDeviceIdentity();
      setDeviceIdentityJson(JSON.stringify(result.devicePublicIdentity, null, 2));
      setHubMessage('设备密钥已在 Android 安全适配中生成；将下面的公钥身份交给 Owner 独立签发 Grant。');
    } catch (error) { setHubMessage('创建设备密钥失败：' + safeHubError(error)); }
    finally { setHubBusy(false); }
  };
  const startNewDeviceEnrollment = () => Alert.alert('创建新的 App 设备身份？',
    '这会擦除本机旧 Keystore 包裹身份并生成新的 PQ 密钥。旧设备记录不会从 Hub 自动撤销，Hub 上可能仍保持有效；需要另一台已授权设备撤销旧记录。待处理原始密文只作为本地审计保留。', [
      {text: '取消', style: 'cancel'},
      {text: '创建新身份', style: 'destructive', onPress: async () => {
        setHubBusy(true);
        try {
          const result = await clientHub.startNewDeviceEnrollment();
          clearIntentMemory();
          clearMonitorMemory();
          setSessionCapabilities(null);
          setStatusSnapshot(null);
          setSnapshotVerifiedAt(0);
          setStatusSyncError('');
          setTopologySnapshot(null);
          setStatusChanges([]);
          statusCursorRef.current = undefined;
          lastFullReconcileAt.current = 0;
          lastManagementReconcileAt.current = 0;
          setNodesList([]);
          setApprovals([]);
          clearClientDeviceMemory();
          setRecoveredInvite(null);
          setDeviceIdentityJson(JSON.stringify(result.devicePublicIdentity, null, 2));
          setDeviceId('phone-android-' + Date.now().toString(36));
          setOwnerDeviceGrant('');
          setHubMessage(result.previousDeviceMayRemainOnHub ?
            '新 PQ 身份已创建。旧设备可能仍在 Hub 有效；请用另一台授权设备撤销旧记录，并让 Owner 为新身份签发 Grant。' :
            '新 PQ 身份已创建；请让 Owner 为新身份签发 Grant。');
          await refreshHubStatus();
        } catch (error) { setHubMessage('创建新设备身份失败：' + safeHubError(error)); }
        finally { setHubBusy(false); }
      }},
    ]);
  const enrollDevice = async () => {
    if (!hubStatus.pinned || !deviceIdentityJson || !ownerId.trim() || !ownerKeyId.trim() ||
        !ownerPublicIdentity.trim() || !deviceId.trim() || !ownerDeviceGrant.trim()) {
      setHubMessage('请先固定 Hub、生成设备公钥身份，并填写 Owner ID、公钥和外部签发的 Grant。');
      return;
    }
    setHubBusy(true);
    setHubMessage('正在验证外部 OwnerDeviceGrant 并登记设备');
    try {
      await clientHub.enroll({ownerId: ownerId.trim(), ownerKeyId: ownerKeyId.trim(),
        ownerPublicIdentityJson: ownerPublicIdentity.trim(), deviceId: deviceId.trim(),
        ownerDeviceGrantBase64: ownerDeviceGrant.trim()});
      setOwnerDeviceGrant('');
      const sessionResult = asObject(await rpc('session.capabilities', {}));
      const session = sessionResult as unknown as ClientHubSessionCapabilities;
      setSessionCapabilities(session);
      const current = await refreshHubStatus();
      setHubStatus(current);
      setHubMessage(session.role === 'external' ?
        '加密会话已建立 · 此 Owner 仅能使用其授权操作。' :
        '加密会话已建立 · 可用操作由 Hub 返回的 session.capabilities 授权。');
      await refreshRemoteData();
    } catch (error) { setHubMessage('设备登记/会话建立失败：' + safeHubError(error)); }
    finally { setHubBusy(false); }
  };
  const recoverEnrollment = async () => {
    if (!hubStatus.enrollmentRecoveryRequired || hubBusy || hubStatus.authFenced) return;
    setHubBusy(true);
    setHubMessage('正在用本机持久保存的原始登记请求恢复；不会签发新 Grant 或设备身份。');
    let enrollmentRecovered = false;
    try {
      const enrollment = await clientHub.recoverEnrollment();
      enrollmentRecovered = true;
      setOwnerId(enrollment.ownerId);
      setDeviceId(enrollment.deviceId);
      setOwnerDeviceGrant('');
      const session = asObject(await rpc('session.capabilities', {})) as
        unknown as ClientHubSessionCapabilities;
      setSessionCapabilities(session);
      const current = await refreshHubStatus();
      await refreshRemoteData(hubCapabilities || undefined);
      setHubMessage(`已恢复同一设备登记响应 · epoch ${enrollment.sessionEpoch} · 已读取加密 session.capabilities。`);
      if (current.enrollmentRecoveryRequired) {
        setHubMessage('Hub 返回登记结果，但本机仍标记登记待恢复；保留原请求并停止新登记。');
      }
    } catch (error) {
      const current = await clientHub.getStatus().catch(() => null);
      if (current) setHubStatus(current);
      setHubMessage(enrollmentRecovered ?
        'Hub 已确认原设备登记；后续会话读取未完成：' + safeHubError(error) :
        '原登记请求恢复未完成：' + safeHubError(error) + '。仍保留本机同一 Grant 和身份，可安全重试。');
    } finally { setHubBusy(false); }
  };
  const initializeHubSession = async () => {
    const current = await refreshHubStatus();
    if (current.authFenced) {
      setDeviceIdentityJson('');
      setOwnerDeviceGrant('');
      setSessionCapabilities(null);
      clearIntentMemory();
      clearMonitorMemory();
      setStatusSnapshot(null);
      setSnapshotVerifiedAt(0);
      setStatusSyncError('');
      setTopologySnapshot(null);
      lastFullReconcileAt.current = 0;
      lastManagementReconcileAt.current = 0;
      setApprovals([]);
      setNodesList([]);
      clearClientDeviceMemory();
      setRecoveredInvite(null);
      setHubMessage('设备授权已被安全桥接隔离，远程操作关闭。旧密钥与待处理密文按恢复规则保留；请核对身份并重新取得 Owner 授权。');
      return;
    }
    if (!current.pinned) return;
    setHubUrl(current.baseUrl || hubUrl);
    let capabilities: ClientHubCapabilities | undefined;
    try {
      const candidate = await clientHub.fetchHubMetadata({baseUrl: current.baseUrl || hubUrl});
      setHubCandidate(candidate);
      setHubCapabilities(candidate.capabilities);
      capabilities = candidate.capabilities;
    } catch (error) {
      setHubMessage('已固定 Hub，但无法读取当前能力：' + safeHubError(error));
    }
    if (!current.enrolled) return;
    try {
      if (current.pendingOperationId) {
        const recovered = asObject(await clientHub.recoverPending());
        const pending = recovered;
        if (pending.ok === false) {
          await reconcileVerifiedRecoveryRejection(pending, capabilities, current.pendingOperation);
          return;
        }
        if (pending.ok !== true) {
          setHubMessage('待恢复请求尚未得到可验证响应；先完成权威状态对账。不会创建新请求。');
          return;
        }
        const afterRecovery = await refreshHubStatus();
        if (afterRecovery.pendingOperationId) {
          setHubMessage('仍有未确定的原始加密请求；已停止新的 RPC，等待恢复结果。');
          return;
        }
        await acceptRecoveredResponse(current, recovered, 'recover');
        return;
      }
      const sessionResult = asObject(await rpc('session.capabilities', {}));
      setSessionCapabilities(sessionResult as unknown as ClientHubSessionCapabilities);
      await refreshHubStatus();
      await refreshRemoteData(capabilities);
    } catch (error) { setHubMessage('无法恢复加密会话：' + safeHubError(error)); }
  };
  const recoverPendingNow = async () => {
    const current = await refreshHubStatus();
    if (!current.pendingOperationId || current.authFenced) return;
    setHubBusy(true);
    try {
      const recovered = asObject(await clientHub.recoverPending());
      await acceptRecoveredResponse(current, recovered, 'recover');
    } catch (error) {
      const latest = await clientHub.getStatus().catch(() => null);
      if (latest) setHubStatus(latest);
      setHubMessage('原始请求恢复失败：' + safeHubError(error));
    }
    finally { setHubBusy(false); }
  };

  const retryPendingExact = () => {
    if (hubStatus.sessionError !== 'RECOVERY_REJECTED' || !hubStatus.pendingOperationId || hubBusy) return;
    Alert.alert('显式重发原始请求？',
      'Hub 的恢复端没有这条请求记录。若原包从未到达 Hub，这次会执行原操作；若 Hub 曾接受请求，其重放保护会阻止再次执行。将原样发送本机保留的同一签名密文、operation ID 和序号，不创建新请求。', [
        {text: '取消', style: 'cancel'},
        {text: '原样重发一次', style: 'destructive', onPress: async () => {
          setHubBusy(true);
          try {
            const current = await refreshHubStatus();
            if (current.sessionError !== 'RECOVERY_REJECTED' || !current.pendingOperationId) {
              throw new Error('RECOVERY_STATE_CHANGED');
            }
            const response = asObject(await clientHub.retryPendingExact());
            await acceptRecoveredResponse(current, response, 'exact_retry');
          } catch (error) {
            const latest = await clientHub.getStatus().catch(() => null);
            if (latest) setHubStatus(latest);
            setHubMessage('原请求原样重发未完成：' + safeHubError(error) +
              '。没有生成新的 operation；如仍有 pending，请先再次调用 /recover。');
          } finally { setHubBusy(false); }
        }},
      ]);
  };

  const refreshAfterUncertainOutcome = async () => {
    setHubBusy(true);
    try {
      let current = await refreshHubStatus();
      if (current.pendingOperationId) {
        setHubMessage('仍有待恢复的原始密文；先调用 /rpc/recover，再读取业务状态。');
        return;
      }
      let capabilities = hubCapabilities;
      if (!capabilities && current.baseUrl) {
        const candidate = await clientHub.fetchHubMetadata({baseUrl: current.baseUrl});
        setHubCandidate(candidate);
        setHubCapabilities(candidate.capabilities);
        capabilities = candidate.capabilities;
      }
      let session = sessionCapabilities;
      if (!session && current.remoteEnabled && current.sessionCapabilitiesReady) {
        session = asObject(await rpc('session.capabilities', {})) as
          unknown as ClientHubSessionCapabilities;
        setSessionCapabilities(session);
        current = await refreshHubStatus();
      }
      await refreshRemoteData(capabilities || undefined);
      if (session?.role === 'manager' && session.available_rpc_operations.includes('intent.list') &&
          capsAllows(capabilities || null, 'control_intents', 'intent.list', current)) {
        const intents = await intentRpc('intent.list', {}, capabilities, session);
        if (Array.isArray(intents)) {
          setIntentHistory(intents.map(asObject).slice(0, 200));
          setIntentProgress({});
          setIntentHistoryVisibleCount(8);
          setIntentHistoryMessage('已重读权威 Intent 历史。OUTCOME_UNCERTAIN 未提供可验证 intent_id，因此不会猜测关联或查询 goal.result。');
        }
      }
      setHubMessage('已刷新 Hub 权威状态。此操作的业务结果仍待核实；没有重发 Intent。');
    } catch (error) {
      setHubMessage('权威状态刷新失败：' + safeHubError(error));
    } finally { setHubBusy(false); }
  };

  const submitIntent = async () => {
    const text = draft.trim();
    if (!text) { setVoiceStatus('请先输入或转写一段文字'); return; }
    if (!intentOperationAvailable('intent.submit')) {
      setVoiceStatus('Hub 会话未授权 intent.submit，内容尚未发送');
      return;
    }
    setHubBusy(true);
    let submitted: JsonObject;
    try {
      submitted = asObject(await intentRpc('intent.submit', {text}));
    } catch (error) {
      setVoiceStatus('加密提交失败：' + safeHubError(error));
      setHubBusy(false);
      return;
    }
    const id = field(submitted, 'id');
    if (id) {
      rememberIntent(submitted);
      setExpandedIntentId(id);
      setTab('work');
      setIntentHistoryMessage('Hub 已持久接受此 Intent；正在读取 Intent、Goal 与 Worker 状态。');
    }
    setDraft('');
    setCompose(false);
    setVoiceStatus('');
    setHubMessage(id ? `请求已由 Hub 持久接受 · Intent ${id}` :
      'Hub 已验证 intent.submit 成功响应，但没有返回可读取的 Intent ID。');
    try {
      if (id && intentOperationAvailable('intent.status')) await refreshIntentStatus(id);
      else if (id) await refreshGoalResult(id);
      await refreshRemoteData();
      if (id) setIntentHistoryMessage(goalResultAvailable() ?
        '已读取 Intent 状态；Goal 与 Worker 结果来自独立的 goal.result。' :
        '已读取当前授权的 Intent 状态；此加密会话没有提供 goal.result 权限。');
    } catch (error) {
      setHubMessage(id ?
        `Intent ${id} 已由 Hub 持久接受；后续 Intent / Goal 状态读取失败：${safeHubError(error)}` :
        'Intent 已由 Hub 接受；后续状态刷新失败：' + safeHubError(error));
    }
    setHubBusy(false);
  };

  const refreshTopology = async () => {
    const value = await rpcIfAllowed('topology_management', 'topology.snapshot', {}) as
      ClientTopologySnapshot | undefined;
    if (value) setTopologySnapshot(value);
    return value;
  };
  const invalidateMonitorPreview = (reason: string) => {
    if (!monitorPreview) return;
    setMonitorPreviewStaleReason(reason);
    setMonitorMessage(reason);
  };
  const refreshMonitorOperations = async () => {
    if (!clientHub.monitorBroadcastReady) return [] as MonitorBroadcastOperation[];
    const result = await clientHub.getMonitorBroadcastOperations();
    const operations = Array.isArray(result.operations) ? result.operations.slice(0, 64) : [];
    setMonitorOperations(operations);
    return operations;
  };
  const acceptMonitorPreview = (preview: MonitorBroadcastPreview,
    bodyFromCurrentMemory: string | null,
    authoritativeTopology: ClientTopologySnapshot | null = topologySnapshot) => {
    if (!preview.operationId || !preview.previewId || !preview.groupId ||
        !preview.monitorEndpointId || !preview.source?.endpointId ||
        preview.source.endpointId !== preview.monitorEndpointId ||
        !preview.monitorKeyId || !preview.monitorBindingId ||
        !Number.isSafeInteger(preview.monitorBindingEpoch) || preview.monitorBindingEpoch < 1 ||
        !/^[0-9a-f]{64}$/.test(preview.bodySha256) ||
        !/^[0-9a-f]{64}$/.test(preview.snapshotDigest) ||
        !/^[0-9a-f]{64}$/.test(preview.consentDigest) ||
        !Number.isSafeInteger(preview.groupRevision) || preview.groupRevision < 1 ||
        monitorPreviewConfirmationCutoffMs(preview) === null ||
        !Array.isArray(preview.recipients) ||
        preview.recipients.length > MONITOR_BROADCAST_MAX_RECIPIENTS ||
        !['PREPARED', 'APPROVED', 'DISPATCH_AUTHORIZED'].includes(preview.status)) {
      throw new Error('安全桥没有返回完整、已验证的 Advisor 同意预览');
    }
    if (preview.source.ownerId !== monitorOwnerId ||
        preview.recipients.some(recipient => recipient.ownerId !== monitorOwnerId)) {
      throw new Error('Advisor 预览身份不属于当前 Owner；已拒绝显示');
    }
    const endpointIds = [preview.source.endpointId,
      ...preview.recipients.map(recipient => recipient.endpointId)];
    if (new Set(endpointIds).size !== endpointIds.length ||
        preview.recipients.some((recipient, index) => index > 0 &&
          preview.recipients[index - 1].endpointId > recipient.endpointId)) {
      throw new Error('Advisor 预览中的 Endpoint roster 无效或未按协议排序');
    }
    if ([preview.source, ...preview.recipients].some(card =>
      !card.principalId || !card.ownerId || !card.nodeId ||
      !Number.isSafeInteger(card.membershipRevision) || card.membershipRevision < 1 ||
      !Number.isSafeInteger(card.groupJoinRevision) || card.groupJoinRevision < 1 ||
      !card.bindingId || !Number.isSafeInteger(card.bindingEpoch) || card.bindingEpoch < 1 ||
      !card.keyId || !Number.isSafeInteger(card.keyVersion) || card.keyVersion < 1 ||
      !/^sha256:[0-9a-f]{64}$/.test(card.keyFingerprint) ||
      !/^[0-9a-f]{64}$/.test(card.keyProofDigest))) {
      throw new Error('安全桥返回的同意卡片缺少必需身份或版本信息');
    }
    setMonitorPreview(preview);
    setMonitorPreparedBody(bodyFromCurrentMemory);
    setMonitorNeedsBodyReentry(bodyFromCurrentMemory === null);
    const confirmAlreadyTried = preview.status !== 'PREPARED' || preview.canConfirm === false;
    monitorConfirmAttemptedRef.current = confirmAlreadyTried;
    setMonitorConfirmAttempted(confirmAlreadyTried);
    setMonitorStatus(null);
    setMonitorStatusPreviewId('');
    const staleReason = monitorPreviewConfirmationExpiryReason(preview) ||
      getMonitorPreviewStaleReason(preview, authoritativeTopology, monitorOwnerId) || '';
    setMonitorPreviewStaleReason(staleReason);
    setMonitorMessage(staleReason || (confirmAlreadyTried ?
      '已恢复只读预览；确认操作已尝试，只能读取同一预览状态。' :
      '已验证同一 Owner 的固定 roster 和 Advisor Endpoint 密钥授权。'));
  };
  const toggleBroadcastPermission = (membership: JsonObject) => {
    const groupId = field(membership, 'group_id');
    const membershipId = field(membership, 'membership_id');
    const version = Number(membership.version);
    if (!groupId || !membershipId || !Number.isSafeInteger(version) || version < 1 ||
        !membershipIsActive(membership) || !monitorTopologyApplyAllowed) return;
    const nextEnabled = !membershipAllowsBroadcast(membership);
    applyTopology({kind: 'membership.set_broadcast_permission', set_broadcast_permission: {
      group_id: groupId, membership_id: membershipId, enabled: nextEnabled,
      expected_membership_version: version,
    }}, nextEnabled ? '明确授予 message.broadcast' : '撤销 message.broadcast');
  };
  const prepareMonitorBroadcast = async () => {
    if (monitorSessionBlocksWrites(hubStatus)) {
      setMonitorMessage('加密会话存在待恢复请求或未核实结果；先完成原包恢复与状态对账。');
      return;
    }
    if (monitorOperations.some(operation =>
      operation.confirmAttempted && operation.confirmStatusReconciled !== true)) {
      setMonitorMessage('已有 Confirm 结果尚未核实；只能读取原预览状态，不能开始新的 Prepare。');
      return;
    }
    if (!monitorOperationAllowed(hubCapabilities, sessionCapabilities, hubStatus,
      'monitor.broadcast_prepare')) {
      setMonitorMessage('加密 session.capabilities 或已验证的 Advisor 安全桥未授权 Prepare。');
      return;
    }
    const bodyBytes = monitorBodyUtf8ByteLength(monitorBody);
    if (bodyBytes === null) {
      setMonitorMessage('正文含有不完整的 Unicode 字符；请修正后再准备。正文不会被自动替换或规范化。');
      return;
    }
    if (bodyBytes === 0) {
      setMonitorMessage('请先输入要发送的正文；空格和换行会按原样保留。');
      return;
    }
    if (bodyBytes > MONITOR_BROADCAST_BODY_MAX_BYTES) {
      setMonitorMessage(`正文为 ${bodyBytes.toLocaleString()} 个 UTF-8 字节，超过 16,384 字节上限。`);
      return;
    }
    if (!monitorGroupId || !monitorEndpointId) {
      setMonitorMessage('请选择一个 Group 和该 Group 中已单独授权广播的 Advisor Endpoint。');
      return;
    }
    setMonitorBusy(true);
    setMonitorMessage('正在刷新拓扑并由 Android 安全桥准备加密前预览…');
    const sentBody = monitorBodyInspection.exactBody;
    try {
      const freshTopology = await refreshTopology();
      if (!freshTopology) throw new Error('当前加密会话未返回权威拓扑');
      const freshGroup = (freshTopology.groups || []).find(item =>
        field(item, 'group_id') === monitorGroupId &&
        field(item, 'state').toUpperCase() === 'ACTIVE');
      const freshMembership = (freshTopology.memberships || []).find(item =>
        field(item, 'group_id') === monitorGroupId &&
        membershipIsActive(item) && membershipHasMonitorRole(item) &&
        membershipAllowsBroadcast(item) &&
        (freshTopology.endpoints || []).some(endpoint =>
          field(endpoint, 'endpoint_id') === monitorEndpointId &&
          field(endpoint, 'principal_id') === field(item, 'principal_id') &&
          Array.isArray(endpoint.group_ids) && endpoint.group_ids.includes(monitorGroupId)));
      if (!freshGroup || !freshMembership) {
        throw new Error('当前拓扑未确认所选 Group、Advisor 角色与独立广播权限；请重新选择。');
      }
      setMonitorPreparedBody(sentBody);
      setMonitorNeedsBodyReentry(false);
      setMonitorPreview(null);
      setMonitorPreviewStaleReason('');
      setMonitorStatus(null);
      setMonitorConfirmAttempted(false);
      monitorConfirmAttemptedRef.current = false;
      const preview = await clientHub.monitorBroadcastPrepare({
        groupId: monitorGroupId, monitorEndpointId, body: sentBody,
      });
      if (preview.groupId !== monitorGroupId ||
          preview.monitorEndpointId !== monitorEndpointId) {
        throw new Error('安全桥返回的预览与所选 Group/Advisor 不一致');
      }
      acceptMonitorPreview(preview, sentBody, freshTopology);
      await refreshMonitorOperations().catch(() => []);
      setMonitorMessage(`已准备并验证预览；请核对 Advisor 身份、版本与完整 roster。` +
        ` Group 授权截止 ${preview.grantExpiresAt}，最迟可确认至 ${preview.validUntil}。`);
    } catch (error) {
      const code = hubErrorCode(error);
      const msg = errorMessage(error).toLowerCase();
      if (code === 'OUTCOME_UNCERTAIN' || /outcome.?uncertain/.test(msg)) {
        const operationId = hubErrorOperationId(error);
        setMonitorMessage(operationId ?
          'Prepare 结果待核实；只能用原 operation ID 做只读恢复，不会创建新 Prepare。' :
          'Prepare 结果待核实；正在读取本机保存的原 operation ID。不会创建新 Prepare。');
      } else if (/temporarily busy|backpressure|capacity|limit/i.test(msg) ||
          /TEMPORARILY_BUSY|CAPACITY|BACKPRESSURE/.test(code)) {
        setMonitorMessage('Hub 当前暂时繁忙，Advisor 广播容量已满或服务正忙。不会自动重试；稍后由你手动重新准备。');
      } else if (/preview expired|expired/i.test(msg) || /EXPIRED/.test(code)) {
        setMonitorMessage('预览已过期；请读取最新 Group 与权限后重新准备。');
        setMonitorPreviewStaleReason('此预览已过期；需重新准备。');
      } else if (/not currently authorized|unauthorized/i.test(msg) || /AUTHORIZ/.test(code)) {
        setMonitorMessage('Hub 当前未授权此 Advisor 广播。请读取权威 Group 成员与权限状态。');
      } else if (/inputs conflict|CONFLICT/.test(msg) || /CONFLICT/.test(code)) {
        setMonitorMessage('拓扑或版本已变化；请重读 Group 与成员 roster 后重新准备。');
        setMonitorPreviewStaleReason('拓扑已变化；此预览失效。');
      } else {
        setMonitorMessage('Advisor Prepare 未确认成功：' + safeHubError(error) + '。不会自动创建第二个操作。');
      }
      await refreshMonitorOperations().catch(() => []);
      const latest = await clientHub.getStatus().catch(() => null);
      if (latest) setHubStatus(latest);
    } finally {
      setMonitorBusy(false);
    }
  };
  const recoverMonitorBroadcast = async (operationId: string) => {
    if (!monitorOperationAllowed(hubCapabilities, sessionCapabilities, hubStatus,
      'monitor.broadcast_recover')) return;
    const operation = monitorOperations.find(item => item.operationId === operationId);
    if (!operation || operation.confirmAttempted) {
      setMonitorMessage('只读 Prepare 恢复不可用于已尝试的 Confirm；该预览只能读取状态。');
      return;
    }
    setMonitorBusy(true);
    setMonitorMessage('正在用原 Prepare operation ID 查询只读恢复结果…');
    try {
      const preview = await clientHub.monitorBroadcastRecover({operationId});
      if (preview.operationId !== operationId || preview.groupId !== operation.groupId ||
          preview.monitorEndpointId !== operation.monitorEndpointId) {
        throw new Error('安全桥返回了不同的 Prepare operation ID');
      }
      const rememberedBody = monitorPreparedBody;
      acceptMonitorPreview(preview, rememberedBody);
      if (rememberedBody === null) setMonitorNeedsBodyReentry(true);
      await refreshMonitorOperations().catch(() => []);
      setMonitorMessage(preview.status === 'PREPARED' ?
        (rememberedBody === null ?
          '已恢复只读预览。重新输入原文后，安全桥会先比对摘要；不匹配时不会签名或发送。' :
          '已恢复同一 Prepare 的只读预览；请检查版本和完整 roster。') :
        '已恢复同一 Prepare 的只读结果；该操作已进入 Confirm 阶段，只能读取状态。');
    } catch (error) {
      setMonitorMessage('原 Prepare 只读恢复失败：' + safeHubError(error) + '。不会创建新的 Prepare。');
    } finally {
      setMonitorBusy(false);
    }
  };
  const verifyRecoveredMonitorBody = async () => {
    if (!monitorPreview || !monitorNeedsBodyReentry || !clientHub.monitorBroadcastReady) return;
    const bytes = monitorBodyUtf8ByteLength(monitorBody);
    if (bytes === null || bytes === 0 || bytes > MONITOR_BROADCAST_BODY_MAX_BYTES) {
      setMonitorMessage('请重新输入有效 Unicode 正文，且不超过 16,384 UTF-8 字节；尚未联系 Hub。');
      return;
    }
    setMonitorBusy(true);
    setMonitorMessage('Android 安全桥正在本机比对正文摘要；不会发送正文或创建 RPC。');
    try {
      const checked = await clientHub.monitorBroadcastBodyMatches({
        previewId: monitorPreview.previewId, body: monitorBody,
      });
      if (!checked.matches || checked.bodySha256 !== monitorPreview.bodySha256) {
        setMonitorMessage('本机摘要与原 Prepare 不匹配；未签名、未发送。请重新输入原文或放弃此预览。');
        return;
      }
      setMonitorPreparedBody(monitorBody);
      setMonitorNeedsBodyReentry(false);
      setMonitorMessage('本机已确认当前正文与原 Prepare 摘要完全一致；仍需逐项审核并明确批准。');
    } catch (error) {
      setMonitorMessage('本机正文比对失败：' + safeHubError(error) + '。没有发送 Confirm。');
    } finally {
      setMonitorBusy(false);
    }
  };
  const readMonitorBroadcastStatus = async (previewId = monitorPreview?.previewId || '') => {
    if (!previewId || !monitorOperationAllowed(hubCapabilities, sessionCapabilities,
      hubStatus, 'monitor.broadcast_status')) return;
    const expectedPreview = monitorPreview?.previewId === previewId ? monitorPreview : null;
    setMonitorBusy(true);
    setMonitorMessage('正在读取同一 Advisor 预览的权威分发状态…');
    try {
      const status = await clientHub.monitorBroadcastStatus({previewId});
      if (status.previewId !== previewId ||
          (expectedPreview && status.groupId !== expectedPreview.groupId) ||
          !['PREPARED', 'APPROVED', 'DISPATCH_AUTHORIZED'].includes(status.approvalStatus) ||
          !Array.isArray(status.recipients) ||
          status.recipients.length > MONITOR_BROADCAST_MAX_RECIPIENTS ||
          status.recipients.some((recipient, index) =>
            !Number.isSafeInteger(recipient.ordinal) || recipient.ordinal < 0 ||
            recipient.ordinal >= MONITOR_BROADCAST_MAX_RECIPIENTS ||
            (index > 0 && status.recipients[index - 1].ordinal >= recipient.ordinal)) ||
          new Set(status.recipients.map(recipient => recipient.endpointId)).size !==
            status.recipients.length ||
          (expectedPreview && (status.approvalStatus === 'DISPATCH_AUTHORIZED' ?
            status.recipients.length !== expectedPreview.recipients.length ||
              status.recipients.some((recipient, index) =>
                recipient.endpointId !== expectedPreview.recipients[index]?.endpointId ||
                recipient.ordinal !== index) :
            status.recipients.some(recipient => {
              const expectedOrdinal = expectedPreview.recipients.findIndex(card =>
                card.endpointId === recipient.endpointId);
              return expectedOrdinal < 0 || recipient.ordinal !== expectedOrdinal;
            })))) {
        throw new Error('Hub 返回的状态不匹配此预览或其有序 recipient roster');
      }
      setMonitorStatus(status);
      setMonitorStatusPreviewId(previewId);
      setMonitorMessage('已读取此预览的 Hub/Node/Relay 状态。持久化状态不代表 Runtime 或模型消费。');
    } catch (error) {
      setMonitorMessage('读取同一预览状态失败：' + safeHubError(error) + '。不会再次 Confirm。');
    } finally {
      setMonitorBusy(false);
    }
  };
  const performMonitorConfirm = async () => {
    if (!monitorPreview || !monitorFeatureReady || monitorConfirmAttemptedRef.current ||
        !monitorOperationAllowed(hubCapabilities, sessionCapabilities, hubStatus,
          'monitor.broadcast_confirm')) return;
    if (monitorSessionBlocksWrites(hubStatus)) {
      setMonitorMessage('加密会话存在待恢复请求或未核实结果；先完成原包恢复与状态对账。');
      return;
    }
    if (monitorOperations.some(operation =>
      operation.confirmAttempted && operation.confirmStatusReconciled !== true)) {
      setMonitorMessage('已有 Confirm 结果尚未核实；只能读取原预览状态，不能再次批准。');
      return;
    }
    if (monitorPreview.status !== 'PREPARED' || monitorPreview.canConfirm === false) {
      setMonitorMessage('此预览不再允许确认；请只读取它的状态。');
      return;
    }
    const expiryReason = monitorPreviewConfirmationExpiryReason(monitorPreview, Date.now());
    if (expiryReason) {
      setMonitorPreviewStaleReason(expiryReason);
      setMonitorMessage(expiryReason + ' 未发送 Confirm。');
      return;
    }
    const staleReason = getMonitorPreviewStaleReason(monitorPreview, topologySnapshot, monitorOwnerId);
    if (staleReason || monitorPreviewStaleReason) {
      const reason = staleReason || monitorPreviewStaleReason;
      setMonitorPreviewStaleReason(reason);
      setMonitorMessage(reason);
      return;
    }
    const bytes = monitorBodyUtf8ByteLength(monitorBody);
    if (bytes === null || bytes === 0 || bytes > MONITOR_BROADCAST_BODY_MAX_BYTES) {
      setMonitorMessage('正文必须是有效 Unicode 且不超过 16,384 个 UTF-8 字节；未发送 Confirm。');
      return;
    }
    if (monitorPreparedBody !== null && monitorBody !== monitorPreparedBody) {
      setMonitorPreviewStaleReason('正文已更改；此预览只绑定原正文，需重新准备。');
      setMonitorMessage('正文与 Prepare 时不同；未发送 Confirm。');
      return;
    }

    monitorConfirmAttemptedRef.current = true;
    setMonitorConfirmAttempted(true);
    setMonitorBusy(true);
    setMonitorMessage('安全桥正在重读原预览、比对精确正文并按当前序列加密签名…');
    try {
      const result = await clientHub.monitorBroadcastConfirm({
        previewId: monitorPreview.previewId, body: monitorBody,
        consentDigest: monitorPreview.consentDigest,
      });
      if (result.previewId !== monitorPreview.previewId ||
          result.groupId !== monitorPreview.groupId ||
          result.monitorEndpointId !== monitorPreview.monitorEndpointId ||
          result.bodySha256 !== monitorPreview.bodySha256) {
        throw new Error('安全桥 Confirm 结果不匹配此 Advisor 预览');
      }
      setMonitorMessage(`Hub 已确认 ${result.status}。正在读取逐收件人状态；这不表示消息已被 Runtime 或模型消费。`);
      await readMonitorBroadcastStatus(monitorPreview.previewId);
      await refreshMonitorOperations().catch(() => []);
    } catch (error) {
      const code = hubErrorCode(error);
      const outcomeUncertain = code === 'OUTCOME_UNCERTAIN' ||
        /outcome.?uncertain/i.test(errorMessage(error));
      const unlockedWithoutDurableConfirm = outcomeUncertain ? false :
        await reconcileMonitorConfirmAttemptLock(monitorPreview.operationId);
      if (outcomeUncertain) {
        setMonitorMessage('Confirm 结果待核实。只能读取同一 preview 的状态；不会再次签名或发送。');
      } else if (unlockedWithoutDurableConfirm) {
        setMonitorMessage('安全桥记录显示 Confirm 未持久化，因此没有可重发的 Confirm 密文。请先刷新 Group 授权与拓扑；仍在有效期内且权限当前有效时，可重新明确批准。原因：' + safeHubError(error));
      } else {
        setMonitorMessage('Confirm 未确认成功：' + safeHubError(error) +
          '。确认保持锁定；先恢复待处理原包或读取同一预览状态。');
      }
      await refreshMonitorOperations().catch(() => []);
    } finally {
      setMonitorBusy(false);
    }
  };
  const requestMonitorConfirm = () => {
    if (!monitorPreview) return;
    Alert.alert('明确批准此 Advisor 广播',
      `Group ${monitorPreview.groupId} · v${monitorPreview.groupRevision}\n` +
      `Advisor ${monitorPreview.monitorEndpointId}\n` +
      `${monitorPreview.recipients.length} 个有序收件人\n` +
      `Group 授权到期 ${monitorPreview.grantExpiresAt}\n` +
      `Preview 到期 ${monitorPreview.expiresAt} · 最迟可确认 ${monitorPreview.validUntil}\n` +
      `正文 ${monitorBodyBytes?.toLocaleString() || '无效'} / ${MONITOR_BROADCAST_BODY_MAX_BYTES.toLocaleString()} UTF-8 字节\n\n` +
      '安全桥会在手机内核对原正文和新鲜授权后加密签名。确认尝试后只可查询此预览状态。', [
        {text: '返回检查', style: 'cancel'},
        {text: '明确批准并加密', onPress: async () => { await performMonitorConfirm(); }},
      ]);
  };
  const refreshNodeBindings = async () => {
    const value = await rpcIfAllowed('client_device_management', 'nodes.list', {}) as
      JsonObject[] | undefined;
    if (value) setNodesList(value);
    return value;
  };
  const fetchClientDevices = async () => {
    const generation = clientDevicesGeneration.current;
    setClientDevicesBusy(true);
    setClientDevicesMessage('正在通过加密会话读取本 Owner 的设备…');
    try {
      const current = await clientHub.getStatus();
      setHubStatus(current);
      if (!capsAllows(hubCapabilities, 'client_device_management', 'devices.list', current)) {
        throw new Error('当前加密会话未授权 devices.list');
      }
      const result = await rpc('devices.list', {});
      if (generation !== clientDevicesGeneration.current) return;
      if (!Array.isArray(result)) throw new Error('Hub devices.list 返回格式无效');
      setClientDevices(result.map(asObject));
      setClientDevicesLoaded(true);
      setClientDevicesMessage(`已从 Hub 读取 ${result.length} 台本 Owner 的设备；列表不会自动代表设备在线。`);
    } catch (error) {
      if (generation === clientDevicesGeneration.current) {
        setClientDevices([]);
        setClientDevicesLoaded(false);
        setClientDevicesMessage('设备列表读取失败：' + safeHubError(error));
      }
      throw error;
    } finally {
      if (generation === clientDevicesGeneration.current) setClientDevicesBusy(false);
    }
  };
  const revokeClientDevice = (device: JsonObject) => {
    const targetId = field(device, 'device_id');
    const expectedVersion = Number(device.version);
    if (!targetId || !Number.isSafeInteger(expectedVersion) || expectedVersion < 1 ||
      field(device, 'state') !== 'ACTIVE' || targetId === hubStatus.deviceId) return;
    Alert.alert('永久撤销此 App 设备？',
      `${targetId} · 当前 Hub 版本 v${expectedVersion}\n撤销后该设备的旧密钥和旧请求将被 Hub 拒绝。请核对设备 ID。`, [
        {text: '取消', style: 'cancel'},
        {text: '永久撤销', style: 'destructive', onPress: async () => {
          setClientDevicesBusy(true);
          let accepted = false;
          try {
            const current = await clientHub.getStatus();
            setHubStatus(current);
            if (!capsAllows(hubCapabilities, 'client_device_management', 'devices.revoke', current) ||
              targetId === current.deviceId) throw new Error('当前会话不能撤销此设备');
            await rpc('devices.revoke', {device_id: targetId, expected_version: expectedVersion});
            accepted = true;
            await fetchClientDevices();
            setClientDevicesMessage(`Hub 已确认撤销 ${targetId}，并已重新读取权威设备列表。`);
          } catch (error) {
            if (accepted) {
              setClientDevices([]);
              setClientDevicesLoaded(false);
            } else await fetchClientDevices().catch(() => undefined);
            setClientDevicesMessage(accepted ?
              `Hub 已确认撤销 ${targetId}，但设备列表未能重新读取：${safeHubError(error)}` :
              `撤销 ${targetId} 未确认成功：${safeHubError(error)}。请重新读取权威设备列表。`);
          } finally { setClientDevicesBusy(false); }
        }},
      ]);
  };
  const changeQueuedGoal = (goal: JsonObject, action: 'pause' | 'resume') => {
    const goalId = field(goal, 'goal_id');
    if (!goalId) return;
    Alert.alert(action === 'pause' ? '暂停排队任务？' : '恢复排队任务？',
      `Goal ${goalId}\n此操作只影响尚未被 Node 领取的远端 Worker；不会停止已经运行的原生 Worker。Hub 将再次检查当前状态和版本。`, [
        {text: '取消', style: 'cancel'},
        {text: action === 'pause' ? '暂停排队' : '恢复排队', onPress: async () => {
          setGoalLifecycleBusy(goalId);
          let accepted = false;
          try {
            const current = await clientHub.getStatus();
            setHubStatus(current);
            if (!capsAllows(hubCapabilities, 'queued_goal_lifecycle', 'goal.lifecycle', current) ||
              current.role !== 'manager') throw new Error('当前加密会话未授权 Goal 生命周期操作');
            const fresh = await rpc('status.snapshot', {}) as ClientStatusSnapshot;
            setStatusSnapshot(fresh);
            setSnapshotVerifiedAt(Date.now());
            setStatusSyncError('');
            const freshGoal = (fresh.goals || []).find(item => field(item, 'goal_id') === goalId);
            if (!freshGoal || queuedGoalAction(freshGoal,
              indexWorkersById(fresh.workers || [])) !== action) {
              throw new Error('Goal 或 Worker 的权威状态已变化；请按新快照决定是否操作');
            }
            const expectedVersion = Number(freshGoal.lifecycle_version);
            if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
              throw new Error('Hub 快照没有可用的 Goal 生命周期版本');
            }
            await rpc('goal.lifecycle', {goal_id: goalId, action,
              expected_version: expectedVersion});
            accepted = true;
            await refreshRemoteData();
            setHubMessage(`Hub 已确认 Goal ${goalId}${action === 'pause' ? '暂停排队' : '恢复排队'}，权威状态已重读。`);
          } catch (error) {
            setHubMessage(accepted ?
              `Hub 已确认 Goal ${goalId} 的生命周期操作，但后续状态刷新失败：${safeHubError(error)}` :
              `Goal ${goalId} 的生命周期操作未确认成功：${safeHubError(error)}。不会自动重试。`);
            if (!accepted) await refreshRemoteData().catch(() => undefined);
          } finally { setGoalLifecycleBusy(null); }
        }},
      ]);
  };
  const revokeNode = (binding: JsonObject) => Alert.alert('撤销 Node 绑定？',
    `${field(binding, 'node_name') || field(binding, 'node_id')} · v${field(binding, 'version')}`, [
      {text: '取消', style: 'cancel'},
      {text: '撤销', style: 'destructive', onPress: async () => {
        setTopologyActionBusy(true);
        let accepted = false;
        try {
          await rpc('nodes.revoke', {binding_id: field(binding, 'id'),
            expected_version: Number(binding.version)});
          accepted = true;
          await refreshNodeBindings();
          setHubMessage('Hub 已确认撤销 Node 绑定；权威列表已重读。');
        } catch (error) {
          setNodesList([]);
          setHubMessage((accepted ? 'Hub 已确认撤销，但 Node 列表未能重读：' :
            'Node 撤销未确认成功：') + safeHubError(error) + '。请重新读取权威 Node 列表。');
          if (!accepted) await refreshNodeBindings().catch(() => undefined);
        }
        finally { setTopologyActionBusy(false); }
      }},
    ]);
  const decideApproval = (approval: JsonObject, decision: 'accept' | 'decline') =>
    Alert.alert(decision === 'accept' ? '批准此操作？' : '拒绝此操作？',
      `${field(approval, 'method')} · Goal ${field(approval, 'goal_id')}\n\n请求详情：${JSON.stringify(approval.request || {}, null, 2)}`,
      [{text: '取消', style: 'cancel'}, {text: decision === 'accept' ? '批准' : '拒绝',
        style: decision === 'decline' ? 'destructive' : 'default', onPress: async () => {
          setTopologyActionBusy(true);
          let accepted = false;
          try {
            await rpc('approvals.decide', {approval_id: field(approval, 'id'), decision});
            accepted = true;
            const refreshed = await rpcIfAllowed('approval_read_and_decide', 'approvals.list',
              {pending_only: true}) as JsonObject[] | undefined;
            if (!refreshed) throw new Error('当前会话无法重读审批列表');
            setApprovals(refreshed);
            setHubMessage('Hub 已确认审批决定；待处理列表已重读。');
          } catch (error) {
            setApprovals([]);
            setHubMessage((accepted ? 'Hub 已确认审批决定，但列表未能重读：' :
              '审批决定未确认成功：') + safeHubError(error) + '。请重新读取权威审批状态。');
            if (!accepted) await refreshRemoteData().catch(() => undefined);
          }
          finally { setTopologyActionBusy(false); }
        }}]);
  const applyTopology = async (action: Record<string, unknown>, title: string) => {
    if (!activeNetwork) {
      setHubMessage('请先明确选择 ACTIVE Network。');
      return;
    }
    const selectedGroups = new Set(selectedNetworkGroups.map(group => field(group, 'group_id')));
    const kind = field(action, 'kind');
    const affectedGroup = Object.values(action).filter(value => typeof value === 'object' && value !== null)
      .map(asObject).flatMap(value => [field(value, 'group_id'), field(value, 'parent_group_id'),
        field(asObject(value.proposal), 'source_group_id'), field(asObject(value.proposal), 'target_group_id')])
      .filter(Boolean);
    if (affectedGroup.some(id => !selectedGroups.has(id)) ||
      (kind === 'group.create' && field(asObject(asObject(action.create_group).group), 'network_id') !== activeNetwork.network_id)) {
      setHubMessage('Group 操作必须属于当前明确选择的 Network；请重读拓扑并核对 ID。');
      return;
    }
    Alert.alert(title, `Hub ${hubStatus.hubId}\nNetwork ${activeNetwork.network_id}\n\n此操作将提交给 Hub，并按对象版本校验。`, [
      {text: '取消', style: 'cancel'},
      {text: '提交', onPress: async () => {
        invalidateMonitorPreview('Hub 拓扑写入会使 Advisor 预览失效；需重读 roster 并重新准备。');
        setTopologyActionBusy(true);
        let accepted = false;
        try {
          await rpc('topology.apply', action);
          accepted = true;
          setTopologySnapshot(null);
          await refreshTopology();
          setHubMessage(`${title} 已由 Hub 确认，权威拓扑已重读。`);
        } catch (error) {
          setTopologySnapshot(null);
          setHubMessage(accepted ?
            `${title} 已由 Hub 确认，但权威拓扑未能重读：${safeHubError(error)}` :
            `${title} 未确认成功：${safeHubError(error)}。请重读权威拓扑。`);
          if (!accepted) await refreshTopology().catch(() => undefined);
        }
        finally { setTopologyActionBusy(false); }
      }},
    ]);
  };
  const createGroup = () => {
    try {
      const action = createGroupRequest(topologySnapshot, hubStatus.activeNetworkId,
        groupName, parentGroupId);
      applyTopology({...action}, '创建 Group');
    } catch (error) { setHubMessage(errorMessage(error)); }
  };
  const previewGroupKey = async () => {
    const groupId = keyGroupId.trim();
    const endpointId = keyEndpointId.trim();
    const ownerKeyId = keyOwnerId.trim();
    if (!groupId || !endpointId || !ownerKeyId) return;
    if (!selectedNetworkGroups.some(group => field(group, 'group_id') === groupId)) {
      setHubMessage('请使用当前 Network 中的 Group。');
      return;
    }
    setKeyConsentBusy(true);
    setVerifiedKeyManifest(null);
    setKeySignedProof('');
    setKeyGrantStatus(null);
    try {
      const response = await clientHub.previewGroupKey({groupId, endpointId, ownerKeyId});
      if (!response.ok || response.verified !== true) throw new Error('Endpoint 证明未通过完整验证');
      setVerifiedKeyManifest(response.result);
      setHubMessage('Endpoint 证明、公钥、绑定与 manifest 摘要已在设备上验证。请核对身份和有效期，再由独立 owner 签名器签署。');
    } catch (error) { setHubMessage('Group 密钥预览失败：' + safeHubError(error)); }
    finally { setKeyConsentBusy(false); await refreshHubStatus(); }
  };
  const refreshGroupKeyStatus = async (groupId = keyGroupId.trim(), endpointId = keyEndpointId.trim()) => {
    if (!groupId || !endpointId || !operationAllowed(hubStatus, 'group.key_status')) return;
    setKeyConsentBusy(true);
    try {
      const response = await clientHub.groupKeyStatus({groupId, endpointId});
      if (!response.ok || !response.result) throw new Error('Hub 未返回此 Group 与 Endpoint 的当前授权');
      setKeyGrantStatus(response.result);
      setHubMessage('已读取 Hub 的当前 Group Endpoint 公钥授权状态。');
    } catch (error) {
      setKeyGrantStatus(null);
      setHubMessage('读取 Group 公钥授权状态失败：' + safeHubError(error));
    } finally { setKeyConsentBusy(false); await refreshHubStatus(); }
  };
  const approveGroupKey = () => {
    const manifest = verifiedKeyManifest;
    if (!manifest || !keySignedProof.trim()) return;
    const groupId = field(manifest, 'group_id');
    const endpointId = field(manifest, 'endpoint_id');
    const ownerKeyId = field(manifest, 'owner_key_id');
    const expectedDigest = field(manifest, 'digest');
    Alert.alert('明确授权 Group Endpoint 公钥',
      `Group ${groupId}\nEndpoint ${endpointId}\nPrincipal ${field(manifest, 'principal_id')}\nNode ${field(manifest, 'node_id')}\nBinding ${field(manifest, 'binding_id')} / epoch ${field(manifest, 'binding_epoch')}\nGroup/Membership/Join revisions ${field(manifest, 'group_revision')}/${field(manifest, 'membership_revision')}/${field(manifest, 'endpoint_join_revision')}\n公钥指纹 ${field(manifest, 'candidate_fingerprint')}\nManifest ${expectedDigest}\n截止 ${field(manifest, 'expires_at')}\n\n只有独立 owner 签名与新鲜 manifest 均匹配才提交。`, [
        {text: '取消', style: 'cancel'},
        {text: '批准并提交', onPress: async () => {
          setKeyConsentBusy(true);
          try {
            const result = await clientHub.grantGroupKey({groupId, endpointId, ownerKeyId,
              expectedDigest, signedProofBase64: keySignedProof.trim()}) as {ok?: boolean; result?: JsonObject};
            if (!result.ok) throw new Error('Hub 未确认 Group Key Grant');
            const current = await clientHub.groupKeyStatus({groupId, endpointId});
            if (!current.ok || !current.result) throw new Error('Hub 未返回授权后的权威状态');
            setKeyGrantStatus(current.result);
            setHubMessage('Hub 已接受 owner 签名；权威状态：' + field(current.result, 'current_status'));
            setVerifiedKeyManifest(null);
            setKeySignedProof('');
          } catch (error) {
            setVerifiedKeyManifest(null);
            setHubMessage('Group Key Grant 未确认：' + safeHubError(error) + '。请重新读取权威 manifest。');
          } finally { setKeyConsentBusy(false); await refreshHubStatus(); }
        }},
      ]);
  };
  const joinGroup = () => {
    if (!joinEndpointId.trim() || !joinGroupId.trim()) return;
    applyTopology({kind: 'endpoint.join_group', join_group: {
      endpoint_id: joinEndpointId.trim(), group_id: joinGroupId.trim(),
    }}, '加入 Group');
  };
  const leaveGroup = () => {
    if (!leaveEndpointId.trim() || !leaveGroupId.trim() || !leaveBindingId.trim() ||
        !leaveBindingEpoch.trim() || !Number.isInteger(Number(leaveBindingEpoch))) return;
    applyTopology({kind: 'endpoint.leave_group', leave_group: {
      endpoint_id: leaveEndpointId.trim(), group_id: leaveGroupId.trim(),
      binding_id: leaveBindingId.trim(), expected_binding_epoch: Number(leaveBindingEpoch),
    }}, '将 Endpoint 移出 Group');
  };
  const bindRole = () => {
    if (!roleMembershipId.trim() || !roleGroupId.trim()) return;
    const membership = (topologySnapshot?.memberships || []).find(item =>
      field(item, 'membership_id') === roleMembershipId.trim() &&
      field(item, 'group_id') === roleGroupId.trim());
    if (!membership) { setHubMessage('找不到对应 Group 的 Membership；请先刷新拓扑'); return; }
    applyTopology({kind: 'membership.bind_role', bind_role: {
      group_id: roleGroupId.trim(), membership_id: roleMembershipId.trim(),
      role: roleValue.trim(), expected_membership_version: Number(membership.version),
    }}, '更新 Group 角色');
  };
  const setGroupParent = (group: JsonObject) => {
    const nextParent = parentGroupId.trim();
    applyTopology({kind: 'group.set_parent', set_parent: {
      group_id: field(group, 'group_id'),
      ...(nextParent ? {parent_group_id: nextParent} : {}),
      expected_group_version: Number(group.version),
    }}, '更新 Group 层级');
  };
  const proposeSameOwnerLink = () => {
    const scopes = linkScopes.split(',').map(item => item.trim()).filter(Boolean);
    if (!linkSourceEndpointId.trim() || !linkSourceGroupId.trim() ||
        !linkTargetEndpointId.trim() || !linkTargetGroupId.trim() || !scopes.length ||
        !Number.isFinite(Date.parse(linkExpiresAt)) || Date.parse(linkExpiresAt) <= Date.now()) {
      setHubMessage('请填写同 Owner 的 Source/Target、允许的数据范围和未来 RFC3339 到期时间。');
      return;
    }
    applyTopology({kind: 'link.propose', propose_link: {proposal: {
      source_endpoint_id: linkSourceEndpointId.trim(), source_group_id: linkSourceGroupId.trim(),
      target_endpoint_id: linkTargetEndpointId.trim(), target_group_id: linkTargetGroupId.trim(),
      direction: 'forward', actions: ['ask', 'reply'], data_scopes: scopes,
      expires_at: linkExpiresAt.trim(),
    }}}, '提交同 Owner Link 提案');
  };
  const revokeLink = (link: JsonObject) => applyTopology({kind: 'link.revoke', revoke_link: {
    link_id: field(link, 'link_id'), expected_link_version: Number(link.version),
    reason: 'owner_requested',
  }}, '撤销 Link 提案');

  useEffect(() => {
    refreshModels();
    const status = DeviceEventEmitter.addListener('CicadaSpeechStatus', event => {
      if (event?.sessionId && event.sessionId !== voiceSessionRef.current) return;
      const message = String(event?.message || '');
      setVoiceStatus(message);
      if (message.includes('下载') || message.includes('安装') || message.includes('校验')) {
        setModelStatus(message);
      }
    });
    const result = DeviceEventEmitter.addListener('CicadaSpeechResult', event => {
      if (!speechEventBelongsToSession(voiceSessionRef.current, event)) return;
      const text = String(event?.text || '').trim();
      if (!text) return;
      if (event.partial) setVoiceStatus('识别中：' + text);
      else {
        setDraft(previous => previous.trim() ? previous.trim() + ' ' + text : text);
        setVoiceStatus('转写完成，可编辑后发送');
      }
    });
    const stopped = DeviceEventEmitter.addListener('CicadaSpeechStopped', event => {
      if (!speechEventBelongsToSession(voiceSessionRef.current, event)) return;
      setRecording(false);
      setVoiceBusy(false);
    });
    return () => { status.remove(); result.remove(); stopped.remove(); };
  }, [setVoiceBusy]);

  const initializeHubSessionRef = useRef(initializeHubSession);
  initializeHubSessionRef.current = initializeHubSession;
  const refreshRemoteDataRef = useRef(refreshRemoteData);
  refreshRemoteDataRef.current = refreshRemoteData;
  const refreshTopologyRef = useRef(refreshTopology);
  refreshTopologyRef.current = refreshTopology;
  const refreshMonitorOperationsRef = useRef(refreshMonitorOperations);
  refreshMonitorOperationsRef.current = refreshMonitorOperations;
  const activeTabRef = useRef(tab);
  activeTabRef.current = tab;
  const refreshStatusChangesRef = useRef(refreshStatusChanges);
  refreshStatusChangesRef.current = refreshStatusChanges;

  useEffect(() => {
    initializeHubSessionRef.current().catch(error =>
      setHubMessage('初始化 Hub 会话失败：' + safeHubError(error)));
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setClockNow(Date.now()), 60_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!showMonitorPanel || !monitorFeatureReady) return;
    let active = true;
    const syncMonitor = () => {
      if (active) setMonitorNow(Date.now());
    };
    syncMonitor();
    const timer = setInterval(syncMonitor, 1000);
    refreshTopologyRef.current().catch(error => {
      if (active) setMonitorMessage('刷新 Advisor 拓扑失败：' + safeHubError(error));
    });
    refreshMonitorOperationsRef.current().catch(error => {
      if (active) setMonitorMessage('读取本机 Advisor 操作索引失败：' + safeHubError(error));
    });
    return () => { active = false; clearInterval(timer); };
  }, [showMonitorPanel, monitorFeatureReady]);

  useEffect(() => {
    if (!monitorPreview) return;
    const staleReason = monitorPreviewConfirmationExpiryReason(monitorPreview, monitorNow) ||
      getMonitorPreviewStaleReason(monitorPreview, topologySnapshot, monitorOwnerId);
    if (staleReason) setMonitorPreviewStaleReason(previous => previous || staleReason);
  }, [monitorPreview, monitorNow, topologySnapshot, monitorOwnerId]);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', state => {
      if (state !== 'active') setRecoveredInvite(null);
    });
    return () => subscription.remove();
  }, []);

  useEffect(() => {
    if (!hubStatus.remoteEnabled || !hubStatus.sessionCapabilitiesReady || !hubCapabilities) return;
    let active = true;
    const sync = async () => {
      if (!active || AppState.currentState !== 'active') return;
      try {
        if (Date.now() - lastFullReconcileAt.current >= 300_000) {
          await refreshRemoteDataRef.current(hubCapabilities, activeTabRef.current === 'panel');
        } else {
          await refreshStatusChangesRef.current(hubCapabilities);
        }
      } catch (error) {
        setStatusSyncError('最近一次 Hub 同步失败：' + safeHubError(error));
        setHubMessage('状态同步失败：' + safeHubError(error));
      }
    };
    const timer = setInterval(() => { sync().catch(() => undefined); }, 45_000);
    const appStateSubscription = AppState.addEventListener('change', state => {
      if (state === 'active') sync().catch(() => undefined);
    });
    return () => {
      active = false;
      clearInterval(timer);
      appStateSubscription.remove();
    };
  }, [hubStatus.remoteEnabled, hubStatus.sessionCapabilitiesReady, hubCapabilities]);

  useEffect(() => {
    if (!realSession || !hubCapabilities) return;
    const managementDue = tab === 'panel' &&
      Date.now() - lastManagementReconcileAt.current >= 60_000;
    if (!managementDue && Date.now() - lastFullReconcileAt.current < 60_000) return;
    refreshRemoteDataRef.current(hubCapabilities, tab === 'panel').catch(error =>
      setHubMessage('页面状态刷新失败：' + safeHubError(error)));
  }, [tab, realSession, hubCapabilities]);

  const stopVoice = async () => {
    if (voiceTimerRef.current) { clearTimeout(voiceTimerRef.current); voiceTimerRef.current = null; }
    try { await speechDevice?.stopListening(); } catch {}
    setRecording(false);
    connection.setVoiceBusy(false);
  };
  const closeComposer = () => {
    stopVoice();
    setCompose(false);
    setDraft('');
    setVoiceStatus('');
  };
  const startVoice = async () => {
    if (!mountedRef.current) return;
    if (recording) {
      await stopVoice();
      setVoiceStatus('录音已停止 · 转写结果可编辑');
      return;
    }
    voiceSessionRef.current = '';
    if (!speechDevice) {
      setVoiceStatus('此平台的离线语音适配尚未接入，可直接输入文字');
      return;
    }
    if (!selectedModel) {
      setVoiceStatus('请先在「设置」安装并选择离线模型，或直接输入文字');
      return;
    }
    if (Platform.OS === 'android') {
      connection.setVoiceBusy(true);
      const granted = await PermissionsAndroid.request(
        PermissionsAndroid.PERMISSIONS.RECORD_AUDIO);
      if (!mountedRef.current) return;
      if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
        connection.setVoiceBusy(false);
        setVoiceStatus('未获得麦克风权限，仍可直接输入文字');
        return;
      }
    }
    try {
      voiceSessionRef.current = clientHub.scope.profileId + ':' +
        clientHub.scope.selectionGeneration + ':' + Date.now().toString(36);
      await speechDevice.startListening(voiceSessionRef.current);
      setRecording(true);
    } catch {
      connection.setVoiceBusy(false);
      setVoiceStatus('无法启动本地转写，请重试或直接输入文字');
    }
  };
  const openComposer = (voice: boolean) => {
    setCompose(true);
    setVoiceStatus(selectedModel ? selectedModel.name + ' 已就绪 · 录音不会上传'
      : '未安装模型 · 可直接输入文字');
    if (voice) {
      connection.setVoiceBusy(true);
      voiceTimerRef.current = setTimeout(() => {
        voiceTimerRef.current = null;
        startVoice().finally(() => { if (!recording && !voiceSessionRef.current) connection.setVoiceBusy(false); });
      }, 180);
    }
  };
  const installModel = async (model: SpeechModel) => {
    if (!speechDevice || modelBusyId) return;
    setModelBusyId(model.id);
    setModelActionId(model.id);
    setModelStatus('正在下载 ' + model.name + ' · ' + sizeLabel(model.downloadBytes));
    try {
      setModelStatus(await speechDevice.installModel(model.id));
      await refreshModels();
    } catch (error) { setModelStatus(errorMessage(error)); }
    finally { setModelBusyId(null); }
  };
  const selectModel = async (model: SpeechModel) => {
    if (!speechDevice || modelBusyId) return;
    setModelActionId(model.id);
    try {
      await speechDevice.selectModel(model.id);
      setModelStatus('已选择 ' + model.name);
      await refreshModels();
    } catch (error) { setModelStatus('选择失败：' + errorMessage(error)); }
  };
  const removeModel = (model: SpeechModel) => Alert.alert('删除 ' + model.name + '？',
    '删除后仍可直接输入文字。', [
      {text: '取消', style: 'cancel'},
      {text: '删除', style: 'destructive', onPress: async () => {
        if (!speechDevice) return;
        setModelBusyId(model.id);
        setModelActionId(model.id);
        try {
          setModelStatus(await speechDevice.removeModel(model.id));
          await refreshModels();
        } catch (error) { setModelStatus('删除失败：' + errorMessage(error)); }
        finally { setModelBusyId(null); }
      }},
    ]);

  const page = () => {
    const realStatus = Boolean(statusSnapshot && realSession &&
      hubCapabilities?.status_snapshot);
    const snapshotStale = realStatus && (Boolean(hubStatus.pendingOperationId) ||
      Boolean(statusSyncError) || !snapshotVerifiedAt ||
      clockNow - snapshotVerifiedAt >= 300_000);
    const snapshotWarning = hubStatus.pendingOperationId ?
      '存在结果未确定的原始加密请求；新 RPC 已阻断，显示上次已验签快照。' : statusSyncError ||
      '距上次成功读取 Hub 快照已超过 5 分钟；下方状态可能已过期。';
    const intentHistoryAllowed = intentOperationAvailable('intent.list');
    const intentStatusAllowed = intentOperationAvailable('intent.status');
    const intentGoalResultAllowed = goalResultAvailable();
    const clientDeviceListAllowed = capsAllows(hubCapabilities, 'client_device_management',
      'devices.list', hubStatus);
    const clientDeviceRevokeAllowed = capsAllows(hubCapabilities, 'client_device_management',
      'devices.revoke', hubStatus);
    const monitorExpiryReason = monitorPreview ?
      monitorPreviewConfirmationExpiryReason(monitorPreview, monitorNow) : null;
    const monitorExpired = Boolean(monitorExpiryReason);
    const monitorCurrentStaleReason = monitorPreview ? monitorPreviewStaleReason ||
      monitorExpiryReason ||
      getMonitorPreviewStaleReason(monitorPreview, topologySnapshot, monitorOwnerId) || '' : '';
    const monitorBodyMatchesPrepare = monitorPreparedBody !== null &&
      monitorBody === monitorPreparedBody;
    const monitorUnknownConfirm = monitorOperations.some(operation =>
      operation.confirmAttempted && operation.confirmStatusReconciled !== true);
    const monitorCanConfirm = Boolean(monitorPreview && monitorFeatureReady &&
      monitorPreview.status === 'PREPARED' && monitorPreview.canConfirm !== false &&
      monitorPreview.recipients.length > 0 &&
      !monitorConfirmAttempted && !monitorExpired && !monitorCurrentStaleReason &&
      !monitorUnknownConfirm && !monitorSessionBlocksWrites(hubStatus) &&
      monitorBodyMatchesPrepare &&
      monitorBodyBytes !== null && monitorBodyBytes > 0 &&
      monitorBodyBytes <= MONITOR_BROADCAST_BODY_MAX_BYTES &&
      monitorOperationAllowed(hubCapabilities, sessionCapabilities, hubStatus,
        'monitor.broadcast_confirm'));
    const monitorUnknownPrepare = monitorOperations.some(operation => {
      const state = operation.state.toUpperCase();
      const prepareNotReconciled = !operation.confirmAttempted &&
        (/UNCERTAIN|PENDING|LOST/.test(state) ||
          (!monitorPreview && operation.previewId && state === 'PREPARED'));
      const validUntil = monitorOperationValidUntil(operation);
      return Boolean(prepareNotReconciled && (!validUntil ||
        !monitorPreviewIsExpired(validUntil, monitorNow)));
    });
    const monitorRecoverableOperations = monitorOperations.filter(operation => {
      const samePreview = operation.operationId === monitorPreview?.operationId;
      const validUntil = monitorOperationValidUntil(operation);
      const expired = Boolean(validUntil && monitorPreviewIsExpired(validUntil, monitorNow));
      const state = operation.state.toUpperCase();
      return !samePreview && !expired && !operation.confirmAttempted &&
        !['FAILED', 'REJECTED', 'EXPIRED', 'CANCELLED', 'APPROVED',
          'DISPATCH_AUTHORIZED', 'COMPLETE', 'DONE'].includes(state);
    });
    const monitorStatusOperations = monitorOperations.filter(operation =>
      operation.confirmAttempted && operation.confirmStatusReconciled !== true &&
      Boolean(operation.previewId) &&
      operation.previewId !== monitorPreview?.previewId);
    const realNodes = statusSnapshot?.nodes || [];
    const realWorkers = statusSnapshot?.workers || [];
    const realGoals = statusSnapshot?.goals || [];
    const realGroups = statusSnapshot?.groups || [];
    const runningGoals = realGoals.filter(goal => stateOf(goal.goal_lifecycle) === 'running').length;
    const waitingDecisions = approvals.filter(item => field(item, 'status') === 'pending').length +
      realGoals.filter(goal => ['blocked', 'paused'].includes(stateOf(goal.goal_lifecycle))).length;
    const completedGoals = realGoals.filter(goal => stateOf(goal.goal_lifecycle) === 'completed').length;
    if (tab === 'today') return <>
      <Eyebrow>你的 CICADA</Eyebrow>
      <Text style={s.hero}>工作进展，{'\n'}随时在手。</Text>
      <Text style={s.intro}>{realStatus ?
        `Hub ${snapshotStale ? '上次快照，待对账' : '权威快照'} · ${statusSnapshot?.captured_at || '观察时间未知'} · ${statusSnapshot?.source || '来源未知'}` :
        realSession ? '加密会话已验证，正在读取 Hub 权威快照。' :
          '连接 Hub 后查看权威状态。'}</Text>
      {snapshotStale && <Notice>{snapshotWarning} 仍可查看上次已验签快照，请重新连接并刷新。</Notice>}
      <View style={s.darkCard}>
        <Text style={s.darkKicker}>{realStatus ?
          snapshotStale ? '状态概览 · 上次 Hub 快照' : '状态概览 · Hub 快照' :
          '状态概览 · 等待安全会话'}</Text>
        <View style={s.metrics}>
          <Metric value={realStatus ? String(runningGoals).padStart(2, '0') : '—'} label="运行中" />
          <Metric value={realStatus ? String(waitingDecisions).padStart(2, '0') : '—'} label="等待决定" />
          <Metric value={realStatus ? String(completedGoals).padStart(2, '0') : '—'} label="已完成" />
        </View>
        <Text style={s.darkNote}>{realStatus ?
          `快照来源：${statusSnapshot?.source || 'Hub'} · 一致性：${statusSnapshot?.read_consistency || '未知'}` :
          hubStatus.authFenced ? '设备认证已隔离 · 远程功能关闭' :
            realSession ? 'Hub 会话已认证 · 尚无权威快照' : '尚未建立经认证的 Hub 会话 · 状态未知'}</Text>
      </View>
      <Section name="需要关注" action="查看全部" onPress={() => setTab('work')} />
      {realStatus ? <>
        {approvals.slice(0, 3).map(approval => <Card key={field(approval, 'id')}
          onPress={() => show('审批 ' + field(approval, 'id'),
            `Goal ${field(approval, 'goal_id')} · ${field(approval, 'method')}\n状态：${field(approval, 'status')}\n来源：Hub approvals.list\n${JSON.stringify(approval.request || {}, null, 2)}`)}>
          <Pill text="等待用户决定" tone="amber" />
          <Text style={[s.cardTitle, s.space]}>{field(approval, 'method') || '待处理审批'}</Text>
          <Text style={s.description}>Goal {field(approval, 'goal_id')} · Hub 审批记录</Text>
        </Card>)}
        {realGoals.filter(goal => ['blocked', 'paused', 'failed'].includes(
          field(observation(goal.goal_lifecycle) as JsonObject, 'state'))).slice(0, 3).map(goal =>
          <Card key={field(goal, 'goal_id')} onPress={() => show('Goal ' + field(goal, 'goal_id'),
            `状态：${observationLabel(goal.goal_lifecycle)}\n${observationMeta(goal.goal_lifecycle)}`)}>
            <Pill text={observationLabel(goal.goal_lifecycle)} tone="amber" />
            <Text style={[s.cardTitle, s.space]}>Goal {field(goal, 'goal_id')}</Text>
            <Text style={s.description}>{observationMeta(goal.goal_lifecycle)}</Text>
          </Card>)}
        {approvals.length === 0 && realGoals.length === 0 &&
          <Notice>Hub 快照中没有可显示的 Goal 或待处理审批。</Notice>}
      </> : <Notice>尚未读取 Hub 权威状态；没有展示示例 Goal 或审批。</Notice>}
      <Section name="节点与工作" action="节点详情" onPress={() => setTab('nodes')} />
      {realStatus ? <VisibleItems items={realNodes} pageSize={6} renderItem={node => <Card key={field(node, 'node_id')} onPress={() => setTab('nodes')}>
        <View style={s.row}><Text style={s.cardTitle}>{field(node, 'name') || field(node, 'node_id')}</Text>
          <Pill text={observationLabel(node.node_connectivity)} tone="muted" /></View>
        <Text style={s.description}>{workersPerNode.get(field(node, 'node_id')) || 0} 个 Worker · {observationMeta(node.node_connectivity)}</Text>
      </Card>} /> : <Notice>尚未建立安全会话；连接后读取 Hub 上的 Node 和 Worker。</Notice>}
    </>;
    if (tab === 'nodes') return <>
      <Heading eyebrow="部署状态" title="节点"
        subtitle="Node 在线、Worker 运行与 Goal 结果分别判断。" />
      {realStatus ? <>
        {snapshotStale && <Notice>{snapshotWarning} 下方保留上次已验签快照。</Notice>}
        <Notice>Hub 权威快照 · {statusSnapshot?.captured_at || '观察时间未知'} · 来源：{statusSnapshot?.source || 'Hub'}</Notice>
        <Section name="Nodes" />
        <VisibleItems items={realNodes} renderItem={node => {
          const id = field(node, 'node_id');
          return <Card key={id} onPress={() => show(field(node, 'name') || id,
            `Node ${id}\n已验证绑定：${node.verified === true ? '是' : '否'}\n状态：${observationLabel(node.node_connectivity)}\n${observationMeta(node.node_connectivity)}`)}>
            <View style={s.row}><Text style={s.cardTitle}>{field(node, 'name') || id}</Text>
              <Pill text={observationLabel(node.node_connectivity)} tone="muted" /></View>
            <Text style={s.description}>{id} · {workersPerNode.get(id) || 0} 个 Worker · {observationMeta(node.node_connectivity)}</Text>
          </Card>;
        }} />
        <Section name="Workers" />
        <VisibleItems items={realWorkers} renderItem={worker => <Card key={field(worker, 'worker_id')}
          onPress={() => show('Worker ' + field(worker, 'worker_id'),
            `Goal：${field(worker, 'goal_id') || '无'}\nNode：${field(worker, 'node_id') || '未知'}\n${observationMeta(worker.worker_execution)}`)}>
          <View style={s.row}><Text style={s.cardTitle}>{field(worker, 'worker_id')}</Text>
            <Pill text={observationLabel(worker.worker_execution)} tone="muted" /></View>
          <Text style={s.description}>Goal {field(worker, 'goal_id') || '—'} · Node {field(worker, 'node_id') || '—'}</Text>
          <Text style={s.small}>{observationMeta(worker.worker_execution)}</Text>
        </Card>} />
        <Section name="Endpoints / Native Session" />
        <VisibleItems items={statusSnapshot?.endpoints || []} renderItem={endpoint => <Card key={field(endpoint, 'endpoint_id')}>
          <View style={s.row}><Text style={s.cardTitle}>{field(endpoint, 'name') || field(endpoint, 'endpoint_id')}</Text>
            <Pill text={observationLabel(endpoint.presence)} tone="muted" /></View>
          <Text style={s.description}>Node {field(endpoint, 'node_id') || '未知'} · Native Session {observationLabel(endpoint.native_session)}</Text>
          <Text style={s.small}>{observationMeta(endpoint.presence)} · {observationMeta(endpoint.native_session)}</Text>
        </Card>} />
      </> : <Notice>尚未连接 Hub；建立安全会话后显示真实 Node 状态。</Notice>}
    </>;
    if (tab === 'work') return <>
      <Heading eyebrow="目标与团队" title="工作"
        subtitle="Goal、Worker 和 Group 的进度各有来源。" />
      {intentHistoryAllowed && <Section name="Control 请求"
        action="查看请求历史" onPress={() => pageScrollRef.current?.scrollToEnd({animated: true})} />}
      {realStatus ? <Notice>Hub 权威快照 · {statusSnapshot?.captured_at || '观察时间未知'} · {statusSnapshot?.read_consistency || '一致性未知'}</Notice>
        : <Notice>尚未连接 Hub；建立安全会话后显示真实工作状态。</Notice>}
      {snapshotStale && <Notice>{snapshotWarning} 下方保留上次已验签快照。</Notice>}
      <Section name="Goals" />
      {hubCapabilities?.queued_goal_lifecycle && operationAllowed(hubStatus, 'goal.lifecycle') &&
        <Notice>仅可暂停或恢复尚未被领取的远端排队 Worker；已运行的原生 Worker 不会因此停止。操作前会重读 Hub 快照和版本。</Notice>}
      {realStatus ? <>
        <VisibleItems items={realGoals} renderItem={goal => {
          const action = queuedGoalAction(goal, workersById);
          const mayChange = !snapshotStale && action && !goalLifecycleBusy &&
            hubStatus.role === 'manager' &&
            capsAllows(hubCapabilities, 'queued_goal_lifecycle', 'goal.lifecycle', hubStatus);
          return <Card key={field(goal, 'goal_id')}>
            <View style={s.row}><Text style={s.cardTitle}>Goal {field(goal, 'goal_id')}</Text>
              <Pill text={observationLabel(goal.goal_lifecycle)} tone="muted" /></View>
            <Text style={s.description}>{Array.isArray(goal.worker_ids) ? goal.worker_ids.length : 0} 个 Worker · {field(goal, 'node_id') || 'Node 未知'}</Text>
            <Text style={s.small}>{observationMeta(goal.goal_lifecycle)} · Hub lifecycle v{field(goal, 'lifecycle_version') || '—'}</Text>
            <Pressable onPress={() => show('Goal ' + field(goal, 'goal_id'),
              `状态：${observationLabel(goal.goal_lifecycle)}\n版本：${field(goal, 'lifecycle_version')}\n${observationMeta(goal.goal_lifecycle)}`)}>
              <Text style={s.link}>查看状态详情  →</Text>
            </Pressable>
            {mayChange && <View style={s.modelActions}><Button
              title={action === 'pause' ? '暂停排队' : '恢复排队'} secondary
              onPress={() => changeQueuedGoal(goal, action)} /></View>}
          </Card>;
        }} />
        <Section name="Workers" />
        <VisibleItems items={realWorkers} renderItem={worker => <Card key={field(worker, 'worker_id')}>
          <View style={s.row}><Text style={s.cardTitle}>{field(worker, 'worker_id')}</Text>
            <Pill text={observationLabel(worker.worker_execution)} tone="muted" /></View>
          <Text style={s.description}>Goal {field(worker, 'goal_id') || '—'} · Attempt {field(worker, 'attempt') || '—'}</Text>
          <Text style={s.small}>{observationMeta(worker.worker_execution)}</Text>
        </Card>} />
        <Section name="Tasks" />
        <VisibleItems items={statusSnapshot?.tasks || []} renderItem={task => <Card key={field(task, 'task_id')}>
          <View style={s.row}><Text style={s.cardTitle}>Task {field(task, 'task_id')}</Text>
            <Pill text={observationLabel(task.task_lifecycle)} tone="muted" /></View>
          <Text style={s.description}>Goal {field(task, 'goal_id') || '—'} · Group {field(task, 'group_id') || '—'}</Text>
          <Text style={s.small}>{observationMeta(task.task_lifecycle)}</Text>
        </Card>} />
        <Section name="Groups" />
        <VisibleItems items={realGroups} renderItem={group => <Card key={field(group, 'group_id')}>
          <View style={s.row}><Text style={s.cardTitle}>{field(group, 'name') || field(group, 'group_id')}</Text>
            <Pill text={observationLabel(group.lifecycle)} tone="muted" /></View>
          <Text style={s.description}>{field(group, 'group_id')} · parent {field(group, 'parent_group_id') || 'none'} · v{field(group, 'version')}</Text>
          <Text style={s.small}>{observationMeta(group.lifecycle)}</Text>
        </Card>} />
        {hubCapabilities?.status_changes_partial && operationAllowed(hubStatus, 'status.changes') && <>
          <Section name="状态变化 · 轮询 · 部分覆盖" />
          <Notice>{hubCapabilities.status_events ? '此视图只读取 status.changes 轮询页；完整事件流未在此界面启用。' : 'status_events=false：不启用实时事件。这里仅展示 status.changes 轮询页，覆盖不完整。'}</Notice>
          {statusChanges.slice(0, 12).map((change, index) => <Card key={change.id || `${change.entity_type}-${change.entity_id}-${index}`}>
            <Text style={s.cardTitle}>{change.entity_type || '实体'} · {change.change_type || '状态变化'}</Text>
            <Text style={s.description}>{change.entity_id || ''} · {change.observed_at || change.created_at || '时间未知'}</Text>
            <Text style={s.small}>来源：Hub status.changes · state {JSON.stringify(change.state ?? {})}</Text>
          </Card>)}
        </>}
      </> : <Notice>建立加密 session.capabilities 会话后，Hub 会返回此 Owner 可查看的 Goal、Worker、Task 和 Group。</Notice>}
      {intentHistoryAllowed && <>
        <Section name="Control 请求历史" action={intentHistoryBusy ? '读取中…' : '找回本人历史请求'}
          onPress={() => { if (!intentHistoryBusy) void fetchIntentHistory(); }} />
        {hubStatus.outcomeUncertainOperationId && <Notice>
          存在 Hub 已确认但业务结果未确定的操作 {hubStatus.outcomeUncertainOperationId}。Intent 列表按权威数据刷新；此操作无法从原包推断 intent_id。
        </Notice>}
        <Notice>历史按需从 Hub 的 intent.list 读取；页面只保留并显示最近 200 条，再分批展开。当前服务端会返回当前 Owner 的全量记录，首次读取量仍随历史增长。正文仅保留在当前内存；撤权、固定其他 Hub 或创建新设备身份时清空。</Notice>
        {!!intentHistoryMessage && <Text style={s.small}>{intentHistoryMessage}</Text>}
        {intentHistory.length === 0 && !intentHistoryBusy && !intentHistoryMessage &&
          <Text style={s.small}>点「找回本人历史请求」读取 Hub 上属于当前 Owner 的记录。</Text>}
        {intentHistory.slice(0, intentHistoryVisibleCount).map(item => {
          const id = field(item, 'id');
          const progress = intentProgress[id];
          const intent = progress ? asObject(progress.intent) : item;
          const job = progress ? asObject(progress.job) : {};
          const goalResult = goalResults[id];
          const status = field(intent, 'status');
          const expanded = expandedIntentId === id;
          const result = status === 'resolved' && intent.result &&
            JSON.stringify(intent.result) !== '{}' ? JSON.stringify(intent.result, null, 2) : '';
          return <Card key={id} onPress={() => {
            if (expanded) { setExpandedIntentId(''); return; }
            setExpandedIntentId(id);
            if (intentStatusAllowed && id) {
              refreshIntentStatus(id).catch(error =>
                setIntentHistoryMessage('权威状态读取失败：' + safeHubError(error)));
            } else if (intentGoalResultAllowed && id) {
              refreshGoalResult(id).catch(error =>
                setIntentHistoryMessage('Goal / Worker 结果读取失败：' + safeHubError(error)));
            }
          }}>
            <View style={s.row}><Text style={s.cardTitle}>Intent {id}</Text>
              <Pill text={intentStatusLabel(status)} tone={status === 'resolved' ? 'green' :
                status === 'failed' || status === 'needs_input' ? 'amber' : 'muted'} /></View>
            <Text style={s.description} numberOfLines={3}>{field(intent, 'text') || '（请求正文为空）'}</Text>
            <Text style={s.small}>创建：{field(intent, 'created_at') || '时间未知'} · 更新：{field(intent, 'updated_at') || '时间未知'}</Text>
            {expanded && <>
              <Text style={s.small}>Intent 业务状态：{intentStatusLabel(status)} · 来源：{progress ? 'Hub intent.status' : 'Hub intent.list'}</Text>
              {progress && <Text style={s.small}>Intent 作业状态：{intentJobStatusLabel(field(job, 'state'))} · 这不代表 Goal 或 Worker 成功。</Text>}
              {!progress && intentStatusAllowed && <Text style={s.small}>展开记录会重读 intent.status；有 manager 授权时再用 intent_id 查询 goal.result。</Text>}
              {!progress && !intentStatusAllowed && <Text style={s.small}>当前会话未授权 intent.status；以上字段来自 Hub intent.list。</Text>}
              {!!field(intent, 'question') && <Text style={s.description}>需要补充：{field(intent, 'question')}</Text>}
              {!!field(intent, 'error') && <Text style={s.description}>失败原因：{field(intent, 'error')}</Text>}
              {!!result && <Text style={s.small}>Control 结果：{result}</Text>}
              {intentGoalResultAllowed && goalResult && <>
                <Text style={s.small}>goal.result · Intent：{intentStatusLabel(goalResult.intent_status)}</Text>
                <Text style={s.small}>Goal：{goalResult.goal_id || '尚未生成 Goal'} ·
                  {goalResult.goal_status ? observationLabel({state: goalResult.goal_status, known: true}) : '暂无 Goal 终态'}</Text>
                {!!goalResult.outcome && <Text style={s.small}>Goal outcome：{goalResult.outcome}</Text>}
                {!!goalResult.summary && <Text style={s.description}>Goal 摘要：{goalResult.summary}</Text>}
                {goalResult.workers.length > 0 && <>
                  <Text style={s.small}>Worker 终态（{goalResult.workers.length}{goalResult.workers_truncated ? '+' : ''}）</Text>
                  {goalResult.workers.map((worker, index) => <View key={`${worker.worker_id}-${index}`}>
                    <Text style={s.small}>{worker.worker_id} · {observationLabel({state: worker.status, known: true})} · attempt {worker.attempt}</Text>
                    {!!worker.summary && <Text style={s.small}>{worker.summary}</Text>}
                  </View>)}
                </>}
                {goalResult.workers_truncated && <Text style={s.small}>Hub 已截断 Worker 摘要；完整详情需在受授权 Hub 面板查看。</Text>}
                {goalResult.artifacts.length > 0 && <>
                  <Text style={s.small}>Artifact 引用（仅元数据，不含文件内容或读取权限）</Text>
                  {goalResult.artifacts.map((artifact, index) => <Text key={`${artifact.artifact_id}-${index}`} style={s.small}>
                    {artifact.name} · {artifact.kind} · {artifact.status} · ref {artifact.artifact_id}
                    {artifact.digest ? ` · digest ${artifact.digest}` : ''}
                  </Text>)}
                </>}
                {goalResult.artifacts_truncated && <Text style={s.small}>Hub 已截断 Artifact 引用。</Text>}
              </>}
              {!intentGoalResultAllowed && <Text style={s.small}>
                当前会话未同时提供 v1.2 manager 的 goal.result 授权；不展示推测的 Goal 或 Artifact 状态。
              </Text>}
              {intentGoalResultAllowed && !goalResult && <Text style={s.small}>
                正在读取 goal.result；未返回 Goal 时只说明此 Intent 尚未生成 Goal。
              </Text>}
            </>}
          </Card>;
        })}
        {intentHistory.length > intentHistoryVisibleCount && <Button
          title={`查看更多（${Math.min(intentHistoryVisibleCount + 8, intentHistory.length)} / ${intentHistory.length}）`}
          secondary onPress={() => setIntentHistoryVisibleCount(count =>
            Math.min(count + 8, intentHistory.length))} />}
      </>}
    </>;
    if (tab === 'panel') return <>
      <Heading eyebrow="Hub 管理面板" title="管理"
        subtitle="手机发起操作，权威状态由 Hub 更新。" />
      <SharedSpaceConsentPanel status={hubStatus} topology={topologySnapshot}
        publicCapabilities={hubCapabilities} sessionCapabilities={sessionCapabilities} />
      {!hubStatus.remoteEnabled || !hubStatus.sessionCapabilitiesReady ? <>
        <Notice>尚未建立经认证的后量子加密会话。远程管理功能关闭；请先在「我的」中固定 Hub 身份并登记 OwnerDeviceGrant。</Notice>
        <ActionCard title="配置安全连接" body="手动核对 Hub 公钥、登记设备并建立加密会话"
          onPress={() => setTab('settings')} />
      </> : <>
        <Notice>Control 会话：{sessionCapabilities?.role || hubStatus.role || '未知角色'} · 授权来自加密 session.capabilities · 所有变更在 Hub 端校验。</Notice>
        {!!hubMessage && <Text style={s.small}>{hubMessage}</Text>}
        <NodePairingPanel status={hubStatus} publicCapabilities={hubCapabilities}
          sessionCapabilities={sessionCapabilities} api={clientHub}
          onRefresh={async () => {
            await refreshHubStatus();
            const bindings = await refreshNodeBindings();
            await refreshRemoteData();
            return bindings;
          }} />
        {operationAllowed(hubStatus, 'nodes.list') && <>
          <Section name="已登记 Node" action="刷新" onPress={() => {
            refreshNodeBindings().catch(error => setHubMessage('Node 列表读取失败：' + safeHubError(error)));
          }} />
          <VisibleItems items={nodesList} renderItem={binding => <Card key={field(binding, 'id')}>
            <View style={s.row}><Text style={s.cardTitle}>{field(binding, 'node_name') || field(binding, 'node_id')}</Text>
              <Pill text={field(binding, 'authorized') === 'true' ? field(binding, 'state') || '已授权' : '未授权'} tone="muted" /></View>
            <Text style={s.description}>Node {field(binding, 'node_id')} · 绑定版本 {field(binding, 'version')} · 授权：{binding.authorized === true ? '有效' : '无效'}</Text>
            {binding.state === 'ACTIVE' && operationAllowed(hubStatus, 'nodes.revoke') &&
              <View style={s.modelActions}><Button title="撤销绑定" secondary onPress={() => revokeNode(binding)} /></View>}
          </Card>} />
        </>}
        {sessionCapabilities?.role === 'manager' &&
          capsAllows(hubCapabilities, 'approval_read_and_decide', 'approvals.list', hubStatus) && <>
          <Section name="待处理审批" action="刷新" onPress={() => {
            refreshRemoteData().catch(error => setHubMessage('审批刷新失败：' + safeHubError(error)));
          }} />
          <VisibleItems items={approvals} renderItem={approval => <Card key={field(approval, 'id')}>
            <Text style={s.kicker}>{field(approval, 'method')} · Goal {field(approval, 'goal_id')}</Text>
            <Text style={[s.cardTitle, s.space]}>Approval {field(approval, 'id')}</Text>
            <Text style={s.description}>状态：{field(approval, 'status')} · Worker {field(approval, 'worker_id')}</Text>
            <Text style={s.small}>请求详情：{JSON.stringify(approval.request || {}, null, 2)}</Text>
            {field(approval, 'status') === 'pending' && operationAllowed(hubStatus, 'approvals.decide') &&
              <View style={s.modelActions}>
                <Button title="接受" onPress={() => decideApproval(approval, 'accept')} disabled={topologyActionBusy} />
                <Button title="拒绝" secondary onPress={() => decideApproval(approval, 'decline')} disabled={topologyActionBusy} />
              </View>}
          </Card>} />
          {approvals.length === 0 && <Text style={s.small}>当前没有待处理审批。</Text>}
        </>}
        {capsAllows(hubCapabilities, 'topology_management', 'topology.snapshot', hubStatus) && <>
          <Section name="Group 与拓扑" action="重读权威拓扑" onPress={() => {
            refreshTopology().catch(error => setHubMessage('拓扑读取失败：' + safeHubError(error)));
          }} />
          <Card><Text style={s.cardTitle}>权威拓扑</Text>
            <Text style={s.description}>{(topologySnapshot?.groups || []).length} 个 Group · {(topologySnapshot?.memberships || []).length} 个 Membership · {(topologySnapshot?.endpoints || []).length} 个 Endpoint</Text>
            <Text style={s.small}>来源：topology.snapshot · {topologySnapshot?.captured_at || '尚未读取'}</Text>
          </Card>
          <Card><Text style={s.cardTitle}>当前 Network</Text>
            <Text style={s.description}>{activeNetwork ? activeNetwork.name + ' · ' + activeNetwork.network_id :
              '请选择一个 ACTIVE Network'}</Text>
            {(topologySnapshot?.networks || []).slice(0, 100).map(network =>
              <Button key={network.network_id} title={network.name + ' · ' + network.state}
                secondary={network.network_id !== hubStatus.activeNetworkId}
                disabled={network.state !== 'ACTIVE' || recording || hubBusy || topologyActionBusy}
                onPress={() => Alert.alert('选择 Network', network.name + '\n' + network.network_id +
                  '\n\n未发送的文字和授权预览将清空；Hub 会话与原请求计数保留。', [
                  {text: '取消', style: 'cancel'},
                  {text: '选择', onPress: () => {
                    connection.selectNetwork(network.network_id).catch(error => {
                      if (mountedRef.current) setHubMessage('Network 选择未完成：' + safeHubError(error));
                    });
                  }},
                ])} />)}
            {!!(topologySnapshot?.networks_truncated || topologySnapshot?.network_endpoints_truncated) &&
              <Notice>Hub 返回的 Network 或 Endpoint 列表不完整；不可见记录不代表不存在。</Notice>}
          </Card>
          <NetworkKeyConsentPanel api={clientHub} status={hubStatus} topology={topologySnapshot}
            publicCapabilities={hubCapabilities} sessionCapabilities={sessionCapabilities}
            onRefresh={async () => { await refreshHubStatus(); await refreshTopology(); }} />
          <NetworkDiscoveryPanel api={clientHub} status={hubStatus} topology={topologySnapshot}
            publicCapabilities={hubCapabilities} sessionCapabilities={sessionCapabilities} />
          <GroupDirectoryPermissionPanel api={clientHub} status={hubStatus} topology={topologySnapshot}
            publicCapabilities={hubCapabilities} sessionCapabilities={sessionCapabilities}
            onRefresh={async () => { await refreshHubStatus(); return await refreshTopology(); }} />
          {clientHub.regroupDelegationReady && <RegroupDelegationPanel api={clientHub} status={hubStatus} topology={topologySnapshot}
            publicCapabilities={hubCapabilities} sessionCapabilities={sessionCapabilities}
            onRefresh={async () => { await refreshHubStatus(); await refreshTopology(); }} />}
          {monitorFeatureReady && <>
            <ActionCard title={showMonitorPanel ? '收起 Advisor 广播' : 'Advisor 广播'}
              body="向一个同 Owner Group 中已固定的收件人 roster 发送精确文本；先逐项审核，再由 Android 安全桥加密批准。"
              onPress={() => setShowMonitorPanel(open => !open)} />
            <View collapsable={false} nativeID="monitor-panel-host">
            {showMonitorPanel && <>
              <Notice>Advisor 入口已由当前 Hub catalog、加密 session.capabilities 和 Android 安全桥共同授权。Prepare 只向 Control 发送精确正文的 SHA-256；明文仅留在本机内存，Confirm 由安全桥重新核对、加密并签名。</Notice>
              {!!monitorMessage && <Text style={s.small}>{monitorMessage}</Text>}
              <Card>
                <Section name="1 · 选择确切 Group" action="重读拓扑" onPress={() => {
                  refreshTopology().catch(error => setMonitorMessage('拓扑读取失败：' + safeHubError(error)));
                }} />
                {monitorActiveGroups.length === 0 &&
                  <Text style={s.small}>当前权威拓扑没有活跃 Group。</Text>}
                {monitorActiveGroups.slice(0, 32).map(group => {
                  const id = field(group, 'group_id');
                  const selected = id === monitorGroupId;
                  return <Pressable key={id} style={[s.monitorChoice, selected && s.monitorChoiceSelected]}
                    onPress={() => {
                      if (id === monitorGroupId) return;
                      invalidateMonitorPreview('Group 选择已改变；当前预览不能再确认。');
                      setMonitorGroupId(id);
                      setMonitorEndpointId('');
                    }} disabled={monitorBusy}>
                    <Text style={s.cardTitle}>{field(group, 'name') || id}</Text>
                    <Text style={s.description}>{id} · Group v{field(group, 'version')}</Text>
                    {selected && <Pill text="已选择" tone="green" />}
                  </Pressable>;
                })}
                {!!monitorGroupId && !selectedMonitorGroup &&
                  <Notice>所选 Group 已不在最新活跃拓扑中，请重新选择。</Notice>}
                <Section name="2 · 选择该 Group 的 Advisor Endpoint" />
                {monitorGroupId && eligibleMonitorEndpoints.length === 0 &&
                  <Notice>此 Group 没有已加入且同时具备 `monitor` 角色和独立 `message.broadcast` 权限的 Endpoint。授予角色不会自动开启该权限。</Notice>}
                {eligibleMonitorEndpoints.map(endpoint => {
                  const id = field(endpoint, 'endpoint_id');
                  const selected = id === monitorEndpointId;
                  return <Pressable key={id} style={[s.monitorChoice, selected && s.monitorChoiceSelected]}
                    onPress={() => {
                      if (id === monitorEndpointId) return;
                      invalidateMonitorPreview('Advisor Endpoint 选择已改变；当前预览不能再确认。');
                      setMonitorEndpointId(id);
                    }} disabled={monitorBusy}>
                    <Text style={s.cardTitle}>{field(endpoint, 'name') || id}</Text>
                    <Text style={s.description}>{id} · Principal {field(endpoint, 'principal_id')}</Text>
                    <Text style={s.small}>Binding {field(endpoint, 'binding_id')} · epoch {field(endpoint, 'binding_epoch')} · 角色 monitor · message.broadcast 已单独允许</Text>
                    {selected && <Pill text="已选择来源" tone="green" />}
                  </Pressable>;
                })}
                <Section name="3 · 精确正文" />
                <TextInput style={[s.hubInput, s.monitorBodyInput]} value={monitorBody}
                  onChangeText={value => {
                    setMonitorBody(value);
                    if (monitorPreview && monitorPreparedBody !== null && value !== monitorPreparedBody) {
                      setMonitorPreviewStaleReason('正文已更改；当前预览绑定的是原正文，需重新 Prepare。');
                      setMonitorMessage('正文已更改；原预览不能批准。正文未被自动修整或规范化。');
                    }
                  }} placeholder="输入要交给所选 Advisor 的准确文本" multiline
                  autoCapitalize="none" autoCorrect={false} editable={!monitorBusy}
                  accessibilityLabel="Advisor 广播精确正文" />
                <Text style={s.small}>{monitorBodyBytes === null ?
                  '正文包含孤立 UTF-16 代理项；安全桥会拒绝这种无效 Unicode。' :
                  `${monitorBodyBytes.toLocaleString()} / ${MONITOR_BROADCAST_BODY_MAX_BYTES.toLocaleString()} UTF-8 字节`}
                  {' · 空格、尾部空格与换行按原样保留'}</Text>
                {monitorNeedsBodyReentry && <Button title="本机核对原正文摘要" secondary
                  onPress={async () => { await verifyRecoveredMonitorBody(); }}
                  disabled={monitorBusy || monitorBodyBytes === null || monitorBodyBytes === 0 ||
                    monitorBodyBytes > MONITOR_BROADCAST_BODY_MAX_BYTES} />}
                <Button title={monitorBusy ? '处理中…' : '准备五分钟预览'} secondary
                  onPress={async () => { await prepareMonitorBroadcast(); }}
                  disabled={monitorBusy || !monitorFeatureReady || monitorSessionBlocksWrites(hubStatus) || !selectedMonitorGroup ||
                    !eligibleMonitorEndpoints.some(endpoint => field(endpoint, 'endpoint_id') === monitorEndpointId) ||
                    monitorBodyBytes === null || monitorBodyBytes === 0 ||
                    monitorBodyBytes > MONITOR_BROADCAST_BODY_MAX_BYTES ||
                    monitorUnknownPrepare || monitorUnknownConfirm} />
                {monitorUnknownPrepare && <Notice>有原 Prepare 结果尚未核实。请使用下方只读恢复；新 Prepare 已关闭。</Notice>}
                {monitorUnknownConfirm && <Notice>原 Confirm 结果尚未核实。只允许查询原预览状态；新的 Prepare 和 Confirm 已关闭。</Notice>}
              </Card>

              {monitorRecoverableOperations.length > 0 && <>
                <Section name="只读恢复原 Prepare" />
                {monitorRecoverableOperations.map(operation => <Card key={operation.operationId}>
                  <Text style={s.cardTitle}>Prepare 待恢复</Text>
                  <Text style={s.description}>Group {operation.groupId} · Advisor {operation.monitorEndpointId}</Text>
                  <Text style={s.small}>状态：{operation.state} · Preview 到期：{operation.expiresAt || '尚未取得预览'}</Text>
                  <Text style={s.small}>Group 授权到期：{operation.grantExpiresAt || '索引未提供'} · 最迟可确认：{monitorOperationValidUntil(operation) || '未知'}</Text>
                  <Button title="恢复原预览（只读）" secondary onPress={async () => {
                    await recoverMonitorBroadcast(operation.operationId);
                  }} disabled={monitorBusy || !monitorOperationAllowed(hubCapabilities,
                    sessionCapabilities, hubStatus, 'monitor.broadcast_recover')} />
                </Card>)}
              </>}
              {monitorStatusOperations.length > 0 && <>
                <Section name="Confirm 已尝试 · 只读状态" />
                {monitorStatusOperations.map(operation => <Card key={operation.operationId}>
                  <Text style={s.cardTitle}>Confirm 结果待核实</Text>
                  <Text style={s.description}>Group {operation.groupId} · Advisor {operation.monitorEndpointId}</Text>
                  <Text style={s.small}>到期：{operation.expiresAt || '未知'} · 不会再次 Confirm</Text>
                  <Button title="查询同一预览状态" secondary onPress={async () => {
                    if (operation.previewId) await readMonitorBroadcastStatus(operation.previewId);
                  }} disabled={monitorBusy || !monitorOperationAllowed(hubCapabilities,
                    sessionCapabilities, hubStatus, 'monitor.broadcast_status')} />
                </Card>)}
              </>}

              {monitorPreview && <>
                <Section name="4 · 核对已验证的完整同意预览" />
                <Card>
                  <View style={s.row}><Text style={s.cardTitle}>Advisor 预览</Text>
                    <Pill text={monitorExpired ? '已过期' : monitorPreview.status}
                      tone={monitorExpired ? 'amber' : monitorPreview.status === 'PREPARED' ? 'green' : 'muted'} /></View>
                  <Text style={s.description}>Group {monitorPreview.groupId} · revision {monitorPreview.groupRevision} · {monitorPreview.recipients.length} 个有序收件人</Text>
                  <Text style={s.small}>Preview 到期：{monitorPreview.expiresAt} · Group 授权到期：{monitorPreview.grantExpiresAt}</Text>
                  <Text style={s.small}>最迟可确认：{monitorPreview.validUntil} · Snapshot {monitorPreview.snapshotDigest}</Text>
                  <Text style={s.small}>Consent digest：{monitorPreview.consentDigest}</Text>
                  <Text style={s.small}>正文摘要：{monitorPreview.bodySha256} · 正文不会显示在预览卡或发送到 Prepare</Text>
                  {monitorCurrentStaleReason ? <Notice>{monitorCurrentStaleReason}</Notice> : null}
                  {monitorNeedsBodyReentry && <Notice>此预览来自只读恢复，原文不在本机内存。请原样重新输入；安全桥会在签名或联网前比对 SHA-256，不匹配时不会 Confirm。</Notice>}
                  <Section name="Advisor 来源身份与当前版本" />
                  <MonitorConsentCard endpoint={monitorPreview.source} source />
                  <Text style={s.small}>Verified Advisor key {monitorPreview.monitorKeyId} · binding {monitorPreview.monitorBindingId} / epoch {monitorPreview.monitorBindingEpoch}</Text>
                  <Section name={`固定收件人 roster · ${monitorPreview.recipients.length}`} />
                  {monitorPreview.recipients.length === 0 &&
                    <Notice>当前预览没有收件人，因此不能批准广播。</Notice>}
                  {monitorPreview.recipients.map((recipient, index) => <MonitorConsentCard
                    key={recipient.endpointId} endpoint={recipient} ordinal={index + 1} />)}
                  <View style={s.modelActions}>
                    <Button title="刷新同一预览状态" secondary onPress={async () => {
                      await readMonitorBroadcastStatus(monitorPreview.previewId);
                    }} disabled={monitorBusy || !monitorOperationAllowed(hubCapabilities,
                      sessionCapabilities, hubStatus, 'monitor.broadcast_status')} />
                    <Button title="明确批准并加密" onPress={requestMonitorConfirm}
                      disabled={!monitorCanConfirm || monitorBusy} />
                  </View>
                  {monitorConfirmAttempted &&
                    <Text style={s.small}>Confirm 已尝试：此预览只开放状态查询，不再签名或重发。</Text>}
                </Card>
              </>}

              {monitorStatus && monitorStatusPreviewId && <>
                <Section name="5 · Hub 权威审批与逐收件人结果" />
                <Card>
                  <Text style={s.cardTitle}>{monitorApprovalStatusText(monitorStatus.approvalStatus)}</Text>
                  <Text style={s.description}>Group {monitorStatus.groupId} · 到期 {monitorStatus.expiresAt}</Text>
                  {monitorStatus.recipients.length === 0 &&
                    <Notice>Hub 尚未记录逐收件人投递结果；审批状态不代表已投递</Notice>}
                  {monitorStatus.recipients.map((outcome, index) => <MonitorOutcomeCard
                    key={`${outcome.ordinal}/${outcome.endpointId}`} outcome={outcome} index={index} />)}
                  <Text style={s.small}>NODE_REPORTED 与 RELAY_PERSISTED 仅说明持久化证据，不表示 Node Runtime 或本地模型已消费，也不表示业务任务已完成。</Text>
                </Card>
              </>}
            </>}
            </View>
          </>}
          {capsAllows(hubCapabilities, 'group_endpoint_key_grants', 'group.key_manifest', hubStatus) &&
            operationAllowed(hubStatus, 'group.key_grant') && <Card>
            <Text style={s.cardTitle}>Group Endpoint 公钥授权</Text>
            <Text style={s.description}>设备独立核对完整 Endpoint 证明和所有绑定摘要；owner 使用独立签名器签署，不在手机输入私钥。</Text>
            <TextInput style={s.hubInput} value={keyGroupId} onChangeText={value => {
              setKeyGroupId(value); setVerifiedKeyManifest(null); setKeySignedProof(''); setKeyGrantStatus(null);
            }} placeholder="Group ID" accessibilityLabel="公钥授权 Group ID" />
            <TextInput style={s.hubInput} value={keyEndpointId} onChangeText={value => {
              setKeyEndpointId(value); setVerifiedKeyManifest(null); setKeySignedProof(''); setKeyGrantStatus(null);
            }} placeholder="Endpoint ID" accessibilityLabel="公钥授权 Endpoint ID" />
            <TextInput style={s.hubInput} value={keyOwnerId} onChangeText={value => {
              setKeyOwnerId(value); setVerifiedKeyManifest(null); setKeySignedProof('');
            }} placeholder="独立 owner 公钥 ID" accessibilityLabel="公钥授权 Owner key ID" />
            <Button title="读取并验证候选证明" onPress={previewGroupKey} secondary={keyConsentBusy}
              disabled={keyConsentBusy || !keyGroupId.trim() || !keyEndpointId.trim() || !keyOwnerId.trim()} />
            {operationAllowed(hubStatus, 'group.key_status') && <Button
              title="刷新当前授权状态" secondary onPress={() => refreshGroupKeyStatus()}
              disabled={keyConsentBusy || !keyGroupId.trim() || !keyEndpointId.trim()} />}
            {keyGrantStatus && <Text style={s.small}>
              Hub 当前状态：{field(keyGrantStatus, 'current_status')} · 接受于 {field(keyGrantStatus, 'accepted_at') || '未知'}
            </Text>}
            {verifiedKeyManifest && <>
              <Text style={s.small}>已验证：{field(verifiedKeyManifest, 'principal_id')} / {field(verifiedKeyManifest, 'node_id')} · epoch {field(verifiedKeyManifest, 'binding_epoch')}</Text>
              <Text style={s.small}>公钥：{field(verifiedKeyManifest, 'candidate_fingerprint')}</Text>
              <Text style={s.small}>Manifest：{field(verifiedKeyManifest, 'digest')} · 截止 {field(verifiedKeyManifest, 'expires_at')}</Text>
              <Button title="查看独立签名参数" secondary onPress={() => show('Owner Group Key Grant 签名参数',
                `owner_id=${field(verifiedKeyManifest, 'owner_id')}\nlink_id=group-endpoint-key-grant:v1\ncontract_digest=${field(verifiedKeyManifest, 'digest')}\nkey_binding_digest=${field(verifiedKeyManifest, 'candidate_binding_digest')}\nexpected_link_version=${field(verifiedKeyManifest, 'candidate_version')}\nside=SOURCE\nissued_at=${field(verifiedKeyManifest, 'issued_at')}\nexpires_at=${field(verifiedKeyManifest, 'expires_at')}\nowner_key_id=${field(verifiedKeyManifest, 'owner_key_id')}`)} />
              <TextInput style={s.hubInput} value={keySignedProof} onChangeText={setKeySignedProof}
                placeholder="独立签名器返回的 owner signed_proof（base64）" accessibilityLabel="Owner 签名证明" />
              <Button title="核对并明确批准" onPress={approveGroupKey} secondary={keyConsentBusy}
                disabled={keyConsentBusy || !keySignedProof.trim()} />
            </>}
          </Card>}
          <ActionCard title={showTopologyEditor ? '收起拓扑管理' : '管理拓扑'}
            body="查看权威 Group、成员、Endpoint 和 Link；获准时可编辑。"
            onPress={() => setShowTopologyEditor(open => !open)} />
          {operationAllowed(hubStatus, 'topology.apply') && <>
            <ActionCard title={showCreateGroupForm ? '收起创建 Group' : '创建 Group'}
              body="创建一个 Hub 权威 Group；父级为可选项。"
              onPress={() => setShowCreateGroupForm(open => !open)} />
            {showCreateGroupForm && <Card>
              <TextInput style={s.hubInput} value={groupName} onChangeText={setGroupName}
                placeholder="新 Group 名称" accessibilityLabel="新 Group 名称" />
              <TextInput style={s.hubInput} value={parentGroupId} onChangeText={setParentGroupId}
                placeholder="父 Group ID（可选；留空创建根 Group）" accessibilityLabel="父 Group ID" />
              <Button title="提交创建" onPress={createGroup} secondary={topologyActionBusy}
                disabled={topologyActionBusy || !groupName.trim() || !activeNetwork?.can_create_group} />
            </Card>}
            {showTopologyEditor && <>
            <TextInput style={s.hubInput} value={joinEndpointId} onChangeText={setJoinEndpointId}
              placeholder="Endpoint ID" accessibilityLabel="Endpoint ID" />
            <TextInput style={s.hubInput} value={joinGroupId} onChangeText={setJoinGroupId}
              placeholder="加入的 Group ID" accessibilityLabel="加入的 Group ID" />
            <Button title="将 Endpoint 加入 Group" onPress={joinGroup} secondary={topologyActionBusy}
              disabled={topologyActionBusy || !joinEndpointId.trim() || !joinGroupId.trim()} />
            <TextInput style={s.hubInput} value={leaveEndpointId} onChangeText={setLeaveEndpointId}
              placeholder="离开 Group 的 Endpoint ID" accessibilityLabel="离组 Endpoint ID" />
            <TextInput style={s.hubInput} value={leaveGroupId} onChangeText={setLeaveGroupId}
              placeholder="离开的 Group ID" accessibilityLabel="离开的 Group ID" />
            <TextInput style={s.hubInput} value={leaveBindingId} onChangeText={setLeaveBindingId}
              placeholder="当前 binding_id" accessibilityLabel="Binding ID" />
            <TextInput style={s.hubInput} value={leaveBindingEpoch} onChangeText={setLeaveBindingEpoch}
              placeholder="当前 binding_epoch" keyboardType="number-pad" accessibilityLabel="Binding epoch" />
            <Button title="将 Endpoint 移出 Group" onPress={leaveGroup} secondary={topologyActionBusy}
              disabled={topologyActionBusy || !leaveEndpointId.trim() || !leaveGroupId.trim() || !leaveBindingId.trim() || !leaveBindingEpoch.trim()} />
            <TextInput style={s.hubInput} value={roleGroupId} onChangeText={setRoleGroupId}
              placeholder="Membership 所属 Group ID" accessibilityLabel="Membership 所属 Group ID" />
            <TextInput style={s.hubInput} value={roleMembershipId} onChangeText={setRoleMembershipId}
              placeholder="Membership ID" accessibilityLabel="Membership ID" />
            <TextInput style={s.hubInput} value={roleValue} onChangeText={setRoleValue}
              placeholder="角色（member/worker/monitor）" accessibilityLabel="新角色" />
            <Button title="更新成员角色" onPress={bindRole} secondary={topologyActionBusy}
              disabled={topologyActionBusy || !roleMembershipId.trim() || !roleGroupId.trim() || !roleValue.trim()} />
            <Section name="同 Owner Link 提案" />
            <Notice>此入口只提交 topology.apply 的同 Owner 提案；跨用户 Thread 连线会在 Hub capability 关闭时隐藏。</Notice>
            <TextInput style={s.hubInput} value={linkSourceEndpointId} onChangeText={setLinkSourceEndpointId}
              placeholder="Source Endpoint ID" accessibilityLabel="Source Endpoint ID" />
            <TextInput style={s.hubInput} value={linkSourceGroupId} onChangeText={setLinkSourceGroupId}
              placeholder="Source Group ID" accessibilityLabel="Source Group ID" />
            <TextInput style={s.hubInput} value={linkTargetEndpointId} onChangeText={setLinkTargetEndpointId}
              placeholder="Target Endpoint ID" accessibilityLabel="Target Endpoint ID" />
            <TextInput style={s.hubInput} value={linkTargetGroupId} onChangeText={setLinkTargetGroupId}
              placeholder="Target Group ID" accessibilityLabel="Target Group ID" />
            <TextInput style={s.hubInput} value={linkScopes} onChangeText={setLinkScopes}
              placeholder="精确 data_scopes（逗号分隔）" accessibilityLabel="Link 数据范围" />
            <TextInput style={s.hubInput} value={linkExpiresAt} onChangeText={setLinkExpiresAt}
              placeholder="到期时间 RFC3339，例如 2026-09-24T12:00:00Z" accessibilityLabel="Link 到期时间" />
            <Button title="提交同 Owner Link 提案" onPress={proposeSameOwnerLink} secondary={topologyActionBusy}
              disabled={topologyActionBusy || !linkSourceEndpointId.trim() || !linkSourceGroupId.trim() || !linkTargetEndpointId.trim() || !linkTargetGroupId.trim() || !linkScopes.trim() || !linkExpiresAt.trim()} />
            </>}
          </>}
          {showTopologyEditor && <>
          <VisibleItems items={selectedNetworkGroups} renderItem={group => <Card key={field(group, 'group_id')}>
            <Text style={s.cardTitle}>{field(group, 'name') || field(group, 'group_id')}</Text>
            <Text style={s.description}>{field(group, 'group_id')} · {field(group, 'state')} · v{field(group, 'version')}</Text>
            <Text style={s.small}>父 Group：{field(group, 'parent_group_id') || '无'} · 来源：topology.snapshot · {topologySnapshot?.captured_at || '观察时间未知'}</Text>
            {operationAllowed(hubStatus, 'topology.apply') && <View style={s.modelActions}>
              <Button title="按上方父 Group 更新层级" secondary onPress={() => setGroupParent(group)} disabled={topologyActionBusy} />
            </View>}
          </Card>} />
          <Section name="Membership" />
          <Notice>`message.broadcast` 是每个 Membership 的独立权限；`monitor` 角色不会自动授予。所有变更使用当前版本提交，失败或断线后以新 topology.snapshot 对账。</Notice>
          <VisibleItems items={(topologySnapshot?.memberships || []).filter(member =>
            selectedNetworkGroups.some(group => field(group, 'group_id') === field(member, 'group_id')))} renderItem={member => {
            const hasPermission = typeof member.broadcast_permission_enabled === 'boolean';
            const permissionEnabled = member.broadcast_permission_enabled === true;
            const version = Number(member.version);
            const canToggle = hasPermission && membershipIsActive(member) &&
              Number.isSafeInteger(version) && version > 0 && monitorTopologyApplyAllowed;
            return <Card key={field(member, 'membership_id')}>
              <Text style={s.cardTitle}>{field(member, 'display_name') || field(member, 'principal_id')}</Text>
              <Text style={s.description}>Group {field(member, 'group_id')} · {field(member, 'role')} · {field(member, 'status')} · v{field(member, 'version')}</Text>
              <Text style={s.small}>message.broadcast：{hasPermission ?
                (permissionEnabled ? '已明确允许' : '未允许') : '未由当前 snapshot 确认'}
                {' · Advisor 角色本身不改变此值'}</Text>
              {canToggle && <View style={s.modelActions}>
                <Button title={permissionEnabled ? '撤销广播权限' : '明确允许广播'} secondary
                  onPress={() => toggleBroadcastPermission(member)} disabled={topologyActionBusy} />
              </View>}
            </Card>;
          }} />
          <Section name="Endpoints" />
          <VisibleItems items={(topologySnapshot?.endpoints || []).filter(endpoint =>
            Array.isArray(endpoint.network_ids) && endpoint.network_ids.includes(hubStatus.activeNetworkId))} renderItem={endpoint => <Card key={field(endpoint, 'endpoint_id')}>
            <Text style={s.cardTitle}>{field(endpoint, 'name') || field(endpoint, 'endpoint_id')}</Text>
            <Text style={s.description}>{field(endpoint, 'endpoint_id')} · {field(endpoint, 'presence')} · Groups {(Array.isArray(endpoint.group_ids) ? endpoint.group_ids : []).join(', ')}</Text>
          </Card>} />
          {(topologySnapshot?.links || []).length > 0 && <Section name="Link 元数据" />}
          <VisibleItems items={topologySnapshot?.links || []} renderItem={link => <Card key={field(link, 'link_id')}>
            <Text style={s.cardTitle}>Link {field(link, 'link_id')} · {field(link, 'state')}</Text>
            <Text style={s.description}>{field(link, 'source_endpoint_id')} → {field(link, 'target_endpoint_id')}</Text>
            <Text style={s.small}>动作：{(Array.isArray(link.actions) ? link.actions : []).join(', ')} · 范围：{(Array.isArray(link.data_scopes) ? link.data_scopes : []).join(', ')} · 到期：{field(link, 'expires_at')}</Text>
            {operationAllowed(hubStatus, 'topology.apply') && <View style={s.modelActions}>
              <Button title="撤销此 Link" secondary onPress={() => revokeLink(link)} disabled={topologyActionBusy} />
            </View>}
          </Card>} />
          </>}
          {hubCapabilities?.external_thread_links === true && <>
            <Section name="跨用户 Thread 对接" />
            <Notice>仅按 Hub 声明能力显示；双方需要分别核验完整 Link 与密钥授权。不会提供普通明文聊天。</Notice>
          </>}
        </>}
        {hubCapabilities?.external_link_invites === true &&
          operationAllowed(hubStatus, 'link.list') && <LinkProposalPanel
            key={`${hubStatus.hubId || ''}/${hubStatus.ownerId || ''}/${hubStatus.deviceId || ''}/${hubStatus.sessionEpoch || ''}`}
            status={hubStatus} capabilities={hubCapabilities} sessionCapabilities={sessionCapabilities}
            apiScope={clientHub.scope} getCurrentStatus={() => clientHub.getStatus()}
            linkConsentApi={clientHub.linkConsent}
            linkReviewPolicyStatusReady={clientHub.linkReviewPolicyStatusReady}
            readLinkReviewPolicyStatus={input => clientHub.linkReviewPolicyStatus(input)} request={rpc}
            recoveredInvite={recoveredInvite}
            clearRecoveredInvite={() => setRecoveredInvite(null)} />}
      </>}
    </>;
    return <>
      <Heading eyebrow="设备与隐私" title="设置"
        subtitle="语音在本机处理；确认后加密提交给 Control。" />
      <Section name="本地模型中心" />
      <Notice>模型按需下载，App 不预装权重。当前只启用语音转文字；识别结果请检查。</Notice>
      <Text style={s.description}>当前使用：{selectedModel?.name || '未选择'}。
        可安装多个模型并随时切换；录音和识别留在本机。</Text>
      {models.map(model => <Card key={model.id}>
        <View style={s.row}><Text style={s.cardTitle}>{model.name}</Text>
          <Pill text={model.selected ? '当前使用' : model.installed ? '已安装' : '未安装'}
            tone={model.selected ? 'green' : 'muted'} /></View>
        <Text style={s.description}>{model.languages} · {sizeLabel(model.downloadBytes)} 下载</Text>
        <Text style={s.description}>{model.capabilities}</Text>
        <Text style={s.small}>来源：{model.source} · 许可：{model.license}</Text>
        <Pressable onPress={() => { Linking.openURL(model.licenseUrl).catch(() =>
          setModelStatus('无法打开许可页面')); }}>
          <Text style={s.link}>查看来源与许可  →</Text>
        </Pressable>
        <View style={s.modelActions}>
          {!model.installed && <Button title={modelBusyId === model.id ? '安装中…' : '下载并安装'}
            onPress={() => { installModel(model); }} />}
          {model.installed && !model.selected && <Button title="设为语音模型"
            onPress={() => { selectModel(model); }} />}
          {model.installed && <Button title="删除" secondary
            onPress={() => removeModel(model)} />}
        </View>
        {modelActionId === model.id && !!modelStatus &&
          <Text style={s.small}>{modelStatus}</Text>}
      </Card>)}
      {!speechDevice && <Text style={s.small}>此平台的模型适配尚未接入</Text>}
      <Card><Text style={s.cardTitle}>更多模型</Text>
        <Text style={s.description}>Qwen3-ASR 0.6B、Qwen3.5-2B 等正在评估。
          完成手机推理、资源和授权验证后才开放下载。</Text></Card>
      <Section name="连接与安全" />
      <Notice>Hub 的用户内容、状态和管理 RPC 只通过 ML-KEM-768 + ML-DSA-65 + AES-256-GCM 加密到受授权 Control。不会降级到 /v1 bearer。公开能力与身份只是候选信息，不代表已信任。</Notice>
      <Card>
        <View style={s.row}><Text style={s.cardTitle}>App ↔ Hub 安全会话</Text>
          <Pill text={realSession ? `加密会话 · ${sessionCapabilities?.role || hubStatus.role || '已认证'}` :
            hubStatus.enrolled ? '设备已登记 · 会话未就绪' : hubStatus.pinned ? 'Hub 已固定 · 设备未登记' : '未连接'}
            tone={realSession ? 'green' : 'amber'} /></View>
        <Text style={s.description}>{hubStatus.hubId ? `Hub ${hubStatus.hubId}` : '尚未固定 Hub ID'}
          {hubStatus.deviceId ? ` · Device ${hubStatus.deviceId}` : ''}</Text>
        <Text style={s.small}>此构建的原生安全桥接：{hubStatus.nativeAvailable ? '可用' : '未提供'} ·
          加密会话：{realSession ? '已启用' : '关闭'} · 角色只来自 session.capabilities。</Text>
        {!!hubMessage && <Text style={s.small}>{hubMessage}</Text>}
        {hubStatus.enrollmentRecoveryRequired && <Notice>
          设备登记结果尚不确定：{hubStatus.pendingEnrollmentOwnerId || '未知 Owner'} ·
          {hubStatus.pendingEnrollmentDeviceId || '未知 Device'}。本机持久保存了原始 Grant 与登记请求；
          用下方按钮原样重发同一登记请求，不要重新签发 Grant 或更换设备身份。
        </Notice>}
        {hubStatus.enrollmentRecoveryRequired && <Button
          title={hubBusy ? '正在恢复登记…' : '原样恢复设备登记'} secondary
          onPress={() => { void recoverEnrollment(); }}
          disabled={hubBusy || hubStatus.authFenced} />}
        {hubStatus.pendingOperationId && !hubStatus.authFenced && <>
          <Text style={s.small}>待恢复操作：{hubStatus.pendingOperation || '未知'} · {hubStatus.pendingOperationId}</Text>
          {hubStatus.sessionError === 'STILL_PROCESSING' && <Notice>
            Hub 仍在处理原请求。原包与计数保留；稍后再次调用 /rpc/recover，不创建新 operation。
          </Notice>}
          {hubStatus.sessionError === 'RECOVERY_UNAVAILABLE' && <Notice>
            Hub 无法恢复这条旧请求的结果密文。App 保留 pending 并阻断新操作；重复查询不会重发业务操作，需 Hub 维护者对账。
          </Notice>}
          {hubStatus.sessionError === 'RECOVERY_REJECTED' && <Notice>
            Hub 的恢复端没有该请求记录。可以选择显式原样重发；若请求从未到达 Hub，这会执行原操作。重放保护会阻止已接受请求再次执行。
          </Notice>}
          {hubStatus.recoveryBlocked && !['STILL_PROCESSING', 'RECOVERY_UNAVAILABLE', 'RECOVERY_REJECTED']
            .includes(hubStatus.sessionError || '') && <Notice>
            上次恢复遇到冲突。原签名密文、operation ID 和序号仍保留；再次查询恢复状态不会创建新操作。
          </Notice>}
          <Text style={s.small}>先查询 /v2/client/rpc/recover；恢复仅使用同一原始签名密文和请求序号。</Text>
          <View style={s.modelActions}><Button title={hubBusy ? '正在查询恢复状态…' : '再次查询原请求恢复'} secondary
            onPress={() => { void recoverPendingNow(); }} disabled={hubBusy} /></View>
          {hubStatus.sessionError === 'RECOVERY_REJECTED' && <Button title="原样重发一次（可能执行原操作）"
            secondary onPress={retryPendingExact} disabled={hubBusy} />}
        </>}
        {hubStatus.outcomeUncertainOperationId && <>
          <Notice>Hub 已用已验签密文响应确认 OUTCOME_UNCERTAIN：业务结果仍待核实。原传输 pending 已退休；没有重发 Intent，也不会把它标成成功。</Notice>
          {hubStatus.uncertainNeedsReconciliation && <Text style={s.small}>
            新管理写入暂时关闭，直到读取一次经过认证的 Hub 状态快照。
          </Text>}
          <Text style={s.small}>不确定 operation：{hubStatus.outcomeUncertainOperationId}</Text>
          <Button title={hubBusy ? '正在重读状态…' : '刷新权威状态与 Intent 历史'} secondary
            onPress={() => { void refreshAfterUncertainOutcome(); }} disabled={hubBusy} />
        </>}
        {hubStatus.linkConsentReconciliationRequired && <Notice>
          Link 授权结果仍未确定。原始密文和授权证明保留在此 Hub 配置；普通状态快照不能解除该限制。
          请通过 Link 授权面板恢复原请求并核对双方当前证明，勿重新提交。
        </Notice>}
        {hubStatus.enrolled && !hubStatus.sessionCapabilitiesReady &&
          <View style={s.modelActions}><Button title="恢复加密会话" secondary
            onPress={() => { void initializeHubSession(); }} disabled={hubBusy} /></View>}
        {sessionCapabilities && <Text style={s.small}>Hub 授权操作：{sessionCapabilities.available_rpc_operations.join(', ') || '无'}</Text>}
      </Card>
      {clientDeviceListAllowed && <>
        <Section name="本 Owner 的 App 设备" action={clientDevicesBusy ? '读取中…' : '读取设备列表'}
          onPress={() => { if (!clientDevicesBusy) void fetchClientDevices().catch(() => undefined); }} />
        <Notice>设备清单来自加密 devices.list。撤销使用 Hub 返回的版本，由 Hub 永久隔离目标设备；当前手机不能撤销自身。设备登记不授予 peer 消息解密权。</Notice>
        {!!clientDevicesMessage && <Text style={s.small}>{clientDevicesMessage}</Text>}
        {clientDevicesLoaded && clientDevices.length === 0 &&
          <Text style={s.small}>Hub 未返回此 Owner 的 App 设备。</Text>}
        {clientDevicesLoaded && clientDevices.slice(0, 50).map(device => {
          const id = field(device, 'device_id');
          const self = Boolean(hubStatus.deviceId && id === hubStatus.deviceId);
          const active = field(device, 'state') === 'ACTIVE';
          const version = Number(device.version);
          return <Card key={id}>
            <View style={s.row}><Text style={s.cardTitle}>{id}{self ? ' · 当前手机' : ''}</Text>
              <Pill text={active ? '已授权' : '已撤销'} tone={active ? 'green' : 'muted'} /></View>
            <Text style={s.small}>Hub 版本 v{field(device, 'version') || '—'} · 更新：{field(device, 'updated_at') || '时间未知'}</Text>
            {active && !self && clientDeviceRevokeAllowed && !!hubStatus.deviceId &&
              Number.isSafeInteger(version) && version > 0 && <View style={s.modelActions}>
                <Button title="永久撤销此设备" secondary disabled={clientDevicesBusy}
                  onPress={() => revokeClientDevice(device)} />
              </View>}
          </Card>;
        })}
        {clientDevicesLoaded && clientDevices.length > 50 &&
          <Notice>Hub 返回 {clientDevices.length} 台设备；当前页面只显示前 50 台。请使用 Hub 管理界面处理其余设备。</Notice>}
      </>}
      {hubStatus.authFenced && <>
        <Notice>{hubStatus.sessionError || 'App 设备认证已隔离；所有远程操作保持关闭。旧密钥没有因单个 HTTP 403 自动删除。'}</Notice>
        <Button title="重新授权需要时创建新设备身份" onPress={startNewDeviceEnrollment} secondary={hubBusy} disabled={hubBusy} />
      </>}
      <Section name="1 · 读取未受信任的 Hub 信息" />
      <TextInput style={s.hubInput} value={hubUrl} onChangeText={setHubUrl}
        placeholder="https://hub.example" autoCapitalize="none" autoCorrect={false}
        keyboardType="url" accessibilityLabel="Hub URL" />
      <Button title={hubBusy ? '正在读取…' : '读取公开能力与身份'} secondary disabled={hubBusy || !hubUrl.trim()}
        onPress={() => { void fetchHubCandidate(); }} />
      {hubCandidate && <Card>
        <Text style={s.cardTitle}>未受信任的身份候选</Text>
        <Text style={s.description}>contract：{hubCandidate.identity.contract} · Hub：{hubCandidate.identity.hub_id} · Control Key ID：{hubCandidate.identity.control_public_identity.id}</Text>
        <Text style={s.small}>能力状态：{hubCandidate.capabilities.status} · status_events：{String(hubCandidate.capabilities.status_events)} · status_changes_partial：{String(hubCandidate.capabilities.status_changes_partial)} · external_thread_links：{String(hubCandidate.capabilities.external_thread_links)}</Text>
        <Text style={s.small}>Control 完整公钥身份（需通过独立渠道核对）：</Text>
        <Text selectable style={s.mono}>{JSON.stringify(hubCandidate.identity.control_public_identity)}</Text>
        <Text style={s.small}>公开 available_rpc_operations 仅描述服务器实现，不授予当前设备权限。</Text>
      </Card>}
      <Section name="2 · 独立核对并固定 Hub 身份" />
      <Notice>请从你已信任的独立渠道取得 Hub ID 和完整 Control 公钥身份，再手动输入。不要把刚从这个 URL 读到的数据当作信任根。Control 公钥 ID 与 Owner ID 是不同身份。</Notice>
      <TextInput style={s.hubInput} value={trustedHubId} onChangeText={setTrustedHubId}
        placeholder="独立核验的 hub_id" autoCapitalize="none" autoCorrect={false}
        accessibilityLabel="独立核验的 Hub ID" />
      <TextInput style={[s.hubInput, s.multilineInput]} value={trustedControlIdentity}
        onChangeText={setTrustedControlIdentity} placeholder="完整 Control public identity JSON"
        multiline autoCapitalize="none" autoCorrect={false} accessibilityLabel="独立核验的 Control 公钥身份" />
      <Button title={hubBusy ? '正在固定…' : '核对并固定 Hub 公钥'}
        onPress={() => { void pinHub(); }} secondary={hubBusy}
        disabled={hubBusy || !hubUrl.trim() || !trustedHubId.trim() || !trustedControlIdentity.trim()} />
      <Section name="3 · 生成手机设备身份" />
      <Text style={s.description}>设备私钥由 Android 安全适配生成并留在设备；UI 只展示公钥身份。Owner 必须在可信外部批准工具中独立签发绑定此公钥、Hub、设备 ID 和期限的 OwnerDeviceGrant。</Text>
      {!hubStatus.authFenced && <Button title="生成 / 读取设备公钥身份" onPress={() => { void createDeviceIdentity(); }}
        secondary={!hubStatus.pinned || hubBusy || hubStatus.enrollmentRecoveryRequired}
        disabled={!hubStatus.pinned || hubBusy || hubStatus.enrollmentRecoveryRequired} />}
      {!!deviceIdentityJson && <Card>
        <Text style={s.cardTitle}>设备公钥身份</Text>
        <Text selectable style={s.mono}>{deviceIdentityJson}</Text>
      </Card>}
      <Section name="4 · 登记外部 OwnerDeviceGrant" />
      <Notice>Owner ID 必须是 Owner 的 Human Principal ID。不要填 Hub ID、Control public key ID，手机也不会替 Owner 签名。</Notice>
      <TextInput style={s.hubInput} value={ownerId} onChangeText={setOwnerId}
        placeholder="Owner Principal ID" autoCapitalize="none" autoCorrect={false}
        accessibilityLabel="Owner Principal ID" />
      <TextInput style={s.hubInput} value={ownerKeyId} onChangeText={setOwnerKeyId}
        placeholder="Owner 审批公钥 ID" autoCapitalize="none" autoCorrect={false}
        accessibilityLabel="Owner 公钥 ID" />
      <TextInput style={[s.hubInput, s.multilineInput]} value={ownerPublicIdentity}
        onChangeText={setOwnerPublicIdentity} placeholder="Owner 完整 public identity JSON"
        multiline autoCapitalize="none" autoCorrect={false} accessibilityLabel="Owner 公钥身份" />
      <TextInput style={s.hubInput} value={deviceId} onChangeText={setDeviceId}
        placeholder="唯一 device_id" autoCapitalize="none" autoCorrect={false}
        accessibilityLabel="设备 ID" />
      <TextInput style={[s.hubInput, s.multilineInput]} value={ownerDeviceGrant}
        onChangeText={setOwnerDeviceGrant} placeholder="Owner 独立签发的 OwnerDeviceGrant（标准 padded base64）"
        multiline autoCapitalize="none" autoCorrect={false} accessibilityLabel="OwnerDeviceGrant" />
      <Button title={hubBusy ? '验证并登记中…' : '验证 Grant 并登记此设备'}
        onPress={() => { void enrollDevice(); }}
        secondary={!hubStatus.pinned || !deviceIdentityJson || hubBusy ||
          hubStatus.enrollmentRecoveryRequired || !ownerDeviceGrant.trim()}
        disabled={!hubStatus.pinned || !deviceIdentityJson || hubBusy ||
          hubStatus.enrollmentRecoveryRequired || !ownerDeviceGrant.trim()} />
      {!!hubMessage && <Text style={s.small}>{hubMessage}</Text>}
      {!!hubCandidate && <Card>
        <Text style={s.cardTitle}>当前 Hub 公布能力</Text>
        <Text style={s.description}>status snapshot：{String(hubCandidate.capabilities.status_snapshot)} · Partial changes：{String(hubCandidate.capabilities.status_changes_partial)} · Realtime events：{String(hubCandidate.capabilities.status_events)} · External thread links：{String(hubCandidate.capabilities.external_thread_links)}</Text>
        <Text style={s.small}>false 的能力不会显示相应入口；真实操作还必须出现在设备加密 session.capabilities allowlist 中。</Text>
      </Card>}
      <Card><Text style={s.cardTitle}>录音与文字</Text>
        <Text style={s.description}>录音不上传；本地转写先由用户检查和编辑。intent.submit 发送的是用户确认的文字。</Text></Card>
    </>;
  };

  return <SafeAreaView style={s.screen} edges={['top', 'bottom']}>
    <View style={s.header}>
      <View style={s.logo}><Text style={s.logoText}>C</Text></View>
      <Text style={s.brand}>CICADA</Text>
      <Pill text={realSession ? `E2EE · ${sessionCapabilities?.role || hubStatus.role || '已认证'}` :
        hubStatus.authFenced ? '授权已隔离' : hubStatus.pinned ? '未建立会话' : '未连接'}
        tone={realSession ? 'green' : 'amber'} />
    </View>
    <View style={s.connectionBar}>
      <Pressable onPress={connection.openProfiles} disabled={recording}
        accessibilityLabel="管理 Hub 连接"><Text style={s.connectionText}>
          {connection.profile.label} · {hubStatus.hubId || '未固定身份'}
      </Text></Pressable>
      <Text style={s.connectionText}>{activeNetwork?.name || hubStatus.activeNetworkId || '未选择 Network'}</Text>
    </View>
    <ScrollView key={tab} ref={pageScrollRef} style={s.scroll} contentContainerStyle={s.content}>
      {page()}
    </ScrollView>
    <View style={s.composeBar}>
      <Pressable style={s.placeholder} onPress={() => openComposer(false)}
        accessibilityLabel="打开文字输入">
        <Text style={s.placeholderText}>问问 Control…</Text>
      </Pressable>
      <Pressable style={s.micButton} onPress={() => openComposer(true)}
        accessibilityLabel="打开语音输入"><Text style={s.micText}>🎙</Text></Pressable>
    </View>
    <View style={s.nav}>{tabs.map(item =>
      <Pressable key={item.id} style={s.navItem} onPress={() => setTab(item.id)}
        accessibilityRole="tab" accessibilityState={{selected: tab === item.id}}>
        <Text style={[s.navText, tab === item.id && s.navSelected]}>{item.name}</Text>
      </Pressable>)}</View>
    <Modal visible={compose} transparent animationType="fade" onRequestClose={closeComposer}>
      <KeyboardAvoidingView style={s.overlay}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <View style={s.dialog}>
          <Text style={s.dialogTitle}>交给 Control</Text>
          <Text style={s.dialogIntro}>写下或说出你的请求。语音在本机转写；确认发送后，文字只通过经认证的后量子加密会话交给 Control。</Text>
          <TextInput style={s.input} multiline value={draft} onChangeText={setDraft}
            placeholder="例如：查看优化组的进展" placeholderTextColor={c.muted}
            accessibilityLabel="请求内容" />
          <Text style={s.voiceStatus}>{voiceStatus}</Text>
          <View style={s.dialogActions}>
            <Button title={recording ? '停止录音' : '开始语音'}
              onPress={() => { startVoice(); }} secondary />
          <Button title={operationAllowed(hubStatus, 'intent.submit') ?
              '确认并加密发送' : '远程发送未启用'} onPress={() => { void submitIntent(); }}
              secondary={!operationAllowed(hubStatus, 'intent.submit')}
              disabled={hubBusy || !operationAllowed(hubStatus, 'intent.submit')} />
          </View>
          <Pressable style={s.close} onPress={closeComposer}><Text style={s.link}>关闭</Text></Pressable>
        </View>
      </KeyboardAvoidingView>
    </Modal>
    <Modal visible={detail !== null} transparent animationType="fade"
      onRequestClose={() => setDetail(null)}>
      <View style={s.overlay}><View style={s.dialog}>
        <Text style={s.dialogTitle}>{detail?.title}</Text>
        <Text style={s.detailBody}>{detail?.body}</Text>
        <Pressable style={s.close} onPress={() => setDetail(null)}>
          <Text style={s.link}>关闭</Text></Pressable>
      </View></View>
    </Modal>
  </SafeAreaView>;
}

type LinkListEntry = {link: JsonObject; my_side: string};

/** Proposal metadata only. The token is never persisted, logged, or sent outside sealed RPC. */
function LinkProposalPanel({status, capabilities, sessionCapabilities, apiScope, getCurrentStatus,
  linkConsentApi, linkReviewPolicyStatusReady, readLinkReviewPolicyStatus, request, recoveredInvite, clearRecoveredInvite}: {
  status: ClientHubStatus;
  capabilities: ClientHubCapabilities;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  apiScope: HubProfileScope;
  linkConsentApi: LinkConsentApi;
  getCurrentStatus: () => Promise<ClientHubStatus>;
  linkReviewPolicyStatusReady: boolean;
  readLinkReviewPolicyStatus: (input: {linkId: string; expectedLinkVersion: number}) => Promise<unknown>;
  request: (operation: ClientHubGenericRpcOperation, body: Record<string, unknown>) => Promise<unknown>;
  recoveredInvite: JsonObject | null;
  clearRecoveredInvite: () => void;
}) {
  const [links, setLinks] = useState<LinkListEntry[]>([]);
  const [cursor, setCursor] = useState('');
  const [hasMore, setHasMore] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [listError, setListError] = useState(false);
  const [linkListDiagnosticState, setLinkListDiagnosticState] = useState<LinkListDiagnosticState>('IDLE');
  const [linkListGeneration, setLinkListGeneration] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [sourceEndpointId, setSourceEndpointId] = useState('');
  const [sourceGroupId, setSourceGroupId] = useState('');
  const [scopes, setScopes] = useState('');
  const [issuedToken, setIssuedToken] = useState('');
  const [issuedExpiresAt, setIssuedExpiresAt] = useState('');
  const [receivedToken, setReceivedToken] = useState('');
  const [preview, setPreview] = useState<JsonObject | null>(null);
  const [targetEndpointId, setTargetEndpointId] = useState('');
  const [targetGroupId, setTargetGroupId] = useState('');
  const issued = issuedToken || field(recoveredInvite || {}, 'token');
  const issuedExpiry = issuedExpiresAt || field(recoveredInvite || {}, 'expires_at');
  const allowed = (operation: ClientRpcOperation) =>
    capsAllows(capabilities, 'external_link_invites', operation, status);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', state => {
      if (state !== 'active') {
        setIssuedToken('');
        setIssuedExpiresAt('');
        setReceivedToken('');
        setPreview(null);
      }
    });
    return () => subscription.remove();
  }, []);

  const readLinks = async (nextCursor = '') => {
    if (!allowed('link.list')) return false;
    setLinkListGeneration(generation => generation + 1);
    setLinkListDiagnosticState('LOADING');
    setListError(true);
    if (!nextCursor) { setLinks([]); setLoaded(false); }
    setBusy(true);
    setMessage('正在通过加密会话读取本人 Link 提案…');
    let invalidResponse = false;
    try {
      const page = asObject(await request('link.list', nextCursor ?
        {cursor: nextCursor, limit: 50} : {limit: 50}));
      if (!Array.isArray(page.links) || typeof page.has_more !== 'boolean' ||
        (page.has_more && (typeof page.cursor !== 'string' || !page.cursor))) {
        invalidResponse = true;
        throw new Error('Hub link.list 返回格式无效');
      }
      const entries = page.links.map(value => {
        const item = asObject(value);
        return {link: asObject(item.link), my_side: field(item, 'my_side')};
      }).filter(item => Boolean(field(item.link, 'link_id')));
      setLinks(previous => nextCursor ? [...previous, ...entries] : entries);
      setCursor(typeof page.cursor === 'string' ? page.cursor : '');
      setHasMore(page.has_more);
      setLoaded(true);
      setListError(false);
      // Keep terminal success as a fixed state; render derives empty/nonempty
      // from the committed links state so pagination does not use this closure.
      setLinkListDiagnosticState('OK_NONEMPTY');
      setMessage(page.has_more ? '只显示已读取的分页；可继续加载。' :
        '已读取本人可见的 Link 元数据；PROPOSED 仍不能发消息。');
      return true;
    } catch (error) {
      if (!nextCursor) { setLinks([]); setLoaded(false); }
      setListError(true);
      const failureKind: LinkListDiagnosticFailureKind = error instanceof ClientHubRpcError ?
        'RPC_REJECTED' : invalidResponse ? 'INVALID_RESPONSE' : 'REQUEST_FAILED';
      setLinkListDiagnosticState(linkListDiagnosticStateForFailure(failureKind));
      setMessage('Link 列表未对账：' + safeHubError(error));
      return false;
    } finally { setBusy(false); }
  };
  const createInvite = async (expiry: string, exactScopes: string[]) => {
    setBusy(true);
    setIssuedToken('');
    clearRecoveredInvite();
    try {
      const result = asObject(await request('link.invite_create', {
        source_endpoint_id: sourceEndpointId.trim(), source_group_id: sourceGroupId.trim(),
        hub_id: status.hubId, actions: ['ask', 'reply'], data_scopes: exactScopes,
        expires_at: expiry,
      }));
      const token = field(result, 'token');
      if (!token) throw new Error('Hub 没有返回一次性邀请 token');
      setIssuedToken(token);
      setIssuedExpiresAt(field(result, 'expires_at'));
      setMessage('Hub 已创建一次性提案邀请。仅通过可信渠道交给目标用户；关闭或切到后台后不再显示。');
    } catch (error) {
      setMessage('邀请创建未确认成功：' + safeHubError(error) +
        '。若原始密文待恢复，请先在「我的」恢复，不要重新创建邀请。');
    } finally { setBusy(false); }
  };
  const askCreateInvite = () => {
    const exactScopes = scopes.split(',').map(item => item.trim()).filter(Boolean);
    if (!sourceEndpointId.trim() || !sourceGroupId.trim() || exactScopes.length === 0 ||
      !status.hubId || !allowed('link.invite_create')) return;
    const expiry = new Date(Date.now() + 30 * 60_000).toISOString();
    Alert.alert('创建跨用户提案邀请？',
      `Source ${sourceEndpointId.trim()} · Group ${sourceGroupId.trim()}\n动作：ask、reply\n数据范围：${exactScopes.join(', ')}\n到期：${expiry}\n一次性 token 谁拿到谁可能接受；请只发给目标用户。提案不启用消息路由。${issued ? '\n当前显示的旧邀请 token 将被隐藏，但不会由此撤销。' : ''}`, [
        {text: '取消', style: 'cancel'},
        {text: '创建邀请', onPress: () => { void createInvite(expiry, exactScopes); }},
      ]);
  };
  const readPreview = async () => {
    if (!receivedToken.trim() || !allowed('link.invite_preview')) return;
    setBusy(true);
    setPreview(null);
    try {
      const result = asObject(await request('link.invite_preview',
        {token: receivedToken.trim()}));
      if (!field(result, 'hub_id') || !field(result, 'expires_at') ||
        field(result, 'hub_id') !== status.hubId) {
        throw new Error('Hub 邀请预览缺少必要字段');
      }
      setPreview(result);
      setMessage('请核对来源标签、Hub、动作、数据范围和期限。预览不等于同意。');
    } catch (error) { setMessage('邀请预览失败：' + safeHubError(error)); }
    finally { setBusy(false); }
  };
  const acceptInvite = async () => {
    if (!preview || !receivedToken.trim() || !targetEndpointId.trim() ||
      !targetGroupId.trim() || !allowed('link.invite_accept')) return;
    setBusy(true);
    let accepted = false;
    try {
      const result = asObject(await request('link.invite_accept', {
        token: receivedToken.trim(), target_endpoint_id: targetEndpointId.trim(),
        target_group_id: targetGroupId.trim(),
      }));
      accepted = result.state === 'PROPOSED';
      setReceivedToken('');
      setPreview(null);
      if (!await readLinks()) throw new Error('Link 列表未能重读');
      setMessage(accepted ? `Hub 已记录 Link ${field(result, 'link_id')} 为 PROPOSED；双方尚不能发消息。` :
        'Hub 返回的提案状态未确认；请读取权威 Link 列表。');
    } catch (error) {
      setLinks([]);
      setLoaded(false);
      setListError(true);
      setMessage((accepted ? '提案已由 Hub 接受，但列表读取失败：' :
        '接受邀请未确认成功：') + safeHubError(error) + '。请重新读取权威 Link 列表。');
    } finally { setBusy(false); }
  };
  const askAcceptInvite = () => {
    if (!preview || !targetEndpointId.trim() || !targetGroupId.trim() ||
      !allowed('link.invite_accept')) return;
    Alert.alert('接受为 Link 提案？',
      `来源：${field(preview, 'source_endpoint_label')} / ${field(preview, 'source_group_label')}\n目标：${targetEndpointId.trim()} / ${targetGroupId.trim()}\n方向：${field(preview, 'direction')} · 动作：${(Array.isArray(preview.actions) ? preview.actions : []).join(', ')}\n范围：${(Array.isArray(preview.data_scopes) ? preview.data_scopes : []).join(', ')}\n到期：${field(preview, 'expires_at')}\n接受只创建 PROPOSED，不开放消息。`, [
        {text: '取消', style: 'cancel'},
        {text: '接受提案', onPress: () => { void acceptInvite(); }},
      ]);
  };
  const revokeProposal = async (link: JsonObject) => {
    setBusy(true);
    let revoked = false;
    try {
      await request('topology.apply', {kind: 'link.revoke', revoke_link: {
        link_id: field(link, 'link_id'), expected_link_version: Number(link.version),
      }});
      revoked = true;
      if (!await readLinks()) throw new Error('Link 列表未能重读');
      setMessage(`Hub 已撤销 Link ${field(link, 'link_id')}；权威列表已重读。`);
    } catch (error) {
      setLinks([]);
      setLoaded(false);
      setListError(true);
      setMessage((revoked ? 'Hub 已确认撤销，但权威列表读取失败：' :
        '撤销未确认成功：') + safeHubError(error) + '。请重新读取权威 Link 列表。');
    } finally { setBusy(false); }
  };

  return <>
    <Section name="跨用户 Link 提案" action={busy ? '处理中…' : '重读本人提案'}
      onPress={() => { if (!busy) void readLinks(); }} />
    <Notice>{capabilities.external_thread_links ?
      '此页只管理双方同意的提案；App 尚未提供普通 peer 消息入口。密钥授权须经独立公钥核验、外部 Owner 签名及手机明确确认。' :
      'external_thread_links=false：Hub 只开放邀请与 PROPOSED 提案；不显示聊天、消息发送或已连通状态。密钥授权只记录精确范围的双方同意，不开放普通消息。'}</Notice>
    {!!message && <Text testID={linkListDiagnosticTestId(
      linkListDiagnosticState === 'OK_EMPTY' || linkListDiagnosticState === 'OK_NONEMPTY' ?
        (links.length > 0 ? 'OK_NONEMPTY' : 'OK_EMPTY') : linkListDiagnosticState)}
      style={s.small}>{message}</Text>}
    {loaded && links.length === 0 && <Text style={s.small}>当前没有本人可见的 Link 提案。</Text>}
    {links.map(item => {
      const link = item.link;
      const version = Number(link.version);
      return <Card key={field(link, 'link_id')}>
        <View style={s.row}><Text style={s.cardTitle} testID="link-list-row">Link {field(link, 'link_id')}</Text>
          <Pill text={field(link, 'state') || '状态未知'} tone="muted" /></View>
        <Text style={s.description}>{field(link, 'source_endpoint_id')} / {field(link, 'source_group_id')} → {field(link, 'target_endpoint_id')} / {field(link, 'target_group_id')}</Text>
        <Text style={s.small}>我的方向：{item.my_side || '未知'} · 动作：{(Array.isArray(link.actions) ? link.actions : []).join(', ')} · 范围：{(Array.isArray(link.data_scopes) ? link.data_scopes : []).join(', ')}</Text>
        <Text style={s.small}>到期：{field(link, 'expires_at')} · Hub 版本 v{field(link, 'version')} · 来源：加密 link.list</Text>
        {!listError && Number.isSafeInteger(version) && version > 0 &&
          <LinkReviewPolicyStatusPanel key={`${field(link, 'link_id')}/${linkListGeneration}`}
            status={status} publicCapabilities={capabilities} sessionCapabilities={sessionCapabilities}
            apiScope={apiScope} linkId={field(link, 'link_id')} linkVersion={version}
            listGeneration={linkListGeneration}
            linkReviewPolicyStatusReady={linkReviewPolicyStatusReady}
            readStatus={readLinkReviewPolicyStatus} getCurrentStatus={getCurrentStatus} />}
        {!listError && Number.isSafeInteger(version) && version > 0 && field(link, 'state') === 'PROPOSED' &&
          linkConsentCapabilitiesAllow(status, capabilities, sessionCapabilities, apiScope, linkConsentApi.linkConsentReady) &&
          <LinkConsentPanel api={linkConsentApi} scope={apiScope} linkId={field(link, 'link_id')}
            linkVersion={version} listGeneration={linkListGeneration} />}
        {field(link, 'state') === 'PROPOSED' && !listError &&
          Number.isSafeInteger(version) && version > 0 && allowed('topology.apply') &&
          <View style={s.modelActions}><Button title="撤销提案" secondary disabled={busy}
            onPress={() => Alert.alert('撤销此 Link 提案？',
              `${field(link, 'link_id')} · 当前版本 v${version}\nHub 将再次校验归属和版本。`, [
                {text: '取消', style: 'cancel'},
                {text: '撤销提案', style: 'destructive', onPress: () => { void revokeProposal(link); }},
              ])} /></View>}
      </Card>;
    })}
    {loaded && hasMore && !!cursor && <Button title={busy ? '读取中…' : '加载更多提案'}
      secondary disabled={busy} onPress={() => { void readLinks(cursor); }} />}
    {allowed('link.invite_create') && <>
      <Section name="发出一次性邀请" />
      <Text style={s.description}>填写自己已加入且当前有效的 Source Endpoint 与 Group。默认动作 ask、reply，有效期 30 分钟；Hub 再校验所有归属和范围。</Text>
      <TextInput style={s.hubInput} value={sourceEndpointId} onChangeText={setSourceEndpointId}
        placeholder="我的 Source Endpoint ID" accessibilityLabel="邀请 Source Endpoint ID" />
      <TextInput style={s.hubInput} value={sourceGroupId} onChangeText={setSourceGroupId}
        placeholder="我的 Source Group ID" accessibilityLabel="邀请 Source Group ID" />
      <TextInput style={s.hubInput} value={scopes} onChangeText={setScopes}
        placeholder="数据范围，逗号分隔" accessibilityLabel="邀请数据范围" />
      <Button title="创建提案邀请" secondary disabled={busy || !sourceEndpointId.trim() ||
        !sourceGroupId.trim() || !scopes.trim()} onPress={askCreateInvite} />
      {!!issued && <Card>
        <Text style={s.cardTitle}>一次性邀请 token · 仅此处显示</Text>
        <Text style={s.description}>到期：{issuedExpiry}。持有 token 的其他 Owner 可能接受；仅通过可信渠道交给目标用户。切到后台后清除显示。</Text>
        <Text style={s.mono} selectable>{issued}</Text>
        <View style={s.modelActions}><Button title="清除 token" secondary onPress={() => {
          setIssuedToken(''); setIssuedExpiresAt(''); clearRecoveredInvite();
        }} /></View>
      </Card>}
    </>}
    {allowed('link.invite_preview') && <>
      <Section name="预览收到的邀请" />
      <TextInput style={s.hubInput} value={receivedToken} onChangeText={value => {
        setReceivedToken(value); setPreview(null);
      }} secureTextEntry autoCapitalize="none" autoCorrect={false}
        placeholder="粘贴一次性邀请 token" accessibilityLabel="收到的邀请 token" />
      <Button title="加密预览邀请" secondary disabled={busy || !receivedToken.trim()}
        onPress={() => { void readPreview(); }} />
      {preview && <Card>
        <Text style={s.cardTitle}>待确认的提案范围</Text>
        <Text style={s.description}>来源：{field(preview, 'source_endpoint_label')} / {field(preview, 'source_group_label')}</Text>
        <Text style={s.small}>Hub：{field(preview, 'hub_id')} · 方向：{field(preview, 'direction')} · 动作：{(Array.isArray(preview.actions) ? preview.actions : []).join(', ')}</Text>
        <Text style={s.small}>范围：{(Array.isArray(preview.data_scopes) ? preview.data_scopes : []).join(', ')} · 到期：{field(preview, 'expires_at')}</Text>
        {allowed('link.invite_accept') && <>
          <TextInput style={s.hubInput} value={targetEndpointId} onChangeText={setTargetEndpointId}
            placeholder="我的 Target Endpoint ID" accessibilityLabel="邀请 Target Endpoint ID" />
          <TextInput style={s.hubInput} value={targetGroupId} onChangeText={setTargetGroupId}
            placeholder="我的 Target Group ID" accessibilityLabel="邀请 Target Group ID" />
          <Button title="接受为提案" disabled={busy || !targetEndpointId.trim() ||
            !targetGroupId.trim()} onPress={askAcceptInvite} />
        </>}
      </Card>}
    </>}
  </>;
}

function Card({children, onPress}: {children: React.ReactNode; onPress?: () => void}) {
  return onPress ? <Pressable style={s.card} onPress={onPress}>{children}</Pressable> :
    <View style={s.card}>{children}</View>;
}
function VisibleItems({items, renderItem, pageSize = 20}: {
  items: JsonObject[];
  renderItem: (item: JsonObject) => React.ReactNode;
  pageSize?: number;
}) {
  const [visibleCount, setVisibleCount] = useState(pageSize);
  useEffect(() => { setVisibleCount(pageSize); }, [items, pageSize]);
  return <>
    {items.slice(0, visibleCount).map(renderItem)}
    {items.length > visibleCount && <Button secondary
      title={`显示更多 · ${visibleCount} / ${items.length}`}
      onPress={() => setVisibleCount(count => Math.min(count + pageSize, items.length))} />}
  </>;
}
function Pill({text, tone}: {text: string; tone: 'amber' | 'green' | 'muted'}) {
  return <View style={[s.pill, tone === 'amber' ? s.pillAmber :
    tone === 'green' ? s.pillGreen : s.pillMuted]}>
    <Text style={[s.pillText, tone === 'amber' ? s.amber :
      tone === 'green' ? s.green : s.muted]}>{text}</Text></View>;
}
function Eyebrow({children}: {children: string}) {
  return <Text style={s.eyebrow}>{children}</Text>;
}
function Heading({eyebrow, title, subtitle}:
  {eyebrow: string; title: string; subtitle: string}) {
  return <><Eyebrow>{eyebrow}</Eyebrow><Text style={s.pageTitle}>{title}</Text>
    <Text style={s.intro}>{subtitle}</Text></>;
}
function Section({name, action, onPress}:
  {name: string; action?: string; onPress?: () => void}) {
  return <View style={s.section}><Text style={s.sectionTitle}>{name}</Text>
    {action && onPress && <Pressable onPress={onPress}>
      <Text style={s.link}>{action}  →</Text></Pressable>}</View>;
}
function Notice({children}: {children: React.ReactNode}) {
  return <View style={s.notice}><Text style={s.noticeText}>{children}</Text></View>;
}
function Metric({value, label}: {value: string; label: string}) {
  return <View style={s.metric}><Text style={s.metricValue}>{value}</Text>
    <Text style={s.metricLabel}>{label}</Text></View>;
}
function Button({title, onPress, secondary, disabled}:
  {title: string; onPress: () => void; secondary?: boolean; disabled?: boolean}) {
  return <Pressable style={[s.button, secondary && s.buttonSecondary,
    disabled && s.buttonDisabled]} onPress={onPress} disabled={disabled}>
    <Text style={[s.buttonText, secondary && s.buttonTextSecondary]}>{title}</Text>
  </Pressable>;
}
function ActionCard({title, body, onPress}:
  {title: string; body: string; onPress: () => void}) {
  return <Card onPress={onPress}><Text style={s.cardTitle}>{title}   →</Text>
    <Text style={s.description}>{body}</Text></Card>;
}

function MonitorConsentCard({endpoint, source = false, ordinal}: {
  endpoint: MonitorConsentEndpoint; source?: boolean; ordinal?: number;
}) {
  return <View style={s.monitorConsentCard}>
    <Text style={s.kicker}>{source ? 'Advisor 来源' : `收件人 ${ordinal || ''}`}</Text>
    <Text style={s.cardTitle}>{endpoint.endpointId}</Text>
    <Text style={s.description}>Owner {endpoint.ownerId} · Principal {endpoint.principalId} · Node {endpoint.nodeId}</Text>
    <Text style={s.small}>Membership revision {endpoint.membershipRevision} · Group join revision {endpoint.groupJoinRevision}</Text>
    <Text style={s.small}>Binding {endpoint.bindingId} · epoch {endpoint.bindingEpoch} · Key {endpoint.keyId} / v{endpoint.keyVersion}</Text>
    <Text style={s.mono}>Key fingerprint {endpoint.keyFingerprint}</Text>
  </View>;
}

function MonitorOutcomeCard({outcome, index}: {outcome: MonitorRecipientOutcome; index: number}) {
  const statusTone = outcome.state === 'ACCEPTED' ? 'green' :
    outcome.state === 'FAILED' ? 'amber' : 'muted';
  return <View style={s.monitorOutcomeCard}>
    <View style={s.row}><Text style={s.cardTitle}>收件人 {index + 1} · {outcome.endpointId}</Text>
      <Pill text={outcome.state} tone={statusTone} /></View>
    <Text style={s.description}>{monitorRecipientOutcomeText(outcome)}</Text>
    {!!outcome.reportedAt && <Text style={s.small}>报告时间：{outcome.reportedAt}</Text>}
  </View>;
}

const s = StyleSheet.create({
  screen: {flex: 1, backgroundColor: c.white},
  header: {height: 76, flexDirection: 'row', alignItems: 'center',
    paddingHorizontal: 22, backgroundColor: c.white},
  connectionBar: {paddingHorizontal: 22, paddingBottom: 12, gap: 4},
  connectionText: {fontSize: 12, color: c.muted},
  logo: {width: 38, height: 38, borderRadius: 14, backgroundColor: c.ink,
    alignItems: 'center', justifyContent: 'center'},
  logoText: {fontSize: 18, fontWeight: '700', color: c.white},
  brand: {flex: 1, marginLeft: 10, fontSize: 17, fontWeight: '700',
    letterSpacing: 2, color: c.ink},
  scroll: {flex: 1},
  content: {paddingHorizontal: 22, paddingTop: 12, paddingBottom: 30},
  eyebrow: {fontSize: 12, color: c.green, letterSpacing: 2, fontWeight: '700',
    marginTop: 10, marginBottom: 10},
  hero: {fontSize: 32, lineHeight: 43, fontWeight: '700', color: c.ink},
  pageTitle: {fontSize: 32, fontWeight: '700', color: c.ink, marginBottom: 8},
  intro: {fontSize: 14, lineHeight: 21, color: c.muted, marginBottom: 22},
  darkCard: {borderRadius: 20, padding: 18, backgroundColor: c.ink},
  darkKicker: {fontSize: 12, fontWeight: '700', color: '#B9D6CC'},
  metrics: {flexDirection: 'row', marginTop: 18, marginBottom: 18},
  metric: {flex: 1},
  metricValue: {fontSize: 30, fontWeight: '700', color: c.white},
  metricLabel: {fontSize: 12, color: '#BFD6CE'},
  darkNote: {fontSize: 12, lineHeight: 17, color: '#C8DAD4'},
  section: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    marginTop: 26, marginBottom: 12},
  sectionTitle: {fontSize: 18, fontWeight: '700', color: c.ink},
  card: {borderRadius: 20, borderWidth: 1, borderColor: c.border,
    backgroundColor: c.white, padding: 18, marginBottom: 10},
  row: {flexDirection: 'row', justifyContent: 'space-between',
    alignItems: 'center', flexWrap: 'wrap', gap: 6},
  cardTitle: {fontSize: 17, fontWeight: '700', color: c.ink},
  description: {fontSize: 13, lineHeight: 19, color: c.muted, marginTop: 8},
  kicker: {fontSize: 12, fontWeight: '700', color: c.green},
  space: {marginTop: 12},
  small: {fontSize: 12, lineHeight: 18, color: c.muted, marginTop: 10},
  pill: {alignSelf: 'flex-start', paddingHorizontal: 9, paddingVertical: 6,
    borderRadius: 99},
  pillAmber: {backgroundColor: c.cream},
  pillGreen: {backgroundColor: c.mint},
  pillMuted: {backgroundColor: c.pale},
  pillText: {fontSize: 11, fontWeight: '700'},
  amber: {color: c.amber}, green: {color: c.green}, muted: {color: c.muted},
  link: {fontSize: 13, fontWeight: '700', color: c.green, marginTop: 8},
  notice: {borderRadius: 12, padding: 13, backgroundColor: c.cream, marginBottom: 4},
  noticeText: {fontSize: 12, lineHeight: 18, color: c.amber},
  button: {flex: 1, minHeight: 46, borderRadius: 13, paddingHorizontal: 14,
    alignItems: 'center', justifyContent: 'center', backgroundColor: c.green},
  buttonDisabled: {opacity: 0.45},
  buttonText: {fontSize: 14, fontWeight: '700', color: c.white},
  buttonSecondary: {backgroundColor: c.mint},
  buttonTextSecondary: {color: c.green},
  composeBar: {height: 76, flexDirection: 'row', alignItems: 'center',
    paddingHorizontal: 18, backgroundColor: c.white},
  placeholder: {height: 50, flex: 1, borderRadius: 18,
    backgroundColor: c.pale, paddingHorizontal: 17, justifyContent: 'center'},
  placeholderText: {fontSize: 15, color: c.muted},
  micButton: {width: 52, height: 50, marginLeft: 9, borderRadius: 18,
    backgroundColor: c.green, alignItems: 'center', justifyContent: 'center'},
  micText: {fontSize: 22, color: c.white},
  nav: {height: 48, flexDirection: 'row', paddingHorizontal: 8,
    backgroundColor: c.white},
  navItem: {flex: 1, alignItems: 'center', justifyContent: 'center'},
  navText: {fontSize: 12, color: c.muted},
  navSelected: {color: c.green, fontWeight: '700'},
  overlay: {flex: 1, paddingHorizontal: 24, justifyContent: 'center',
    backgroundColor: '#0009'},
  dialog: {backgroundColor: c.white, padding: 22, borderRadius: 3},
  dialogTitle: {fontSize: 22, fontWeight: '700', color: c.ink},
  dialogIntro: {fontSize: 13, lineHeight: 18, color: c.muted,
    marginTop: 8, marginBottom: 18},
  input: {minHeight: 132, maxHeight: 180, borderRadius: 16,
    paddingHorizontal: 14, paddingVertical: 14, textAlignVertical: 'top',
    backgroundColor: c.pale, color: c.ink, fontSize: 17},
  voiceStatus: {minHeight: 32, fontSize: 12, lineHeight: 17,
    color: c.muted, marginTop: 12, marginBottom: 16},
  dialogActions: {flexDirection: 'row', gap: 9},
  modelActions: {flexDirection: 'row', gap: 9, marginTop: 16},
  close: {alignSelf: 'flex-end', paddingTop: 24},
  detailBody: {fontSize: 14, lineHeight: 22, color: c.muted, marginTop: 18},
  hubInput: {minHeight: 48, borderRadius: 13, paddingHorizontal: 14,
    paddingVertical: 12, backgroundColor: c.pale, color: c.ink, fontSize: 14,
    marginTop: 8, marginBottom: 8},
  multilineInput: {minHeight: 92, maxHeight: 180, textAlignVertical: 'top'},
  monitorBodyInput: {minHeight: 132, maxHeight: 240},
  monitorChoice: {borderWidth: 1, borderColor: c.border, borderRadius: 14,
    padding: 14, marginTop: 8, backgroundColor: c.white},
  monitorChoiceSelected: {borderColor: c.green, backgroundColor: c.mint},
  monitorConsentCard: {borderRadius: 14, borderWidth: 1, borderColor: c.border,
    backgroundColor: c.pale, padding: 14, marginTop: 8},
  monitorOutcomeCard: {borderRadius: 14, borderWidth: 1, borderColor: c.border,
    padding: 14, marginTop: 8},
  mono: {fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', fontSize: 10,
    lineHeight: 15, color: c.ink, marginTop: 8},
});

export default App;
