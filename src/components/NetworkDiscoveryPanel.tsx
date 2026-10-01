import React, {useEffect, useRef, useState} from 'react';
import {AppState, Pressable, StyleSheet, Text, View} from 'react-native';
import type {
  ClientHubApi, ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
} from '../platform/clientHub';
import {
  appendNetworkDirectoryPage, emptyNetworkDirectoryView, NetworkDiscoveryLifecycle,
  networkDiscoveryScopeKey,
} from '../platform/networkDiscovery';
import type {
  NetworkDirectoryView, NetworkDiscoveryRequestToken, NetworkDiscoveryScope,
} from '../platform/networkDiscovery';
import {
  endpointAdmissionPreviewFromRpc, explicitActiveNetwork, groupsInNetwork,
  networkDirectoryPageFromRpc, ownerNetworkReadAllows, endpointsInNetwork,
} from '../platform/networkTopology';
import type {
  EndpointAdmissionPreview, NetworkTopologyRecord, NetworkTopologySnapshot,
} from '../platform/networkTopology';

interface Props {
  api: ClientHubApi;
  status: ClientHubStatus;
  topology: NetworkTopologySnapshot | null;
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
}

const PAGE_SIZE = 8;
const DIRECTORY_LIMIT = 64;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (item: NetworkTopologyRecord | undefined, key: string): string =>
  typeof item?.[key] === 'string' ? item[key] as string : '';
const safeVersion = (value: unknown): number | null =>
  Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : null;
const sortedOperations = (value: unknown): string[] => Array.isArray(value) ?
  value.filter((item): item is string => typeof item === 'string').slice().sort() : [];

function authorityRevision(
  status: ClientHubStatus,
  publicCapabilities: ClientHubCapabilities | null,
  sessionCapabilities: ClientHubSessionCapabilities | null,
): string {
  return JSON.stringify([
    publicCapabilities?.contract_revision ?? '', publicCapabilities?.catalog_sha256 ?? '',
    publicCapabilities?.client_control_pq_e2ee === true,
    publicCapabilities?.authenticated_client_session === true,
    publicCapabilities?.topology_management === true,
    sortedOperations(publicCapabilities?.available_rpc_operations),
    sortedOperations(publicCapabilities?.external_rpc_operations),
    sessionCapabilities?.owner_id ?? '', sessionCapabilities?.role ?? '',
    sessionCapabilities?.contract_revision ?? '', sessionCapabilities?.catalog_sha256 ?? '',
    sortedOperations(sessionCapabilities?.available_rpc_operations),
    sortedOperations(status.allowedOperations),
  ]);
}

function fenceRevision(status: ClientHubStatus): string {
  return JSON.stringify([
    status.nativeAvailable, status.pinned, status.enrolled, status.remoteEnabled,
    status.sessionCapabilitiesReady, status.authFenced, status.recoveryBlocked === true,
    status.enrollmentRecoveryRequired === true, status.pendingOperationId ?? '',
    status.uncertainNeedsReconciliation === true,
  ]);
}

function topologySnapshotFromRpc(value: unknown, ownerId: string | undefined): NetworkTopologySnapshot | null {
  if (!isRecord(value) || value.contract_version !== 2 ||
      typeof ownerId !== 'string' || !ownerId || value.owner_principal_id !== ownerId ||
      typeof value.captured_at !== 'string' || value.read_consistency !== 'best_effort' ||
      !Array.isArray(value.networks) || value.networks.length > 100 ||
      typeof value.networks_truncated !== 'boolean' ||
      typeof value.network_endpoints_truncated !== 'boolean' ||
      !Array.isArray(value.groups) || !Array.isArray(value.memberships) ||
      !Array.isArray(value.endpoints) || !Array.isArray(value.links)) return null;
  return value as unknown as NetworkTopologySnapshot;
}

function resultFromRpc(response: unknown): unknown {
  if (!isRecord(response) || response.ok !== true ||
      !Object.prototype.hasOwnProperty.call(response, 'result')) {
    throw new DiscoveryError('rpc');
  }
  return response.result;
}

class DiscoveryError extends Error {
  constructor(readonly reason: 'stale' | 'permission' | 'topology' | 'rpc' | 'result') {
    super(reason);
  }
}

function messageFor(error: unknown): string {
  if (error instanceof DiscoveryError) {
    if (error.reason === 'stale') return 'Hub、Network 或应用状态已变化；已清除本地结果，请在当前会话重新读取。';
    if (error.reason === 'permission') return '当前公开能力、加密 session.capabilities 或 Owner 状态未授权此读取。';
    if (error.reason === 'topology') return '当前拓扑已变化或不完整；请先重读权威拓扑，再选择 Group 与 Endpoint。';
    if (error.reason === 'result') return 'Hub 返回的只读结果未通过字段与范围核对，已丢弃。';
  }
  return '读取未完成；当前结果已清除。请检查连接与 Hub 权威状态后重试。';
}

function previewInputStamp(
  topology: NetworkTopologySnapshot | null,
  networkId: string,
  groupId: string,
  endpointId: string,
): string | null {
  const network = explicitActiveNetwork(topology, networkId);
  const group = groupsInNetwork(topology, networkId).find(item => item.group_id === groupId);
  const endpoint = endpointsInNetwork(topology, networkId).find(item => item.endpoint_id === endpointId);
  if (!network || !group || group.state !== 'ACTIVE' || !safeVersion(group.version) ||
      !endpoint || !text(endpoint, 'principal_id') || text(endpoint, 'presence') === 'left') return null;
  // Endpoint principal_id names the Endpoint principal. It is not compared with the human Owner ID.
  return JSON.stringify([
    network.network_id, network.name, network.version,
    group.group_id, group.name, group.state, group.version, group.context_policy,
    endpoint.endpoint_id, endpoint.name, endpoint.principal_id,
    Array.isArray(endpoint.network_ids) ? [...endpoint.network_ids].sort() : [],
    Array.isArray(endpoint.group_ids) ? [...endpoint.group_ids].sort() : [],
    endpoint.binding_id ?? null, endpoint.binding_epoch ?? null, endpoint.binding_status ?? null,
  ]);
}

function samePreviewInput(
  displayedTopology: NetworkTopologySnapshot | null,
  freshTopology: NetworkTopologySnapshot | null,
  networkId: string,
  groupId: string,
  endpointId: string,
): boolean {
  const displayed = previewInputStamp(displayedTopology, networkId, groupId, endpointId);
  return Boolean(displayed && displayed === previewInputStamp(freshTopology, networkId, groupId, endpointId));
}

function previewLines(value: EndpointAdmissionPreview): string[] {
  const lines = [
    `Owner Principal：${value.owner_principal_id}`,
    `Network：${value.network_name} · ${value.network_id} · version ${value.network_version}`,
    `Group：${value.group_name} · ${value.group_id} · version ${value.group_version}`,
    `Group context：${value.group_context_policy}`,
    `Endpoint：${value.endpoint_name} · ${value.endpoint_id}`,
    `Endpoint Principal：${value.endpoint_principal_id}`,
    `迁移状态：${value.endpoint_migration_state}`,
    `Network Membership revision：${value.network_membership_revision}`,
    `Endpoint Network revision：${value.endpoint_network_revision}`,
    `Network access binding：${value.network_access_binding_id} · epoch ${value.network_access_epoch}`,
    `Native binding：${value.native_binding_id} · epoch ${value.native_binding_epoch}`,
  ];
  if (value.existing_group_binding_id !== undefined) {
    lines.push(`已有 Group binding：${value.existing_group_binding_id} · epoch ${value.existing_group_binding_epoch}`);
  }
  if (value.membership_status !== undefined) lines.push(`Membership：${value.membership_status} · revision ${value.membership_revision}`);
  else lines.push(`Membership revision：${value.membership_revision}`);
  if (value.endpoint_group_status !== undefined) {
    lines.push(`Endpoint Group：${value.endpoint_group_status} · revision ${value.endpoint_group_revision}`);
  } else lines.push(`Endpoint Group revision：${value.endpoint_group_revision}`);
  lines.push(
    `预览角色：${value.admission_roles.join(', ')}`,
    `新增 grants：${value.admission_grants.length}`,
    `包含历史：${String(value.history_included)}`,
    `创建 key grant：${String(value.key_grant_created)}`,
    `保留现有 Thread memory：${String(value.existing_thread_memory_retained)}`,
  );
  return lines;
}

export function NetworkDiscoveryPanel({api, status, topology, publicCapabilities,
  sessionCapabilities}: Props): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [foreground, setForeground] = useState(AppState.currentState === 'active');
  const [message, setMessage] = useState('');
  const [directoryState, setDirectoryState] = useState<{scopeKey: string; view: NetworkDirectoryView} | null>(null);
  const [previewState, setPreviewState] = useState<{
    scopeKey: string; inputStamp: string; value: EndpointAdmissionPreview; topologyCapturedAt: string;
  } | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [selectedEndpointId, setSelectedEndpointId] = useState('');
  const [groupPage, setGroupPage] = useState(0);
  const [endpointPage, setEndpointPage] = useState(0);
  const lifecycle = useRef(new NetworkDiscoveryLifecycle());
  const mounted = useRef(true);
  const busyRef = useRef(false);
  const foregroundRef = useRef(AppState.currentState === 'active');
  const scopeKeyRef = useRef('');

  const network = explicitActiveNetwork(topology, status.activeNetworkId);
  const scope: NetworkDiscoveryScope = {
    profileId: api.scope.profileId,
    selectionGeneration: api.scope.selectionGeneration,
    networkId: status.activeNetworkId || '',
    hubId: status.hubId || '',
    ownerId: status.ownerId || '',
    deviceId: status.deviceId || '',
    sessionEpoch: Number.isSafeInteger(status.sessionEpoch) ? Number(status.sessionEpoch) : null,
    authorityRevision: authorityRevision(status, publicCapabilities, sessionCapabilities),
    fenceRevision: fenceRevision(status),
    networkVersion: network?.version ?? null,
  };
  const currentScopeKey = networkDiscoveryScopeKey(scope);
  scopeKeyRef.current = currentScopeKey;
  const selectedInputStamp = previewInputStamp(topology, status.activeNetworkId || '',
    selectedGroupId, selectedEndpointId);
  const readyForDirectory = ownerNetworkReadAllows(publicCapabilities, sessionCapabilities,
    status, topology, 'network.directory');
  const readyForPreview = ownerNetworkReadAllows(publicCapabilities, sessionCapabilities,
    status, topology, 'topology.endpoint_admission_preview');
  const visibleDirectory = directoryState?.scopeKey === currentScopeKey ? directoryState.view : null;
  const visiblePreview = previewState?.scopeKey === currentScopeKey &&
    previewState.inputStamp === selectedInputStamp ? previewState : null;
  const groups = groupsInNetwork(topology, status.activeNetworkId).filter(group =>
    group.state === 'ACTIVE' && Boolean(text(group, 'group_id')) && safeVersion(group.version));
  const endpoints = endpointsInNetwork(topology, status.activeNetworkId).filter(endpoint =>
    Boolean(text(endpoint, 'endpoint_id')) && Boolean(text(endpoint, 'principal_id')) &&
    text(endpoint, 'presence') !== 'left');
  const selectedGroup = groups.find(group => group.group_id === selectedGroupId);
  const selectedEndpoint = endpoints.find(endpoint => endpoint.endpoint_id === selectedEndpointId);

  useEffect(() => {
    mounted.current = true;
    const currentLifecycle = lifecycle.current;
    return () => { mounted.current = false; currentLifecycle.invalidate(); };
  }, []);

  useEffect(() => {
    lifecycle.current.invalidate();
    busyRef.current = false;
    setBusy(false);
    setDirectoryState(null);
    setPreviewState(null);
    setSelectedGroupId('');
    setSelectedEndpointId('');
    setGroupPage(0);
    setEndpointPage(0);
    setMessage('');
  }, [currentScopeKey]);

  useEffect(() => {
    if (previewState && previewState.inputStamp !== selectedInputStamp) setPreviewState(null);
  }, [previewState, selectedInputStamp]);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', next => {
      const active = next === 'active';
      foregroundRef.current = active;
      lifecycle.current.invalidate();
      busyRef.current = false;
      setBusy(false);
      setDirectoryState(null);
      setPreviewState(null);
      setSelectedGroupId('');
      setSelectedEndpointId('');
      setGroupPage(0);
      setEndpointPage(0);
      setMessage('');
      setForeground(active);
    });
    return () => subscription.remove();
  }, []);

  const current = (token: NetworkDiscoveryRequestToken): boolean =>
    mounted.current && foregroundRef.current &&
    lifecycle.current.isCurrent(token, scopeKeyRef.current);

  const begin = (): NetworkDiscoveryRequestToken | null => {
    if (busyRef.current || !foregroundRef.current) return null;
    busyRef.current = true;
    setBusy(true);
    return lifecycle.current.capture(scopeKeyRef.current);
  };

  const finish = (token: NetworkDiscoveryRequestToken) => {
    if (current(token)) {
      busyRef.current = false;
      setBusy(false);
    }
  };

  const checkedStatus = async (
    token: NetworkDiscoveryRequestToken,
    operation: 'network.directory' | 'topology.endpoint_admission_preview',
    selectedNetworkId: string,
    expected: ClientHubStatus,
    permissionTopology: NetworkTopologySnapshot | null,
  ): Promise<ClientHubStatus> => {
    const latest = await api.getStatus();
    if (!current(token)) throw new DiscoveryError('stale');
    if (latest.profileId !== api.scope.profileId ||
        (latest.selectionGeneration !== undefined &&
          latest.selectionGeneration !== api.scope.selectionGeneration) ||
        latest.activeNetworkId !== selectedNetworkId || latest.hubId !== expected.hubId ||
        latest.ownerId !== expected.ownerId || latest.deviceId !== expected.deviceId ||
        latest.sessionEpoch !== expected.sessionEpoch) throw new DiscoveryError('stale');
    if (!ownerNetworkReadAllows(publicCapabilities, sessionCapabilities, latest,
      permissionTopology, operation)) throw new DiscoveryError('permission');
    return latest;
  };

  const readDirectory = async (afterEndpointId?: string) => {
    const selectedNetworkId = status.activeNetworkId;
    if (!selectedNetworkId || !readyForDirectory) return;
    const token = begin();
    if (!token) return;
    const expected = status;
    if (!afterEndpointId) setDirectoryState(null);
    setPreviewState(null);
    setMessage('');
    try {
      await checkedStatus(token, 'network.directory', selectedNetworkId, expected, topology);
      const body: Record<string, unknown> = {network_id: selectedNetworkId, limit: DIRECTORY_LIMIT};
      if (afterEndpointId) body.after_endpoint_id = afterEndpointId;
      const result = resultFromRpc(await api.rpc({operation: 'network.directory', body}));
      if (!current(token)) throw new DiscoveryError('stale');
      const page = networkDirectoryPageFromRpc(result, selectedNetworkId, DIRECTORY_LIMIT);
      if (!page) throw new DiscoveryError('result');
      await checkedStatus(token, 'network.directory', selectedNetworkId, expected, topology);
      const prior = afterEndpointId && directoryState?.scopeKey === token.scopeKey ?
        directoryState.view : emptyNetworkDirectoryView();
      const view = appendNetworkDirectoryPage(prior, page, afterEndpointId);
      if (current(token)) {
        setDirectoryState({scopeKey: token.scopeKey, view});
        setMessage(view.cursorLoop ?
          'Hub 重复了分页游标，已停止翻页；可重新读取第一页。' : '目录来自当前 Network 的显式发布记录，只供发现与核对。');
      }
    } catch (error) {
      if (current(token)) {
        setDirectoryState(null);
        setPreviewState(null);
        setMessage(messageFor(error));
      }
    } finally { finish(token); }
  };

  const previewEndpoint = async () => {
    const selectedNetworkId = status.activeNetworkId;
    if (!selectedNetworkId || !readyForPreview || !selectedGroup || !selectedEndpoint) return;
    const token = begin();
    if (!token) return;
    const expected = status;
    const groupId = text(selectedGroup, 'group_id');
    const endpointId = text(selectedEndpoint, 'endpoint_id');
    setPreviewState(null);
    setMessage('');
    try {
      await checkedStatus(token, 'topology.endpoint_admission_preview', selectedNetworkId,
        expected, topology);
      const freshTopology = topologySnapshotFromRpc(resultFromRpc(await api.rpc({
        operation: 'topology.snapshot', body: {},
      })), expected.ownerId);
      if (!current(token)) throw new DiscoveryError('stale');
      if (!freshTopology || !samePreviewInput(topology, freshTopology,
        selectedNetworkId, groupId, endpointId)) throw new DiscoveryError('topology');
      const currentStatus = await checkedStatus(token, 'topology.endpoint_admission_preview',
        selectedNetworkId, expected, freshTopology);
      if (!current(token)) throw new DiscoveryError('stale');
      const result = resultFromRpc(await api.rpc({operation: 'topology.endpoint_admission_preview', body: {
        network_id: selectedNetworkId, group_id: groupId, endpoint_id: endpointId,
      }}));
      if (!current(token)) throw new DiscoveryError('stale');
      const preview = endpointAdmissionPreviewFromRpc(result, freshTopology,
        selectedNetworkId, groupId, endpointId);
      if (!preview) throw new DiscoveryError('result');
      await checkedStatus(token, 'topology.endpoint_admission_preview', selectedNetworkId,
        currentStatus, freshTopology);
      if (current(token)) {
        setPreviewState({scopeKey: token.scopeKey, value: preview,
          inputStamp: previewInputStamp(freshTopology, selectedNetworkId, groupId, endpointId) || '',
          topologyCapturedAt: freshTopology.captured_at});
        setMessage('只读预览已核对当前 CAS 与上下文；未执行加入、授权或发送。');
      }
    } catch (error) {
      if (current(token)) {
        setPreviewState(null);
        setMessage(messageFor(error));
      }
    } finally { finish(token); }
  };

  const visibleGroups = groups.slice(groupPage * PAGE_SIZE, (groupPage + 1) * PAGE_SIZE);
  const visibleEndpoints = endpoints.slice(endpointPage * PAGE_SIZE, (endpointPage + 1) * PAGE_SIZE);

  return <View style={styles.card}>
    <Pressable style={styles.heading} accessibilityRole="button"
      accessibilityState={{expanded}} onPress={() => setExpanded(open => !open)}>
      <View style={styles.headingText}>
        <Text style={styles.title}>Network 发现与预览</Text>
        <Text style={styles.small}>目录与同 Owner Endpoint 预览 · 只读</Text>
      </View>
      <Text style={styles.toggle}>{expanded ? '收起' : '展开'}</Text>
    </Pressable>

    {expanded && <View>
      <Text style={styles.description}>只有点击读取时才连接 Hub。Endpoint ID 是发现引用，不表示已加入 Group、已授权密钥或可发送消息。</Text>
      <Text style={styles.small}>当前 Network：{network ? `${network.name} · ${network.network_id}` : '未选择 ACTIVE Network'}</Text>
      {topology?.captured_at && <Text style={styles.small}>选择来源：topology.snapshot · {topology.captured_at}</Text>}
      {!readyForDirectory && !readyForPreview &&
        <Text style={styles.notice}>当前公开能力、加密 session.capabilities 或本地会话状态未授权只读 Network 操作。</Text>}

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>已发布 Endpoint 目录</Text>
        <Text style={styles.small}>来源：network.directory · 每页最多 64 项 · 不包含 Owner、Node、Group、密钥或工作区资料</Text>
        <Action title={busy ? '正在读取…' : '读取目录'} disabled={busy || !foreground || !readyForDirectory}
          onPress={() => { readDirectory().catch(() => undefined); }} />
        {visibleDirectory && visibleDirectory.endpoints.length === 0 &&
          <Text style={styles.small}>当前已读取页面没有可展示的显式发布 Endpoint。</Text>}
        {visibleDirectory?.endpoints.map(endpoint => <View key={endpoint.endpoint_id} style={styles.directoryItem}>
          <Text style={styles.cardTitle}>{endpoint.alias || '未命名 Endpoint'}</Text>
          <Text selectable style={styles.small}>Endpoint reference：{endpoint.endpoint_id}</Text>
          <Text style={styles.small}>存在状态：{endpoint.presence === 'ACCESS_RECENT' ? '近期访问' : '未知'}</Text>
        </View>)}
        {visibleDirectory?.nextCursor && <Action title="读取下一页" secondary disabled={busy || !foreground || !readyForDirectory}
          onPress={() => { readDirectory(visibleDirectory.nextCursor).catch(() => undefined); }} />}
        {visibleDirectory && <Text style={styles.small}>
          已显示 {visibleDirectory.endpoints.length} 个唯一 Endpoint reference
          {visibleDirectory.nextCursor ? ' · 还有下一页' : ' · 当前没有后续页'}
        </Text>}
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>同 Owner Group / Endpoint 预览</Text>
        <Text style={styles.small}>输入只从当前拓扑选取。每次预览前重读 topology.snapshot，并由 Hub 再次核对当前范围。</Text>
        <Text style={styles.label}>ACTIVE Group</Text>
        {visibleGroups.map(group => {
          const id = text(group, 'group_id');
          const selected = id === selectedGroupId;
          return <Pressable key={id} style={[styles.option, selected && styles.selected]}
            disabled={busy} onPress={() => {
              setSelectedGroupId(id); setPreviewState(null); setMessage('');
            }} accessibilityRole="button" accessibilityState={{selected}}>
            <Text style={styles.optionText}>{text(group, 'name') || id}</Text>
            <Text style={styles.small}>{id} · version {String(group.version)}</Text>
          </Pressable>;
        })}
        {groups.length === 0 && <Text style={styles.small}>当前权威投影中没有 ACTIVE Group。</Text>}
        {groups.length > PAGE_SIZE && <Pager page={groupPage} count={groups.length} busy={busy}
          onPage={setGroupPage} />}

        <Text style={styles.label}>Network Endpoint</Text>
        {visibleEndpoints.map(endpoint => {
          const id = text(endpoint, 'endpoint_id');
          const selected = id === selectedEndpointId;
          return <Pressable key={id} style={[styles.option, selected && styles.selected]}
            disabled={busy} onPress={() => {
              setSelectedEndpointId(id); setPreviewState(null); setMessage('');
            }} accessibilityRole="button" accessibilityState={{selected}}>
            <Text style={styles.optionText}>{text(endpoint, 'name') || id}</Text>
            <Text style={styles.small}>{id}</Text>
          </Pressable>;
        })}
        {endpoints.length === 0 && <Text style={styles.small}>当前拓扑中没有属于此 Network 的可选 Endpoint。</Text>}
        {endpoints.length > PAGE_SIZE && <Pager page={endpointPage} count={endpoints.length} busy={busy}
          onPage={setEndpointPage} />}
        <Action title={busy ? '正在核对…' : '读取同 Owner Endpoint 预览'}
          disabled={busy || !foreground || !readyForPreview || !selectedGroup || !selectedEndpoint}
          onPress={() => { previewEndpoint().catch(() => undefined); }} />
        {visiblePreview && <View style={styles.evidence}>
          <Text style={styles.label}>Hub 只读预览 · {visiblePreview.value.endpoint_migration_state}</Text>
          <Text style={styles.small}>来源：topology.endpoint_admission_preview · topology.snapshot · {visiblePreview.topologyCapturedAt}</Text>
          <Text selectable style={styles.details}>{previewLines(visiblePreview.value).join('\n')}</Text>
          <Text style={styles.notice}>此结果只用于审阅 CAS 与上下文；本页没有 Join、Admission、Grant、密钥或发送操作。</Text>
        </View>}
      </View>

      {!!message && <Text accessibilityLiveRegion="polite" style={styles.description}>{message}</Text>}
    </View>}
  </View>;
}

function Action({title, disabled, onPress, secondary = false}: {
  title: string; disabled: boolean; onPress: () => void; secondary?: boolean;
}): React.JSX.Element {
  return <Pressable accessibilityRole="button" accessibilityState={{disabled}} disabled={disabled}
    onPress={onPress} style={[styles.button, secondary && styles.secondary, disabled && styles.disabled]}>
    <Text style={[styles.buttonText, secondary && styles.secondaryText]}>{title}</Text>
  </Pressable>;
}

function Pager({page, count, busy, onPage}: {
  page: number; count: number; busy: boolean; onPage: (next: number) => void;
}): React.JSX.Element {
  const pages = Math.ceil(count / PAGE_SIZE);
  return <View style={styles.pager}>
    <Action title="上一页" secondary disabled={busy || page <= 0} onPress={() => onPage(page - 1)} />
    <Text style={styles.small}>{page + 1} / {pages}</Text>
    <Action title="下一页" secondary disabled={busy || page + 1 >= pages} onPress={() => onPage(page + 1)} />
  </View>;
}

const styles = StyleSheet.create({
  card: {borderRadius: 20, borderWidth: 1, borderColor: '#E1E7E3', backgroundColor: '#FFFFFF', padding: 18, marginBottom: 10},
  heading: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12},
  headingText: {flex: 1},
  title: {fontSize: 17, fontWeight: '700', color: '#1A2D2B'},
  toggle: {fontSize: 13, fontWeight: '600', color: '#186A63', paddingVertical: 8},
  section: {borderTopWidth: 1, borderTopColor: '#E1E7E3', marginTop: 16, paddingTop: 14},
  sectionTitle: {fontSize: 14, fontWeight: '700', color: '#1A2D2B'},
  label: {fontSize: 13, fontWeight: '600', color: '#1A2D2B', marginTop: 12},
  description: {fontSize: 13, lineHeight: 19, color: '#697974', marginTop: 8},
  small: {fontSize: 12, lineHeight: 18, color: '#697974', marginTop: 6},
  notice: {fontSize: 12, lineHeight: 18, color: '#AE7025', backgroundColor: '#FFF5E3', padding: 10, borderRadius: 12, marginTop: 10},
  button: {paddingVertical: 11, paddingHorizontal: 14, backgroundColor: '#186A63', borderRadius: 12, marginTop: 10},
  buttonText: {color: '#FFFFFF', fontSize: 13, fontWeight: '600', textAlign: 'center'},
  secondary: {backgroundColor: '#F7F8F6'},
  secondaryText: {color: '#186A63'},
  disabled: {opacity: 0.4},
  directoryItem: {padding: 10, borderRadius: 12, borderWidth: 1, borderColor: '#E1E7E3', marginTop: 8},
  cardTitle: {fontSize: 13, fontWeight: '600', color: '#1A2D2B'},
  option: {padding: 10, borderRadius: 12, borderWidth: 1, borderColor: '#E1E7E3', marginTop: 8},
  selected: {backgroundColor: '#E8F3EF', borderColor: '#186A63'},
  optionText: {fontSize: 13, fontWeight: '600', color: '#1A2D2B'},
  pager: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 8},
  evidence: {marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: '#E1E7E3'},
  details: {fontSize: 12, lineHeight: 19, color: '#697974', marginTop: 8},
});
