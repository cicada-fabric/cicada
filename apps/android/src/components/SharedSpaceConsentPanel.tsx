import React, {useEffect, useMemo, useRef, useState} from 'react';
import {Pressable, StyleSheet, Text, View} from 'react-native';
import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
} from '../platform/clientHub';
import type {NetworkTopologySnapshot} from '../platform/networkTopology';
import {
  captureSharedSpaceCallback, createSharedSpaceReviewDraft, deriveSharedSpaceScope,
  markSharedSpaceReviewIntent, sharedSpaceAuthority, sharedSpaceCallbackIsCurrent,
  sharedSpaceDraftIsCurrent, sharedSpaceEndpoints, sharedSpaceGroups,
  SHARED_SPACE_CLOSED_OPERATIONS,
} from '../platform/sharedSpaceConsent';
import type {
  SharedSpaceAuthority, SharedSpaceReviewDraft, SharedSpaceScope,
} from '../platform/sharedSpaceConsent';

interface Props {
  status: ClientHubStatus;
  topology: NetworkTopologySnapshot | null;
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
}

const MAX_VISIBLE_CHOICES = 24;
const textField = (record: Record<string, unknown>, key: string) =>
  typeof record[key] === 'string' ? record[key] as string : '';
const valueField = (record: Record<string, unknown>, key: string) =>
  typeof record[key] === 'string' || typeof record[key] === 'number' ? String(record[key]) : '';
const ownerIdOf = (record: Record<string, unknown>) => {
  const value = textField(record, 'owner_id');
  return value && value === value.trim() ? value : '';
};

function contextKey(authority: SharedSpaceAuthority): string {
  return authority.ready ? JSON.stringify([
    authority.profileId, authority.selectionGeneration, authority.hubId,
    authority.ownerId, authority.deviceId, authority.sessionEpoch,
    authority.network.network_id, authority.network.version,
  ]) : '';
}

function activeGroupId(authority: SharedSpaceAuthority, groupId: string): string {
  return authority.ready && sharedSpaceGroups(authority).some(group => group.group_id === groupId) ?
    groupId : '';
}

function currentScopeFor(authority: SharedSpaceAuthority, groupId: string,
  endpointId: string): SharedSpaceScope | null {
  if (!groupId || !endpointId) return null;
  const derived = deriveSharedSpaceScope(authority, groupId, endpointId);
  return derived.scope || null;
}

export function SharedSpaceConsentPanel({status, topology, publicCapabilities,
  sessionCapabilities}: Props): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [selection, setSelection] = useState({key: '', groupId: '', endpointId: ''});
  const [reviewDraft, setReviewDraft] = useState<SharedSpaceReviewDraft | null>(null);
  const authority = useMemo(() => sharedSpaceAuthority({
    status, capabilities: publicCapabilities, sessionCapabilities, topology,
  }), [status, publicCapabilities, sessionCapabilities, topology]);
  const authorityKey = contextKey(authority);
  const selectionMatches = Boolean(authorityKey && selection.key === authorityKey);
  const selectedGroupId = selectionMatches ? activeGroupId(authority, selection.groupId) : '';
  const selectedEndpointId = selectedGroupId && selectionMatches ? selection.endpointId : '';
  const scope = useMemo(() => currentScopeFor(authority, selectedGroupId, selectedEndpointId),
    [authority, selectedGroupId, selectedEndpointId]);
  const scopeRef = useRef<SharedSpaceScope | null>(scope);
  scopeRef.current = scope;
  const currentDraft = sharedSpaceDraftIsCurrent(reviewDraft, scope) ? reviewDraft : null;
  const groups = authority.ready ? sharedSpaceGroups(authority) : [];
  const endpoints = authority.ready ? sharedSpaceEndpoints(authority) : [];
  const displayedGroups = groups.slice(0, MAX_VISIBLE_CHOICES);
  const displayedEndpoints = endpoints.slice(0, MAX_VISIBLE_CHOICES);

  useEffect(() => {
    if (reviewDraft && !sharedSpaceDraftIsCurrent(reviewDraft, scope)) setReviewDraft(null);
  }, [reviewDraft, scope]);

  const chooseGroup = (groupId: string) => {
    setSelection({key: authorityKey, groupId, endpointId: ''});
    setReviewDraft(null);
  };

  const chooseEndpoint = (endpointId: string) => {
    setSelection({key: authorityKey, groupId: selectedGroupId, endpointId});
    setReviewDraft(null);
  };

  const markReviewed = () => {
    if (!scope) return;
    const callback = captureSharedSpaceCallback(scope);
    const currentScope = scopeRef.current;
    if (!sharedSpaceCallbackIsCurrent(callback, currentScope)) return;
    const draft = createSharedSpaceReviewDraft(scope);
    const reviewed = markSharedSpaceReviewIntent(draft, currentScope);
    if (reviewed) setReviewDraft(reviewed);
  };

  const headline = authority.ready ? '本机范围预览 · 操作仍关闭' : '暂不可用';
  return <View style={styles.card}>
    <Pressable accessibilityRole="button" accessibilityState={{expanded}}
      accessibilityLabel={`共享空间与委托，${headline}`}
      style={styles.header} onPress={() => setExpanded(open => !open)}>
      <View style={styles.headingText}>
        <Text style={styles.title}>共享空间与委托</Text>
        <Text style={styles.summary}>{headline}</Text>
      </View>
      <Text style={styles.expand}>{expanded ? '收起' : '查看'}</Text>
    </Pressable>

    {expanded && <View style={styles.body}>
      {!authority.ready ? <Text style={styles.notice}>{authority.reason}</Text> : <>
        <Text style={styles.description}>当前配置 {authority.profileId} · 选择代次 {authority.selectionGeneration}</Text>
        <Text selectable style={styles.small}>Hub：{authority.hubId}{'\n'}Group Owner：{authority.ownerId}{'\n'}Device：{authority.deviceId} · session epoch {authority.sessionEpoch}{'\n'}ACTIVE Network：{authority.network.name} · {authority.network.network_id} · v{authority.network.version}{'\n'}拓扑来源：加密 topology.snapshot · {authority.topology.captured_at}</Text>
        {(authority.topology.networks_truncated || authority.topology.network_endpoints_truncated) &&
          <Text style={styles.notice}>Hub 返回的是有界拓扑投影，当前列表可能不完整；未显示的记录不代表不存在。</Text>}

        <Text style={styles.sectionTitle}>1 · 选择当前 Network 的 ACTIVE Group</Text>
        {displayedGroups.map(group => {
          const id = textField(group, 'group_id');
          const selected = id === selectedGroupId;
          return <Pressable key={id} accessibilityRole="button"
            accessibilityState={{selected}}
            style={[styles.choice, selected && styles.choiceSelected]}
            onPress={() => chooseGroup(id)}>
            <Text style={styles.choiceTitle}>{textField(group, 'name') || id}</Text>
            <Text style={styles.small}>{id} · Group v{valueField(group, 'version')}</Text>
          </Pressable>;
        })}
        {groups.length === 0 && <Text style={styles.small}>当前权威拓扑没有可展示的 ACTIVE Group。</Text>}
        {groups.length > displayedGroups.length &&
          <Text style={styles.small}>列表已限制为前 {displayedGroups.length} 个 Group；完整记录请在 Hub 权威面板核对。</Text>}

        {selectedGroupId && <>
          <Text style={styles.sectionTitle}>2 · 选择 Network 已登记 Endpoint</Text>
          {displayedEndpoints.map(endpoint => {
            const id = textField(endpoint, 'endpoint_id');
            const endpointOwner = ownerIdOf(endpoint);
            const isForeign = Boolean(endpointOwner && endpointOwner !== authority.ownerId);
            const selected = id === selectedEndpointId && isForeign;
            return <Pressable key={id} accessibilityRole="button"
              accessibilityState={{disabled: !isForeign, selected}}
              disabled={!isForeign} style={[styles.choice, selected && styles.choiceSelected,
                !isForeign && styles.choiceUnavailable]}
              onPress={() => chooseEndpoint(id)}>
              <Text style={styles.choiceTitle}>{textField(endpoint, 'name') || id}</Text>
              <Text selectable style={styles.small}>Endpoint：{id}</Text>
              <Text selectable style={styles.small}>Endpoint Owner：{endpointOwner || '拓扑未提供 owner_id'}</Text>
              {!isForeign && <Text style={styles.small}>{endpointOwner ? '属于当前 Owner，不是跨 Owner 候选。' : 'Owner 范围未知，不可作为候选。'}</Text>}
            </Pressable>;
          })}
          {endpoints.length === 0 && <Text style={styles.small}>当前 Network 投影没有 Endpoint。</Text>}
          {endpoints.length > displayedEndpoints.length &&
            <Text style={styles.small}>Endpoint 列表已限制为前 {displayedEndpoints.length} 项；请在 Hub 权威面板核对完整名单。</Text>}
        </>}

        {scope && <View style={styles.scopeCard}>
          <Text style={styles.sectionTitle}>精确范围 · 仅本机草稿</Text>
          <Text selectable style={styles.scopeText}>Hub：{scope.hubId}{'\n'}Group Owner：{scope.ownerId}{'\n'}Device：{scope.deviceId} · session epoch {scope.sessionEpoch}{'\n'}Network：{scope.networkId} · v{scope.networkVersion}{'\n'}Group：{scope.groupId} · v{scope.groupVersion}{'\n'}Endpoint：{scope.endpointId}{'\n'}Endpoint Owner：{scope.endpointOwnerId}{scope.endpointBindingId ?
            `\nBinding：${scope.endpointBindingId}${scope.endpointBindingEpoch ? ` · epoch ${scope.endpointBindingEpoch}` : ''}` : ''}</Text>
          <Text style={styles.notice}>此标记只表示你读过上述精确范围；它不是签名、审批、授权或可执行操作。</Text>
          <Pressable accessibilityRole="button" accessibilityState={{disabled: !scope}}
            style={styles.reviewButton} onPress={markReviewed}>
            <Text style={styles.reviewButtonText}>{currentDraft?.reviewed ? '已标记阅读 · 本机草稿' : '我已核对此范围 · 仅标记阅读'}</Text>
          </Pressable>
        </View>}
        {selectedGroupId && selectedEndpointId && !scope && <Text style={styles.notice}>
          {deriveSharedSpaceScope(authority, selectedGroupId, selectedEndpointId).reason}
        </Text>}

        <Text style={styles.sectionTitle}>后续独立阶段 · 当前未开放</Text>
        <Text style={styles.stage}>1. Group Owner admission 仅建立受限 Membership；它不等于 Endpoint 的 native Join。</Text>
        <Text style={styles.stage}>2. Endpoint Owner 单独同意加入该 Group，并明确确认共享上下文风险；此操作本身不执行 Join。</Text>
        <Text style={styles.stage}>3. Node 之后执行新的可信 Join 并发布候选；再由 Hub 返回当前 manifest。</Text>
        <Text style={styles.stage}>4. Endpoint Owner 独立签 SOURCE；Group Owner 独立签 TARGET。各自的 App 必须核对本方 Owner 证明并由本人明确确认，两方互不代签。</Text>
        <Text style={styles.stage}>5. 两份证明必须绑定同一当前 manifest，Hub 才能报告 current；本构建没有原生验签、手机确认或提交流程。</Text>
        <Text style={styles.small}>v1.5 语义：admission 不会加入 Node，也不授予历史；key manifest 标记不含历史。本 App 不提供 Shared Space 消息入口。</Text>

        <Text style={styles.sectionTitle}>委托与重组提案</Text>
        <Text style={styles.small}>Advisor proposal 只是提案，不是 User Approval。未来委托须绑定精确 proposal、Group 版本、到期时间与一次性 max_uses=1，并按版本 CAS 撤销；当前读取、签发、撤销均关闭。</Text>
        <Text style={styles.small}>尚未完成独立证明与授权核验的 {SHARED_SPACE_CLOSED_OPERATIONS.length} 项操作保持关闭。拓扑委托使用单独的手机确认流程。</Text>
      </>}
    </View>}
  </View>;
}

const styles = StyleSheet.create({
  card: {borderRadius: 20, borderWidth: 1, borderColor: '#E1E7E3', backgroundColor: '#FFFFFF', padding: 16, marginBottom: 10},
  header: {minHeight: 46, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'},
  headingText: {flex: 1, paddingRight: 12},
  title: {fontSize: 16, fontWeight: '700', color: '#1A2D2B'},
  summary: {fontSize: 12, color: '#697974', marginTop: 3},
  expand: {fontSize: 13, fontWeight: '600', color: '#186A63', paddingVertical: 10, paddingHorizontal: 4},
  body: {paddingTop: 12},
  description: {fontSize: 13, lineHeight: 19, color: '#697974', marginBottom: 6},
  small: {fontSize: 12, lineHeight: 18, color: '#697974', marginTop: 4},
  notice: {fontSize: 12, lineHeight: 18, color: '#805D25', backgroundColor: '#FFF5E3', borderRadius: 10, padding: 10, marginTop: 8},
  sectionTitle: {fontSize: 13, fontWeight: '700', color: '#1A2D2B', marginTop: 14, marginBottom: 6},
  choice: {borderWidth: 1, borderColor: '#E1E7E3', borderRadius: 12, padding: 12, marginTop: 7},
  choiceSelected: {borderColor: '#186A63', backgroundColor: '#E8F3EF'},
  choiceUnavailable: {backgroundColor: '#F7F8F6'},
  choiceTitle: {fontSize: 13, fontWeight: '600', color: '#1A2D2B'},
  scopeCard: {borderRadius: 14, backgroundColor: '#F7F8F6', padding: 12, marginTop: 12},
  scopeText: {fontSize: 12, lineHeight: 19, color: '#1A2D2B'},
  reviewButton: {alignSelf: 'flex-start', marginTop: 10, borderRadius: 10, borderWidth: 1, borderColor: '#186A63', paddingVertical: 10, paddingHorizontal: 12},
  reviewButtonText: {fontSize: 12, fontWeight: '600', color: '#186A63'},
  stage: {fontSize: 12, lineHeight: 18, color: '#697974', marginTop: 6},
});
