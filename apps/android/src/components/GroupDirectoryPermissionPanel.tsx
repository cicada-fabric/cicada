import React, {useEffect, useMemo, useRef, useState} from 'react';
import {AppState, Pressable, Text, View} from 'react-native';
import type {
  ClientHubApi, ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
} from '../platform/clientHub';
import type {NetworkTopologyRecord, NetworkTopologySnapshot} from '../platform/networkTopology';
import {
  GROUP_DIRECTORY_PERMISSION_READY, GroupDirectoryPermissionLifecycle,
  createGroupDirectoryPermissionReview, groupDirectoryPermissionAuthority,
  groupDirectoryPermissionSnapshotFromRpc, parseGroupDirectoryPermissionSnapshot,
  validateGroupDirectoryPermissionResult,
} from '../platform/groupDirectoryPermission';
import type {
  GroupDirectoryPermissionAuthority, GroupDirectoryPermissionCapture,
  GroupDirectoryPermissionReview, GroupDirectoryPermissionTarget,
} from '../platform/groupDirectoryPermission';

interface Props {
  api: ClientHubApi;
  status: ClientHubStatus;
  topology: NetworkTopologySnapshot | null;
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  onRefresh?: () => Promise<NetworkTopologySnapshot | undefined>;
}

interface ReviewState {
  readonly review: GroupDirectoryPermissionReview;
  readonly capture: GroupDirectoryPermissionCapture;
}

interface Latest {
  readonly api: ClientHubApi;
  readonly status: ClientHubStatus;
  readonly topology: NetworkTopologySnapshot | null;
  readonly publicCapabilities: ClientHubCapabilities | null;
  readonly sessionCapabilities: ClientHubSessionCapabilities | null;
  readonly authority: GroupDirectoryPermissionAuthority;
  readonly authorityKey: string;
  readonly foreground: boolean;
  readonly onRefresh?: () => Promise<NetworkTopologySnapshot | undefined>;
}

const record = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value === value.trim() && value.length <= 256;
const display = (value: unknown, fallback: string) =>
  typeof value === 'string' && value.length > 0 ? value : fallback;

/** The wrapper keeps the v1.6.1 build inert before mounting any effects or hooks. */
export function GroupDirectoryPermissionPanel(props: Props): React.JSX.Element | null {
  if (!GROUP_DIRECTORY_PERMISSION_READY) return null;
  return <ReadyGroupDirectoryPermissionPanel {...props} />;
}

function ReadyGroupDirectoryPermissionPanel({api, status, topology, publicCapabilities,
  sessionCapabilities, onRefresh}: Props): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [foreground, setForeground] = useState(AppState.currentState === 'active');
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [selectedMembershipId, setSelectedMembershipId] = useState('');
  const [groupLimit, setGroupLimit] = useState(20);
  const [membershipLimit, setMembershipLimit] = useState(20);
  const [reviewState, setReviewState] = useState<ReviewState | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const busyRef = useRef(false);
  const mountedRef = useRef(true);
  const requestRef = useRef(0);
  const lifecycleRef = useRef(new GroupDirectoryPermissionLifecycle());
  const authority = useMemo(() => groupDirectoryPermissionAuthority({
    status, publicCapabilities, sessionCapabilities, topology, apiScope: api.scope,
    bridgeReady: GROUP_DIRECTORY_PERMISSION_READY && typeof api.rpc === 'function',
  }), [api.scope, status, publicCapabilities, sessionCapabilities, topology, api.rpc]);
  const authorityKey = authority.ready ? authority.scope.scopeKey : `unavailable:${authority.reason}`;
  const latestRef = useRef<Latest>({api, status, topology, publicCapabilities,
    sessionCapabilities, authority, authorityKey, foreground, onRefresh});
  latestRef.current = {api, status, topology, publicCapabilities, sessionCapabilities,
    authority, authorityKey, foreground, onRefresh};

  useEffect(() => {
    requestRef.current += 1;
    lifecycleRef.current.invalidate();
    setReviewState(null);
    setMessage('');
    busyRef.current = false;
    setBusy(false);
  }, [authorityKey, selectedGroupId, selectedMembershipId]);

  useEffect(() => {
    setGroupLimit(20);
    setMembershipLimit(20);
  }, [authorityKey, selectedGroupId]);

  useEffect(() => {
    const lifecycle = lifecycleRef.current;
    mountedRef.current = true;
    const subscription = AppState.addEventListener('change', state => {
      const active = state === 'active';
      setForeground(active);
      if (!active) {
        requestRef.current += 1;
        lifecycle.invalidate();
        busyRef.current = false;
        setBusy(false);
        setReviewState(null);
        setMessage('');
        setExpanded(false);
      }
    });
    return () => {
      mountedRef.current = false;
      requestRef.current += 1;
      lifecycle.invalidate();
      subscription.remove();
    };
  }, []);

  const scopeIsCurrent = (token: number, scopeKey: string) => {
    const current = latestRef.current;
    return mountedRef.current && requestRef.current === token && current.foreground &&
      current.authority.ready && current.authority.scope.scopeKey === scopeKey;
  };

  const freshAuthority = async (captured: Latest, token: number) => {
    if (!captured.authority.ready || !captured.foreground) throw new Error('authority_unavailable');
    const statusBefore = await captured.api.getStatus();
    const raw = await captured.api.rpc({operation: 'topology.snapshot', body: {}});
    const statusAfter = await captured.api.getStatus();
    const current = latestRef.current;
    if (!scopeIsCurrent(token, captured.authority.scope.scopeKey) ||
        !sameSession(statusBefore, statusAfter)) throw new Error('scope_changed');
    const snapshot = groupDirectoryPermissionSnapshotFromRpc(raw, captured.authority.scope.ownerId);
    if (!snapshot) throw new Error('invalid_snapshot_response');
    const nextAuthority = groupDirectoryPermissionAuthority({
      status: statusAfter,
      publicCapabilities: current.publicCapabilities,
      sessionCapabilities: current.sessionCapabilities,
      topology: snapshot,
      apiScope: current.api.scope,
      bridgeReady: GROUP_DIRECTORY_PERMISSION_READY && typeof current.api.rpc === 'function',
    });
    if (!nextAuthority.ready || nextAuthority.scope.scopeKey !== captured.authority.scope.scopeKey) {
      throw new Error(nextAuthority.ready ? 'scope_changed' : nextAuthority.reason);
    }
    return {snapshot, status: statusAfter, authority: nextAuthority};
  };

  const begin = () => {
    const current = latestRef.current;
    if (!current.authority.ready || !current.foreground || busyRef.current) return null;
    busyRef.current = true;
    setBusy(true);
    const token = ++requestRef.current;
    return {token, captured: current, scopeKey: current.authority.scope.scopeKey};
  };

  const finish = (token: number) => {
    if (mountedRef.current && requestRef.current === token) {
      busyRef.current = false;
      setBusy(false);
    }
  };

  const selectedTarget: GroupDirectoryPermissionTarget | null = authority.ready && topology &&
    selectedGroupId && selectedMembershipId ? parseGroupDirectoryPermissionSnapshot(
      topology, authority, selectedGroupId, selectedMembershipId) : null;
  const groupChoices = authority.ready && topology ? uniqueGroups(topology, authority.scope.networkId) : [];
  const membershipChoices = selectedGroupId && topology ? uniqueMemberships(topology, selectedGroupId) : [];
  const currentReview = authority.ready && selectedTarget &&
    reviewState?.review.scopeKey === authority.scope.scopeKey &&
    reviewState.review.targetKey === selectedTarget.targetKey ? reviewState : null;

  const refreshParent = async (current: Latest) => {
    if (current.onRefresh) return await current.onRefresh();
    return undefined;
  };

  const createPreview = async () => {
    if (!selectedTarget) return;
    const run = begin();
    if (!run) return;
    setReviewState(null);
    setMessage('正在重新读取加密拓扑快照并核对 Membership 版本…');
    try {
      const fresh = await freshAuthority(run.captured, run.token);
      const target = parseGroupDirectoryPermissionSnapshot(fresh.snapshot, fresh.authority,
        selectedTarget.groupId, selectedTarget.membershipId);
      if (!target || target.targetKey !== selectedTarget.targetKey || !scopeIsCurrent(run.token, run.scopeKey)) {
        throw new Error('target_changed');
      }
      const review = createGroupDirectoryPermissionReview(fresh.authority, target,
        !target.currentEnabled);
      const capture = review && lifecycleRef.current.capture(review);
      if (!review || !capture) throw new Error('review_unavailable');
      setReviewState({review, capture});
      setMessage('预览已绑定新鲜快照与当前 Membership 版本。请核对范围后再明确确认。');
    } catch {
      if (scopeIsCurrent(run.token, run.scopeKey)) {
        setReviewState(null);
        setMessage('无法建立有效预览。拓扑、权限或会话状态可能已变化；请刷新后重新选择。');
      }
      if (mountedRef.current) await refreshParent(latestRef.current).catch(() => undefined);
    } finally {
      finish(run.token);
    }
  };

  const confirmReview = async () => {
    const selected = currentReview;
    if (!selected) return;
    const run = begin();
    if (!run) return;
    if (!scopeIsCurrent(run.token, selected.review.scopeKey)) {
      finish(run.token);
      return;
    }
    setMessage('正在再次读取加密拓扑快照并验证预览仍然有效…');
    let accepted = false;
    try {
      const fresh = await freshAuthority(run.captured, run.token);
      if (!scopeIsCurrent(run.token, run.scopeKey) || reviewState?.review.reviewId !== selected.review.reviewId) {
        throw new Error('review_stale');
      }
      const attempt = lifecycleRef.current.confirm(selected.review, selected.capture,
        fresh.authority, fresh.snapshot, selected.review.reviewId, latestRef.current.foreground);
      if (!attempt) throw new Error('review_stale');
      setReviewState(null);
      setMessage('已确认此 Membership 版本 CAS；正在提交加密 topology.apply…');
      const response = await run.captured.api.rpc({
        operation: 'topology.apply',
        body: attempt.action as unknown as Record<string, unknown>,
      });
      if (!scopeIsCurrent(run.token, run.scopeKey)) return;
      if (!validateGroupDirectoryPermissionResult(attempt, response)) {
        throw new Error('result_unverified');
      }
      accepted = true;
      setMessage('Hub 已返回匹配的 CAS 结果；正在重读权威 Membership 状态…');
      let refreshed: NetworkTopologySnapshot | undefined;
      if (latestRef.current.onRefresh) refreshed = await refreshParent(latestRef.current);
      if (!scopeIsCurrent(run.token, run.scopeKey)) return;
      if (!refreshed) {
        const followup = await freshAuthority(run.captured, run.token);
        refreshed = followup.snapshot;
      }
      const afterStatus = await run.captured.api.getStatus();
      const afterAuthority = groupDirectoryPermissionAuthority({
        status: afterStatus,
        publicCapabilities: latestRef.current.publicCapabilities,
        sessionCapabilities: latestRef.current.sessionCapabilities,
        topology: refreshed,
        apiScope: latestRef.current.api.scope,
        bridgeReady: GROUP_DIRECTORY_PERMISSION_READY && typeof latestRef.current.api.rpc === 'function',
      });
      const afterTarget = afterAuthority.ready ? parseGroupDirectoryPermissionSnapshot(
        refreshed, afterAuthority, attempt.groupId, attempt.membershipId) : null;
      if (!scopeIsCurrent(run.token, run.scopeKey) || !afterAuthority.ready || !afterTarget ||
          afterTarget.currentEnabled !== attempt.enabled ||
          afterTarget.membershipVersion !== attempt.expectedMembershipVersion + 1) {
        throw new Error('followup_unverified');
      }
      setMessage(`已由新鲜 Hub 快照核实：${attempt.enabled ? 'directory.read 已启用' : 'directory.read 已撤销'}，Membership v${afterTarget.membershipVersion}。`);
    } catch {
      if (scopeIsCurrent(run.token, run.scopeKey)) {
        setReviewState(null);
        setMessage(accepted ?
          'Hub 返回的 CAS 结果有效，但后续权威刷新未能核实最终状态。没有重试写入；请刷新状态后再检查。' :
          '操作未得到可核实的完成结果。没有重试写入；请读取当前权威状态并处理任何待恢复或不确定请求。');
      }
      if (mountedRef.current) await refreshParent(latestRef.current).catch(() => undefined);
    } finally {
      finish(run.token);
    }
  };

  const headline = authority.ready ? `Owner ${authority.scope.ownerId} · ${authority.scope.role}` :
    '需要已验证的加密 Owner 会话';
  return <View style={styles.container}>
    <Pressable accessibilityRole="button" accessibilityState={{expanded}}
      style={styles.header} onPress={() => {
        if (expanded) {
          setExpanded(false);
          setReviewState(null);
          setMessage('');
          requestRef.current += 1;
          lifecycleRef.current.invalidate();
        } else setExpanded(true);
      }}>
      <View style={styles.heading}>
        <Text style={styles.title}>Group 目录读取权限</Text>
        <Text style={styles.summary}>{headline}</Text>
      </View>
      <Text style={styles.expand}>{expanded ? '收起' : '管理'}</Text>
    </Pressable>
    {expanded && <View style={styles.body}>
      <Text style={styles.description}>只由当前 Owner 管理一个 Group 中一个 Principal 的 Membership。权限适用于该 Principal 当前加入此 Group 的全部 Endpoint。directory.read 仅用于发现；Join 或 Advisor 角色本身不授予目录读取。撤销不能收回对方已收到的信息。</Text>
      {!authority.ready && <Text style={styles.notice}>{authority.reason}</Text>}
      {authority.ready && <>
        <Text style={styles.scope}>Hub：{authority.scope.hubId} · Owner：{authority.scope.ownerId}{'\n'}ACTIVE Network：{authority.scope.networkId} · v{authority.scope.networkVersion}</Text>
        <Text style={styles.label}>选择 Group</Text>
        {groupChoices.length === 0 ? <Text style={styles.note}>当前快照没有可选择的 ACTIVE Group。</Text> :
          groupChoices.slice(0, groupLimit).map(group => {
            const id = String(group.group_id);
            const selected = selectedGroupId === id;
            return <Pressable key={id} accessibilityRole="button"
              accessibilityState={{selected}} style={[styles.choice, selected && styles.choiceSelected]}
              disabled={busy} onPress={() => {
                requestRef.current += 1;
                lifecycleRef.current.invalidate();
                setSelectedGroupId(id);
                setSelectedMembershipId('');
                setReviewState(null);
                setMessage('');
              }}>
              <Text style={styles.choiceTitle}>{display(group.name, '未命名 Group')}</Text>
              <Text style={styles.note}>{id}</Text>
            </Pressable>;
          })}
        {groupChoices.length > groupLimit && <Pressable accessibilityRole="button"
          style={styles.pageButton} disabled={busy}
          onPress={() => setGroupLimit(value => value + 20)}>
          <Text style={styles.pageButtonText}>再显示 20 个 Group（{groupChoices.length - groupLimit} 个剩余）</Text>
        </Pressable>}
        {!!selectedGroupId && <>
          <Text style={styles.label}>选择 Membership</Text>
          {membershipChoices.length === 0 ? <Text style={styles.note}>此 Group 没有可选择的活跃 Membership。</Text> :
            membershipChoices.slice(0, membershipLimit).map(member => {
              const id = String(member.membership_id);
              const selected = selectedMembershipId === id;
              return <Pressable key={id} accessibilityRole="button"
                accessibilityState={{selected}} style={[styles.choice, selected && styles.choiceSelected]}
                disabled={busy} onPress={() => {
                  requestRef.current += 1;
                  lifecycleRef.current.invalidate();
                  setSelectedMembershipId(id);
                  setReviewState(null);
                  setMessage('');
                }}>
                <Text style={styles.choiceTitle}>{display(member.display_name, String(member.principal_id || 'Principal'))}</Text>
                <Text style={styles.note}>{String(member.principal_id || '')} · {String(member.role || '角色未知')}</Text>
              </Pressable>;
            })}
          {membershipChoices.length > membershipLimit && <Pressable accessibilityRole="button"
            style={styles.pageButton} disabled={busy}
            onPress={() => setMembershipLimit(value => value + 20)}>
            <Text style={styles.pageButtonText}>再显示 20 个 Membership（{membershipChoices.length - membershipLimit} 个剩余）</Text>
          </Pressable>}
        </>}
        {selectedTarget && <View style={styles.target}>
          <Text style={styles.targetTitle}>{selectedTarget.groupName} · {selectedTarget.currentEnabled ? '已启用' : '未启用'}</Text>
          <Text style={styles.note}>Principal：{selectedTarget.principalId} · Membership：{selectedTarget.membershipId} · v{selectedTarget.membershipVersion}</Text>
          <EndpointScope ids={selectedTarget.subjectEndpointIds} />
          <Pressable accessibilityRole="button" disabled={busy || !foreground}
            style={[styles.button, (busy || !foreground) && styles.disabled]} onPress={createPreview}>
            <Text style={styles.buttonText}>{busy ? '处理中…' : `预览${selectedTarget.currentEnabled ? '撤销' : '启用'} directory.read`}</Text>
          </Pressable>
        </View>}
        {currentReview && <View style={styles.review}>
          <Text style={styles.targetTitle}>确认此次变更</Text>
          <Text style={styles.note}>Group：{currentReview.review.target.groupName} · {currentReview.review.target.groupId} · v{currentReview.review.target.groupVersion}</Text>
          <Text style={styles.note}>Principal：{currentReview.review.target.principalId} · Membership：{currentReview.review.target.membershipId}</Text>
          <Text style={styles.note}>预期 Membership 版本：{currentReview.review.action.set_directory_permission.expected_membership_version}</Text>
          <EndpointScope ids={currentReview.review.target.subjectEndpointIds} />
          <View style={styles.actions}>
            <Pressable accessibilityRole="button" disabled={busy || !foreground}
              style={[styles.button, styles.destructive, (busy || !foreground) && styles.disabled]}
              onPress={confirmReview}>
              <Text style={styles.buttonText}>明确确认并提交 CAS</Text>
            </Pressable>
            <Pressable accessibilityRole="button" disabled={busy}
              style={styles.cancel} onPress={() => {
                requestRef.current += 1;
                lifecycleRef.current.invalidate();
                setReviewState(null);
                setMessage('预览已取消。');
              }}>
              <Text style={styles.cancelText}>取消预览</Text>
            </Pressable>
          </View>
        </View>}
      </>}
      {!!message && <Text accessibilityLiveRegion="polite" style={styles.note}>{message}</Text>}
    </View>}
  </View>;
}

function EndpointScope({ids}: {ids: readonly string[]}): React.JSX.Element {
  const visible = ids.slice(0, 12);
  const remaining = ids.length - visible.length;
  return <View style={styles.endpointScope}>
    <Text style={styles.note}>当前 joined Endpoint 共 {ids.length} 个：{visible.join('、') || '无'}{remaining > 0 ? `，另有 ${remaining} 个` : ''}</Text>
    <Text style={styles.note}>权限仍覆盖此 Principal 在该 Group 中的全部 {ids.length} 个当前 Endpoint。</Text>
  </View>;
}

function sameSession(left: ClientHubStatus, right: ClientHubStatus): boolean {
  const scope = (value: ClientHubStatus) => JSON.stringify([
    value.profileId, value.selectionGeneration, value.hubId, value.ownerId, value.deviceId,
    value.sessionEpoch, value.role, value.activeNetworkId, value.pinned, value.enrolled,
    value.remoteEnabled, value.sessionCapabilitiesReady, value.authFenced, value.recoveryBlocked,
    value.enrollmentRecoveryRequired, value.pendingOperationId, value.outcomeUncertainOperationId,
    value.uncertainNeedsReconciliation, value.networkGrantReconciliationRequired,
    value.regroupReconciliationRequired, value.allowedOperations,
  ]);
  return scope(left) === scope(right);
}

function uniqueGroups(snapshot: NetworkTopologySnapshot, networkId: string): NetworkTopologyRecord[] {
  if (!Array.isArray(snapshot.groups)) return [];
  const candidates = snapshot.groups.filter(record).filter(group =>
    group.network_id === networkId && group.state === 'ACTIVE' && identifier(group.group_id));
  const counts = new Map<string, number>();
  for (const group of candidates) counts.set(String(group.group_id), (counts.get(String(group.group_id)) || 0) + 1);
  return candidates.filter(group => counts.get(String(group.group_id)) === 1);
}

function uniqueMemberships(snapshot: NetworkTopologySnapshot, groupId: string): NetworkTopologyRecord[] {
  if (!Array.isArray(snapshot.memberships)) return [];
  const candidates = snapshot.memberships.filter(record).filter(member =>
    member.group_id === groupId && member.status === 'active' && identifier(member.membership_id) &&
    identifier(member.principal_id));
  const counts = new Map<string, number>();
  for (const member of candidates) counts.set(String(member.membership_id), (counts.get(String(member.membership_id)) || 0) + 1);
  return candidates.filter(member => counts.get(String(member.membership_id)) === 1);
}

const styles = {
  container: {marginTop: 10, paddingTop: 8, borderTopWidth: 1, borderTopColor: '#E1E7E3'},
  header: {flexDirection: 'row' as const, justifyContent: 'space-between' as const, alignItems: 'center' as const},
  heading: {flex: 1, gap: 2},
  title: {color: '#1A2D2B', fontSize: 14, fontWeight: '700' as const},
  summary: {color: '#697974', fontSize: 11},
  expand: {color: '#186A63', fontSize: 13, fontWeight: '700' as const, padding: 8},
  body: {paddingTop: 8, gap: 8},
  description: {color: '#697974', fontSize: 12, lineHeight: 17},
  scope: {color: '#1A2D2B', fontSize: 11, lineHeight: 16},
  label: {color: '#1A2D2B', fontSize: 12, fontWeight: '700' as const, marginTop: 3},
  choice: {padding: 9, borderRadius: 9, borderWidth: 1, borderColor: '#E1E7E3', backgroundColor: '#FFFFFF'},
  choiceSelected: {borderColor: '#186A63', backgroundColor: '#E8F3EF'},
  pageButton: {alignSelf: 'flex-start' as const, paddingVertical: 6, paddingHorizontal: 4},
  pageButtonText: {color: '#186A63', fontSize: 11, fontWeight: '700' as const},
  choiceTitle: {color: '#1A2D2B', fontSize: 12, fontWeight: '600' as const},
  target: {padding: 10, borderRadius: 10, backgroundColor: '#F7F8F6', gap: 5},
  targetTitle: {color: '#1A2D2B', fontSize: 13, fontWeight: '700' as const},
  note: {color: '#697974', fontSize: 11, lineHeight: 16},
  notice: {color: '#AE7025', fontSize: 12, lineHeight: 17},
  review: {padding: 10, borderRadius: 10, borderWidth: 1, borderColor: '#D9A85D', backgroundColor: '#FFF5E3', gap: 5},
  endpointScope: {gap: 3},
  actions: {flexDirection: 'row' as const, flexWrap: 'wrap' as const, gap: 8, marginTop: 3},
  button: {alignSelf: 'flex-start' as const, borderRadius: 9, backgroundColor: '#E8F3EF', paddingVertical: 9, paddingHorizontal: 11},
  destructive: {backgroundColor: '#FCE8E6'},
  disabled: {opacity: 0.5},
  buttonText: {color: '#186A63', fontSize: 12, fontWeight: '700' as const},
  cancel: {alignSelf: 'flex-start' as const, borderRadius: 9, paddingVertical: 9, paddingHorizontal: 11},
  cancelText: {color: '#697974', fontSize: 12, fontWeight: '700' as const},
} as const;
