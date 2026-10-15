import React, {useEffect, useMemo, useRef, useState} from 'react';
import {Alert, AppState, Pressable, StyleSheet, Text, TextInput, View} from 'react-native';
import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
} from '../platform/clientHub';
import type {NetworkTopologySnapshot} from '../platform/networkTopology';
import {
  captureRegroupDelegationCallback, regroupDelegationActionLabel,
  regroupDelegationAuthority, regroupDelegationCallbackIsCurrent,
  regroupDelegationExpiryAllowed, regroupDelegationFailureMessage,
  regroupProposalFromRpc, regroupProposalTopologyStatus, suggestedRegroupDelegationExpiry,
} from '../platform/regroupDelegation';
import type {
  RegroupDelegationApi, RegroupProposalReview, RegroupDelegationAuthority,
} from '../platform/regroupDelegation';

interface Props {
  api: RegroupDelegationApi;
  status: ClientHubStatus & {
    regroupReconciliationRequired?: boolean;
    regroupUncertainOperationId?: string;
  };
  topology: NetworkTopologySnapshot | null;
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  onRefresh?: () => Promise<void>;
}

const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const timeText = (value: string) => value ? new Date(value).toLocaleString() : '未知';

function currentReview(
  value: {scopeKey: string; review: RegroupProposalReview} | null,
  authority: RegroupDelegationAuthority,
): RegroupProposalReview | null {
  return authority.ready && value?.scopeKey === authority.scope.scopeKey ? value.review : null;
}

export function RegroupDelegationPanel({api, status, topology, publicCapabilities,
  sessionCapabilities, onRefresh}: Props): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [proposalId, setProposalId] = useState('');
  const [expiry, setExpiry] = useState('');
  const [reviewState, setReviewState] = useState<{scopeKey: string; review: RegroupProposalReview} | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const operationRef = useRef(0);
  const mounted = useRef(true);
  const foreground = useRef(AppState.currentState === 'active');
  const authority = useMemo(() => regroupDelegationAuthority({
    apiScope: api.scope, status, publicCapabilities, sessionCapabilities, topology,
  }), [api.scope, status, publicCapabilities, sessionCapabilities, topology]);
  const authorityRef = useRef(authority);
  authorityRef.current = authority;
  const stateReview = currentReview(reviewState, authority);
  const liveTopologyStatus = stateReview && authority.ready ?
    regroupProposalTopologyStatus(stateReview.proposal, authority.scope.topology) : null;
  const currentScopeKey = authority.ready ? authority.scope.scopeKey : 'unavailable';
  const callbackCurrent = (callback: ReturnType<typeof captureRegroupDelegationCallback>) =>
    mounted.current && regroupDelegationCallbackIsCurrent(callback,
      authorityRef.current.ready ? authorityRef.current.scope : null,
      operationRef.current, foreground.current);

  const clearTransient = (reason = '') => {
    operationRef.current++;
    busyRef.current = false;
    setBusy(false);
    setProposalId('');
    setExpiry('');
    setReviewState(null);
    setMessage(reason);
  };

  useEffect(() => {
    mounted.current = true;
    foreground.current = AppState.currentState === 'active';
    return () => {
      mounted.current = false;
      busyRef.current = false;
    };
  }, []);

  useEffect(() => {
    clearTransient('Hub 配置或选择范围已改变；旧提案已清除。');
  }, [currentScopeKey]);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', next => {
      const isForeground = next === 'active';
      foreground.current = isForeground;
      if (!isForeground) {
        setExpanded(false);
        clearTransient('应用进入后台，提案范围和输入已清除。');
      }
    });
    return () => subscription.remove();
  }, []);

  const begin = () => {
    if (busyRef.current || !foreground.current || !authorityRef.current.ready) return null;
    busyRef.current = true;
    setBusy(true);
    return captureRegroupDelegationCallback(authorityRef.current.scope, ++operationRef.current);
  };
  const finish = (callback: ReturnType<typeof captureRegroupDelegationCallback>) => {
    if (!callbackCurrent(callback)) return;
    busyRef.current = false;
    setBusy(false);
  };
  const refreshParent = async (callback: ReturnType<typeof captureRegroupDelegationCallback>) => {
    if (!onRefresh || !callbackCurrent(callback)) return;
    try { await onRefresh(); } catch { /* Retain the on-device recovery state. */ }
  };

  const readProposal = async (id = proposalId.trim(), refreshOnly = false) => {
    const current = authorityRef.current;
    if (!current.ready || !current.canRead || !id || id !== id.trim()) return;
    const callback = begin();
    if (!callback) return;
    if (!refreshOnly) setReviewState(null);
    setMessage('');
    try {
      const response = await api.previewRegroupDelegation({proposalId: id});
      if (!callbackCurrent(callback)) return;
      if (!record(response) || typeof response.reviewId !== 'string' || !response.reviewId.trim()) {
        throw new Error('INVALID_REGROUP_REVIEW_RESPONSE');
      }
      const latest = authorityRef.current;
      if (!latest.ready) return;
      const parsed = regroupProposalFromRpc(response.proposal, response.reviewId, latest.scope, id);
      if (!parsed) throw new Error('INVALID_REGROUP_PROPOSAL_RESULT');
      if (!callbackCurrent(callback)) return;
      setReviewState({scopeKey: latest.scope.scopeKey, review: parsed});
      setExpiry(suggestedRegroupDelegationExpiry(parsed.proposal.expires_at));
      setMessage(latest.writesFenced ?
        '已读取当前提案与 delegation。此读取只检查权威状态，不会解除原请求对账锁。' :
        parsed.versionsCurrent && parsed.issueMembershipsCurrent ? '已读取并核对指定 Advisor 提案及 Group Membership。' :
          parsed.issueMembershipReason || '提案仍可查看，但 Group 或 Membership 版本已变化，不能签发委托。');
    } catch (error) {
      if (callbackCurrent(callback)) {
        setReviewState(null);
        setMessage(regroupDelegationFailureMessage(error));
      }
    } finally {
      finish(callback);
    }
  };

  const refreshAfterAcceptedWrite = async (
    callback: ReturnType<typeof captureRegroupDelegationCallback>,
    id: string,
  ) => {
    await refreshParent(callback);
    if (!callbackCurrent(callback)) return;
    const latest = authorityRef.current;
    if (!latest.ready || !latest.canRead) return;
    try {
      const response = await api.previewRegroupDelegation({proposalId: id});
      if (!callbackCurrent(callback) || !record(response) || typeof response.reviewId !== 'string') return;
      const newest = authorityRef.current;
      if (!newest.ready) return;
      const parsed = regroupProposalFromRpc(response.proposal, response.reviewId, newest.scope, id);
      if (!parsed || !callbackCurrent(callback)) return;
      setReviewState({scopeKey: newest.scope.scopeKey, review: parsed});
      setExpiry(suggestedRegroupDelegationExpiry(parsed.proposal.expires_at));
      setMessage('已提交写入并重新读取同一提案；以下显示 Hub 当前 delegation 状态。');
    } catch (error) {
      if (callbackCurrent(callback)) setMessage(regroupDelegationFailureMessage(error));
    }
  };

  const issue = () => {
    const current = authorityRef.current;
    const selected = currentReview(reviewState, current);
    if (!current.ready || !current.canIssue || busyRef.current || !selected) return;
    const proposal = selected.proposal;
    const currentTopology = regroupProposalTopologyStatus(proposal, current.scope.topology);
    const sourceMembership = currentTopology.sourceMembership;
    const targetMembership = currentTopology.targetMembership;
    const expiryText = expiry.trim();
    if (!currentTopology.sourceGroupCurrent || !currentTopology.targetGroupCurrent ||
        !currentTopology.versionsCurrent || !currentTopology.issueMembershipsCurrent ||
        !sourceMembership || !targetMembership ||
        proposal.state !== 'PROPOSED' || proposal.delegation ||
        Date.parse(proposal.expires_at) <= Date.now() ||
        !regroupDelegationExpiryAllowed(expiryText, proposal.expires_at)) {
      setMessage(currentTopology.issueMembershipReason ||
        '提案、Group 或 Membership 版本已变化，或委托有效期超出 proposal；签发关闭，请重新读取。');
      return;
    }
    const callback = begin();
    if (!callback) return;
    const action = regroupDelegationActionLabel(proposal);
    let decided = false;
    const cancel = () => {
      if (decided) return;
      decided = true;
      finish(callback);
    };
    Alert.alert('签发一次性 Advisor 委托',
      `Hub：${proposal.hub_id}\nOwner：${proposal.owner_id}\nAdvisor Endpoint / Principal：${proposal.endpoint_id} / ${proposal.principal_id}\nBinding：${proposal.binding_id} · epoch ${proposal.binding_epoch}\nNetwork：${proposal.input.network_id}\nSource Group：${proposal.input.source_group_id} · v${proposal.input.expected_source_version}\nSource 成员关系版本：v${sourceMembership.version}\nTarget Group：${proposal.input.target_group_id} · v${proposal.input.expected_target_version}\nTarget 成员关系版本：v${targetMembership.version}\n动作：${action}\nProposal 到期：${timeText(proposal.expires_at)}\n委托到期：${timeText(expiryText)}\n\n确认时会再次核对成员关系、Group 版本和有效期；Hub 负责最终权限校验。`, [
        {text: '取消', style: 'cancel', onPress: cancel},
        {text: '确认签发', onPress: async () => {
          if (decided) return;
          decided = true;
          const latest = authorityRef.current;
          if (!callbackCurrent(callback)) return;
          const latestTopology = latest.ready ?
            regroupProposalTopologyStatus(proposal, latest.scope.topology) : null;
          if (!latest.ready || !latest.canIssue || !latestTopology ||
              !latestTopology.sourceGroupCurrent || !latestTopology.targetGroupCurrent ||
              !latestTopology.versionsCurrent || !latestTopology.issueMembershipsCurrent ||
              !latestTopology.sourceMembership || !latestTopology.targetMembership ||
              latestTopology.sourceMembership.membershipId !== sourceMembership.membershipId ||
              latestTopology.sourceMembership.version !== sourceMembership.version ||
              latestTopology.targetMembership.membershipId !== targetMembership.membershipId ||
              latestTopology.targetMembership.version !== targetMembership.version ||
              proposal.state !== 'PROPOSED' || proposal.delegation ||
              Date.parse(proposal.expires_at) <= Date.now() ||
              !regroupDelegationExpiryAllowed(expiryText, proposal.expires_at) ||
              latest.scope.scopeKey !== current.scope.scopeKey) {
            setMessage(latestTopology?.issueMembershipReason ||
              '确认期间 Group Membership、Group 版本、授权或有效期已改变；未提交 issue，请重新读取。');
            finish(callback);
            return;
          }
          setReviewState(null); // The preview review ID is single-use after confirmation.
          setMessage('已确认 Owner 意图，正在提交精确的一次性委托…');
          try {
            const response = await api.issueRegroupDelegation({
              reviewId: selected.reviewId, expiresAt: expiryText, confirmed: true,
            });
            if (!callbackCurrent(callback)) return;
            if (!record(response) || response.ok !== true) {
              const error = Object.assign(new Error('REGROUP_ISSUE_REJECTED'), {
                errorCode: record(response) ?
                  response.errorCode || response.error_code || 'REGROUP_ISSUE_REJECTED' : 'REGROUP_ISSUE_REJECTED',
              });
              throw error;
            }
            setMessage('Hub 已接受 issue；正在重新读取同一提案的当前 delegation…');
            await refreshAfterAcceptedWrite(callback, proposal.proposal_id);
          } catch (error) {
            if (callbackCurrent(callback)) setMessage(regroupDelegationFailureMessage(error));
            await refreshParent(callback);
          } finally {
            finish(callback);
          }
        }},
      ], {cancelable: true, onDismiss: cancel});
  };

  const revoke = () => {
    const current = authorityRef.current;
    const selected = currentReview(reviewState, current);
    const delegation = selected?.proposal.delegation;
    if (!current.ready || !current.canRevoke || busyRef.current || !selected ||
        !delegation || delegation.state !== 'ACTIVE') return;
    const callback = begin();
    if (!callback) return;
    let decided = false;
    const cancel = () => {
      if (decided) return;
      decided = true;
      finish(callback);
    };
    Alert.alert('撤销当前 Advisor 委托？',
      `Proposal：${delegation.proposal_id}\nDelegation：${delegation.delegation_id}\nOwner：${delegation.owner_id}\nHub：${delegation.hub_id}\n当前状态：${delegation.state} · version ${delegation.version}\n到期：${timeText(delegation.expires_at)}\n\n撤销将提交 expected_version=${delegation.version}；若 Hub 状态已改变，CAS 会拒绝。`, [
        {text: '取消', style: 'cancel', onPress: cancel},
        {text: '确认撤销', style: 'destructive', onPress: async () => {
          if (decided) return;
          decided = true;
          const latest = authorityRef.current;
          if (!callbackCurrent(callback) || !latest.ready || !latest.canRevoke ||
              latest.scope.scopeKey !== current.scope.scopeKey) {
            finish(callback);
            return;
          }
          setReviewState(null);
          setMessage('已确认撤销意图，正在提交 delegation version CAS…');
          try {
            const response = await api.revokeRegroupDelegation({
              reviewId: selected.reviewId,
              delegationId: delegation.delegation_id,
              expectedVersion: delegation.version,
              confirmed: true,
            });
            if (!callbackCurrent(callback)) return;
            if (!record(response) || response.ok !== true) {
              const error = Object.assign(new Error('REGROUP_REVOKE_REJECTED'), {
                errorCode: record(response) ?
                  response.errorCode || response.error_code || 'REGROUP_REVOKE_REJECTED' : 'REGROUP_REVOKE_REJECTED',
              });
              throw error;
            }
            setMessage('Hub 已接受 revoke；正在重新读取同一提案的当前 delegation…');
            await refreshAfterAcceptedWrite(callback, delegation.proposal_id);
          } catch (error) {
            if (callbackCurrent(callback)) setMessage(regroupDelegationFailureMessage(error));
            await refreshParent(callback);
          } finally {
            finish(callback);
          }
        }},
      ], {cancelable: true, onDismiss: cancel});
  };

  const proposal = stateReview?.proposal;
  const delegation = proposal?.delegation;
  const canIssueCurrent = Boolean(authority.ready && authority.canIssue && !busy && stateReview &&
    liveTopologyStatus?.sourceGroupCurrent && liveTopologyStatus.targetGroupCurrent &&
    liveTopologyStatus.versionsCurrent && liveTopologyStatus.issueMembershipsCurrent &&
    liveTopologyStatus.sourceMembership && liveTopologyStatus.targetMembership &&
    proposal?.state === 'PROPOSED' && !delegation &&
    Date.parse(proposal.expires_at) > Date.now() &&
    regroupDelegationExpiryAllowed(expiry.trim(), proposal.expires_at));
  const canRevokeCurrent = Boolean(authority.ready && authority.canRevoke && !busy && stateReview &&
    delegation?.state === 'ACTIVE');
  const headline = authority.ready && authority.canRead ?
    '输入 proposal ID，逐项核对后再操作' : '需要当前已授权的加密 Owner 会话';

  return <View style={styles.card}>
    <Pressable accessibilityRole="button" accessibilityState={{expanded}}
      accessibilityLabel={`Advisor 重组委托，${headline}`}
      style={styles.header} onPress={() => {
        if (expanded) {
          setExpanded(false);
          clearTransient('已收起并清除提案范围。');
        } else {
          setExpanded(true);
          setMessage('');
        }
      }}>
      <View style={styles.headingText}>
        <Text style={styles.title}>Advisor 重组委托</Text>
        <Text style={styles.summary}>{headline}</Text>
      </View>
      <Text style={styles.expand}>{expanded ? '收起' : '查看'}</Text>
    </Pressable>

    {expanded && <View style={styles.body}>
      <Text style={styles.description}>按 proposal ID 读取单个真实 Hub 提案；v1.6 没有提案列表 API。Owner 使用当前设备的加密 session.capabilities 确认，Advisor 不能代 User 批准 Goal。</Text>
      {!authority.ready && <Text style={styles.notice}>{authority.reason}</Text>}
      {authority.ready && <>
        <Text selectable style={styles.small}>Hub：{authority.scope.hubId} · Owner：{authority.scope.ownerId}{'\n'}ACTIVE Network：{authority.scope.networkName} · {authority.scope.networkId} · v{authority.scope.networkVersion}{'\n'}配置：{authority.scope.profileId} · 选择代次 {authority.scope.selectionGeneration}{'\n'}当前角色：{sessionCapabilities?.role || '未知'}</Text>
        {authority.writesFenced && <Text style={styles.notice}>{authority.reason || '写入仍被对账锁定。'}
          {status.regroupUncertainOperationId ? `原 operation ID：${status.regroupUncertainOperationId}。` : ''}
          提案读取只能检查当前 delegation，不能证明具体原请求的执行结果。</Text>}
        <TextInput style={styles.input} value={proposalId} editable={!busy}
          maxLength={256} autoCapitalize="none" autoCorrect={false}
          placeholder="Advisor proposal ID" accessibilityLabel="Advisor proposal ID"
          onChangeText={value => {
            setProposalId(value);
            setReviewState(null);
            setExpiry('');
            setMessage('');
          }} />
        <Action title={authority.writesFenced ? '读取并对账当前提案' : '读取指定 Advisor 提案'}
          disabled={busy || !authority.canRead || !proposalId.trim()}
          onPress={() => { readProposal().catch(() => undefined); }} secondary />

        {proposal && <View style={styles.evidence}>
          <Text style={styles.sectionTitle}>精确提案 · Hub 当前返回值</Text>
          <Text selectable style={styles.scopeText}>Proposal：{proposal.proposal_id}{'\n'}Hub / Human Owner：{proposal.hub_id} / {proposal.owner_id}{'\n'}Advisor Endpoint：{proposal.endpoint_id}{'\n'}Advisor Principal：{proposal.principal_id}{proposal.principal_id === proposal.owner_id ? ' · 不可用（与 Owner 相同）' : ''}{'\n'}Node Binding：{proposal.binding_id} · epoch {proposal.binding_epoch}{'\n'}Network：{proposal.input.network_id}{'\n'}Source Group：{proposal.input.source_group_id} · expected v{proposal.input.expected_source_version}{'\n'}Target Group：{proposal.input.target_group_id} · expected v{proposal.input.expected_target_version}{'\n'}动作：{regroupDelegationActionLabel(proposal)}{'\n'}状态：{proposal.state}{'\n'}创建：{timeText(proposal.created_at)} · 到期：{timeText(proposal.expires_at)}</Text>
          {(!liveTopologyStatus?.sourceGroupCurrent || !liveTopologyStatus?.targetGroupCurrent) &&
            <Text style={styles.notice}>当前 topology.snapshot 未确认 source 与 target 均为所选 ACTIVE Network 内的 ACTIVE Group；签发关闭。</Text>}
          {liveTopologyStatus && !liveTopologyStatus.versionsCurrent &&
            <Text style={styles.notice}>至少一个当前 Group 版本与提案 CAS 版本不同；签发关闭，先读取当前权威状态。</Text>}
          {liveTopologyStatus && !liveTopologyStatus.issueMembershipsCurrent &&
            <Text style={styles.notice}>{liveTopologyStatus.issueMembershipReason ||
              '当前 topology.snapshot 未确认 source/target 的显式 ACTIVE Advisor Endpoint Membership；签发关闭。'}</Text>}
          {liveTopologyStatus?.issueMembershipsCurrent && liveTopologyStatus.sourceMembership &&
            liveTopologyStatus.targetMembership && <Text style={styles.small}>
              当前成员关系版本：source v{liveTopologyStatus.sourceMembership.version} · target v{liveTopologyStatus.targetMembership.version}
            </Text>}
          {delegation && <Text selectable style={styles.scopeText}>当前 delegation：{delegation.delegation_id}{'\n'}Owner / Hub：{delegation.owner_id} / {delegation.hub_id}{'\n'}状态：{delegation.state} · version {delegation.version} · uses {delegation.use_count}/{delegation.max_uses}{'\n'}到期：{timeText(delegation.expires_at)}</Text>}
          {!delegation && proposal.state === 'PROPOSED' && <>
            <Text style={styles.sectionTitle}>一次性有效期 · RFC3339Nano</Text>
            <Text style={styles.small}>必须晚于现在，且不晚于 proposal 到期或 24 小时。建议值可编辑。</Text>
            <TextInput style={styles.input} value={expiry} editable={!busy}
              autoCapitalize="none" autoCorrect={false} keyboardType="numbers-and-punctuation"
              accessibilityLabel="Delegation expiry time"
              placeholder="2026-10-01T18:00:00.000Z" onChangeText={setExpiry} />
            <Action title="确认并签发一次性委托" disabled={!canIssueCurrent} onPress={issue} />
          </>}
          {delegation?.state === 'ACTIVE' && <Action title="确认并撤销当前委托" disabled={!canRevokeCurrent}
            onPress={revoke} destructive />}
          {delegation && delegation.state !== 'ACTIVE' &&
            <Text style={styles.small}>此 delegation 已是 {delegation.state}；不能再次签发同一 proposal。</Text>}
        </View>}
      </>}
      {!!message && <Text accessibilityLiveRegion="polite" style={styles.description}>{message}</Text>}
      {busy && <Text style={styles.small}>正在通过当前加密 Owner 会话读取或提交；原 RPC 密文与计数由 Native 保管。</Text>}
    </View>}
  </View>;
}

function Action({title, disabled, onPress, secondary = false, destructive = false}: {
  title: string; disabled: boolean; onPress: () => void; secondary?: boolean; destructive?: boolean;
}): React.JSX.Element {
  return <Pressable accessibilityRole="button" accessibilityState={{disabled}} disabled={disabled}
    onPress={onPress} style={[styles.button, secondary && styles.secondary,
      destructive && styles.destructive, disabled && styles.disabled]}>
    <Text style={[styles.buttonText, secondary && styles.secondaryText,
      destructive && styles.destructiveText]}>{title}</Text>
  </Pressable>;
}

const styles = StyleSheet.create({
  card: {borderRadius: 20, borderWidth: 1, borderColor: '#E1E7E3', backgroundColor: '#FFFFFF', padding: 16, marginBottom: 10},
  header: {minHeight: 46, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'},
  headingText: {flex: 1, paddingRight: 12},
  title: {fontSize: 16, fontWeight: '700', color: '#1A2D2B'},
  summary: {fontSize: 12, color: '#697974', marginTop: 3},
  expand: {fontSize: 13, fontWeight: '600', color: '#186A63', paddingVertical: 10, paddingHorizontal: 4},
  body: {paddingTop: 12},
  description: {fontSize: 13, lineHeight: 19, color: '#697974', marginTop: 8},
  small: {fontSize: 12, lineHeight: 18, color: '#697974', marginTop: 6},
  notice: {fontSize: 12, lineHeight: 18, color: '#805D25', backgroundColor: '#FFF5E3', borderRadius: 10, padding: 10, marginTop: 8},
  input: {borderWidth: 1, borderColor: '#E1E7E3', borderRadius: 12, padding: 12, marginTop: 12, color: '#1A2D2B', fontSize: 13},
  evidence: {marginTop: 14, paddingTop: 12, borderTopWidth: 1, borderTopColor: '#E1E7E3'},
  sectionTitle: {fontSize: 13, fontWeight: '700', color: '#1A2D2B', marginTop: 12, marginBottom: 6},
  scopeText: {fontSize: 12, lineHeight: 19, color: '#1A2D2B', marginTop: 6},
  button: {paddingVertical: 12, paddingHorizontal: 14, backgroundColor: '#186A63', borderRadius: 12, marginTop: 10},
  buttonText: {color: '#FFFFFF', fontSize: 13, fontWeight: '600', textAlign: 'center'},
  secondary: {backgroundColor: '#F7F8F6'},
  secondaryText: {color: '#186A63'},
  destructive: {backgroundColor: '#FBF2F0'},
  destructiveText: {color: '#9C4938'},
  disabled: {opacity: 0.4},
});
