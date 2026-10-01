import React, {useEffect, useRef, useState} from 'react';
import {AppState, Pressable, Text, View} from 'react-native';
import type {
  ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus, HubProfileScope,
} from '../platform/clientHub';
import {
  linkReviewPolicyStatusCanRead, linkReviewPolicyStatusFromRpc, linkReviewPolicyStatusSupported,
  linkReviewPolicyStatusScopeKey, LinkReviewPolicyStatusLifecycle,
} from '../platform/linkReviewPolicyStatus';
import type {LinkReviewPolicyAuthorityInput, LinkReviewPolicyStatus} from '../platform/linkReviewPolicyStatus';

type ReadStatus = (input: {linkId: string; expectedLinkVersion: number}) => Promise<unknown>;

interface Props {
  status: ClientHubStatus;
  publicCapabilities: ClientHubCapabilities;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  apiScope: HubProfileScope;
  linkId: string;
  linkVersion: number;
  listGeneration: number;
  linkReviewPolicyStatusReady: boolean;
  readStatus: ReadStatus;
  getCurrentStatus: () => Promise<ClientHubStatus>;
}

interface DisplayedStatus {
  readonly authorityKey: string;
  readonly value: LinkReviewPolicyStatus;
}

export function LinkReviewPolicyStatusPanel(props: Props): React.JSX.Element | null {
  const [expanded, setExpanded] = useState(false);
  const [foreground, setForeground] = useState(AppState.currentState === 'active');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [displayed, setDisplayed] = useState<DisplayedStatus | null>(null);
  const lifecycleRef = useRef(new LinkReviewPolicyStatusLifecycle());
  const authorityInput: LinkReviewPolicyAuthorityInput = {
    status: props.status, publicCapabilities: props.publicCapabilities,
    sessionCapabilities: props.sessionCapabilities, apiScope: props.apiScope,
    linkId: props.linkId, linkVersion: props.linkVersion, listGeneration: props.listGeneration,
    bridgeReady: props.linkReviewPolicyStatusReady,
  };
  const authorityKey = linkReviewPolicyStatusScopeKey(authorityInput);
  const visible = linkReviewPolicyStatusSupported(props.status, props.publicCapabilities,
    props.sessionCapabilities, props.apiScope, props.linkReviewPolicyStatusReady);
  const allowed = visible && foreground && linkReviewPolicyStatusCanRead(props.status,
    props.publicCapabilities, props.sessionCapabilities, props.apiScope, props.linkReviewPolicyStatusReady);
  const latestRef = useRef({
    authorityKey, foreground, status: props.status, publicCapabilities: props.publicCapabilities,
    sessionCapabilities: props.sessionCapabilities, apiScope: props.apiScope,
    linkId: props.linkId, linkVersion: props.linkVersion, listGeneration: props.listGeneration,
    linkReviewPolicyStatusReady: props.linkReviewPolicyStatusReady,
    readStatus: props.readStatus, getCurrentStatus: props.getCurrentStatus,
  });
  latestRef.current = {
    authorityKey, foreground, status: props.status, publicCapabilities: props.publicCapabilities,
    sessionCapabilities: props.sessionCapabilities, apiScope: props.apiScope,
    linkId: props.linkId, linkVersion: props.linkVersion, listGeneration: props.listGeneration,
    linkReviewPolicyStatusReady: props.linkReviewPolicyStatusReady,
    readStatus: props.readStatus, getCurrentStatus: props.getCurrentStatus,
  };

  useEffect(() => {
    lifecycleRef.current.invalidate();
    setDisplayed(null);
    setMessage('');
    setBusy(false);
  }, [authorityKey]);

  useEffect(() => {
    const lifecycle = lifecycleRef.current;
    const subscription = AppState.addEventListener('change', state => {
      const isForeground = state === 'active';
      setForeground(isForeground);
      if (!isForeground) {
        lifecycle.invalidate();
        setDisplayed(null);
        setMessage('');
        setBusy(false);
        setExpanded(false);
      }
    });
    return () => {
      subscription.remove();
      lifecycle.invalidate();
    };
  }, []);

  const readStatus = async () => {
    const captured = latestRef.current;
    if (!captured.linkReviewPolicyStatusReady || !captured.foreground ||
        !linkReviewPolicyStatusCanRead(captured.status,
        captured.publicCapabilities, captured.sessionCapabilities, captured.apiScope,
        captured.linkReviewPolicyStatusReady)) return;
    const lifecycle = lifecycleRef.current;
    const capture = lifecycle.capture(captured.authorityKey);
    setDisplayed(null);
    setBusy(true);
    setMessage('');
    try {
      const raw = await captured.readStatus({
        linkId: captured.linkId, expectedLinkVersion: captured.linkVersion,
      });
      const parsed = linkReviewPolicyStatusFromRpc(raw, captured.linkId, captured.linkVersion);
      const afterRpc = latestRef.current;
      if (!lifecycle.isCurrent(capture, afterRpc.authorityKey, afterRpc.foreground)) return;
      if (!parsed) throw new Error('invalid_link_review_policy_status');

      const currentStatus = await afterRpc.getCurrentStatus();
      const afterStatus = latestRef.current;
      const freshKey = linkReviewPolicyStatusScopeKey({
        status: currentStatus, publicCapabilities: afterStatus.publicCapabilities,
        sessionCapabilities: afterStatus.sessionCapabilities, apiScope: afterStatus.apiScope,
        linkId: afterStatus.linkId, linkVersion: afterStatus.linkVersion,
        listGeneration: afterStatus.listGeneration, bridgeReady: afterStatus.linkReviewPolicyStatusReady,
      });
      if (!lifecycle.isCurrent(capture, afterStatus.authorityKey, afterStatus.foreground) ||
          freshKey !== capture.scopeKey || !linkReviewPolicyStatusCanRead(currentStatus,
            afterStatus.publicCapabilities, afterStatus.sessionCapabilities, afterStatus.apiScope,
            afterStatus.linkReviewPolicyStatusReady)) return;
      setDisplayed({authorityKey: capture.scopeKey, value: parsed});
      setMessage('状态来自本次加密读取，并与当前 link.list 版本一致。');
    } catch {
      const latest = latestRef.current;
      if (lifecycle.isCurrent(capture, latest.authorityKey, latest.foreground)) {
        setDisplayed(null);
        setMessage('未能读取有效的审阅策略状态。请刷新 Link 列表后重试。');
      }
    } finally {
      const latest = latestRef.current;
      if (lifecycle.isCurrent(capture, latest.authorityKey, latest.foreground)) setBusy(false);
    }
  };

  const value = displayed?.authorityKey === authorityKey ? displayed.value : null;
  if (!visible) return null;
  return <View style={styles.container}>
    <Pressable accessibilityRole="button" onPress={() => setExpanded(open => !open)}>
      <Text style={styles.toggle}>{expanded ? '收起审阅策略状态' : '读取审阅策略状态'}  {expanded ? '⌃' : '⌄'}</Text>
    </Pressable>
    {expanded && <View style={styles.body}>
      <Text style={styles.explanation}>只读取 Hub 的审阅策略元数据；不会读取消息，也不代表消息已审阅或已送达。</Text>
      <Pressable accessibilityRole="button" disabled={!allowed || busy} onPress={() => { void readStatus(); }}
        style={[styles.button, (!allowed || busy) && styles.disabled]}>
        <Text style={styles.buttonText}>{busy ? '读取中…' : '从 Hub 读取状态'}</Text>
      </Pressable>
      {!allowed && <Text style={styles.note}>当前加密会话未开放此只读操作。</Text>}
      {!!message && <Text style={styles.note}>{message}</Text>}
      {value && <View style={styles.result}>
        <Text style={styles.resultTitle}>{value.unconfigured ? '未配置审阅策略' :
          `Hub 策略记录：${value.policy.mode === 'METADATA' ? '审阅元数据' : '不启用审阅'} · v${value.policy_version}`}</Text>
        <Text style={styles.note}>Hub 记录是否为当前策略：{value.current ? '是' : '否'} · 记录的签署侧：{value.accepted_sides.map(side => side === 'SOURCE' ? '来源方' : '目标方').join('、') || '无'}</Text>
        {!value.unconfigured && <>
          <Text style={styles.note}>策略摘要：{value.policy_digest}</Text>
          {!!value.expires_at && <Text style={styles.note}>Hub 记录到期：{value.expires_at}</Text>}
          {value.policy.mode === 'METADATA' && <>
            <Text style={styles.note}>审阅者：{value.policy.reviewers.map(item =>
              `${item.endpoint_id} / ${item.group_id}`).join('；')}</Text>
            <Text style={styles.note}>最多转移 {value.policy.max_failovers} 次 · 审阅租约 {value.policy.reviewer_lease_seconds} 秒 · 审阅结果最长有效时间 {value.policy.max_review_age_seconds} 秒</Text>
          </>}
        </>}
        <Text style={styles.footnote}>以上为 Hub 返回的策略状态元数据，不授予消息、密钥或签名权限。</Text>
      </View>}
    </View>}
  </View>;
}

const styles = {
  container: {marginTop: 10, paddingTop: 8, borderTopWidth: 1, borderTopColor: '#E1E7E3'},
  toggle: {color: '#186A63', fontSize: 13, fontWeight: '700'},
  body: {paddingTop: 8, gap: 7},
  explanation: {color: '#697974', fontSize: 12, lineHeight: 17},
  button: {alignSelf: 'flex-start', borderRadius: 10, backgroundColor: '#E8F3EF', paddingVertical: 9, paddingHorizontal: 12},
  disabled: {opacity: 0.5},
  buttonText: {color: '#186A63', fontSize: 13, fontWeight: '700'},
  note: {color: '#697974', fontSize: 12, lineHeight: 17},
  result: {padding: 10, borderRadius: 10, backgroundColor: '#F7F8F6', gap: 5},
  resultTitle: {color: '#1A2D2B', fontSize: 14, fontWeight: '700'},
  footnote: {color: '#697974', fontSize: 11, lineHeight: 16, marginTop: 3},
} as const;
